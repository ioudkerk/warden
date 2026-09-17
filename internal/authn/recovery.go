package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
	"github.com/warden-project/warden/internal/store/dbtypes"
)

// Recovery codes: the way back in when the phone is gone (SPEC §7.1).
//
// They are the reason a second factor can be required at all. Without them, enabling TOTP
// is asking every user to bet their account on a device they will eventually lose, and a
// support process that resets the factor on request is a social-engineering target that
// undoes the factor for everybody.
//
// Which makes a recovery code a *password-equivalent credential*, and it is treated as one:
// shown once, hashed at rest, single use — and using one is an event, not a routine login.
// §7.2 requires recovery to invalidate every session and refresh token, and that is
// enforced here rather than left to the caller, because a caller that forgets loses the
// property silently.

const (
	// RecoveryCodeCount is how many are issued at once. Ten is the number people are
	// used to and enough that losing a printout mid-list is survivable.
	RecoveryCodeCount = 10

	// recoveryCodeBytes is 20 bytes — 160 bits — rendered as 32 base32 characters in
	// groups of four. Not stretched with Argon2id and it does not need to be: there is
	// nothing to stretch in a value chosen by a random number generator, which is the
	// same reasoning service-account tokens follow.
	recoveryCodeBytes = 20
)

// GenerateRecoveryCodes issues a fresh set, replacing any that exist.
//
// Replacing rather than adding, because a set is a unit: "here are your ten codes" is a
// thing a person writes down once. Leaving the previous set alive would mean a printout
// somebody threw away last year still opens the account.
//
// The plaintext is returned once and never again.
func (a *Authenticator) GenerateRecoveryCodes(ctx context.Context, tenantID, userID string) ([]string, error) {
	// Generated before the transaction, per M0-7: a retry would otherwise mint a
	// different set from the one the caller is about to display.
	codes := make([]string, 0, RecoveryCodeCount)
	rows := make([]db.InsertSecondFactorParams, 0, RecoveryCodeCount)
	issuedAt := time.Now().UTC().Format(time.RFC3339Nano)

	for range RecoveryCodeCount {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		id, err := newID("crd")
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
		rows = append(rows, db.InsertSecondFactorParams{
			ID: id, UserID: userID, TenantID: tenantID, Type: FactorRecoveryCode,
			SecretHash: hashRecoveryCode(code),
			// Confirmed on issue: unlike an authenticator, there is no device to prove
			// possession of, and asking somebody to type one back would spend a code to
			// learn what generating it already established.
			Params: dbtypes.JSONMap{"confirmed_at": issuedAt},
		})
	}

	if err := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		if _, delErr := q.DeleteSecondFactorsOfType(ctx, db.DeleteSecondFactorsOfTypeParams{
			TenantID: tenantID, UserID: userID, Type: FactorRecoveryCode,
		}); delErr != nil {
			return delErr
		}
		for _, row := range rows {
			if insertErr := q.InsertSecondFactor(ctx, row); insertErr != nil {
				return insertErr
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("storing the recovery codes: %w", err)
	}

	a.recordFactorEvent(ctx, tenantID, userID, ActionRecoveryCodesIssued, FactorRecoveryCode,
		"a set of recovery codes was issued")
	return codes, nil
}

// RemainingRecoveryCodes reports how many are unspent, so a settings page can say so
// before the answer is zero.
func (a *Authenticator) RemainingRecoveryCodes(ctx context.Context, tenantID, userID string) (int64, error) {
	var count int64
	err := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var queryErr error
		count, queryErr = db.New(tx).CountUnusedRecoveryCodes(ctx,
			db.CountUnusedRecoveryCodesParams{TenantID: tenantID, UserID: userID})
		return queryErr
	}, store.ReadOnly())
	return count, err
}

// redeemRecoveryCode spends a code if it matches, and ends every session if it does.
//
// Looked up by hash rather than compared one by one: the codes are random, so there is
// nothing for a slow hash to defend, and an indexed read is one query instead of ten.
func (a *Authenticator) redeemRecoveryCode(ctx context.Context, tenantID, userID, presented string) bool {
	normalised := normaliseRecoveryCode(presented)
	if normalised == "" {
		return false
	}

	var (
		credentialID string
		alreadyUsed  bool
	)
	err := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		row, queryErr := q.RecoveryCodeByHash(ctx, db.RecoveryCodeByHashParams{
			TenantID: tenantID, UserID: userID, SecretHash: hashRecoveryCode(normalised),
		})
		if queryErr != nil {
			return queryErr
		}
		if _, used := row.Params["used_at"]; used {
			alreadyUsed = true
			return nil
		}

		credentialID = row.ID
		params := cloneParams(row.Params)
		params["used_at"] = time.Now().UTC().Format(time.RFC3339Nano)

		now := time.Now().UTC()
		_, updateErr := q.UpdateSecondFactorParams(ctx, db.UpdateSecondFactorParamsParams{
			TenantID: tenantID, ID: row.ID, Params: params, LastUsedAt: &now,
		})
		return updateErr
	})

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false
	case err != nil:
		a.log.Error("could not redeem a recovery code",
			"tenant_id", tenantID, "user_id", userID, "error", err)
		return false
	case alreadyUsed:
		// Spent already. Worth a warning: either somebody is working through a stolen
		// list, or a person is retrying one that did not appear to work.
		a.log.Warn("a recovery code was presented after it had already been used",
			"tenant_id", tenantID, "user_id", userID)
		return false
	case credentialID == "":
		return false
	}

	a.afterRecovery(ctx, tenantID, userID)
	return true
}

// verifyRecoveryFactor is the hook VerifySecondFactor calls.
//
// The credential rows are per code, so this is asked once per row; the redemption itself is
// keyed by hash, so it runs at most once. Returning on the first row keeps a ten-code set
// from doing ten lookups for one wrong guess.
func (a *Authenticator) verifyRecoveryFactor(
	ctx context.Context, tenantID, userID string, _ db.SecondFactorsForUserRow, code string,
) bool {
	return a.redeemRecoveryCode(ctx, tenantID, userID, code)
}

// afterRecovery does what SPEC §7.2 requires of a recovery: everything else stops.
//
// Using a recovery code means the normal factor is unavailable, and the honest reading of
// that is "something has changed, possibly not in the account holder's favour". Every
// session and every refresh token goes, so whoever was signed in — including whoever should
// not have been — starts again.
//
// It runs after the code is spent rather than before, so a failed revocation cannot leave a
// code consumed and the sessions alive with no record of why.
func (a *Authenticator) afterRecovery(ctx context.Context, tenantID, userID string) {
	// Refresh tokens first, then sessions: the longest-lived credential goes first, so a
	// failure halfway leaves the person signed in with dead tokens rather than signed out
	// with a live one. The same order Storage.EndSession uses, for the same reason.
	if a.refresh != nil {
		if _, err := a.refresh.RevokeAllForUser(ctx, tenantID, userID,
			"a recovery code was used"); err != nil {
			a.log.Error("could not revoke refresh tokens after a recovery code was used",
				"tenant_id", tenantID, "user_id", userID, "error", err)
		}
	}

	if a.sessions != nil {
		if count, err := a.sessions.RevokeAllForUser(ctx, tenantID, userID,
			"a recovery code was used"); err != nil {
			a.log.Error("could not end sessions after a recovery code was used",
				"tenant_id", tenantID, "user_id", userID, "error", err)
		} else {
			a.log.Info("ended every session after a recovery code was used",
				"tenant_id", tenantID, "user_id", userID, "sessions", count)
		}
	} else {
		a.log.Error("a recovery code was used and no sessions were ended: the authenticator " +
			"was built without the session store, so SPEC §7.2's requirement is not being met")
	}

	if a.audit == nil || a.system == nil {
		return
	}
	err := a.system.InSystem(ctx, "recording a recovery code redemption", func(ctx context.Context, tx pgx.Tx) error {
		_, appendErr := a.audit.Append(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: ActionRecoveryCodeUsed,
			TargetType: targetUser, TargetID: userID,
			Reason: "a recovery code was used in place of a second factor",
			After:  map[string]any{"sessions_revoked": true},
		})
		return appendErr
	})
	if err != nil {
		a.log.Error("could not record a recovery code redemption in the audit log", "error", err)
	}
}

// --- the codes themselves --------------------------------------------------------------

// newRecoveryCode returns a code in the shape people can read back over a telephone.
func newRecoveryCode() (string, error) {
	raw := make([]byte, recoveryCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating a recovery code: %w", err)
	}

	encoded := base32NoPad.EncodeToString(raw)
	var grouped strings.Builder
	for i, r := range encoded {
		if i > 0 && i%4 == 0 {
			grouped.WriteByte('-')
		}
		grouped.WriteRune(r)
	}
	return grouped.String(), nil
}

// hashRecoveryCode is SHA-256 over the normalised code.
func hashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(normaliseRecoveryCode(code)))
	return fmt.Sprintf("%x", sum)
}

// normaliseRecoveryCode turns what somebody typed into what was stored: upper case, with
// the grouping dashes and any spaces removed.
func normaliseRecoveryCode(code string) string {
	cleaned := strings.ToUpper(strings.NewReplacer("-", "", " ", "", "=", "").Replace(strings.TrimSpace(code)))
	if cleaned == "" {
		return ""
	}
	// Only the alphabet the generator uses. Anything else cannot be a code this system
	// issued, and rejecting it here keeps a hash lookup from being attempted on rubbish.
	for _, r := range cleaned {
		if !strings.ContainsRune(base32Alphabet, r) {
			return ""
		}
	}
	return cleaned
}

// base32Alphabet is RFC 4648's, which is what base32NoPad encodes with.
const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
