package authn

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
	"github.com/warden-project/warden/internal/store/dbtypes"
)

// Second factors: enrolment, confirmation and verification (SPEC §7.1).
//
// The shape of this is decided by one rule: a factor a person cannot use is worse than no
// factor at all, because it locks them out of their own account. So an enrolment is not a
// factor until it has been *proved* — the secret is stored, the account is not protected by
// it, and only a correct code from the device turns it on. Somebody who scans a QR code,
// closes the tab and never confirms has changed nothing.

// Credential types, matching credential_type_valid in migration 000002.
const (
	FactorTOTP         = "totp"
	FactorWebAuthn     = "webauthn"
	FactorRecoveryCode = "recovery_code"
)

// secondFactorTypes are the credential types that count as a second factor. The recovery
// code is here because it *is* one: it stands in for the others when the device is gone.
var secondFactorTypes = []string{FactorTOTP, FactorWebAuthn, FactorRecoveryCode}

// Errors a caller distinguishes.
var (
	// ErrNoSecondFactor means the user has none enrolled.
	ErrNoSecondFactor = errors.New("no second factor is enrolled")

	// ErrInvalidSecondFactor is every way a presented factor can fail: wrong code, a
	// code already used, an expired enrolment, an unknown credential. One error, for the
	// reason ErrInvalidCredentials gives at length — the caller's response is identical
	// in each case, and distinguishing them tells whoever is guessing which guess was
	// closer.
	ErrInvalidSecondFactor = errors.New("invalid second factor")

	// ErrFactorAlreadyConfirmed is returned when confirming an enrolment that is already
	// live. Not a security answer; it stops a double submission looking like a failure.
	ErrFactorAlreadyConfirmed = errors.New("this second factor is already confirmed")
)

// Factor is an enrolled second factor as a caller sees it. The secret never leaves this
// package after enrolment.
type Factor struct {
	ID          string
	Type        string
	Label       string
	Confirmed   bool
	ConfirmedAt time.Time
	CreatedAt   time.Time
	LastUsedAt  *time.Time
}

// TOTPEnrolment is what a person needs to set up an authenticator, returned once.
type TOTPEnrolment struct {
	CredentialID string
	// Secret is the base32 shared secret, for the person who cannot scan a QR code.
	Secret string
	// URI is the otpauth:// value a QR code encodes.
	URI string
}

// EnrolTOTP begins a TOTP enrolment. It is not a second factor until ConfirmTOTP.
//
// Re-enrolling replaces: a user setting up a new authenticator is not asking to keep the
// old one, and leaving both would mean a device they have lost still opens the account.
func (a *Authenticator) EnrolTOTP(ctx context.Context, tenantID, userID, issuer, account string) (*TOTPEnrolment, error) {
	if a.keyring == nil {
		return nil, errors.New(
			"enrolling a second factor needs the keyring: a TOTP secret is stored encrypted, " +
				"because it is a credential that can mint codes rather than a hash that can only " +
				"check them")
	}

	// Generated before the transaction opens, per M0-7's convention: the store's retry
	// loop re-runs the callback, and a secret minted inside it would differ between
	// attempts — the person would be shown one value and the database would hold another.
	secret, err := NewTOTPSecret()
	if err != nil {
		return nil, err
	}
	id, err := newID("crd")
	if err != nil {
		return nil, err
	}

	// A TOTP seed is not a password: verification needs the original bytes, so it cannot
	// be hashed. Encrypted under the deployment KEK with the credential's own identity as
	// additional authenticated data, so a ciphertext lifted from one row cannot be
	// replanted in another.
	sealed, err := a.keyring.EncryptString(secret, factorAAD(tenantID, userID, id))
	if err != nil {
		return nil, fmt.Errorf("sealing the TOTP secret: %w", err)
	}

	if err := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		// Replace rather than accumulate.
		if _, delErr := q.DeleteSecondFactorsOfType(ctx, db.DeleteSecondFactorsOfTypeParams{
			TenantID: tenantID, UserID: userID, Type: FactorTOTP,
		}); delErr != nil {
			return delErr
		}
		return q.InsertSecondFactor(ctx, db.InsertSecondFactorParams{
			ID: id, UserID: userID, TenantID: tenantID, Type: FactorTOTP,
			SecretHash: sealed,
			Params:     dbtypes.JSONMap{"algorithm": TOTPAlgorithm, "digits": TOTPDigits},
			Label:      ptrIfNotEmpty(account),
		})
	}); err != nil {
		return nil, fmt.Errorf("storing the TOTP enrolment: %w", err)
	}

	return &TOTPEnrolment{
		CredentialID: id,
		Secret:       secret,
		URI:          OTPAuthURI(issuer, account, secret),
	}, nil
}

// ConfirmTOTP turns a pending enrolment into a live second factor.
//
// The code proves the person holds the device and copied the secret correctly. Requiring it
// is what stops an enrolment that nobody can satisfy from locking an account.
func (a *Authenticator) ConfirmTOTP(ctx context.Context, tenantID, userID, code string) error {
	factors, err := a.loadFactors(ctx, tenantID, userID, FactorTOTP)
	if err != nil {
		return err
	}
	if len(factors) == 0 {
		return ErrNoSecondFactor
	}
	row := factors[0]

	if _, confirmed := row.Params["confirmed_at"]; confirmed {
		return ErrFactorAlreadyConfirmed
	}

	secret, err := a.openFactorSecret(tenantID, userID, row)
	if err != nil {
		return err
	}
	counter, ok := VerifyTOTP(secret, code, time.Now(), TOTPSkew)
	if !ok {
		return ErrInvalidSecondFactor
	}

	now := time.Now().UTC()
	params := dbtypes.JSONMap{
		"algorithm":    TOTPAlgorithm,
		"digits":       TOTPDigits,
		"confirmed_at": now.Format(time.RFC3339Nano),
		// The counter that has just been spent, so the same code cannot be replayed for
		// the rest of its step.
		"last_counter": strconv.FormatUint(counter, 10),
	}
	if err := a.updateFactor(ctx, tenantID, row.ID, params, &now); err != nil {
		return err
	}

	a.recordFactorEvent(ctx, tenantID, userID, ActionSecondFactorEnrolled, FactorTOTP,
		"a time-based one-time password device was enrolled")
	return nil
}

// VerifySecondFactor checks a presented code against everything the user has enrolled.
//
// TOTP first, then recovery codes, because that is the order of frequency rather than of
// importance. The answer is the same error whichever fails.
func (a *Authenticator) VerifySecondFactor(
	ctx context.Context, tenantID, userID, code string,
) (method string, err error) {
	factors, err := a.loadFactors(ctx, tenantID, userID, secondFactorTypes...)
	if err != nil {
		return "", err
	}

	var confirmed int
	for _, row := range factors {
		if _, ok := row.Params["confirmed_at"]; ok {
			confirmed++
		}
	}
	if confirmed == 0 {
		return "", ErrNoSecondFactor
	}

	for _, row := range factors {
		if _, ok := row.Params["confirmed_at"]; !ok {
			continue
		}
		switch row.Type {
		case FactorTOTP:
			if a.verifyTOTPFactor(ctx, tenantID, userID, row, code) {
				return AMROTP, nil
			}
		case FactorRecoveryCode:
			if a.verifyRecoveryFactor(ctx, tenantID, userID, row, code) {
				return AMRRecoveryCode, nil
			}
		}
	}
	return "", ErrInvalidSecondFactor
}

// verifyTOTPFactor checks one TOTP credential and spends the counter it matched.
func (a *Authenticator) verifyTOTPFactor(
	ctx context.Context, tenantID, userID string, row db.SecondFactorsForUserRow, code string,
) bool {
	secret, err := a.openFactorSecret(tenantID, userID, row)
	if err != nil {
		a.log.Error("could not open a stored TOTP secret",
			"tenant_id", tenantID, "user_id", userID, "credential_id", row.ID, "error", err)
		return false
	}

	counter, ok := VerifyTOTP(secret, code, time.Now(), TOTPSkew)
	if !ok {
		return false
	}

	// RFC 6238 §5.2: a code accepted once is never accepted again, and that includes the
	// rest of its own thirty-second step. Without this, anybody who watched the six digits
	// being typed has them for up to ninety seconds.
	if last, present := row.Params["last_counter"]; present {
		if spent, parseErr := strconv.ParseUint(fmt.Sprint(last), 10, 64); parseErr == nil && counter <= spent {
			a.log.Warn("a TOTP code was presented after it had already been used",
				"tenant_id", tenantID, "user_id", userID, "credential_id", row.ID)
			return false
		}
	}

	now := time.Now().UTC()
	params := cloneParams(row.Params)
	params["last_counter"] = strconv.FormatUint(counter, 10)
	if err := a.updateFactor(ctx, tenantID, row.ID, params, &now); err != nil {
		// The code was right. Failing the login because the bookkeeping write failed
		// would turn a database blip into a lockout; the replay window is the cost.
		a.log.Error("could not record a spent TOTP counter",
			"tenant_id", tenantID, "credential_id", row.ID, "error", err)
	}
	return true
}

// --- enrolment state -----------------------------------------------------------------

// Factors lists what a user has enrolled, for a settings page and for the login to decide
// whether to ask for a second factor at all.
func (a *Authenticator) Factors(ctx context.Context, tenantID, userID string) ([]Factor, error) {
	rows, err := a.loadFactors(ctx, tenantID, userID, secondFactorTypes...)
	if err != nil {
		return nil, err
	}

	out := make([]Factor, 0, len(rows))
	for _, row := range rows {
		factor := Factor{
			ID: row.ID, Type: row.Type, Label: derefOrEmpty(row.Label),
			CreatedAt: row.CreatedAt, LastUsedAt: row.LastUsedAt,
		}
		if raw, ok := row.Params["confirmed_at"]; ok {
			factor.Confirmed = true
			if parsed, parseErr := time.Parse(time.RFC3339Nano, fmt.Sprint(raw)); parseErr == nil {
				factor.ConfirmedAt = parsed
			}
		}
		out = append(out, factor)
	}
	return out, nil
}

// HasSecondFactor reports whether a user can be asked for one.
func (a *Authenticator) HasSecondFactor(ctx context.Context, tenantID, userID string) (bool, error) {
	count, err := a.countConfirmed(ctx, tenantID, userID)
	return count > 0, err
}

// RemoveFactor deletes an enrolled factor.
//
// The caller is responsible for having re-authenticated the person first: removing a second
// factor is the step an attacker holding a stolen session would take before anything else.
func (a *Authenticator) RemoveFactor(ctx context.Context, tenantID, userID, credentialID string) error {
	var removed int64
	if err := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var delErr error
		removed, delErr = db.New(tx).DeleteSecondFactor(ctx, db.DeleteSecondFactorParams{
			TenantID: tenantID, UserID: userID, ID: credentialID,
		})
		return delErr
	}); err != nil {
		return err
	}
	if removed == 0 {
		return ErrNoSecondFactor
	}

	a.recordFactorEvent(ctx, tenantID, userID, ActionSecondFactorRemoved, "",
		"a second factor was removed")
	return nil
}

// SetMFAEnforced turns the requirement on or off for one user.
func (a *Authenticator) SetMFAEnforced(ctx context.Context, tenantID, userID string, enforced bool) error {
	if enforced {
		count, err := a.countConfirmed(ctx, tenantID, userID)
		if err != nil {
			return err
		}
		if count == 0 {
			// Enforcing a factor nobody has enrolled locks the account out of itself.
			return ErrNoSecondFactor
		}
	}

	return a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := db.New(tx).SetUserMFAEnforced(ctx, db.SetUserMFAEnforcedParams{
			TenantID: tenantID, ID: userID, MfaEnforced: enforced,
		})
		return err
	})
}

// --- plumbing -------------------------------------------------------------------------

func (a *Authenticator) loadFactors(
	ctx context.Context, tenantID, userID string, types ...string,
) ([]db.SecondFactorsForUserRow, error) {
	var rows []db.SecondFactorsForUserRow
	err := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var queryErr error
		rows, queryErr = db.New(tx).SecondFactorsForUser(ctx, db.SecondFactorsForUserParams{
			TenantID: tenantID, UserID: userID, Types: types,
		})
		return queryErr
	}, store.ReadOnly())
	return rows, err
}

func (a *Authenticator) countConfirmed(ctx context.Context, tenantID, userID string) (int64, error) {
	var count int64
	err := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var queryErr error
		count, queryErr = db.New(tx).CountConfirmedSecondFactors(ctx,
			db.CountConfirmedSecondFactorsParams{
				TenantID: tenantID, UserID: userID, Types: secondFactorTypes,
			})
		return queryErr
	}, store.ReadOnly())
	return count, err
}

func (a *Authenticator) updateFactor(
	ctx context.Context, tenantID, credentialID string, params dbtypes.JSONMap, usedAt *time.Time,
) error {
	return a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := db.New(tx).UpdateSecondFactorParams(ctx, db.UpdateSecondFactorParamsParams{
			TenantID: tenantID, ID: credentialID, Params: params, LastUsedAt: usedAt,
		})
		return err
	})
}

// openFactorSecret decrypts a stored secret.
func (a *Authenticator) openFactorSecret(tenantID, userID string, row db.SecondFactorsForUserRow) (string, error) {
	if a.keyring == nil {
		return "", errors.New("opening a stored second factor needs the keyring")
	}
	return a.keyring.DecryptString(row.SecretHash, factorAAD(tenantID, userID, row.ID))
}

// factorAAD binds a sealed secret to the row it belongs to.
//
// Additional authenticated data, so a ciphertext copied from one user's row into another's
// fails to open rather than quietly authenticating the wrong person.
func factorAAD(tenantID, userID, credentialID string) []byte {
	return []byte("warden/credential/" + tenantID + "/" + userID + "/" + credentialID)
}

func cloneParams(in dbtypes.JSONMap) dbtypes.JSONMap {
	out := make(dbtypes.JSONMap, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func ptrIfNotEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func derefOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Audit actions for second factors. Enrolling and removing one are both moments an account
// takeover would pass through, so both are in the record.
const (
	ActionSecondFactorEnrolled = "security.second_factor_enrolled"
	ActionSecondFactorRemoved  = "security.second_factor_removed"
	ActionRecoveryCodesIssued  = "security.recovery_codes_issued"
	ActionRecoveryCodeUsed     = "security.recovery_code_used"
)

// Authentication method references, as they appear in `amr` (SPEC §8.2).
const (
	AMRPassword     = "pwd"
	AMROTP          = "otp"
	AMRWebAuthn     = "webauthn"
	AMRRecoveryCode = "rc"
	AMRMFA          = "mfa"
	// AMRMagicLink is RFC 8176's value for a link sent to a registered address. It is
	// one factor, not two: it proves control of a mailbox, which is why a magic link
	// still meets a second factor when the account has one.
	AMRMagicLink = "mail"
)

func (a *Authenticator) recordFactorEvent(ctx context.Context, tenantID, userID, action, factorType, reason string) {
	a.log.Info(reason, "tenant_id", tenantID, "user_id", userID, "type", factorType)
	if a.audit == nil || a.system == nil {
		return
	}
	err := a.system.InSystem(ctx, "recording a second-factor change", func(ctx context.Context, tx pgx.Tx) error {
		_, appendErr := a.audit.Append(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: action,
			TargetType: targetUser, TargetID: userID,
			Reason: reason,
			After:  map[string]any{"type": factorType},
		})
		return appendErr
	})
	if err != nil {
		a.log.Error("could not record a second-factor change in the audit log", "error", err)
	}
}
