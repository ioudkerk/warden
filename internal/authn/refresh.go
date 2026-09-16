package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/metrics"
	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
)

// refreshTokenBytes is the entropy in a refresh token. SPEC §8.3 says 256 bits, and
// the figure is not negotiable downward: a refresh token is a bearer credential with a
// thirty-day life and no second factor in front of it.
const refreshTokenBytes = 32

// ErrInvalidRefreshToken is returned for a token that is unknown, expired, already
// consumed, revoked, or whose session has ended.
//
// One error for all of them, as everywhere else in this package. The client's correct
// response to each is identical — start a new login — and distinguishing them would
// tell whoever presented a stolen token which part of it Warden recognised.
var ErrInvalidRefreshToken = errors.New("invalid refresh token")

// ErrTokenReuse is returned when a token that had already been consumed is presented
// again. It wraps ErrInvalidRefreshToken, so a caller that only cares about the
// outcome can ignore the distinction and a caller that wants to alert can test for it.
//
// It is deliberately NOT distinguishable in the HTTP response. The family is already
// dead by the time this is returned; telling the presenter that their token was
// recognised as a replay only helps them work out what happened.
var ErrTokenReuse = fmt.Errorf("%w: this token has already been used", ErrInvalidRefreshToken)

// RefreshToken is a newly minted token. The plaintext exists here and nowhere else:
// only its SHA-256 is stored, so a copy of the database does not yield the ability to
// refresh anybody's session.
type RefreshToken struct {
	// Token is the opaque value to hand to the client. Shown once.
	Token     string
	ID        string
	FamilyID  string
	SessionID string
	UserID    string
	TenantID  string
	ClientID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// RefreshTokens issues, rotates and revokes refresh tokens.
//
// The security property it exists for is threat 7 of SPEC §17.1: a stolen refresh
// token must not be usable indefinitely. Rotation alone does not achieve that — a
// thief who refreshes before the legitimate client simply takes over the chain. What
// achieves it is rotation *plus* reuse detection: whichever party refreshes second
// presents a consumed token, and that presentation kills the family for both. The
// legitimate user is logged out, which is the point; they log in again, and the thief
// holds nothing.
type RefreshTokens struct {
	tenant   *store.Store
	system   *store.Store
	sessions *Sessions
	log      *slog.Logger
	audit    *audit.Writer
	metrics  *metrics.Metrics

	absoluteLifetime time.Duration
	idleLifetime     time.Duration

	now func() time.Time
}

// RefreshTokenOptions configure a RefreshTokens.
type RefreshTokenOptions struct {
	// AbsoluteLifetime is measured from the first token in a family, so rotation
	// cannot extend a chain forever.
	AbsoluteLifetime time.Duration
	// IdleLifetime bounds the gap between one rotation and the next.
	IdleLifetime time.Duration
	Log          *slog.Logger
	Audit        *audit.Writer
	// Metrics is optional. Without it a replay is still logged and audited; what is
	// lost is the counter an alert would be keyed on.
	Metrics *metrics.Metrics
}

// NewRefreshTokens builds the refresh-token store.
//
// sessions is required, not optional: revoking a family has to end the session it
// belongs to. Leaving the session alive would mean a detected theft logged the thief
// out of token refresh while leaving their browser session working, which is most of a
// session-fixation attack with the alarm already raised.
func NewRefreshTokens(tenant, system *store.Store, sessions *Sessions, opts RefreshTokenOptions) (*RefreshTokens, error) {
	switch {
	case tenant == nil:
		return nil, errors.New("refresh tokens require the tenant-scoped connection")
	case sessions == nil:
		return nil, errors.New("refresh tokens require the session store: revoking a family ends its session")
	case opts.AbsoluteLifetime <= 0:
		return nil, errors.New("refresh tokens require a positive absolute lifetime")
	case opts.IdleLifetime <= 0:
		return nil, errors.New("refresh tokens require a positive idle lifetime")
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	return &RefreshTokens{
		tenant: tenant, system: system, sessions: sessions, log: log,
		audit: opts.Audit, metrics: opts.Metrics,
		absoluteLifetime: opts.AbsoluteLifetime,
		idleLifetime:     opts.IdleLifetime,
		now:              time.Now,
	}, nil
}

// SetClock replaces the store's notion of the current time. For tests.
func (r *RefreshTokens) SetClock(now func() time.Time) { r.now = now }

// newRefreshToken generates the opaque value and its stored hash.
func newRefreshToken() (token string, hash []byte, err error) {
	raw := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generating a refresh token: %w", err)
	}
	token = "wrt_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// Issue starts a new family for a session that has just been established.
func (r *RefreshTokens) Issue(ctx context.Context, tenantID, sessionID, userID, clientID string) (*RefreshToken, error) {
	// Generated before the transaction opens. The store's retry loop re-runs the whole
	// callback on a serialization failure, and a token minted inside it would be a
	// different token on the second attempt — the caller would be handed one value
	// while the database recorded another. M0-7 states this convention; this is the
	// second place it is load-bearing.
	token, hash, err := newRefreshToken()
	if err != nil {
		return nil, err
	}
	id, err := newID("rft")
	if err != nil {
		return nil, err
	}
	familyID, err := newID("rfm")
	if err != nil {
		return nil, err
	}

	now := r.now().UTC()
	issued := &RefreshToken{
		Token: token, ID: id, FamilyID: familyID,
		SessionID: sessionID, UserID: userID, TenantID: tenantID, ClientID: clientID,
		IssuedAt: now, ExpiresAt: r.chainDeadline(now, now),
	}

	if err := r.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return db.New(tx).InsertRefreshToken(ctx, db.InsertRefreshTokenParams{
			ID: id, SessionID: sessionID, TenantID: tenantID, FamilyID: familyID,
			TokenHash: hash, ClientID: clientID,
			IssuedAt: now, ExpiresAt: issued.ExpiresAt,
		})
	}); err != nil {
		return nil, fmt.Errorf("storing the refresh token: %w", err)
	}
	return issued, nil
}

// chainDeadline returns when a token expires: the sooner of its own idle window and
// the family's absolute ceiling.
func (r *RefreshTokens) chainDeadline(familyStart, now time.Time) time.Time {
	idle := now.Add(r.idleLifetime)
	absolute := familyStart.Add(r.absoluteLifetime)
	if absolute.Before(idle) {
		return absolute
	}
	return idle
}

// Rotate exchanges a refresh token for its successor.
//
// The presented token is consumed and a new one issued into the same family, both in
// one SERIALIZABLE transaction. The isolation level is the load-bearing part and the
// reason M0-7 built store.Isolation: "has this been consumed?" and "consume it" must
// be indivisible, or two simultaneous presentations of the same token both read
// "not consumed", both succeed, and the chain silently forks — which is exactly the
// state reuse detection exists to notice, arrived at without noticing it.
//
// On reuse it returns ErrTokenReuse *after* revoking the family. The revocation is not
// conditional on the caller doing anything with the error.
func (r *RefreshTokens) Rotate(ctx context.Context, presented, clientID string) (*RefreshToken, error) {
	presented = strings.TrimSpace(presented)
	if presented == "" {
		return nil, ErrInvalidRefreshToken
	}
	sum := sha256.Sum256([]byte(presented))

	// Both generated before the transaction, for the reason Issue gives.
	successorToken, successorHash, err := newRefreshToken()
	if err != nil {
		return nil, err
	}
	successorID, err := newID("rft")
	if err != nil {
		return nil, err
	}

	// A client presents a token and no tenant, so the tenant has to be resolved before
	// a tenant scope can exist. That single read is the only part of rotation that runs
	// on the system pool; everything that follows runs under row-level security like
	// any other tenant data. refresh_token is registered as tenant-scoped and stays
	// that way — unlike service_account and setup_token, it needs no RLS exception,
	// because one column is enough to open the scope.
	if r.system == nil {
		return nil, errors.New(
			"refreshing needs database.system_url: a presented token has to be resolved to " +
				"its tenant before a tenant scope can exist")
	}
	var tenantID string
	if err := r.system.InSystem(ctx, "resolving a refresh token to its tenant",
		func(ctx context.Context, tx pgx.Tx) error {
			var resolveErr error
			tenantID, resolveErr = db.New(tx).RefreshTokenTenantByHash(ctx, sum[:])
			return resolveErr
		}, store.ReadOnly()); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	var (
		issued *RefreshToken
		// reuse carries what the family revocation needs, out of the transaction, so
		// the audit write and the session revocation happen after it commits.
		reuse *reuseEvent
	)

	txErr := r.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Reset on every attempt: the retry loop re-runs this callback from the top,
		// and a value left over from an aborted attempt would be reported as if it had
		// happened.
		issued, reuse = nil, nil

		q := db.New(tx)
		row, err := q.RefreshTokenByHash(ctx, sum[:])
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidRefreshToken
		}
		if err != nil {
			return err
		}

		now := r.now().UTC()

		// A consumed token presented again is evidence, and it is treated as evidence
		// whether or not the family is already dead. Kill first, classify second: the
		// revocation below is idempotent, so running it against an already-revoked
		// family costs one no-op UPDATE and closes the case where some token in the
		// family somehow escaped an earlier sweep.
		//
		// Checking revocation first — which this did briefly — makes a replay against
		// a dead family indistinguishable from an ordinary expired-token refusal, and
		// that is exactly the traffic worth seeing: somebody hammering a stolen token
		// looks like nothing at all. What must not happen is *alerting* once per
		// retry, and that is solved by classifying the record rather than by
		// discarding it. See handleReuse.
		if row.ConsumedAt != nil {
			reuse = &reuseEvent{
				tenantID: row.TenantID, familyID: row.FamilyID,
				sessionID: row.SessionID, userID: row.UserID,
				clientID: row.ClientID, tokenID: row.ID,
				firstConsumedAt: *row.ConsumedAt,
				// Whether the alarm has already been raised for this family. It
				// decides how loudly this presentation is reported, not whether it is.
				alreadyRevoked: row.RevokedAt != nil,
			}
			revoked, revokeErr := q.RevokeRefreshTokenFamily(ctx, db.RevokeRefreshTokenFamilyParams{
				TenantID: row.TenantID, FamilyID: row.FamilyID,
			})
			if revokeErr != nil {
				return revokeErr
			}
			reuse.revokedCount = revoked

			// nil, not ErrTokenReuse, and this is the whole reason the reuse signal
			// travels out of the transaction in a variable. pgx.BeginTxFunc rolls back
			// whenever the callback returns an error, so returning the error here would
			// discard the family revocation that had just been written — the detection
			// would report a theft and leave every token in the family live. The
			// revocation is the part that must commit; the error is reported by the
			// caller afterwards.
			return nil
		}

		switch {
		case row.RevokedAt != nil:
			// Revoked but never consumed: this is the token the legitimate client was
			// still holding when the family died. Collateral damage from someone
			// else's replay, or from a logout — not evidence of anything, and logging
			// it as such would bury the presentations that are.
			return ErrInvalidRefreshToken
		case !now.Before(row.ExpiresAt):
			return ErrInvalidRefreshToken
		case row.SessionRevokedAt != nil:
			return ErrInvalidRefreshToken
		case !now.Before(row.SessionExpiresAt):
			return ErrInvalidRefreshToken
		case clientID != "" && row.ClientID != clientID:
			// A token issued to one client presented by another. Not reuse, but not
			// something to quietly honour either.
			return ErrInvalidRefreshToken
		}

		consumed, err := q.ConsumeRefreshToken(ctx, db.ConsumeRefreshTokenParams{ID: row.ID, At: now})
		if err != nil {
			return err
		}
		if consumed == 0 {
			// Another transaction consumed it between the read and this write. At
			// SERIALIZABLE that should surface as a serialization failure and be
			// retried rather than reaching here, but if it ever does it is a replay by
			// definition, and it is handled exactly like one — including committing the
			// revocation rather than returning an error that would roll it back.
			reuse = &reuseEvent{
				tenantID: row.TenantID, familyID: row.FamilyID,
				sessionID: row.SessionID, userID: row.UserID,
				clientID: row.ClientID, tokenID: row.ID,
			}
			revoked, revokeErr := q.RevokeRefreshTokenFamily(ctx, db.RevokeRefreshTokenFamilyParams{
				TenantID: row.TenantID, FamilyID: row.FamilyID,
			})
			if revokeErr != nil {
				return revokeErr
			}
			reuse.revokedCount = revoked
			return nil
		}

		// The absolute deadline is anchored to when the family began — the login —
		// which is what stops rotation extending a chain forever.
		familyStart := row.FamilyStartedAt

		issued = &RefreshToken{
			Token: successorToken, ID: successorID, FamilyID: row.FamilyID,
			SessionID: row.SessionID, UserID: row.UserID, TenantID: row.TenantID,
			ClientID: row.ClientID,
			IssuedAt: now, ExpiresAt: r.chainDeadline(familyStart, now),
		}
		if !issued.ExpiresAt.After(now) {
			// The absolute ceiling has passed. Refusing here rather than issuing a
			// token that is already expired keeps the client from a refresh loop.
			return ErrInvalidRefreshToken
		}

		return q.InsertRefreshToken(ctx, db.InsertRefreshTokenParams{
			ID: successorID, SessionID: row.SessionID, TenantID: row.TenantID,
			FamilyID: row.FamilyID, TokenHash: successorHash, ClientID: row.ClientID,
			IssuedAt: now, ExpiresAt: issued.ExpiresAt,
		})
	}, store.Isolation(pgx.Serializable))

	if txErr != nil {
		return nil, txErr
	}

	// The family revocation committed with the detection, so this runs afterwards and
	// deals with everything outside that transaction: ending the session, and raising
	// the security event M1-5 requires. ErrTokenReuse is returned here rather than from
	// inside the callback, for the reason given there.
	if reuse != nil {
		r.handleReuse(ctx, reuse)
		return nil, ErrTokenReuse
	}
	return issued, nil
}

// reuseEvent is what a detected replay needs to report, carried out of the
// transaction that detected it.
type reuseEvent struct {
	tenantID, familyID, sessionID, userID, clientID, tokenID string
	// reason is what the caller said it was revoking for. It reaches the audit entry,
	// so an investigator reads why rather than inferring it from the action alone.
	reason          string
	firstConsumedAt time.Time
	revokedCount    int64
	// alreadyRevoked means the family had been revoked before this presentation, so
	// the alarm has already been raised once and this is a subsequent attempt.
	alreadyRevoked bool
}

// Audit actions for a replayed refresh token.
//
// Two actions rather than one, because alerting and investigation want different
// things from the same fact. ActionRefreshTokenReuse is the first replay against a live
// family: a token is in two places at once, and somebody should look now. The repeat
// action is every presentation after that — the shape of a stolen token being retried,
// which is worth having in the record and is not worth paging about a second time.
//
// An alert keyed on the first action fires once per incident. A query over both shows
// how hard somebody tried.
const (
	ActionRefreshTokenReuse       = "security.refresh_token_reuse"
	ActionRefreshTokenReuseRepeat = "security.refresh_token_reuse_repeat"

	// ActionRefreshTokenRevoked is the routine one: a client asked for a token to be
	// revoked and it was. Not in the security namespace, because nothing went wrong —
	// and keeping it out of there is what lets an alert match security.* and mean it.
	ActionRefreshTokenRevoked = "oauth.refresh_token_revoked"
)

// reuseReason is what the audit entry says happened, preferring the caller's words.
func reuseReason(given string) string {
	if given != "" {
		return given
	}
	return "a refresh token was presented after it had already been used"
}

// handleReuse ends the session and records the replay.
//
// Nothing here can fail the caller's request: the family is already revoked, which is
// the part that had to be atomic. What is left is containment and reporting, and an
// error in either must be loud rather than fatal.
//
// Every replay is recorded. Only the first is raised as an alarm.
func (r *RefreshTokens) handleReuse(ctx context.Context, e *reuseEvent) {
	action, outcome := ActionRefreshTokenReuse, "detected"
	if e.alreadyRevoked {
		action, outcome = ActionRefreshTokenReuseRepeat, "repeat"
	}
	if r.metrics != nil {
		r.metrics.RefreshTokenReuse.WithLabelValues(outcome).Inc()
	}

	fields := []any{
		"tenant_id", e.tenantID, "user_id", e.userID, "session_id", e.sessionID,
		"family_id", e.familyID, "client_id", e.clientID,
		"tokens_revoked", e.revokedCount, "first_consumed_at", e.firstConsumedAt,
	}
	if e.alreadyRevoked {
		// Warn, not error: the incident is already open. Still logged in full, because
		// "they kept trying for an hour" is the sort of thing that only exists in the
		// record if somebody wrote it down at the time.
		r.log.Warn("a consumed refresh token was presented again; the family was already revoked", fields...)
	} else {
		// The one event in this package that means somebody probably holds a
		// credential they should not.
		r.log.Error("refresh token reuse detected: the family has been revoked", fields...)
	}

	// Ending the session is containment, and it runs on repeats too. It is idempotent,
	// and "kill first, ask questions second" is the right order for a credential that
	// is demonstrably in the wrong hands: if an earlier attempt failed to end the
	// session, this is another chance to.
	if err := r.sessions.Revoke(ctx, e.tenantID, e.sessionID, "refresh token reuse"); err != nil {
		r.log.Error("could not end the session of a reused refresh token",
			"session_id", e.sessionID, "error", err)
	}

	if r.audit == nil || r.system == nil {
		r.log.Warn("refresh token reuse was not recorded in the audit log: " +
			"no audit writer or no database.system_url")
		return
	}
	err := r.system.InSystem(ctx, "recording refresh token reuse", func(ctx context.Context, tx pgx.Tx) error {
		_, appendErr := r.audit.Append(ctx, tx, audit.Entry{
			TenantID:   e.tenantID,
			Action:     action,
			TargetType: targetUser, TargetID: e.userID,
			Reason: reuseReason(e.reason),
			After: map[string]any{
				"family_id":         e.familyID,
				"session_id":        e.sessionID,
				"client_id":         e.clientID,
				"token_id":          e.tokenID,
				"tokens_revoked":    e.revokedCount,
				"first_consumed_at": e.firstConsumedAt.Format(time.RFC3339Nano),
				"already_revoked":   e.alreadyRevoked,
			},
		})
		return appendErr
	})
	if err != nil {
		r.log.Error("could not record refresh token reuse in the audit log", "error", err)
	}
}

// RevokeFamily revokes a whole chain and reports it, for a caller that has already
// detected the replay itself.
//
// The OpenID Provider is that caller: fosite does its own reuse detection — storage
// returns ErrInactiveToken and fosite's refresh handler asks for the exchange to be
// revoked — and this is where that lands, so there is one implementation of what a
// detected reuse means rather than two that can drift apart.
func (r *RefreshTokens) RevokeFamily(ctx context.Context, tenantID, familyID, reason string) error {
	revoked, sample, err := r.revokeFamilyRows(ctx, tenantID, familyID)
	if err != nil || sample == nil {
		return err
	}

	r.handleReuse(ctx, &reuseEvent{
		tenantID: tenantID, familyID: familyID,
		sessionID: sample.SessionID, userID: sample.Subject,
		clientID: sample.ClientID, tokenID: sample.ID,
		revokedCount: revoked, reason: reason,
		// Nothing was revoked because everything already was, so the alarm has been
		// raised for this family before and this presentation is a subsequent attempt.
		// Without this, a caller that revokes an already-dead family — which fosite
		// does, every time somebody retries a stolen token — would raise a fresh alarm
		// per attempt rather than one per incident.
		alreadyRevoked: revoked == 0,
	})
	return nil
}

// RevokeFamilyOnRequest revokes a chain because somebody asked, rather than because
// something went wrong.
//
// The separation from RevokeFamily is the whole point of having two methods. A client
// calling RFC 7009's revocation endpoint is doing exactly what it is supposed to do:
// signing a user out, discarding a credential it no longer needs. Routing that through
// the reuse path would raise security.refresh_token_reuse — an alarm that means
// "somebody probably holds a credential they should not" — for a well-behaved client,
// and an alarm that fires on correct behaviour is one an operator learns to ignore.
//
// It also leaves the browser session alone. Revoking a grant is not signing out: the
// tokens issued to *this* client die, and the person stays signed in to the provider,
// which is what RFC 7009 describes and what the logout endpoint is for otherwise.
func (r *RefreshTokens) RevokeFamilyOnRequest(ctx context.Context, tenantID, familyID, reason string) error {
	revoked, sample, err := r.revokeFamilyRows(ctx, tenantID, familyID)
	if err != nil || sample == nil {
		return err
	}
	if revoked == 0 {
		// Already gone. Revocation is idempotent and RFC 7009 requires a 200 either
		// way, so there is nothing to record: the event was written the first time.
		return nil
	}

	r.log.Info("a refresh token family was revoked at the client's request",
		"tenant_id", tenantID, "family_id", familyID, "client_id", sample.ClientID,
		"user_id", sample.Subject, "tokens_revoked", revoked, "reason", reason)

	if r.audit == nil || r.system == nil {
		return nil
	}
	if auditErr := r.system.InSystem(ctx, "recording a token revocation", func(ctx context.Context, tx pgx.Tx) error {
		_, appendErr := r.audit.Append(ctx, tx, audit.Entry{
			TenantID:   tenantID,
			Action:     ActionRefreshTokenRevoked,
			TargetType: targetUser, TargetID: sample.Subject,
			Reason: reason,
			After: map[string]any{
				"family_id": familyID, "session_id": sample.SessionID,
				"client_id": sample.ClientID, "tokens_revoked": revoked,
			},
		})
		return appendErr
	}); auditErr != nil {
		// Not fatal: the tokens are already dead, which is what the caller asked for.
		r.log.Error("could not record a token revocation in the audit log", "error", auditErr)
	}
	return nil
}

// revokeFamilyRows kills every token in a family and reports what it found.
//
// A nil sample means there was nothing to revoke — the family was swept, or never
// existed — which is not an error for either caller: revocation is idempotent.
func (r *RefreshTokens) revokeFamilyRows(
	ctx context.Context, tenantID, familyID string,
) (int64, *db.RefreshTokenFamilyMemberRow, error) {
	var (
		revoked int64
		sample  db.RefreshTokenFamilyMemberRow
	)
	err := r.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		// Read a member before revoking, for the session and subject the event names.
		member, memberErr := q.RefreshTokenFamilyMember(ctx, db.RefreshTokenFamilyMemberParams{
			TenantID: tenantID, FamilyID: familyID,
		})
		if memberErr != nil {
			return memberErr
		}
		sample = member

		var revokeErr error
		revoked, revokeErr = q.RevokeRefreshTokenFamily(ctx, db.RevokeRefreshTokenFamilyParams{
			TenantID: tenantID, FamilyID: familyID,
		})
		return revokeErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	return revoked, &sample, nil
}

// RevokeForSession kills every refresh token belonging to a session.
//
// This is what a logout has to call, and what session revocation has to call: a
// refresh token that outlives its session is a way back in after signing out.
func (r *RefreshTokens) RevokeForSession(ctx context.Context, tenantID, sessionID string) (int64, error) {
	var revoked int64
	err := r.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var revokeErr error
		revoked, revokeErr = db.New(tx).RevokeRefreshTokensForSession(ctx,
			db.RevokeRefreshTokensForSessionParams{TenantID: tenantID, SessionID: sessionID})
		return revokeErr
	})
	return revoked, err
}

// PurgeExpired removes refresh tokens that can no longer be presented. A worker job.
func (r *RefreshTokens) PurgeExpired(ctx context.Context, olderThan time.Duration) (int64, error) {
	if r.system == nil {
		return 0, errors.New("purging refresh tokens needs database.system_url: it is cross-tenant by nature")
	}
	var deleted int64
	err := r.system.InSystem(ctx, "purging expired refresh tokens", func(ctx context.Context, tx pgx.Tx) error {
		var purgeErr error
		deleted, purgeErr = db.New(tx).DeleteExpiredRefreshTokens(ctx, r.now().Add(-olderThan))
		return purgeErr
	})
	return deleted, err
}
