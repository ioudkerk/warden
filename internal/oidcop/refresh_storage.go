package oidcop

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ory/fosite"

	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
)

// fosite's refresh-token storage, implemented against Warden's refresh_token table.
//
// This is the join between two designs that would otherwise duplicate each other.
// fosite knows how to rotate a refresh token and, when storage reports one as inactive,
// how to revoke everything descended from the exchange. M1-5 knows what SPEC §8.3
// actually requires: a *family*, revoked as a unit, with a security event. Backing
// fosite's interface with M1-5's table gives one row per token carrying both the
// protocol payload and the family state, so the two can never disagree about whether a
// token has been used — which is the question all of this turns on.
//
// The division of labour:
//
//   - GetRefreshTokenSession returns fosite.ErrInactiveToken for a consumed token. That
//     is the signal fosite's refresh handler tests for, and it is what makes it call
//     handleRefreshTokenReuse.
//   - RevokeRefreshToken and RevokeRefreshTokenMaybeGracePeriod are where fosite's
//     revocation lands, and they delegate to authn.RefreshTokens so the family dies and
//     the security event is raised exactly as M1-5 built it.

// CreateRefreshTokenSession stores a refresh token for a completed exchange.
//
// accessSignature ties the token to the access token issued alongside it. Warden does
// not need it — revocation works by family and by request id, both of which are on the
// row — so it is accepted and ignored rather than stored for nobody to read.
func (s *Storage) CreateRefreshTokenSession(
	ctx context.Context, signature, _ string, request fosite.Requester,
) error {
	tenantID, ok := TenantFrom(ctx)
	if !ok {
		resolved, err := s.clients.TenantOf(ctx, request.GetClient().GetID())
		if err != nil {
			return err
		}
		tenantID = resolved
	}

	form := encodeForm(request.GetRequestForm())
	sessionData, err := encodeSession(request.GetSession())
	if err != nil {
		return err
	}
	subject, wardenSession := subjectAndSession(request.GetSession())
	if wardenSession == nil {
		// Every refresh token hangs off a session: refresh_token's foreign key says so,
		// and "log out everywhere" depends on it. A flow that reached here without one
		// would produce a token nothing can revoke.
		return errors.New(
			"a refresh token was issued for a request with no Warden session; it would " +
				"survive a logout, because revocation walks sessions")
	}

	// A rotation stays in the family it came from. The context carries it when fosite
	// is exchanging one token for another; a fresh login starts a new one.
	familyID, inherited := familyFrom(ctx)
	if !inherited {
		familyID, err = newFamilyID()
		if err != nil {
			return err
		}
	}

	id, err := newTokenID()
	if err != nil {
		return err
	}

	expires := request.GetSession().GetExpiresAt(fosite.RefreshToken)
	if expires.IsZero() {
		expires = time.Now().UTC().Add(30 * 24 * time.Hour)
	}

	return s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return db.New(tx).InsertProviderRefreshToken(ctx, db.InsertProviderRefreshTokenParams{
			ID: id, SessionID: *wardenSession, TenantID: tenantID,
			FamilyID: familyID, TokenHash: signatureHash(signature),
			ClientID:  request.GetClient().GetID(),
			RequestID: ptr(request.GetID()), Subject: subject,
			GrantedScope:    orEmpty(request.GetGrantedScopes()),
			GrantedAudience: orEmpty(request.GetGrantedAudience()),
			Form:            form, SessionData: sessionData,
			IssuedAt: request.GetRequestedAt(), ExpiresAt: expires,
		})
	})
}

// GetRefreshTokenSession rehydrates a refresh token.
//
// A consumed token is returned *with* fosite.ErrInactiveToken, not instead of it.
// fosite needs the request in order to revoke what descended from it, and returning the
// error alone would report the reuse while leaving the family alive — the same mistake
// M1-5 made once and has a test for.
func (s *Storage) GetRefreshTokenSession(
	ctx context.Context, signature string, session fosite.Session,
) (fosite.Requester, error) {
	tenantID, err := s.refreshTenantOf(ctx, signature)
	if err != nil {
		return nil, err
	}

	var row db.ProviderRefreshTokenByHashRow
	err = s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var queryErr error
		row, queryErr = db.New(tx).ProviderRefreshTokenByHash(ctx, db.ProviderRefreshTokenByHashParams{
			TenantID: tenantID, TokenHash: signatureHash(signature),
		})
		return queryErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	client, err := s.clients.ByID(ctx, row.TenantID, row.ClientID)
	if err != nil {
		return nil, err
	}
	form := decodeForm(row.Form)
	if session != nil && len(row.SessionData) > 0 {
		if decodeErr := decodeSession(row.SessionData, session); decodeErr != nil {
			return nil, decodeErr
		}
	}

	request := &fosite.Request{
		ID: derefOr(row.RequestID, ""), RequestedAt: row.IssuedAt, Client: client,
		RequestedScope:    fosite.Arguments(row.GrantedScope),
		GrantedScope:      fosite.Arguments(row.GrantedScope),
		RequestedAudience: fosite.Arguments(row.GrantedAudience),
		GrantedAudience:   fosite.Arguments(row.GrantedAudience),
		Form:              form, Session: session,
	}

	switch {
	case row.ConsumedAt != nil:
		// Consumed and presented again: a replay. ErrInactiveToken is the signal
		// fosite's refresh handler tests for, and it is what makes it revoke the
		// exchange.
		return request, fosite.ErrInactiveToken

	case row.RevokedAt != nil:
		// Revoked but never consumed. This is the token the legitimate client was
		// still holding when somebody else's replay killed the family — collateral
		// damage, not evidence, and M1-5 draws exactly this distinction.
		//
		// ErrNotFound rather than ErrInactiveToken, and the difference matters:
		// ErrInactiveToken sends fosite into its reuse handling, which revokes the
		// family again and raises a second security event for an incident already
		// reported. A live run produced two events for one theft before this line
		// said ErrNotFound.
		return request, fosite.ErrNotFound

	case !time.Now().Before(row.ExpiresAt):
		return request, fosite.ErrTokenExpired
	}
	return request, nil
}

// DeleteRefreshTokenSession is fosite's "this token is finished".
//
// Implemented as a revocation rather than a delete: the row carries the family, and
// deleting it would lose the evidence a later replay is checked against. A deleted token
// answers "never existed", which is precisely the answer that must not be given to a
// replay.
func (s *Storage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	tenantID, err := s.refreshTenantOf(ctx, signature)
	if errors.Is(err, fosite.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		row, queryErr := q.ProviderRefreshTokenByHash(ctx, db.ProviderRefreshTokenByHashParams{
			TenantID: tenantID, TokenHash: signatureHash(signature),
		})
		if errors.Is(queryErr, pgx.ErrNoRows) {
			return nil
		}
		if queryErr != nil {
			return queryErr
		}
		_, consumeErr := q.ConsumeRefreshToken(ctx, db.ConsumeRefreshTokenParams{
			ID: row.ID, At: time.Now().UTC(),
		})
		return consumeErr
	})
}

// RotateRefreshToken consumes the presented token so its successor can be issued.
//
// fosite calls this during a refresh, before creating the replacement. Consuming rather
// than deleting is what makes the next presentation of this token a detectable replay.
func (s *Storage) RotateRefreshToken(ctx context.Context, _, refreshTokenSignature string) error {
	tenantID, err := s.refreshTenantOf(ctx, refreshTokenSignature)
	if errors.Is(err, fosite.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		row, queryErr := q.ProviderRefreshTokenByHash(ctx, db.ProviderRefreshTokenByHashParams{
			TenantID: tenantID, TokenHash: signatureHash(refreshTokenSignature),
		})
		if errors.Is(queryErr, pgx.ErrNoRows) {
			return nil
		}
		if queryErr != nil {
			return queryErr
		}
		consumed, consumeErr := q.ConsumeRefreshToken(ctx, db.ConsumeRefreshTokenParams{
			ID: row.ID, At: time.Now().UTC(),
		})
		if consumeErr != nil {
			return consumeErr
		}
		if consumed == 0 {
			// Somebody consumed it between the read and the write. At this isolation
			// level that is a replay by definition.
			return fosite.ErrInactiveToken
		}
		return nil
	}, store.Isolation(pgx.Serializable))
}

// RevokeRefreshToken is where a detected reuse lands.
//
// fosite passes the *request* id, not a signature, because it wants everything from that
// exchange gone. The family is looked up from it and handed to M1-5, which revokes the
// whole chain, ends the session and raises security.refresh_token_reuse.
func (s *Storage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.revokeFamilyForRequest(ctx, requestID)
}

// RevokeRefreshTokenMaybeGracePeriod is fosite's hook for implementations that allow a
// replayed token briefly.
//
// Warden allows none, and that is a settled decision rather than an omission: once a
// token has been rotated it cannot be used. A grace window is a period in which a stolen
// token is honoured, which is the thing reuse detection exists to close.
func (s *Storage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID, _ string) error {
	return s.revokeFamilyForRequest(ctx, requestID)
}

func (s *Storage) revokeFamilyForRequest(ctx context.Context, requestID string) error {
	tenantID, ok := TenantFrom(ctx)
	if !ok {
		return errors.New("revoking a refresh token family needs a tenant scope")
	}

	var family db.RefreshTokenFamilyByRequestRow
	err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var queryErr error
		family, queryErr = db.New(tx).RefreshTokenFamilyByRequest(ctx,
			db.RefreshTokenFamilyByRequestParams{TenantID: tenantID, RequestID: ptr(requestID)})
		return queryErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}

	// M1-5 owns what happens next: the family dies, the session ends, and the event is
	// written. Doing it here instead would be a second implementation of the one thing
	// this task is actually about.
	//
	// Which of the two it is depends on who asked. fosite calls this same method from
	// two places — its reuse handling, and RFC 7009's revocation endpoint — and the
	// difference between them is the difference between an alarm and a log line. There
	// is no way to tell from the arguments, so the revocation endpoint says so in the
	// context and reuse is the default. Defaulting the other way would silence a real
	// alarm the first time a caller forgot to mark itself.
	if clientRequestedRevocation(ctx) {
		return s.refresh.RevokeFamilyOnRequest(ctx, family.TenantID, family.FamilyID,
			"the client revoked this token")
	}
	return s.refresh.RevokeFamily(ctx, family.TenantID, family.FamilyID,
		"the authorization server detected a replayed token")
}

// clientRevocationKey marks a request as RFC 7009 revocation rather than reuse handling.
type clientRevocationKey struct{}

// WithClientRevocation notes that the revocation about to happen was asked for by the
// client, so it is recorded as routine rather than raised as a security event.
func WithClientRevocation(ctx context.Context) context.Context {
	return context.WithValue(ctx, clientRevocationKey{}, true)
}

func clientRequestedRevocation(ctx context.Context) bool {
	asked, ok := ctx.Value(clientRevocationKey{}).(bool)
	return ok && asked
}

// RevokeAccessToken removes the access tokens of one exchange.
func (s *Storage) RevokeAccessToken(ctx context.Context, requestID string) error {
	tenantID, ok := TenantFrom(ctx)
	if !ok {
		return errors.New("revoking an access token needs a tenant scope")
	}
	return s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, deleteErr := db.New(tx).DeleteOAuthSessionsByRequest(ctx,
			db.DeleteOAuthSessionsByRequestParams{TenantID: tenantID, RequestID: requestID})
		return deleteErr
	})
}

// refreshTenantOf resolves a refresh token signature to its tenant.
func (s *Storage) refreshTenantOf(ctx context.Context, signature string) (string, error) {
	if tenantID, ok := TenantFrom(ctx); ok {
		return tenantID, nil
	}
	if s.system == nil {
		return "", errors.New(
			"resolving a refresh token needs database.system_url when the request has no tenant scope")
	}
	var tenantID string
	err := s.system.InSystem(ctx, "resolving a refresh token to its tenant",
		func(ctx context.Context, tx pgx.Tx) error {
			var resolveErr error
			tenantID, resolveErr = db.New(tx).RefreshTokenTenantByHash(ctx, signatureHash(signature))
			return resolveErr
		}, store.ReadOnly())
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fosite.ErrNotFound
	}
	return tenantID, err
}

// --- the family carried across a rotation -------------------------------------------

type familyKey struct{}

// WithFamily notes that a token about to be issued continues an existing chain.
func WithFamily(ctx context.Context, familyID string) context.Context {
	return context.WithValue(ctx, familyKey{}, familyID)
}

func familyFrom(ctx context.Context) (string, bool) {
	familyID, ok := ctx.Value(familyKey{}).(string)
	return familyID, ok && familyID != ""
}

func newFamilyID() (string, error) { return randomID("rfm") }
func newTokenID() (string, error)  { return randomID("rft") }

func randomID(prefix string) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating an identifier: %w", err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func ptr[T any](v T) *T { return &v }

func derefOr[T any](p *T, fallback T) T {
	if p == nil {
		return fallback
	}
	return *p
}
