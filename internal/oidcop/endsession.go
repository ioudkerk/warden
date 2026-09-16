package oidcop

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/store/db"
)

// EndSession revokes a browser session and everything issued through it.
//
// "Everything" is not decoration. Nothing in fosite's storage interfaces consults a
// Warden session — a refresh token is valid because its own row says so — so a logout
// that only revoked the session would leave a thirty-day refresh token working, and the
// person who just signed out could be signed back in by any client still holding one.
// That is the gap this closes, and it is why oauth_session carries a session_id column
// at all.
//
// The order is deliberate: the longest-lived credential dies first. If the process
// stopped halfway, a revoked refresh token with a live session means the user is still
// signed in and can get new tokens; a revoked session with a live refresh token means
// somebody signed out and a credential outlived them.
func (s *Storage) EndSession(ctx context.Context, tenantID, sessionID, reason string) error {
	switch {
	case tenantID == "" || sessionID == "":
		return errors.New("ending a session needs the tenant and the session")
	case s.sessions == nil:
		return errors.New("ending a session needs the session store")
	}

	if _, err := s.refresh.RevokeForSession(ctx, tenantID, sessionID); err != nil {
		return fmt.Errorf("revoking the session's refresh tokens: %w", err)
	}

	if err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, deleteErr := db.New(tx).DeleteOAuthSessionsForSession(ctx,
			db.DeleteOAuthSessionsForSessionParams{TenantID: tenantID, SessionID: &sessionID})
		return deleteErr
	}); err != nil {
		return fmt.Errorf("removing the session's tokens and codes: %w", err)
	}

	return s.sessions.Revoke(ctx, tenantID, sessionID, reason)
}
