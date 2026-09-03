// Package httpapi serves Warden's HTTP surface.
package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Caller is an authenticated service account. Every request carries one, and the
// tenant on it is the only tenant that request may ask about.
type Caller struct {
	ServiceAccountID string
	TenantID         string
	Name             string
}

type callerKey struct{}

// CallerFrom returns the authenticated caller, if there is one.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// errUnauthenticated is returned for every authentication failure, whatever the
// cause. A caller learns that their credential did not work and nothing else:
// distinguishing "no such token" from "expired" from "disabled" tells someone probing
// the endpoint which of those they have found.
var errUnauthenticated = errors.New("unauthenticated")

// authenticate resolves a bearer token to a service account.
//
// The lookup runs on the system pool, and necessarily so: it has to find which tenant
// the token belongs to before a tenant scope can exist. That is the one query in
// Warden that cannot itself be tenant-scoped, which is why service_account is
// registered as a deliberate exception to row-level security rather than an oversight.
func (s *Server) authenticate(ctx context.Context, r *http.Request) (Caller, error) {
	header := r.Header.Get("Authorization")
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "bearer") || token == "" {
		return Caller{}, errUnauthenticated
	}

	// Look the account up by the hash of the token: the token itself is never stored,
	// so a copy of the database does not confer the ability to impersonate an
	// application.
	sum := sha256.Sum256([]byte(token))

	var (
		caller     Caller
		storedHash []byte
		disabledAt *time.Time
		expiresAt  *time.Time
	)
	err := s.system.InSystem(ctx, "authenticating a service account", func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT id, tenant_id, name, token_hash, disabled_at, expires_at
			  FROM service_account WHERE token_hash = $1`, sum[:],
		).Scan(&caller.ServiceAccountID, &caller.TenantID, &caller.Name, &storedHash, &disabledAt, &expiresAt)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Caller{}, errUnauthenticated
		}
		return Caller{}, err
	}

	// The index lookup already matched, so this is belt and braces — but comparing in
	// constant time costs nothing and keeps the habit intact for the places where it
	// will matter.
	if subtle.ConstantTimeCompare(storedHash, sum[:]) != 1 {
		return Caller{}, errUnauthenticated
	}
	if disabledAt != nil {
		return Caller{}, errUnauthenticated
	}
	if expiresAt != nil && !time.Now().Before(*expiresAt) {
		return Caller{}, errUnauthenticated
	}

	return caller, nil
}

// requireCaller wraps a handler so it only runs for an authenticated request.
func (s *Server) requireCaller(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, err := s.authenticate(r.Context(), r)
		if err != nil {
			if errors.Is(err, errUnauthenticated) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="warden"`)
				writeProblem(w, http.StatusUnauthorized, "unauthenticated",
					"A valid service-account token is required in the Authorization header.")
				return
			}
			s.log.Error("authenticating a request", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"The request could not be processed.")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, caller)))
	}
}
