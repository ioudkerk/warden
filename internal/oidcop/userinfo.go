package oidcop

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ory/fosite"

	"github.com/warden-project/warden/internal/store/db"
)

// The claims the userinfo endpoint releases (SPEC §7.7).
//
// Scope decides what is released, not the client's appetite: a token granted only
// "openid" yields the subject and nothing else. That is the whole point of the scope
// having been asked for and granted, and an endpoint that returns the email address
// regardless makes "email" decoration rather than authorization.

// ErrSubjectUnavailable is returned when a token's subject can no longer be served:
// the user was deleted, suspended or deprovisioned after the token was issued.
//
// One error for all three. The caller turns it into an invalid_token, which is the
// truthful answer — a token for an account that may no longer act is not a valid token —
// and which does not tell the holder of a stolen token what became of the account.
var ErrSubjectUnavailable = errors.New("the subject of this token can no longer be served")

// Profile is what Warden knows about a user, before any scope is applied.
type Profile struct {
	UserID        string
	Email         string
	EmailVerified bool
	Name          string
	Status        string
	Attributes    map[string]any
	UpdatedAt     time.Time
}

// Profile reads a user, for the userinfo endpoint.
//
// Tenant-scoped, so row-level security is the second guard on top of the explicit
// predicate: the tenant comes from the access token's own session, and a token is only
// ever able to name a subject in the tenant it was issued for.
func (s *Storage) Profile(ctx context.Context, tenantID, userID string) (*Profile, error) {
	var row db.UserProfileRow
	err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var queryErr error
		row, queryErr = db.New(tx).UserProfile(ctx, db.UserProfileParams{
			TenantID: tenantID, ID: userID,
		})
		return queryErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSubjectUnavailable
	}
	if err != nil {
		return nil, err
	}
	if row.Status != "active" {
		// Suspended, deprovisioned, or invited and never activated. M1-10 will kill the
		// tokens at the moment the status changes; until then this is what stops a
		// token outliving the account's right to use it, and it is worth keeping
		// afterwards as the second check on the same rule.
		return nil, ErrSubjectUnavailable
	}

	return &Profile{
		UserID: row.ID, Email: row.Email, EmailVerified: row.EmailVerified,
		Name: row.DisplayName, Status: row.Status,
		Attributes: row.Attributes, UpdatedAt: row.UpdatedAt,
	}, nil
}

// UserInfoClaims assembles the userinfo response for one set of granted scopes.
//
// `sub` is unconditional: OpenID Connect Core §5.3.2 requires it, and a relying party
// compares it with the `sub` of the id token to be sure the two describe the same
// person. Everything else is gated.
func UserInfoClaims(p *Profile, granted fosite.Arguments, tenantID string) map[string]any {
	claims := map[string]any{"sub": p.UserID}

	// The tenant travels with the subject. Warden's subject identifiers are unique
	// across the deployment, so this is not needed to disambiguate them — it is here
	// because a relying party serving several tenants routes on it, and it is already
	// in the id token as `tid`.
	if tenantID != "" {
		claims["tid"] = tenantID
	}

	if granted.Has("email") {
		claims["email"] = p.Email
		claims["email_verified"] = p.EmailVerified
	}
	if granted.Has("profile") {
		if p.Name != "" {
			claims["name"] = p.Name
		}
		if !p.UpdatedAt.IsZero() {
			claims["updated_at"] = p.UpdatedAt.Unix()
		}
	}
	return claims
}
