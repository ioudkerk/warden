package oidcop

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/ory/fosite"

	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
)

// Access token claim assembly (SPEC §8.2).
//
// The access token is a JWT, and what is in it is a trade. Every claim an SDK can read
// locally is a decision it does not have to ask the PDP about; every claim is also a fact
// frozen at issuance that stays true to the token for up to fifteen minutes after it stops
// being true of the user. That is why the lifetime is bounded to fifteen minutes and why
// `wd.perm_rev` is here: it is the tenant's permission revision at issuance, so an SDK
// holding a cached model can tell that its copy is older than the token and go and ask.

// MaxAccessTokenBytes is SPEC §8.2's hard cap.
//
// Four kilobytes, and the figure is not arbitrary: it is roughly where tokens start
// breaking things outside Warden's control. Many HTTP servers default to an 8 KB request
// line and header block, cookies are capped at 4 KB per cookie, and a token that fits
// everywhere is worth more than a token that carries everything.
const MaxAccessTokenBytes = 4096

// AccessTokenFacts is what a token says about a subject beyond their identity.
type AccessTokenFacts struct {
	// Roles are tenant-wide role keys. Resource-scoped roles are deliberately absent:
	// a role scoped to one project says nothing without naming the project, and the
	// token has nowhere to put that.
	Roles []string
	// Groups the subject belongs to, nesting walked outward.
	Groups []string
	// PermRev is the tenant's permission revision at issuance.
	PermRev int64
	// Attrs are the allowlisted user attributes this client may see.
	Attrs map[string]any
	// Status is the subject's lifecycle state, which the caller checks. It is not a
	// claim: a token is issued to an active user or not at all.
	Status string
}

// ErrSubjectNotIssuable is returned when a token cannot be issued for a subject.
//
// The account was deleted, suspended or deprovisioned. SPEC §7.6 makes anything but
// active a denial, and issuing a fresh token for a suspended user would hand out fifteen
// minutes of access that no revocation can reach — the token is verified by signature,
// not by a lookup.
var ErrSubjectNotIssuable = errors.New("no token may be issued for this subject")

// ClaimGrant is what a client was registered to receive in its access tokens.
//
// The zero value is the default and the default is the point: identity, and the revision
// pointer that tells a reader how fresh its own model is. Nothing about what the subject
// may do — that question is answered at /v1/authz/check, where the answer is current,
// revocable and logged.
type ClaimGrant struct {
	Roles      bool
	Groups     bool
	Attributes []string
}

// ClaimGrantFor reads what a client may put in its tokens.
func ClaimGrantFor(client fosite.Client) ClaimGrant {
	warden, ok := client.(*Client)
	if !ok {
		return ClaimGrant{}
	}
	grant := ClaimGrant{Attributes: warden.TokenAttributes}
	for _, claim := range warden.TokenClaims {
		switch claim {
		case TokenClaimRoles:
			grant.Roles = true
		case TokenClaimGroups:
			grant.Groups = true
		}
	}
	return grant
}

// wants reports whether anything beyond identity was granted.
func (g ClaimGrant) wants() bool {
	return g.Roles || g.Groups || len(g.Attributes) > 0
}

// AccessTokenFactsFor reads what a subject's access token should say.
//
// It reads only what the client was granted. A client with the default grant costs one
// query — the subject's status and the tenant revision, both of which are needed whatever
// the token carries — and the two recursive membership walks never run. That is the
// difference between a token endpoint that does constant work and one that pays for a
// role and group expansion on every issuance for facts nobody asked for.
//
// Nothing here is cached. The key would be (tenant revision, subject), which is the
// memoization M2 builds for decisions, and building half of it here would leave two caches
// to invalidate.
func (s *Storage) AccessTokenFactsFor(
	ctx context.Context, tenantID, userID string, grant ClaimGrant,
) (*AccessTokenFacts, error) {
	facts := &AccessTokenFacts{Attrs: map[string]any{}}

	err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)

		// Always read, whatever the client was granted: perm_rev is in every token, and
		// the status check is what stops a suspended user collecting a fresh token that
		// no revocation can reach.
		subject, subjectErr := q.TokenClaimSubject(ctx, db.TokenClaimSubjectParams{
			TenantID: tenantID, UserID: userID,
		})
		if subjectErr != nil {
			return subjectErr
		}
		facts.Status = subject.Status
		facts.PermRev = subject.PermissionRev
		if subject.Status != "active" || !grant.wants() {
			// Nothing further to assemble: either the token will not be issued, or it
			// carries only what is already here.
			return nil
		}
		facts.Attrs = allowedAttrs(subject.Attributes, grant.Attributes)

		if grant.Roles {
			roles, rolesErr := q.TokenClaimRoles(ctx, db.TokenClaimRolesParams{
				TenantID: tenantID, UserID: &userID,
			})
			if rolesErr != nil {
				return rolesErr
			}
			facts.Roles = roles
		}

		if grant.Groups {
			groups, groupsErr := q.TokenClaimGroups(ctx, db.TokenClaimGroupsParams{
				TenantID: tenantID, UserID: &userID,
			})
			if groupsErr != nil {
				return groupsErr
			}
			facts.Groups = groups
		}
		return nil
	}, store.ReadOnly())

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSubjectNotIssuable
	}
	if err != nil {
		return nil, err
	}
	if facts.Status != "active" {
		return nil, ErrSubjectNotIssuable
	}
	return facts, nil
}

// allowedAttrs filters a user's attributes down to what a client may see.
//
// An allowlist rather than a denylist, and empty by default: attributes are arbitrary
// tenant-defined data — they may hold an employee number, a cost centre, a home address —
// and the failure mode of a denylist is that the next attribute somebody adds is disclosed
// to every client until somebody notices.
func allowedAttrs(all map[string]any, allowed []string) map[string]any {
	out := map[string]any{}
	if len(all) == 0 || len(allowed) == 0 {
		return out
	}
	for _, key := range allowed {
		if value, present := all[key]; present {
			out[key] = value
		}
	}
	return out
}

// wardenClaims renders the `wd` block at a given level of truncation.
//
// The order the specification fixes: groups go first, then attributes. It is the right
// order — groups are the claim most likely to be enormous and least likely to be load
// bearing, since a group is a way of assigning roles rather than a thing conditions are
// usually written against, while `wd.attrs` exists precisely so that a condition can be
// evaluated without a round trip.
//
// `wd.roles` and `wd.perm_rev` are never dropped. Without perm_rev a reader cannot tell
// whether its cached model predates the token, which is the one thing that makes local
// evaluation safe at all; and a client that was deliberately granted roles is a client
// with nothing else to fall back on.
func wardenClaims(facts *AccessTokenFacts, grant ClaimGrant, level truncation) map[string]any {
	// perm_rev alone is the default token's `wd`, and it earns its place: it is what lets
	// a reader with a cached model notice that the model is older than the token in its
	// hand. Without it, local evaluation is a guess; with it, a stale cache is detectable.
	wd := map[string]any{"perm_rev": facts.PermRev}

	if grant.Roles {
		wd["roles"] = orEmptyStrings(facts.Roles)
	}
	if grant.Groups && level < dropGroups {
		wd["groups"] = orEmptyStrings(facts.Groups)
	}
	if level < dropAttrs && len(facts.Attrs) > 0 {
		wd["attrs"] = facts.Attrs
	}
	if level > keepEverything {
		// Set whenever anything was dropped, so a reader never mistakes an absent claim
		// for an empty one. An SDK that sees it knows to ask rather than assume.
		wd["truncated"] = true
	}
	return wd
}

// truncation is how much of the `wd` block has been given up to fit the cap.
type truncation int

const (
	keepEverything truncation = iota
	dropGroups
	dropAttrs
)

// String names the level for the log line that records a truncation.
func (t truncation) String() string {
	switch t {
	case dropGroups:
		return "groups"
	case dropAttrs:
		return "groups and attributes"
	default:
		return "nothing"
	}
}
