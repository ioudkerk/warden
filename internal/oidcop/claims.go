package oidcop

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

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

// AccessTokenFactsFor reads what a subject's access token should say.
//
// Three queries on the tenant-scoped pool. They are not cached, and the honest reason is
// that the cache key would be (tenant revision, user) — which is the memoization M2 builds
// for decisions — and building half of it here would mean two caches to invalidate. At one
// token per ten minutes per session this is not the hot path; the decision API is.
func (s *Storage) AccessTokenFactsFor(
	ctx context.Context, tenantID, userID string, allowedAttributes []string,
) (*AccessTokenFacts, error) {
	facts := &AccessTokenFacts{Attrs: map[string]any{}}

	err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)

		subject, subjectErr := q.TokenClaimSubject(ctx, db.TokenClaimSubjectParams{
			TenantID: tenantID, UserID: userID,
		})
		if subjectErr != nil {
			return subjectErr
		}
		facts.Status = subject.Status
		facts.PermRev = subject.PermissionRev
		if subject.Status != "active" {
			// Read but not assembled: there is nothing to put in a token that will not
			// be issued.
			return nil
		}
		facts.Attrs = allowedAttrs(subject.Attributes, allowedAttributes)

		roles, rolesErr := q.TokenClaimRoles(ctx, db.TokenClaimRolesParams{
			TenantID: tenantID, UserID: &userID,
		})
		if rolesErr != nil {
			return rolesErr
		}
		facts.Roles = roles

		groups, groupsErr := q.TokenClaimGroups(ctx, db.TokenClaimGroupsParams{
			TenantID: tenantID, UserID: &userID,
		})
		if groupsErr != nil {
			return groupsErr
		}
		facts.Groups = groups
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
// `wd.roles` and `wd.perm_rev` are never dropped. Without perm_rev an SDK cannot tell
// whether its cached model predates the token, which is the one thing that makes local
// evaluation safe at all.
func wardenClaims(facts *AccessTokenFacts, level truncation) map[string]any {
	wd := map[string]any{
		"roles":    orEmptyStrings(facts.Roles),
		"perm_rev": facts.PermRev,
	}
	if level < dropGroups {
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
