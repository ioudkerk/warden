package authz

import (
	"context"
	"fmt"
	"time"
)

// Reason codes, as published in docs/api.md and pinned by the conformance corpus.
// They are part of the wire contract, not free text.
const (
	ReasonGrantMatched      = "grant_matched"
	ReasonSubjectNotFound   = "subject_not_found"
	ReasonSubjectInactive   = "subject_inactive"
	ReasonUnknownPermission = "unknown_permission"
	ReasonExplicitDeny      = "explicit_deny"
	ReasonConditionFailed   = "condition_failed"
	ReasonMissingAttribute  = "missing_attribute"
	ReasonMFARequired       = "mfa_required"
	ReasonGrantExpired      = "grant_expired"
	ReasonOutOfScope        = "out_of_scope"
	ReasonNoGrant           = "no_grant"
)

// StatusActive is the only subject status that can produce an allow (SPEC §7.6).
const StatusActive = "active"

// Request is one decision to make.
type Request struct {
	Subject     string
	Permission  string
	Resource    string
	Environment string
	// Attributes are supplied by the caller and take precedence over any registered
	// on the resource: the application is the source of truth for its own objects
	// (SPEC §9.6).
	Attributes map[string]any
	Context    map[string]any
	Now        time.Time
}

// Decision is the outcome, with the consistency token of the model it was evaluated
// against (SPEC §10.5).
type Decision struct {
	Allowed      bool
	Reason       string
	MatchedGrant string
	Revision     int64
}

// Evaluate implements SPEC §10.2 against an already-loaded model.
//
// Where the algorithm leaves the reason for a denial open, the one reported is from
// the candidate that came closest to allowing — a condition that failed is far more
// useful than "no grant" when a grant plainly exists. The full precedence is
// normative and documented in conformance/README.md; every implementation must follow
// it or the corpus stops being portable between them.
func Evaluate(ctx context.Context, m *Model, conds *ConditionSet, req Request) (Decision, error) {
	dec := func(reason string) Decision {
		return Decision{Allowed: false, Reason: reason, Revision: m.Revision}
	}

	// 1. Resolve the subject.
	subject, ok := m.Subjects[req.Subject]
	if !ok {
		return dec(ReasonSubjectNotFound), nil
	}
	if subject.Status != StatusActive {
		return dec(ReasonSubjectInactive), nil
	}

	// The declared surface is checked before any grant, so a misspelled permission
	// reads as a typo rather than as a missing grant.
	want, err := ParsePermission(req.Permission)
	if err != nil {
		return Decision{}, err
	}
	if !m.DeclaredPermissions[req.Permission] {
		return dec(ReasonUnknownPermission), nil
	}

	groups := m.GroupsOf[req.Subject]
	matchesSubject := func(userID, groupID string) bool {
		if groupID != "" {
			return groups[groupID]
		}
		return userID == req.Subject
	}

	// 4. An explicit deny outranks every allow, evaluated before any grant so no
	//    combination of grants can shadow it (SPEC §9.7).
	for i := range m.Denials {
		d := &m.Denials[i]
		if !matchesSubject(d.UserID, d.GroupID) || !d.Permission.Matches(want) {
			continue
		}
		if m.scopeCovers(d.ScopeKind, d.ScopeRef, want, req) {
			return dec(ReasonExplicitDeny), nil
		}
	}

	// 5. Gather candidates: grants whose subject matches and whose role covers the
	//    permission. Whether each applies is then a question of scope and validity,
	//    tracked apart so the denial can say which of the two failed.
	type candidate struct {
		grant     Grant
		condition string // from the role's permission entry, if any
	}
	var (
		candidates    []candidate
		sawExpired    bool
		sawOutOfScope bool
		anyGrantsIt   bool
	)

	grants := make([]Grant, len(m.Grants))
	copy(grants, m.Grants)
	sortGrants(grants)

	for i := range grants {
		g := &grants[i]
		if !matchesSubject(g.UserID, g.GroupID) {
			continue
		}
		permCondition, covered := m.RoleGrants(g.RoleID, want)
		if !covered {
			continue
		}
		anyGrantsIt = true

		if !m.scopeCovers(g.ScopeKind, g.ScopeRef, want, req) {
			sawOutOfScope = true
			continue
		}
		if !validAt(g, req.Now) {
			sawExpired = true
			continue
		}
		candidates = append(candidates, candidate{grant: *g, condition: permCondition})
	}

	if len(candidates) == 0 {
		switch {
		case sawExpired:
			return dec(ReasonGrantExpired), nil
		case sawOutOfScope:
			return dec(ReasonOutOfScope), nil
		case anyGrantsIt:
			return Decision{}, fmt.Errorf("internal: a candidate was lost between partitions")
		default:
			return dec(ReasonNoGrant), nil
		}
	}

	// 6. Evaluate each candidate's constraints; the first that holds allows.
	var sawMissing, sawMFA, sawFailed bool

	for i := range candidates {
		c := &candidates[i]
		role := m.Roles[c.grant.RoleID]
		if role != nil && role.RequiresMFA && !hasSecondFactor(req.Context) {
			sawMFA = true
			continue
		}

		// Both the grant's condition and any condition on the role's permission
		// entry must hold: each narrows, neither widens (SPEC §9.6).
		failed := false
		for _, expr := range []string{c.grant.Condition, c.condition} {
			if expr == "" {
				continue
			}
			result, err := conds.Eval(ctx, expr, m, want, req)
			if err != nil {
				return Decision{}, err
			}
			switch result {
			case CondMissingAttribute:
				sawMissing, failed = true, true
			case CondFalse:
				sawFailed, failed = true, true
			}
			if failed {
				break
			}
		}
		if failed {
			continue
		}

		return Decision{
			Allowed:      true,
			Reason:       ReasonGrantMatched,
			MatchedGrant: c.grant.ID,
			Revision:     m.Revision,
		}, nil
	}

	// 7. Every candidate failed. Report the most actionable cause: an unresolvable
	//    attribute is a configuration error, an MFA requirement is a step the caller
	//    can take, and a false condition is a legitimate policy denial.
	switch {
	case sawMissing:
		return dec(ReasonMissingAttribute), nil
	case sawMFA:
		return dec(ReasonMFARequired), nil
	case sawFailed:
		return dec(ReasonConditionFailed), nil
	default:
		return Decision{}, fmt.Errorf("internal: no candidate allowed and no reason recorded")
	}
}

// scopeCovers implements the scope forms of SPEC §9.5.
func (m *Model) scopeCovers(kind, ref string, want Permission, req Request) bool {
	switch kind {
	case "tenant":
		return true

	case "application":
		return ref == want.App

	case "environment":
		// "billing/prod". An environment-scoped grant cannot be shown to apply to a
		// check that does not say which environment it is in; denying is the safe
		// reading.
		app, env, ok := splitEnvScope(ref)
		return ok && app == want.App && req.Environment != "" && req.Environment == env

	case "resource":
		// Exactly that object, and nothing below it.
		return req.Resource != "" && req.Resource == ref

	case "subtree":
		return req.Resource != "" && m.IsAncestor(ref, req.Resource)

	default:
		return false
	}
}

func splitEnvScope(ref string) (app, env string, ok bool) {
	for i := 0; i < len(ref); i++ {
		if ref[i] == '/' {
			return ref[:i], ref[i+1:], true
		}
	}
	return "", "", false
}

// validAt reports whether a grant's window contains now. The window is half-open:
// valid_from is inclusive and valid_until is the first instant at which the grant no
// longer applies.
func validAt(g *Grant, now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !g.ValidFrom.IsZero() && now.Before(g.ValidFrom) {
		return false
	}
	if g.ValidUntil != nil && !now.Before(*g.ValidUntil) {
		return false
	}
	return true
}

// hasSecondFactor reads the authentication methods from the request context. The
// names match the OIDC amr claim Warden issues (SPEC §8.2).
func hasSecondFactor(ctx map[string]any) bool {
	raw, ok := ctx["amr"]
	if !ok {
		return false
	}
	var values []any
	switch v := raw.(type) {
	case []any:
		values = v
	case []string:
		for _, s := range v {
			values = append(values, s)
		}
	default:
		return false
	}
	for _, v := range values {
		switch v {
		case "otp", "webauthn", "mfa", "hwk":
			return true
		}
	}
	return false
}
