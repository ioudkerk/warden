package reference

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/warden-project/warden/conformance"
)

// Evaluator implements conformance.Evaluator.
type Evaluator struct{}

// New returns the reference evaluator.
func New() *Evaluator { return &Evaluator{} }

// Load compiles a case's model, including every condition expression, so that a
// malformed CEL expression is a load error rather than a per-check surprise.
func (e *Evaluator) Load(_ context.Context, c *conformance.Case) (conformance.Decider, error) {
	m, err := build(c)
	if err != nil {
		return nil, err
	}
	conds, err := compileConditions(c)
	if err != nil {
		return nil, err
	}
	return &decider{model: m, conditions: conds}, nil
}

type decider struct {
	model      *model
	conditions map[string]*condition // keyed by expression text
}

// candidate is a grant that could produce the decision, plus how close it came.
type candidate struct {
	grant conformance.Grant
	order int // declaration order, for a deterministic candidate sequence
}

// Check implements SPEC §10.2. The numbered comments are that algorithm's steps.
//
// Where the algorithm leaves the *reason* for a denial open, this implementation
// reports the one from the candidate that came closest to allowing — a condition
// that failed is more useful than "no grant" when a grant plainly exists. The full
// precedence is documented in ../README.md under "Deny reason precedence", and every
// implementation must follow it or the corpus will not be portable.
func (d *decider) Check(_ context.Context, req conformance.Request) (conformance.Decision, error) {
	t, ok := d.model.tenants[req.Tenant]
	if !ok {
		return conformance.Decision{}, fmt.Errorf("tenant %q is not in the model", req.Tenant)
	}

	// 1. Resolve the subject.
	user, ok := t.users[req.Subject]
	if !ok {
		return deny(conformance.ReasonSubjectNotFound), nil
	}
	if user.Status != conformance.StatusActive {
		return deny(conformance.ReasonSubjectInactive), nil
	}

	// The permission surface is checked before any grant is considered, so a
	// misspelled permission is reported as a typo rather than as a missing grant.
	want, err := parsePermission(req.Permission)
	if err != nil {
		return conformance.Decision{}, err
	}
	if !d.model.declaredPermissions[req.Permission] {
		return deny(conformance.ReasonUnknownPermission), nil
	}

	// 2. Resolve the subject's groups, transitively.
	groups := t.groupsOf(req.Subject)

	subjectMatches := func(s conformance.Subject) bool {
		if s.IsGroup() {
			return groups[s.Group]
		}
		return s.User == req.Subject
	}

	// 4. An explicit deny outranks every allow (SPEC §9.7). Evaluated before any
	//    grant, so no combination of grants can shadow it.
	for _, dn := range t.denials {
		if !subjectMatches(dn.Subject) {
			continue
		}
		pattern, err := parsePermission(dn.Permission)
		if err != nil {
			return conformance.Decision{}, err
		}
		if !pattern.matches(want) {
			continue
		}
		covers, err := d.scopeCovers(t, dn.Scope, want, req)
		if err != nil {
			return conformance.Decision{}, err
		}
		if covers {
			return deny(conformance.ReasonExplicitDeny), nil
		}
	}

	// 5. Gather candidate grants. A grant is a candidate when its subject matches and
	//    its role's expanded permission set covers the requested permission. Whether
	//    it applies is then a question of scope and validity, tracked separately so
	//    the denial can say which of the two failed.
	var (
		inScopeAndValid []candidate
		expired         bool
		outOfScope      bool
		anyGrantsPerm   bool
	)

	for i, g := range t.grants {
		if !subjectMatches(g.Subject) {
			continue
		}
		if !d.roleGrants(g.Role, want) {
			continue
		}
		anyGrantsPerm = true

		covers, err := d.scopeCovers(t, g.Scope, want, req)
		if err != nil {
			return conformance.Decision{}, err
		}
		if !covers {
			outOfScope = true
			continue
		}
		valid, err := validAt(g, req.Now)
		if err != nil {
			return conformance.Decision{}, err
		}
		if !valid {
			expired = true
			continue
		}
		inScopeAndValid = append(inScopeAndValid, candidate{grant: g, order: i})
	}

	if len(inScopeAndValid) == 0 {
		switch {
		case expired:
			return deny(conformance.ReasonGrantExpired), nil
		case outOfScope:
			return deny(conformance.ReasonOutOfScope), nil
		case anyGrantsPerm:
			// Unreachable: a grant that gives the permission is either in scope and
			// valid, out of scope, or expired.
			return conformance.Decision{}, fmt.Errorf("internal: candidate lost between partitions")
		default:
			return deny(conformance.ReasonNoGrant), nil
		}
	}

	// A deterministic order matters: two implementations must agree on which grant
	// produced an allow when a case asserts matched_grant. Declaration order in the
	// case file is the corpus's rule.
	sort.Slice(inScopeAndValid, func(i, j int) bool {
		return inScopeAndValid[i].order < inScopeAndValid[j].order
	})

	// 6. Evaluate each candidate's constraints. The first that holds allows.
	var (
		sawMissingAttribute bool
		sawMFARequired      bool
		sawConditionFailed  bool
	)

	for _, cand := range inScopeAndValid {
		// A role constrained to require MFA cannot be used without a second factor
		// in the authentication context (SPEC §9.3).
		if d.model.roles[cand.grant.Role].RequiresMFA && !hasSecondFactor(req.Context) {
			sawMFARequired = true
			continue
		}

		if cand.grant.Condition != "" {
			result, err := d.conditions[cand.grant.Condition].eval(t, want, req)
			switch {
			case err != nil:
				return conformance.Decision{}, err
			case result == condMissingAttribute:
				sawMissingAttribute = true
				continue
			case result == condFalse:
				sawConditionFailed = true
				continue
			}
		}

		return conformance.Decision{
			Allowed:      true,
			Reason:       conformance.ReasonGrantMatched,
			MatchedGrant: cand.grant.ID,
		}, nil
	}

	// 7. Every candidate failed. Report the most actionable cause: an unresolvable
	//    attribute is a configuration error, an MFA requirement is a step the caller
	//    can take, and a false condition is a legitimate policy denial.
	switch {
	case sawMissingAttribute:
		return deny(conformance.ReasonMissingAttribute), nil
	case sawMFARequired:
		return deny(conformance.ReasonMFARequired), nil
	case sawConditionFailed:
		return deny(conformance.ReasonConditionFailed), nil
	default:
		return conformance.Decision{}, fmt.Errorf("internal: no candidate allowed and no reason recorded")
	}
}

func deny(reason string) conformance.Decision {
	return conformance.Decision{Allowed: false, Reason: reason}
}

// roleGrants reports whether a role's expanded permission set covers want.
func (d *decider) roleGrants(roleKey string, want permission) bool {
	for _, p := range d.model.rolePermissions[roleKey] {
		if p.matches(want) {
			return true
		}
	}
	return false
}

// scopeCovers implements the scope forms of SPEC §9.5.
func (d *decider) scopeCovers(t *tenant, scope string, want permission, req conformance.Request) (bool, error) {
	switch {
	case scope == "tenant":
		return true, nil

	case strings.HasPrefix(scope, "app:"):
		rest := strings.TrimPrefix(scope, "app:")
		appKey, envName, hasEnv := strings.Cut(rest, "/env:")
		if appKey != want.app {
			return false, nil
		}
		if !hasEnv {
			return true, nil
		}
		// An environment-scoped grant cannot be shown to apply to a check that does
		// not say which environment it is in. Denying is the safe reading.
		return req.Environment != "" && req.Environment == envName, nil

	case strings.HasSuffix(scope, "/**"):
		base := strings.TrimSuffix(scope, "/**")
		if req.Resource == "" {
			return false, nil
		}
		return t.isAncestor(base, req.Resource), nil

	default:
		// A bare instance scope covers exactly that object and nothing below it.
		if _, err := parseResourceRef(scope); err != nil {
			return false, fmt.Errorf("grant scope: %w", err)
		}
		return req.Resource != "" && req.Resource == scope, nil
	}
}

// validAt reports whether a grant's validity window contains now. A case with no
// clock may not contain a validity window (enforced by Case.Validate), so the zero
// time means "no time dependence" and everything is valid.
func validAt(g conformance.Grant, now time.Time) (bool, error) {
	if g.ValidFrom == "" && g.ValidUntil == "" {
		return true, nil
	}
	if now.IsZero() {
		return false, fmt.Errorf("grant %q has a validity window but the check has no evaluation time", g.ID)
	}
	if g.ValidFrom != "" {
		from, err := time.Parse(time.RFC3339, g.ValidFrom)
		if err != nil {
			return false, err
		}
		if now.Before(from) {
			return false, nil
		}
	}
	if g.ValidUntil != "" {
		until, err := time.Parse(time.RFC3339, g.ValidUntil)
		if err != nil {
			return false, err
		}
		// The window is half-open: valid_until is the first instant at which the
		// grant no longer applies.
		if !now.Before(until) {
			return false, nil
		}
	}
	return true, nil
}

// hasSecondFactor reads the authentication methods from the check context. The names
// match the OIDC amr claim Warden issues (SPEC §8.2).
func hasSecondFactor(ctx map[string]any) bool {
	raw, ok := ctx["amr"]
	if !ok {
		return false
	}
	values, ok := raw.([]any)
	if !ok {
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
