package authz

import (
	"fmt"
	"sort"
	"strings"
	"time"

	celast "cel.dev/cel-go/common/ast"
)

// Explanation is the derivation behind a decision (SPEC §10.3).
//
// It answers the question a reason code cannot: not "denied" but "denied because
// this grant, which does reach this object, carries a condition that compared 90000
// against a limit of 50000". Every support conversation that begins "why can't this
// user…" ends with one of these, and §14.2's simulator is built on it.
//
// It leaks policy structure, so it is returned only from /v1/authz/explain — never
// from a plain check.
type Explanation struct {
	// Considered lists every grant whose subject and permission matched, in the
	// order the engine tried them, each with what became of it. A grant that was
	// never a candidate is not listed: the interesting set is the near misses.
	Considered []ConsideredGrant `json:"considered_grants"`

	// Denials lists explicit denies that matched. One of these ends evaluation
	// immediately, so at most one can be decisive.
	Denials []ConsideredDenial `json:"explicit_denials,omitempty"`

	// SubjectRoles are the roles the subject holds, direct and group-derived. Often
	// the answer on its own: the user is simply not in the group they thought.
	SubjectRoles  []string `json:"subject_roles"`
	SubjectGroups []string `json:"subject_groups"`

	// Notes records anything that stopped evaluation before grants were considered:
	// an inactive subject, an undeclared permission.
	Notes []string `json:"notes,omitempty"`
}

// ConsideredGrant is one grant the engine looked at and what happened to it.
type ConsideredGrant struct {
	GrantID string `json:"grant_id"`
	Role    string `json:"role"`
	Scope   string `json:"scope"`

	// Outcome is one of: matched, out_of_scope, expired, condition_failed,
	// missing_attribute, mfa_required, not_reached.
	Outcome string `json:"outcome"`

	// Conditions holds each condition attached to this grant, with the values its
	// expression actually read. This is the part that ends arguments.
	Conditions []ConditionTrace `json:"conditions,omitempty"`

	// Detail explains an outcome that needs more than its name.
	Detail string `json:"detail,omitempty"`
}

// ConsideredDenial is an explicit deny that matched the permission.
type ConsideredDenial struct {
	DenialID   string `json:"denial_id"`
	Permission string `json:"permission"`
	Scope      string `json:"scope"`
	Decisive   bool   `json:"decisive"`
}

// ConditionTrace is one condition expression and how it evaluated.
type ConditionTrace struct {
	Expression string `json:"expression"`
	// Result is true, false, or missing_attribute.
	Result string `json:"result"`
	// Values maps each path the expression read to the value it found. A path the
	// expression referenced but that was absent maps to null, which is usually the
	// whole explanation.
	Values map[string]any `json:"values,omitempty"`
}

// Outcomes for a considered grant.
const (
	OutcomeMatched          = "matched"
	OutcomeOutOfScope       = "out_of_scope"
	OutcomeExpired          = "expired"
	OutcomeConditionFailed  = "condition_failed"
	OutcomeMissingAttribute = "missing_attribute"
	OutcomeMFARequired      = "mfa_required"
	// OutcomeNotReached marks a candidate the engine never tried, because an earlier
	// one already allowed. Listing it is honest: it says the decision did not depend
	// on this grant, rather than implying it failed.
	OutcomeNotReached = "not_reached"
)

// trace accumulates an explanation while a decision is being made. A nil *trace is
// valid and records nothing, so the fast path pays for none of this.
type trace struct{ e *Explanation }

func newTrace(explain bool) *trace {
	if !explain {
		return nil
	}
	// The slices start empty rather than nil so they marshal as [] and never as
	// null. A client should not have to handle both spellings of "nothing here".
	return &trace{e: &Explanation{
		Considered:    []ConsideredGrant{},
		SubjectRoles:  []string{},
		SubjectGroups: []string{},
	}}
}

func (t *trace) enabled() bool { return t != nil }

func (t *trace) note(format string, args ...any) {
	if t == nil {
		return
	}
	t.e.Notes = append(t.e.Notes, fmt.Sprintf(format, args...))
}

func (t *trace) subject(roles, groups []string) {
	if t == nil {
		return
	}
	sort.Strings(roles)
	sort.Strings(groups)
	t.e.SubjectRoles = roles
	t.e.SubjectGroups = groups
}

func (t *trace) denial(d *Denial, decisive bool) {
	if t == nil {
		return
	}
	t.e.Denials = append(t.e.Denials, ConsideredDenial{
		DenialID:   d.ID,
		Permission: d.Permission.String(),
		Scope:      scopeString(d.ScopeKind, d.ScopeRef),
		Decisive:   decisive,
	})
}

func (t *trace) grant(g *Grant, roleKey, outcome, detail string, conditions []ConditionTrace) {
	if t == nil {
		return
	}
	t.e.Considered = append(t.e.Considered, ConsideredGrant{
		GrantID:    g.ID,
		Role:       roleKey,
		Scope:      scopeString(g.ScopeKind, g.ScopeRef),
		Outcome:    outcome,
		Detail:     detail,
		Conditions: conditions,
	})
}

func (t *trace) result() *Explanation {
	if t == nil {
		return nil
	}
	return t.e
}

// scopeString renders a scope the way an administrator wrote it, rather than as the
// two columns it is stored in.
func scopeString(kind, ref string) string {
	switch kind {
	case "tenant":
		return "tenant"
	case "application":
		return "app:" + ref
	case "environment":
		if app, env, ok := strings.Cut(ref, "/"); ok {
			return "app:" + app + "/env:" + env
		}
		return "app:" + ref
	case "subtree":
		return ref + "/**"
	default:
		return ref
	}
}

// referencedPaths extracts the dotted variable paths an expression reads, so an
// explanation can report the values it actually saw.
//
// Walking the compiled AST rather than the source text matters: it finds exactly what
// CEL resolved, it cannot be fooled by a path appearing inside a string literal, and
// it survives whitespace and comments.
func referencedPaths(a *celast.AST) []string {
	seen := map[string]bool{}

	celast.PostOrderVisit(a.Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		if e.Kind() != celast.SelectKind {
			return
		}
		// Only record a complete chain: for subject.attributes.department, the walk
		// also visits subject.attributes, and reporting both is noise.
		if path, ok := selectPath(e); ok {
			for prefix := range seen {
				if strings.HasPrefix(path, prefix+".") {
					delete(seen, prefix)
				}
			}
			shadowed := false
			for other := range seen {
				if strings.HasPrefix(other, path+".") {
					shadowed = true
					break
				}
			}
			if !shadowed {
				seen[path] = true
			}
		}
	}))

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// selectPath reconstructs a dotted path from a chain of select expressions rooted at
// an identifier. Anything else — an index, a call — has no stable name to report.
func selectPath(e celast.Expr) (string, bool) {
	var parts []string
	cur := e
	for cur.Kind() == celast.SelectKind {
		sel := cur.AsSelect()
		if sel.IsTestOnly() {
			return "", false
		}
		parts = append(parts, sel.FieldName())
		cur = sel.Operand()
	}
	if cur.Kind() != celast.IdentKind {
		return "", false
	}
	parts = append(parts, cur.AsIdent())

	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "."), true
}

// resolvePath walks a dotted path through the activation. A path that is absent
// resolves to nil, which is what the explanation should say: the expression asked for
// something that was not there.
func resolvePath(activation map[string]any, path string) any {
	var cur any = activation
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	return cur
}

// roleKey returns a role's human-readable key, for an explanation that a person
// reads rather than a machine.
func (m *Model) roleKey(roleID string) string {
	if r, ok := m.Roles[roleID]; ok {
		return r.Key
	}
	return roleID
}

// roleKeysFor lists every role the subject holds, direct and group-derived. Often the
// answer on its own: the user is not in the group they believed they were.
func (m *Model) roleKeysFor(subjectID string) []string {
	groups := m.GroupsOf[subjectID]
	seen := map[string]bool{}
	for i := range m.Grants {
		g := &m.Grants[i]
		if g.UserID == subjectID || (g.GroupID != "" && groups[g.GroupID]) {
			seen[m.roleKey(g.RoleID)] = true
		}
	}
	return sortedKeys(seen)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func resourceOrNothing(ref string) string {
	if ref == "" {
		return "a check with no resource"
	}
	return ref
}

// validityDetail says which end of the window the clock fell outside, because "the
// grant expired" and "the grant has not started" are different problems.
func validityDetail(g *Grant, now time.Time) string {
	if !g.ValidFrom.IsZero() && now.Before(g.ValidFrom) {
		return fmt.Sprintf("valid from %s, which is after the evaluation time %s",
			g.ValidFrom.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if g.ValidUntil != nil {
		return fmt.Sprintf("valid until %s, which is at or before the evaluation time %s",
			g.ValidUntil.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return "outside its validity window"
}
