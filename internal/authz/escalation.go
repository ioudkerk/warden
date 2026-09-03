package authz

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Privilege escalation through role assignment is threat 3 of SPEC §17.1: a subject
// may never assign a role containing permissions they do not themselves hold, unless
// they hold warden.role:assign_any.
//
// The rule is easy to state and easy to get subtly wrong, because "hold" has three
// dimensions and all of them can leak authority:
//
//   - which permissions. The obvious one.
//   - at what scope. An assigner who holds invoice:approve on one project must not
//     be able to grant it tenant-wide; that is escalation with the permission set
//     unchanged.
//   - for how long. An assigner whose own grant expires on Friday must not be able
//     to grant the same role permanently, or a time-boxed elevation becomes a
//     permanent one in a single step.
//
// Conditions are the fourth: a permission an assigner holds only when the amount is
// under fifty thousand is not the same permission unconditionally. This guard treats
// a conditional holding as not holding it at all for the purpose of delegation. That
// is deliberately conservative — it means a conditional approver cannot delegate
// approval — and the conservative direction is the correct one, because the
// alternative silently widens a constraint someone chose.

// Administrative permissions, declared by the built-in warden application.
const (
	PermRoleAssign    = "warden.role:assign"
	PermRoleAssignAny = "warden.role:assign_any"
	PermDenialCreate  = "warden.denial:create"
)

// EscalationError explains why an assignment was refused. It is a value rather than a
// string because the management API returns it and the audit log records it: "you may
// not grant this" is not an answer anybody can act on.
type EscalationError struct {
	// Missing lists the permissions the role would confer that the assigner does not
	// hold at a scope covering the assignment.
	Missing []string
	// Reason is one of: not_permitted, missing_permissions, scope_too_broad,
	// validity_too_long, not_assignable_by.
	Reason string
	Detail string
}

func (e *EscalationError) Error() string {
	if len(e.Missing) == 0 {
		return "assignment refused: " + e.Detail
	}
	return fmt.Sprintf("assignment refused: %s (%s)", e.Detail, strings.Join(e.Missing, ", "))
}

// Refusal reasons.
const (
	RefusalNotPermitted       = "not_permitted"
	RefusalMissingPermissions = "missing_permissions"
	RefusalValidityTooLong    = "validity_too_long"
	RefusalNotAssignableBy    = "not_assignable_by"
)

// AssignmentRequest describes an assignment being attempted.
type AssignmentRequest struct {
	// Assigner is the subject making the assignment.
	Assigner string
	// RoleID is the role being assigned.
	RoleID string
	// ScopeKind and ScopeRef are where it would apply.
	ScopeKind string
	ScopeRef  string
	// ValidUntil bounds the new grant. Nil means it never expires.
	ValidUntil *time.Time
	// Now is the evaluation time.
	Now time.Time
}

// CanAssign reports whether the assigner may create this assignment, or explains why
// not. A nil return means yes.
func CanAssign(m *Model, req AssignmentRequest) *EscalationError {
	held := m.heldPermissions(req.Assigner, req.Now)

	// Assigning at all is a permission. Without it there is nothing to check further.
	if !held.covers(m, PermRoleAssign, ScopeTenant, "") && !held.covers(m, PermRoleAssignAny, ScopeTenant, "") {
		return &EscalationError{
			Reason: RefusalNotPermitted,
			Detail: fmt.Sprintf("%s holds neither %s nor %s", req.Assigner, PermRoleAssign, PermRoleAssignAny),
		}
	}

	role, ok := m.Roles[req.RoleID]
	if !ok {
		return &EscalationError{
			Reason: RefusalNotPermitted,
			Detail: fmt.Sprintf("role %s does not exist in this tenant", req.RoleID),
		}
	}

	// assign_any is the documented escape hatch (SPEC §17.1). It skips the
	// containment check and nothing else: an assigner with it can still not exceed
	// their own validity window, because that would turn a time-boxed elevation into
	// a permanent one.
	unrestricted := held.covers(m, PermRoleAssignAny, ScopeTenant, "")

	if !unrestricted {
		var missing []string
		for _, p := range role.Permissions {
			// A permission the role grants only under a condition is still a
			// permission the assigner must hold: the condition narrows who can use
			// it, not who can hand it out.
			if !held.covers(m, p.String(), req.ScopeKind, req.ScopeRef) {
				missing = append(missing, p.String())
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return &EscalationError{
				Reason:  RefusalMissingPermissions,
				Missing: missing,
				Detail: fmt.Sprintf(
					"%s would confer permissions %s does not hold at %s; hold them, or hold %s",
					role.Key, req.Assigner, scopeString(req.ScopeKind, req.ScopeRef), PermRoleAssignAny),
			}
		}
	}

	// Time. An assigner cannot grant beyond their own expiry, whatever else they
	// hold: otherwise a four-hour elevation is a permanent one in two steps.
	if limit, bounded := held.expiresAt(req.Now); bounded {
		if req.ValidUntil == nil {
			return &EscalationError{
				Reason: RefusalValidityTooLong,
				Detail: fmt.Sprintf(
					"%s's own authority expires at %s, so it cannot create a grant that never expires",
					req.Assigner, limit.Format(time.RFC3339)),
			}
		}
		if req.ValidUntil.After(limit) {
			return &EscalationError{
				Reason: RefusalValidityTooLong,
				Detail: fmt.Sprintf(
					"%s's own authority expires at %s, before the requested %s",
					req.Assigner, limit.Format(time.RFC3339), req.ValidUntil.Format(time.RFC3339)),
			}
		}
	}

	return nil
}

// CanCreateDenial reports whether the subject may write an explicit deny. Denies
// restrict rather than widen, so containment does not apply — but SPEC §9.7 makes
// them administrator-only and always justified, because a deny that nobody can
// account for is as hard to unpick as a grant nobody can account for.
func CanCreateDenial(m *Model, subject, reason string, now time.Time) *EscalationError {
	if strings.TrimSpace(reason) == "" {
		return &EscalationError{
			Reason: RefusalNotPermitted,
			Detail: "an explicit denial requires a written justification (SPEC §9.7)",
		}
	}
	if !m.heldPermissions(subject, now).covers(m, PermDenialCreate, ScopeTenant, "") {
		return &EscalationError{
			Reason: RefusalNotPermitted,
			Detail: fmt.Sprintf("%s does not hold %s", subject, PermDenialCreate),
		}
	}
	return nil
}

// holding is one permission a subject holds, and where.
type holding struct {
	scopeKind string
	scopeRef  string
}

// heldSet is what a subject holds, unconditionally, right now.
type heldSet struct {
	// byPermission maps a permission pattern — which may contain wildcards, since a
	// grant may — to the scopes it is held at.
	byPermission map[string][]holding
	// earliestExpiry is when the subject's authority runs out, if it is bounded at
	// all. Used for the validity check.
	earliestExpiry time.Time
	bounded        bool
}

// heldPermissions computes what a subject holds unconditionally at this instant.
//
// Conditional grants are excluded, and so are conditional permission entries within a
// role. A permission held only when some condition holds is not one the subject can
// hand over unconditionally, and working out whether a narrower condition implies a
// wider one is a question this guard should not be trying to answer.
func (m *Model) heldPermissions(subject string, now time.Time) *heldSet {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	held := &heldSet{byPermission: map[string][]holding{}}
	groups := m.GroupsOf[subject]

	for i := range m.Grants {
		g := &m.Grants[i]
		if g.UserID != subject && (g.GroupID == "" || !groups[g.GroupID]) {
			continue
		}
		if g.Condition != "" {
			continue // conditional: see above
		}
		if !validAt(g, now) {
			continue
		}

		role, ok := m.Roles[g.RoleID]
		if !ok {
			continue
		}
		// A role whose use requires a second factor still confers what it confers;
		// MFA gates using the role, not holding it.
		for _, p := range role.Permissions {
			if role.PermissionConditions[p.String()] != "" {
				continue
			}
			key := p.String()
			held.byPermission[key] = append(held.byPermission[key],
				holding{scopeKind: g.ScopeKind, scopeRef: g.ScopeRef})
		}
	}

	// The subject's authority lasts as long as their longest-lived grant. A subject
	// with one permanent grant is not time-bounded at all.
	horizon, bounded := time.Time{}, true
	for i := range m.Grants {
		g := &m.Grants[i]
		if g.UserID != subject && (g.GroupID == "" || !groups[g.GroupID]) {
			continue
		}
		if !validAt(g, now) {
			continue
		}
		if g.ValidUntil == nil {
			bounded = false
			break
		}
		if g.ValidUntil.After(horizon) {
			horizon = *g.ValidUntil
		}
	}
	held.bounded = bounded && !horizon.IsZero()
	held.earliestExpiry = horizon

	return held
}

// expiresAt reports when the subject's authority ends, if it is bounded.
func (h *heldSet) expiresAt(_ time.Time) (time.Time, bool) {
	return h.earliestExpiry, h.bounded
}

// covers reports whether the set contains want at a scope that reaches targetScope.
func (h *heldSet) covers(m *Model, want, targetKind, targetRef string) bool {
	wantPerm, err := ParsePermission(want)
	if err != nil {
		return false
	}
	for pattern, holdings := range h.byPermission {
		held, parseErr := ParsePermission(pattern)
		if parseErr != nil || !held.Matches(wantPerm) {
			continue
		}
		for _, at := range holdings {
			if scopeReaches(m, at.scopeKind, at.scopeRef, targetKind, targetRef) {
				return true
			}
		}
	}
	return false
}

// scopeReaches reports whether a permission held at (heldKind, heldRef) extends to an
// assignment at (targetKind, targetRef).
//
// It errs toward false. Every case it cannot prove is one where granting would be a
// widening, and the cost of a false negative is an administrator being told to ask
// for a permission they arguably already have — while the cost of a false positive is
// the escalation this whole file exists to prevent.
func scopeReaches(m *Model, heldKind, heldRef, targetKind, targetRef string) bool {
	switch heldKind {
	case ScopeTenant:
		// Tenant-wide reaches everything in the tenant.
		return true

	case ScopeApplication:
		switch targetKind {
		case ScopeTenant:
			return false // narrower cannot reach wider
		case ScopeApplication:
			return heldRef == targetRef
		case ScopeEnvironment:
			app, _, ok := strings.Cut(targetRef, "/")
			return ok && app == heldRef
		case ScopeResource, ScopeSubtree:
			ref, err := ParseResourceRef(targetRef)
			return err == nil && ref.App == heldRef
		}

	case ScopeEnvironment:
		// An environment-scoped holding reaches only the identical environment. It
		// cannot be shown to cover a resource, because a resource reference says
		// nothing about which environment it belongs to.
		return targetKind == ScopeEnvironment && heldRef == targetRef

	case ScopeSubtree:
		// A subtree holding reaches the root and everything registered beneath it.
		// Model.IsAncestor is the same walk the engine uses for a subtree grant, so
		// delegation and enforcement cannot disagree about what "beneath" means.
		switch targetKind {
		case ScopeResource, ScopeSubtree:
			return targetRef == heldRef || m.IsAncestor(heldRef, targetRef)
		}

	case ScopeResource:
		// Exactly that object, and not its descendants: a holding on the object is
		// not a holding on the subtree below it.
		return targetKind == ScopeResource && heldRef == targetRef
	}
	return false
}
