// Package authz is Warden's policy decision point: the component that answers
// "may this subject do this thing to this object?".
//
// It implements the evaluation algorithm of SPEC §10.2 over a model loaded from
// PostgreSQL. Its correctness claim is not "it looks right" but "it agrees with the
// conformance corpus", which is executed against it and against the independent
// reference implementation in conformance/reference. Any divergence between the two
// is a bug in one of them.
package authz

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Scope kinds, as stored in grant_.scope_kind and denial.scope_kind. The schema's
// CHECK constraint lists the same set; the two must agree, and a bare string in one
// place would silently never match rather than fail.
const (
	ScopeTenant      = "tenant"
	ScopeApplication = "application"
	ScopeEnvironment = "environment"
	ScopeResource    = "resource"
	ScopeSubtree     = "subtree"
)

// Permission is app.type:action, split once so matching never re-parses.
type Permission struct {
	App, ResourceType, Action string
}

// ParsePermission splits a permission string. A wildcard is legal in the resource
// type or action of a grant, never in a check (SPEC §9.2).
func ParsePermission(s string) (Permission, error) {
	dot := strings.IndexByte(s, '.')
	colon := strings.IndexByte(s, ':')
	if dot <= 0 || colon <= dot+1 || colon == len(s)-1 {
		return Permission{}, fmt.Errorf("permission %q is not of the form app.type:action", s)
	}
	return Permission{App: s[:dot], ResourceType: s[dot+1 : colon], Action: s[colon+1:]}, nil
}

func (p Permission) String() string { return p.App + "." + p.ResourceType + ":" + p.Action }

// Matches reports whether p, which may contain wildcards, covers the concrete
// permission want.
func (p Permission) Matches(want Permission) bool {
	return p.App == want.App &&
		(p.ResourceType == "*" || p.ResourceType == want.ResourceType) &&
		(p.Action == "*" || p.Action == want.Action)
}

// ResourceRef is app.type:id.
type ResourceRef struct {
	App, ResourceType, ID string
}

// ParseResourceRef splits a resource reference.
func ParseResourceRef(s string) (ResourceRef, error) {
	dot := strings.IndexByte(s, '.')
	colon := strings.IndexByte(s, ':')
	if dot <= 0 || colon <= dot+1 || colon == len(s)-1 {
		return ResourceRef{}, fmt.Errorf("resource %q is not of the form app.type:id", s)
	}
	return ResourceRef{App: s[:dot], ResourceType: s[dot+1 : colon], ID: s[colon+1:]}, nil
}

func (r ResourceRef) String() string { return r.App + "." + r.ResourceType + ":" + r.ID }

// Subject is the actor in a decision.
type Subject struct {
	ID         string
	Status     string
	Attributes map[string]any
}

// Role carries its fully expanded permission set: its own permissions, everything it
// inherits transitively, and the closure of every action's `implies`. All of that
// expansion happens when the model is built, never during a check (SPEC §9.2).
type Role struct {
	ID          string
	Key         string
	RequiresMFA bool
	Permissions []Permission
	// Conditions attached to individual permission entries, keyed by the permission
	// string as written. A grant-level condition is held on the grant.
	PermissionConditions map[string]string
}

// Grant binds a subject or group to a role at a scope (SPEC §9.5).
type Grant struct {
	ID         string
	Seq        int64 // declaration order; the corpus depends on this being stable
	UserID     string
	GroupID    string
	RoleID     string
	ScopeKind  string
	ScopeRef   string
	Condition  string
	ValidFrom  time.Time
	ValidUntil *time.Time
}

// Denial is an explicit deny. It outranks every allow (SPEC §9.7).
type Denial struct {
	ID         string
	UserID     string
	GroupID    string
	Permission Permission
	ScopeKind  string
	ScopeRef   string
}

// Resource is a registered instance, carrying its parent and its attributes.
type Resource struct {
	Ref        string
	ParentRef  string
	Attributes map[string]any
}

// Model is one tenant's authorization world at one revision.
//
// It is immutable once built. The engine caches it keyed on (tenant, revision), so a
// check is a read of an already-resolved structure rather than a set of queries —
// which is what SPEC §18's latency budget requires and what the permission_rev
// counter exists to make safe.
type Model struct {
	TenantID string
	Revision int64

	// DeclaredPermissions is the union of every application's surface. A check for
	// anything outside it denies with unknown_permission, so a typo surfaces in
	// staging instead of silently denying in production (SPEC §9.2).
	DeclaredPermissions map[string]bool

	Subjects  map[string]Subject
	Roles     map[string]*Role
	Grants    []Grant
	Denials   []Denial
	Resources map[string]Resource

	// GroupsOf maps a subject to every group it belongs to, transitively.
	GroupsOf map[string]map[string]bool
}

// IsAncestor reports whether ancestor is at or above ref in the registered hierarchy.
// An unregistered resource has no ancestors, which is why an application that does
// not mirror its object graph loses the cascade and nothing else (SPEC §9.5).
func (m *Model) IsAncestor(ancestor, ref string) bool {
	if ancestor == ref {
		return true
	}
	seen := map[string]bool{}
	for cur := ref; cur != ""; {
		if seen[cur] {
			return false // a cycle; rejected on write, guarded here anyway
		}
		seen[cur] = true
		r, ok := m.Resources[cur]
		if !ok {
			return false
		}
		if r.ParentRef == ancestor {
			return true
		}
		cur = r.ParentRef
	}
	return false
}

// RoleGrants reports whether a role's expanded permission set covers want, and
// returns any condition attached to the matching permission entry.
func (m *Model) RoleGrants(roleID string, want Permission) (string, bool) {
	role, ok := m.Roles[roleID]
	if !ok {
		return "", false
	}
	for _, p := range role.Permissions {
		if p.Matches(want) {
			return role.PermissionConditions[p.String()], true
		}
	}
	return "", false
}

// sortGrants orders grants by declaration sequence. Where several could allow the
// same check, the earliest is the one reported — the corpus asserts which grant
// produced a decision, so the order has to be defined rather than incidental.
func sortGrants(g []Grant) {
	sort.Slice(g, func(i, j int) bool { return g[i].Seq < g[j].Seq })
}

// NewModel returns an empty model for a tenant, ready for LoadModelInto.
func NewModel(tenantID string) *Model {
	return &Model{
		TenantID:            tenantID,
		DeclaredPermissions: map[string]bool{},
		Subjects:            map[string]Subject{},
		Roles:               map[string]*Role{},
		Resources:           map[string]Resource{},
		GroupsOf:            map[string]map[string]bool{},
	}
}
