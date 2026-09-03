package authz

import (
	"strings"
	"testing"
	"time"
)

// Privilege escalation through role assignment is threat 3 of SPEC §17.1, and
// docs/tasks.md marks it as needing a dedicated suite rather than a passing mention.
// These tests are built around one question: can a subject end up able to hand out
// authority nobody gave them?

var testNow = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

// modelBuilder assembles a Model in memory. The guard is pure logic over a loaded
// model, so exercising it needs no database — which means these can be exhaustive.
type modelBuilder struct{ m *Model }

func newModel() *modelBuilder {
	return &modelBuilder{m: &Model{
		TenantID:            "ten_test",
		Revision:            1,
		DeclaredPermissions: map[string]bool{},
		Subjects:            map[string]Subject{},
		Roles:               map[string]*Role{},
		Resources:           map[string]Resource{},
		GroupsOf:            map[string]map[string]bool{},
	}}
}

func (b *modelBuilder) role(id string, permissions ...string) *modelBuilder {
	role := &Role{ID: id, Key: id, PermissionConditions: map[string]string{}}
	for _, p := range permissions {
		parsed, err := ParsePermission(p)
		if err != nil {
			panic(err)
		}
		role.Permissions = append(role.Permissions, parsed)
		b.m.DeclaredPermissions[p] = true
	}
	b.m.Roles[id] = role
	return b
}

// conditionalRole is a role whose permission is only conferred when a condition holds.
func (b *modelBuilder) conditionalRole(id, permission, condition string) *modelBuilder {
	b.role(id, permission)
	b.m.Roles[id].PermissionConditions[permission] = condition
	return b
}

func (b *modelBuilder) user(id string) *modelBuilder {
	b.m.Subjects[id] = Subject{ID: id, Status: StatusActive}
	return b
}

type grantOpt func(*Grant)

func at(kind, ref string) grantOpt { return func(g *Grant) { g.ScopeKind, g.ScopeRef = kind, ref } }
func until(t time.Time) grantOpt   { return func(g *Grant) { g.ValidUntil = &t } }
func when(expr string) grantOpt    { return func(g *Grant) { g.Condition = expr } }

func (b *modelBuilder) grant(user, role string, opts ...grantOpt) *modelBuilder {
	g := Grant{
		ID: "grn_" + user + "_" + role, Seq: int64(len(b.m.Grants) + 1),
		UserID: user, RoleID: role, ScopeKind: "tenant", ScopeRef: "ten_test",
	}
	for _, o := range opts {
		o(&g)
	}
	b.m.Grants = append(b.m.Grants, g)
	return b
}

func (b *modelBuilder) inGroup(user, group string) *modelBuilder {
	if b.m.GroupsOf[user] == nil {
		b.m.GroupsOf[user] = map[string]bool{}
	}
	b.m.GroupsOf[user][group] = true
	return b
}

func (b *modelBuilder) resource(ref, parent string) *modelBuilder {
	b.m.Resources[ref] = Resource{Ref: ref, ParentRef: parent}
	return b
}

func (b *modelBuilder) build() *Model { return b.m }

// assign attempts an assignment and returns the refusal, if any.
func assign(m *Model, assigner, role string, opts ...func(*AssignmentRequest)) *EscalationError {
	req := AssignmentRequest{
		Assigner: assigner, RoleID: role,
		ScopeKind: "tenant", ScopeRef: "ten_test", Now: testNow,
	}
	for _, o := range opts {
		o(&req)
	}
	return CanAssign(m, req)
}

func atScope(kind, ref string) func(*AssignmentRequest) {
	return func(r *AssignmentRequest) { r.ScopeKind, r.ScopeRef = kind, ref }
}
func expiring(t time.Time) func(*AssignmentRequest) {
	return func(r *AssignmentRequest) { r.ValidUntil = &t }
}

// --- The core rule ----------------------------------------------------------------

// An administrator may hand out what they hold, and nothing more. This is the whole
// of SPEC §17.1 threat 3 in two cases.
func TestAnAssignerMayGrantOnlyWhatTheyHold(t *testing.T) {
	m := newModel().
		role("admin", PermRoleAssign, "billing.invoice:read").
		role("viewer", "billing.invoice:read").
		role("approver", "billing.invoice:read", "billing.invoice:approve").
		user("alice").grant("alice", "admin").
		build()

	if err := assign(m, "alice", "viewer"); err != nil {
		t.Fatalf("alice holds invoice:read and should be able to grant viewer: %v", err)
	}

	err := assign(m, "alice", "approver")
	if err == nil {
		t.Fatal("alice granted a role conferring invoice:approve, which she does not hold")
	}
	if err.Reason != RefusalMissingPermissions {
		t.Errorf("reason = %q, want %q", err.Reason, RefusalMissingPermissions)
	}
	if len(err.Missing) != 1 || err.Missing[0] != "billing.invoice:approve" {
		t.Errorf("missing = %v, want exactly the permission she lacks", err.Missing)
	}
}

// Holding warden.role:assign_any is the documented escape hatch, and it is the only
// way to widen the set of permissions in circulation.
func TestAssignAnyBypassesContainment(t *testing.T) {
	m := newModel().
		role("owner", PermRoleAssignAny).
		role("approver", "billing.invoice:approve").
		user("olivia").grant("olivia", "owner").
		build()

	if err := assign(m, "olivia", "approver"); err != nil {
		t.Fatalf("assign_any should permit granting a role the holder lacks: %v", err)
	}
}

// Without any assignment permission at all, nothing is assignable — including a role
// whose permissions the subject does hold. Being able to do something is not the same
// as being able to delegate it.
func TestHoldingAPermissionIsNotPermissionToDelegateIt(t *testing.T) {
	m := newModel().
		role("approver", "billing.invoice:approve").
		user("maria").grant("maria", "approver").
		build()

	err := assign(m, "maria", "approver")
	if err == nil {
		t.Fatal("a subject who holds a role was able to hand it out without warden.role:assign")
	}
	if err.Reason != RefusalNotPermitted {
		t.Errorf("reason = %q, want %q", err.Reason, RefusalNotPermitted)
	}
}

// Inheritance and groups are how authority actually arrives, so containment has to
// see through both.
func TestHoldingsArriveThroughGroups(t *testing.T) {
	m := newModel().
		role("admin", PermRoleAssign, "billing.invoice:approve").
		role("approver", "billing.invoice:approve").
		user("bob").inGroup("bob", "grp_admins").
		build()
	m.Grants = append(m.Grants, Grant{
		ID: "grn_g", Seq: 1, RoleID: "admin", ScopeKind: "tenant", ScopeRef: "ten_test",
	})
	m.Grants[0].GroupID = "grp_admins"

	if err := assign(m, "bob", "approver"); err != nil {
		t.Fatalf("a group-derived holding should count: %v", err)
	}
}

func TestAGrantToAnotherGroupDoesNotCount(t *testing.T) {
	m := newModel().
		role("admin", PermRoleAssign, "billing.invoice:approve").
		role("approver", "billing.invoice:approve").
		user("bob").inGroup("bob", "grp_readers").
		build()
	m.Grants = append(m.Grants, Grant{
		ID: "grn_g", Seq: 1, GroupID: "grp_admins",
		RoleID: "admin", ScopeKind: "tenant", ScopeRef: "ten_test",
	})

	if err := assign(m, "bob", "approver"); err == nil {
		t.Fatal("a grant to a group bob is not in was counted as his")
	}
}

// --- Scope ------------------------------------------------------------------------

// The subtle case: the permission set is unchanged and the assignment is still an
// escalation, because it applies somewhere the assigner's own authority does not.
func TestAnAssignerCannotWidenTheScopeOfWhatTheyHold(t *testing.T) {
	m := newModel().
		role("admin", PermRoleAssign).
		role("approver", "billing.invoice:approve").
		user("alice").
		grant("alice", "admin").
		grant("alice", "approver", at("subtree", "billing.project:alpha")).
		resource("billing.project:alpha", "").
		resource("billing.invoice:a1", "billing.project:alpha").
		build()

	// Within her own subtree: fine.
	if err := assign(m, "alice", "approver", atScope("subtree", "billing.project:alpha")); err != nil {
		t.Fatalf("alice should be able to delegate within her own subtree: %v", err)
	}
	if err := assign(m, "alice", "approver", atScope("resource", "billing.invoice:a1")); err != nil {
		t.Fatalf("alice should be able to delegate on a resource beneath her subtree: %v", err)
	}

	// Tenant-wide: escalation, with the permission set identical.
	err := assign(m, "alice", "approver", atScope("tenant", "ten_test"))
	if err == nil {
		t.Fatal("alice granted tenant-wide a permission she holds only on one project")
	}
	if err.Reason != RefusalMissingPermissions {
		t.Errorf("reason = %q", err.Reason)
	}

	// A different branch: also escalation.
	if err := assign(m, "alice", "approver", atScope("subtree", "billing.project:beta")); err == nil {
		t.Fatal("alice granted on a project outside her own subtree")
	}
}

func TestScopeReachability(t *testing.T) {
	m := newModel().
		resource("billing.project:alpha", "").
		resource("billing.invoice:a1", "billing.project:alpha").
		build()

	cases := []struct {
		name                  string
		heldKind, heldRef     string
		targetKind, targetRef string
		want                  bool
	}{
		{"tenant reaches everything", "tenant", "ten_test", "resource", "billing.invoice:a1", true},
		{"tenant reaches an application", "tenant", "ten_test", "application", "billing", true},

		{"application reaches its own resources", "application", "billing", "resource", "billing.invoice:a1", true},
		{"application reaches its own environments", "application", "billing", "environment", "billing/prod", true},
		{"application does not reach another application", "application", "billing", "resource", "shipping.parcel:p1", false},
		{"application does not reach the whole tenant", "application", "billing", "tenant", "ten_test", false},

		{"environment reaches only itself", "environment", "billing/prod", "environment", "billing/prod", true},
		{"environment does not reach another environment", "environment", "billing/prod", "environment", "billing/staging", false},
		// A resource reference says nothing about which environment it is in, so an
		// environment-scoped holding cannot be shown to cover it.
		{"environment does not reach a resource", "environment", "billing/prod", "resource", "billing.invoice:a1", false},

		{"subtree reaches its root", "subtree", "billing.project:alpha", "resource", "billing.project:alpha", true},
		{"subtree reaches a descendant", "subtree", "billing.project:alpha", "resource", "billing.invoice:a1", true},
		{"subtree does not reach a sibling", "subtree", "billing.project:alpha", "resource", "billing.project:beta", false},
		{"subtree does not reach the application", "subtree", "billing.project:alpha", "application", "billing", false},

		{"resource reaches only itself", "resource", "billing.project:alpha", "resource", "billing.project:alpha", true},
		// Holding a permission on an object is not holding it on everything beneath.
		{"resource does not reach its own descendants", "resource", "billing.project:alpha", "resource", "billing.invoice:a1", false},
		{"resource does not reach a subtree rooted at itself", "resource", "billing.project:alpha", "subtree", "billing.project:alpha", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scopeReaches(m, tc.heldKind, tc.heldRef, tc.targetKind, tc.targetRef)
			if got != tc.want {
				t.Errorf("scopeReaches(%s:%s -> %s:%s) = %v, want %v",
					tc.heldKind, tc.heldRef, tc.targetKind, tc.targetRef, got, tc.want)
			}
		})
	}
}

// --- Time -------------------------------------------------------------------------

// A time-boxed elevation must not become permanent in one step. Without this, an
// administrator granted four hours of authority grants themselves the same role with
// no expiry and keeps it.
func TestAnAssignerCannotOutliveTheirOwnAuthority(t *testing.T) {
	expiry := testNow.Add(4 * time.Hour)
	m := newModel().
		role("admin", PermRoleAssign, "billing.invoice:approve").
		role("approver", "billing.invoice:approve").
		user("temp").grant("temp", "admin", until(expiry)).
		build()

	// Permanent: refused.
	err := assign(m, "temp", "approver")
	if err == nil {
		t.Fatal("a temporarily elevated assigner created a grant that never expires")
	}
	if err.Reason != RefusalValidityTooLong {
		t.Errorf("reason = %q, want %q", err.Reason, RefusalValidityTooLong)
	}

	// Beyond their own expiry: refused.
	if err := assign(m, "temp", "approver", expiring(expiry.Add(time.Hour))); err == nil {
		t.Fatal("the assignment outlived the assigner's own authority")
	}

	// Within it: allowed.
	if err := assign(m, "temp", "approver", expiring(expiry.Add(-time.Hour))); err != nil {
		t.Fatalf("an assignment inside the assigner's window should be permitted: %v", err)
	}
	// Exactly at it: allowed, since the window is half-open and the grant is gone at
	// that instant anyway.
	if err := assign(m, "temp", "approver", expiring(expiry)); err != nil {
		t.Fatalf("an assignment ending exactly when the assigner's does: %v", err)
	}
}

// assign_any bypasses containment and nothing else. A temporary owner is still
// temporary.
func TestAssignAnyDoesNotBypassTheValidityBound(t *testing.T) {
	expiry := testNow.Add(time.Hour)
	m := newModel().
		role("owner", PermRoleAssignAny).
		role("approver", "billing.invoice:approve").
		user("olivia").grant("olivia", "owner", until(expiry)).
		build()

	if err := assign(m, "olivia", "approver"); err == nil {
		t.Fatal("a temporarily elevated owner created a permanent grant")
	}
}

// An expired grant confers nothing.
func TestAnExpiredHoldingConfersNothing(t *testing.T) {
	m := newModel().
		role("admin", PermRoleAssign, "billing.invoice:approve").
		role("approver", "billing.invoice:approve").
		user("lapsed").grant("lapsed", "admin", until(testNow.Add(-time.Hour))).
		build()

	if err := assign(m, "lapsed", "approver"); err == nil {
		t.Fatal("an expired grant was treated as current authority")
	}
}

// --- Conditions -------------------------------------------------------------------

// A permission held only under a condition is not the same permission
// unconditionally. Treating it as equivalent would let an assigner launder away a
// constraint someone deliberately attached.
func TestAConditionalHoldingCannotBeDelegatedUnconditionally(t *testing.T) {
	m := newModel().
		role("admin", PermRoleAssign).
		role("approver", "billing.invoice:approve").
		user("alice").
		grant("alice", "admin").
		grant("alice", "approver", when("resource.attributes.amount <= 50000")).
		build()

	err := assign(m, "alice", "approver")
	if err == nil {
		t.Fatal("a conditionally held permission was delegated with the condition dropped")
	}
	if err.Reason != RefusalMissingPermissions {
		t.Errorf("reason = %q", err.Reason)
	}
}

// The same rule applies to a condition attached to a role's permission entry rather
// than to the grant.
func TestAConditionOnTheRoleEntryAlsoBlocksDelegation(t *testing.T) {
	m := newModel().
		role("admin", PermRoleAssign).
		conditionalRole("limited", "billing.invoice:approve", "resource.attributes.amount <= 100").
		role("approver", "billing.invoice:approve").
		user("alice").grant("alice", "admin").grant("alice", "limited").
		build()

	if err := assign(m, "alice", "approver"); err == nil {
		t.Fatal("a permission conferred only under a role-entry condition was delegated unconditionally")
	}
}

// --- Wildcards ---------------------------------------------------------------------

// A wildcard holding covers what it matches, and no more. This is where a naive
// string comparison would fail open.
func TestWildcardHoldingsCoverWhatTheyMatch(t *testing.T) {
	m := newModel().
		role("admin", PermRoleAssign, "billing.*:*").
		role("billing_approver", "billing.invoice:approve").
		role("shipping_reader", "shipping.parcel:read").
		user("alice").grant("alice", "admin").
		build()

	if err := assign(m, "alice", "billing_approver"); err != nil {
		t.Fatalf("billing.*:* should cover billing.invoice:approve: %v", err)
	}
	if err := assign(m, "alice", "shipping_reader"); err == nil {
		t.Fatal("billing.*:* covered a permission in another application")
	}
}

// --- Explicit denials ---------------------------------------------------------------

func TestCreatingADenialRequiresPermissionAndAReason(t *testing.T) {
	m := newModel().
		role("admin", PermDenialCreate).
		user("alice").grant("alice", "admin").
		user("bob").
		build()

	if err := CanCreateDenial(m, "alice", "regulated data", testNow); err != nil {
		t.Fatalf("an administrator with the permission should be able to write a denial: %v", err)
	}
	// SPEC §9.7 requires a written justification, always.
	if err := CanCreateDenial(m, "alice", "   ", testNow); err == nil {
		t.Fatal("a denial was accepted with no justification")
	}
	if err := CanCreateDenial(m, "bob", "because", testNow); err == nil {
		t.Fatal("a subject without warden.denial:create wrote a denial")
	}
}

// --- The refusal itself --------------------------------------------------------------

// A refusal an administrator cannot act on is barely better than a refusal with no
// explanation, so the message has to name what is missing and what would fix it.
func TestARefusalSaysWhatWouldFixIt(t *testing.T) {
	m := newModel().
		role("admin", PermRoleAssign).
		role("approver", "billing.invoice:approve", "billing.invoice:void").
		user("alice").grant("alice", "admin").
		build()

	err := assign(m, "alice", "approver")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if len(err.Missing) != 2 {
		t.Errorf("missing = %v; both absent permissions should be listed", err.Missing)
	}
	if !strings.Contains(err.Error(), PermRoleAssignAny) {
		t.Errorf("the refusal should name the permission that would lift it: %v", err)
	}
	if !strings.Contains(err.Error(), "billing.invoice:approve") {
		t.Errorf("the refusal should name what is missing: %v", err)
	}
}

func TestAssigningANonexistentRoleIsRefused(t *testing.T) {
	m := newModel().role("admin", PermRoleAssign).user("alice").grant("alice", "admin").build()
	if err := assign(m, "alice", "no_such_role"); err == nil {
		t.Fatal("assigning a role that does not exist was permitted")
	}
}

func TestAnUnknownAssignerIsRefused(t *testing.T) {
	m := newModel().role("viewer", "billing.invoice:read").build()
	if err := assign(m, "usr_nobody", "viewer"); err == nil {
		t.Fatal("a subject with no grants at all was able to assign")
	}
}
