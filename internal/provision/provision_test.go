package provision_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/authz"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/provision"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

const dsnEnv = "WARDEN_TEST_DATABASE_URL"

type fixture struct {
	p    *provision.Provisioner
	conn *pgx.Conn
	// alice is a tenant.admin who also holds billing.viewer.
	alice string
	// olivia is a tenant.owner, so she holds warden.role:assign_any.
	olivia string
	// bob holds nothing administrative.
	bob string
}

func setup(t *testing.T) fixture {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("set %s to run the provisioning tests", dsnEnv)
	}
	ctx := context.Background()

	conn, connErr := pgx.Connect(ctx, dsn)
	if connErr != nil {
		t.Fatalf("connecting: %v", connErr)
	}
	t.Cleanup(func() { conn.Close(ctx) })

	if _, resetErr := conn.Exec(ctx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public`); resetErr != nil {
		t.Fatalf("resetting: %v", resetErr)
	}
	paths, globErr := filepath.Glob(filepath.Join("..", "store", "migrations", "*.up.sql"))
	if globErr != nil || len(paths) == 0 {
		t.Fatalf("no migrations: %v", globErr)
	}
	sort.Strings(paths)
	for _, path := range paths {
		sql, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("reading %s: %v", path, readErr)
		}
		if _, execErr := conn.Exec(ctx, string(sql)); execErr != nil {
			t.Fatalf("applying %s: %v", filepath.Base(path), execErr)
		}
	}

	cfg := config.Defaults()
	cfg.Environment = config.EnvDevelopment
	cfg.Issuer = "http://localhost"
	cfg.Database.URL = secrets.New(dsn)
	cfg.Database.SystemURL = secrets.New(dsn)
	cfg.Database.MaxOpenConns = 4
	cfg.Database.MaxIdleConns = 1
	cfg.Database.ConnectTimeout = 10 * time.Second
	cfg.Database.StatementTimeout = 10 * time.Second

	db, err := store.Open(ctx, cfg, store.SystemAccess)
	if err != nil {
		t.Fatalf("opening the system store: %v", err)
	}
	t.Cleanup(db.Close)

	p, err := provision.New(db)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	manifest, err := provision.LoadManifest(filepath.Join("..", "..", "examples", "warden.yaml"))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if _, err := p.Apply(ctx, manifest); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := p.CreateTenant(ctx, "acme", "ACME"); err != nil {
		t.Fatalf("tenant: %v", err)
	}

	f := fixture{p: p, conn: conn}
	for _, u := range []struct {
		name  string
		roles []string
		into  *string
	}{
		{"alice", []string{"tenant.admin", "billing.viewer"}, &f.alice},
		{"olivia", []string{"tenant.owner"}, &f.olivia},
		{"bob", nil, &f.bob},
	} {
		id, err := p.CreateUser(ctx, "acme", u.name+"@acme.test", nil)
		if err != nil {
			t.Fatalf("user %s: %v", u.name, err)
		}
		*u.into = id
		for _, role := range u.roles {
			if _, err := p.Grant(ctx, provision.GrantOptions{
				Actor:      provision.Actor{SystemOperator: true},
				TenantSlug: "acme", UserID: id, RoleKey: role, Scope: "tenant",
			}); err != nil {
				t.Fatalf("granting %s to %s: %v", role, u.name, err)
			}
		}
	}
	return f
}

func (f fixture) grant(t *testing.T, o provision.GrantOptions) error {
	t.Helper()
	o.TenantSlug = "acme"
	if o.Scope == "" {
		o.Scope = "tenant"
	}
	_, err := f.p.Grant(context.Background(), o)
	return err
}

// The forgetting case. A caller who does not say who is acting must get an error, not
// a bypass — the guard has to be impossible to omit by accident, or it will be
// omitted.
func TestAnAssignmentWithNoActorIsRefused(t *testing.T) {
	f := setup(t)
	err := f.grant(t, provision.GrantOptions{UserID: f.bob, RoleKey: "billing.viewer"})
	if err == nil {
		t.Fatal("an assignment with no actor succeeded; the guard can be bypassed by omission")
	}
	if !strings.Contains(err.Error(), "actor is required") {
		t.Errorf("the error should say an actor is required: %v", err)
	}
}

func TestAnActorCannotBeBothSubjectAndOperator(t *testing.T) {
	f := setup(t)
	err := f.grant(t, provision.GrantOptions{
		Actor:  provision.Actor{SubjectID: f.alice, SystemOperator: true},
		UserID: f.bob, RoleKey: "billing.viewer",
	})
	if err == nil {
		t.Fatal("an ambiguous actor was accepted")
	}
}

// SPEC §17.1 threat 3, through the real provisioning path.
func TestAnAdministratorCannotAssignWhatTheyDoNotHold(t *testing.T) {
	f := setup(t)

	// alice holds billing.viewer, so she can hand it on.
	if err := f.grant(t, provision.GrantOptions{
		Actor: provision.Actor{SubjectID: f.alice}, UserID: f.bob,
		RoleKey: "billing.viewer", Reason: "bob joins",
	}); err != nil {
		t.Fatalf("alice should be able to grant a role she holds: %v", err)
	}

	// She does not hold billing.invoice:approve.
	err := f.grant(t, provision.GrantOptions{
		Actor: provision.Actor{SubjectID: f.alice}, UserID: f.bob,
		RoleKey: "billing.approver", Reason: "trying it on",
	})
	if err == nil {
		t.Fatal("alice assigned a role conferring a permission she does not hold")
	}
	var refusal *authz.EscalationError
	if !errors.As(err, &refusal) {
		t.Fatalf("expected an EscalationError, got %T: %v", err, err)
	}
	if refusal.Reason != authz.RefusalMissingPermissions {
		t.Errorf("reason = %q", refusal.Reason)
	}
}

// The owner holds warden.role:assign_any, which is the documented escape hatch.
func TestTheOwnerCanAssignBeyondWhatTheyHold(t *testing.T) {
	f := setup(t)
	if err := f.grant(t, provision.GrantOptions{
		Actor: provision.Actor{SubjectID: f.olivia}, UserID: f.bob,
		RoleKey: "billing.approver", Reason: "authorised",
	}); err != nil {
		t.Fatalf("the tenant owner should be able to assign anything: %v", err)
	}
}

func TestASubjectWithNoAdministrativeRoleCannotAssignAtAll(t *testing.T) {
	f := setup(t)
	err := f.grant(t, provision.GrantOptions{
		Actor: provision.Actor{SubjectID: f.bob}, UserID: f.bob,
		RoleKey: "billing.viewer", Reason: "why not",
	})
	if err == nil {
		t.Fatal("a subject with no assignment permission granted a role to himself")
	}
	if !strings.Contains(err.Error(), authz.PermRoleAssign) {
		t.Errorf("the refusal should name the missing permission: %v", err)
	}
}

// Scope widening: the permission set is identical and it is still an escalation.
func TestAnAdministratorCannotWidenScope(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	for _, ref := range []string{"billing.project:alpha", "billing.project:beta"} {
		if err := f.p.RegisterResource(ctx, "acme", ref, "", nil); err != nil {
			t.Fatalf("registering %s: %v", ref, err)
		}
	}
	// alice gets approver on alpha only.
	if _, err := f.p.Grant(ctx, provision.GrantOptions{
		Actor:      provision.Actor{SystemOperator: true},
		TenantSlug: "acme", UserID: f.alice, RoleKey: "billing.approver",
		Scope: "billing.project:alpha/**",
	}); err != nil {
		t.Fatalf("seeding alice's scoped grant: %v", err)
	}

	if err := f.grant(t, provision.GrantOptions{
		Actor: provision.Actor{SubjectID: f.alice}, UserID: f.bob,
		RoleKey: "billing.approver", Scope: "billing.project:alpha/**", Reason: "within",
	}); err != nil {
		t.Fatalf("alice should be able to delegate within her own subtree: %v", err)
	}

	for _, scope := range []string{"billing.project:beta/**", "tenant"} {
		if err := f.grant(t, provision.GrantOptions{
			Actor: provision.Actor{SubjectID: f.alice}, UserID: f.bob,
			RoleKey: "billing.approver", Scope: scope, Reason: "widening",
		}); err == nil {
			t.Errorf("alice widened her scope to %s", scope)
		}
	}
}

// A refused assignment is exactly the thing worth having a record of.
func TestARefusedAssignmentIsAudited(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	if err := f.grant(t, provision.GrantOptions{
		Actor: provision.Actor{SubjectID: f.alice}, UserID: f.bob,
		RoleKey: "billing.approver", Reason: "trying it on",
	}); err == nil {
		t.Fatal("expected a refusal")
	}

	var count int
	var actor, detail string
	if err := f.conn.QueryRow(ctx, `
		SELECT count(*), coalesce(max(actor_user_id),''), coalesce(max(after::text),'')
		  FROM audit_event WHERE action = 'role.assignment_refused'`).
		Scan(&count, &actor, &detail); err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	if count != 1 {
		t.Fatalf("the refusal produced %d audit entries", count)
	}
	if actor != f.alice {
		t.Errorf("the entry names actor %q, want %q", actor, f.alice)
	}
	if !strings.Contains(detail, "missing_permissions") {
		t.Errorf("the entry should record why it was refused: %s", detail)
	}

	// And the refusal must not have left a grant behind.
	var grants int
	if err := f.conn.QueryRow(ctx,
		`SELECT count(*) FROM grant_ WHERE subject_user_id = $1`, f.bob).Scan(&grants); err != nil {
		t.Fatalf("counting grants: %v", err)
	}
	if grants != 0 {
		t.Errorf("a refused assignment left %d grants behind", grants)
	}
}

// A successful assignment records who made it, which is what makes the audit entry
// answer "who gave them that?".
func TestAGrantRecordsItsAssigner(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	if err := f.grant(t, provision.GrantOptions{
		Actor: provision.Actor{SubjectID: f.alice}, UserID: f.bob,
		RoleKey: "billing.viewer", Reason: "bob joins",
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	var grantedBy *string
	if err := f.conn.QueryRow(ctx,
		`SELECT granted_by FROM grant_ WHERE subject_user_id = $1`, f.bob).Scan(&grantedBy); err != nil {
		t.Fatalf("reading the grant: %v", err)
	}
	if grantedBy == nil || *grantedBy != f.alice {
		t.Errorf("granted_by = %v, want %q", grantedBy, f.alice)
	}
}

// The system roles of SPEC §9.3 are immutable, and that is enforced by the database
// rather than by everyone remembering.
func TestSystemRolesAreImmutable(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	for _, stmt := range []string{
		`UPDATE role SET name = 'Renamed' WHERE id = 'rol_tenant_owner'`,
		`DELETE FROM role WHERE id = 'rol_tenant_admin'`,
	} {
		if _, err := f.conn.Exec(ctx, stmt); err == nil {
			t.Errorf("%q was permitted against an immutable system role", stmt)
		} else if !strings.Contains(err.Error(), "immutable") {
			t.Errorf("%q failed for the wrong reason: %v", stmt, err)
		}
	}
}
