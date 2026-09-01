package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

// A request-serving role that can bypass row-level security has tenant isolation
// switched off with no outward symptom whatsoever: every query works, every test
// passes, and the boundary simply is not there. Startup is the only cheap moment to
// notice, so Warden refuses rather than warns.
func TestTenantPoolRefusesAPrivilegedRoleInProduction(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	// Point database.url at the superuser: the misconfiguration being guarded against.
	cfg := testConfig(t, systemURL, applicationURL, config.EnvProduction)
	cfg.Database.URL = secrets.New(systemURL)

	s, err := store.Open(ctx, cfg, store.TenantScoped)
	if err == nil {
		s.Close()
		t.Fatal("Warden started with a request-serving role that bypasses row-level security")
	}
	for _, want := range []string{"tenant isolation", "deploy/roles.sql"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q, got: %v", want, err)
		}
	}
	// The message must not carry the connection string, which holds a password.
	if strings.Contains(err.Error(), "warden:warden@") {
		t.Errorf("the refusal leaked the connection string: %v", err)
	}
}

// The same configuration on a developer's laptop is a warning, not a refusal — one
// role and no ambitions is a reasonable way to run locally, as long as it is said out
// loud.
func TestTenantPoolWarnsButStartsOutsideProduction(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	cfg := testConfig(t, systemURL, applicationURL, config.EnvDevelopment)
	cfg.Database.URL = secrets.New(systemURL)

	s, err := store.Open(ctx, cfg, store.TenantScoped)
	if err != nil {
		t.Fatalf("development should start with a warning, not a refusal: %v", err)
	}
	defer s.Close()

	warning := s.IsolationWarning()
	if warning == "" {
		t.Fatal("no isolation warning was recorded; a developer would have no idea RLS is not applying")
	}
	if !strings.Contains(warning, "not enforced") {
		t.Errorf("the warning should say plainly that isolation is not enforced, got: %q", warning)
	}
}

// The correct configuration passes in production without complaint.
func TestTenantPoolAcceptsAnUnprivilegedRole(t *testing.T) {
	systemURL, applicationURL := setupDatabase(t)

	cfg := testConfig(t, systemURL, applicationURL, config.EnvProduction)
	s := openStore(t, cfg, store.TenantScoped)

	if s.Role() != appRole {
		t.Errorf("connected as %q, expected %q", s.Role(), appRole)
	}
	if w := s.IsolationWarning(); w != "" {
		t.Errorf("a correctly configured pool should record no warning, got: %q", w)
	}
}

// The mirror image: a system pool that *cannot* bypass would fail later, mid-migration
// or mid-job, with an error that looks like missing data rather than missing privilege.
func TestSystemPoolRefusesAnUnprivilegedRole(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	cfg := testConfig(t, systemURL, applicationURL, config.EnvProduction)
	cfg.Database.SystemURL = secrets.New(applicationURL) // the unprivileged role

	s, err := store.Open(ctx, cfg, store.SystemAccess)
	if err == nil {
		s.Close()
		t.Fatal("the system pool accepted a role that cannot bypass row-level security")
	}
	if !strings.Contains(err.Error(), "BYPASSRLS") {
		t.Errorf("the refusal should name the missing privilege, got: %v", err)
	}
}

func TestSystemAccessRequiresConfiguration(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	cfg := testConfig(t, systemURL, applicationURL, config.EnvProduction)
	cfg.Database.SystemURL = secrets.Secret{}

	_, err := store.Open(ctx, cfg, store.SystemAccess)
	if !errors.Is(err, store.ErrNoSystemAccess) {
		t.Fatalf("expected ErrNoSystemAccess, got %v", err)
	}
}

// --- Guard rails on the two entry points -------------------------------------------

func TestInTenantRequiresATenant(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)
	app := openStore(t, testConfig(t, systemURL, applicationURL, config.EnvProduction), store.TenantScoped)

	err := app.InTenant(ctx, "", func(context.Context, pgx.Tx) error {
		t.Error("the callback should not have run")
		return nil
	})
	if err == nil {
		t.Fatal("InTenant accepted an empty tenant id")
	}
}

// Running a tenant-scoped query on the system pool would silently see every tenant.
// It is refused rather than left to the caller to remember.
func TestInTenantIsRefusedOnTheSystemPool(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)
	sys := openStore(t, testConfig(t, systemURL, applicationURL, config.EnvProduction), store.SystemAccess)

	err := sys.InTenant(ctx, tenantA, func(context.Context, pgx.Tx) error {
		t.Error("the callback should not have run")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "bypasses row-level security") {
		t.Fatalf("expected a refusal explaining why, got %v", err)
	}
}

func TestInSystemIsRefusedOnTheTenantPool(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)
	app := openStore(t, testConfig(t, systemURL, applicationURL, config.EnvProduction), store.TenantScoped)

	err := app.InSystem(ctx, "a reason", func(context.Context, pgx.Tx) error {
		t.Error("the callback should not have run")
		return nil
	})
	if err == nil {
		t.Fatal("InSystem ran on a tenant-scoped pool")
	}
}

// SPEC §6.2: cross-tenant work "is itself audited". The reason is what the audit log
// records once it exists (M2-12), so it is required rather than optional.
func TestInSystemRequiresAReason(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)
	sys := openStore(t, testConfig(t, systemURL, applicationURL, config.EnvProduction), store.SystemAccess)

	err := sys.InSystem(ctx, "", func(context.Context, pgx.Tx) error {
		t.Error("the callback should not have run")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "audited") {
		t.Fatalf("expected a refusal citing the audit requirement, got %v", err)
	}
}

// The system pool does what it says: it sees every tenant.
func TestSystemPoolSeesEveryTenant(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	seedConn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer seedConn.Close(ctx)
	seedTwoTenants(t, ctx, seedConn)

	sys := openStore(t, testConfig(t, systemURL, applicationURL, config.EnvProduction), store.SystemAccess)

	if err := sys.InSystem(ctx, "test: counting tenants", func(ctx context.Context, tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM app_user`).Scan(&n); err != nil {
			return err
		}
		if n != 2 {
			t.Errorf("the system pool saw %d users; both tenants' rows should be visible", n)
		}
		return nil
	}); err != nil {
		t.Fatalf("InSystem: %v", err)
	}
}
