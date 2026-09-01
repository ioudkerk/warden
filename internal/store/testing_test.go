package store_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

// These tests need a real PostgreSQL. They are skipped without one rather than
// failing, so `go test ./...` stays useful on a machine with no database — but CI
// always sets the variable, so the isolation guarantees are never merely optional.
const dsnEnv = "WARDEN_TEST_DATABASE_URL"

// The application role the tests create. It is deliberately not a superuser and not
// the owner of anything: superusers bypass row-level security unconditionally, so a
// test that used one would prove nothing at all.
const (
	appRole     = "warden_test_app"
	appPassword = "warden_test_app_password"
)

func systemDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("set %s to a PostgreSQL superuser connection string to run the store tests "+
			"(make dev-up provides one)", dsnEnv)
	}
	return dsn
}

// appDSN returns the system connection string with the credentials swapped for the
// unprivileged application role.
func appDSN(t *testing.T, system string) string {
	t.Helper()
	u, err := url.Parse(system)
	if err != nil {
		t.Fatalf("parsing %s: %v", dsnEnv, err)
	}
	u.User = url.UserPassword(appRole, appPassword)
	return u.String()
}

// migrateFresh drops and rebuilds the schema, then applies every migration in order.
//
// Applying the .up.sql files directly rather than shelling out to golang-migrate
// keeps the tests self-contained; the migrate binary's own behaviour is covered by
// the round-trip job in CI.
func migrateFresh(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()

	if _, err := conn.Exec(ctx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatalf("resetting the schema: %v", err)
	}

	paths, err := filepath.Glob(filepath.Join("migrations", "*.up.sql"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no migrations found: %v", err)
	}
	sort.Strings(paths)

	for _, path := range paths {
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if _, err := conn.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("applying %s: %v", filepath.Base(path), err)
		}
	}
}

// setupDatabase gives every test a freshly migrated schema and the application role,
// granted exactly what deploy/roles.sql grants it.
func setupDatabase(t *testing.T) (systemURL, applicationURL string) {
	t.Helper()
	ctx := context.Background()
	systemURL = systemDSN(t)

	conn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting as the system role: %v", err)
	}
	defer conn.Close(ctx)

	migrateFresh(t, ctx, conn)

	// CREATE ROLE has no IF NOT EXISTS, and the role outlives a single test run.
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, appRole).Scan(&exists); err != nil {
		t.Fatalf("checking for the application role: %v", err)
	}
	if !exists {
		if _, err := conn.Exec(ctx, fmt.Sprintf(
			`CREATE ROLE %s LOGIN PASSWORD %s`, pgx.Identifier{appRole}.Sanitize(), quoteLiteral(appPassword),
		)); err != nil {
			t.Fatalf("creating the application role: %v", err)
		}
	}

	// The same grants as deploy/roles.sql. Notably absent: BYPASSRLS, ownership, and
	// any DDL privilege.
	for _, stmt := range []string{
		fmt.Sprintf(`GRANT USAGE ON SCHEMA public TO %s`, appRole),
		fmt.Sprintf(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %s`, appRole),
		fmt.Sprintf(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %s`, appRole),
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("granting to the application role: %v", err)
		}
	}

	return systemURL, appDSN(t, systemURL)
}

func quoteLiteral(s string) string { return "'" + s + "'" }

// testConfig builds a valid configuration pointing at the test database.
func testConfig(t *testing.T, systemURL, applicationURL string, env config.Environment) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Environment = env
	cfg.Issuer = "https://warden.test"
	cfg.Database.URL = secrets.New(applicationURL)
	cfg.Database.SystemURL = secrets.New(systemURL)
	cfg.Database.ConnectTimeout = 10 * time.Second
	cfg.Database.StatementTimeout = 10 * time.Second
	cfg.Database.MaxOpenConns = 4
	cfg.Database.MaxIdleConns = 1
	return cfg
}

func openStore(t *testing.T, cfg *config.Config, access store.Access) *store.Store {
	t.Helper()
	s, err := store.Open(context.Background(), cfg, access)
	if err != nil {
		t.Fatalf("opening the %s store: %v", access, err)
	}
	t.Cleanup(s.Close)
	return s
}
