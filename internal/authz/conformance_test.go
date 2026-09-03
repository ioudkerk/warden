package authz_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/conformance"
	"github.com/warden-project/warden/internal/authz"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

const dsnEnv = "WARDEN_TEST_DATABASE_URL"

// The conformance corpus, executed against the real decision engine reading a real
// PostgreSQL.
//
// This is the test the corpus was written for. conformance/reference already answers
// all 87 checks; this proves that a completely separate implementation — different
// data structures, a different model source, SQL in the middle — reaches the same
// answers. Two independent implementations agreeing is evidence that the semantics
// are the ones written down, rather than the ones one author happened to encode.
func TestCorpusAgainstThePDP(t *testing.T) {
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("set %s to run the decision engine against a real database", dsnEnv)
	}

	cases, err := conformance.Load(filepath.Join("..", "..", "conformance", "cases"))
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}

	for _, c := range cases {
		t.Run(c.Suite, func(t *testing.T) {
			ctx := context.Background()
			systemURL, applicationURL := freshDatabase(t)

			// Seed through the system connection: the corpus declares several
			// tenants' worlds at once, which is exactly the cross-tenant work the
			// system pool exists for.
			sysConn, err := pgx.Connect(ctx, systemURL)
			if err != nil {
				t.Fatalf("connecting: %v", err)
			}
			defer sysConn.Close(ctx)

			tx, beginErr := sysConn.Begin(ctx)
			if beginErr != nil {
				t.Fatalf("begin: %v", beginErr)
			}
			if seedErr := seedCase(ctx, tx, c); seedErr != nil {
				t.Fatalf("seeding %s: %v", c.Path, seedErr)
			}
			if commitErr := tx.Commit(ctx); commitErr != nil {
				t.Fatalf("commit: %v", commitErr)
			}

			cfg := config.Defaults()
			cfg.Environment = config.EnvProduction
			cfg.Issuer = "https://warden.test"
			cfg.Database.URL = secrets.New(applicationURL)
			cfg.Database.SystemURL = secrets.New(systemURL)
			cfg.Database.MaxOpenConns = 4
			cfg.Database.MaxIdleConns = 1
			cfg.Database.ConnectTimeout = 10 * time.Second
			cfg.Database.StatementTimeout = 10 * time.Second

			db, err := store.Open(ctx, cfg, store.TenantScoped)
			if err != nil {
				t.Fatalf("opening the store: %v", err)
			}
			defer db.Close()

			engine, err := authz.NewEngine(db)
			if err != nil {
				t.Fatalf("building the engine: %v", err)
			}

			for _, chk := range c.Checks {
				t.Run(chk.Name, func(t *testing.T) {
					now, timeErr := c.EvaluationTime(chk)
					if timeErr != nil {
						t.Fatalf("%v", timeErr)
					}

					got, err := engine.Check(ctx, tenantID(chk.Tenant), authz.Request{
						Subject:     userID(chk.Subject),
						Permission:  chk.Permission,
						Resource:    chk.Resource,
						Environment: chk.Environment,
						Attributes:  chk.Attributes,
						Context:     chk.Context,
						Now:         now,
					})
					if err != nil {
						t.Fatalf("check: %v", err)
					}

					// Compare through the corpus harness so the failure output and
					// the comparison rules are identical to the reference runner's.
					problems := conformance.Compare(c, chk, conformance.Decision{
						Allowed:      got.Allowed,
						Reason:       got.Reason,
						MatchedGrant: got.MatchedGrant,
					})
					for _, p := range problems {
						t.Error(p)
					}
				})
			}
		})
	}
}

// freshDatabase rebuilds the schema and returns the system and application URLs.
func freshDatabase(t *testing.T) (systemURL, applicationURL string) {
	t.Helper()
	ctx := context.Background()
	systemURL = os.Getenv(dsnEnv)

	conn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx)

	if _, resetErr := conn.Exec(ctx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public`); resetErr != nil {
		t.Fatalf("resetting the schema: %v", resetErr)
	}
	paths, err := filepath.Glob(filepath.Join("..", "store", "migrations", "*.up.sql"))
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

	const appRole, appPassword = "warden_test_app", "warden_test_app_password"
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, appRole).Scan(&exists); err != nil {
		t.Fatalf("checking for the application role: %v", err)
	}
	if !exists {
		if _, err := conn.Exec(ctx, `CREATE ROLE `+appRole+` LOGIN PASSWORD '`+appPassword+`'`); err != nil {
			t.Fatalf("creating the application role: %v", err)
		}
	}
	for _, stmt := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + appRole,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + appRole,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ` + appRole,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("granting: %v", err)
		}
	}

	return systemURL, replaceCredentials(t, systemURL, appRole, appPassword)
}
