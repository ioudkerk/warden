package authn_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/provision"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

const dsnEnv = "WARDEN_TEST_DATABASE_URL"

// goodPassword clears the default policy: long enough, and not in the corpus.
const goodPassword = "correct horse battery staple"

type fixture struct {
	a        *authn.Authenticator
	p        *provision.Provisioner
	tenantID string
	// maria has a password; bob exists with none.
	maria, bob string
	mariaEmail string
	bobEmail   string
}

// dsnFromEnv returns the test database, skipping the test when there is none.
func dsnFromEnv(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("set %s to run the credential tests", dsnEnv)
	}
	return dsn
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := dsnFromEnv(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck // teardown

	if _, resetErr := conn.Exec(ctx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public`); resetErr != nil {
		t.Fatalf("resetting the schema: %v", resetErr)
	}
	paths, globErr := filepath.Glob(filepath.Join("..", "store", "migrations", "*.up.sql"))
	if globErr != nil || len(paths) == 0 {
		t.Fatalf("no migrations found: %v", globErr)
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

	// The unprivileged role, so the tenant pool is subject to row-level security the
	// way it is in production. A superuser here would still pass every test in this
	// file and would quietly stop proving that credentials are tenant-scoped.
	const appRole, appPassword = "warden_test_app", "warden_test_app_password"
	var exists bool
	if scanErr := conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, appRole).Scan(&exists); scanErr != nil {
		t.Fatalf("checking for the application role: %v", scanErr)
	}
	if !exists {
		if _, createErr := conn.Exec(ctx,
			`CREATE ROLE `+appRole+` LOGIN PASSWORD '`+appPassword+`'`); createErr != nil {
			t.Fatalf("creating the application role: %v", createErr)
		}
	}
	for _, stmt := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + appRole,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + appRole,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ` + appRole,
	} {
		if _, grantErr := conn.Exec(ctx, stmt); grantErr != nil {
			t.Fatalf("granting to the application role: %v", grantErr)
		}
	}

	cfg := config.Defaults()
	cfg.Environment = config.EnvDevelopment
	cfg.Issuer = "https://warden.example.com"
	cfg.Database.SystemURL = secrets.New(dsn)
	cfg.Database.URL = secrets.New(strings.Replace(dsn, "warden:warden@", appRole+":"+appPassword+"@", 1))
	cfg.Database.MaxOpenConns = 6
	cfg.Database.MaxIdleConns = 2
	cfg.Database.ConnectTimeout = 10 * time.Second
	cfg.Database.StatementTimeout = 10 * time.Second

	system, err := store.Open(ctx, cfg, store.SystemAccess)
	if err != nil {
		t.Fatalf("opening the system store: %v", err)
	}
	t.Cleanup(system.Close)
	tenantPool, err := store.Open(ctx, cfg, store.TenantScoped)
	if err != nil {
		t.Fatalf("opening the tenant store: %v", err)
	}
	t.Cleanup(tenantPool.Close)

	p, err := provision.New(system)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	manifest, err := provision.LoadManifest(filepath.Join("..", "..", "examples", "warden.yaml"))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if _, applyErr := p.Apply(ctx, manifest); applyErr != nil {
		t.Fatalf("apply: %v", applyErr)
	}
	tenantID, err := p.CreateTenant(ctx, "acme", "ACME")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}

	f := &fixture{
		p: p, tenantID: tenantID,
		mariaEmail: "maria@acme.test", bobEmail: "bob@acme.test",
	}
	if f.maria, err = p.CreateUser(ctx, "acme", f.mariaEmail, nil); err != nil {
		t.Fatalf("creating maria: %v", err)
	}
	if f.bob, err = p.CreateUser(ctx, "acme", f.bobEmail, nil); err != nil {
		t.Fatalf("creating bob: %v", err)
	}

	// Cheap parameters. Every test here is about the logic around the hash, not the
	// cost of it; the one test that depends on the cost builds its own authenticator.
	params := authn.DefaultParams()
	params.Memory, params.Time = 8*1024, 1

	f.a, err = authn.New(tenantPool, system, authn.Options{
		Params: params,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Audit:  audit.NewWriter(),
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	// Maria can log in; Bob exists but has no credential, which is the state a user is
	// in between being invited and redeeming the invitation.
	if err := f.a.SetPassword(ctx, f.tenantID, f.maria, goodPassword); err != nil {
		t.Fatalf("setting maria's password: %v", err)
	}
	activate(t, conn, f.maria)
	activate(t, conn, f.bob)
	return f
}

// activate moves a user to 'active'. CreateUser leaves them 'invited', and an invited
// user is denied regardless of password — correct, but it would mask the behaviour
// every other test here is trying to observe.
func activate(t *testing.T, conn *pgx.Conn, userID string) {
	t.Helper()
	if _, err := conn.Exec(context.Background(),
		`UPDATE app_user SET status='active' WHERE id=$1`, userID); err != nil {
		t.Fatalf("activating %s: %v", userID, err)
	}
}

func TestAuthenticateAcceptsTheRightPassword(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	result, err := f.a.Authenticate(ctx, f.tenantID, f.mariaEmail, goodPassword)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if result.UserID != f.maria {
		t.Fatalf("authenticated as %s; want %s", result.UserID, f.maria)
	}
}

// TestEveryFailureLooksTheSame is the enumeration property, at the level of what a
// caller can observe. The timing half is TestUnknownUserAndWrongPasswordTakeTheSameTime.
func TestEveryFailureLooksTheSame(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	for name, attempt := range map[string]struct{ email, password string }{
		"no such user":            {"nobody@acme.test", goodPassword},
		"wrong password":          {f.mariaEmail, "a different password entirely"},
		"user with no password":   {f.bobEmail, goodPassword},
		"empty password":          {f.mariaEmail, ""},
		"email of another tenant": {"user@rival.test", goodPassword},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.a.Authenticate(ctx, f.tenantID, attempt.email, attempt.password)
			if err == nil {
				t.Fatal("the attempt succeeded")
			}
			if !errors.Is(err, authn.ErrInvalidCredentials) {
				t.Fatalf("error is %v; every failure must be ErrInvalidCredentials, or the "+
					"difference becomes an account-existence oracle", err)
			}
			// The error text must not name the cause either: it reaches logs and,
			// sooner or later, a response body.
			if msg := err.Error(); msg != authn.ErrInvalidCredentials.Error() {
				t.Fatalf("error text is %q; want exactly %q", msg, authn.ErrInvalidCredentials.Error())
			}
		})
	}
}

// TestASuspendedUserIsRefusedWithTheRightPassword covers SPEC §7.6: anything but
// active denies. It is also an enumeration case — a suspended account must not be
// distinguishable from a nonexistent one.
func TestASuspendedUserIsRefusedWithTheRightPassword(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	dsn := os.Getenv(dsnEnv)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck // teardown

	for _, status := range []string{"suspended", "deprovisioned", "invited"} {
		t.Run(status, func(t *testing.T) {
			if _, execErr := conn.Exec(ctx,
				`UPDATE app_user SET status=$1 WHERE id=$2`, status, f.maria); execErr != nil {
				t.Fatalf("setting status: %v", execErr)
			}
			_, authErr := f.a.Authenticate(ctx, f.tenantID, f.mariaEmail, goodPassword)
			if !errors.Is(authErr, authn.ErrInvalidCredentials) {
				t.Fatalf("a %s user with the correct password got %v; want ErrInvalidCredentials", status, authErr)
			}
		})
	}

	// And it works again once she is active, so the test is observing status rather
	// than a broken fixture.
	if _, execErr := conn.Exec(ctx, `UPDATE app_user SET status='active' WHERE id=$1`, f.maria); execErr != nil {
		t.Fatalf("reactivating: %v", execErr)
	}
	if _, authErr := f.a.Authenticate(ctx, f.tenantID, f.mariaEmail, goodPassword); authErr != nil {
		t.Fatalf("a reactivated user could not log in: %v", authErr)
	}
}

// TestRehashOnParameterChange is SPEC §7.2's upgrade path.
func TestRehashOnParameterChange(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	dsn := os.Getenv(dsnEnv)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck // teardown

	storedHash := func() string {
		var h string
		if scanErr := conn.QueryRow(ctx,
			`SELECT secret_hash FROM credential WHERE user_id=$1 AND type='password'`,
			f.maria).Scan(&h); scanErr != nil {
			t.Fatalf("reading the stored hash: %v", scanErr)
		}
		return h
	}
	before := storedHash()

	// A second authenticator over the same database, with a higher cost — this is what
	// raising security parameters looks like at deploy time.
	raised := authn.DefaultParams()
	raised.Memory, raised.Time = 16*1024, 2

	tenantPool, system := f.stores(t)
	upgraded, err := authn.New(tenantPool, system, authn.Options{
		Params: raised, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	result, err := upgraded.Authenticate(ctx, f.tenantID, f.mariaEmail, goodPassword)
	if err != nil {
		t.Fatalf("the old hash stopped verifying after the parameters were raised: %v", err)
	}
	if !result.Rehashed {
		t.Fatal("logging in under raised parameters did not rehash")
	}

	after := storedHash()
	if after == before {
		t.Fatal("the stored hash was not replaced")
	}
	if !strings.Contains(after, "m=16384,t=2") {
		t.Fatalf("the new hash is %q; want the raised parameters", after)
	}

	// And the new hash verifies, so the rehash did not corrupt the credential.
	if _, authErr := upgraded.Authenticate(ctx, f.tenantID, f.mariaEmail, goodPassword); authErr != nil {
		t.Fatalf("the rehashed credential does not verify: %v", authErr)
	}
}

// TestPolicyIsEnforcedPerTenant covers the per-tenant half of SPEC §7.2.
func TestPolicyIsEnforcedPerTenant(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	// The default policy: twelve characters, no composition rules, breach check on.
	if err := f.a.SetPassword(ctx, f.tenantID, f.bob, "short1!"); err == nil {
		t.Fatal("a seven-character password was accepted under the default policy")
	}
	if err := f.a.SetPassword(ctx, f.tenantID, f.bob, "passwordpassword"); err == nil {
		t.Fatal("a breached password was accepted")
	} else if !strings.Contains(err.Error(), "breach") {
		t.Fatalf("a breached password was refused for the wrong reason: %v", err)
	}
	if err := f.a.SetPassword(ctx, f.tenantID, f.bob, goodPassword); err != nil {
		t.Fatalf("a good password was refused: %v", err)
	}

	// Tighten the policy and the same password stops qualifying.
	strict := authn.DefaultPolicy()
	strict.MinLength = 16
	strict.RequireUpper, strict.RequireDigit = true, true
	if err := f.a.SetPolicy(ctx, f.tenantID, strict); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	err := f.a.SetPassword(ctx, f.tenantID, f.bob, "lowercaseonlybutlong")
	if err == nil {
		t.Fatal("the tightened policy was not applied")
	}
	var violation *authn.PolicyViolation
	if !errors.As(err, &violation) {
		t.Fatalf("error is %v; want a PolicyViolation listing what failed", err)
	}
	if len(violation.Reasons) != 2 {
		t.Fatalf("reasons = %v; want both the uppercase and the digit rule, so that "+
			"someone choosing a password is told everything at once", violation.Reasons)
	}

	if err := f.a.SetPassword(ctx, f.tenantID, f.bob, "Vp2kwQm3zLd6rXy9"); err != nil {
		t.Fatalf("a password meeting the tightened policy was refused: %v", err)
	}

	// A tightened policy must not lock out an existing credential that predates it.
	// The rule governs what may be *set*, not what may be used.
	if _, authErr := f.a.Authenticate(ctx, f.tenantID, f.mariaEmail, goodPassword); authErr != nil {
		t.Fatalf("tightening the policy locked out an existing password: %v", authErr)
	}
}

func TestPolicyRoundTripsThroughTheDatabase(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	want := authn.Policy{
		MinLength: 20, MaxLength: 200,
		RequireUpper: true, RequireSymbol: true, CheckBreached: false,
	}
	if err := f.a.SetPolicy(ctx, f.tenantID, want); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}

	// A fresh authenticator, so the answer comes from the database rather than the
	// in-process cache.
	tenantPool, system := f.stores(t)
	fresh, err := authn.New(tenantPool, system, authn.Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	got, err := fresh.Policy(ctx, f.tenantID)
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	if got != want {
		t.Fatalf("policy round-tripped as %+v; want %+v", got, want)
	}
}

// TestAPartialPolicyKeepsTheOtherDefaults is the trap in storing a struct as JSON: a
// policy that sets only min_length must not read back with check_breached false.
func TestAPartialPolicyKeepsTheOtherDefaults(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	dsn := os.Getenv(dsnEnv)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck // teardown

	if _, execErr := conn.Exec(ctx,
		`UPDATE tenant SET settings = jsonb_build_object('password_policy',
		   jsonb_build_object('min_length', 16)) WHERE id=$1`, f.tenantID); execErr != nil {
		t.Fatalf("writing a partial policy: %v", execErr)
	}

	tenantPool, system := f.stores(t)
	fresh, err := authn.New(tenantPool, system, authn.Options{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	got, err := fresh.Policy(ctx, f.tenantID)
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	if got.MinLength != 16 {
		t.Fatalf("min length = %d; want the stored 16", got.MinLength)
	}
	if !got.CheckBreached {
		t.Fatal("a policy that set only min_length switched the breach check off")
	}
	if got.MaxLength != authn.DefaultPolicy().MaxLength {
		t.Fatalf("max length = %d; want the default %d", got.MaxLength, authn.DefaultPolicy().MaxLength)
	}
}

// stores reopens the pools, for tests that need a second Authenticator.
func (f *fixture) stores(t *testing.T) (tenantPool, system *store.Store) {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	const appRole, appPassword = "warden_test_app", "warden_test_app_password"

	cfg := config.Defaults()
	cfg.Environment = config.EnvDevelopment
	cfg.Issuer = "https://warden.example.com"
	cfg.Database.SystemURL = secrets.New(dsn)
	cfg.Database.URL = secrets.New(strings.Replace(dsn, "warden:warden@", appRole+":"+appPassword+"@", 1))
	cfg.Database.MaxOpenConns = 4
	cfg.Database.MaxIdleConns = 1
	cfg.Database.ConnectTimeout = 10 * time.Second
	cfg.Database.StatementTimeout = 10 * time.Second

	ctx := context.Background()
	var err error
	if system, err = store.Open(ctx, cfg, store.SystemAccess); err != nil {
		t.Fatalf("system store: %v", err)
	}
	t.Cleanup(system.Close)
	if tenantPool, err = store.Open(ctx, cfg, store.TenantScoped); err != nil {
		t.Fatalf("tenant store: %v", err)
	}
	t.Cleanup(tenantPool.Close)
	return tenantPool, system
}
