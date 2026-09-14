package oidcop_test

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

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/cache"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/oidcop"
	"github.com/warden-project/warden/internal/provision"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

const dsnEnv = "WARDEN_TEST_DATABASE_URL"

type fixture struct {
	clients    *oidcop.Clients
	tenantPool *store.Store
	system     *store.Store
	acme       string
	rival      string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("set %s to run the OAuth client tests", dsnEnv)
	}
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
			t.Fatalf("granting: %v", grantErr)
		}
	}

	cfg := config.Defaults()
	cfg.Environment = config.EnvDevelopment
	cfg.Issuer = "https://warden.example.com"
	cfg.Database.SystemURL = secrets.New(dsn)
	cfg.Database.URL = secrets.New(strings.Replace(dsn, "warden:warden@", appRole+":"+appPassword+"@", 1))
	cfg.Database.MaxOpenConns = 4
	cfg.Database.MaxIdleConns = 1
	cfg.Database.ConnectTimeout = 10 * time.Second
	cfg.Database.StatementTimeout = 10 * time.Second

	system, err := store.Open(ctx, cfg, store.SystemAccess)
	if err != nil {
		t.Fatalf("system store: %v", err)
	}
	t.Cleanup(system.Close)
	tenantPool, err := store.Open(ctx, cfg, store.TenantScoped)
	if err != nil {
		t.Fatalf("tenant store: %v", err)
	}
	t.Cleanup(tenantPool.Close)

	p, err := provision.New(system)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	acme, err := p.CreateTenant(ctx, "acme", "ACME")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	rival, err := p.CreateTenant(ctx, "rival", "Rival")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}

	// Cheap Argon2id: these tests are about the registry, not the cost of a hash.
	params := authn.DefaultParams()
	params.Memory, params.Time = 8*1024, 1

	clients, err := oidcop.NewClients(tenantPool, system, params)
	if err != nil {
		t.Fatalf("NewClients: %v", err)
	}
	return &fixture{
		clients: clients, tenantPool: tenantPool, system: system,
		acme: acme, rival: rival,
	}
}

func TestRegisteringAPublicClient(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	client, secret, err := f.clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: f.acme, Key: "billing-web", Name: "Billing",
		Public:       true,
		RedirectURIs: []string{"https://billing.acme.test/callback"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if secret != "" {
		t.Fatal("a public client was given a secret; it cannot keep one")
	}
	if !strings.HasPrefix(client.ID, "oac_") {
		t.Fatalf("client_id is %q; want an opaque generated id", client.ID)
	}
	if client.ID == "billing-web" {
		t.Fatal("the client_id is the chosen key; two tenants choosing the same key would " +
			"be indistinguishable at the token endpoint")
	}
	if !client.RequirePKCE {
		t.Fatal("a public client was registered without PKCE required")
	}
	if client.TokenEndpointAuthMethod != oidcop.AuthMethodNone {
		t.Fatalf("auth method is %q; a public client authenticates with nothing",
			client.TokenEndpointAuthMethod)
	}

	// The defaults are the safe ones.
	if got := client.GetGrantTypes(); !got.Has("authorization_code") || !got.Has("refresh_token") {
		t.Fatalf("default grants are %v", got)
	}
	if got := client.GetResponseTypes(); len(got) != 1 || got[0] != "code" {
		t.Fatalf("default response types are %v; want code only", got)
	}
}

// TestAConfidentialClientAuthenticatesWithItsSecret covers the credential half: the
// secret is shown once, stored only as a hash, and is what the token endpoint checks.
func TestAConfidentialClientAuthenticatesWithItsSecret(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	client, secret, err := f.clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: f.acme, Key: "server-side", Name: "Server side",
		// Public is false: the zero value is the confidential one, so a caller who
		// did not think about it gets a client that must authenticate rather than one
		// that need not.
		RedirectURIs: []string{"https://acme.test/callback"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if client.Public {
		t.Fatal("the zero value of Public produced a public client; the safe default is " +
			"the one that requires a credential")
	}
	if secret == "" {
		t.Fatal("a confidential client was registered with no secret")
	}
	if client.TokenEndpointAuthMethod != oidcop.AuthMethodClientSecretBasic {
		t.Fatalf("auth method is %q", client.TokenEndpointAuthMethod)
	}

	// Stored as a hash, never in the clear.
	if client.SecretHash == secret || !strings.HasPrefix(client.SecretHash, "$argon2id$") {
		t.Fatalf("the secret is stored as %q; want an Argon2id hash", client.SecretHash)
	}

	ok, err := f.clients.AuthenticateSecret(ctx, client, secret)
	if err != nil {
		t.Fatalf("AuthenticateSecret: %v", err)
	}
	if !ok {
		t.Fatal("the correct client secret did not authenticate")
	}

	ok, err = f.clients.AuthenticateSecret(ctx, client, secret+"x")
	if err != nil {
		t.Fatalf("AuthenticateSecret: %v", err)
	}
	if ok {
		t.Fatal("a wrong client secret authenticated")
	}

	// An unknown client still does the Argon2id work, so the token endpoint does not
	// become an oracle for which client ids exist.
	if ok, decoyErr := f.clients.AuthenticateSecret(ctx, nil, secret); decoyErr != nil || ok {
		t.Fatalf("authenticating against no client returned ok=%v err=%v", ok, decoyErr)
	}
}

// TestRotatingAClientSecretInvalidatesTheOldOne. There is no overlap window for client
// secrets — SPEC §8.4's is for service accounts, a different credential.
func TestRotatingAClientSecretInvalidatesTheOldOne(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	client, first, err := f.clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: f.acme, Key: "server-side",
		RedirectURIs: []string{"https://acme.test/callback"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	second, err := f.clients.SetSecret(ctx, f.acme, client.ID)
	if err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	if second == first {
		t.Fatal("rotation produced the same secret")
	}

	reloaded, err := f.clients.ByID(ctx, f.acme, client.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if ok, authErr := f.clients.AuthenticateSecret(ctx, reloaded, first); authErr != nil || ok {
		t.Fatalf("the previous secret still authenticates (ok=%v err=%v)", ok, authErr)
	}
	if ok, authErr := f.clients.AuthenticateSecret(ctx, reloaded, second); authErr != nil || !ok {
		t.Fatalf("the new secret does not authenticate (ok=%v err=%v)", ok, authErr)
	}

	// A public client has no secret to rotate, and says so rather than inventing one.
	public, _, err := f.clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: f.acme, Key: "spa", Public: true,
		RedirectURIs: []string{"https://acme.test/spa"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, rotateErr := f.clients.SetSecret(ctx, f.acme, public.ID); !errors.Is(rotateErr, oidcop.ErrNoSuchClient) {
		t.Fatalf("rotating a public client's secret returned %v", rotateErr)
	}
}

func TestRedirectURIsAreValidated(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	for name, uri := range map[string]string{
		"wildcard host": "https://*.acme.test/callback",
		"wildcard path": "https://acme.test/*",
		"question mark": "https://acme.test/cb?",
		"fragment":      "https://acme.test/cb#done",
		"no scheme":     "acme.test/callback",
		"plain http":    "http://acme.test/callback",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := f.clients.Register(ctx, oidcop.NewClientOptions{
				TenantID: f.acme, Key: "c-" + strings.ReplaceAll(name, " ", "-"),
				RedirectURIs: []string{uri},
			})
			if err == nil {
				t.Fatalf("%q was accepted as a redirect_uri", uri)
			}
		})
	}

	// Loopback http is allowed: RFC 8252 §8.3, and there is no network to intercept.
	if _, _, err := f.clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: f.acme, Key: "native-app",
		RedirectURIs: []string{"http://127.0.0.1:8484/callback"},
	}); err != nil {
		t.Fatalf("loopback http was refused: %v — RFC 8252 §8.3 allows it for native apps", err)
	}
}

// TestForbiddenGrantsAreRefused is half of M1-6's exit condition: implicit and ROPC are
// absent, not disabled. The other half is the schema constraint, covered below.
func TestForbiddenGrantsAreRefused(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	for _, grant := range []string{"implicit", "password"} {
		t.Run(grant, func(t *testing.T) {
			_, _, err := f.clients.Register(ctx, oidcop.NewClientOptions{
				TenantID: f.acme, Key: "bad-" + grant,
				GrantTypes:   []string{"authorization_code", grant},
				RedirectURIs: []string{"https://acme.test/callback"},
			})
			if err == nil {
				t.Fatalf("a client was registered with the %q grant", grant)
			}
			if !strings.Contains(err.Error(), "not implemented") {
				t.Fatalf("the refusal does not say the grant is unimplemented: %v", err)
			}
		})
	}
}

// TestTheDatabaseRefusesForbiddenGrantsToo is the structural half. Application code can
// be bypassed — a migration, a console, a future handler — and the constraint cannot.
func TestTheDatabaseRefusesForbiddenGrantsToo(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	conn, err := pgx.Connect(ctx, os.Getenv(dsnEnv))
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck // teardown

	for name, stmt := range map[string]string{
		"implicit grant": `INSERT INTO oauth_client (id, tenant_id, key, name, grant_types, redirect_uris)
		                   VALUES ('oac_bad1', $1, 'bad1', 'Bad', '{authorization_code,implicit}', '{https://x/cb}')`,
		"password grant": `INSERT INTO oauth_client (id, tenant_id, key, name, grant_types, redirect_uris)
		                   VALUES ('oac_bad2', $1, 'bad2', 'Bad', '{authorization_code,password}', '{https://x/cb}')`,
		"token response type": `INSERT INTO oauth_client (id, tenant_id, key, name, response_types, redirect_uris)
		                        VALUES ('oac_bad3', $1, 'bad3', 'Bad', '{code,token}', '{https://x/cb}')`,
		"public client with a secret": `INSERT INTO oauth_client (id, tenant_id, key, name, public, secret_hash, redirect_uris)
		                                VALUES ('oac_bad4', $1, 'bad4', 'Bad', true, '$argon2id$v=19$m=1,t=1,p=1$a$b', '{https://x/cb}')`,
		"public client without PKCE": `INSERT INTO oauth_client (id, tenant_id, key, name, public, require_pkce, redirect_uris)
		                               VALUES ('oac_bad5', $1, 'bad5', 'Bad', true, false, '{https://x/cb}')`,
		"code flow with no redirect_uri": `INSERT INTO oauth_client (id, tenant_id, key, name, redirect_uris)
		                                   VALUES ('oac_bad6', $1, 'bad6', 'Bad', '{}')`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, execErr := conn.Exec(ctx, stmt, f.acme); execErr == nil {
				t.Fatalf("the database accepted %s; SPEC §7.7 requires these to be absent, "+
					"which means unrepresentable and not merely unused", name)
			}
		})
	}
}

func TestClientsAreTenantScoped(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	acmeClient, _, err := f.clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: f.acme, Key: "billing-web",
		RedirectURIs: []string{"https://billing.acme.test/callback"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// The rival tenant cannot see it, by id or by key.
	if _, byIDErr := f.clients.ByID(ctx, f.rival, acmeClient.ID); !errors.Is(byIDErr, oidcop.ErrNoSuchClient) {
		t.Fatalf("another tenant loaded the client by id: %v", byIDErr)
	}
	if _, byKeyErr := f.clients.ByKey(ctx, f.rival, "billing-web"); !errors.Is(byKeyErr, oidcop.ErrNoSuchClient) {
		t.Fatalf("another tenant loaded the client by key: %v", byKeyErr)
	}
	if list, listErr := f.clients.List(ctx, f.rival); listErr != nil || len(list) != 0 {
		t.Fatalf("another tenant listed %d clients (err %v)", len(list), listErr)
	}

	// Nor can it disable or delete it.
	if enableErr := f.clients.SetEnabled(ctx, f.rival, acmeClient.ID, false); !errors.Is(enableErr, oidcop.ErrNoSuchClient) {
		t.Fatalf("another tenant disabled the client: %v", enableErr)
	}
	if deleteErr := f.clients.Delete(ctx, f.rival, acmeClient.ID); !errors.Is(deleteErr, oidcop.ErrNoSuchClient) {
		t.Fatalf("another tenant deleted the client: %v", deleteErr)
	}

	// And it survived all of that.
	still, err := f.clients.ByID(ctx, f.acme, acmeClient.ID)
	if err != nil {
		t.Fatalf("the client was affected by another tenant: %v", err)
	}
	if !still.Enabled() {
		t.Fatal("another tenant disabled the client")
	}

	// The same key in two tenants is fine, and produces different client ids.
	rivalClient, _, err := f.clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: f.rival, Key: "billing-web",
		RedirectURIs: []string{"https://billing.rival.test/callback"},
	})
	if err != nil {
		t.Fatalf("the same key in another tenant was refused: %v", err)
	}
	if rivalClient.ID == acmeClient.ID {
		t.Fatal("two tenants' clients share a client_id")
	}
}

// TestTenantOfResolvesAClientBeforeAnyScopeExists is what the token endpoint depends on.
func TestTenantOfResolvesAClientBeforeAnyScopeExists(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	client, _, err := f.clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: f.acme, Key: "billing-web",
		RedirectURIs: []string{"https://billing.acme.test/callback"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	tenantID, err := f.clients.TenantOf(ctx, client.ID)
	if err != nil {
		t.Fatalf("TenantOf: %v", err)
	}
	if tenantID != f.acme {
		t.Fatalf("resolved to %s; want %s", tenantID, f.acme)
	}

	if _, unknownErr := f.clients.TenantOf(ctx, "oac_nothing"); !errors.Is(unknownErr, oidcop.ErrNoSuchClient) {
		t.Fatalf("an unknown client id returned %v; want ErrNoSuchClient", unknownErr)
	}

	// Lookup is the two-step the protocol endpoints use.
	looked, err := f.clients.Lookup(ctx, client.ID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if looked.Key != "billing-web" {
		t.Fatalf("Lookup returned %q", looked.Key)
	}
}

func TestDisablingAndDeletingAClient(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	client, _, err := f.clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: f.acme, Key: "billing-web",
		RedirectURIs: []string{"https://billing.acme.test/callback"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if disableErr := f.clients.SetEnabled(ctx, f.acme, client.ID, false); disableErr != nil {
		t.Fatalf("SetEnabled: %v", disableErr)
	}
	disabled, err := f.clients.ByID(ctx, f.acme, client.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if disabled.Enabled() {
		t.Fatal("the client is still enabled")
	}

	if enableErr := f.clients.SetEnabled(ctx, f.acme, client.ID, true); enableErr != nil {
		t.Fatalf("SetEnabled: %v", enableErr)
	}
	if again, byIDErr := f.clients.ByID(ctx, f.acme, client.ID); byIDErr != nil || !again.Enabled() {
		t.Fatalf("the client was not re-enabled: %v", byIDErr)
	}

	if deleteErr := f.clients.Delete(ctx, f.acme, client.ID); deleteErr != nil {
		t.Fatalf("Delete: %v", deleteErr)
	}
	if _, goneErr := f.clients.ByID(ctx, f.acme, client.ID); !errors.Is(goneErr, oidcop.ErrNoSuchClient) {
		t.Fatalf("the client survived deletion: %v", goneErr)
	}
}

// TestAnEmptyAudienceMeansTheClientItself keeps a token with no stated audience from
// being one that some other resource server accepts.
func TestAnEmptyAudienceMeansTheClientItself(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	client, _, err := f.clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: f.acme, Key: "billing-web",
		RedirectURIs: []string{"https://billing.acme.test/callback"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	audience := client.GetAudience()
	if len(audience) != 1 || audience[0] != client.ID {
		t.Fatalf("audience is %v; an unconfigured audience must mean this client alone", audience)
	}
}

// --- the provider fixture -----------------------------------------------------------

// providerFixture is the client registry plus a fully composed provider, which needs
// the session store, the refresh-token store and a signing key behind it.
type providerFixture struct {
	*fixture
	provider *oidcop.Provider
	storage  *oidcop.Storage
	// session is a live Warden session. Every token the provider issues hangs off one:
	// refresh_token's foreign key says so, and "log out everywhere" walks it.
	session *authn.Session
	user    string
}

func testKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	material := make([]byte, secrets.KEKSize)
	for i := range material {
		material[i] = byte(i * 5)
	}
	kek, err := secrets.NewKEKFromBytes(material)
	if err != nil {
		t.Fatalf("NewKEKFromBytes: %v", err)
	}
	kr, err := secrets.NewKeyring(kek)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

// keyringMaterial returns the raw KEK, so a test can assert a derived secret is not it.
func keyringMaterial(t *testing.T, _ *secrets.Keyring) []byte {
	t.Helper()
	material := make([]byte, secrets.KEKSize)
	for i := range material {
		material[i] = byte(i * 5)
	}
	return material
}

func newProviderFixture(t *testing.T) *providerFixture {
	t.Helper()
	f := newFixture(t)
	ctx := context.Background()

	keyring := testKeyring(t)
	cfg := config.Defaults()
	cfg.Environment = config.EnvDevelopment
	cfg.Issuer = "https://warden.example.com"
	// ES256: the provider tests care about composition and policy, not key size, and an
	// RSA keygen per fixture is a visible cost.
	cfg.Security.TokenSigningAlgorithm = keys.ES256

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	km, err := keys.NewManager(f.system, keyring, cfg, log)
	if err != nil {
		t.Fatalf("key manager: %v", err)
	}
	km.SetCacheTTL(0)
	if _, rotateErr := km.Rotate(ctx, true); rotateErr != nil {
		t.Fatalf("creating a signing key: %v", rotateErr)
	}

	inProcess := config.Defaults()
	inProcess.Environment = config.EnvDevelopment
	inProcess.Cache.Backend = config.CacheInProcess
	cacheClient, err := cache.Open(ctx, inProcess)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	t.Cleanup(func() { _ = cacheClient.Close() }) //nolint:errcheck // teardown

	sessions, err := authn.NewSessions(f.tenantPool, f.system, cacheClient, authn.SessionOptions{
		AbsoluteLifetime: 30 * 24 * time.Hour,
		IdleTimeout:      7 * 24 * time.Hour,
		Log:              log,
	})
	if err != nil {
		t.Fatalf("sessions: %v", err)
	}
	refresh, err := authn.NewRefreshTokens(f.tenantPool, f.system, sessions, authn.RefreshTokenOptions{
		AbsoluteLifetime: 30 * 24 * time.Hour,
		IdleLifetime:     7 * 24 * time.Hour,
		Log:              log,
	})
	if err != nil {
		t.Fatalf("refresh tokens: %v", err)
	}

	storage, err := oidcop.NewStorage(f.tenantPool, f.system, f.clients, oidcop.StorageOptions{
		Refresh: refresh, Sessions: sessions, Log: log,
	})
	if err != nil {
		t.Fatalf("storage: %v", err)
	}

	opts, err := oidcop.ProviderOptionsFrom(cfg, km, keyring, log)
	if err != nil {
		t.Fatalf("provider options: %v", err)
	}
	provider, err := oidcop.NewProvider(storage, opts)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}

	p, err := provision.New(f.system)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	user, err := p.CreateUser(ctx, "acme", "maria@acme.test", nil)
	if err != nil {
		t.Fatalf("creating a user: %v", err)
	}
	session, err := sessions.Create(ctx, f.acme, user, []string{"pwd"}, "", "test")
	if err != nil {
		t.Fatalf("creating a session: %v", err)
	}

	return &providerFixture{
		fixture: f, provider: provider, storage: storage,
		session: session, user: user,
	}
}

// confidentialClient registers a client that can hold a secret, which is the only kind
// that could otherwise skip PKCE or use client authentication.
func (f *providerFixture) confidentialClient(t *testing.T) (*oidcop.Client, string) {
	t.Helper()
	client, secret, err := f.clients.Register(context.Background(), oidcop.NewClientOptions{
		TenantID: f.acme, Key: "provider-test", Name: "Provider test",
		RedirectURIs: []string{"https://app.acme.test/callback"},
	})
	if err != nil {
		t.Fatalf("registering a client: %v", err)
	}
	return client, secret
}
