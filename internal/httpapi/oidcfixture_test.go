package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/cache"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/httpapi"
	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/oidcop"
	"github.com/warden-project/warden/internal/provision"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

// oidcFixture is a complete provider behind the real handler: a tenant, a user with a
// password, a registered client, a signing key and a cache.
//
// Heavier than the decision-API fixture on purpose. The flow under test crosses every
// piece of M1 — keys, credentials, sessions, refresh tokens, the client registry and the
// provider — and a fixture that stubbed any of them would be testing the stub.
type oidcFixture struct {
	handler http.Handler
	keys    *keys.Manager

	issuer      string
	client      *oidcop.Client
	redirectURI string

	// resource is a confidential client standing in for a resource server: it is the
	// thing that introspects tokens and revokes them, and it can only do either because
	// it holds a secret. audience is what a token says it is for.
	resource       *oidcop.Client
	resourceSecret string
	device         *oidcop.Client
	deviceOnly     *oidcop.Client

	confidential       *oidcop.Client
	confidentialSecret string

	// A client belonging to a different tenant entirely.
	rival         *oidcop.Client
	rivalSecret   string
	audience      string
	postLogoutURI string

	email    string
	password string
	userID   string

	// Kept so a test can build a second server that differs in one setting.
	cfg  *config.Config
	deps httpapi.Deps
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("set %s to run the OIDC flow tests", dsnEnv)
	}
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck // teardown

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

	const appRole, appPassword = "warden_test_app", "warden_test_app_password"
	var exists bool
	if scanErr := conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, appRole).Scan(&exists); scanErr != nil {
		t.Fatalf("role check: %v", scanErr)
	}
	if !exists {
		if _, createErr := conn.Exec(ctx,
			`CREATE ROLE `+appRole+` LOGIN PASSWORD '`+appPassword+`'`); createErr != nil {
			t.Fatalf("creating role: %v", createErr)
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

	// http, so the fixture exercises the development cookie names. A test on https
	// would never notice that a Secure cookie is dropped over plaintext.
	const issuer = "http://warden.test"

	cfg := config.Defaults()
	cfg.Environment = config.EnvDevelopment
	cfg.Issuer = issuer
	cfg.Database.SystemURL = secrets.New(dsn)
	cfg.Database.URL = secrets.New(strings.Replace(dsn, "warden:warden@", appRole+":"+appPassword+"@", 1))
	cfg.Database.MaxOpenConns = 8
	cfg.Database.MaxIdleConns = 2
	cfg.Database.ConnectTimeout = 10 * time.Second
	cfg.Database.StatementTimeout = 10 * time.Second
	cfg.Security.TokenSigningAlgorithm = keys.ES256
	// A small allowance, so the rate-limiting test does not need dozens of requests.
	cfg.Security.Lockout.FreeAttempts = 3

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

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keyring := testKeyring(t)

	km, err := keys.NewManager(system, keyring, cfg, log)
	if err != nil {
		t.Fatalf("key manager: %v", err)
	}
	km.SetCacheTTL(0)
	if _, rotateErr := km.Rotate(ctx, true); rotateErr != nil {
		t.Fatalf("signing key: %v", rotateErr)
	}

	inProcess := config.Defaults()
	inProcess.Environment = config.EnvDevelopment
	inProcess.Cache.Backend = config.CacheInProcess
	cacheClient, err := cache.Open(ctx, inProcess)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	t.Cleanup(func() { _ = cacheClient.Close() }) //nolint:errcheck // teardown

	sessions, err := authn.NewSessions(tenantPool, system, cacheClient, authn.SessionOptions{
		AbsoluteLifetime: 30 * 24 * time.Hour,
		IdleTimeout:      7 * 24 * time.Hour,
		Log:              log,
	})
	if err != nil {
		t.Fatalf("sessions: %v", err)
	}
	refresh, err := authn.NewRefreshTokens(tenantPool, system, sessions, authn.RefreshTokenOptions{
		AbsoluteLifetime: 30 * 24 * time.Hour,
		IdleLifetime:     7 * 24 * time.Hour,
		Log:              log,
		// Without this the security events are logged and never written, and a test
		// that counted them would report zero however the code behaved.
		Audit: audit.NewWriter(),
	})
	if err != nil {
		t.Fatalf("refresh tokens: %v", err)
	}

	// Cheap Argon2id: this fixture exercises the flow, not the cost of a hash.
	params := authn.DefaultParams()
	params.Memory, params.Time = 8*1024, 1

	authenticator, err := authn.New(tenantPool, system, authn.Options{
		Params: params, Log: log,
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	lockout, err := authn.NewLockout(cacheClient, authn.LockoutOptions{
		Policy: authn.LockoutPolicy{
			FreeAttempts: 3, BaseDelay: time.Second, MaxDelay: time.Minute,
			PairWindow: time.Hour, AccountCap: 20, AccountWindow: time.Hour,
		},
		Log: log, Pepper: []byte("a-fixture-pepper"),
	})
	if err != nil {
		t.Fatalf("lockout: %v", err)
	}

	clients, err := oidcop.NewClients(tenantPool, system, params)
	if err != nil {
		t.Fatalf("clients: %v", err)
	}
	storage, err := oidcop.NewStorage(tenantPool, system, clients, oidcop.StorageOptions{
		Refresh: refresh, Sessions: sessions, Log: log,
	})
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	providerOpts, err := oidcop.ProviderOptionsFrom(cfg, km, keyring, params, log)
	if err != nil {
		t.Fatalf("provider options: %v", err)
	}
	provider, err := oidcop.NewProvider(storage, providerOpts)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}

	// The tenant, the user and the client.
	p, err := provision.New(system)
	if err != nil {
		t.Fatalf("provisioner: %v", err)
	}
	tenantID, err := p.CreateTenant(ctx, "acme", "ACME")
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	const email, password = "maria@acme.test", "correct horse battery staple"
	userID, err := p.CreateUser(ctx, "acme", email, nil)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if setErr := authenticator.SetPassword(ctx, tenantID, userID, password); setErr != nil {
		t.Fatalf("setting a password: %v", setErr)
	}

	const redirectURI = "https://app.acme.test/callback"
	const audience = "https://api.acme.test"
	const postLogoutURI = "https://app.acme.test/signed-out"
	client, _, err := clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: tenantID, Key: "app", Name: "The ACME application",
		Public:                 true,
		RedirectURIs:           []string{redirectURI},
		Scopes:                 []string{"openid", "profile", "email", "offline_access"},
		Audiences:              []string{audience},
		PostLogoutRedirectURIs: []string{postLogoutURI},
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	// The resource server. Confidential, because RFC 7662 requires the introspection
	// endpoint to be authenticated and a client that cannot hold a secret cannot
	// authenticate; and registered with the same audience, which is how a token says
	// which resource server it was issued for.
	resource, resourceSecret, err := clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: tenantID, Key: "api", Name: "The ACME API",
		Public: false,
		// The device grant as well, so that "a device code belongs to one client" has a
		// second client to be tested against.
		GrantTypes: []string{oidcop.GrantClientCredentials, oidcop.GrantDeviceCode},
		Scopes:     []string{"openid", "profile", "email", "offline_access"},
		Audiences:  []string{audience},
	})
	if err != nil {
		t.Fatalf("resource client: %v", err)
	}

	// A thing with a screen and no browser.
	device, _, err := clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: tenantID, Key: "tv", Name: "The ACME television",
		Public: true,
		// Both grants: a device that wants to stay signed in has to hold the refresh
		// grant as well, or the refresh token it is issued is one it may never use.
		GrantTypes: []string{oidcop.GrantDeviceCode, oidcop.GrantRefreshToken},
		Scopes:     []string{"openid", "profile", "email", "offline_access"},
	})
	if err != nil {
		t.Fatalf("device client: %v", err)
	}

	// The same thing without the refresh grant, for the rule that a client is not handed
	// a credential it cannot use.
	deviceOnly, _, err := clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: tenantID, Key: "radio", Name: "The ACME radio",
		Public:     true,
		GrantTypes: []string{oidcop.GrantDeviceCode},
		Scopes:     []string{"openid", "profile", "email", "offline_access"},
	})
	if err != nil {
		t.Fatalf("device-only client: %v", err)
	}

	// A confidential client of this tenant that performs the code flow. Pushing an
	// authorization request for it is supposed to require its secret.
	confidential, confidentialSecret, err := clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: tenantID, Key: "backoffice", Name: "The ACME back office",
		Public:       false,
		RedirectURIs: []string{"https://backoffice.acme.test/callback"},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
	})
	if err != nil {
		t.Fatalf("confidential client: %v", err)
	}

	// A second tenant, with a confidential client of its own. Nothing in the ordinary
	// flows touches it; it exists so that "one tenant cannot act in another" can be
	// tested rather than assumed.
	otherTenantID, err := p.CreateTenant(ctx, "rival", "Rival")
	if err != nil {
		t.Fatalf("second tenant: %v", err)
	}
	rival, rivalSecret, err := clients.Register(ctx, oidcop.NewClientOptions{
		TenantID: otherTenantID, Key: "rival-app", Name: "The rival application",
		Public:     false,
		GrantTypes: []string{oidcop.GrantClientCredentials, oidcop.GrantDeviceCode},
		Scopes:     []string{"openid", "profile", "email", "offline_access"},
	})
	if err != nil {
		t.Fatalf("rival client: %v", err)
	}

	deps := httpapi.Deps{
		Config: cfg, Log: log,
		Tenant: tenantPool, System: system,
		Cache: cacheClient, Keys: km, Sessions: sessions,
		Provider: provider, Authn: authenticator, Lockout: lockout,
	}
	server, err := httpapi.New(deps)
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	return &oidcFixture{
		handler: server.Handler(), keys: km, issuer: issuer,
		client: client, redirectURI: redirectURI,
		resource: resource, resourceSecret: resourceSecret, audience: audience,
		device:     device,
		deviceOnly: deviceOnly,
		rival:      rival, rivalSecret: rivalSecret,
		confidential: confidential, confidentialSecret: confidentialSecret,
		postLogoutURI: postLogoutURI,
		email:         email, password: password, userID: userID,
		cfg: cfg, deps: deps,
	}
}

// withHTTPSIssuer returns a second server built from the same dependencies but with an
// https issuer, for the handful of behaviours that turn on the deployment's scheme.
func (f *oidcFixture) withHTTPSIssuer(t *testing.T) *oidcFixture {
	t.Helper()
	secureCfg := *f.cfg
	secureCfg.Issuer = "https://warden.test"

	server, err := httpapi.New(httpapi.Deps{
		Config: &secureCfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Tenant: f.deps.Tenant, System: f.deps.System,
		Cache: f.deps.Cache, Keys: f.deps.Keys, Sessions: f.deps.Sessions,
		Provider: f.deps.Provider, Authn: f.deps.Authn, Lockout: f.deps.Lockout,
	})
	if err != nil {
		t.Fatalf("second server: %v", err)
	}
	clone := *f
	clone.handler = server.Handler()
	return &clone
}

// securityEvents counts audit rows of one action.
func (f *oidcFixture) securityEvents(t *testing.T, action string) []string {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv(dsnEnv))
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck // teardown

	rows, err := conn.Query(ctx,
		`SELECT target_id FROM audit_event WHERE action = $1 ORDER BY occurred_at`, action)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var target string
		if scanErr := rows.Scan(&target); scanErr != nil {
			t.Fatalf("scanning: %v", scanErr)
		}
		out = append(out, target)
	}
	return out
}

// verifyAgainstJWKS is what a relying party does with an id token: fetch the published
// keys, select by kid, check the signature. Deliberately through the HTTP surface, so
// the test proves a stock library could do the same.
func (f *oidcFixture) verifyAgainstJWKS(t *testing.T, token string) map[string]any {
	t.Helper()

	rec := f.do(t, http.MethodGet, "/.well-known/jwks.json", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("JWKS = %d", rec.Code)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("parsing JWKS: %v", err)
	}

	parsed, err := jose.ParseSigned(token)
	if err != nil {
		t.Fatalf("the id token is not a JWS: %v", err)
	}
	kid := parsed.Signatures[0].Header.KeyID
	if kid == "" {
		t.Fatal("the id token carries no kid; a relying party would have to guess which " +
			"key signed it, and would break on the first rotation")
	}
	matched := set.Key(kid)
	if len(matched) == 0 {
		t.Fatalf("the id token names key %q, which JWKS does not publish", kid)
	}

	payload, err := parsed.Verify(matched[0])
	if err != nil {
		t.Fatalf("the id token did not verify against the published key: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("the id token payload is not JSON: %v", err)
	}
	return claims
}

var _ = httptest.NewRecorder
