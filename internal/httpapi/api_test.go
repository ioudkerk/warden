package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/decisionlog"
	"github.com/warden-project/warden/internal/httpapi"
	"github.com/warden-project/warden/internal/provision"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

const dsnEnv = "WARDEN_TEST_DATABASE_URL"

type fixture struct {
	handler  http.Handler
	acmeTok  string
	rivalTok string
	maria    string
	rival    string
	sink     *decisionlog.Sink
}

// newFixture builds two tenants, each with a user and its own service-account token.
// Two tenants rather than one on purpose: the property that matters most here is that
// a token issued to one cannot ask about the other.
func newFixture(t *testing.T) fixture { return newFixtureWithExplain(t, true) }

func newFixtureWithExplain(t *testing.T, mayExplain bool) fixture {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("set %s to run the HTTP API tests", dsnEnv)
	}
	ctx := context.Background()

	conn, connErr := pgx.Connect(ctx, dsn)
	if connErr != nil {
		t.Fatalf("connecting: %v", connErr)
	}
	defer conn.Close(ctx)
	if _, resetErr := conn.Exec(ctx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public`); resetErr != nil {
		t.Fatalf("resetting: %v", resetErr)
	}
	paths, globErr := filepath.Glob(filepath.Join("..", "store", "migrations", "*.up.sql"))
	if globErr != nil || len(paths) == 0 {
		t.Fatalf("no migrations found: %v", globErr)
	}
	sort.Strings(paths)
	for _, p := range paths {
		sql, readErr := os.ReadFile(p)
		if readErr != nil {
			t.Fatalf("reading %s: %v", p, readErr)
		}
		if _, execErr := conn.Exec(ctx, string(sql)); execErr != nil {
			t.Fatalf("applying %s: %v", filepath.Base(p), execErr)
		}
	}

	const appRole, appPassword = "warden_test_app", "warden_test_app_password"
	var exists bool
	if scanErr := conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, appRole).Scan(&exists); scanErr != nil {
		t.Fatalf("role check: %v", scanErr)
	}
	if !exists {
		if _, createErr := conn.Exec(ctx, `CREATE ROLE `+appRole+` LOGIN PASSWORD '`+appPassword+`'`); createErr != nil {
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

	cfg := config.Defaults()
	cfg.Environment = config.EnvProduction
	cfg.Issuer = "https://warden.test"
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
	manifest, err := provision.LoadManifest(filepath.Join("..", "..", "examples", "warden.yaml"))
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if _, applyErr := p.Apply(ctx, manifest); applyErr != nil {
		t.Fatalf("apply: %v", applyErr)
	}

	f := fixture{}
	for _, tn := range []string{"acme", "rival"} {
		if _, tenantErr := p.CreateTenant(ctx, tn, tn); tenantErr != nil {
			t.Fatalf("tenant %s: %v", tn, tenantErr)
		}
		user, userErr := p.CreateUser(ctx, tn, "user@"+tn+".test", map[string]any{"approval_limit": 50000})
		if userErr != nil {
			t.Fatalf("user in %s: %v", tn, userErr)
		}
		if _, grantErr := p.Grant(ctx, provision.GrantOptions{
			TenantSlug: tn, UserID: user, RoleKey: "billing.viewer", Scope: "tenant",
		}); grantErr != nil {
			t.Fatalf("grant in %s: %v", tn, grantErr)
		}
		token, tokenErr := p.CreateServiceAccount(ctx, tn, "api", mayExplain)
		if tokenErr != nil {
			t.Fatalf("token for %s: %v", tn, tokenErr)
		}
		if tn == "acme" {
			f.maria, f.acmeTok = user, token
		} else {
			f.rival, f.rivalTok = user, token
		}
	}

	sink, sinkErr := decisionlog.New(system, slog.New(slog.NewTextHandler(io.Discard, nil)),
		decisionlog.Options{FlushInterval: 20 * time.Millisecond})
	if sinkErr != nil {
		t.Fatalf("decision sink: %v", sinkErr)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sink.Close(closeCtx) //nolint:errcheck // best effort at teardown
	})
	f.sink = sink

	server, err := httpapi.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), tenantPool, system, sink)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	f.handler = server.Handler()
	return f
}

func (f fixture) post(t *testing.T, path, token, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	var decoded map[string]any
	if rec.Body.Len() > 0 {
		if decodeErr := json.Unmarshal(rec.Body.Bytes(), &decoded); decodeErr != nil {
			t.Fatalf("response is not JSON: %s", rec.Body.String())
		}
	}
	return rec.Code, decoded
}

// --- authentication -----------------------------------------------------------------

// Every rejection must look identical. Distinguishing "no such token" from "expired"
// from "disabled" tells someone probing the endpoint which of those they have found.
func TestAuthenticationFailuresAreIndistinguishable(t *testing.T) {
	f := newFixture(t)
	body := fmt.Sprintf(`{"subject":{"id":%q},"permission":"billing.invoice:read"}`, f.maria)

	cases := map[string]string{
		"no header":       "",
		"unknown token":   "wsk_completely-made-up",
		"empty token":     " ",
		"truncated token": f.acmeTok[:len(f.acmeTok)-4],
	}
	var bodies []string
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			status, resp := f.post(t, "/v1/authz/check", token, body)
			if status != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", status)
			}
			b, marshalErr := json.Marshal(resp)
			if marshalErr != nil {
				t.Fatalf("marshalling the response: %v", marshalErr)
			}
			bodies = append(bodies, string(b))
		})
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("authentication failures are distinguishable:\n  %s\n  %s", bodies[0], bodies[i])
		}
	}
}

func TestWrongSchemeIsRejected(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/authz/check",
		strings.NewReader(`{"subject":{"id":"x"},"permission":"billing.invoice:read"}`))
	req.Header.Set("Authorization", "Basic "+f.acmeTok)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a non-bearer scheme should be rejected, got %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("a 401 should say which scheme it wants")
	}
}

// The property this whole layer exists for: a token belongs to one tenant, and the
// tenant it belongs to is the only one it can ask about. A subject id is not a
// capability — knowing one must not be enough to learn anything about it.
func TestATokenCannotAskAboutAnotherTenant(t *testing.T) {
	f := newFixture(t)

	// Sanity: each token works for its own tenant's user.
	for _, c := range []struct{ name, token, subject string }{
		{"acme asks about acme", f.acmeTok, f.maria},
		{"rival asks about rival", f.rivalTok, f.rival},
	} {
		status, resp := f.post(t, "/v1/authz/check", c.token,
			fmt.Sprintf(`{"subject":{"id":%q},"permission":"billing.invoice:read"}`, c.subject))
		if status != http.StatusOK {
			t.Fatalf("%s: got %d", c.name, status)
		}
		if resp["allowed"] != true {
			t.Fatalf("%s: expected allow, got %v", c.name, resp)
		}
	}

	// The crossing attempt: acme's token, rival's subject id.
	status, resp := f.post(t, "/v1/authz/check", f.acmeTok,
		fmt.Sprintf(`{"subject":{"id":%q},"permission":"billing.invoice:read"}`, f.rival))
	if status != http.StatusOK {
		t.Fatalf("got %d", status)
	}
	if resp["allowed"] != false {
		t.Fatal("acme's token learned that rival's user is allowed something")
	}
	// It must look like an absent subject, which is exactly what it is from inside
	// acme's tenant — not like a subject that exists and lacks a grant.
	if resp["reason"] != "subject_not_found" {
		t.Errorf("reason %v; a foreign subject should be indistinguishable from a missing one", resp["reason"])
	}
}

// --- request validation ---------------------------------------------------------------

func TestInvalidRequestsAreRejected(t *testing.T) {
	f := newFixture(t)
	cases := []struct{ name, body, wants string }{
		{"empty body", ``, "malformed"},
		{"not JSON", `nonsense`, "malformed"},
		{"no subject", `{"permission":"billing.invoice:read"}`, "subject.id is required"},
		{"no permission", `{"subject":{"id":"usr_x"}}`, "permission is required"},
		{"malformed permission", `{"subject":{"id":"usr_x"},"permission":"nonsense"}`, "app.type:action"},
		{"wildcard action", `{"subject":{"id":"usr_x"},"permission":"billing.invoice:*"}`, "wildcard"},
		{"wildcard type", `{"subject":{"id":"usr_x"},"permission":"billing.*:read"}`, "wildcard"},
		{"unknown field", `{"subject":{"id":"usr_x"},"permission":"billing.invoice:read","typo":1}`, "malformed"},
		{"half a resource", `{"subject":{"id":"usr_x"},"permission":"billing.invoice:read","resource":{"type":"billing.invoice"}}`, "both type and id"},
		{"bad environment", `{"subject":{"id":"usr_x"},"permission":"billing.invoice:read","environment":"qa"}`, "want dev, staging or prod"},
		{"token subject", `{"subject":{"token":"eyJ..."},"permission":"billing.invoice:read"}`, "milestone M1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, resp := f.post(t, "/v1/authz/check", f.acmeTok, tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("got %d, want 400 (%v)", status, resp)
			}
			detail, _ := resp["detail"].(string) //nolint:errcheck // a missing detail fails the assertion below
			if !strings.Contains(detail, tc.wants) {
				t.Errorf("detail %q does not mention %q", detail, tc.wants)
			}
		})
	}
}

// --- batch ------------------------------------------------------------------------

func TestBatchCheck(t *testing.T) {
	f := newFixture(t)

	body := fmt.Sprintf(`{
		"subject": {"id": %q},
		"checks": [
			{"ref":"a","permission":"billing.invoice:read"},
			{"ref":"b","permission":"billing.invoice:void"}
		]}`, f.maria)
	status, resp := f.post(t, "/v1/authz/batch-check", f.acmeTok, body)
	if status != http.StatusOK {
		t.Fatalf("got %d: %v", status, resp)
	}
	results, resultsOK := resp["results"].(map[string]any)
	if !resultsOK || len(results) != 2 {
		t.Fatalf("expected two results, got %v", resp)
	}
	a, aOK := results["a"].(map[string]any)
	b, bOK := results["b"].(map[string]any)
	if !aOK || !bOK {
		t.Fatalf("results are not objects: %v", results)
	}
	if a["allowed"] != true {
		t.Error("the viewer role should allow read")
	}
	if b["allowed"] != false {
		t.Error("the viewer role should not allow void")
	}
}

// A duplicate ref would silently drop one answer the caller is waiting for, because
// results come back keyed by ref.
func TestBatchRejectsDuplicateRefs(t *testing.T) {
	f := newFixture(t)
	body := fmt.Sprintf(`{"subject":{"id":%q},"checks":[
		{"ref":"a","permission":"billing.invoice:read"},
		{"ref":"a","permission":"billing.invoice:void"}]}`, f.maria)
	status, resp := f.post(t, "/v1/authz/batch-check", f.acmeTok, body)
	if status != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", status)
	}
	detail, _ := resp["detail"].(string) //nolint:errcheck // absence fails the assertion
	if !strings.Contains(detail, "more than once") {
		t.Errorf("detail %q should name the duplicate", detail)
	}
}

// An unbounded batch is an amplification vector: one cheap request turning into
// arbitrary work.
func TestBatchIsCapped(t *testing.T) {
	f := newFixture(t)
	var checks bytes.Buffer
	for i := 0; i < 1001; i++ {
		if i > 0 {
			checks.WriteString(",")
		}
		fmt.Fprintf(&checks, `{"ref":"r%d","permission":"billing.invoice:read"}`, i)
	}
	body := fmt.Sprintf(`{"subject":{"id":%q},"checks":[%s]}`, f.maria, checks.String())
	status, resp := f.post(t, "/v1/authz/batch-check", f.acmeTok, body)
	if status != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", status)
	}
	detail, _ := resp["detail"].(string) //nolint:errcheck // absence fails the assertion
	if !strings.Contains(detail, "1000") {
		t.Errorf("detail %q should state the limit", detail)
	}
}

func TestBatchRequiresAuthentication(t *testing.T) {
	f := newFixture(t)
	status, _ := f.post(t, "/v1/authz/batch-check", "",
		`{"subject":{"id":"x"},"checks":[{"ref":"a","permission":"billing.invoice:read"}]}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", status)
	}
}

// --- responses --------------------------------------------------------------------

func TestDecisionsAreNotCacheableByIntermediaries(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/authz/check",
		strings.NewReader(fmt.Sprintf(`{"subject":{"id":%q},"permission":"billing.invoice:read"}`, f.maria)))
	req.Header.Set("Authorization", "Bearer "+f.acmeTok)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	// A proxy caching an authorization decision would serve one subject's answer to
	// another. The SDK caches deliberately, keyed on the subject; a shared cache in
	// between cannot.
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control is %q, want no-store", got)
	}
}

func TestHealthAndReadinessNeedNoCredential(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s returned %d without a credential; a load balancer cannot hold one", path, rec.Code)
		}
	}
}

// --- explain --------------------------------------------------------------------

// A derivation describes the policy itself, which is exactly what someone probing the
// service would like to know. SPEC §10.3 restricts it; this is that restriction.
func TestExplainIsRefusedInProductionWithoutPermission(t *testing.T) {
	f := newFixtureWithExplain(t, false)
	body := fmt.Sprintf(`{"subject":{"id":%q},"permission":"billing.invoice:read"}`, f.maria)

	status, resp := f.post(t, "/v1/authz/explain", f.acmeTok, body)
	if status != http.StatusForbidden {
		t.Fatalf("got %d, want 403", status)
	}
	detail, _ := resp["detail"].(string) //nolint:errcheck // absence fails the assertion
	if !strings.Contains(detail, "may_explain") {
		t.Errorf("the refusal should name what would permit it, got %q", detail)
	}
}

func TestExplainReturnsTheDerivation(t *testing.T) {
	f := newFixture(t) // its accounts are created with may_explain
	body := fmt.Sprintf(`{"subject":{"id":%q},"permission":"billing.invoice:read"}`, f.maria)

	status, resp := f.post(t, "/v1/authz/explain", f.acmeTok, body)
	if status != http.StatusOK {
		t.Fatalf("got %d: %v", status, resp)
	}
	explain, ok := resp["explain"].(map[string]any)
	if !ok {
		t.Fatalf("no explain in the response: %v", resp)
	}

	// The roles a subject holds are frequently the whole answer — the user is not in
	// the group they believed they were.
	roles, rolesOK := explain["subject_roles"].([]any)
	if !rolesOK || len(roles) == 0 {
		t.Fatalf("subject_roles missing or empty: %v", explain)
	}
	// Slices must marshal as [] and never as null; a client should not have to
	// handle both spellings of "nothing here".
	if _, ok := explain["considered_grants"].([]any); !ok {
		t.Errorf("considered_grants is %T, want an array", explain["considered_grants"])
	}
}

// A plain check must never carry a derivation, whatever the caller's permissions.
// The endpoint is the boundary, not a flag on the request.
func TestPlainCheckNeverExplains(t *testing.T) {
	f := newFixture(t)
	body := fmt.Sprintf(`{"subject":{"id":%q},"permission":"billing.invoice:read"}`, f.maria)

	status, resp := f.post(t, "/v1/authz/check", f.acmeTok, body)
	if status != http.StatusOK {
		t.Fatalf("got %d", status)
	}
	if _, present := resp["explain"]; present {
		t.Fatal("a plain check returned a derivation")
	}
}

func TestExplainRequiresAuthentication(t *testing.T) {
	f := newFixture(t)
	status, _ := f.post(t, "/v1/authz/explain", "",
		`{"subject":{"id":"x"},"permission":"billing.invoice:read"}`)
	if status != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", status)
	}
}
