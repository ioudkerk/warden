package keys_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

const dsnEnv = "WARDEN_TEST_DATABASE_URL"

// managerFixture is a migrated database with one signing key in it, and a manager
// whose clock the test controls.
type managerFixture struct {
	m   *keys.Manager
	db  *store.Store
	cfg *config.Config

	mu  sync.Mutex
	now time.Time
}

func (f *managerFixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func (f *managerFixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func newManagerFixture(t *testing.T) *managerFixture {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("set %s to run the key management tests", dsnEnv)
	}
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	t.Cleanup(func() { conn.Close(ctx) }) //nolint:errcheck // teardown

	if _, resetErr := conn.Exec(ctx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public`); resetErr != nil {
		t.Fatalf("resetting the schema: %v", resetErr)
	}
	paths, err := filepath.Glob(filepath.Join("..", "store", "migrations", "*.up.sql"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no migrations found: %v", err)
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
	cfg.Issuer = "https://warden.example.com"
	cfg.Database.URL = secrets.New(dsn)
	cfg.Database.SystemURL = secrets.New(dsn)
	cfg.Database.MaxOpenConns = 6
	cfg.Database.MaxIdleConns = 2
	cfg.Database.ConnectTimeout = 10 * time.Second
	cfg.Database.StatementTimeout = 10 * time.Second
	// ES256 throughout: the rotation semantics are identical and a P-256 keygen is
	// microseconds where RSA-3072 is tens of milliseconds, which matters in a test
	// that rotates repeatedly.
	cfg.Security.TokenSigningAlgorithm = keys.ES256
	cfg.Security.KeyRotationInterval = 90 * 24 * time.Hour
	cfg.Security.KeyOverlapWindow = 24 * time.Hour

	db, err := store.Open(ctx, cfg, store.SystemAccess)
	if err != nil {
		t.Fatalf("opening the system store: %v", err)
	}
	t.Cleanup(db.Close)

	m, err := keys.NewManager(db, testKeyring(t), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	f := &managerFixture{m: m, db: db, cfg: cfg, now: time.Now().UTC()}
	m.SetClock(f.clock)
	// The cache exists to spare Postgres, not to be exercised here: every test wants
	// to see the effect of the write it just made.
	m.SetCacheTTL(0)

	// The deployment's first key. Rotate on an empty table is the same path `warden
	// init` takes, minus the tenant and the owner neither of which key management
	// touches.
	if _, err := m.Rotate(ctx, true); err != nil {
		t.Fatalf("creating the first signing key: %v", err)
	}
	return f
}

func testKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	material := make([]byte, secrets.KEKSize)
	for i := range material {
		material[i] = byte(i)
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

// publishedKIDs reads JWKS and returns the key ids in it.
func publishedKIDs(t *testing.T, f *managerFixture) []string {
	t.Helper()
	body, _, err := f.m.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("parsing JWKS: %v", err)
	}
	out := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		out = append(out, k.KeyID)
	}
	return out
}

// verifyAgainstJWKS is what a relying party does: fetch the published set, find the
// key the token names, check the signature. It deliberately goes through the same
// JSON a real client would, rather than reaching for the key material directly.
func verifyAgainstJWKS(t *testing.T, f *managerFixture, token string) (map[string]any, error) {
	t.Helper()
	body, _, err := f.m.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var set jose.JSONWebKeySet
	if unmarshalErr := json.Unmarshal(body, &set); unmarshalErr != nil {
		t.Fatalf("parsing JWKS: %v", unmarshalErr)
	}

	parsed, err := jose.ParseSigned(token)
	if err != nil {
		return nil, err
	}
	kid := parsed.Signatures[0].Header.KeyID
	matches := set.Key(kid)
	if len(matches) == 0 {
		return nil, errNoSuchKey
	}
	payload, err := parsed.Verify(matches[0])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

type constErr string

func (e constErr) Error() string { return string(e) }

// errNoSuchKey is what a relying party effectively concludes when the token's kid is
// not in JWKS. It is the failure the overlap window exists to prevent.
const errNoSuchKey = constErr("no key in JWKS matches the token's kid")

// TestRotationKeepsPreviousTokensVerifiableForTheOverlapWindow is M1-1's exit
// condition, end to end: a token signed before a rotation must verify against
// published JWKS for the whole overlap window, and must stop verifying after it.
func TestRotationKeepsPreviousTokensVerifiableForTheOverlapWindow(t *testing.T) {
	ctx := context.Background()
	f := newManagerFixture(t)

	oldKID, err := f.m.ActiveKID(ctx)
	if err != nil {
		t.Fatalf("ActiveKID: %v", err)
	}
	oldToken, err := f.m.Sign(ctx, map[string]any{"sub": "usr_before", "iss": f.cfg.Issuer})
	if err != nil {
		t.Fatalf("signing before the rotation: %v", err)
	}

	// Move to the day the key falls due, and rotate the way the worker would.
	f.advance(f.cfg.Security.KeyRotationInterval)
	newKID, err := f.m.Rotate(ctx, false)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newKID == "" {
		t.Fatal("a key past its expiry was not treated as due")
	}
	if newKID == oldKID {
		t.Fatal("rotation reused the previous kid; a kid must never name two different keys")
	}

	newToken, err := f.m.Sign(ctx, map[string]any{"sub": "usr_after", "iss": f.cfg.Issuer})
	if err != nil {
		t.Fatalf("signing after the rotation: %v", err)
	}

	// Immediately after rotation both keys are published and both tokens verify.
	if got := publishedKIDs(t, f); len(got) != 2 {
		t.Fatalf("JWKS publishes %v; want the active and the previous key", got)
	}
	for name, token := range map[string]string{"pre-rotation": oldToken, "post-rotation": newToken} {
		claims, verifyErr := verifyAgainstJWKS(t, f, token)
		if verifyErr != nil {
			t.Fatalf("%s token did not verify right after rotation: %v", name, verifyErr)
		}
		if claims["iss"] != f.cfg.Issuer {
			t.Fatalf("%s token claims = %v", name, claims)
		}
	}

	// Anywhere inside the window, including the last moment of it, the old token
	// still verifies. Sweeping at each step is what the worker and every JWKS
	// request do, so this also asserts the sweep does not retire early. The steps sum
	// to one minute short of the window.
	steps := []time.Duration{time.Minute, f.cfg.Security.KeyOverlapWindow/2 - time.Minute,
		f.cfg.Security.KeyOverlapWindow/2 - time.Minute}
	for _, step := range steps {
		f.advance(step)
		if _, sweepErr := f.m.Sweep(ctx); sweepErr != nil {
			t.Fatalf("Sweep: %v", sweepErr)
		}
		if _, verifyErr := verifyAgainstJWKS(t, f, oldToken); verifyErr != nil {
			t.Fatalf("the pre-rotation token stopped verifying inside the overlap window: %v", verifyErr)
		}
	}

	// Past the window, the old key leaves JWKS and the old token becomes
	// unverifiable — which is the point of retiring it.
	f.advance(2 * time.Minute)
	retired, err := f.m.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if retired != 1 {
		t.Fatalf("swept %d keys past the overlap window; want 1", retired)
	}
	if got := publishedKIDs(t, f); len(got) != 1 || got[0] != newKID {
		t.Fatalf("JWKS publishes %v; want only the active key %s", got, newKID)
	}
	if _, err := verifyAgainstJWKS(t, f, oldToken); !errors.Is(err, errNoSuchKey) {
		t.Fatalf("verifying the pre-rotation token after the window: %v; want it to be unverifiable", err)
	}
	// The new token is unaffected, which is what distinguishes a retirement from an
	// outage.
	if _, err := verifyAgainstJWKS(t, f, newToken); err != nil {
		t.Fatalf("the post-rotation token stopped verifying: %v", err)
	}
}

// TestRotateDoesNothingBeforeTheKeyIsDue keeps the scheduled worker from replacing a
// perfectly good key every hour.
func TestRotateDoesNothingBeforeTheKeyIsDue(t *testing.T) {
	ctx := context.Background()
	f := newManagerFixture(t)

	before, err := f.m.ActiveKID(ctx)
	if err != nil {
		t.Fatalf("ActiveKID: %v", err)
	}

	f.advance(f.cfg.Security.KeyRotationInterval - time.Hour)
	kid, err := f.m.Rotate(ctx, false)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if kid != "" {
		t.Fatalf("rotated to %s an hour before the key was due", kid)
	}

	after, err := f.m.ActiveKID(ctx)
	if err != nil {
		t.Fatalf("ActiveKID: %v", err)
	}
	if after != before {
		t.Fatalf("the active key changed from %s to %s without being due", before, after)
	}
	if got := publishedKIDs(t, f); len(got) != 1 {
		t.Fatalf("JWKS publishes %v; want one key", got)
	}
}

// TestForceRotatesEvenWhenNotDue is the compromise path: an operator does not have to
// wait for a schedule to stop using a key they no longer trust.
func TestForceRotatesEvenWhenNotDue(t *testing.T) {
	ctx := context.Background()
	f := newManagerFixture(t)

	before, err := f.m.ActiveKID(ctx)
	if err != nil {
		t.Fatalf("ActiveKID: %v", err)
	}
	kid, err := f.m.Rotate(ctx, true)
	if err != nil {
		t.Fatalf("Rotate(force): %v", err)
	}
	if kid == "" || kid == before {
		t.Fatalf("force rotation produced %q; want a new kid, not %s", kid, before)
	}
}

// TestConcurrentRotationsProduceOneKey covers the multi-replica case the advisory
// lock exists for. Without it the losers fail on signing_key_one_active, which is
// safe but wastes a keygen each and logs an error that is not one.
func TestConcurrentRotationsProduceOneKey(t *testing.T) {
	ctx := context.Background()
	f := newManagerFixture(t)
	f.advance(f.cfg.Security.KeyRotationInterval)

	const replicas = 4
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		rotated []string
		errs    []error
	)
	wg.Add(replicas)
	for i := 0; i < replicas; i++ {
		go func() {
			defer wg.Done()
			kid, err := f.m.Rotate(ctx, false)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, keys.ErrRotationHeld):
				// Lost the race and said so, which is the designed outcome.
			case err != nil:
				errs = append(errs, err)
			case kid != "":
				rotated = append(rotated, kid)
			}
		}()
	}
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("concurrent rotation errors: %v", errs)
	}
	if len(rotated) != 1 {
		t.Fatalf("%d replicas rotated (%v); exactly one should have", len(rotated), rotated)
	}
	if got := publishedKIDs(t, f); len(got) != 2 {
		t.Fatalf("JWKS publishes %v after one rotation; want the active and previous key", got)
	}
}

// TestJWKSETagChangesOnlyWhenTheKeySetDoes is what makes the endpoint cacheable
// without a relying party missing a rotation.
func TestJWKSETagChangesOnlyWhenTheKeySetDoes(t *testing.T) {
	ctx := context.Background()
	f := newManagerFixture(t)

	_, first, err := f.m.JWKS(ctx)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	_, again, err := f.m.JWKS(ctx)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if first != again {
		t.Fatalf("the ETag changed with no change to the key set: %s then %s", first, again)
	}

	if _, rotateErr := f.m.Rotate(ctx, true); rotateErr != nil {
		t.Fatalf("Rotate: %v", rotateErr)
	}
	_, afterRotation, err := f.m.JWKS(ctx)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if afterRotation == first {
		t.Fatal("the ETag did not change across a rotation, so a cached client would never see the new key")
	}
}

// TestJWKSPublishesNoPrivateMaterial is the property the whole design rests on.
func TestJWKSPublishesNoPrivateMaterial(t *testing.T) {
	ctx := context.Background()
	f := newManagerFixture(t)

	body, _, err := f.m.JWKS(ctx)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("parsing JWKS: %v", err)
	}
	for _, k := range set.Keys {
		if !k.IsPublic() {
			t.Fatalf("key %s in JWKS carries private material", k.KeyID)
		}
	}
	// Belt and braces against a future change to how keys are marshalled: the
	// private-parameter names must not appear in the bytes at all.
	for _, member := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
		if containsJSONMember(body, member) {
			t.Fatalf("JWKS contains the private JWK member %s", member)
		}
	}
}

func containsJSONMember(body []byte, member string) bool {
	s := string(body)
	for i := 0; i+len(member) <= len(s); i++ {
		if s[i:i+len(member)] == member {
			return true
		}
	}
	return false
}

// TestStateReportsWhenAKeyIsDue is what the worker reads on every tick.
func TestStateReportsWhenAKeyIsDue(t *testing.T) {
	ctx := context.Background()
	f := newManagerFixture(t)

	state, err := f.m.State(ctx)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if state.Due {
		t.Fatal("a freshly created key reports as due for rotation")
	}
	if state.ExpiresAt == nil {
		t.Fatal("a signing key was written with no expiry, so nothing will ever rotate it")
	}
	if want := state.CreatedAt.Add(f.cfg.Security.KeyRotationInterval); !state.ExpiresAt.Equal(want) {
		t.Fatalf("key expires at %s; want %s, one rotation interval after creation", state.ExpiresAt, want)
	}

	f.advance(f.cfg.Security.KeyRotationInterval)
	state, err = f.m.State(ctx)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if !state.Due {
		t.Fatal("a key past its expiry does not report as due, so the worker would never rotate it")
	}
}
