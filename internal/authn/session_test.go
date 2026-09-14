package authn_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/cache"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
)

const redisEnv = "WARDEN_TEST_REDIS_URL"

// sessionFixture is the credential fixture plus a cache tier.
type sessionFixture struct {
	*fixture
	sessions *authn.Sessions
	cache    cache.Cache
}

func newSessionFixture(t *testing.T) *sessionFixture {
	t.Helper()
	f := newFixture(t)
	c := openTestCache(t)

	sessions, err := authn.NewSessions(f.tenantPool, f.systemPool, c, authn.SessionOptions{
		AbsoluteLifetime: 30 * 24 * time.Hour,
		IdleTimeout:      7 * 24 * time.Hour,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewSessions: %v", err)
	}
	return &sessionFixture{fixture: f, sessions: sessions, cache: c}
}

// openTestCache prefers a real Redis and falls back to the in-process backend.
//
// Falling back rather than skipping is deliberate: the in-process backend is a real
// implementation of the same interface, so every behavioural test here is meaningful
// against it. The one test that genuinely needs Redis — the two-replica propagation
// check, which is the exit condition — skips explicitly and says why, because
// in-process cannot model two processes and a test that pretended otherwise would be
// asserting nothing.
//
// A real Redis is flushed first, and that is not tidiness. Provisioned user ids are
// derived from the email — usr_maria_acme every time — so the cache keys repeat across
// tests while the fixture resets the schema underneath them. A test that writes a
// revocation marker with a clock set in the future leaves that marker behind, and
// every later test for the same user then fails for a reason that has nothing to do
// with what it is testing. That happened; this is the fix.
func openTestCache(t *testing.T) cache.Cache {
	t.Helper()
	cfg := config.Defaults()
	cfg.Environment = config.EnvDevelopment

	url := os.Getenv(redisEnv)
	if url == "" {
		cfg.Cache.Backend = config.CacheInProcess
		c, err := cache.Open(context.Background(), cfg)
		if err != nil {
			t.Fatalf("opening the cache: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() }) //nolint:errcheck // teardown
		return c
	}

	cfg.Cache.Backend, cfg.Cache.URL = config.CacheRedis, secrets.New(url)
	flushTestRedis(t, url)

	c, err := cache.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("opening the cache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() }) //nolint:errcheck // teardown
	return c
}

// flushTestRedis empties the database named by WARDEN_TEST_REDIS_URL.
func flushTestRedis(t *testing.T, url string) {
	t.Helper()
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parsing %s: %v", redisEnv, err)
	}
	client := redis.NewClient(opts)
	defer func() { _ = client.Close() }() //nolint:errcheck // teardown

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flushing the test Redis: %v", err)
	}
}

func TestASessionCanBeCreatedAndValidated(t *testing.T) {
	ctx := context.Background()
	f := newSessionFixture(t)

	created, err := f.sessions.Create(ctx, f.tenantID, f.maria,
		[]string{"pwd"}, "203.0.113.7", "Mozilla/5.0")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("the session has no sid")
	}

	got, err := f.sessions.Validate(ctx, created.ID)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.UserID != f.maria || got.TenantID != f.tenantID {
		t.Fatalf("validated as %s in %s; want %s in %s", got.UserID, got.TenantID, f.maria, f.tenantID)
	}
	if len(got.AMR) != 1 || got.AMR[0] != "pwd" {
		t.Fatalf("amr = %v; it lands in the access token unchanged (SPEC §8.2)", got.AMR)
	}
	if got.IP != "203.0.113.7" || got.UserAgent != "Mozilla/5.0" {
		t.Fatalf("the active-sessions detail was not preserved: ip=%q ua=%q", got.IP, got.UserAgent)
	}
}

func TestAnUnknownSessionIsRefused(t *testing.T) {
	ctx := context.Background()
	f := newSessionFixture(t)

	for name, sid := range map[string]string{
		"empty":     "",
		"unknown":   "ses_nothing_like_a_real_one",
		"near miss": "ses_" + "AAAAAAAAAAAAAAAA",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.sessions.Validate(ctx, sid); !errors.Is(err, authn.ErrNoSession) {
				t.Fatalf("got %v; want ErrNoSession", err)
			}
		})
	}
}

func TestRevokingOneSessionLeavesTheOthers(t *testing.T) {
	ctx := context.Background()
	f := newSessionFixture(t)

	laptop, err := f.sessions.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", "laptop")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	phone, err := f.sessions.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", "phone")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := f.sessions.Revoke(ctx, f.tenantID, laptop.ID, "the user pressed sign out"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, err := f.sessions.Validate(ctx, laptop.ID); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("the revoked session still validates: %v", err)
	}
	if _, err := f.sessions.Validate(ctx, phone.ID); err != nil {
		t.Fatalf("revoking one session ended another: %v", err)
	}

	// Idempotent: a caller retrying after a timeout must not get a failure for having
	// succeeded.
	if err := f.sessions.Revoke(ctx, f.tenantID, laptop.ID, "retry"); err != nil {
		t.Fatalf("revoking an already-revoked session failed: %v", err)
	}
}

func TestRevokeAllEndsEverySession(t *testing.T) {
	ctx := context.Background()
	f := newSessionFixture(t)

	var sids []string
	for _, device := range []string{"laptop", "phone", "tablet"} {
		session, err := f.sessions.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", device)
		if err != nil {
			t.Fatalf("Create(%s): %v", device, err)
		}
		sids = append(sids, session.ID)
	}
	// Bob's session must survive: "log out everywhere" is scoped to one user.
	bobSession, err := f.sessions.Create(ctx, f.tenantID, f.bob, []string{"pwd"}, "", "bob's laptop")
	if err != nil {
		t.Fatalf("Create for bob: %v", err)
	}

	count, err := f.sessions.RevokeAllForUser(ctx, f.tenantID, f.maria, "password changed")
	if err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	if count != len(sids) {
		t.Fatalf("revoked %d sessions; want %d", count, len(sids))
	}

	for _, sid := range sids {
		if _, validateErr := f.sessions.Validate(ctx, sid); !errors.Is(validateErr, authn.ErrNoSession) {
			t.Fatalf("session %s survived revoke-all: %v", sid, validateErr)
		}
	}
	if _, validateErr := f.sessions.Validate(ctx, bobSession.ID); validateErr != nil {
		t.Fatalf("revoking maria's sessions ended bob's: %v", validateErr)
	}
}

// TestRevokeAllCatchesASessionItNeverEnumerated is why the revocation marker exists.
//
// Deleting only the sessions a query found leaves a race: a login committing between
// the enumeration and the delete produces a session the revocation never saw. The
// clock reproduces it deterministically and without reaching into the cache — a
// session created while the clock still reads T0, after a revocation at T1, is exactly
// the login that was in flight when the revocation ran.
func TestRevokeAllCatchesASessionItNeverEnumerated(t *testing.T) {
	ctx := context.Background()
	f := newSessionFixture(t)

	now := time.Now().UTC()
	f.sessions.SetClock(func() time.Time { return now })

	if _, err := f.sessions.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", "laptop"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The revocation happens a minute later.
	revokedAt := now.Add(time.Minute)
	now = revokedAt
	if _, err := f.sessions.RevokeAllForUser(ctx, f.tenantID, f.maria, "incident"); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}

	// The in-flight login lands now, but it authenticated before the revocation, so
	// its auth_time predates the marker.
	now = revokedAt.Add(-30 * time.Second)
	inFlight, err := f.sessions.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", "racing laptop")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	now = revokedAt.Add(time.Second)
	if _, validateErr := f.sessions.Validate(ctx, inFlight.ID); !errors.Is(validateErr, authn.ErrNoSession) {
		t.Fatalf("a session that authenticated before revoke-all but was written after it "+
			"still validates (%v); the revocation marker is what is meant to catch this", validateErr)
	}

	// And a session that authenticated *after* the revocation is valid, which is the
	// other half: a marker that killed everything forever would be a lockout, not a
	// logout.
	now = revokedAt.Add(time.Minute)
	fresh, err := f.sessions.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", "laptop again")
	if err != nil {
		t.Fatalf("Create after revoke-all: %v", err)
	}
	if _, err := f.sessions.Validate(ctx, fresh.ID); err != nil {
		t.Fatalf("a session created after revoke-all was refused: %v", err)
	}
}

func TestActiveSessionsListsWhatTheUserWouldRecognise(t *testing.T) {
	ctx := context.Background()
	f := newSessionFixture(t)

	for _, device := range []string{"laptop", "phone"} {
		if _, err := f.sessions.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "198.51.100.4", device); err != nil {
			t.Fatalf("Create(%s): %v", device, err)
		}
	}
	revoked, err := f.sessions.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", "old tablet")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if revokeErr := f.sessions.Revoke(ctx, f.tenantID, revoked.ID, "user signed out"); revokeErr != nil {
		t.Fatalf("Revoke: %v", revokeErr)
	}

	active, err := f.sessions.ActiveForUser(ctx, f.tenantID, f.maria)
	if err != nil {
		t.Fatalf("ActiveForUser: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("listed %d sessions; want the 2 still live, not the revoked one", len(active))
	}
	for _, session := range active {
		if session.ID == revoked.ID {
			t.Fatal("a revoked session appears in the active list")
		}
		if session.UserAgent == "" {
			t.Fatal("the list carries no user agent, so the user cannot tell the devices apart")
		}
	}

	// After revoke-all the list is empty, rather than showing devices that are no
	// longer signed in.
	if _, revokeErr := f.sessions.RevokeAllForUser(ctx, f.tenantID, f.maria, "test"); revokeErr != nil {
		t.Fatalf("RevokeAllForUser: %v", revokeErr)
	}
	active, err = f.sessions.ActiveForUser(ctx, f.tenantID, f.maria)
	if err != nil {
		t.Fatalf("ActiveForUser: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("after revoke-all the active list still shows %d sessions", len(active))
	}
}

// TestTheAbsoluteLifetimeIsACeilingTheIdleTimeoutCannotPush covers the interaction
// between the two settings. A session that is used constantly must still end.
func TestTheAbsoluteLifetimeIsACeilingTheIdleTimeoutCannotPush(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	c := openTestCache(t)

	sessions, err := authn.NewSessions(f.tenantPool, f.systemPool, c, authn.SessionOptions{
		AbsoluteLifetime: 2 * time.Hour,
		IdleTimeout:      time.Hour,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewSessions: %v", err)
	}

	now := time.Now().UTC()
	sessions.SetClock(func() time.Time { return now })

	session, err := sessions.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", "laptop")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Used every half hour, so the idle timeout never fires.
	for elapsed := 30 * time.Minute; elapsed < 2*time.Hour; elapsed += 30 * time.Minute {
		now = now.Add(30 * time.Minute)
		if _, validateErr := sessions.Validate(ctx, session.ID); validateErr != nil {
			t.Fatalf("an actively used session expired after %s: %v", elapsed, validateErr)
		}
	}

	// Past the absolute ceiling it ends regardless of use.
	now = now.Add(31 * time.Minute)
	if _, validateErr := sessions.Validate(ctx, session.ID); !errors.Is(validateErr, authn.ErrNoSession) {
		t.Fatalf("a session outlived its absolute lifetime: %v", validateErr)
	}
}
