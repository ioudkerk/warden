package authn_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/cache"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
)

// This file holds M1-4's exit condition: "POST /v1/users/{id}/revoke-all invalidates
// within 1 s".
//
// The measurement that matters is across *replicas*, not within one process. A single
// Sessions that revokes and then refuses is proving only that it can read its own
// write. What a deployment needs is that a revocation issued on the replica behind one
// load-balancer backend takes effect on every other, and the only way to test that is
// two independent Sessions values over two independent connections to a shared Redis.
//
// It needs a real Redis for the same reason. The in-process backend cannot model two
// processes — it *is* the process — so this test skips rather than pretending.

// replica builds an independent Sessions over its own cache connection, as a separate
// server process would have.
func replica(t *testing.T, f *fixture, redisURL string) *authn.Sessions {
	t.Helper()
	cfg := config.Defaults()
	cfg.Environment = config.EnvDevelopment
	cfg.Cache.Backend, cfg.Cache.URL = config.CacheRedis, secrets.New(redisURL)

	c, err := cache.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("opening the cache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() }) //nolint:errcheck // teardown

	sessions, err := authn.NewSessions(f.tenantPool, f.systemPool, c, authn.SessionOptions{
		AbsoluteLifetime: 30 * 24 * time.Hour,
		IdleTimeout:      7 * 24 * time.Hour,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewSessions: %v", err)
	}
	return sessions
}

func requireRedis(t *testing.T) string {
	t.Helper()
	url := os.Getenv(redisEnv)
	if url == "" {
		t.Skipf("set %s to run the cross-replica propagation test: it needs a shared cache "+
			"tier, and the in-process backend cannot model two processes", redisEnv)
	}
	flushTestRedis(t, url)
	return url
}

// TestRevokeAllPropagatesToAnotherReplicaWithinOneSecond is the exit condition.
func TestRevokeAllPropagatesToAnotherReplicaWithinOneSecond(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	redisURL := requireRedis(t)

	issuer := replica(t, f, redisURL)   // where the user logged in
	revoker := replica(t, f, redisURL)  // where an administrator presses "sign out everywhere"
	observer := replica(t, f, redisURL) // a third, serving traffic throughout

	var sids []string
	for _, device := range []string{"laptop", "phone", "tablet"} {
		session, err := issuer.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", device)
		if err != nil {
			t.Fatalf("Create(%s): %v", device, err)
		}
		sids = append(sids, session.ID)
	}

	// The observer accepts them, so the test is measuring a transition and not a
	// session that never worked.
	for _, sid := range sids {
		if _, err := observer.Validate(ctx, sid); err != nil {
			t.Fatalf("the observing replica did not accept session %s before revocation: %v", sid, err)
		}
	}

	started := time.Now()
	if _, err := revoker.RevokeAllForUser(ctx, f.tenantID, f.maria, "exit condition"); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}

	// Poll rather than sleep: the number that belongs in the failure message is how
	// long it actually took, and sleeping a second would report a second no matter how
	// fast it was.
	deadline := started.Add(time.Second)
	for _, sid := range sids {
		for {
			_, err := observer.Validate(ctx, sid)
			if errors.Is(err, authn.ErrNoSession) {
				break
			}
			if err != nil {
				t.Fatalf("validating on the observing replica: %v", err)
			}
			if time.Now().After(deadline) {
				t.Fatalf("session %s was still accepted by another replica %s after revoke-all; "+
					"SPEC §8.3 and M1-4 require it to have taken effect within 1s",
					sid, time.Since(started))
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	elapsed := time.Since(started)
	t.Logf("revocation was visible on an independent replica after %s", elapsed)

	// The margin is the interesting part. Nothing caches a session in process, so this
	// is a Redis round trip rather than a propagation delay, and it should be orders of
	// magnitude inside the budget. If this ever starts reporting hundreds of
	// milliseconds, something has introduced a local cache and quietly turned the
	// guarantee into a promise about a TTL.
	if elapsed > 100*time.Millisecond {
		t.Errorf("revocation took %s to become visible. It is inside the 1s budget, but it "+
			"should be a single cache round trip; this suggests a local session cache "+
			"was introduced somewhere", elapsed)
	}
}

// TestRevokeOneSessionPropagatesToAnotherReplica is the same property for the
// single-session case, which is the one a user triggers themselves from a device list.
func TestRevokeOneSessionPropagatesToAnotherReplica(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	redisURL := requireRedis(t)

	issuer := replica(t, f, redisURL)
	observer := replica(t, f, redisURL)

	laptop, err := issuer.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", "laptop")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	phone, err := issuer.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", "phone")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := observer.Validate(ctx, laptop.ID); err != nil {
		t.Fatalf("the observing replica did not accept the session: %v", err)
	}

	started := time.Now()
	if err := issuer.Revoke(ctx, f.tenantID, laptop.ID, "signed out from the device list"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	deadline := started.Add(time.Second)
	for {
		_, validateErr := observer.Validate(ctx, laptop.ID)
		if errors.Is(validateErr, authn.ErrNoSession) {
			break
		}
		if validateErr != nil {
			t.Fatalf("validating on the observing replica: %v", validateErr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("a revoked session was still accepted by another replica after %s",
				time.Since(started))
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Logf("single-session revocation was visible on another replica after %s", time.Since(started))

	// The other session is untouched on the other replica too, which is what makes
	// this a revocation rather than a cache flush.
	if _, err := observer.Validate(ctx, phone.ID); err != nil {
		t.Fatalf("revoking one session ended another on a different replica: %v", err)
	}
}

// TestASessionCreatedOnOneReplicaWorksOnAnother is the property revocation depends on:
// if sessions did not cross replicas in the first place, the tests above would pass
// against a deployment where nobody could stay logged in.
func TestASessionCreatedOnOneReplicaWorksOnAnother(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	redisURL := requireRedis(t)

	issuer := replica(t, f, redisURL)
	observer := replica(t, f, redisURL)

	created, err := issuer.Create(ctx, f.tenantID, f.maria, []string{"pwd", "otp"}, "203.0.113.9", "laptop")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := observer.Validate(ctx, created.ID)
	if err != nil {
		t.Fatalf("a session created on one replica was not accepted by another: %v", err)
	}
	if got.UserID != f.maria {
		t.Fatalf("the other replica resolved the session to %s; want %s", got.UserID, f.maria)
	}
	if len(got.AMR) != 2 {
		t.Fatalf("amr = %v; the authentication methods must survive the round trip, because "+
			"they land in the access token (SPEC §8.2)", got.AMR)
	}
}
