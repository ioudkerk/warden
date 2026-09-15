package authn_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/cache"
)

// lockoutFixture is a limiter over a cache, with a clock the test drives.
type lockoutFixture struct {
	lockout *authn.Lockout
	cache   cache.Cache
	now     time.Time
}

func newLockoutFixture(t *testing.T, policy authn.LockoutPolicy) *lockoutFixture {
	t.Helper()
	c := openTestCache(t)

	lockout, err := authn.NewLockout(c, authn.LockoutOptions{
		Policy: policy,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Pepper: []byte("a-test-pepper-of-sufficient-length"),
	})
	if err != nil {
		t.Fatalf("NewLockout: %v", err)
	}

	f := &lockoutFixture{lockout: lockout, cache: c, now: time.Now().UTC()}
	lockout.SetClock(func() time.Time { return f.now })
	return f
}

func testPolicy() authn.LockoutPolicy {
	return authn.LockoutPolicy{
		FreeAttempts:  3,
		BaseDelay:     time.Second,
		MaxDelay:      time.Minute,
		PairWindow:    time.Hour,
		AccountCap:    10,
		AccountWindow: time.Hour,
	}
}

func TestTheFirstFewFailuresCostNothing(t *testing.T) {
	ctx := context.Background()
	f := newLockoutFixture(t, testPolicy())

	// People mistype passwords. The first attempts past a typo should feel like
	// nothing, or the limiter is a support burden rather than a defence.
	for i := 1; i <= testPolicy().FreeAttempts; i++ {
		decision, err := f.lockout.Check(ctx, "ten_acme", "maria@acme.test", "203.0.113.5")
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !decision.Allowed {
			t.Fatalf("attempt %d was refused while within the free allowance", i)
		}
		if _, err := f.lockout.Failed(ctx, "ten_acme", "maria@acme.test", "203.0.113.5"); err != nil {
			t.Fatalf("Failed: %v", err)
		}
	}

	// The next one is delayed.
	decision, err := f.lockout.Check(ctx, "ten_acme", "maria@acme.test", "203.0.113.5")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Allowed {
		t.Fatal("the attempt after the free allowance was not delayed")
	}
	if decision.Reason != authn.ReasonPairBackoff {
		t.Fatalf("reason = %q; want the pair backoff", decision.Reason)
	}
}

// TestTheDelayDoubles is the "exponential backoff" of SPEC §7.2.
func TestTheDelayDoubles(t *testing.T) {
	ctx := context.Background()
	policy := testPolicy()
	f := newLockoutFixture(t, policy)

	const email, ip = "maria@acme.test", "203.0.113.5"
	for i := 0; i < policy.FreeAttempts; i++ {
		if _, err := f.lockout.Failed(ctx, "ten_acme", email, ip); err != nil {
			t.Fatalf("Failed: %v", err)
		}
	}

	var previous time.Duration
	for step := 1; step <= 5; step++ {
		delay, err := f.lockout.Failed(ctx, "ten_acme", email, ip)
		if err != nil {
			t.Fatalf("Failed: %v", err)
		}
		if delay <= 0 {
			t.Fatalf("failure %d past the allowance produced no delay", step)
		}
		if previous > 0 && delay != policy.MaxDelay && delay != previous*2 {
			t.Fatalf("delay went %s then %s; it should double until it reaches the cap of %s",
				previous, delay, policy.MaxDelay)
		}
		if delay > policy.MaxDelay {
			t.Fatalf("delay %s exceeds the cap %s", delay, policy.MaxDelay)
		}
		previous = delay
	}
}

// TestWaitingOutTheDelayWorks. A limiter that never forgives is a lockout, and a user
// who waits must get back in.
func TestWaitingOutTheDelayWorks(t *testing.T) {
	ctx := context.Background()
	policy := testPolicy()
	f := newLockoutFixture(t, policy)

	const email, ip = "maria@acme.test", "203.0.113.5"
	for i := 0; i <= policy.FreeAttempts; i++ {
		if _, err := f.lockout.Failed(ctx, "ten_acme", email, ip); err != nil {
			t.Fatalf("Failed: %v", err)
		}
	}

	decision, err := f.lockout.Check(ctx, "ten_acme", email, ip)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Allowed {
		t.Fatal("the attempt was not delayed")
	}

	f.now = f.now.Add(decision.RetryAfter + time.Second)
	decision, err = f.lockout.Check(ctx, "ten_acme", email, ip)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("still refused %s after the stated RetryAfter; the delay must be honest",
			decision.RetryAfter)
	}
}

// TestTheAccountCapSurvivesChangingIP is the distributed case the second counter exists
// for: each source looks innocent and only the account sees the volume.
func TestTheAccountCapSurvivesChangingIP(t *testing.T) {
	ctx := context.Background()
	policy := testPolicy()
	f := newLockoutFixture(t, policy)

	const email = "maria@acme.test"
	for i := 0; i < policy.AccountCap; i++ {
		// A different address every time, so the pair counter never builds.
		ip := "203.0.113." + string(rune('0'+i%10))
		decision, err := f.lockout.Check(ctx, "ten_acme", email, ip)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !decision.Allowed {
			t.Fatalf("attempt %d from a fresh address was refused before the account cap", i)
		}
		if _, err := f.lockout.Failed(ctx, "ten_acme", email, ip); err != nil {
			t.Fatalf("Failed: %v", err)
		}
	}

	decision, err := f.lockout.Check(ctx, "ten_acme", email, "198.51.100.1")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Allowed {
		t.Fatal("the account cap did not apply to an attempt from a new address; a " +
			"distributed attempt would never be limited")
	}
	if decision.Reason != authn.ReasonAccountCapped {
		t.Fatalf("reason = %q; want the account cap", decision.Reason)
	}

	// Another account is unaffected, so the cap is not a global outage.
	other, err := f.lockout.Check(ctx, "ten_acme", "bob@acme.test", "198.51.100.1")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !other.Allowed {
		t.Fatal("capping one account refused another")
	}
}

// TestAnUnknownAddressIsLimitedIdentically is the enumeration property. An attacker who
// is never slowed has learned the address does not exist.
func TestAnUnknownAddressIsLimitedIdentically(t *testing.T) {
	ctx := context.Background()
	policy := testPolicy()
	f := newLockoutFixture(t, policy)

	const ip = "203.0.113.5"
	for _, identifier := range []string{"maria@acme.test", "nobody-at-all@acme.test"} {
		t.Run(identifier, func(t *testing.T) {
			for i := 0; i <= policy.FreeAttempts; i++ {
				if _, err := f.lockout.Failed(ctx, "ten_acme", identifier, ip); err != nil {
					t.Fatalf("Failed: %v", err)
				}
			}
			decision, err := f.lockout.Check(ctx, "ten_acme", identifier, ip)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if decision.Allowed {
				t.Fatal("this identifier was not limited; a caller could tell it apart " +
					"from one that was, which is an account-existence oracle")
			}
		})
	}
}

// TestSuccessClearsThePairButNotTheAccount. An attacker who guesses one password must
// not thereby reset the budget protecting every other account.
func TestSuccessClearsThePairButNotTheAccount(t *testing.T) {
	ctx := context.Background()
	policy := testPolicy()
	f := newLockoutFixture(t, policy)

	const email, ip = "maria@acme.test", "203.0.113.5"
	for i := 0; i <= policy.FreeAttempts; i++ {
		if _, err := f.lockout.Failed(ctx, "ten_acme", email, ip); err != nil {
			t.Fatalf("Failed: %v", err)
		}
	}
	before, err := f.lockout.Check(ctx, "ten_acme", email, ip)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if before.Allowed {
		t.Fatal("the pair was not delayed before the successful login")
	}

	if successErr := f.lockout.Succeeded(ctx, "ten_acme", email, ip); successErr != nil {
		t.Fatalf("Succeeded: %v", successErr)
	}
	cleared, err := f.lockout.Check(ctx, "ten_acme", email, ip)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !cleared.Allowed {
		t.Fatal("a successful login did not clear the pair backoff")
	}

	// The account counter kept its memory: the remaining budget is the cap minus what
	// was already spent, not the whole cap again.
	remaining := policy.AccountCap - (policy.FreeAttempts + 1)
	for i := 0; i < remaining; i++ {
		if _, failErr := f.lockout.Failed(ctx, "ten_acme", email, "198.51.100.9"); failErr != nil {
			t.Fatalf("Failed: %v", failErr)
		}
	}
	capped, err := f.lockout.Check(ctx, "ten_acme", email, "198.51.100.9")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if capped.Allowed {
		t.Fatal("a successful login reset the account counter; guessing one password " +
			"would refill the budget protecting the rest")
	}
}

// TestTheCounterIsSharedAcrossReplicas. A per-process counter would multiply the limit
// by the number of replicas, which is the quietest way to not have a limiter.
func TestTheCounterIsSharedAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	policy := testPolicy()
	f := newLockoutFixture(t, policy)

	// A second limiter over the same cache, with the same pepper — a second replica.
	second, err := authn.NewLockout(f.cache, authn.LockoutOptions{
		Policy: policy,
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Pepper: []byte("a-test-pepper-of-sufficient-length"),
	})
	if err != nil {
		t.Fatalf("NewLockout: %v", err)
	}
	second.SetClock(func() time.Time { return f.now })

	const email, ip = "maria@acme.test", "203.0.113.5"
	// Alternate between them, as a load balancer would.
	for i := 0; i <= policy.FreeAttempts; i++ {
		limiter := f.lockout
		if i%2 == 1 {
			limiter = second
		}
		if _, failErr := limiter.Failed(ctx, "ten_acme", email, ip); failErr != nil {
			t.Fatalf("Failed: %v", failErr)
		}
	}

	decision, err := second.Check(ctx, "ten_acme", email, ip)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Allowed {
		t.Fatal("failures spread across two replicas did not add up; each process is " +
			"counting on its own and the real limit is multiplied by the replica count")
	}
}

// TestIdentifiersAreNotStoredInTheClear. The addresses people fail to log in as are
// worth as much to an attacker as a user list.
func TestIdentifiersAreNotStoredInTheClear(t *testing.T) {
	ctx := context.Background()
	f := newLockoutFixture(t, testPolicy())

	const email = "maria@acme.test"
	if _, err := f.lockout.Failed(ctx, "ten_acme", email, "203.0.113.5"); err != nil {
		t.Fatalf("Failed: %v", err)
	}

	// The limiter's own keys must not contain the address. Probing the cache for a key
	// built from the plaintext is the check a dump would allow.
	for _, candidate := range []string{
		"warden:lockout:pair:ten_acme:" + email + ":203.0.113.5",
		"warden:lockout:account:ten_acme:" + email,
	} {
		if _, err := f.cache.Get(ctx, candidate); err == nil {
			t.Fatalf("the limiter stores %q, which names the address in the clear", candidate)
		}
	}
}

func TestAPolicyThatWouldNotLimitIsRefused(t *testing.T) {
	c := openTestCache(t)
	for name, policy := range map[string]authn.LockoutPolicy{
		"no base delay":      {FreeAttempts: 3, BaseDelay: 0, MaxDelay: time.Minute, PairWindow: time.Hour, AccountCap: 10, AccountWindow: time.Hour},
		"max below base":     {FreeAttempts: 3, BaseDelay: time.Minute, MaxDelay: time.Second, PairWindow: time.Hour, AccountCap: 10, AccountWindow: time.Hour},
		"no account cap":     {FreeAttempts: 3, BaseDelay: time.Second, MaxDelay: time.Minute, PairWindow: time.Hour, AccountCap: 0, AccountWindow: time.Hour},
		"no pair window":     {FreeAttempts: 3, BaseDelay: time.Second, MaxDelay: time.Minute, PairWindow: 0, AccountCap: 10, AccountWindow: time.Hour},
		"negative allowance": {FreeAttempts: -1, BaseDelay: time.Second, MaxDelay: time.Minute, PairWindow: time.Hour, AccountCap: 10, AccountWindow: time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := authn.NewLockout(c, authn.LockoutOptions{
				Policy: policy, Pepper: []byte("pepper"),
			}); err == nil {
				t.Fatal("the policy was accepted")
			}
		})
	}

	t.Run("no pepper", func(t *testing.T) {
		if _, err := authn.NewLockout(c, authn.LockoutOptions{Policy: testPolicy()}); err == nil {
			t.Fatal("a limiter without a pepper was accepted; its keys would name addresses")
		}
	})

	t.Run("no cache", func(t *testing.T) {
		_, err := authn.NewLockout(nil, authn.LockoutOptions{
			Policy: testPolicy(), Pepper: []byte("pepper"),
		})
		if err == nil {
			t.Fatal("a limiter with no cache was accepted")
		}
		if !strings.Contains(err.Error(), "replica") {
			t.Fatalf("the refusal does not explain why a shared counter matters: %v", err)
		}
	})
}
