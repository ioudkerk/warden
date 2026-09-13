package authn_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"testing"
	"time"

	"github.com/warden-project/warden/internal/authn"
)

// This file holds M1-2's exit condition: "a timing test shows unknown-user and
// wrong-password responses are indistinguishable (§7.2)".
//
// The measurement is calibrated against the cost of one Argon2id hash rather than
// against a percentage, because that is the quantity that actually leaks. If the
// unknown-user path skipped the hash — the natural way to write this function, and the
// bug this test exists to catch — the difference between the two medians would be
// approximately one whole Argon2id operation. So the bound is stated in those terms,
// and the test additionally asserts that *both* paths are slow enough to have done the
// work, which is what stops it passing on a build where neither does.

// timingParams are heavier than the other tests use and lighter than production, so
// that one hash is comfortably above scheduler noise without making the test slow.
func timingParams() authn.Params {
	p := authn.DefaultParams()
	p.Memory, p.Time = 16*1024, 2
	return p
}

func median(samples []time.Duration) time.Duration {
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

// argon2Cost measures one hash under the given parameters, which is the unit every
// threshold in this file is expressed in.
func argon2Cost(t *testing.T, p authn.Params) time.Duration {
	t.Helper()
	const runs = 5
	samples := make([]time.Duration, 0, runs)
	for i := 0; i < runs; i++ {
		start := time.Now()
		if _, err := authn.Hash("a password of no importance", p); err != nil {
			t.Fatalf("Hash: %v", err)
		}
		samples = append(samples, time.Since(start))
	}
	return median(samples)
}

func TestUnknownUserAndWrongPasswordTakeTheSameTime(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	tenantPool, system := f.stores(t)
	a, err := authn.New(tenantPool, system, authn.Options{
		Params: timingParams(),
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		// No audit writer: the failure path writes an audit entry and the success
		// path does not, and that asymmetry is real but belongs to a different
		// measurement. Both paths measured here are failures, so both would write one.
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	// Maria needs a credential under these parameters, or the wrong-password path
	// would verify an 8 MiB hash from the fixture against a 16 MiB decoy and the two
	// would differ for a reason that is not the one under test.
	if setErr := a.SetPassword(ctx, f.tenantID, f.maria, goodPassword); setErr != nil {
		t.Fatalf("setting a password under the timing parameters: %v", setErr)
	}

	cost := argon2Cost(t, timingParams())
	t.Logf("one Argon2id hash at m=%d,t=%d costs %s", timingParams().Memory, timingParams().Time, cost)
	if cost < 2*time.Millisecond {
		// Below this the difference being measured is smaller than the scheduler's
		// noise floor and the test proves nothing either way. Skipping loudly beats
		// passing vacuously.
		t.Skipf("Argon2id costs only %s on this machine, which is too fast for the "+
			"measurement to mean anything; raise timingParams()", cost)
	}

	// Warm-up. The first call pays for the decoy hash, the connection pool and the
	// policy lookup, none of which recur.
	for i := 0; i < 3; i++ {
		_, _ = a.Authenticate(ctx, f.tenantID, "warmup@acme.test", goodPassword)   //nolint:errcheck // warm-up
		_, _ = a.Authenticate(ctx, f.tenantID, f.mariaEmail, "the wrong password") //nolint:errcheck // warm-up
	}

	const samples = 15
	unknown := make([]time.Duration, 0, samples)
	wrong := make([]time.Duration, 0, samples)

	// Interleaved, not one batch after the other. CPU frequency scaling, GC and a
	// noisy neighbour all drift over the run; alternating means any drift lands on
	// both series instead of being mistaken for a difference between them.
	for i := 0; i < samples; i++ {
		start := time.Now()
		_, unknownErr := a.Authenticate(ctx, f.tenantID, "definitely-not-a-user@acme.test", goodPassword)
		unknown = append(unknown, time.Since(start))

		start = time.Now()
		_, wrongErr := a.Authenticate(ctx, f.tenantID, f.mariaEmail, "definitely not her password")
		wrong = append(wrong, time.Since(start))

		// Both must fail, and fail identically. A test that measured a success against
		// a failure would be measuring the wrong thing.
		if !errors.Is(unknownErr, authn.ErrInvalidCredentials) {
			t.Fatalf("the unknown-user attempt returned %v", unknownErr)
		}
		if !errors.Is(wrongErr, authn.ErrInvalidCredentials) {
			t.Fatalf("the wrong-password attempt returned %v", wrongErr)
		}
	}

	unknownMedian, wrongMedian := median(unknown), median(wrong)
	difference := unknownMedian - wrongMedian
	if difference < 0 {
		difference = -difference
	}
	t.Logf("unknown user: %s, wrong password: %s, difference %s (one hash is %s)",
		unknownMedian, wrongMedian, difference, cost)

	// (a) Both paths did the Argon2id work. This is the assertion that has teeth: a
	// function that returned early for an unknown address would land far below one
	// hash, and no amount of noise moves a median by that much.
	floor := cost / 2
	if unknownMedian < floor {
		t.Fatalf("an attempt against an unknown address took %s, less than half the %s an "+
			"Argon2id hash costs — the expensive path was skipped, which makes the endpoint "+
			"an account-existence oracle", unknownMedian, cost)
	}
	if wrongMedian < floor {
		t.Fatalf("an attempt with a wrong password took %s, less than half the %s an "+
			"Argon2id hash costs — the verification did not happen", wrongMedian, cost)
	}

	// (b) And they are close to each other. Half a hash is the bound because a skipped
	// hash is a whole one; anything under that is database and scheduler noise.
	if difference > floor {
		t.Fatalf("unknown-user and wrong-password attempts differ by %s, more than half the %s "+
			"an Argon2id hash costs; the two paths are distinguishable by timing (SPEC §7.2)",
			difference, cost)
	}
}

// TestAUserWithNoPasswordIsTimedLikeOneWithAWrongPassword covers the third state, and
// the one most likely to be forgotten: an invited user who never set a credential.
// There is no hash to verify, so the natural implementation returns immediately.
func TestAUserWithNoPasswordIsTimedLikeOneWithAWrongPassword(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	tenantPool, system := f.stores(t)
	a, err := authn.New(tenantPool, system, authn.Options{
		Params: timingParams(),
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	if setErr := a.SetPassword(ctx, f.tenantID, f.maria, goodPassword); setErr != nil {
		t.Fatalf("setting a password under the timing parameters: %v", setErr)
	}

	cost := argon2Cost(t, timingParams())
	if cost < 2*time.Millisecond {
		t.Skipf("Argon2id costs only %s on this machine; the measurement would prove nothing", cost)
	}

	for i := 0; i < 3; i++ {
		_, _ = a.Authenticate(ctx, f.tenantID, f.bobEmail, goodPassword) //nolint:errcheck // warm-up
	}

	const samples = 11
	noCredential := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		start := time.Now()
		_, authErr := a.Authenticate(ctx, f.tenantID, f.bobEmail, goodPassword)
		noCredential = append(noCredential, time.Since(start))
		if !errors.Is(authErr, authn.ErrInvalidCredentials) {
			t.Fatalf("a user with no password returned %v", authErr)
		}
	}

	got := median(noCredential)
	t.Logf("user with no password: %s (one hash is %s)", got, cost)
	if got < cost/2 {
		t.Fatalf("an attempt against a user with no password credential took %s, less than half "+
			"the %s an Argon2id hash costs. 'Invited but never activated' is distinguishable "+
			"from 'wrong password', which leaks which addresses have pending invitations",
			got, cost)
	}
}
