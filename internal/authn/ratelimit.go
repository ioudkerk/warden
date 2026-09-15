package authn

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/warden-project/warden/internal/cache"
)

// Lockout is SPEC §7.2's "exponential backoff per (account, IP) pair plus a global
// per-account cap".
//
// Two counters, because they answer different attacks. The pair counter slows somebody
// guessing one account from one place, which is the common case and the one that should
// cost them time rather than lock anybody out. The account counter is the backstop
// against a distributed attempt, where each source looks innocent and only the account
// sees the volume — but it is also the one that can be used to lock a real person out on
// purpose, so it is deliberately generous and the lockout is a delay rather than
// something an administrator has to clear.
//
// **It counts what was presented, not what exists.** An attempt against an address with
// no account increments exactly as one against a real user, because anything else is an
// enumeration oracle: an attacker who is never rate-limited has learned that the address
// is unknown. This is the same reasoning that makes Authenticate do constant work.
type Lockout struct {
	cache cache.Cache
	log   *slog.Logger

	// pepper keys the hash of identifiers used in cache keys, so a dump of Redis is
	// not a list of the addresses people have tried to log in as.
	pepper []byte

	policy LockoutPolicy
	now    func() time.Time
}

// LockoutPolicy is the tunable part.
type LockoutPolicy struct {
	// FreeAttempts is how many failures a (account, IP) pair gets before any delay.
	// People mistype passwords; the first few attempts should feel like nothing.
	FreeAttempts int

	// BaseDelay is the delay after the first attempt past FreeAttempts. It doubles
	// with each subsequent failure.
	BaseDelay time.Duration

	// MaxDelay caps the doubling. Past this, an attacker is slowed as much as they
	// are going to be, and a legitimate user locked out by somebody else's guessing
	// has a bounded wait.
	MaxDelay time.Duration

	// PairWindow is how long pair failures are remembered.
	PairWindow time.Duration

	// AccountCap is the number of failures an account tolerates across all sources
	// within AccountWindow before every attempt is refused.
	AccountCap int

	// AccountWindow is the account counter's memory.
	AccountWindow time.Duration
}

// DefaultLockoutPolicy is what a deployment gets unless it says otherwise.
//
// The figures are chosen so that a human who has forgotten their password notices
// nothing for the first few tries, while an automated attempt is reduced to a handful of
// guesses per hour per source. The account cap is high enough that locking somebody out
// on purpose takes a hundred deliberate failures and still expires by itself.
func DefaultLockoutPolicy() LockoutPolicy {
	return LockoutPolicy{
		FreeAttempts:  5,
		BaseDelay:     time.Second,
		MaxDelay:      15 * time.Minute,
		PairWindow:    time.Hour,
		AccountCap:    100,
		AccountWindow: time.Hour,
	}
}

// Validate rejects a policy that would not limit anything.
func (p LockoutPolicy) Validate() error {
	switch {
	case p.FreeAttempts < 0:
		return errors.New("free attempts cannot be negative")
	case p.BaseDelay <= 0:
		return errors.New("the base delay must be positive")
	case p.MaxDelay < p.BaseDelay:
		return fmt.Errorf("the maximum delay %s is below the base delay %s", p.MaxDelay, p.BaseDelay)
	case p.PairWindow <= 0:
		return errors.New("the pair window must be positive")
	case p.AccountCap < 1:
		return errors.New("the account cap must be at least 1")
	case p.AccountWindow <= 0:
		return errors.New("the account window must be positive")
	}
	return nil
}

// LockoutOptions configure a Lockout.
type LockoutOptions struct {
	Policy LockoutPolicy
	Log    *slog.Logger
	// Pepper keys the identifier hash. Derive it from the KEK
	// (secrets.Keyring.Derive) so it is stable across replicas: a per-process pepper
	// would give each replica its own counters, and the limit would multiply by the
	// number of replicas.
	Pepper []byte
}

// NewLockout builds the limiter.
func NewLockout(c cache.Cache, opts LockoutOptions) (*Lockout, error) {
	if c == nil {
		return nil, errors.New(
			"rate limiting requires the cache tier: counters have to be shared across " +
				"replicas or the limit multiplies by the number of processes")
	}
	policy := opts.Policy
	if policy == (LockoutPolicy{}) {
		policy = DefaultLockoutPolicy()
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if len(opts.Pepper) == 0 {
		return nil, errors.New("rate limiting requires a pepper for the identifier hash")
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	return &Lockout{
		cache: c, log: log, pepper: opts.Pepper,
		policy: policy, now: time.Now,
	}, nil
}

// SetClock replaces the limiter's notion of the current time. For tests.
func (l *Lockout) SetClock(now func() time.Time) { l.now = now }

// Decision is what Check returns.
type Decision struct {
	// Allowed is false when the attempt must be refused without checking the password.
	Allowed bool
	// RetryAfter is how long the caller should tell the client to wait. Zero when
	// allowed.
	RetryAfter time.Duration
	// Reason distinguishes the two counters, for logs and metrics. Never for the
	// response: a caller that told a client which limit it hit would be describing the
	// shape of the defence.
	Reason string
}

const (
	// ReasonPairBackoff is the per-(account, IP) delay.
	ReasonPairBackoff = "pair_backoff"
	// ReasonAccountCapped is the global per-account limit.
	ReasonAccountCapped = "account_capped"
)

// identifierKey hashes an identifier for use in a cache key.
//
// HMAC rather than a plain hash, so that somebody who obtains the cache cannot confirm a
// guessed address by hashing it themselves. The addresses people fail to log in as are
// worth as much to an attacker as a user list.
func (l *Lockout) identifierKey(parts ...string) string {
	mac := hmac.New(sha256.New, l.pepper)
	for _, part := range parts {
		mac.Write([]byte(part))
		mac.Write([]byte{0}) // a separator, so ("ab","c") and ("a","bc") differ
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

func (l *Lockout) pairKey(tenantID, identifier, ip string) string {
	return "warden:lockout:pair:" + l.identifierKey(tenantID, identifier, ip)
}

func (l *Lockout) accountKey(tenantID, identifier string) string {
	return "warden:lockout:account:" + l.identifierKey(tenantID, identifier)
}

// nextAllowedKey holds the instant a pair may try again.
//
// Stored rather than computed from the count at read time, because the delay has to run
// from the *last* failure. A count alone would let somebody who waited out one backoff
// spend their next attempt immediately and then be told to wait the doubled delay from
// the original failure, which is both confusing and shorter than intended.
func (l *Lockout) nextAllowedKey(tenantID, identifier, ip string) string {
	return "warden:lockout:until:" + l.identifierKey(tenantID, identifier, ip)
}

// Check reports whether an attempt may proceed.
//
// It is called *before* the password is verified, and it must be: the point of a limiter
// is to make the expensive check not happen. It does not record anything — a successful
// login should not count against a limit — so the caller pairs it with Failed or
// Succeeded.
func (l *Lockout) Check(ctx context.Context, tenantID, identifier, ip string) (Decision, error) {
	// The account cap first. It is the one that refuses outright, and checking it first
	// means a capped account is not also told a pair-specific delay, which would leak
	// which of the two it hit.
	accountCount, err := l.counter(ctx, l.accountKey(tenantID, identifier))
	if err != nil {
		return Decision{}, err
	}
	if accountCount >= int64(l.policy.AccountCap) {
		return Decision{
			Allowed:    false,
			RetryAfter: l.policy.AccountWindow,
			Reason:     ReasonAccountCapped,
		}, nil
	}

	raw, err := l.cache.Get(ctx, l.nextAllowedKey(tenantID, identifier, ip))
	if errors.Is(err, cache.ErrMiss) {
		return Decision{Allowed: true}, nil
	}
	if err != nil {
		return Decision{}, fmt.Errorf("reading the lockout state: %w", err)
	}

	until, err := time.Parse(time.RFC3339Nano, string(raw))
	if err != nil {
		// An unreadable marker is treated as no marker. Failing closed here would lock
		// a user out because of a storage bug, and the counters themselves still apply.
		l.log.Warn("a lockout marker could not be parsed", "value", string(raw))
		return Decision{Allowed: true}, nil //nolint:nilerr // see above: a storage bug must not lock anyone out
	}

	if remaining := until.Sub(l.now()); remaining > 0 {
		return Decision{Allowed: false, RetryAfter: remaining, Reason: ReasonPairBackoff}, nil
	}
	return Decision{Allowed: true}, nil
}

// Failed records an unsuccessful attempt and returns how long the pair must now wait.
//
// Called for every failure, whatever the cause — wrong password, unknown address,
// suspended account. Counting only real accounts would make the limiter itself an
// enumeration oracle: the attempts that are never slowed are the ones against addresses
// that do not exist.
func (l *Lockout) Failed(ctx context.Context, tenantID, identifier, ip string) (time.Duration, error) {
	if _, err := l.cache.Increment(ctx, l.accountKey(tenantID, identifier),
		l.policy.AccountWindow); err != nil {
		return 0, fmt.Errorf("counting a failed attempt: %w", err)
	}

	count, err := l.cache.Increment(ctx, l.pairKey(tenantID, identifier, ip), l.policy.PairWindow)
	if err != nil {
		return 0, fmt.Errorf("counting a failed attempt: %w", err)
	}

	delay := l.delayFor(count)
	if delay <= 0 {
		return 0, nil
	}

	until := l.now().Add(delay)
	// The marker outlives the delay by the pair window, so that a long backoff is not
	// forgotten because its own key expired first.
	ttl := delay + l.policy.PairWindow
	if err := l.cache.Set(ctx, l.nextAllowedKey(tenantID, identifier, ip),
		[]byte(until.Format(time.RFC3339Nano)), ttl); err != nil {
		return 0, fmt.Errorf("recording the lockout: %w", err)
	}
	return delay, nil
}

// delayFor computes the backoff imposed *after* the nth failure.
//
// The +1 is the difference between "how many failures have there been" and "how many
// attempts were free", and getting it wrong is an off-by-one that quietly grants an
// extra try: with FreeAttempts at 3, the third failure is what must impose the first
// delay, so that attempts one to three cost nothing and the fourth is slowed. Counting
// from the fourth failure instead would mean four free attempts under a setting that
// says three.
func (l *Lockout) delayFor(count int64) time.Duration {
	over := count - int64(l.policy.FreeAttempts) + 1
	if over <= 0 {
		return 0
	}
	// Doubling, capped. The shift is computed in float so that a large count cannot
	// overflow into a negative duration — which would read as "no delay" and quietly
	// disable the limiter at exactly the point it matters most.
	delay := float64(l.policy.BaseDelay) * math.Pow(2, float64(over-1))
	if delay > float64(l.policy.MaxDelay) || math.IsInf(delay, 1) {
		return l.policy.MaxDelay
	}
	return time.Duration(delay)
}

// Succeeded clears the pair's backoff after a successful login.
//
// The account counter is deliberately *not* cleared. It is the backstop against a
// distributed attempt, and an attacker who has guessed one password should not thereby
// reset the budget protecting the rest.
func (l *Lockout) Succeeded(ctx context.Context, tenantID, identifier, ip string) error {
	return l.cache.Delete(ctx,
		l.pairKey(tenantID, identifier, ip),
		l.nextAllowedKey(tenantID, identifier, ip))
}

// counter reads a counter, treating absence as zero.
func (l *Lockout) counter(ctx context.Context, key string) (int64, error) {
	raw, err := l.cache.Get(ctx, key)
	if errors.Is(err, cache.ErrMiss) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("reading a lockout counter: %w", err)
	}
	var count int64
	if _, scanErr := fmt.Sscanf(string(raw), "%d", &count); scanErr != nil {
		l.log.Warn("a lockout counter could not be parsed", "value", string(raw))
		return 0, nil //nolint:nilerr // an unreadable counter reads as zero; the cap still applies on the next increment
	}
	return count, nil
}

// Policy returns the limiter's configuration, for diagnostics.
func (l *Lockout) Policy() LockoutPolicy { return l.policy }
