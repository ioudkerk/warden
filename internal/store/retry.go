package store

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The two SQLSTATEs PostgreSQL uses to say "this was not your fault, run it again".
//
// They are the only ones retried here, deliberately. A unique violation retried three
// times is three identical failures and one hidden bug; a connection error retried
// mid-transaction is a request replayed against a server that may already have
// committed it. These two, and only these two, are the ones the database itself
// defines as transient and expects the client to reissue.
const (
	// codeSerializationFailure: two transactions at REPEATABLE READ or SERIALIZABLE
	// whose interleaving has no equivalent serial order. Cannot occur at READ
	// COMMITTED, which is what Warden uses unless a caller asks for more.
	codeSerializationFailure = "40001"

	// codeDeadlockDetected: A holds a row B wants and B holds a row A wants.
	// PostgreSQL breaks the cycle by aborting one of them. This one can happen at
	// any isolation level.
	codeDeadlockDetected = "40P01"
)

// RetryPolicy bounds how hard a transaction tries.
type RetryPolicy struct {
	// MaxAttempts includes the first try, so 3 means "the original and two retries".
	// Zero or one disables retrying.
	MaxAttempts int
	// BaseDelay is the first backoff interval; it doubles each attempt.
	BaseDelay time.Duration
	// MaxDelay caps the doubling.
	MaxDelay time.Duration
}

// DefaultRetryPolicy is deliberately impatient.
//
// A deadlock is already resolved by the time the error arrives — PostgreSQL aborted
// one side, so the lock the retry needs is either free or about to be. Waiting longer
// does not raise the odds of success; it holds a pooled connection and a request
// open while nothing happens. Three attempts over tens of milliseconds either works
// or means the contention is structural, which is a thing to fix rather than to
// absorb.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 3, BaseDelay: 5 * time.Millisecond, MaxDelay: 100 * time.Millisecond}
}

// delay returns the backoff before the given attempt, with full jitter.
//
// The jitter is not decoration. Two transactions that deadlock and then both wait
// exactly 5 ms will collide again on the same rows, in the same order, at the same
// moment. Spreading the retries across the interval is what makes the second attempt
// a different race from the first.
func (p RetryPolicy) delay(attempt int) time.Duration {
	d := p.BaseDelay
	for range attempt - 1 {
		d *= 2
		if d >= p.MaxDelay {
			d = p.MaxDelay
			break
		}
	}
	return rand.N(d) //nolint:gosec // jitter, not a security decision
}

// RetryInfo describes one retried attempt, for an observer that wants to count them.
type RetryInfo struct {
	// Attempt is the number of the attempt that just failed, starting at 1.
	Attempt int
	// Code is the SQLSTATE that caused the retry: 40001 or 40P01.
	Code string
	// Delay is how long the store waited before trying again. Zero when the retry
	// budget is exhausted and there will be no further attempt.
	Delay time.Duration
	// Exhausted reports that this was the last attempt and the error is being
	// returned to the caller.
	Exhausted bool
	Err       error
}

// RetryableCode returns the SQLSTATE that makes err retryable, or "" if it is not.
//
// Exported because the classification is the interesting part: a caller writing its
// own transaction loop, and a test asserting that something really did deadlock,
// should both be able to ask the same question the store asks.
func RetryableCode(err error) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return ""
	}
	switch pgErr.Code {
	case codeSerializationFailure, codeDeadlockDetected:
		return pgErr.Code
	default:
		return ""
	}
}

// IsRetryable reports whether PostgreSQL aborted the transaction and asked for it to
// be reissued.
func IsRetryable(err error) bool { return RetryableCode(err) != "" }

// TxOption configures one transaction. Options are variadic and last so that the
// common call — no options at all — reads exactly as it did before they existed.
type TxOption func(*pgx.TxOptions)

// Isolation raises the transaction's isolation level above the READ COMMITTED
// default.
//
// Ask for this only with a retry loop behind it, which is what the store's helpers
// provide: at REPEATABLE READ and above, a serialization failure is a normal outcome
// of concurrency rather than an error condition, and code that does not retry is code
// that fails under load.
func Isolation(level pgx.TxIsoLevel) TxOption {
	return func(o *pgx.TxOptions) { o.IsoLevel = level }
}

// ReadOnly marks the transaction read-only, which lets PostgreSQL refuse a write that
// was not supposed to happen rather than performing it.
func ReadOnly() TxOption {
	return func(o *pgx.TxOptions) { o.AccessMode = pgx.ReadOnly }
}

// SetRetryObserver installs a function called on every retried transaction.
//
// Call it during startup, before the store serves anything: it is a plain assignment
// and racing it against live traffic is a data race. It exists so that
// cmd/warden can feed retries to Prometheus without internal/store importing the
// metrics package, and so a test can count retries without scraping anything.
func (s *Store) SetRetryObserver(fn func(RetryInfo)) { s.onRetry = fn }

// SetRetryPolicy replaces the retry policy. Same rule: startup only.
func (s *Store) SetRetryPolicy(p RetryPolicy) { s.retry = p }

// inTx runs fn in a transaction, reissuing it when PostgreSQL says the failure was
// transient.
//
// A retry re-runs the whole of fn, which is safe only because the previous attempt
// rolled back — the database is in the state fn first saw. What that does not undo is
// anything fn did outside the database. A callback that sends an email, writes a
// file, or returns a value generated inside itself must not be handed to this; the
// convention in Warden is that such values are produced before the transaction opens
// and passed in, which is why a retried CreateServiceAccount does not mint a second
// token.
func (s *Store) inTx(ctx context.Context, opts []TxOption, fn func(context.Context, pgx.Tx) error) error {
	txOptions := pgx.TxOptions{}
	for _, opt := range opts {
		opt(&txOptions)
	}

	attempts := s.retry.MaxAttempts
	if attempts < 1 {
		attempts = 1
	}

	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		err = pgx.BeginTxFunc(ctx, s.pool, txOptions, func(tx pgx.Tx) error {
			return fn(ctx, tx)
		})
		if err == nil {
			return nil
		}

		code := RetryableCode(err)
		if code == "" {
			return err
		}

		// A cancelled context means nobody is waiting for the answer any more.
		// Sleeping and reissuing would spend a connection on a request that has
		// already gone.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return err
		}

		last := attempt == attempts
		info := RetryInfo{Attempt: attempt, Code: code, Err: err, Exhausted: last}
		if !last {
			info.Delay = s.retry.delay(attempt)
		}
		if s.onRetry != nil {
			s.onRetry(info)
		}
		if last {
			break
		}

		timer := time.NewTimer(info.Delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
	}
	return err
}
