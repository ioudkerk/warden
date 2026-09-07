package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/store"
)

func TestRetryableCodeClassifies(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"serialization failure", &pgconn.PgError{Code: "40001"}, "40001"},
		{"deadlock", &pgconn.PgError{Code: "40P01"}, "40P01"},
		{"wrapped deadlock", fmt.Errorf("bumping the revision: %w", &pgconn.PgError{Code: "40P01"}), "40P01"},

		// The point of classifying at all: these must not be retried. A unique
		// violation retried three times is three identical failures and a bug that
		// took three times as long to find.
		{"unique violation", &pgconn.PgError{Code: "23505"}, ""},
		{"foreign key violation", &pgconn.PgError{Code: "23503"}, ""},
		{"check violation", &pgconn.PgError{Code: "23514"}, ""},
		{"insufficient privilege", &pgconn.PgError{Code: "42501"}, ""},
		{"no rows", pgx.ErrNoRows, ""},
		{"plain error", errors.New("something else"), ""},
		{"nil", nil, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := store.RetryableCode(tc.err); got != tc.want {
				t.Fatalf("RetryableCode(%v) = %q, want %q", tc.err, got, tc.want)
			}
			if got := store.IsRetryable(tc.err); got != (tc.want != "") {
				t.Fatalf("IsRetryable(%v) = %v, want %v", tc.err, got, tc.want != "")
			}
		})
	}
}

// TestDeadlockIsRetried provokes a real deadlock between two transactions and asserts
// that both of them nevertheless complete.
//
// It is written against the database rather than a fake because the thing under test
// is a claim about PostgreSQL: that it aborts one side of a lock cycle with 40P01 and
// that reissuing the aborted transaction then succeeds. A mock returning a canned
// error would assert only that the retry loop loops.
func TestDeadlockIsRetried(t *testing.T) {
	systemURL, applicationURL := setupDatabase(t)
	cfg := testConfig(t, systemURL, applicationURL, config.EnvDevelopment)
	s := openStore(t, cfg, store.SystemAccess)

	ctx := context.Background()

	// Two rows for the two transactions to fight over.
	const (
		tenantA = "ten_deadlock_a"
		tenantB = "ten_deadlock_b"
	)
	if err := s.InSystem(ctx, "test fixture", func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO tenant (id, slug, name) VALUES ($1, 'deadlock-a', 'A'), ($2, 'deadlock-b', 'B')`,
			tenantA, tenantB)
		return err
	}); err != nil {
		t.Fatalf("seeding the tenants: %v", err)
	}

	var retries []store.RetryInfo
	var mu sync.Mutex
	s.SetRetryObserver(func(info store.RetryInfo) {
		mu.Lock()
		defer mu.Unlock()
		retries = append(retries, info)
	})

	// Each transaction locks its first row, waits for the other to have locked its
	// own, then reaches for the row the other is holding. That is the cycle.
	bothLocked := make(chan struct{})
	var once sync.Once
	var ready sync.WaitGroup
	ready.Add(2)
	release := func() { once.Do(func() { close(bothLocked) }) }

	lockThen := func(first, second string) error {
		firstTime := true
		return s.InSystem(ctx, "deadlock probe", func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx,
				`UPDATE tenant SET permission_rev = permission_rev + 1 WHERE id = $1`, first); err != nil {
				return err
			}
			// Only the first attempt participates in the handshake. A retry must not
			// wait for a partner that has already committed and gone.
			if firstTime {
				firstTime = false
				ready.Done()
				select {
				case <-bothLocked:
				case <-time.After(10 * time.Second):
					return errors.New("timed out waiting for both transactions to take their first lock")
				}
			}
			_, err := tx.Exec(ctx,
				`UPDATE tenant SET permission_rev = permission_rev + 1 WHERE id = $1`, second)
			return err
		})
	}

	go func() { ready.Wait(); release() }()

	errs := make(chan error, 2)
	go func() { errs <- lockThen(tenantA, tenantB) }()
	go func() { errs <- lockThen(tenantB, tenantA) }()

	for i := range 2 {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("transaction %d failed instead of being retried: %v", i, err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("a transaction never returned; PostgreSQL's deadlock_timeout is 1s by default")
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(retries) == 0 {
		t.Fatal("both transactions succeeded without a retry, so this test did not deadlock " +
			"and proves nothing; the lock ordering above no longer produces a cycle")
	}
	for _, info := range retries {
		if info.Code != "40P01" {
			t.Errorf("retried on %s, want a deadlock (40P01)", info.Code)
		}
		if info.Exhausted {
			t.Errorf("attempt %d exhausted the budget, yet the transaction succeeded", info.Attempt)
		}
	}
	t.Logf("deadlock detected and retried %d time(s); both transactions committed", len(retries))
}

// TestRetryGivesUp checks the other half of the contract: a transaction that keeps
// failing is eventually returned to the caller rather than retried forever.
func TestRetryGivesUp(t *testing.T) {
	systemURL, applicationURL := setupDatabase(t)
	cfg := testConfig(t, systemURL, applicationURL, config.EnvDevelopment)
	s := openStore(t, cfg, store.SystemAccess)
	s.SetRetryPolicy(store.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: time.Millisecond})

	var observed []store.RetryInfo
	s.SetRetryObserver(func(info store.RetryInfo) { observed = append(observed, info) })

	attempts := 0
	err := s.InSystem(context.Background(), "always deadlocks", func(context.Context, pgx.Tx) error {
		attempts++
		return &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}
	})

	if err == nil {
		t.Fatal("a transaction that always fails must return its error")
	}
	if !store.IsRetryable(err) {
		t.Fatalf("the returned error lost its classification: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("ran %d attempts, want 3", attempts)
	}
	if len(observed) != 3 || !observed[2].Exhausted {
		t.Fatalf("observer saw %d attempts, last exhausted=%v; want 3 with the last exhausted",
			len(observed), len(observed) > 0 && observed[len(observed)-1].Exhausted)
	}
	if observed[2].Delay != 0 {
		t.Errorf("the exhausted attempt reported a delay of %s; nothing waits after it", observed[2].Delay)
	}
}

// TestPermanentErrorIsNotRetried is the counterpart: the loop must not turn one bug
// into three.
func TestPermanentErrorIsNotRetried(t *testing.T) {
	systemURL, applicationURL := setupDatabase(t)
	cfg := testConfig(t, systemURL, applicationURL, config.EnvDevelopment)
	s := openStore(t, cfg, store.SystemAccess)

	attempts := 0
	err := s.InSystem(context.Background(), "duplicate key", func(ctx context.Context, tx pgx.Tx) error {
		attempts++
		_, execErr := tx.Exec(ctx,
			`INSERT INTO tenant (id, slug, name) VALUES ('ten_dup', 'dup', 'Dup'), ('ten_dup', 'dup2', 'Dup')`)
		return execErr
	})

	if err == nil {
		t.Fatal("inserting the same primary key twice must fail")
	}
	if attempts != 1 {
		t.Fatalf("a unique violation was attempted %d times; it must not be retried", attempts)
	}
}

// TestIsolationOptionApplies checks that a caller can ask for more than READ
// COMMITTED, which is the point of having the option at all: M1-5's refresh-token
// reuse detection needs it.
func TestIsolationOptionApplies(t *testing.T) {
	systemURL, applicationURL := setupDatabase(t)
	cfg := testConfig(t, systemURL, applicationURL, config.EnvDevelopment)
	s := openStore(t, cfg, store.SystemAccess)

	for _, tc := range []struct {
		name string
		opts []store.TxOption
		want string
	}{
		{"default", nil, "read committed"},
		{"serializable", []store.TxOption{store.Isolation(pgx.Serializable)}, "serializable"},
		{"repeatable read", []store.TxOption{store.Isolation(pgx.RepeatableRead)}, "repeatable read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var level string
			err := s.InSystem(context.Background(), "reading the isolation level",
				func(ctx context.Context, tx pgx.Tx) error {
					return tx.QueryRow(ctx, `SHOW transaction_isolation`).Scan(&level)
				}, tc.opts...)
			if err != nil {
				t.Fatalf("running the transaction: %v", err)
			}
			if level != tc.want {
				t.Fatalf("transaction_isolation = %q, want %q", level, tc.want)
			}
		})
	}
}

// TestReadOnlyOptionRefusesWrites makes the read-only option worth having: it must
// actually stop a write rather than merely document an intention.
func TestReadOnlyOptionRefusesWrites(t *testing.T) {
	systemURL, applicationURL := setupDatabase(t)
	cfg := testConfig(t, systemURL, applicationURL, config.EnvDevelopment)
	s := openStore(t, cfg, store.SystemAccess)

	err := s.InSystem(context.Background(), "writing in a read-only transaction",
		func(ctx context.Context, tx pgx.Tx) error {
			_, execErr := tx.Exec(ctx, `INSERT INTO tenant (id, slug, name) VALUES ('ten_ro', 'ro', 'RO')`)
			return execErr
		}, store.ReadOnly())

	if err == nil {
		t.Fatal("a write inside a read-only transaction must be refused")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "25006" {
		t.Fatalf("got %v, want SQLSTATE 25006 (read_only_sql_transaction)", err)
	}
}
