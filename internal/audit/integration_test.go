package audit_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
)

const dsnEnv = "WARDEN_TEST_DATABASE_URL"

func freshDB(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("set %s to run the audit integration tests", dsnEnv)
	}
	ctx := context.Background()
	conn, connErr := pgx.Connect(ctx, dsn)
	if connErr != nil {
		t.Fatalf("connecting: %v", connErr)
	}
	t.Cleanup(func() { conn.Close(ctx) })

	if _, resetErr := conn.Exec(ctx, `DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public`); resetErr != nil {
		t.Fatalf("resetting: %v", resetErr)
	}
	paths, globErr := filepath.Glob(filepath.Join("..", "store", "migrations", "*.up.sql"))
	if globErr != nil || len(paths) == 0 {
		t.Fatalf("no migrations: %v", globErr)
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
	return conn
}

// appendEntries writes n entries with diffs, each in its own transaction, the way
// real callers do.
func appendEntries(t *testing.T, conn *pgx.Conn, n int) []string {
	t.Helper()
	ctx := context.Background()
	w := audit.NewWriter()
	ids := make([]string, 0, n)

	for i := 0; i < n; i++ {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		id, err := w.Append(ctx, tx, audit.Entry{
			Action:     "role.granted",
			TargetType: "grant",
			TargetID:   "grn_" + strings.Repeat("x", i+1),
			Reason:     "entry number for the chain",
			// Deliberately several keys of different lengths: jsonb would reorder
			// these by length, which is the round-trip bug this guards against.
			After: map[string]any{
				"role": "billing.approver", "scope": "tenant",
				"subject_user": "usr_a", "subject_group": "", "condition": "",
				"valid_until": nil,
			},
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

func verify(t *testing.T, conn *pgx.Conn) audit.VerifyResult {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // read-only verification
	result, err := audit.Verify(ctx, tx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return result
}

// The baseline, and the test that caught two real bugs on first run: an entry has to
// verify against the bytes PostgreSQL actually returns, not the bytes Go handed it.
// Nanosecond timestamps truncated to microseconds, and jsonb reordering object keys
// by length, each made every entry fail its own verification.
func TestAWrittenChainVerifies(t *testing.T) {
	conn := freshDB(t)
	appendEntries(t, conn, 5)

	result := verify(t, conn)
	if result.Entries != 5 {
		t.Fatalf("verified %d entries, wrote 5", result.Entries)
	}
	if !result.OK() {
		t.Fatalf("a freshly written chain does not verify: %v", result.Problems)
	}
}

func TestEmptyChainVerifies(t *testing.T) {
	conn := freshDB(t)
	if result := verify(t, conn); !result.OK() || result.Entries != 0 {
		t.Fatalf("an empty log should verify: %v", result.Problems)
	}
}

// The property the whole design exists for.
func TestAnEditedEntryIsDetected(t *testing.T) {
	conn := freshDB(t)
	ctx := context.Background()
	appendEntries(t, conn, 5)

	// Triggers off: this is an attacker with database access, not an API caller.
	mustExec(t, conn, `ALTER TABLE audit_event DISABLE TRIGGER USER`)
	mustExec(t, conn, `UPDATE audit_event SET reason = 'nothing to see' WHERE seq = 3`)
	mustExec(t, conn, `ALTER TABLE audit_event ENABLE TRIGGER USER`)

	result := verify(t, conn)
	if result.OK() {
		t.Fatal("an edited entry verified")
	}
	if result.Problems[0].Seq != 3 {
		t.Errorf("the first problem is at seq %d, want 3 — the report should point at where tampering begins",
			result.Problems[0].Seq)
	}
	if !strings.Contains(result.Problems[0].Detail, "altered") {
		t.Errorf("detail %q should say the entry was altered", result.Problems[0].Detail)
	}
	_ = ctx
}

func TestADeletedEntryIsDetected(t *testing.T) {
	conn := freshDB(t)
	appendEntries(t, conn, 5)

	mustExec(t, conn, `ALTER TABLE audit_event DISABLE TRIGGER USER`)
	mustExec(t, conn, `DELETE FROM audit_event WHERE seq = 3`)
	mustExec(t, conn, `ALTER TABLE audit_event ENABLE TRIGGER USER`)

	result := verify(t, conn)
	if result.OK() {
		t.Fatal("a deletion left the chain verifying")
	}
	if result.Entries != 4 {
		t.Errorf("read %d entries after deleting one of five", result.Entries)
	}
	if !strings.Contains(result.Problems[0].Detail, "removed") {
		t.Errorf("detail %q should say an entry was removed", result.Problems[0].Detail)
	}
}

// Truncating the log from the end is the subtlest attack: every remaining entry still
// verifies, because nothing about them changed. It is not detectable from the chain
// alone, and pretending otherwise would be worse than saying so.
func TestTruncationFromTheEndIsNotDetectableFromTheChainAlone(t *testing.T) {
	conn := freshDB(t)
	appendEntries(t, conn, 5)

	mustExec(t, conn, `ALTER TABLE audit_event DISABLE TRIGGER USER`)
	mustExec(t, conn, `DELETE FROM audit_event WHERE seq > 3`)
	mustExec(t, conn, `ALTER TABLE audit_event ENABLE TRIGGER USER`)

	result := verify(t, conn)
	if !result.OK() {
		t.Fatalf("the surviving prefix should still verify: %v", result.Problems)
	}
	// This is a documented limitation, not a passing grade. Detecting it needs the
	// head hash published somewhere outside this database — the signed archive of
	// SPEC §16.1, or an external witness. Recorded here so the gap is not mistaken
	// for coverage.
	if result.Entries != 3 {
		t.Fatalf("expected the 3 surviving entries, got %d", result.Entries)
	}
}

// Append-only is enforced, not merely intended.
func TestTheLogRefusesUpdatesAndDeletes(t *testing.T) {
	conn := freshDB(t)
	ctx := context.Background()
	appendEntries(t, conn, 2)

	for _, stmt := range []string{
		`UPDATE audit_event SET reason = 'edited'`,
		`DELETE FROM audit_event`,
		`TRUNCATE audit_event`,
	} {
		if _, err := conn.Exec(ctx, stmt); err == nil {
			t.Errorf("%q was permitted; the log is not append-only", stmt)
		} else if !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%q failed for the wrong reason: %v", stmt, err)
		}
	}
}

// Concurrent appends must not fork the chain: two entries claiming the same
// predecessor would be reported as tampering forever after.
func TestConcurrentAppendsDoNotForkTheChain(t *testing.T) {
	conn := freshDB(t)
	dsn := os.Getenv(dsnEnv)
	ctx := context.Background()
	w := audit.NewWriter()

	const writers = 24
	done := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func(n int) {
			c, err := pgx.Connect(ctx, dsn)
			if err != nil {
				done <- err
				return
			}
			defer c.Close(ctx)

			tx, err := c.Begin(ctx)
			if err != nil {
				done <- err
				return
			}
			if _, appendErr := w.Append(ctx, tx, audit.Entry{
				Action: "concurrent.write", TargetID: "t", Reason: "racing",
			}); appendErr != nil {
				_ = tx.Rollback(ctx) //nolint:errcheck // the append error is what matters
				done <- appendErr
				return
			}
			done <- tx.Commit(ctx)
		}(i)
	}
	for i := 0; i < writers; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent append: %v", err)
		}
	}

	result := verify(t, conn)
	if result.Entries != writers {
		t.Fatalf("wrote %d entries concurrently, verified %d", writers, result.Entries)
	}
	if !result.OK() {
		t.Fatalf("concurrent appends forked the chain: %v", result.Problems)
	}
}

func mustExec(t *testing.T, conn *pgx.Conn, sql string) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}
