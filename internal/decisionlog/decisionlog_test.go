package decisionlog_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/decisionlog"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

const dsnEnv = "WARDEN_TEST_DATABASE_URL"

func newSink(t *testing.T, opts decisionlog.Options) (*decisionlog.Sink, *pgx.Conn) {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("set %s to run the decision log tests", dsnEnv)
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
	if _, err := conn.Exec(ctx,
		`INSERT INTO tenant (id, slug, name) VALUES ('ten_a','a','A'), ('ten_b','b','B')`); err != nil {
		t.Fatalf("seeding tenants: %v", err)
	}

	cfg := config.Defaults()
	cfg.Environment = config.EnvDevelopment
	cfg.Issuer = "http://localhost"
	cfg.Database.URL = secrets.New(dsn)
	cfg.Database.SystemURL = secrets.New(dsn)
	cfg.Database.MaxOpenConns = 4
	cfg.Database.MaxIdleConns = 1
	cfg.Database.ConnectTimeout = 10 * time.Second
	cfg.Database.StatementTimeout = 10 * time.Second

	db, err := store.Open(ctx, cfg, store.SystemAccess)
	if err != nil {
		t.Fatalf("opening the system store: %v", err)
	}
	t.Cleanup(db.Close)

	if opts.FlushInterval == 0 {
		opts.FlushInterval = 20 * time.Millisecond
	}
	sink, err := decisionlog.New(db, slog.New(slog.NewTextHandler(io.Discard, nil)), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = sink.Close(closeCtx) //nolint:errcheck // best effort at teardown
	})
	return sink, conn
}

func TestRecordsAreWritten(t *testing.T) {
	sink, conn := newSink(t, decisionlog.Options{})
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		sink.Record(decisionlog.Record{
			TenantID: "ten_a", SubjectID: "usr_1",
			Permission: "billing.invoice:read", Allowed: i%2 == 0,
			Reason: "grant_matched", Revision: 7, Latency: 250 * time.Microsecond,
		})
	}

	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := sink.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var count int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM decision_event`).Scan(&count); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if count != 10 {
		t.Fatalf("wrote %d records, queued 10", count)
	}
	if written := sink.Stats().Written.Load(); written != 10 {
		t.Errorf("Written reports %d", written)
	}
}

// Closing must drain rather than discard: a clean shutdown should not throw away the
// last second of decisions.
func TestCloseDrainsWhatIsQueued(t *testing.T) {
	// A long flush interval, so nothing is written before Close is called.
	sink, conn := newSink(t, decisionlog.Options{FlushInterval: time.Hour})
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		sink.Record(decisionlog.Record{
			TenantID: "ten_a", SubjectID: "usr_1",
			Permission: "billing.invoice:read", Reason: "no_grant",
		})
	}
	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := sink.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var count int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM decision_event`).Scan(&count); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if count != 50 {
		t.Fatalf("drained %d of 50 queued records", count)
	}
}

// The property that matters most: recording must never block a decision. A full
// buffer drops and counts, because an authorization service that stalls on its
// logging backend has turned observability into an availability incident.
func TestAFullBufferDropsRatherThanBlocks(t *testing.T) {
	sink, _ := newSink(t, decisionlog.Options{Buffer: 4, FlushInterval: time.Hour})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			sink.Record(decisionlog.Record{
				TenantID: "ten_a", SubjectID: "usr_1",
				Permission: "billing.invoice:read", Reason: "no_grant",
			})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked on a full buffer; a decision would have stalled behind its own logging")
	}

	stats := sink.Stats()
	if stats.Dropped.Load() == 0 {
		t.Error("nothing was dropped, so the buffer bound is not being enforced")
	}
	if stats.Accepted.Load() != 10000 {
		t.Errorf("Accepted reports %d of 10000 offered", stats.Accepted.Load())
	}
}

// The levels of SPEC §16.2.
func TestLevelsSelectWhatIsRecorded(t *testing.T) {
	sink, _ := newSink(t, decisionlog.Options{})

	cases := []struct {
		level       decisionlog.Level
		allow, deny bool
	}{
		{decisionlog.LevelOff, false, false},
		{decisionlog.LevelDenies, false, true},
		{decisionlog.LevelAll, true, true},
	}
	for _, tc := range cases {
		t.Run(string(tc.level), func(t *testing.T) {
			if got := sink.ShouldRecord(tc.level, true); got != tc.allow {
				t.Errorf("allow recorded = %v, want %v", got, tc.allow)
			}
			if got := sink.ShouldRecord(tc.level, false); got != tc.deny {
				t.Errorf("deny recorded = %v, want %v", got, tc.deny)
			}
		})
	}

	// Sampled always records denials — the decisions someone disputes — and only a
	// fraction of allows.
	if !sink.ShouldRecord(decisionlog.LevelSampled, false) {
		t.Error("sampled must record every denial")
	}
}

// An unrecognised level must record denials rather than nothing: erring toward
// recording less than configured silently loses what the log was turned on for.
func TestAnUnrecognisedLevelFallsBackToDenies(t *testing.T) {
	sink, _ := newSink(t, decisionlog.Options{})
	if sink.ShouldRecord("nonsense", true) {
		t.Error("an unknown level recorded an allow")
	}
	if !sink.ShouldRecord("nonsense", false) {
		t.Error("an unknown level dropped a denial")
	}
}

func TestParseLevelRejectsNonsense(t *testing.T) {
	for _, valid := range []string{"off", "denies", "sampled", "all"} {
		if _, err := decisionlog.ParseLevel(valid); err != nil {
			t.Errorf("ParseLevel(%q): %v", valid, err)
		}
	}
	if _, err := decisionlog.ParseLevel("everything"); err == nil {
		t.Error("an invented level was accepted")
	}
}

// Decisions are tenant data, and the log is subject to the same isolation as the rest.
func TestTheLogIsTenantIsolated(t *testing.T) {
	sink, conn := newSink(t, decisionlog.Options{})
	ctx := context.Background()

	for _, tn := range []string{"ten_a", "ten_b"} {
		sink.Record(decisionlog.Record{
			TenantID: tn, SubjectID: "usr_1",
			Permission: "billing.invoice:read", Reason: "no_grant",
		})
	}
	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := sink.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var seenByA int
	if err := conn.QueryRow(ctx, `
		SELECT count(*) FROM decision_event WHERE tenant_id = 'ten_b'`).Scan(&seenByA); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if seenByA != 1 {
		t.Fatalf("expected one record for ten_b, got %d", seenByA)
	}
	// The isolation itself is asserted in internal/store, against every table
	// including this one and its partitions; this only confirms the rows land where
	// their tenant says.
}
