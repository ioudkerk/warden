// Package decisionlog records authorization decisions (SPEC §16.2).
//
// Unlike the audit log this is high volume — one record per decision, at whatever
// rate the PDP answers them — so two properties matter more than completeness.
//
// It never blocks a decision. Records go onto a bounded channel and a background
// worker writes them in batches; when the channel is full, records are dropped and
// counted. Dropping is the correct behaviour and not a compromise: an authorization
// service that slows down or fails because its logging backend is unhappy has turned
// an observability feature into an availability incident.
//
// It is configurable per application. Recording every allow at full volume is rarely
// worth what it costs, so the default is denials only — the decisions someone will
// actually come asking about.
package decisionlog

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/store"
)

// Level controls how much is recorded (SPEC §16.2).
type Level string

const (
	// LevelOff records nothing.
	LevelOff Level = "off"
	// LevelDenies records every denial. The default: a denial is what someone
	// disputes, and denials are a small fraction of traffic in a healthy system.
	LevelDenies Level = "denies"
	// LevelSampled records every denial plus a fraction of allows, so the log shows
	// what normal looks like without paying for all of it.
	LevelSampled Level = "sampled"
	// LevelAll records everything.
	LevelAll Level = "all"
)

// ParseLevel converts a configured string, rejecting anything unrecognised rather
// than silently choosing a level nobody asked for.
func ParseLevel(s string) (Level, error) {
	switch Level(s) {
	case LevelOff, LevelDenies, LevelSampled, LevelAll:
		return Level(s), nil
	default:
		return "", fmt.Errorf("decision log level %q; want off, denies, sampled or all", s)
	}
}

// Record is one decision.
type Record struct {
	TenantID      string
	SubjectID     string
	ApplicationID string
	Permission    string
	ResourceRef   string
	Allowed       bool
	Reason        string
	MatchedGrant  string
	Latency       time.Duration
	Degraded      bool
	Revision      int64
	OccurredAt    time.Time
}

// Stats are the sink's counters, exposed for the metrics of SPEC §16.3.
type Stats struct {
	Accepted atomic.Int64
	Written  atomic.Int64
	// Dropped counts records discarded because the buffer was full. A non-zero and
	// rising value means the log is lossy, which is a capacity signal — never a
	// reason to start blocking decisions.
	Dropped atomic.Int64
	Failed  atomic.Int64
}

// Sink buffers records and writes them in batches.
type Sink struct {
	db  *store.Store
	log *slog.Logger

	records chan Record
	stats   Stats

	// sampleRate is the fraction of allows recorded at LevelSampled.
	sampleRate float64

	batchSize     int
	flushInterval time.Duration

	stop     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

// Options configure a sink.
type Options struct {
	// Buffer bounds the queue. Bounded on purpose: an unbounded one turns a slow
	// database into an out-of-memory kill, which is a worse failure than a lossy log.
	Buffer        int
	BatchSize     int
	FlushInterval time.Duration
	SampleRate    float64
}

// New starts a sink. Close it to drain and stop.
//
// It writes through the system pool because a decision belongs to the tenant it was
// made for, and the writer is not itself acting within a tenant scope.
func New(db *store.Store, log *slog.Logger, opts Options) (*Sink, error) {
	if db.Access() != store.SystemAccess {
		return nil, errors.New("the decision log writes through the system pool")
	}
	if opts.Buffer <= 0 {
		opts.Buffer = 4096
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 256
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = time.Second
	}
	if opts.SampleRate <= 0 || opts.SampleRate > 1 {
		opts.SampleRate = 0.01
	}

	s := &Sink{
		db: db, log: log,
		records:       make(chan Record, opts.Buffer),
		sampleRate:    opts.SampleRate,
		batchSize:     opts.BatchSize,
		flushInterval: opts.FlushInterval,
		stop:          make(chan struct{}),
		stopped:       make(chan struct{}),
	}
	go s.run()
	return s, nil
}

// ShouldRecord reports whether a decision is recorded at the given level.
func (s *Sink) ShouldRecord(level Level, allowed bool) bool {
	switch level {
	case LevelOff:
		return false
	case LevelAll:
		return true
	case LevelDenies:
		return !allowed
	case LevelSampled:
		if !allowed {
			return true
		}
		return s.sample()
	default:
		// An unrecognised level records denials. Erring toward recording less than
		// asked would silently lose the decisions someone configured the log for.
		return !allowed
	}
}

func (s *Sink) sample() bool {
	// crypto/rand rather than math/rand: this is not security-critical, but a sink
	// seeded identically across replicas would sample the same decisions on each,
	// which is a strange and hard-to-spot bias in the data.
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return false
	}
	return float64(n.Int64())/1_000_000 < s.sampleRate
}

// Record queues a decision. It never blocks: if the buffer is full the record is
// dropped and counted.
func (s *Sink) Record(r Record) {
	if r.OccurredAt.IsZero() {
		r.OccurredAt = time.Now().UTC()
	}
	s.stats.Accepted.Add(1)

	select {
	case s.records <- r:
	default:
		s.stats.Dropped.Add(1)
	}
}

// Stats returns the current counters.
func (s *Sink) Stats() *Stats { return &s.stats }

// Close drains what is queued and stops the writer.
func (s *Sink) Close(ctx context.Context) error {
	s.stopOnce.Do(func() { close(s.stop) })
	select {
	case <-s.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Sink) run() {
	defer close(s.stopped)

	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	batch := make([]Record, 0, s.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.write(batch)
		batch = batch[:0]
	}

	for {
		select {
		case r := <-s.records:
			batch = append(batch, r)
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.stop:
			// Drain what is already queued before stopping, so a clean shutdown does
			// not throw away the last second of decisions.
			for {
				select {
				case r := <-s.records:
					batch = append(batch, r)
					if len(batch) >= s.batchSize {
						flush()
					}
					continue
				default:
				}
				break
			}
			flush()
			return
		}
	}
}

func (s *Sink) write(batch []Record) {
	// A bounded context of its own: the writer must not inherit a request's deadline,
	// and must not hang on a database that has stopped answering.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := s.db.InSystem(ctx, "writing decision log records", func(ctx context.Context, tx pgx.Tx) error {
		rows := make([][]any, 0, len(batch))
		for i := range batch {
			r := &batch[i]
			id, err := newID()
			if err != nil {
				return err
			}
			rows = append(rows, []any{
				id, r.TenantID, r.OccurredAt, r.SubjectID, nullIfEmpty(r.ApplicationID),
				r.Permission, nullIfEmpty(r.ResourceRef), r.Allowed, r.Reason,
				nullIfEmpty(r.MatchedGrant), int32(r.Latency.Microseconds()),
				r.Degraded, r.Revision,
			})
		}
		_, err := tx.CopyFrom(ctx,
			pgx.Identifier{"decision_event"},
			[]string{"id", "tenant_id", "occurred_at", "subject_id", "application_id",
				"permission_key", "resource_ref", "allowed", "reason", "matched_grant",
				"latency_us", "degraded", "revision"},
			pgx.CopyFromRows(rows))
		return err
	})
	if err != nil {
		s.stats.Failed.Add(int64(len(batch)))
		// Logged, not retried. A retry loop against a database that is refusing
		// writes is how a logging path becomes the thing that takes the service down.
		s.log.Error("dropping decision log records", "count", len(batch), "error", err)
		return
	}
	s.stats.Written.Add(int64(len(batch)))
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func newID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "dec_" + base64.RawURLEncoding.EncodeToString(b), nil
}
