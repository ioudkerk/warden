// Package audit writes and verifies the administrative audit log (SPEC §16.1).
//
// The log is append-only and hash-chained. Each entry's hash covers the previous
// entry's hash and a canonical encoding of its own content, so altering or removing
// any entry breaks verification of every entry after it. Someone with database access
// can still delete rows; what they cannot do is delete them without leaving evidence.
package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Entry is one administrative mutation.
type Entry struct {
	// TenantID is empty for a deployment-level action belonging to no tenant.
	TenantID string
	// Action names what happened, in the past tense and dotted:
	// "role.granted", "tenant.created", "service_account.created".
	Action     string
	TargetType string
	TargetID   string

	ActorUserID    string
	ActorClientID  string
	ImpersonatorID string

	// Before and After describe the change. Anything secret must be redacted before
	// it gets here: an audit log holding a client secret has become a second copy of
	// the credential store, with weaker access controls and longer retention.
	Before any
	After  any

	Reason    string
	IP        string
	UserAgent string
	RequestID string
}

// auditChainLockKey identifies the advisory lock that serialises appends. Its value
// is arbitrary; that every appender uses the same one is not.
const auditChainLockKey int64 = 0x7761_7264_656e_0001 // "warden" + 1

// Writer appends entries to the log.
//
// It takes a pgx.Tx rather than a pool, deliberately: an audit entry is written in
// the same transaction as the change it describes. Writing it separately would allow
// a change that committed with no record, or a record of a change that rolled back,
// and both are worse than no log at all.
type Writer struct{}

// NewWriter returns a writer.
func NewWriter() *Writer { return &Writer{} }

// Append writes one entry, chained to the current head.
//
// The read of the previous hash and the insert happen in one transaction, and the
// read takes a lock, so two concurrent appends cannot both chain to the same
// predecessor and leave a fork.
func (w *Writer) Append(ctx context.Context, tx pgx.Tx, e Entry) (string, error) {
	if e.Action == "" {
		return "", errors.New("an audit entry needs an action")
	}

	// Serialise appenders. Two transactions that both read the same head would write
	// two entries claiming the same predecessor, and verification reports that as
	// tampering forever after — a self-inflicted false positive in the one place
	// where a false positive is most expensive.
	//
	// A row lock is not enough. `FOR UPDATE` on an empty table locks nothing, so the
	// first writers to an empty log all see no head and all chain to nil; and under
	// READ COMMITTED a blocked reader re-checks the row it already chose rather than
	// re-running the query, so it can still miss a newly inserted head. An advisory
	// lock has neither problem: it exists independently of any row and is held for
	// the transaction.
	//
	// The constant is arbitrary but fixed; every appender must use the same one.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditChainLockKey); err != nil {
		return "", fmt.Errorf("locking the audit chain: %w", err)
	}

	var prevHash []byte
	err := tx.QueryRow(ctx, `
		SELECT hash FROM audit_event ORDER BY seq DESC LIMIT 1`).Scan(&prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("reading the audit chain head: %w", err)
	}

	id, err := newID()
	if err != nil {
		return "", err
	}
	// Truncated to microseconds because that is the resolution PostgreSQL stores.
	// Hashing nanoseconds and storing microseconds makes every entry fail its own
	// verification — which is precisely the bug the verifier caught on first run.
	occurredAt := time.Now().UTC().Truncate(time.Microsecond)

	before, err := marshalOrNil(e.Before)
	if err != nil {
		return "", fmt.Errorf("encoding the before state: %w", err)
	}
	after, err := marshalOrNil(e.After)
	if err != nil {
		return "", fmt.Errorf("encoding the after state: %w", err)
	}

	hash := chainHash(prevHash, canonical(id, occurredAt, e, before, after))

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_event (
			id, tenant_id, occurred_at, actor_user_id, actor_client_id, impersonator_id,
			action, target_type, target_id, before, after, reason, ip, user_agent,
			request_id, prev_hash, hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		id, nullIfEmpty(e.TenantID), occurredAt,
		nullIfEmpty(e.ActorUserID), nullIfEmpty(e.ActorClientID), nullIfEmpty(e.ImpersonatorID),
		e.Action, nullIfEmpty(e.TargetType), nullIfEmpty(e.TargetID),
		before, after, nullIfEmpty(e.Reason), nullIfEmpty(e.IP), nullIfEmpty(e.UserAgent),
		nullIfEmpty(e.RequestID), prevHash, hash)
	if err != nil {
		return "", fmt.Errorf("appending to the audit log: %w", err)
	}
	return id, nil
}

// canonical produces the bytes an entry's hash is taken over.
//
// It must be deterministic and unambiguous. Length-prefixing every field is what
// makes it unambiguous: without it, an entry with action "a" and target "bc" would
// hash identically to one with action "ab" and target "c", and an attacker able to
// choose those strings could substitute one entry for another without breaking the
// chain.
func canonical(id string, occurredAt time.Time, e Entry, before, after []byte) []byte {
	var buf []byte
	add := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		buf = append(buf, n[:]...)
		buf = append(buf, b...)
	}
	addString := func(s string) { add([]byte(s)) }

	addString(id)
	addString(occurredAt.UTC().Format(time.RFC3339Nano))
	addString(e.TenantID)
	addString(e.ActorUserID)
	addString(e.ActorClientID)
	addString(e.ImpersonatorID)
	addString(e.Action)
	addString(e.TargetType)
	addString(e.TargetID)
	add(before)
	add(after)
	addString(e.Reason)
	addString(e.IP)
	addString(e.UserAgent)
	addString(e.RequestID)
	return buf
}

func chainHash(prevHash, content []byte) []byte {
	h := sha256.New()
	h.Write(prevHash) // nil for the first entry, which is the genesis case
	h.Write(content)
	return h.Sum(nil)
}

func marshalOrNil(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
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
	return "aud_" + base64.RawURLEncoding.EncodeToString(b), nil
}
