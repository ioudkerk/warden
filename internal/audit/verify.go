package audit

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/store/db"
)

// VerifyResult reports the state of the chain.
type VerifyResult struct {
	Entries int
	First   time.Time
	Last    time.Time
	// Problems is empty when the chain is intact. Each entry names the first place
	// the recomputed hash stopped matching, which is where tampering begins — every
	// entry after it will also fail, so only the first is worth acting on.
	Problems []Problem
}

// Problem is one break in the chain.
type Problem struct {
	Seq    int64
	ID     string
	Detail string
}

func (p Problem) String() string { return fmt.Sprintf("seq %d (%s): %s", p.Seq, p.ID, p.Detail) }

// OK reports whether the chain verified.
func (r VerifyResult) OK() bool { return len(r.Problems) == 0 }

// Verify recomputes the whole chain and reports where, if anywhere, it breaks.
//
// A hash chain that nobody recomputes is decoration: it detects nothing until someone
// looks. This is what `warden audit verify` runs, and what a scheduled job should run
// so that "looks" is not a thing a human has to remember to do.
//
// It reads the entire log in sequence order, so it must run on the system pool: the
// chain spans tenants, and a connection that could see only some entries would
// compute a different chain and report tampering that had not happened.
func Verify(ctx context.Context, tx pgx.Tx) (VerifyResult, error) {
	rows, err := db.New(tx).AuditEventsInOrder(ctx)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("reading the audit log: %w", err)
	}

	var (
		result   VerifyResult
		expected []byte // the hash the next entry must claim as its predecessor
	)

	for i := range rows {
		r := &rows[i]
		// seq is an identity column and NOT NULL in the database; sqlc does not
		// infer that from GENERATED ALWAYS AS IDENTITY, so it arrives as a pointer
		// that is never nil.
		var seq int64
		if r.Seq != nil {
			seq = *r.Seq
		}
		id, action := r.ID, r.Action
		occurredAt := r.OccurredAt
		before, after := r.Before, r.After
		prevHash, storedHash := r.PrevHash, r.Hash

		if result.Entries == 0 {
			result.First = occurredAt
		}
		result.Last = occurredAt
		result.Entries++

		// The recorded predecessor must be the hash of the entry that actually
		// precedes it. This is what catches a deletion: remove an entry and the next
		// one's prev_hash points at something no longer there.
		if !bytesEqual(prevHash, expected) {
			result.Problems = append(result.Problems, Problem{
				Seq: seq, ID: id,
				Detail: fmt.Sprintf("recorded predecessor %s, but the preceding entry hashes to %s "+
					"— an entry was removed, reordered, or inserted here",
					hexOrNone(prevHash), hexOrNone(expected)),
			})
		}

		recomputed := chainHash(prevHash, canonical(id, occurredAt, Entry{
			TenantID:       deref(r.TenantID),
			Action:         action,
			TargetType:     deref(r.TargetType),
			TargetID:       deref(r.TargetID),
			ActorUserID:    deref(r.ActorUserID),
			ActorClientID:  deref(r.ActorClientID),
			ImpersonatorID: deref(r.ImpersonatorID),
			Reason:         deref(r.Reason),
			IP:             deref(r.Ip),
			UserAgent:      deref(r.UserAgent),
			RequestID:      deref(r.RequestID),
		}, before, after))

		// And the entry's own hash must match its content. This is what catches an
		// edit: change any field and the recomputation diverges.
		if !bytesEqual(recomputed, storedHash) {
			result.Problems = append(result.Problems, Problem{
				Seq: seq, ID: id,
				Detail: "the entry's content does not match its recorded hash — it was altered after it was written",
			})
		}

		expected = storedHash
	}
	return result, nil
}

// ErrTampered is returned by VerifyOrError when the chain does not verify.
var ErrTampered = errors.New("the audit log does not verify")

// VerifyOrError is Verify with the result turned into an error, for a caller that
// wants a non-zero exit rather than a report.
func VerifyOrError(ctx context.Context, tx pgx.Tx) (VerifyResult, error) {
	result, err := Verify(ctx, tx)
	if err != nil {
		return result, err
	}
	if !result.OK() {
		return result, fmt.Errorf("%w: %s", ErrTampered, result.Problems[0])
	}
	return result, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hexOrNone(b []byte) string {
	if len(b) == 0 {
		return "(none)"
	}
	return hex.EncodeToString(b[:8]) + "…"
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
