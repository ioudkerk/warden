package audit

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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
	rows, err := tx.Query(ctx, `
		SELECT seq, id, tenant_id, occurred_at, actor_user_id, actor_client_id,
		       impersonator_id, action, target_type, target_id, before, after,
		       reason, ip, user_agent, request_id, prev_hash, hash
		  FROM audit_event ORDER BY seq`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("reading the audit log: %w", err)
	}
	defer rows.Close()

	var (
		result   VerifyResult
		expected []byte // the hash the next entry must claim as its predecessor
	)

	for rows.Next() {
		var (
			seq                                 int64
			id, action                          string
			tenantID, actorUser, actorClient    *string
			impersonator, targetType, targetID  *string
			reason, ip, userAgent, requestID    *string
			before, after, prevHash, storedHash []byte
			occurredAt                          time.Time
		)
		if err := rows.Scan(&seq, &id, &tenantID, &occurredAt, &actorUser, &actorClient,
			&impersonator, &action, &targetType, &targetID, &before, &after,
			&reason, &ip, &userAgent, &requestID, &prevHash, &storedHash); err != nil {
			return VerifyResult{}, err
		}

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
			TenantID:       deref(tenantID),
			Action:         action,
			TargetType:     deref(targetType),
			TargetID:       deref(targetID),
			ActorUserID:    deref(actorUser),
			ActorClientID:  deref(actorClient),
			ImpersonatorID: deref(impersonator),
			Reason:         deref(reason),
			IP:             deref(ip),
			UserAgent:      deref(userAgent),
			RequestID:      deref(requestID),
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
	if err := rows.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("reading the audit log: %w", err)
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
