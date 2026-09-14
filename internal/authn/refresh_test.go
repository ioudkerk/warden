package authn_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/authn"
)

// refreshFixture is the session fixture plus a refresh-token store and a live session
// to hang tokens off.
type refreshFixture struct {
	*sessionFixture
	tokens  *authn.RefreshTokens
	session *authn.Session
}

func newRefreshFixture(t *testing.T) *refreshFixture {
	t.Helper()
	return newRefreshFixtureWithLifetimes(t, 30*24*time.Hour, 7*24*time.Hour)
}

func newRefreshFixtureWithLifetimes(t *testing.T, absolute, idle time.Duration) *refreshFixture {
	t.Helper()
	f := newSessionFixture(t)

	tokens, err := authn.NewRefreshTokens(f.tenantPool, f.systemPool, f.sessions,
		authn.RefreshTokenOptions{
			AbsoluteLifetime: absolute,
			IdleLifetime:     idle,
			Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
			Audit:            audit.NewWriter(),
		})
	if err != nil {
		t.Fatalf("NewRefreshTokens: %v", err)
	}

	session, err := f.sessions.Create(context.Background(), f.tenantID, f.maria,
		[]string{"pwd"}, "203.0.113.5", "laptop")
	if err != nil {
		t.Fatalf("creating a session: %v", err)
	}
	return &refreshFixture{sessionFixture: f, tokens: tokens, session: session}
}

// issue starts a family for the fixture's session.
func (f *refreshFixture) issue(t *testing.T) *authn.RefreshToken {
	t.Helper()
	token, err := f.tokens.Issue(context.Background(), f.tenantID, f.session.ID, f.maria, "billing-web")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return token
}

// securityEvents reads the audit log for a given action.
func (f *refreshFixture) securityEvents(t *testing.T, action string) []map[string]any {
	t.Helper()
	ctx := context.Background()
	conn := connect(ctx, t)
	defer conn.Close(ctx) //nolint:errcheck // teardown

	rows, err := conn.Query(ctx,
		`SELECT target_id, reason, after FROM audit_event WHERE action = $1 ORDER BY occurred_at`, action)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var targetID, reason string
		var after map[string]any
		if scanErr := rows.Scan(&targetID, &reason, &after); scanErr != nil {
			t.Fatalf("scanning: %v", scanErr)
		}
		after["target_id"], after["reason"] = targetID, reason
		out = append(out, after)
	}
	return out
}

func TestARefreshTokenRotatesIntoItsSuccessor(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	first := f.issue(t)
	if len(first.Token) < 40 {
		t.Fatalf("token is %d characters; SPEC §8.3 wants 256 bits of entropy", len(first.Token))
	}

	second, err := f.tokens.Rotate(ctx, first.Token, "billing-web")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if second.Token == first.Token {
		t.Fatal("rotation returned the same token, so it did not rotate")
	}
	if second.FamilyID != first.FamilyID {
		t.Fatalf("the successor is in family %s; it must stay in %s or reuse detection "+
			"cannot connect them", second.FamilyID, first.FamilyID)
	}
	if second.SessionID != first.SessionID || second.UserID != f.maria {
		t.Fatalf("the successor changed session or subject: %+v", second)
	}

	// The chain continues.
	third, err := f.tokens.Rotate(ctx, second.Token, "billing-web")
	if err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	if third.FamilyID != first.FamilyID {
		t.Fatal("the family changed on the second rotation")
	}
}

// TestReplayingARotatedTokenKillsTheFamily is M1-5's exit condition.
func TestReplayingARotatedTokenKillsTheFamily(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	// A chain three deep, so the test proves the *whole* family dies rather than just
	// the token that was replayed and its immediate successor.
	first := f.issue(t)
	second, err := f.tokens.Rotate(ctx, first.Token, "billing-web")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	third, err := f.tokens.Rotate(ctx, second.Token, "billing-web")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// The thief replays the first token, which was consumed two rotations ago.
	_, err = f.tokens.Rotate(ctx, first.Token, "billing-web")
	if !errors.Is(err, authn.ErrTokenReuse) {
		t.Fatalf("replaying a consumed token returned %v; want ErrTokenReuse", err)
	}
	if !errors.Is(err, authn.ErrInvalidRefreshToken) {
		t.Fatal("ErrTokenReuse must wrap ErrInvalidRefreshToken, so a caller that only " +
			"cares about the outcome can treat them alike")
	}

	// Every token in the family is now dead, including the one the legitimate client
	// still holds. That is the intended outcome: Warden cannot tell which party is
	// legitimate, so both start again.
	for name, token := range map[string]*authn.RefreshToken{
		"the replayed token": first,
		"its successor":      second,
		"the live token":     third,
	} {
		t.Run(name, func(t *testing.T) {
			if _, rotateErr := f.tokens.Rotate(ctx, token.Token, "billing-web"); !errors.Is(rotateErr, authn.ErrInvalidRefreshToken) {
				t.Fatalf("%s still rotates after the family was revoked: %v", name, rotateErr)
			}
		})
	}

	// Exactly one alarm, however many times the dead family is presented afterwards.
	// The subtests above replayed two more consumed tokens; those are recorded under
	// the repeat action, not this one.
	events := f.securityEvents(t, authn.ActionRefreshTokenReuse)
	if len(events) != 1 {
		t.Fatalf("the audit log holds %d %s events; want exactly 1 — an alert keyed on this "+
			"action must fire once per incident, not once per retry",
			len(events), authn.ActionRefreshTokenReuse)
	}
	event := events[0]
	if already, ok := event["already_revoked"].(bool); !ok || already {
		t.Fatalf("the first detection is marked already_revoked=%v; it is the alarm", event["already_revoked"])
	}
	if event["target_id"] != f.maria {
		t.Fatalf("the event names %v; want the affected user %s", event["target_id"], f.maria)
	}
	if event["family_id"] != first.FamilyID {
		t.Fatalf("the event names family %v; want %s", event["family_id"], first.FamilyID)
	}
	if event["session_id"] != f.session.ID {
		t.Fatalf("the event names session %v; want %s", event["session_id"], f.session.ID)
	}
	if revoked, ok := event["tokens_revoked"].(float64); !ok || int(revoked) != 3 {
		t.Fatalf("the event reports %v tokens revoked; the family held 3", event["tokens_revoked"])
	}

	// And the later presentations are recorded rather than dropped. Somebody hammering
	// a stolen token must not look like silence.
	repeats := f.securityEvents(t, authn.ActionRefreshTokenReuseRepeat)
	if len(repeats) != 2 {
		t.Fatalf("the audit log holds %d %s events; the two consumed tokens replayed after "+
			"the family died should each have been recorded",
			len(repeats), authn.ActionRefreshTokenReuseRepeat)
	}
	for _, repeat := range repeats {
		if already, ok := repeat["already_revoked"].(bool); !ok || !already {
			t.Fatalf("a repeat is marked already_revoked=%v", repeat["already_revoked"])
		}
		if repeat["family_id"] != first.FamilyID {
			t.Fatalf("a repeat names family %v; want %s", repeat["family_id"], first.FamilyID)
		}
	}
}

// TestAReplayAgainstADeadFamilyIsStillRecorded is the property that ordering revocation
// ahead of reuse used to destroy: once the family was revoked, further presentations of
// its consumed tokens were indistinguishable from an ordinary expired-token refusal, so
// somebody retrying a stolen token for an hour left no trace at all.
func TestAReplayAgainstADeadFamilyIsStillRecorded(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	first := f.issue(t)
	if _, err := f.tokens.Rotate(ctx, first.Token, "billing-web"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// The first replay: the alarm.
	if _, err := f.tokens.Rotate(ctx, first.Token, "billing-web"); !errors.Is(err, authn.ErrTokenReuse) {
		t.Fatalf("first replay returned %v; want ErrTokenReuse", err)
	}

	// Somebody keeps trying. Every attempt is refused, and every attempt is recorded.
	const retries = 5
	for i := 0; i < retries; i++ {
		if _, err := f.tokens.Rotate(ctx, first.Token, "billing-web"); !errors.Is(err, authn.ErrInvalidRefreshToken) {
			t.Fatalf("retry %d returned %v; want a refusal", i, err)
		}
	}

	if alarms := f.securityEvents(t, authn.ActionRefreshTokenReuse); len(alarms) != 1 {
		t.Fatalf("%d alarms for one incident; an alert on this action would page per retry", len(alarms))
	}
	repeats := f.securityEvents(t, authn.ActionRefreshTokenReuseRepeat)
	if len(repeats) != retries {
		t.Fatalf("%d of %d retries were recorded; a stolen token being hammered must not "+
			"look like silence", len(repeats), retries)
	}
}

// TestACollateralTokenIsRefusedQuietly is the other half of the distinction. The token
// the legitimate client still held when the family died is not evidence of anything,
// and recording it would bury the presentations that are.
func TestACollateralTokenIsRefusedQuietly(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	first := f.issue(t)
	live, err := f.tokens.Rotate(ctx, first.Token, "billing-web")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, replayErr := f.tokens.Rotate(ctx, first.Token, "billing-web"); !errors.Is(replayErr, authn.ErrTokenReuse) {
		t.Fatalf("replay returned %v; want ErrTokenReuse", replayErr)
	}

	before := len(f.securityEvents(t, authn.ActionRefreshTokenReuseRepeat))

	// The legitimate client presents the token it was last given. It was never
	// consumed — it was revoked as collateral.
	_, collateralErr := f.tokens.Rotate(ctx, live.Token, "billing-web")
	if !errors.Is(collateralErr, authn.ErrInvalidRefreshToken) {
		t.Fatalf("the collateral token returned %v; want a refusal", collateralErr)
	}
	if errors.Is(collateralErr, authn.ErrTokenReuse) {
		t.Fatal("the legitimate client's own token was reported as a replay")
	}

	if after := len(f.securityEvents(t, authn.ActionRefreshTokenReuseRepeat)); after != before {
		t.Fatalf("presenting a revoked-but-never-consumed token wrote %d security events; "+
			"it is collateral damage, not evidence", after-before)
	}
}

// TestReuseEndsTheSessionToo is containment. Somebody who has the refresh token very
// probably has the session cookie as well, so revoking the family without ending the
// session leaves the thief signed in.
func TestReuseEndsTheSessionToo(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	first := f.issue(t)
	if _, err := f.tokens.Rotate(ctx, first.Token, "billing-web"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, err := f.sessions.Validate(ctx, f.session.ID); err != nil {
		t.Fatalf("the session was not valid before the replay: %v", err)
	}

	if _, err := f.tokens.Rotate(ctx, first.Token, "billing-web"); !errors.Is(err, authn.ErrTokenReuse) {
		t.Fatalf("replay returned %v; want ErrTokenReuse", err)
	}

	if _, err := f.sessions.Validate(ctx, f.session.ID); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("the session survived a detected refresh token theft (%v); a thief holding "+
			"the refresh token almost certainly holds the session cookie too", err)
	}
}

// TestOnlyTheReusedFamilyDies keeps detection from becoming a denial of service: one
// compromised chain must not sign the user out of their other devices.
func TestOnlyTheReusedFamilyDies(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	// A second session with its own family, as a second device would have.
	other, err := f.sessions.Create(ctx, f.tenantID, f.maria, []string{"pwd"}, "", "phone")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	otherToken, err := f.tokens.Issue(ctx, f.tenantID, other.ID, f.maria, "billing-web")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	compromised := f.issue(t)
	if _, err := f.tokens.Rotate(ctx, compromised.Token, "billing-web"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, err := f.tokens.Rotate(ctx, compromised.Token, "billing-web"); !errors.Is(err, authn.ErrTokenReuse) {
		t.Fatalf("replay returned %v; want ErrTokenReuse", err)
	}

	// The other device is untouched.
	if _, err := f.tokens.Rotate(ctx, otherToken.Token, "billing-web"); err != nil {
		t.Fatalf("an unrelated family was revoked by another family's reuse: %v", err)
	}
	if _, err := f.sessions.Validate(ctx, other.ID); err != nil {
		t.Fatalf("an unrelated session was ended by another family's reuse: %v", err)
	}
}

// TestAnUnknownTokenIsRefusedWithoutASecurityEvent separates "never existed" from
// "already used". Only the second means somebody has a credential they should not, and
// an alert that fires on every stale client is an alert nobody reads.
func TestAnUnknownTokenIsRefusedWithoutASecurityEvent(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	for name, token := range map[string]string{
		"empty":      "",
		"whitespace": "   ",
		"unknown":    "wrt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.tokens.Rotate(ctx, token, "billing-web")
			if !errors.Is(err, authn.ErrInvalidRefreshToken) {
				t.Fatalf("got %v; want ErrInvalidRefreshToken", err)
			}
			if errors.Is(err, authn.ErrTokenReuse) {
				t.Fatal("an unknown token was reported as reuse, which would raise a security " +
					"event every time a client presented a stale value")
			}
		})
	}

	if events := f.securityEvents(t, "security.refresh_token_reuse"); len(events) != 0 {
		t.Fatalf("%d security events were raised by tokens that never existed", len(events))
	}
}

// TestRevokingASessionKillsItsRefreshTokens is what stops a refresh token being a way
// back in after signing out.
func TestRevokingASessionKillsItsRefreshTokens(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	token := f.issue(t)
	if err := f.sessions.Revoke(ctx, f.tenantID, f.session.ID, "the user signed out"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Rotation refuses because the session is gone, whether or not anything revoked
	// the token itself.
	if _, err := f.tokens.Rotate(ctx, token.Token, "billing-web"); !errors.Is(err, authn.ErrInvalidRefreshToken) {
		t.Fatalf("a refresh token outlived its session: %v", err)
	}

	// And the explicit sweep does mark them, for the record and for the purge.
	revoked, err := f.tokens.RevokeForSession(ctx, f.tenantID, f.session.ID)
	if err != nil {
		t.Fatalf("RevokeForSession: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("revoked %d tokens for the session; want 1", revoked)
	}
}

// TestATokenIssuedToOneClientIsNotAcceptedFromAnother covers the client binding.
func TestATokenIssuedToOneClientIsNotAcceptedFromAnother(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	token := f.issue(t) // issued to billing-web

	if _, err := f.tokens.Rotate(ctx, token.Token, "some-other-client"); !errors.Is(err, authn.ErrInvalidRefreshToken) {
		t.Fatalf("a token issued to one client rotated for another: %v", err)
	}
	// And it was not burned by the attempt, so a misconfigured client cannot log a
	// user out by guessing its own id wrong.
	if _, err := f.tokens.Rotate(ctx, token.Token, "billing-web"); err != nil {
		t.Fatalf("the rightful client could not rotate after a mismatched attempt: %v", err)
	}
}

// TestTheAbsoluteLifetimeBoundsTheWholeChain is what stops rotation extending a
// login indefinitely: each successor is capped by the family's start, not its own.
func TestTheAbsoluteLifetimeBoundsTheWholeChain(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixtureWithLifetimes(t, 6*time.Hour, 2*time.Hour)

	now := time.Now().UTC()
	f.tokens.SetClock(func() time.Time { return now })
	f.sessions.SetClock(func() time.Time { return now })

	token := f.issue(t)
	if got := token.ExpiresAt.Sub(now); got > 2*time.Hour+time.Minute {
		t.Fatalf("the first token expires in %s; the idle lifetime is 2h", got)
	}

	// Rotated every hour, so the idle window never lapses.
	for elapsed := time.Hour; elapsed <= 5*time.Hour; elapsed += time.Hour {
		now = now.Add(time.Hour)
		next, err := f.tokens.Rotate(ctx, token.Token, "billing-web")
		if err != nil {
			t.Fatalf("rotation at %s failed: %v", elapsed, err)
		}
		token = next
	}

	// The last successor must be capped by the family's six-hour ceiling rather than
	// given a fresh two-hour window.
	if token.ExpiresAt.After(now.Add(2 * time.Hour)) {
		t.Fatalf("a successor issued at +5h expires at %s, beyond the family's ceiling; "+
			"rotation is extending the chain forever", token.ExpiresAt)
	}

	// Past the ceiling, rotation refuses.
	now = now.Add(2 * time.Hour)
	if _, err := f.tokens.Rotate(ctx, token.Token, "billing-web"); !errors.Is(err, authn.ErrInvalidRefreshToken) {
		t.Fatalf("a chain outlived its absolute lifetime: %v", err)
	}
}

// TestAnIdleChainExpires covers the other bound.
func TestAnIdleChainExpires(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixtureWithLifetimes(t, 30*24*time.Hour, time.Hour)

	now := time.Now().UTC()
	f.tokens.SetClock(func() time.Time { return now })

	token := f.issue(t)
	now = now.Add(time.Hour + time.Minute)

	if _, err := f.tokens.Rotate(ctx, token.Token, "billing-web"); !errors.Is(err, authn.ErrInvalidRefreshToken) {
		t.Fatalf("a token unused for longer than the idle lifetime still rotated: %v", err)
	}
}

// TestConcurrentRotationsOfOneTokenElectOneWinner is the race SERIALIZABLE is for.
//
// Two simultaneous presentations of the same token must not both succeed. If they did,
// the chain would silently fork — two live tokens in one family, neither aware of the
// other — which is precisely the state reuse detection exists to notice, reached
// without noticing it.
func TestConcurrentRotationsOfOneTokenElectOneWinner(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	token := f.issue(t)

	const attempts = 4
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners []*authn.RefreshToken
		reuses  int
		invalid int
		other   []error
	)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			rotated, err := f.tokens.Rotate(ctx, token.Token, "billing-web")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners = append(winners, rotated)
			case errors.Is(err, authn.ErrTokenReuse):
				reuses++
			case errors.Is(err, authn.ErrInvalidRefreshToken):
				invalid++
			default:
				other = append(other, err)
			}
		}()
	}
	wg.Wait()

	if len(other) > 0 {
		t.Fatalf("unexpected errors from concurrent rotation: %v", other)
	}
	if len(winners) != 1 {
		t.Fatalf("%d of %d concurrent rotations succeeded; exactly one must, or the chain "+
			"has forked into %d live tokens that know nothing of each other",
			len(winners), attempts, len(winners))
	}

	// At least one loser is read as a replay, which is what kills the family. The rest
	// get a plain refusal rather than raising the alarm again: whichever loser lands
	// first revokes the family, and the ones behind it find it already revoked. That
	// is the anti-flood ordering — one theft, one security event — and it is why this
	// does not assert reuses == attempts-1.
	if reuses < 1 {
		t.Fatalf("no loser was detected as a replay; the family would survive a forked chain")
	}
	if winners := len(winners); winners+reuses+invalid != attempts {
		t.Fatalf("outcomes do not add up: %d winners + %d reuses + %d invalid != %d",
			winners, reuses, invalid, attempts)
	}

	// However the losers were classified, the family is dead — including the successor
	// the winner was handed.
	if _, err := f.tokens.Rotate(ctx, winners[0].Token, "billing-web"); !errors.Is(err, authn.ErrInvalidRefreshToken) {
		t.Fatalf("the winner's successor still rotates after a replay was detected: %v", err)
	}
	if events := f.securityEvents(t, "security.refresh_token_reuse"); len(events) < 1 {
		t.Fatal("a forked chain produced no security event")
	}
}

// TestOnlyTheHashIsStored is the property that makes a database copy useless for
// refreshing anybody's session.
func TestOnlyTheHashIsStored(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	token := f.issue(t)

	conn := connect(ctx, t)
	defer conn.Close(ctx) //nolint:errcheck // teardown

	rows, err := conn.Query(ctx, `SELECT id, encode(token_hash, 'hex'), octet_length(token_hash) FROM refresh_token`)
	if err != nil {
		t.Fatalf("reading refresh tokens: %v", err)
	}
	defer rows.Close()

	found := 0
	for rows.Next() {
		var id, stored string
		var length int
		if scanErr := rows.Scan(&id, &stored, &length); scanErr != nil {
			t.Fatalf("scanning: %v", scanErr)
		}
		found++
		if length != 32 {
			t.Fatalf("token %s is stored as %d bytes; want a 32-byte SHA-256", id, length)
		}
		if stored == token.Token || len(stored) == 0 {
			t.Fatalf("token %s appears to be stored in the clear", id)
		}
	}
	if found == 0 {
		t.Fatal("no refresh token rows were written")
	}
}

// TestRotationSurvivesTheRetryLoop guards the convention M0-7 recorded: values
// generated inside a retried transaction differ between attempts. A token minted
// inside the callback would be handed to the caller while the database recorded a
// different one on the winning attempt.
func TestRotationSurvivesTheRetryLoop(t *testing.T) {
	ctx := context.Background()
	f := newRefreshFixture(t)

	token := f.issue(t)
	rotated, err := f.tokens.Rotate(ctx, token.Token, "billing-web")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	// The token handed back must be the one the database can resolve. If minting moved
	// inside the transaction and a retry occurred, these would diverge.
	conn := connect(ctx, t)
	defer conn.Close(ctx) //nolint:errcheck // teardown

	var stored string
	if scanErr := conn.QueryRow(ctx,
		`SELECT id FROM refresh_token WHERE token_hash = sha256($1::bytea)`,
		[]byte(rotated.Token)).Scan(&stored); scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			t.Fatal("the token returned to the caller does not exist in the database")
		}
		t.Fatalf("looking the token up: %v", scanErr)
	}
	if stored != rotated.ID {
		t.Fatalf("the returned token resolves to %s; the caller was told %s", stored, rotated.ID)
	}
}
