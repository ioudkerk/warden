package authn_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/authn"
)

// Emailed links (M1-9's exit condition: single use, fifteen minutes, hashed at rest).
//
// Each of those three is a property that fails silently if it is wrong — the flow works, a
// person signs in, and the guarantee is simply absent. So each is asserted against the
// database rather than against the code that wrote it.

// TestALinkWorksOnce is the single-use rule.
func TestALinkWorksOnce(t *testing.T) {
	f := newMFAFixture(t)
	ctx := context.Background()

	link, err := f.authn.IssueLink(ctx, authn.LinkRequest{
		Kind: authn.LinkMagic, TenantID: f.tenantID, UserID: f.userID,
		Address: f.mariaEmail, TenantName: "ACME",
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	token := tokenFromLink(t, link)

	redeemed, err := f.authn.RedeemLink(ctx, authn.LinkMagic, token)
	if err != nil {
		t.Fatalf("the first redemption: %v", err)
	}
	if redeemed.UserID != f.userID {
		t.Fatalf("resolved to %s, want %s", redeemed.UserID, f.userID)
	}

	if _, err := f.authn.RedeemLink(ctx, authn.LinkMagic, token); !errors.Is(err, authn.ErrInvalidLink) {
		t.Fatalf("the second redemption = %v; a link that works twice is a credential "+
			"sitting in a mailbox for as long as the mailbox lasts", err)
	}
}

// TestTwoRequestsRacingWithOneLink is the same rule where it actually matters.
//
// A person clicks twice, or a mail client prefetches the URL while they are reading. Both
// requests see an unconsumed row; exactly one may win.
//
// Two things hold it, and measuring which was worth doing: the UPDATE carries
// `consumed_at IS NULL` in its WHERE clause, and the transaction runs at SERIALIZABLE.
// **Either alone is sufficient** — removing one leaves this test passing. Removing both
// lets three of these eight redemptions succeed, which is what the guard is worth. The
// comment says that rather than implying the test covers each.
func TestTwoRequestsRacingWithOneLink(t *testing.T) {
	f := newMFAFixture(t)
	ctx := context.Background()

	link, err := f.authn.IssueLink(ctx, authn.LinkRequest{
		Kind: authn.LinkMagic, TenantID: f.tenantID, UserID: f.userID,
		Address: f.mariaEmail, TenantName: "ACME",
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	token := tokenFromLink(t, link)

	const racers = 8
	var (
		wg       sync.WaitGroup
		release  = make(chan struct{})
		mu       sync.Mutex
		accepted int
	)
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			if _, err := f.authn.RedeemLink(ctx, authn.LinkMagic, token); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	close(release)
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("%d of %d simultaneous redemptions succeeded; one link is one sign-in",
			accepted, racers)
	}
}

// TestALinkIsHashedAtRest. The token is in the message and nowhere else: a copy of the
// database must not let anybody sign in as anybody.
func TestALinkIsHashedAtRest(t *testing.T) {
	f := newMFAFixture(t)
	ctx := context.Background()

	link, err := f.authn.IssueLink(ctx, authn.LinkRequest{
		Kind: authn.LinkPasswordReset, TenantID: f.tenantID, UserID: f.userID,
		Address: f.mariaEmail, TenantName: "ACME",
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	token := tokenFromLink(t, link)

	conn, err := pgx.Connect(ctx, dsnFromEnv(t))
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck // teardown

	// Nowhere in the row.
	var found int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM link_token WHERE encode(token_hash,'escape') LIKE '%' || $1 || '%'`,
		token).Scan(&found); err != nil {
		t.Fatalf("querying: %v", err)
	}
	if found != 0 {
		t.Fatal("the token is recoverable from link_token; a database copy would be a set " +
			"of working sign-in links")
	}

	// And the queued message carries it only sealed.
	var payload string
	if err := conn.QueryRow(ctx,
		`SELECT payload::text FROM outbound_email WHERE to_address = $1 ORDER BY created_at DESC LIMIT 1`,
		f.mariaEmail).Scan(&payload); err != nil {
		t.Fatalf("reading the queue: %v", err)
	}
	if strings.Contains(payload, token) {
		t.Fatalf("the queued payload carries the token in the clear: %s", payload)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("the payload is not JSON: %s", payload)
	}
	if decoded["token"] == nil {
		t.Fatal("the queued payload carries no sealed token, so the message could never " +
			"be rendered with a link")
	}
}

// TestTheMessageGreetsTheTenantByName. A caller that leaves the name out gets the tenant's
// own name, not its identifier — which is what the first live run of this flow produced,
// and what a real person would have read: "Sign in to ten_acme".
func TestTheMessageGreetsTheTenantByName(t *testing.T) {
	f := newMFAFixture(t)
	ctx := context.Background()

	if _, err := f.authn.IssueLink(ctx, authn.LinkRequest{
		Kind: authn.LinkMagic, TenantID: f.tenantID, UserID: f.userID, Address: f.mariaEmail,
	}); err != nil {
		t.Fatalf("issuing: %v", err)
	}

	conn, err := pgx.Connect(ctx, dsnFromEnv(t))
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck // teardown

	var want string
	if err := conn.QueryRow(ctx, `SELECT name FROM tenant WHERE id = $1`, f.tenantID).Scan(&want); err != nil {
		t.Fatalf("reading the tenant: %v", err)
	}

	var payload string
	if err := conn.QueryRow(ctx,
		`SELECT payload::text FROM outbound_email WHERE to_address = $1 ORDER BY created_at DESC LIMIT 1`,
		f.mariaEmail).Scan(&payload); err != nil {
		t.Fatalf("reading the queue: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("the payload is not JSON: %s", payload)
	}
	if got := decoded["tenant_name"]; got != want {
		t.Fatalf("tenant_name = %v, want %q. The subject line of every emailed message is "+
			"built from this", got, want)
	}
}

// TestRedeemingInvalidatesTheOthers is §8's rule: two live reset links is one more than
// anyone needs, and the extra one is usually an older message still in a mailbox.
func TestRedeemingInvalidatesTheOthers(t *testing.T) {
	f := newMFAFixture(t)
	ctx := context.Background()

	issue := func() string {
		link, err := f.authn.IssueLink(ctx, authn.LinkRequest{
			Kind: authn.LinkPasswordReset, TenantID: f.tenantID, UserID: f.userID,
			Address: f.mariaEmail, TenantName: "ACME",
		})
		if err != nil {
			t.Fatalf("issuing: %v", err)
		}
		return tokenFromLink(t, link)
	}

	first, second := issue(), issue()

	if _, err := f.authn.RedeemLink(ctx, authn.LinkPasswordReset, second); err != nil {
		t.Fatalf("redeeming the newest: %v", err)
	}
	if _, err := f.authn.RedeemLink(ctx, authn.LinkPasswordReset, first); !errors.Is(err, authn.ErrInvalidLink) {
		t.Fatalf("the older link still works (%v); redeeming one must retire the rest", err)
	}
}

// TestALinkCannotBeUsedAtAnotherEndpoint.
//
// A reset link and a magic link are both valid tokens for the same user. Without checking
// the kind, the one with the weaker consequence — "prove you read this mailbox" — would let
// somebody take the stronger action.
func TestALinkCannotBeUsedAtAnotherEndpoint(t *testing.T) {
	f := newMFAFixture(t)
	ctx := context.Background()

	link, err := f.authn.IssueLink(ctx, authn.LinkRequest{
		Kind: authn.LinkVerifyEmail, TenantID: f.tenantID, UserID: f.userID,
		Address: f.mariaEmail, TenantName: "ACME",
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	token := tokenFromLink(t, link)

	if _, err := f.authn.RedeemLink(ctx, authn.LinkMagic, token); !errors.Is(err, authn.ErrInvalidLink) {
		t.Fatalf("a verification link signed somebody in (%v)", err)
	}
	// And it still works for what it is.
	if _, err := f.authn.RedeemLink(ctx, authn.LinkVerifyEmail, token); err != nil {
		t.Fatalf("the link no longer works at its own endpoint: %v", err)
	}
}

// TestAnUnknownLinkIsRefused.
func TestAnUnknownLinkIsRefused(t *testing.T) {
	f := newMFAFixture(t)
	for name, token := range map[string]string{
		"empty":     "",
		"nonsense":  "not-a-token",
		"plausible": strings.Repeat("A", 43),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.authn.RedeemLink(context.Background(), authn.LinkMagic, token); !errors.Is(
				err, authn.ErrInvalidLink) {
				t.Fatalf("= %v; want the generic refusal", err)
			}
		})
	}
}

// tokenFromLink pulls the token out of the URL the issuer returned.
func tokenFromLink(t *testing.T, link string) string {
	t.Helper()
	_, token, ok := strings.Cut(link, "token=")
	if !ok || token == "" {
		t.Fatalf("no token in %q", link)
	}
	return token
}
