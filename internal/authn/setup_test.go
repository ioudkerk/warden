package authn_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/provision"
	"github.com/warden-project/warden/internal/secrets"
)

// bootstrap runs the real `warden init` path and returns the token out of the printed
// URL, which is the only place it exists — the database holds a hash.
func bootstrap(t *testing.T, f *fixture) (token, ownerID string) {
	t.Helper()
	ctx := context.Background()

	material := make([]byte, secrets.KEKSize)
	for i := range material {
		material[i] = byte(i * 3)
	}
	kek, err := secrets.NewKEKFromBytes(material)
	if err != nil {
		t.Fatalf("NewKEKFromBytes: %v", err)
	}
	keyring, err := secrets.NewKeyring(kek)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}

	result, err := f.p.Bootstrap(ctx, "owner@example.com", "https://warden.example.com",
		keys.ES256, 90*24*time.Hour, keyring)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	parsed, err := url.Parse(result.SetupURL)
	if err != nil {
		t.Fatalf("parsing the setup URL %q: %v", result.SetupURL, err)
	}
	token = parsed.Query().Get("token")
	if token == "" {
		t.Fatalf("the setup URL %q carries no token parameter", result.SetupURL)
	}
	return token, result.OwnerID
}

// TestRedeemingASetupTokenCompletesTheBootstrap is the other half of SPEC §20.2.
// `warden init` deliberately creates an owner with no credential; until this path
// exists, that owner can never log in and the deployment cannot be handed over.
func TestRedeemingASetupTokenCompletesTheBootstrap(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	token, ownerID := bootstrap(t, f)

	tenantID, userID, err := f.a.RedeemSetupToken(ctx, token, goodPassword)
	if err != nil {
		t.Fatalf("RedeemSetupToken: %v", err)
	}
	if userID != ownerID {
		t.Fatalf("redeemed as %s; want the owner %s", userID, ownerID)
	}
	if tenantID != provision.SystemTenantID {
		t.Fatalf("redeemed into tenant %s; want %s", tenantID, provision.SystemTenantID)
	}

	// The owner can now log in, which is the point.
	result, err := f.a.Authenticate(ctx, tenantID, "owner@example.com", goodPassword)
	if err != nil {
		t.Fatalf("the owner could not log in after redeeming the setup link: %v", err)
	}
	if result.UserID != ownerID {
		t.Fatalf("logged in as %s; want %s", result.UserID, ownerID)
	}
}

// TestRedemptionActivatesTheUser covers the lifecycle transition. Before redemption the
// account is 'invited' and every decision denies; a correct password on an invited
// account is still a refusal, so activation has to happen or the credential is useless.
func TestRedemptionActivatesTheUser(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	token, ownerID := bootstrap(t, f)

	conn := connect(ctx, t)
	defer conn.Close(ctx) //nolint:errcheck // teardown

	var status string
	if err := conn.QueryRow(ctx, `SELECT status FROM app_user WHERE id=$1`, ownerID).Scan(&status); err != nil {
		t.Fatalf("reading the owner's status: %v", err)
	}
	if status != "invited" {
		t.Fatalf("the owner starts as %q; `warden init` is meant to leave them invited "+
			"with no credential (SPEC §20.2)", status)
	}

	if _, _, err := f.a.RedeemSetupToken(ctx, token, goodPassword); err != nil {
		t.Fatalf("RedeemSetupToken: %v", err)
	}

	if err := conn.QueryRow(ctx, `SELECT status FROM app_user WHERE id=$1`, ownerID).Scan(&status); err != nil {
		t.Fatalf("re-reading the owner's status: %v", err)
	}
	if status != "active" {
		t.Fatalf("after redemption the owner is %q; want active", status)
	}
}

// TestASetupTokenIsSingleUse is the property that makes the link safe to email.
func TestASetupTokenIsSingleUse(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	token, _ := bootstrap(t, f)

	if _, _, err := f.a.RedeemSetupToken(ctx, token, goodPassword); err != nil {
		t.Fatalf("the first redemption failed: %v", err)
	}

	_, _, err := f.a.RedeemSetupToken(ctx, token, "an attacker's chosen password!")
	if !errors.Is(err, authn.ErrInvalidSetupToken) {
		t.Fatalf("replaying a consumed setup link returned %v; want ErrInvalidSetupToken. "+
			"A reusable setup link is a password reset with no authentication in front of it", err)
	}

	// And the original password still works, so the replay changed nothing.
	if _, authErr := f.a.Authenticate(ctx, provision.SystemTenantID,
		"owner@example.com", goodPassword); authErr != nil {
		t.Fatalf("the replay disturbed the credential set by the first redemption: %v", authErr)
	}
}

// TestConcurrentRedemptionsElectOneWinner is the race the single-statement consume
// exists for: two clicks on the same emailed link, arriving together.
func TestConcurrentRedemptionsElectOneWinner(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	token, _ := bootstrap(t, f)

	const attempts = 4
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		other     []error
	)
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_, _, err := f.a.RedeemSetupToken(ctx, token, goodPassword)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, authn.ErrInvalidSetupToken):
				// Lost the race, which is the designed outcome.
			default:
				other = append(other, err)
			}
		}()
	}
	wg.Wait()

	if len(other) > 0 {
		t.Fatalf("unexpected errors from concurrent redemption: %v", other)
	}
	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent redemptions succeeded; exactly one must, or the last "+
			"writer silently overwrites the password the user thinks they set", succeeded, attempts)
	}
}

// TestARejectedPasswordLeavesTheLinkUsable matters more than it looks: burning a
// one-time bootstrap link because the password was too short would leave a fresh
// deployment with no way in at all.
func TestARejectedPasswordLeavesTheLinkUsable(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	token, _ := bootstrap(t, f)

	if _, _, err := f.a.RedeemSetupToken(ctx, token, "short"); err == nil {
		t.Fatal("a password below the policy was accepted")
	}
	if _, _, err := f.a.RedeemSetupToken(ctx, token, "passwordpassword"); err == nil {
		t.Fatal("a breached password was accepted")
	}

	// The link survived both refusals.
	if _, _, err := f.a.RedeemSetupToken(ctx, token, goodPassword); err != nil {
		t.Fatalf("a link refused for a weak password could not then be redeemed with a good "+
			"one: %v. That would make a bad first guess an unrecoverable bootstrap", err)
	}
}

func TestAnUnknownOrExpiredSetupTokenIsRefused(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	token, ownerID := bootstrap(t, f)

	for name, candidate := range map[string]string{
		"empty":        "",
		"whitespace":   "   ",
		"unknown":      "clearly-not-a-real-token",
		"near miss":    token[:len(token)-1] + "x",
		"with padding": " " + token + " ",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := f.a.RedeemSetupToken(ctx, candidate, goodPassword)
			if name == "with padding" {
				// Surrounding whitespace is what happens when a link is copied out of
				// an email client, and it should work rather than be a mystery.
				if err != nil {
					t.Fatalf("a token with surrounding whitespace was refused: %v", err)
				}
				return
			}
			if !errors.Is(err, authn.ErrInvalidSetupToken) {
				t.Fatalf("got %v; want ErrInvalidSetupToken", err)
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		// A fresh deployment, since the one above has been redeemed.
		conn := connect(ctx, t)
		defer conn.Close(ctx) //nolint:errcheck // teardown
		if _, err := conn.Exec(ctx,
			`UPDATE setup_token SET consumed_at=NULL, expires_at=now() - interval '1 hour'
			  WHERE user_id=$1`, ownerID); err != nil {
			t.Fatalf("expiring the token: %v", err)
		}
		_, _, err := f.a.RedeemSetupToken(ctx, token, goodPassword)
		if !errors.Is(err, authn.ErrInvalidSetupToken) {
			t.Fatalf("an expired setup link returned %v; want ErrInvalidSetupToken", err)
		}
	})
}

// TestRedemptionInvalidatesOtherOutstandingLinks implements docs/design-email.md §8:
// two live setup links is one more than anyone needs.
func TestRedemptionInvalidatesOtherOutstandingLinks(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	token, ownerID := bootstrap(t, f)

	conn := connect(ctx, t)
	defer conn.Close(ctx) //nolint:errcheck // teardown

	// A second outstanding link for the same owner, as a re-issued invitation would
	// produce.
	if _, err := conn.Exec(ctx,
		`INSERT INTO setup_token (id, tenant_id, user_id, token_hash, expires_at)
		 VALUES ('stk_second', $1, $2, sha256('a second link'::bytea), now() + interval '1 hour')`,
		provision.SystemTenantID, ownerID); err != nil {
		t.Fatalf("creating a second setup token: %v", err)
	}

	if _, _, err := f.a.RedeemSetupToken(ctx, token, goodPassword); err != nil {
		t.Fatalf("RedeemSetupToken: %v", err)
	}

	var consumed *string
	if err := conn.QueryRow(ctx,
		`SELECT consumed_at::text FROM setup_token WHERE id='stk_second'`).Scan(&consumed); err != nil {
		t.Fatalf("reading the second token: %v", err)
	}
	if consumed == nil {
		t.Fatal("redeeming one setup link left another outstanding for the same user")
	}
}

// TestTheSetupTokenIsNotRecoverableFromTheDatabase is the property that makes printing
// it once acceptable.
func TestTheSetupTokenIsNotRecoverableFromTheDatabase(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	token, _ := bootstrap(t, f)

	conn := connect(ctx, t)
	defer conn.Close(ctx) //nolint:errcheck // teardown

	rows, err := conn.Query(ctx, `SELECT id, encode(token_hash,'hex') FROM setup_token`)
	if err != nil {
		t.Fatalf("reading setup tokens: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, stored string
		if scanErr := rows.Scan(&id, &stored); scanErr != nil {
			t.Fatalf("scanning: %v", scanErr)
		}
		if strings.Contains(stored, token) || stored == token {
			t.Fatalf("setup token %s is stored in a form that contains the token itself", id)
		}
	}
}

func connect(ctx context.Context, t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsnFromEnv(t))
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	return conn
}
