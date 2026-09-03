package provision_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/provision"
	"github.com/warden-project/warden/internal/secrets"
)

func testKeyring(t *testing.T) *secrets.Keyring {
	t.Helper()
	material := make([]byte, secrets.KEKSize)
	for i := range material {
		material[i] = byte(i * 3)
	}
	kek, err := secrets.NewKEKFromBytes(material)
	if err != nil {
		t.Fatalf("NewKEKFromBytes: %v", err)
	}
	kr, err := secrets.NewKeyring(kek)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

// bootstrapFixture is a migrated but uninitialised database.
func bootstrapFixture(t *testing.T) fixture {
	t.Helper()
	f := setupBare(t)
	return f
}

func TestBootstrapCreatesTheDeployment(t *testing.T) {
	f := bootstrapFixture(t)
	ctx := context.Background()

	result, err := f.p.Bootstrap(ctx, "owner@example.com", "https://warden.example.com",
		keys.RS256, testKeyring(t))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if result.TenantID != provision.SystemTenantID {
		t.Errorf("tenant = %q", result.TenantID)
	}

	// The owner exists but cannot yet do anything: 'invited', not 'active'. An owner
	// who never redeems the setup URL is inert rather than an account with no
	// credential.
	var status, email string
	if err := f.conn.QueryRow(ctx,
		`SELECT status, email FROM app_user WHERE id = $1`, result.OwnerID).Scan(&status, &email); err != nil {
		t.Fatalf("reading the owner: %v", err)
	}
	if status != "invited" {
		t.Errorf("owner status = %q, want invited", status)
	}
	if email != "owner@example.com" {
		t.Errorf("owner email = %q", email)
	}

	var role string
	if err := f.conn.QueryRow(ctx, `
		SELECT r.key FROM grant_ g JOIN role r ON r.id = g.role_id
		 WHERE g.subject_user_id = $1`, result.OwnerID).Scan(&role); err != nil {
		t.Fatalf("reading the owner's grant: %v", err)
	}
	if role != "system.owner" {
		t.Errorf("owner role = %q, want system.owner", role)
	}
}

// The exit condition for M0-9: exactly one usable one-time URL.
func TestBootstrapPrintsOneUsableSetupURL(t *testing.T) {
	f := bootstrapFixture(t)
	ctx := context.Background()

	result, err := f.p.Bootstrap(ctx, "owner@example.com", "https://warden.example.com",
		keys.RS256, testKeyring(t))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	parsed, err := url.Parse(result.SetupURL)
	if err != nil {
		t.Fatalf("the setup URL does not parse: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host != "warden.example.com" {
		t.Errorf("the setup URL is not rooted at the issuer: %s", result.SetupURL)
	}
	token := parsed.Query().Get("token")
	if token == "" {
		t.Fatal("the setup URL carries no token")
	}

	// Exactly one, and stored only as a hash.
	var count int
	if err := f.conn.QueryRow(ctx, `SELECT count(*) FROM setup_token`).Scan(&count); err != nil {
		t.Fatalf("counting setup tokens: %v", err)
	}
	if count != 1 {
		t.Fatalf("bootstrap produced %d setup tokens, want exactly 1", count)
	}

	var storedHash []byte
	var expiresAt time.Time
	if err := f.conn.QueryRow(ctx,
		`SELECT token_hash, expires_at FROM setup_token`).Scan(&storedHash, &expiresAt); err != nil {
		t.Fatalf("reading the setup token: %v", err)
	}

	sum := sha256.Sum256([]byte(token))
	if string(storedHash) != string(sum[:]) {
		t.Error("the stored hash is not the hash of the printed token")
	}

	// The token itself must be nowhere in the database.
	var leaked int
	if err := f.conn.QueryRow(ctx,
		`SELECT count(*) FROM setup_token WHERE encode(token_hash,'escape') LIKE '%' || $1 || '%'`,
		token).Scan(&leaked); err != nil {
		t.Fatalf("scanning for the token: %v", err)
	}
	if leaked != 0 {
		t.Error("the setup token was stored in the clear")
	}

	// Short-lived. A setup link valid for a week is a password with extra steps.
	if lifetime := time.Until(expiresAt); lifetime > time.Hour {
		t.Errorf("the setup token is valid for %s; that is too long for a one-time link", lifetime)
	}
}

// Two tokens from two deployments must not be related. If they were, knowing one
// would be a step toward the other.
func TestSetupTokensAreUnpredictable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		f := bootstrapFixture(t)
		result, err := f.p.Bootstrap(context.Background(), "owner@example.com",
			"https://warden.example.com", keys.RS256, testKeyring(t))
		if err != nil {
			t.Fatalf("Bootstrap: %v", err)
		}
		token := mustToken(t, result.SetupURL)
		if seen[token] {
			t.Fatal("two deployments produced the same setup token")
		}
		seen[token] = true
		// 32 bytes base64url, plus the wst_ prefix.
		if len(token) < 40 {
			t.Errorf("the setup token is only %d characters", len(token))
		}
	}
}

// Running init twice would mint a fresh setup URL for an existing owner — a password
// reset with no authentication in front of it.
func TestBootstrapRefusesToRunTwice(t *testing.T) {
	f := bootstrapFixture(t)
	ctx := context.Background()

	if _, err := f.p.Bootstrap(ctx, "owner@example.com", "https://warden.example.com",
		keys.RS256, testKeyring(t)); err != nil {
		t.Fatalf("the first Bootstrap failed: %v", err)
	}

	_, err := f.p.Bootstrap(ctx, "attacker@example.com", "https://warden.example.com",
		keys.RS256, testKeyring(t))
	if !errors.Is(err, provision.ErrAlreadyInitialised) {
		t.Fatalf("expected ErrAlreadyInitialised, got %v", err)
	}

	// And nothing from the second attempt landed.
	var tokens, users int
	if err := f.conn.QueryRow(ctx,
		`SELECT (SELECT count(*) FROM setup_token), (SELECT count(*) FROM app_user WHERE tenant_id = $1)`,
		provision.SystemTenantID).Scan(&tokens, &users); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if tokens != 1 {
		t.Errorf("%d setup tokens after a refused second init", tokens)
	}
	if users != 1 {
		t.Errorf("%d system users after a refused second init", users)
	}
}

// The signing key's private half is envelope-encrypted, so a copy of the database
// without the KEK cannot mint tokens for anybody.
func TestTheSigningKeyIsSealedUnderTheKEK(t *testing.T) {
	f := bootstrapFixture(t)
	ctx := context.Background()
	kr := testKeyring(t)

	if _, err := f.p.Bootstrap(ctx, "owner@example.com", "https://warden.example.com",
		keys.RS256, kr); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	var sealed []byte
	var publicPEM, kekID string
	if err := f.conn.QueryRow(ctx,
		`SELECT private_key, public_key, kek_id FROM signing_key WHERE status = 'active'`).
		Scan(&sealed, &publicPEM, &kekID); err != nil {
		t.Fatalf("reading the signing key: %v", err)
	}

	if strings.Contains(string(sealed), "PRIVATE KEY") {
		t.Fatal("the private key is stored as PEM text, unencrypted")
	}
	if kekID != kr.ActiveKeyID() {
		t.Errorf("kek_id = %q, want %q", kekID, kr.ActiveKeyID())
	}

	// The public half is stored in the clear, as it should be.
	block, _ := pem.Decode([]byte(publicPEM))
	if block == nil {
		t.Fatal("the public key is not PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Fatalf("the public key does not parse: %v", err)
	}

	// With the right keyring it opens; with a different one it does not.
	tx, err := f.conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:errcheck // read-only

	kid, privateDER, alg, err := keys.Active(ctx, tx, kr)
	if err != nil {
		t.Fatalf("opening the active key: %v", err)
	}
	if kid == "" || alg != keys.RS256 {
		t.Errorf("kid=%q alg=%q", kid, alg)
	}
	if _, err := x509.ParsePKCS8PrivateKey(privateDER); err != nil {
		t.Fatalf("the opened private key does not parse: %v", err)
	}

	other := make([]byte, secrets.KEKSize)
	for i := range other {
		other[i] = byte(255 - i)
	}
	otherKEK, _ := secrets.NewKEKFromBytes(other) //nolint:errcheck // fixed valid length
	otherRing, _ := secrets.NewKeyring(otherKEK)  //nolint:errcheck // valid key
	if _, _, _, err := keys.Active(ctx, tx, otherRing); err == nil {
		t.Fatal("the signing key opened under a different KEK")
	}
}

func TestBootstrapRejectsABadOwnerAddress(t *testing.T) {
	f := bootstrapFixture(t)
	for _, email := range []string{"", "not-an-address", "@example.com"} {
		if _, err := f.p.Bootstrap(context.Background(), email,
			"https://warden.example.com", keys.RS256, testKeyring(t)); err == nil {
			t.Errorf("Bootstrap accepted owner address %q", email)
		}
	}
}

func TestBootstrapRequiresAKeyring(t *testing.T) {
	f := bootstrapFixture(t)
	if _, err := f.p.Bootstrap(context.Background(), "owner@example.com",
		"https://warden.example.com", keys.RS256, nil); err == nil {
		t.Fatal("bootstrapped with nowhere to seal the signing key")
	}
}

// The deployment's first audit entry describes the bootstrap and records neither the
// setup token nor the private key.
func TestBootstrapIsAudited(t *testing.T) {
	f := bootstrapFixture(t)
	ctx := context.Background()

	result, err := f.p.Bootstrap(ctx, "owner@example.com", "https://warden.example.com",
		keys.RS256, testKeyring(t))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	var action, after string
	if err := f.conn.QueryRow(ctx,
		`SELECT action, after::text FROM audit_event WHERE action = 'deployment.initialised'`).
		Scan(&action, &after); err != nil {
		t.Fatalf("reading the audit entry: %v", err)
	}
	if !strings.Contains(after, "owner@example.com") {
		t.Errorf("the entry should record who was made owner: %s", after)
	}
	if strings.Contains(after, mustToken(t, result.SetupURL)) {
		t.Error("the audit entry recorded the setup token")
	}
	if strings.Contains(after, "PRIVATE KEY") {
		t.Error("the audit entry recorded key material")
	}
}

func mustToken(t *testing.T, setupURL string) string {
	t.Helper()
	parsed, err := url.Parse(setupURL)
	if err != nil {
		t.Fatalf("parsing the setup URL: %v", err)
	}
	return parsed.Query().Get("token")
}
