package authn_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/authn/authntest"
	"github.com/warden-project/warden/internal/cache"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
)

// mfaFixture is the credential fixture plus the two things a second factor needs: a keyring
// to seal a TOTP secret, and a cache to hold a WebAuthn challenge between two requests.
type mfaFixture struct {
	*fixture
	authn    *authn.Authenticator
	userID   string
	tenantID string
}

func newMFAFixture(t *testing.T) *mfaFixture {
	t.Helper()
	base := newFixture(t)

	// A KEK the test owns. The value does not matter; what matters is that the TOTP
	// secrets these tests store are sealed the way production seals them, rather than
	// through a path that only exists in tests.
	material := make([]byte, secrets.KEKSize)
	for i := range material {
		material[i] = byte(i*7 + 1)
	}
	kek, err := secrets.NewKEKFromBytes(material)
	if err != nil {
		t.Fatalf("KEK: %v", err)
	}
	keyring, err := secrets.NewKeyring(kek)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}

	inProcess := config.Defaults()
	inProcess.Environment = config.EnvDevelopment
	inProcess.Cache.Backend = config.CacheInProcess
	cacheClient, err := cache.Open(context.Background(), inProcess)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	t.Cleanup(func() { _ = cacheClient.Close() }) //nolint:errcheck // teardown

	params := authn.DefaultParams()
	params.Memory, params.Time = 8*1024, 1

	a, err := authn.New(base.tenantPool, base.systemPool, authn.Options{
		Params:  params,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Audit:   audit.NewWriter(),
		Keyring: keyring,
		Cache:   cacheClient,
		Issuer:  "https://warden.example.com",
		WebAuthn: authn.WebAuthnOptions{
			RPDisplayName: "Warden", RPID: testRPID, Origins: []string{testOrigin},
		},
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	return &mfaFixture{fixture: base, authn: a, userID: base.maria, tenantID: base.tenantID}
}

// enrolKey registers a virtual security key and returns it.
func (f *mfaFixture) enrolKey(t *testing.T) *authntest.Authenticator {
	t.Helper()
	ctx := context.Background()
	key := authntest.New(t)

	challenge, err := f.authn.BeginWebAuthnRegistration(ctx, f.tenantID, f.userID, "maria@acme.test")
	if err != nil {
		t.Fatalf("beginning registration: %v", err)
	}
	response := key.Register(t, authntest.ChallengeFrom(t, challenge.Options), testOrigin, testRPID)
	if err := f.authn.FinishWebAuthnRegistration(
		ctx, f.tenantID, f.userID, challenge.SessionID, "Test key", response); err != nil {
		t.Fatalf("finishing registration: %v", err)
	}
	return key
}
