package secrets_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/warden-project/warden/internal/secrets"
)

func keyring(t *testing.T, seeds ...byte) *secrets.Keyring {
	t.Helper()
	if len(seeds) == 0 {
		seeds = []byte{1}
	}
	keks := make([]secrets.KEK, 0, len(seeds))
	for _, seed := range seeds {
		k := make([]byte, secrets.KEKSize)
		for i := range k {
			k[i] = seed ^ byte(i)
		}
		kek, err := secrets.NewKEKFromBytes(k)
		if err != nil {
			t.Fatalf("NewKEKFromBytes: %v", err)
		}
		keks = append(keks, kek)
	}
	kr, err := secrets.NewKeyring(keks[0], keks[1:]...)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

func TestEnvelopeRoundTrip(t *testing.T) {
	kr := keyring(t)
	aad := []byte("ten_01HZW0ACME/idp_connection/client_secret")

	for _, plaintext := range []string{"", "s", "client-secret", strings.Repeat("long secret ", 1000)} {
		sealed, err := kr.Encrypt([]byte(plaintext), aad)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		opened, err := kr.Decrypt(sealed, aad)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(opened) != plaintext {
			t.Fatal("round trip changed the value")
		}
	}
}

// Checked separately from the round trip, and only with a plaintext long enough that
// a coincidental byte sequence in the ciphertext is not a plausible explanation — a
// one-byte needle matches random ciphertext most of the time.
func TestEnvelopeDoesNotEmbedPlaintext(t *testing.T) {
	kr := keyring(t)
	plaintext := []byte("a distinctive plaintext that must not appear in the output")
	sealed, err := kr.Encrypt(plaintext, []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("plaintext is visible in the ciphertext")
	}
}

// A fresh DEK and nonce per call means the same plaintext must never produce the same
// ciphertext — otherwise equal values are linkable across rows.
func TestEnvelopeIsNotDeterministic(t *testing.T) {
	kr := keyring(t)
	a, err := kr.Encrypt([]byte("same"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := kr.Encrypt([]byte("same"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("encrypting the same plaintext twice produced identical ciphertext")
	}
}

// The aad binds a ciphertext to its location. Moving a row's value into another row
// must fail to decrypt.
func TestEnvelopeRejectsMismatchedAAD(t *testing.T) {
	kr := keyring(t)
	sealed, err := kr.Encrypt([]byte("tenant A secret"), []byte("tenant:A"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := kr.Decrypt(sealed, []byte("tenant:B")); err == nil {
		t.Fatal("decrypting with a different aad must fail")
	}
	if _, err := kr.Decrypt(sealed, nil); err == nil {
		t.Fatal("decrypting with no aad must fail")
	}
}

func TestEnvelopeRejectsTampering(t *testing.T) {
	kr := keyring(t)
	sealed, err := kr.Encrypt([]byte("do not modify"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip one bit at every offset in turn; every position must fail authentication.
	for i := range sealed {
		corrupted := bytes.Clone(sealed)
		corrupted[i] ^= 0x01
		if _, err := kr.Decrypt(corrupted, []byte("aad")); err == nil {
			t.Fatalf("a flipped bit at offset %d was accepted", i)
		}
	}

	for _, truncateTo := range []int{0, 1, 2, 10, len(sealed) - 1} {
		if _, err := kr.Decrypt(sealed[:truncateTo], []byte("aad")); err == nil {
			t.Fatalf("truncation to %d bytes was accepted", truncateTo)
		}
	}
}

func TestEnvelopeRejectsForeignKey(t *testing.T) {
	writer := keyring(t, 1)
	reader := keyring(t, 2)

	sealed, err := writer.Encrypt([]byte("secret"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = reader.Decrypt(sealed, nil)
	if !errors.Is(err, secrets.ErrKeyUnknown) {
		t.Fatalf("expected ErrKeyUnknown, got %v", err)
	}
	if !strings.Contains(err.Error(), writer.ActiveKeyID()) {
		t.Fatal("the error should name the key id, so an operator knows which key to restore")
	}
}

// Rotation: values written under the old key stay readable, new values are written
// under the new one. SPEC §17, "key rotation supported".
func TestEnvelopeKeyRotation(t *testing.T) {
	old := keyring(t, 1)
	sealedUnderOld, err := old.Encrypt([]byte("written before rotation"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// After rotation the new key is active and the old one is retained for reads.
	rotated := keyring(t, 2, 1)

	opened, err := rotated.Decrypt(sealedUnderOld, []byte("aad"))
	if err != nil {
		t.Fatalf("a rotated keyring must still read values written under the retired key: %v", err)
	}
	if string(opened) != "written before rotation" {
		t.Fatal("value changed across rotation")
	}

	sealedUnderNew, err := rotated.Encrypt([]byte("written after rotation"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	newID, err := secrets.KeyIDOf(sealedUnderNew)
	if err != nil {
		t.Fatalf("KeyIDOf: %v", err)
	}
	if newID != rotated.ActiveKeyID() {
		t.Fatal("new values must be written under the active key")
	}
	oldID, err := secrets.KeyIDOf(sealedUnderOld)
	if err != nil {
		t.Fatalf("KeyIDOf: %v", err)
	}
	if oldID == newID {
		t.Fatal("rotation did not change the active key")
	}

	// The retired key alone can no longer read the new values.
	if _, err := old.Decrypt(sealedUnderNew, []byte("aad")); !errors.Is(err, secrets.ErrKeyUnknown) {
		t.Fatalf("expected ErrKeyUnknown from the retired keyring, got %v", err)
	}
}

func TestKeyIDOfDoesNotDecrypt(t *testing.T) {
	kr := keyring(t)
	sealed, err := kr.Encrypt([]byte("secret"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	id, err := secrets.KeyIDOf(sealed)
	if err != nil {
		t.Fatalf("KeyIDOf: %v", err)
	}
	if id != kr.ActiveKeyID() {
		t.Fatalf("KeyIDOf returned %q, want %q", id, kr.ActiveKeyID())
	}
	if _, err := secrets.KeyIDOf([]byte{0x02, 0x00}); err == nil {
		t.Fatal("an unknown envelope version should be rejected")
	}
}

func TestStringHelpersRoundTrip(t *testing.T) {
	kr := keyring(t)
	encoded, err := kr.EncryptString("client-secret", []byte("aad"))
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}
	got, err := kr.DecryptString(encoded, []byte("aad"))
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}
	if got != "client-secret" {
		t.Fatalf("round trip returned %q", got)
	}
	if _, err := kr.DecryptString("not base64!!", []byte("aad")); err == nil {
		t.Fatal("invalid base64 should be rejected")
	}
}

func TestNewKeyringRejectsBadInput(t *testing.T) {
	if _, err := secrets.NewKeyring(secrets.KEK{}); !errors.Is(err, secrets.ErrKEKNotConfigured) {
		t.Fatalf("an unset active key should be ErrKEKNotConfigured, got %v", err)
	}
	kek, err := secrets.NewKEKFromBytes(testKeyBytes())
	if err != nil {
		t.Fatalf("NewKEKFromBytes: %v", err)
	}
	if _, err := secrets.NewKeyring(kek, kek); err == nil {
		t.Fatal("listing the same key twice should be rejected")
	}
	if _, err := secrets.NewKeyring(kek, secrets.KEK{}); err == nil {
		t.Fatal("an empty retired key should be rejected")
	}
}
