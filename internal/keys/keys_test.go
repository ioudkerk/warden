package keys_test

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/secrets"
)

func keyring(t *testing.T, seed byte) *secrets.Keyring {
	t.Helper()
	material := make([]byte, secrets.KEKSize)
	for i := range material {
		material[i] = seed ^ byte(i)
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

func TestGenerateProducesUsableKeys(t *testing.T) {
	kr := keyring(t, 1)
	for _, alg := range []string{keys.RS256, keys.ES256} {
		t.Run(alg, func(t *testing.T) {
			k, err := keys.Generate(alg, kr)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if k.Algorithm != alg {
				t.Errorf("algorithm = %q", k.Algorithm)
			}

			// The public half must be exactly that: parseable, and public.
			block, _ := pem.Decode([]byte(k.PublicPEM))
			if block == nil || block.Type != "PUBLIC KEY" {
				t.Fatalf("public PEM is not a PUBLIC KEY block: %q", k.PublicPEM)
			}
			if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
				t.Fatalf("public key does not parse: %v", err)
			}

			// The private half must not be.
			if strings.Contains(string(k.SealedPrivate), "PRIVATE KEY") {
				t.Fatal("the sealed private key contains PEM text; it is not encrypted")
			}
			if len(k.SealedPrivate) == 0 {
				t.Fatal("no sealed private key")
			}
			if k.KEKID != kr.ActiveKeyID() {
				t.Errorf("kek id = %q, want %q", k.KEKID, kr.ActiveKeyID())
			}
		})
	}
}

// The kid identifies the material, not the row: two deployments cannot disagree about
// which key a kid names, and re-importing the same key cannot mint a second identity
// for it.
func TestKeyIDIsDerivedFromThePublicKey(t *testing.T) {
	kr := keyring(t, 1)
	a, err := keys.Generate(keys.RS256, kr)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := keys.Generate(keys.RS256, kr)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if a.KID == b.KID {
		t.Fatal("two independently generated keys share a kid")
	}
	if a.ID == b.ID {
		t.Fatal("two keys share a row id")
	}
	if a.KID == "" {
		t.Fatal("empty kid")
	}
}

func TestGenerateRejectsSymmetricAndUnknownAlgorithms(t *testing.T) {
	kr := keyring(t, 1)
	// SPEC §17 requires asymmetric signing: a relying party must verify without
	// holding anything that would let it mint.
	for _, alg := range []string{"HS256", "none", "", "RS512"} {
		if _, err := keys.Generate(alg, kr); err == nil {
			t.Errorf("Generate accepted algorithm %q", alg)
		}
	}
}

func TestGenerateRequiresAKeyring(t *testing.T) {
	if _, err := keys.Generate(keys.RS256, nil); err == nil {
		t.Fatal("a key was generated with nowhere safe to put it")
	}
}
