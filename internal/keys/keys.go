// Package keys generates and stores the keys Warden signs tokens with.
//
// Token signing is asymmetric, always (SPEC §17): a relying party must be able to
// verify without holding anything that would let it mint. The public half is
// published through JWKS; the private half is envelope-encrypted under the
// deployment's KEK, so a copy of the database without that key cannot issue tokens
// for anybody.
package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/store/db"

	"github.com/warden-project/warden/internal/secrets"
)

// Supported algorithms. SPEC §8.2 makes RS256 the default and ES256 selectable;
// symmetric algorithms are deliberately absent.
const (
	RS256 = "RS256"
	ES256 = "ES256"
)

// rsaBits is the modulus size for RS256. 2048 is the floor every JWT library
// accepts; 3072 buys margin at a signing cost that is irrelevant next to a database
// round trip.
const rsaBits = 3072

// Key is a generated keypair, with the private half already sealed.
type Key struct {
	ID        string
	KID       string
	Algorithm string
	// PublicPEM is published. It is not a secret and is stored as text.
	PublicPEM string
	// SealedPrivate is envelope ciphertext; only a holder of the KEK can open it.
	SealedPrivate []byte
	KEKID         string
	CreatedAt     time.Time
}

// Generate creates a keypair and seals the private half under the keyring's active
// key.
//
// The additional data binds the ciphertext to this key's identity, so a sealed
// private key cannot be moved onto a different row and thereby be served under a
// different kid.
func Generate(algorithm string, keyring *secrets.Keyring) (*Key, error) {
	if keyring == nil {
		return nil, errors.New("generating a signing key requires a keyring")
	}

	var (
		privateDER []byte
		publicDER  []byte
		err        error
	)
	switch algorithm {
	case RS256:
		var priv *rsa.PrivateKey
		priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			return nil, fmt.Errorf("generating an RSA key: %w", err)
		}
		privateDER, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		publicDER, err = x509.MarshalPKIXPublicKey(&priv.PublicKey)
	case ES256:
		var priv *ecdsa.PrivateKey
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating an ECDSA key: %w", err)
		}
		privateDER, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		publicDER, err = x509.MarshalPKIXPublicKey(&priv.PublicKey)
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q; want %s or %s", algorithm, RS256, ES256)
	}
	if err != nil {
		return nil, fmt.Errorf("encoding the key: %w", err)
	}

	// The kid is derived from the public key, so it identifies the material rather
	// than the row: two deployments cannot disagree about which key a kid names, and
	// re-importing the same key cannot produce a second identity for it.
	sum := sha256.Sum256(publicDER)
	kid := base64.RawURLEncoding.EncodeToString(sum[:16])

	id, err := newID()
	if err != nil {
		return nil, err
	}

	sealed, err := keyring.Encrypt(privateDER, aad(id, kid, algorithm))
	if err != nil {
		return nil, fmt.Errorf("sealing the private key: %w", err)
	}
	// The DER is no longer needed in the clear.
	zero(privateDER)

	return &Key{
		ID: id, KID: kid, Algorithm: algorithm,
		PublicPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		SealedPrivate: sealed,
		KEKID:         keyring.ActiveKeyID(),
		CreatedAt:     time.Now().UTC(),
	}, nil
}

// aad binds a sealed private key to the row that carries it, so a ciphertext moved
// between rows fails to open rather than being served under another key's identity.
func aad(id, kid, algorithm string) []byte {
	return []byte("warden/signing_key/" + id + "/" + kid + "/" + algorithm)
}

// Insert stores a key as the active one, retiring whatever was active before.
//
// The previously active key becomes 'previous' rather than 'retired': tokens it
// signed are still in circulation and must keep verifying until they expire, which is
// what the JWKS overlap window in SPEC §17 is for.
func Insert(ctx context.Context, tx pgx.Tx, k *Key, rotationInterval time.Duration) error {
	q := db.New(tx)
	if err := q.RetireActiveSigningKey(ctx, k.CreatedAt); err != nil {
		return fmt.Errorf("retiring the previous signing key: %w", err)
	}

	expiresAt := k.CreatedAt.Add(rotationInterval)
	if err := q.InsertSigningKey(ctx, db.InsertSigningKeyParams{
		ID: k.ID, Kid: k.KID, Algorithm: k.Algorithm,
		PublicKey: k.PublicPEM, PrivateKey: k.SealedPrivate, KekID: k.KEKID,
		CreatedAt: k.CreatedAt, ExpiresAt: &expiresAt,
	}); err != nil {
		return fmt.Errorf("storing the signing key: %w", err)
	}
	return nil
}

// Active returns the key new tokens are signed with, with its private half opened.
func Active(ctx context.Context, tx pgx.Tx, keyring *secrets.Keyring) (kid string, privateDER []byte, algorithm string, err error) {
	row, err := db.New(tx).ActiveSigningKey(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, "", ErrNotInitialised
		}
		return "", nil, "", err
	}
	id, kid, algorithm, sealed := row.ID, row.Kid, row.Algorithm, row.PrivateKey

	privateDER, err = keyring.Decrypt(sealed, aad(id, kid, algorithm))
	if err != nil {
		// The likeliest cause by far is the wrong KEK, so say so rather than leaving
		// an operator to decode a decryption failure.
		return "", nil, "", fmt.Errorf(
			"could not open signing key %s: %w — is security.kek the same key the deployment was initialised with?",
			kid, err)
	}
	return kid, privateDER, algorithm, nil
}

// PublicSet returns the keys a relying party should accept: the active one and any
// still within the overlap window (SPEC §17).
type PublicKey struct {
	KID       string
	Algorithm string
	PEM       string
	Status    string
}

// PublicSet reads the keys JWKS publishes.
func PublicSet(ctx context.Context, tx pgx.Tx) ([]PublicKey, error) {
	rows, err := db.New(tx).PublicSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]PublicKey, 0, len(rows))
	for _, r := range rows {
		out = append(out, PublicKey{
			KID: r.Kid, Algorithm: r.Algorithm, PEM: r.PublicKey, Status: r.Status,
		})
	}
	return out, nil
}

func newID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "key_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
