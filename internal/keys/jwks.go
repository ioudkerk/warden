package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	jose "github.com/go-jose/go-jose/v3"
)

// JWKS renders the public half of a key set as an RFC 7517 JSON Web Key Set.
//
// The set is what a relying party fetches to verify a token without holding anything
// that could mint one, so it carries exactly the keys Warden is prepared to have
// tokens verified against: the active key and, for the duration of the overlap
// window, the key it replaced. A retired key is absent, and its absence is the
// mechanism by which rotation eventually means something.
//
// Order matters a little. The active key comes first because some verifiers try keys
// in document order when a token carries no "kid", and the active key is the one that
// will match. Warden always sets "kid", so this is a courtesy to badly behaved
// clients rather than something correctness rests on.
func JWKS(set []PublicKey) (*jose.JSONWebKeySet, error) {
	out := &jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(set))}
	for _, k := range set {
		jwk, err := toJWK(k)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", k.KID, err)
		}
		out.Keys = append(out.Keys, jwk)
	}
	return out, nil
}

// MarshalJWKS renders the set and the ETag that identifies it.
//
// The ETag is a hash of the document rather than a revision counter, because JWKS
// changes for two unrelated reasons — a rotation and an expiry sweep — and hashing the
// answer is the only version that cannot get out of step with either.
func MarshalJWKS(set []PublicKey) (body []byte, etag string, err error) {
	jwks, err := JWKS(set)
	if err != nil {
		return nil, "", err
	}
	body, err = json.Marshal(jwks)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	return body, `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`, nil
}

// toJWK converts one stored public key to its JWKS representation.
func toJWK(k PublicKey) (jose.JSONWebKey, error) {
	pub, err := ParsePublicPEM(k.PEM)
	if err != nil {
		return jose.JSONWebKey{}, err
	}
	// Publishing "alg" and "use" is not required, but a verifier that reads them can
	// reject a key being used for the wrong thing, and one that ignores them loses
	// nothing.
	return jose.JSONWebKey{
		Key:       pub,
		KeyID:     k.KID,
		Algorithm: k.Algorithm,
		Use:       "sig",
	}, nil
}

// ParsePublicPEM decodes a stored public key.
//
// It accepts only the key types Warden signs with. An unexpected type here would mean
// the database holds something no algorithm in SPEC §8.2 can use, and serving it in
// JWKS would advertise a key nothing can verify against.
func ParsePublicPEM(text string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, fmt.Errorf("not a PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM block is %q, want PUBLIC KEY", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the public key: %w", err)
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

// parsePrivateDER decodes an opened private key.
func parsePrivateDER(der []byte) (crypto.PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing the private key: %w", err)
	}
	switch priv.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", priv)
	}
}
