// Package authntest provides a WebAuthn authenticator that exists only in a test process.
//
// It lives in its own package rather than in a _test.go file because two packages need it:
// internal/authn, which tests the verification, and internal/httpapi, which tests the flow
// the verification sits inside. Duplicating a hundred lines of CBOR and ECDSA in both would
// mean two implementations of the same authenticator, and a bug in one of them would look
// like a bug in the server.
package authntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// A WebAuthn authenticator, in about a hundred lines.
//
// There is no other way to test this. A security key is a physical device and
// `navigator.credentials` is a browser API, so a test that wanted to exercise the real path
// would need both — which means WebAuthn either goes untested until somebody plugs a key
// into a laptop, or the test brings its own authenticator.
//
// This one does what a real one does: holds a P-256 key pair, answers a challenge by signing
// over the authenticator data and a hash of the client data, and counts. Everything the
// server verifies — the signature, the origin, the relying-party hash, the flags, the
// counter — is produced here honestly, so a server bug shows up as a refusal rather than as
// a test that passes because both sides agree on the same mistake.

// virtualAuthenticator is a security key that exists only in this process.
// Authenticator is a security key that exists only in this process.
type Authenticator struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
	signCount    uint32
	// UserVerified is what the UV flag says. A real key sets it after a PIN or a
	// fingerprint; this one is told.
	UserVerified bool
}

// New returns a fresh authenticator with its own key pair.
func New(t *testing.T) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating an authenticator key: %v", err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("generating a credential id: %v", err)
	}
	return &Authenticator{key: key, credentialID: id}
}

// coseKey renders the public key the way WebAuthn stores it: COSE_Key in CBOR.
//
// The labels are from RFC 8152: 1 = kty (2 is EC2), 3 = alg (-7 is ES256), -1 = crv
// (1 is P-256), -2 and -3 are x and y. Getting any of them wrong produces a credential the
// server stores happily and can never verify against.
func (a *Authenticator) coseKey(t *testing.T) []byte {
	t.Helper()
	x := make([]byte, 32)
	y := make([]byte, 32)
	a.key.X.FillBytes(x)
	a.key.Y.FillBytes(y)

	encoded, err := cbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1, -2: x, -3: y,
	})
	if err != nil {
		t.Fatalf("encoding the COSE key: %v", err)
	}
	return encoded
}

// authenticatorData builds the structure §6.1 defines.
func (a *Authenticator) authenticatorData(t *testing.T, rpID string, attested bool) []byte {
	t.Helper()

	rpIDHash := sha256.Sum256([]byte(rpID))
	data := append([]byte{}, rpIDHash[:]...)

	// Flags: UP (user present) always, UV when verified, AT when the attested credential
	// data follows. A server that ignored UP would accept an assertion the person never
	// touched the key for.
	var flags byte = 0x01
	if a.UserVerified {
		flags |= 0x04
	}
	if attested {
		flags |= 0x40
	}
	data = append(data, flags)

	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, a.signCount)
	data = append(data, counter...)

	if attested {
		data = append(data, make([]byte, 16)...) // AAGUID: zeroes, as a key with no attestation reports
		idLength := make([]byte, 2)
		binary.BigEndian.PutUint16(idLength, uint16(len(a.credentialID))) //nolint:gosec // 32
		data = append(data, idLength...)
		data = append(data, a.credentialID...)
		data = append(data, a.coseKey(t)...)
	}
	return data
}

// Register answers a creation challenge, returning the JSON a browser would post.
func (a *Authenticator) Register(t *testing.T, challenge, origin, rpID string) []byte {
	t.Helper()
	a.signCount++

	clientData := clientDataJSON(t, "webauthn.create", challenge, origin)
	authData := a.authenticatorData(t, rpID, true)

	// "none" attestation: no statement, which is what a key answers when the relying
	// party asked for none — and Warden does.
	attestation, err := cbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{}, "authData": authData,
	})
	if err != nil {
		t.Fatalf("encoding the attestation object: %v", err)
	}

	return mustJSON(t, map[string]any{
		"id":    b64(a.credentialID),
		"rawId": b64(a.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(attestation),
		},
	})
}

// Assert answers a login challenge.
func (a *Authenticator) Assert(t *testing.T, challenge, origin, rpID string) []byte {
	t.Helper()
	a.signCount++
	return a.AssertWithCount(t, challenge, origin, rpID, a.signCount)
}

// AssertWithCount is Assert with the counter forced, for the clone-detection test.
func (a *Authenticator) AssertWithCount(
	t *testing.T, challenge, origin, rpID string, count uint32,
) []byte {
	t.Helper()

	clientData := clientDataJSON(t, "webauthn.get", challenge, origin)
	saved := a.signCount
	a.signCount = count
	authData := a.authenticatorData(t, rpID, false)
	a.signCount = saved

	// The signature covers the authenticator data followed by the SHA-256 of the client
	// data. That binding is what ties the assertion to this origin and this challenge:
	// change either and the signature stops verifying.
	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)

	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("signing the assertion: %v", err)
	}

	return mustJSON(t, map[string]any{
		"id":    b64(a.credentialID),
		"rawId": b64(a.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(signature),
			"userHandle":        nil,
		},
	})
}

// clientDataJSON is what the *browser* builds, and the reason a phishing page cannot relay
// an assertion: the origin in here is the one the browser was actually talking to, and it is
// covered by the signature.
func clientDataJSON(t *testing.T, ceremony, challenge, origin string) []byte {
	t.Helper()
	return mustJSON(t, map[string]any{
		"type":        ceremony,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
}

func b64(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	return encoded
}

// ChallengeFrom pulls the challenge out of the options the server produced, so the
// authenticator signs over the value the server will check rather than one the test chose.
func ChallengeFrom(t *testing.T, options []byte) string {
	t.Helper()
	var parsed struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(options, &parsed); err != nil {
		t.Fatalf("parsing the options: %v", err)
	}
	if parsed.PublicKey.Challenge != "" {
		return parsed.PublicKey.Challenge
	}
	if parsed.Challenge == "" {
		t.Fatalf("the options carry no challenge: %s", options)
	}
	return parsed.Challenge
}
