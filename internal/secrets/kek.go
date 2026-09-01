package secrets

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// KEKSize is the required length of a key-encryption key. AES-256-GCM, per SPEC §17.
const KEKSize = 32

// ErrKEKNotConfigured is returned when no KEK reference was supplied at all. It is a
// startup error: Warden never generates a KEK on the fly, because a generated key
// would silently orphan every previously encrypted row on the next restart.
var ErrKEKNotConfigured = errors.New("no key-encryption key configured")

// KEK is resolved key material plus the identifier derived from it.
type KEK struct {
	// ID is the first 8 bytes of SHA-256 over the key material, hex encoded. It is
	// derived rather than configured so that operators cannot mislabel a key, and so
	// that "which key encrypted this value?" is answerable from the ciphertext alone.
	ID  string
	key []byte
}

// Bytes returns a copy of the key material.
func (k KEK) Bytes() []byte {
	out := make([]byte, len(k.key))
	copy(out, k.key)
	return out
}

// IsZero reports whether the KEK is unset.
func (k KEK) IsZero() bool { return len(k.key) == 0 }

// String redacts. A KEK must never be printed.
func (k KEK) String() string {
	if k.IsZero() {
		return ""
	}
	return "kek:" + k.ID + " " + Redacted
}

// Env and file readers are injectable so tests never touch the real environment or
// filesystem.
type (
	LookupEnvFunc func(string) (string, bool)
	ReadFileFunc  func(string) ([]byte, error)
)

// OSLookupEnv and OSReadFile are the production implementations.
var (
	OSLookupEnv LookupEnvFunc = os.LookupEnv
	OSReadFile  ReadFileFunc  = os.ReadFile
)

// ResolveKEK turns a KEK reference into key material. Supported references:
//
//	env:NAME          read from the named environment variable
//	file:/path/to/key read from a file (permissions are checked)
//	kms:<uri>         fetch from a KMS — not implemented in v1
//
// The material itself may be base64 (standard or URL alphabet, padded or not) or
// hex; it must decode to exactly 32 bytes. A raw 32-byte binary value is accepted
// from a file. Anything else is an error — Warden never hashes or stretches a short
// key into a valid one, because that would turn a weak operator input into something
// that looks strong.
func ResolveKEK(ref string, lookupEnv LookupEnvFunc, readFile ReadFileFunc) (KEK, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return KEK{}, ErrKEKNotConfigured
	}

	scheme, rest, ok := strings.Cut(ref, ":")
	if !ok {
		return KEK{}, fmt.Errorf(
			"malformed key-encryption key reference: want one of env:NAME, file:/path, kms:<uri>, got %q", ref)
	}

	var raw []byte
	switch scheme {
	case "env":
		if rest == "" {
			return KEK{}, errors.New("key-encryption key reference \"env:\" is missing a variable name")
		}
		v, present := lookupEnv(rest)
		if !present {
			return KEK{}, fmt.Errorf("key-encryption key: environment variable %s is not set", rest)
		}
		if strings.TrimSpace(v) == "" {
			return KEK{}, fmt.Errorf("key-encryption key: environment variable %s is empty", rest)
		}
		raw = []byte(strings.TrimSpace(v))

	case "file":
		if rest == "" {
			return KEK{}, errors.New("key-encryption key reference \"file:\" is missing a path")
		}
		b, err := readFile(rest)
		if err != nil {
			return KEK{}, fmt.Errorf("key-encryption key: reading %s: %w", rest, err)
		}
		raw = b

	case "kms":
		return KEK{}, fmt.Errorf(
			"key-encryption key: KMS references are not implemented in this release; use env: or file: (requested %q)", ref)

	default:
		return KEK{}, fmt.Errorf(
			"key-encryption key: unknown reference scheme %q, want one of env, file, kms", scheme)
	}

	key, err := decodeKeyMaterial(raw)
	if err != nil {
		return KEK{}, fmt.Errorf("key-encryption key from %s: %w", ref, err)
	}
	return newKEK(key), nil
}

// NewKEKFromBytes builds a KEK from raw material. Used by tests and by key rotation
// tooling that already holds decoded bytes.
func NewKEKFromBytes(key []byte) (KEK, error) {
	if len(key) != KEKSize {
		return KEK{}, fmt.Errorf("key-encryption key must be %d bytes, got %d", KEKSize, len(key))
	}
	return newKEK(key), nil
}

func newKEK(key []byte) KEK {
	sum := sha256.Sum256(key)
	k := make([]byte, len(key))
	copy(k, key)
	return KEK{ID: hex.EncodeToString(sum[:8]), key: k}
}

// decodeKeyMaterial accepts raw 32 bytes, or a base64 or hex encoding of them.
func decodeKeyMaterial(raw []byte) ([]byte, error) {
	if len(raw) == KEKSize {
		// Already the right length. Treat as raw binary unless it is plainly text,
		// in which case fall through to the decoders below so that a 32-character
		// hex-looking string is not silently used as its own ASCII bytes.
		if !looksLikeEncodedText(raw) {
			return raw, nil
		}
	}

	s := strings.TrimSpace(string(raw))
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == KEKSize {
			return b, nil
		}
	}

	// A 32-character printable string that is neither base64 nor hex is almost always
	// a passphrase someone typed. Refuse it: used directly as an AES-256 key it has
	// far less entropy than its length suggests, and accepting it would be exactly the
	// silent downgrade this function exists to prevent.
	if len(raw) == KEKSize && looksLikeEncodedText(raw) {
		return nil, errors.New(
			"looks like a passphrase rather than encoded key material; supply 32 bytes of " +
				"base64 or hex — generate one with: openssl rand -base64 32")
	}
	return nil, fmt.Errorf(
		"must decode to %d bytes of base64 or hex (got %d bytes); generate one with: openssl rand -base64 32",
		KEKSize, len(raw))
}

// looksLikeEncodedText reports whether the bytes are entirely printable ASCII, which
// is the signature of a key that was pasted as base64/hex rather than written raw.
func looksLikeEncodedText(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
