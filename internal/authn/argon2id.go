// Package authn holds Warden's local credentials: how a password is hashed, what a
// tenant will accept as one, and how a login attempt is answered without revealing
// whether the account exists.
//
// The last of those is the reason this package has a narrow entry point.
// Authenticate does the same work whether or not the user is real, because SPEC §7.2
// requires "identical response and timing for unknown users" and a property like that
// cannot be bolted on at the HTTP layer — by then the expensive branch has already
// been taken or skipped, and the difference is on the wire.
package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are the Argon2id cost parameters.
//
// SPEC §7.2 fixes the defaults at m=64 MiB, t=3, p=2 and calls them tunable. They are
// stored in the hash itself rather than alongside it, so raising them later does not
// invalidate a single existing credential: an old hash still verifies under its own
// parameters, and NeedsRehash says it should be replaced on the next successful login.
type Params struct {
	// Memory is the argon2 memory cost in KiB.
	Memory uint32
	// Time is the number of passes.
	Time uint32
	// Parallelism is the number of lanes.
	Parallelism uint8
	// SaltLength and KeyLength are in bytes.
	SaltLength uint32
	KeyLength  uint32
}

// DefaultParams is SPEC §7.2's m=64 MiB, t=3, p=2.
//
// The memory figure is the one that matters and the one that is tempting to lower.
// 64 MiB per concurrent login is real capacity — and it is also what makes an offline
// attack on a stolen credential table expensive rather than a weekend. Lower it only
// with a number in hand for what it buys and what it costs.
func DefaultParams() Params {
	return Params{
		Memory:      64 * 1024, // 64 MiB
		Time:        3,
		Parallelism: 2,
		SaltLength:  16, // 128 bits; RFC 9106's recommendation
		KeyLength:   32,
	}
}

// Equal reports whether two parameter sets would produce the same cost. SaltLength is
// included: a hash written with a shorter salt should be replaced even though it still
// verifies.
func (p Params) Equal(other Params) bool {
	return p.Memory == other.Memory && p.Time == other.Time &&
		p.Parallelism == other.Parallelism && p.SaltLength == other.SaltLength &&
		p.KeyLength == other.KeyLength
}

func (p Params) String() string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", p.Memory, p.Time, p.Parallelism)
}

// Validate rejects parameters that would produce a hash not worth storing.
//
// The floors are deliberately well below DefaultParams: a deployment may have a reason
// to tune downward, and this is the line past which it stops being a password hash at
// all rather than a recommendation.
func (p Params) Validate() error {
	switch {
	case p.Memory < 8*1024:
		return fmt.Errorf("argon2id memory is %d KiB; the floor is 8192 KiB (8 MiB)", p.Memory)
	case p.Time < 1:
		return errors.New("argon2id time cost must be at least 1")
	case p.Parallelism < 1:
		return errors.New("argon2id parallelism must be at least 1")
	case p.SaltLength < 16:
		return fmt.Errorf("argon2id salt is %d bytes; the floor is 16", p.SaltLength)
	case p.KeyLength < 16:
		return fmt.Errorf("argon2id key length is %d bytes; the floor is 16", p.KeyLength)
	}
	return nil
}

// ErrMalformedHash is returned when a stored credential cannot be parsed.
//
// It is deliberately distinct from "the password is wrong". A row that will not parse
// is a corrupted or truncated credential, and answering "wrong password" to every
// login against it would send the user round a reset loop that cannot succeed while
// hiding a storage bug from whoever is reading the logs.
var ErrMalformedHash = errors.New("the stored credential is not a valid Argon2id hash")

// Hash derives a PHC-encoded Argon2id hash of password.
//
// The encoding is the standard one — $argon2id$v=19$m=...,t=...,p=...$salt$key — so
// the parameters travel with the hash and a credential written by one version of
// Warden is readable by every other.
func Hash(password string, p Params) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating a salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Parallelism, p.KeyLength)
	return encode(p, salt, key), nil
}

func encode(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// Verify reports whether password matches the encoded hash.
//
// A mismatch is (false, nil), not an error: a wrong password is an ordinary outcome
// and giving it an error type invites a caller to log it as one. Only a hash that
// cannot be parsed produces an error.
func Verify(password, encoded string) (bool, error) {
	p, salt, want, err := decode(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Parallelism, p.KeyLength)
	// Constant-time even though a timing signal on the final comparison is the least
	// of the ways this could leak: the habit is what matters, and the cost is nil.
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash reports whether a stored hash was written under different parameters
// from the ones now in force.
//
// SPEC §7.2 asks for a rehash on login when parameters change. That is the only moment
// it can happen: the plaintext exists nowhere else, so a credential written under old
// parameters stays that way until its owner next logs in successfully. A deployment
// that raises its cost parameters should therefore expect the change to roll out over
// weeks, not at deploy time.
func NeedsRehash(encoded string, want Params) (bool, error) {
	have, _, _, err := decode(encoded)
	if err != nil {
		return false, err
	}
	return !have.Equal(want), nil
}

// decode parses a PHC-encoded Argon2id hash.
func decode(encoded string) (p Params, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	// A well-formed encoding splits into: "", "argon2id", "v=19", "m=..,t=..,p=..",
	// salt, key.
	if len(parts) != 6 || parts[0] != "" {
		return Params{}, nil, nil, ErrMalformedHash
	}
	if parts[1] != "argon2id" {
		// argon2i and argon2d are real algorithms and this is not a parse failure so
		// much as a refusal: Warden writes argon2id only, and silently verifying a
		// weaker variant would let a migration import credentials nobody reviewed.
		return Params{}, nil, nil, fmt.Errorf("%w: algorithm is %q, want argon2id", ErrMalformedHash, parts[1])
	}

	var version int
	if _, scanErr := fmt.Sscanf(parts[2], "v=%d", &version); scanErr != nil {
		return Params{}, nil, nil, ErrMalformedHash
	}
	if version != argon2.Version {
		return Params{}, nil, nil, fmt.Errorf(
			"%w: version is %d, and this build implements %d", ErrMalformedHash, version, argon2.Version)
	}

	if _, scanErr := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Parallelism); scanErr != nil {
		return Params{}, nil, nil, ErrMalformedHash
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, ErrMalformedHash
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, ErrMalformedHash
	}
	if len(salt) == 0 || len(key) == 0 {
		return Params{}, nil, nil, ErrMalformedHash
	}

	//nolint:gosec // lengths are bounded by the encoded string, which is a database column
	p.SaltLength, p.KeyLength = uint32(len(salt)), uint32(len(key))
	return p, salt, key, nil
}
