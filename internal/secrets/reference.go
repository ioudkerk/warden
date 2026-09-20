package secrets

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ResolveReference turns an `env:` or `file:` reference into a secret.
//
// The same two schemes the key-encryption key uses, and deliberately so: an operator who
// has learned how to point Warden at one secret has learned how to point it at all of them.
// What it does *not* share with ResolveKEK is the decoding — a KEK must be exactly 32 bytes
// of key material, while an SMTP password is whatever the mail provider issued, and
// insisting on a length or an encoding here would reject valid passwords.
//
// A literal is rejected rather than accepted as a convenience. A password pasted into a
// configuration file ends up in a repository, in a container image and in a backup, and the
// reference form costs one line to avoid all three.
func ResolveReference(ref string, lookupEnv LookupEnvFunc, readFile ReadFileFunc) (Secret, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Secret{}, errors.New("the reference is empty")
	}

	scheme, rest, ok := strings.Cut(ref, ":")
	if !ok {
		return Secret{}, fmt.Errorf(
			"malformed reference: want env:NAME or file:/path, got %q. A literal value is not "+
				"accepted here: it would end up in the repository, the image and the backups", ref)
	}

	switch scheme {
	case "env":
		if rest == "" {
			return Secret{}, errors.New(`the reference "env:" is missing a variable name`)
		}
		value, present := lookupEnv(rest)
		if !present {
			return Secret{}, fmt.Errorf("environment variable %s is not set", rest)
		}
		if strings.TrimSpace(value) == "" {
			return Secret{}, fmt.Errorf("environment variable %s is empty", rest)
		}
		return New(strings.TrimSpace(value)), nil

	case "file":
		if rest == "" {
			return Secret{}, errors.New(`the reference "file:" is missing a path`)
		}
		raw, err := readFile(rest)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return Secret{}, fmt.Errorf("%s does not exist", rest)
			}
			return Secret{}, fmt.Errorf("reading %s: %w", rest, err)
		}
		// Trailing newlines are what an editor adds and what `echo` leaves behind; a
		// password with one appended fails to authenticate and the reason is invisible.
		value := strings.TrimRight(string(raw), "\r\n")
		if value == "" {
			return Secret{}, fmt.Errorf("%s is empty", rest)
		}
		return New(value), nil

	default:
		return Secret{}, fmt.Errorf(
			"unknown reference scheme %q: want env:NAME or file:/path", scheme)
	}
}
