package authn_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/warden-project/warden/internal/authn"
)

// testParams keep the unit tests fast. They are below DefaultParams on purpose and
// every test that depends on the *cost* rather than the correctness says so.
func testParams() authn.Params {
	p := authn.DefaultParams()
	p.Memory = 8 * 1024 // 8 MiB, the validation floor
	p.Time = 1
	return p
}

func TestHashAndVerifyRoundTrip(t *testing.T) {
	const password = "correct horse battery staple"
	encoded, err := authn.Hash(password, testParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Fatalf("encoding is %q; want a PHC string a non-Go implementation can read", encoded)
	}
	if strings.Contains(encoded, password) {
		t.Fatal("the encoded hash contains the password")
	}

	ok, err := authn.Verify(password, encoded)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("the correct password did not verify")
	}

	ok, err = authn.Verify(password+"x", encoded)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("a wrong password verified")
	}
}

// TestHashIsSaltedPerCredential is what stops one stolen table from revealing that two
// users chose the same password.
func TestHashIsSaltedPerCredential(t *testing.T) {
	const password = "the same password twice over"
	first, err := authn.Hash(password, testParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	second, err := authn.Hash(password, testParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if first == second {
		t.Fatal("hashing the same password twice produced identical output, so it is not salted")
	}
	for _, encoded := range []string{first, second} {
		ok, verifyErr := authn.Verify(password, encoded)
		if verifyErr != nil || !ok {
			t.Fatalf("a salted hash did not verify: %v", verifyErr)
		}
	}
}

// TestWrongPasswordIsNotAnError keeps callers from logging an ordinary failed login as
// a system fault.
func TestWrongPasswordIsNotAnError(t *testing.T) {
	encoded, err := authn.Hash("a perfectly good password", testParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, err := authn.Verify("something else entirely", encoded)
	if err != nil {
		t.Fatalf("a mismatch produced an error: %v", err)
	}
	if ok {
		t.Fatal("a mismatch verified")
	}
}

func TestMalformedHashesAreRejected(t *testing.T) {
	valid, err := authn.Hash("a perfectly good password", testParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	cases := map[string]string{
		"empty":              "",
		"not PHC at all":     "hunter2",
		"bcrypt":             "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		"wrong algorithm":    strings.Replace(valid, "argon2id", "argon2i", 1),
		"unknown version":    strings.Replace(valid, "v=19", "v=16", 1),
		"truncated":          valid[:len(valid)/2],
		"missing key":        valid[:strings.LastIndex(valid, "$")],
		"bad base64 in salt": strings.Replace(valid, "$argon2id$", "$argon2id$", 1) + "!!!not base64!!!",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			_, verifyErr := authn.Verify("anything", encoded)
			if verifyErr == nil {
				t.Fatal("a malformed hash verified without error")
			}
			if !errors.Is(verifyErr, authn.ErrMalformedHash) {
				t.Fatalf("error is %v; want it to wrap ErrMalformedHash so callers can tell "+
					"a corrupt credential from a wrong password", verifyErr)
			}
		})
	}
}

// TestNeedsRehashTracksParameterChanges is what makes SPEC §7.2's "rehash on parameter
// change" possible: without it, raising the cost would leave every existing credential
// on the old one forever.
func TestNeedsRehashTracksParameterChanges(t *testing.T) {
	params := testParams()
	encoded, err := authn.Hash("a perfectly good password", params)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	needs, err := authn.NeedsRehash(encoded, params)
	if err != nil {
		t.Fatalf("NeedsRehash: %v", err)
	}
	if needs {
		t.Fatal("a hash written under the current parameters wants rehashing")
	}

	for name, change := range map[string]func(authn.Params) authn.Params{
		"more memory":      func(p authn.Params) authn.Params { p.Memory *= 2; return p },
		"more time":        func(p authn.Params) authn.Params { p.Time++; return p },
		"more parallelism": func(p authn.Params) authn.Params { p.Parallelism++; return p },
		"longer salt":      func(p authn.Params) authn.Params { p.SaltLength *= 2; return p },
		"longer key":       func(p authn.Params) authn.Params { p.KeyLength *= 2; return p },
	} {
		t.Run(name, func(t *testing.T) {
			needs, rehashErr := authn.NeedsRehash(encoded, change(params))
			if rehashErr != nil {
				t.Fatalf("NeedsRehash: %v", rehashErr)
			}
			if !needs {
				t.Fatal("a parameter change did not ask for a rehash")
			}
		})
	}

	// The old hash must keep verifying regardless — a rehash is an upgrade, not an
	// invalidation, and the plaintext only exists at login.
	ok, err := authn.Verify("a perfectly good password", encoded)
	if err != nil || !ok {
		t.Fatalf("a hash due for rehashing stopped verifying: ok=%v err=%v", ok, err)
	}
}

// TestDefaultParamsMatchTheSpec pins SPEC §7.2's figures. If this fails, either the
// spec changed or somebody lowered the cost without saying so.
func TestDefaultParamsMatchTheSpec(t *testing.T) {
	p := authn.DefaultParams()
	if p.Memory != 64*1024 {
		t.Errorf("memory = %d KiB; SPEC §7.2 says 64 MiB", p.Memory)
	}
	if p.Time != 3 {
		t.Errorf("time = %d; SPEC §7.2 says 3", p.Time)
	}
	if p.Parallelism != 2 {
		t.Errorf("parallelism = %d; SPEC §7.2 says 2", p.Parallelism)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("the default parameters do not pass validation: %v", err)
	}
}

func TestParamsValidationRejectsWeakCosts(t *testing.T) {
	for name, p := range map[string]authn.Params{
		"no memory":      {Memory: 1024, Time: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32},
		"no time":        {Memory: 64 * 1024, Time: 0, Parallelism: 2, SaltLength: 16, KeyLength: 32},
		"no parallelism": {Memory: 64 * 1024, Time: 3, Parallelism: 0, SaltLength: 16, KeyLength: 32},
		"short salt":     {Memory: 64 * 1024, Time: 3, Parallelism: 2, SaltLength: 8, KeyLength: 32},
		"short key":      {Memory: 64 * 1024, Time: 3, Parallelism: 2, SaltLength: 16, KeyLength: 8},
	} {
		t.Run(name, func(t *testing.T) {
			if err := p.Validate(); err == nil {
				t.Fatal("validation accepted parameters below the floor")
			}
			if _, err := authn.Hash("a perfectly good password", p); err == nil {
				t.Fatal("Hash accepted parameters below the floor")
			}
		})
	}
}
