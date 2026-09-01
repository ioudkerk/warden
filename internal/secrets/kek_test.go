package secrets_test

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/warden-project/warden/internal/secrets"
)

func testKeyBytes() []byte {
	k := make([]byte, secrets.KEKSize)
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}

func envLookup(pairs map[string]string) secrets.LookupEnvFunc {
	return func(name string) (string, bool) {
		v, ok := pairs[name]
		return v, ok
	}
}

func fileReader(files map[string][]byte) secrets.ReadFileFunc {
	return func(path string) ([]byte, error) {
		b, ok := files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return b, nil
	}
}

func TestResolveKEKAcceptedEncodings(t *testing.T) {
	want := testKeyBytes()
	cases := map[string]string{
		"base64 padded":     base64.StdEncoding.EncodeToString(want),
		"base64 unpadded":   base64.RawStdEncoding.EncodeToString(want),
		"base64url":         base64.URLEncoding.EncodeToString(want),
		"hex":               hex.EncodeToString(want),
		"surrounding space": "  " + base64.StdEncoding.EncodeToString(want) + "\n",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			kek, err := secrets.ResolveKEK("env:WARDEN_KEK", envLookup(map[string]string{"WARDEN_KEK": encoded}), nil)
			if err != nil {
				t.Fatalf("ResolveKEK: %v", err)
			}
			if got := kek.Bytes(); string(got) != string(want) {
				t.Fatalf("resolved the wrong key material")
			}
		})
	}
}

func TestResolveKEKFromFileAcceptsRawBinary(t *testing.T) {
	want := testKeyBytes() // contains bytes outside printable ASCII
	kek, err := secrets.ResolveKEK("file:/etc/warden/kek", nil, fileReader(map[string][]byte{
		"/etc/warden/kek": want,
	}))
	if err != nil {
		t.Fatalf("ResolveKEK: %v", err)
	}
	if string(kek.Bytes()) != string(want) {
		t.Fatal("resolved the wrong key material")
	}
}

// The exit condition for M0-4: a missing or malformed secret is a startup error and
// never a working default.
func TestResolveKEKRejectsEverythingElse(t *testing.T) {
	env := envLookup(map[string]string{
		"EMPTY":      "",
		"SHORT":      base64.StdEncoding.EncodeToString([]byte("too short")),
		"PASSPHRASE": "correct horse battery stapler!!!", // exactly 32 printable chars
		"GARBAGE":    "not base64 and not hex ~~~~",
	})
	files := fileReader(map[string][]byte{"/tmp/short": []byte("nope")})

	cases := []struct {
		name, ref, wantSubstring string
	}{
		{"empty reference", "", "no key-encryption key configured"},
		{"no scheme", "abcdef", "malformed key-encryption key reference"},
		{"unknown scheme", "vault:secret/kek", "unknown reference scheme"},
		{"kms not implemented", "kms://project/key", "not implemented"},
		{"env name missing", "env:", "missing a variable name"},
		{"env var unset", "env:ABSENT", "is not set"},
		{"env var empty", "env:EMPTY", "is empty"},
		{"key too short", "env:SHORT", "must decode to 32 bytes"},
		{"passphrase not key material", "env:PASSPHRASE", "looks like a passphrase"},
		{"undecodable", "env:GARBAGE", "must decode to 32 bytes"},
		{"file path missing", "file:", "missing a path"},
		{"file absent", "file:/nope", "reading /nope"},
		{"file too short", "file:/tmp/short", "must decode to 32 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kek, err := secrets.ResolveKEK(tc.ref, env, files)
			if err == nil {
				t.Fatalf("expected an error, got a usable key %s", kek.ID)
			}
			if !kek.IsZero() {
				t.Fatal("a failed resolution must not return key material")
			}
			if !strings.Contains(err.Error(), tc.wantSubstring) {
				t.Fatalf("error %q does not mention %q", err, tc.wantSubstring)
			}
		})
	}

	if _, err := secrets.ResolveKEK("", nil, nil); !errors.Is(err, secrets.ErrKEKNotConfigured) {
		t.Fatalf("an empty reference should be ErrKEKNotConfigured, got %v", err)
	}
}

func TestKEKIDIsDerivedAndStable(t *testing.T) {
	a, err := secrets.NewKEKFromBytes(testKeyBytes())
	if err != nil {
		t.Fatalf("NewKEKFromBytes: %v", err)
	}
	b, err := secrets.NewKEKFromBytes(testKeyBytes())
	if err != nil {
		t.Fatalf("NewKEKFromBytes: %v", err)
	}
	if a.ID != b.ID {
		t.Fatal("the same key material must yield the same id")
	}

	other := testKeyBytes()
	other[0] ^= 0xff
	c, err := secrets.NewKEKFromBytes(other)
	if err != nil {
		t.Fatalf("NewKEKFromBytes: %v", err)
	}
	if a.ID == c.ID {
		t.Fatal("different key material must yield different ids")
	}
	if len(a.ID) != 16 {
		t.Fatalf("expected a 16-character hex id, got %q", a.ID)
	}
}

func TestKEKNeverPrintsKeyMaterial(t *testing.T) {
	kek, err := secrets.NewKEKFromBytes(testKeyBytes())
	if err != nil {
		t.Fatalf("NewKEKFromBytes: %v", err)
	}
	rendered := fmt.Sprintf("%v %s", kek, kek)
	if strings.Contains(rendered, string(testKeyBytes())) {
		t.Fatal("KEK rendering leaked key material")
	}
	if !strings.Contains(rendered, kek.ID) {
		t.Fatal("KEK rendering should include the id, which is not secret")
	}
}

func TestNewKEKFromBytesRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := secrets.NewKEKFromBytes(make([]byte, n)); err == nil {
			t.Fatalf("expected an error for a %d-byte key", n)
		}
	}
}
