package authn_test

import (
	"crypto/sha1" //nolint:gosec // the corpus format; see breach.go
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/warden-project/warden/internal/authn"
)

func corpusHash(password string) string {
	sum := sha1.Sum([]byte(password)) //nolint:gosec // the corpus format
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// writeCorpus builds a HIBP-format file: "HASH:count", sorted by hash.
func writeCorpus(t *testing.T, passwords []string, withCounts bool) string {
	t.Helper()
	lines := make([]string, 0, len(passwords))
	for i, p := range passwords {
		if withCounts {
			lines = append(lines, fmt.Sprintf("%s:%d", corpusHash(p), (i+1)*13))
		} else {
			lines = append(lines, corpusHash(p))
		}
	}
	sort.Strings(lines)

	path := filepath.Join(t.TempDir(), "corpus.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("writing the corpus: %v", err)
	}
	return path
}

// TestEmbeddedSetCatchesLongWeakPasswords is the property the built-in list exists
// for. The classic short ones are refused on length before the corpus is consulted, so
// a list that only held those would add nothing.
func TestEmbeddedSetCatchesLongWeakPasswords(t *testing.T) {
	set := authn.NewEmbeddedSet()

	// Every one of these clears the default twelve-character floor, so the length rule
	// would let them through.
	for _, password := range []string{
		"passwordpassword", "Password123456", "qwertyuiopasdfgh", "iloveyouiloveyou",
		"1234567890123456", "letmeinletmein", "welcome123456", "adminadminadmin",
	} {
		t.Run(password, func(t *testing.T) {
			if len(password) < authn.DefaultPolicy().MinLength {
				t.Fatalf("this fixture is shorter than the length floor, so it proves nothing")
			}
			found, err := set.Contains(password)
			if err != nil {
				t.Fatalf("Contains: %v", err)
			}
			if !found {
				t.Fatal("a long, obviously weak password is not in the built-in corpus")
			}
		})
	}
}

// TestEmbeddedSetCatchesTheObviousTwelveCharacterCases is a regression test with a
// specific history: "password1234" was accepted by a real deployment during an
// end-to-end check of the setup-link flow, because the hand-written list held
// "Password1234" and not the lowercase form. Every entry below clears the default
// twelve-character floor, so the length rule does not save us — the corpus has to.
func TestEmbeddedSetCatchesTheObviousTwelveCharacterCases(t *testing.T) {
	set := authn.NewEmbeddedSet()
	for _, password := range []string{
		"password1234", "Password1234", "PASSWORD1234",
		"password2025", "welcome12345", "letmein12345", "qwerty123456",
		"admin1234567", "monkey123456", "dragon123456", "football1234",
		"sunshine1234", "princess1234", "superman1234", "iloveyou1234",
		"michael12345", "computer1234", "whatever1234", "chocolate123",
		"password2024!", "Welcome2026!",
	} {
		t.Run(password, func(t *testing.T) {
			if len(password) < authn.DefaultPolicy().MinLength {
				t.Fatalf("this fixture is only %d characters, so the length rule would catch it "+
					"and it proves nothing about the corpus", len(password))
			}
			found, err := set.Contains(password)
			if err != nil {
				t.Fatalf("Contains: %v", err)
			}
			if !found {
				t.Fatal("this password clears the length floor and is in every wordlist, " +
					"but the built-in corpus does not hold it")
			}
		})
	}
}

func TestEmbeddedSetDoesNotFlagGoodPasswords(t *testing.T) {
	set := authn.NewEmbeddedSet()
	for _, password := range []string{
		"correct horse battery staple",
		"vP2!kw9_Qm3zLd6r",
		"the quick brown fox jumps",
	} {
		found, err := set.Contains(password)
		if err != nil {
			t.Fatalf("Contains: %v", err)
		}
		if found {
			t.Fatalf("%q was reported as breached", password)
		}
	}
	if set.Size() < 100 {
		t.Fatalf("the built-in corpus holds %d entries; it was meant to be small, not empty", set.Size())
	}
}

// TestHIBPFileFindsEveryEntry walks the whole corpus rather than spot-checking,
// because a binary search that is wrong is usually wrong only at the edges.
func TestHIBPFileFindsEveryEntry(t *testing.T) {
	for _, withCounts := range []bool{true, false} {
		name := "hash only"
		if withCounts {
			name = "hash and count"
		}
		t.Run(name, func(t *testing.T) {
			// Enough entries that the search actually recurses, and an odd number so
			// the midpoint is never conveniently aligned.
			passwords := make([]string, 0, 401)
			for i := 0; i < 401; i++ {
				passwords = append(passwords, fmt.Sprintf("breached-password-%04d", i))
			}

			set, err := authn.OpenHIBPFile(writeCorpus(t, passwords, withCounts))
			if err != nil {
				t.Fatalf("OpenHIBPFile: %v", err)
			}
			t.Cleanup(func() { _ = set.Close() }) //nolint:errcheck // teardown

			for _, password := range passwords {
				found, containsErr := set.Contains(password)
				if containsErr != nil {
					t.Fatalf("Contains(%q): %v", password, containsErr)
				}
				if !found {
					t.Fatalf("%q is in the corpus but was not found", password)
				}
			}

			for i := 0; i < 200; i++ {
				absent := fmt.Sprintf("absent-password-%04d", i)
				found, containsErr := set.Contains(absent)
				if containsErr != nil {
					t.Fatalf("Contains(%q): %v", absent, containsErr)
				}
				if found {
					t.Fatalf("%q is not in the corpus but was found", absent)
				}
			}
		})
	}
}

// TestHIBPFileHandlesTheEdges covers the first line, the last line, and a corpus of
// one — the three places an off-by-one in a file binary search hides.
func TestHIBPFileHandlesTheEdges(t *testing.T) {
	passwords := []string{}
	for i := 0; i < 64; i++ {
		passwords = append(passwords, fmt.Sprintf("edge-case-password-%03d", i))
	}
	// Which of these sorts first and last depends on their hashes, not their text, so
	// find out rather than assume.
	sorted := append([]string(nil), passwords...)
	sort.Slice(sorted, func(i, j int) bool { return corpusHash(sorted[i]) < corpusHash(sorted[j]) })

	set, err := authn.OpenHIBPFile(writeCorpus(t, passwords, true))
	if err != nil {
		t.Fatalf("OpenHIBPFile: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() }) //nolint:errcheck // teardown

	for _, which := range []struct {
		name     string
		password string
	}{
		{"first line", sorted[0]},
		{"last line", sorted[len(sorted)-1]},
		{"second line", sorted[1]},
		{"penultimate line", sorted[len(sorted)-2]},
	} {
		t.Run(which.name, func(t *testing.T) {
			found, containsErr := set.Contains(which.password)
			if containsErr != nil {
				t.Fatalf("Contains: %v", containsErr)
			}
			if !found {
				t.Fatal("an entry at the edge of the corpus was not found")
			}
		})
	}

	t.Run("corpus of one", func(t *testing.T) {
		single, openErr := authn.OpenHIBPFile(writeCorpus(t, []string{"the only entry here"}, true))
		if openErr != nil {
			t.Fatalf("OpenHIBPFile: %v", openErr)
		}
		t.Cleanup(func() { _ = single.Close() }) //nolint:errcheck // teardown

		found, containsErr := single.Contains("the only entry here")
		if containsErr != nil || !found {
			t.Fatalf("the sole entry was not found: found=%v err=%v", found, containsErr)
		}
		found, containsErr = single.Contains("something else")
		if containsErr != nil || found {
			t.Fatalf("an absent password was found in a corpus of one: found=%v err=%v", found, containsErr)
		}
	})
}

// TestOpenHIBPFileRejectsTheWrongFormat is the guard against the worst failure mode
// here: a corpus that loads, answers "not breached" to everything, and looks like it
// is working.
func TestOpenHIBPFileRejectsTheWrongFormat(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"plaintext password list": "password\n123456\nqwerty\n",
		"lowercase hashes":        strings.ToLower(corpusHash("password")) + ":10\n",
		"csv":                     "hash,count\nABC,1\n",
		"empty":                   "",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".txt")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("writing: %v", err)
			}
			if set, err := authn.OpenHIBPFile(path); err == nil {
				_ = set.Close() //nolint:errcheck // cleanup on an unexpected success
				t.Fatal("a file that is not a corpus was accepted, so the check would silently pass everything")
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		if _, err := authn.OpenHIBPFile(filepath.Join(dir, "nope.txt")); err == nil {
			t.Fatal("a missing corpus was accepted")
		}
	})
}

// TestChainedSetStopsAtTheFirstHit also pins that a chain reports a hit from any
// member, which is what lets the built-in list back a partial download.
func TestChainedSetStopsAtTheFirstHit(t *testing.T) {
	file, err := authn.OpenHIBPFile(writeCorpus(t, []string{"only-in-the-file-corpus"}, true))
	if err != nil {
		t.Fatalf("OpenHIBPFile: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() }) //nolint:errcheck // teardown

	chain := authn.ChainedSet{authn.NewEmbeddedSet(), file}

	for _, c := range []struct {
		password string
		want     bool
	}{
		{"passwordpassword", true},        // built-in
		{"only-in-the-file-corpus", true}, // file
		{"correct horse battery staple", false},
	} {
		found, containsErr := chain.Contains(c.password)
		if containsErr != nil {
			t.Fatalf("Contains(%q): %v", c.password, containsErr)
		}
		if found != c.want {
			t.Fatalf("Contains(%q) = %v, want %v", c.password, found, c.want)
		}
	}
}

func TestDisabledSetFindsNothing(t *testing.T) {
	found, err := authn.DisabledSet{}.Contains("passwordpassword")
	if err != nil {
		t.Fatalf("Contains: %v", err)
	}
	if found {
		t.Fatal("the disabled set reported a hit")
	}
}
