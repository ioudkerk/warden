package authn

import (
	"bufio"
	"bytes"
	"crypto/sha1" //nolint:gosec // SHA-1 is the corpus format, not a security choice; see below
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// BreachSet answers whether a password is known to have been breached.
//
// SHA-1 throughout, and deliberately: this is the format Have I Been Pwned publishes
// its corpus in, and matching it is what lets an operator point Warden at the real
// 900-million-entry download instead of the token list embedded below. SHA-1's
// collision weakness is irrelevant here — nobody is authenticating with these hashes,
// and an attacker who can produce a second preimage for a password already in a breach
// corpus has achieved nothing.
type BreachSet interface {
	// Contains reports whether the password appears in the corpus. An error means the
	// corpus could not be consulted, which callers must treat as a failure rather than
	// as "not breached".
	Contains(password string) (bool, error)
}

// commonPasswords is the built-in corpus.
//
//go:embed data/common-passwords.txt
var commonPasswords string

// EmbeddedSet is the corpus that ships in the binary.
//
// It is small on purpose and it is not a substitute for the real thing —
// OpenHIBPFile is. What it is for is making the mandatory check in SPEC §7.2 mean
// something in a deployment that has not yet downloaded a corpus, since the
// alternative is a check that passes everything and looks like it is working.
//
// Its contents are skewed towards **long** weak passwords, which is not where a
// general list puts its weight. The reason is that the default policy already has a
// twelve-character floor, so "123456" and "qwerty" are refused on length before this
// set is ever consulted; the passwords that reach it are the ones that clear twelve
// characters and are still in every wordlist — "passwordpassword", "qwertyuiop123",
// "iloveyouiloveyou". A list optimised for the classic top-1000 would add almost
// nothing on top of the length rule.
type EmbeddedSet struct {
	once   sync.Once
	hashes map[string]struct{}
}

// NewEmbeddedSet returns the built-in corpus. Parsing is deferred to the first lookup
// so that constructing one costs nothing in a process that never checks a password.
func NewEmbeddedSet() *EmbeddedSet { return &EmbeddedSet{} }

func (s *EmbeddedSet) load() {
	s.hashes = make(map[string]struct{}, 1024)
	for _, line := range strings.Split(commonPasswords, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s.hashes[hashPassword(line)] = struct{}{}
	}
}

// Contains reports whether the password is in the built-in list.
func (s *EmbeddedSet) Contains(password string) (bool, error) {
	s.once.Do(s.load)
	_, found := s.hashes[hashPassword(password)]
	return found, nil
}

// Size reports how many passwords the built-in list holds, for `warden doctor` and
// for the startup log line that tells an operator how thin their coverage is.
func (s *EmbeddedSet) Size() int {
	s.once.Do(s.load)
	return len(s.hashes)
}

// hashPassword renders a password in the corpus format: uppercase hex SHA-1.
func hashPassword(password string) string {
	sum := sha1.Sum([]byte(password)) //nolint:gosec // corpus format; see the BreachSet doc
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// HIBPFile is a corpus in Have I Been Pwned's "hash:count" format, sorted by hash.
//
// The file is searched in place rather than loaded. The full download is tens of
// gigabytes, so reading it into a map is not an option, and a binary search over a
// sorted file costs a handful of seeks — around thirty for a 40 GB corpus, all of them
// in page cache after the first few lookups because the upper levels of the search
// tree are the same bytes every time.
//
// This is where the "k-anonymity" in SPEC §7.2 comes from, and it is worth being
// precise about what it does here: k-anonymity is what makes HIBP's *online* API safe
// to query, because the client sends only a five-character hash prefix. Locally there
// is no query to anonymise. What the format buys Warden is compatibility — an operator
// downloads the same file everyone else does — and the property that actually matters,
// which is that no plaintext password is ever written to disk.
type HIBPFile struct {
	f    *os.File
	size int64
	path string
}

// OpenHIBPFile opens a corpus for searching.
//
// It verifies that the first line parses, because the failure mode otherwise is a
// corpus that answers "not breached" to everything — a check that silently does
// nothing is worse than one that is switched off, since only the second is visible.
func OpenHIBPFile(path string) (*HIBPFile, error) {
	f, err := os.Open(path) //nolint:gosec // an operator-supplied path, by design
	if err != nil {
		return nil, fmt.Errorf("opening the breached-password corpus: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close() //nolint:errcheck // already failing
		return nil, err
	}
	if info.Size() == 0 {
		_ = f.Close() //nolint:errcheck // already failing
		return nil, fmt.Errorf("the breached-password corpus at %s is empty", path)
	}

	set := &HIBPFile{f: f, size: info.Size(), path: path}

	first, err := set.readLineAt(0)
	if err != nil {
		_ = f.Close() //nolint:errcheck // already failing
		return nil, err
	}
	if _, ok := corpusHash(first); !ok {
		_ = f.Close() //nolint:errcheck // already failing
		return nil, fmt.Errorf(
			"%s does not look like a Have I Been Pwned corpus: the first line is %q, "+
				"want an uppercase hex SHA-1 optionally followed by \":count\"",
			path, truncate(string(first), 60))
	}
	return set, nil
}

// Close releases the file.
func (s *HIBPFile) Close() error { return s.f.Close() }

// Path reports where the corpus was loaded from, for diagnostics.
func (s *HIBPFile) Path() string { return s.path }

// Contains binary-searches the corpus for the password's hash.
func (s *HIBPFile) Contains(password string) (bool, error) {
	target := hashPassword(password)

	// The invariant is the usual one for a binary search over a sorted file: every
	// line wholly before lo sorts below target, and every line starting at or after hi
	// sorts at or above it. Offsets, not line numbers, because the lines are not fixed
	// width — the count suffix varies in length.
	lo, hi := int64(0), s.size
	for lo < hi {
		mid := lo + (hi-lo)/2

		start, line, err := s.lineAtOrAfter(mid)
		if errors.Is(err, io.EOF) {
			// No complete line begins at or after mid, so the answer is below it.
			hi = mid
			continue
		}
		if err != nil {
			return false, err
		}

		hash, ok := corpusHash(line)
		if !ok {
			return false, fmt.Errorf("%s: malformed line at offset %d: %q",
				s.path, start, truncate(string(line), 60))
		}

		if hash < target {
			lo = start + int64(len(line)) + 1
		} else {
			hi = mid
		}
	}

	// lo is now the offset of the first line that sorts at or above target.
	_, line, err := s.lineAtOrAfter(lo)
	if errors.Is(err, io.EOF) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	hash, ok := corpusHash(line)
	if !ok {
		return false, fmt.Errorf("%s: malformed line at offset %d", s.path, lo)
	}
	return hash == target, nil
}

// lineAtOrAfter returns the first line that begins at or after offset, and where it
// begins.
//
// The subtlety is the "at". Offset 0 is a line start by definition, and so is any
// offset whose preceding byte is a newline — and that case is not hypothetical: the
// search narrows onto line starts, and the final read is made at one. Skipping
// unconditionally to the next newline would step over exactly the line being looked
// for, which is a bug that hides until the target happens to be the first, last or an
// adjacent entry.
func (s *HIBPFile) lineAtOrAfter(offset int64) (start int64, line []byte, err error) {
	start = offset
	if offset > 0 {
		atLineStart, checkErr := s.followsNewline(offset)
		if checkErr != nil {
			return 0, nil, checkErr
		}
		if !atLineStart {
			nl, findErr := s.indexOfNewline(offset)
			if findErr != nil {
				return 0, nil, findErr
			}
			start = nl + 1
		}
	}
	if start >= s.size {
		return 0, nil, io.EOF
	}
	line, err = s.readLineAt(start)
	if err != nil {
		return 0, nil, err
	}
	return start, line, nil
}

// followsNewline reports whether offset is the first byte of a line.
func (s *HIBPFile) followsNewline(offset int64) (bool, error) {
	var b [1]byte
	if _, err := s.f.ReadAt(b[:], offset-1); err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return b[0] == '\n', nil
}

// indexOfNewline returns the offset of the first '\n' at or after offset.
func (s *HIBPFile) indexOfNewline(offset int64) (int64, error) {
	const chunk = 4096
	buf := make([]byte, chunk)
	for at := offset; at < s.size; at += chunk {
		n, err := s.f.ReadAt(buf, at)
		if n > 0 {
			if i := bytes.IndexByte(buf[:n], '\n'); i >= 0 {
				return at + int64(i), nil
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	return 0, io.EOF
}

// readLineAt reads one line starting at offset, without its terminator.
func (s *HIBPFile) readLineAt(offset int64) ([]byte, error) {
	// A corpus line is 40 hex characters, a colon and a count: comfortably under 64
	// bytes. The reader is sized well above that so a line is one read, and a
	// pathologically long line is caught by bufio rather than allocated.
	r := bufio.NewReaderSize(io.NewSectionReader(s.f, offset, 512), 512)
	line, err := r.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(line) == 0 && errors.Is(err, io.EOF) {
		return nil, io.EOF
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

// corpusHash extracts the hash from a corpus line, which is either "HASH" or
// "HASH:count". It validates the shape, so a file of the wrong kind is reported as
// such instead of matching nothing.
func corpusHash(line []byte) (string, bool) {
	hash := line
	if i := bytes.IndexByte(line, ':'); i >= 0 {
		hash = line[:i]
	}
	if len(hash) != 40 {
		return "", false
	}
	for _, c := range hash {
		isDigit := c >= '0' && c <= '9'
		isUpperHex := c >= 'A' && c <= 'F'
		if !isDigit && !isUpperHex {
			return "", false
		}
	}
	return string(hash), true
}

// ChainedSet consults several corpora in order and reports a hit from any of them.
// The built-in list is cheap and in memory, so it goes first and the file is usually
// not touched at all for the passwords that matter most.
type ChainedSet []BreachSet

// Contains reports whether any member of the chain holds the password.
func (c ChainedSet) Contains(password string) (bool, error) {
	for _, set := range c {
		found, err := set.Contains(password)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

// DisabledSet is the explicit "no corpus" choice. It exists so that switching the
// check off is something a deployment states, and something a test can assert, rather
// than the accidental consequence of a nil.
type DisabledSet struct{}

// Contains always reports false.
func (DisabledSet) Contains(string) (bool, error) { return false, nil }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
