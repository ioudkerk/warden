package authn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238's HMAC-SHA1; see the note on TOTPAlgorithm
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Time-based one-time passwords (RFC 6238), the second factor SPEC §7.1 lists first.
//
// Written here rather than taken from a library, and the reason is proportion: the whole
// algorithm is an HMAC, a counter and a truncation — about sixty lines — and the RFC
// publishes test vectors that prove an implementation correct. A dependency for this would
// be a supply-chain surface, a version to track and a transitive tree to audit, in exchange
// for code that is shorter than the code that would configure it. WebAuthn is the opposite
// case and gets a library.

const (
	// TOTPAlgorithm is HMAC-SHA1, and that is not a mistake.
	//
	// SHA-1 is broken for collision resistance, which is what matters for signatures and
	// certificates. HMAC-SHA1 is not affected by that: it depends on PRF security, which
	// stands, and TOTP truncates the output to six digits anyway. The reason it is SHA-1
	// here is interoperability — RFC 6238 §1.2 makes it the default, and the
	// authenticator applications people actually have on their phones assume it.
	TOTPAlgorithm = "SHA1"

	// TOTPDigits is six, which is what every authenticator displays.
	TOTPDigits = 6

	// TOTPPeriod is the thirty-second step RFC 6238 §4 defines as the default.
	TOTPPeriod = 30 * time.Second

	// TOTPSecretBytes is 160 bits, the minimum RFC 4226 §4 requires for the shared
	// secret. Authenticator apps encode it as 32 base32 characters.
	TOTPSecretBytes = 20

	// TOTPSkew is how many steps either side of now are accepted.
	//
	// One, which is a window of ninety seconds in total. It exists because a phone's
	// clock and a server's drift, and because a person reading six digits off a screen
	// and typing them takes time. Wider would be friendlier and would also widen the
	// window in which an observed code is still worth something to whoever observed it.
	TOTPSkew = 1
)

// base32NoPad is the encoding authenticator apps expect: uppercase, unpadded.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh shared secret, base32 encoded.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, TOTPSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating a TOTP secret: %w", err)
	}
	return base32NoPad.EncodeToString(raw), nil
}

// TOTPCode computes the code for one counter value.
//
// RFC 4226 §5.3's dynamic truncation: the low four bits of the last byte choose where in
// the HMAC to read a four-byte window, the top bit of that window is masked off to avoid
// sign confusion in languages that have signed integers, and the remainder is taken modulo
// ten to the number of digits.
func TOTPCode(secret string, counter uint64) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}

	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(counterBytes[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for range TOTPDigits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", TOTPDigits, truncated%mod), nil
}

// VerifyTOTP checks a code and reports which counter it matched.
//
// The counter comes back because the caller has to store it: RFC 6238 §5.2 requires that a
// code accepted once is not accepted again, and "again" includes the rest of its own
// thirty-second step. Without that, anybody who watched somebody type six digits has those
// digits for up to ninety seconds.
//
// Comparison is constant time. The window is small enough that a timing oracle would be a
// strange way in, but the habit is cheaper to keep than to re-justify at every call site.
func VerifyTOTP(secret, code string, at time.Time, skew int) (counter uint64, ok bool) {
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits {
		return 0, false
	}

	step := uint64(at.Unix()) / uint64(TOTPPeriod.Seconds()) //nolint:gosec // Unix time is positive
	for delta := -skew; delta <= skew; delta++ {
		candidate := step
		switch {
		case delta < 0:
			shift := uint64(-delta) //nolint:gosec // bounded by skew
			if candidate < shift {
				continue
			}
			candidate -= shift
		case delta > 0:
			candidate += uint64(delta) //nolint:gosec // bounded by skew
		}

		expected, err := TOTPCode(secret, candidate)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return candidate, true
		}
	}
	return 0, false
}

// OTPAuthURI renders the otpauth:// URI an authenticator reads from a QR code.
//
// The label is "issuer:account" and the issuer is repeated as a parameter, which is what
// the Key URI format asks for: older applications read the label, newer ones the parameter,
// and a URI that carries only one of them displays as "unknown" somewhere.
func OTPAuthURI(issuer, account, secret string) string {
	label := account
	if issuer != "" {
		label = issuer + ":" + account
	}
	query := url.Values{
		"secret":    {secret},
		"algorithm": {TOTPAlgorithm},
		"digits":    {fmt.Sprintf("%d", TOTPDigits)},
		"period":    {fmt.Sprintf("%d", int(TOTPPeriod.Seconds()))},
	}
	if issuer != "" {
		query.Set("issuer", issuer)
	}
	return "otpauth://totp/" + url.PathEscape(label) + "?" + query.Encode()
}

// decodeTOTPSecret accepts what a person might paste: lower case, spaces, padding.
func decodeTOTPSecret(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(secret))
	key, err := base32NoPad.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("the TOTP secret is not valid base32: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("the TOTP secret is empty")
	}
	return key, nil
}
