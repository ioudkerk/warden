package authn_test

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/warden-project/warden/internal/authn"
)

// TOTP is one of the few things in this codebase whose correctness is published. RFC 6238
// Appendix B prints the codes a correct implementation produces for a known secret at known
// times, and RFC 4226 Appendix D does the same for the counter-based version underneath it.
// Anything that passes both is interoperable with every authenticator application; anything
// that does not is wrong in a way no amount of local testing would reveal.

// rfcSecret is the ASCII seed both RFCs use: "12345678901234567890".
var rfcSecret = base32.StdEncoding.WithPadding(base32.NoPadding).
	EncodeToString([]byte("12345678901234567890"))

// TestTOTPMatchesRFC6238 walks Appendix B's table for SHA-1.
//
// The 2603 codes are the eight-digit values the RFC prints; Warden issues six, so each
// expectation here is the last six digits of the published value — which is what truncation
// to six digits produces, and is how every six-digit authenticator reads the same table.
func TestTOTPMatchesRFC6238(t *testing.T) {
	for _, tc := range []struct {
		unix int64
		want string // RFC 6238 Appendix B, SHA-1 column, last six digits
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		step := uint64(tc.unix) / 30
		got, err := authn.TOTPCode(rfcSecret, step)
		if err != nil {
			t.Fatalf("t=%d: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Errorf("t=%d (counter %d) = %s, want %s — this implementation would not "+
				"interoperate with any authenticator application", tc.unix, step, got, tc.want)
		}
	}
}

// TestHOTPMatchesRFC4226 checks the counter-based construction TOTP is built on.
//
// Appendix D's table is the tighter test of the two: it pins the dynamic truncation for ten
// consecutive counters, so an off-by-one in the offset or a sign error in the masking shows
// up here rather than as an intermittent failure at some future timestamp.
func TestHOTPMatchesRFC4226(t *testing.T) {
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for counter, expected := range want {
		got, err := authn.TOTPCode(rfcSecret, uint64(counter)) //nolint:gosec // a test index
		if err != nil {
			t.Fatalf("counter %d: %v", counter, err)
		}
		if got != expected {
			t.Errorf("counter %d = %s, want %s", counter, got, expected)
		}
	}
}

// TestVerifyAcceptsTheStepEitherSide. A phone's clock drifts and a person takes a few
// seconds to type; without the window, both look like a wrong code.
func TestVerifyAcceptsTheStepEitherSide(t *testing.T) {
	now := time.Unix(1111111111, 0)

	for name, offset := range map[string]time.Duration{
		"the step before": -TOTPStep,
		"this step":       0,
		"the step after":  TOTPStep,
	} {
		t.Run(name, func(t *testing.T) {
			code, err := authn.TOTPCode(rfcSecret, uint64(now.Add(offset).Unix())/30)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := authn.VerifyTOTP(rfcSecret, code, now, authn.TOTPSkew); !ok {
				t.Fatalf("a code from %s was refused", name)
			}
		})
	}

	// And two steps away is outside the window. The bound is the point: the wider it is,
	// the longer an observed code stays worth something.
	code, err := authn.TOTPCode(rfcSecret, uint64(now.Add(2*TOTPStep).Unix())/30)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := authn.VerifyTOTP(rfcSecret, code, now, authn.TOTPSkew); ok {
		t.Fatal("a code two steps away was accepted; the acceptance window is wider than " +
			"it is documented to be")
	}
}

// TestVerifyReportsTheCounterItMatched is what makes replay detectable.
//
// RFC 6238 §5.2 requires a code accepted once never to be accepted again, and "again"
// includes the remaining seconds of its own step. The caller can only enforce that if
// verification says which counter was used.
func TestVerifyReportsTheCounterItMatched(t *testing.T) {
	now := time.Unix(1234567890, 0)
	step := uint64(now.Unix()) / 30

	code, err := authn.TOTPCode(rfcSecret, step)
	if err != nil {
		t.Fatal(err)
	}
	counter, ok := authn.VerifyTOTP(rfcSecret, code, now, authn.TOTPSkew)
	if !ok {
		t.Fatal("the code did not verify")
	}
	if counter != step {
		t.Fatalf("counter = %d, want %d; a caller storing this to refuse a replay would "+
			"store the wrong value", counter, step)
	}
}

// TestVerifyRefusesTheObviousRubbish.
func TestVerifyRefusesTheObviousRubbish(t *testing.T) {
	now := time.Unix(1234567890, 0)
	for name, code := range map[string]string{
		"empty":       "",
		"too short":   "12345",
		"too long":    "1234567",
		"not digits":  "abcdef",
		"wrong code":  "000000",
		"with spaces": "123 456",
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := authn.VerifyTOTP(rfcSecret, code, now, authn.TOTPSkew); ok {
				t.Fatalf("%q was accepted", code)
			}
		})
	}
}

// TestSecretsAreDistinctAndLongEnough. RFC 4226 §4 requires at least 128 bits and
// recommends 160; a generator that returned something short or repeated would be invisible
// until somebody looked at two of them.
func TestSecretsAreDistinctAndLongEnough(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		secret, err := authn.NewTOTPSecret()
		if err != nil {
			t.Fatal(err)
		}
		if seen[secret] {
			t.Fatal("NewTOTPSecret repeated itself")
		}
		seen[secret] = true

		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		if err != nil {
			t.Fatalf("a generated secret is not the base32 an authenticator expects: %v", err)
		}
		if len(raw) < 16 {
			t.Fatalf("a secret of %d bytes is below RFC 4226 §4's minimum of 128 bits", len(raw))
		}
	}
}

// TestSecretsSurviveHowPeopleTypeThem. A person pasting from a screen brings spaces, lower
// case and sometimes the padding; refusing those is refusing the right secret.
func TestSecretsSurviveHowPeopleTypeThem(t *testing.T) {
	now := time.Unix(1111111111, 0)
	code, err := authn.TOTPCode(rfcSecret, uint64(now.Unix())/30)
	if err != nil {
		t.Fatal(err)
	}

	for name, typed := range map[string]string{
		"lower case": strings.ToLower(rfcSecret),
		"spaced":     rfcSecret[:4] + " " + rfcSecret[4:8] + " " + rfcSecret[8:],
		"padded":     rfcSecret + "======",
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := authn.VerifyTOTP(typed, code, now, authn.TOTPSkew); !ok {
				t.Fatalf("the same secret written as %s did not verify", name)
			}
		})
	}
}

// TestTheURIIsWhatAnAuthenticatorReads.
func TestTheURIIsWhatAnAuthenticatorReads(t *testing.T) {
	uri := authn.OTPAuthURI("ACME", "maria@acme.test", rfcSecret)

	for _, want := range []string{
		"otpauth://totp/", "secret=" + rfcSecret, "issuer=ACME",
		"algorithm=SHA1", "digits=6", "period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("the otpauth URI does not contain %q: %s", want, uri)
		}
	}
	// The issuer appears twice on purpose: older applications read the label prefix and
	// newer ones the parameter. A URI carrying one of them shows "unknown" in the other.
	if !strings.Contains(uri, "ACME%3Amaria@acme.test") && !strings.Contains(uri, "ACME:maria@acme.test") {
		t.Errorf("the label does not carry the issuer prefix: %s", uri)
	}
}

// TOTPStep is the period as a duration, for readability in these tests.
const TOTPStep = 30 * time.Second
