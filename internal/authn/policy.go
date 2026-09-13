package authn

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Policy is a tenant's rules for what counts as an acceptable password (SPEC §7.2).
//
// The defaults follow NIST 800-63B rather than tradition: a length floor, a check
// against known-breached passwords, and **no composition rules**. Requiring an
// uppercase letter and a digit does not measurably improve the passwords people
// choose — it produces Password1! — while it does reliably push them towards reuse
// and towards writing the result down. The knobs exist because some deployments are
// audited against a standard that still demands them, not because they are advisable,
// and RequireClasses' documentation says so where an administrator will read it.
type Policy struct {
	// MinLength is the floor, in Unicode code points rather than bytes, so that a
	// twelve-character password is twelve characters in any script.
	MinLength int `json:"min_length"`

	// MaxLength bounds what will be hashed. It is not a security rule — it is a
	// denial-of-service one. Argon2id over a 10 MB "password" costs the server real
	// memory and time, and an unauthenticated endpoint will be asked to do it.
	MaxLength int `json:"max_length"`

	RequireUpper  bool `json:"require_upper"`
	RequireLower  bool `json:"require_lower"`
	RequireDigit  bool `json:"require_digit"`
	RequireSymbol bool `json:"require_symbol"`

	// CheckBreached is mandatory in SPEC §7.2 and defaults to true. It is a field
	// rather than a constant because a deployment with no dataset available should be
	// able to say so deliberately and have that choice visible in its configuration,
	// instead of the check silently passing everything.
	CheckBreached bool `json:"check_breached"`
}

// DefaultPolicy is what a tenant gets before anybody configures one.
func DefaultPolicy() Policy {
	return Policy{
		MinLength:     12, // SPEC §7.2
		MaxLength:     1024,
		CheckBreached: true,
		// Composition rules deliberately off.
	}
}

// Validate rejects a policy that is internally inconsistent or weaker than Warden
// will accept. It runs when a policy is stored, so a bad one is refused at
// configuration time rather than discovered at the next password change.
func (p Policy) Validate() error {
	switch {
	case p.MinLength < 8:
		return fmt.Errorf("minimum length is %d; the floor is 8 (SPEC §7.2 defaults to 12)", p.MinLength)
	case p.MaxLength < p.MinLength:
		return fmt.Errorf("maximum length %d is below the minimum %d", p.MaxLength, p.MinLength)
	case p.MaxLength > 4096:
		return fmt.Errorf("maximum length is %d; the ceiling is 4096, because every "+
			"accepted byte is Argon2id work an unauthenticated caller can ask for", p.MaxLength)
	}
	return nil
}

// PolicyViolation reports why a password was refused.
//
// The reasons are enumerated rather than free text because they are shown to the
// person choosing the password and they get translated (SPEC §7.5 i18n hooks), and
// because "your password was rejected" with no reason is how people end up appending
// a 1.
type PolicyViolation struct {
	Reasons []string
}

func (e *PolicyViolation) Error() string {
	return "the password does not meet this tenant's policy: " + strings.Join(e.Reasons, "; ")
}

// ErrBreachedPassword is reported inside a PolicyViolation and named separately so
// callers can count it: a rising share of rejections for this reason is a signal about
// the user population, not about the policy.
var ErrBreachedPassword = errors.New("this password appears in a known breach corpus")

// Check applies the policy to a candidate password.
//
// It returns every reason it failed rather than the first, so that someone choosing a
// password is told the whole truth at once instead of discovering the rules one
// rejection at a time.
func (p Policy) Check(password string, breached BreachSet) error {
	var reasons []string

	length := utf8.RuneCountInString(password)
	if length < p.MinLength {
		reasons = append(reasons, fmt.Sprintf("must be at least %d characters", p.MinLength))
	}
	if p.MaxLength > 0 && length > p.MaxLength {
		reasons = append(reasons, fmt.Sprintf("must be at most %d characters", p.MaxLength))
	}

	if p.RequireUpper || p.RequireLower || p.RequireDigit || p.RequireSymbol {
		var hasUpper, hasLower, hasDigit, hasSymbol bool
		for _, r := range password {
			switch {
			case unicode.IsUpper(r):
				hasUpper = true
			case unicode.IsLower(r):
				hasLower = true
			case unicode.IsDigit(r):
				hasDigit = true
			case unicode.IsPunct(r) || unicode.IsSymbol(r):
				hasSymbol = true
			}
		}
		if p.RequireUpper && !hasUpper {
			reasons = append(reasons, "must contain an uppercase letter")
		}
		if p.RequireLower && !hasLower {
			reasons = append(reasons, "must contain a lowercase letter")
		}
		if p.RequireDigit && !hasDigit {
			reasons = append(reasons, "must contain a digit")
		}
		if p.RequireSymbol && !hasSymbol {
			reasons = append(reasons, "must contain a symbol")
		}
	}

	// Checked last, and only if the password is otherwise long enough to be worth
	// looking up: the lookup may touch a file, and a two-character password is going
	// to be refused regardless.
	if p.CheckBreached && breached != nil && length >= p.MinLength {
		found, err := breached.Contains(password)
		if err != nil {
			// A dataset that cannot be read is a configuration failure, and it must
			// not silently degrade into "no password is breached". That would turn
			// the one mandatory check in SPEC §7.2 into a no-op at exactly the moment
			// nobody is watching.
			return fmt.Errorf("checking the breached-password dataset: %w", err)
		}
		if found {
			reasons = append(reasons, ErrBreachedPassword.Error())
		}
	}

	if len(reasons) > 0 {
		return &PolicyViolation{Reasons: reasons}
	}
	return nil
}
