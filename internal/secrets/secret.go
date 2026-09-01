// Package secrets holds the types and primitives Warden uses to carry sensitive
// material: a string wrapper that cannot be logged by accident, resolution of the
// key-encryption key from its configured source, and envelope encryption of data at
// rest (SPEC §17, "Secrets at rest").
package secrets

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// Redacted is what a Secret renders as in any human- or machine-readable output.
const Redacted = "«redacted»"

// Secret is a string that must never reach a log, an error message, a stack dump or
// a serialized config. Every stringification path is overridden to redact, so the
// only way to read the value is the explicit Expose call — which greps cleanly and
// shows up in review.
//
// It is a value type with an unexported field: copying is safe and there is no
// pointer through which the value can leak.
type Secret struct {
	v string
}

// New wraps a sensitive value.
func New(v string) Secret { return Secret{v: v} }

// Expose returns the underlying value. Call this at the point of use and never
// assign the result to anything longer-lived than the call.
func (s Secret) Expose() string { return s.v }

// IsZero reports whether the secret is unset. Validation uses this instead of
// comparing against "" so callers never have to touch the value.
func (s Secret) IsZero() bool { return s.v == "" }

// String implements fmt.Stringer. An unset secret renders as the empty string so
// that "missing" and "present" stay distinguishable in diagnostics without leaking.
func (s Secret) String() string {
	if s.v == "" {
		return ""
	}
	return Redacted
}

// GoString covers the %#v verb, which would otherwise print the struct field.
func (s Secret) GoString() string { return fmt.Sprintf("secrets.Secret{%s}", s.String()) }

// Format covers every fmt verb, including %s, %v, %q and %x, so no format string
// anywhere in the codebase can print the value.
func (s Secret) Format(f fmt.State, verb rune) {
	switch verb {
	case 'q':
		fmt.Fprintf(f, "%q", s.String())
	default:
		fmt.Fprint(f, s.String())
	}
}

// MarshalJSON keeps secrets out of serialized config and API responses.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// MarshalText covers encoding/text consumers, including yaml.v3's marshaller.
func (s Secret) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalJSON reads a secret from JSON.
func (s *Secret) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	s.v = v
	return nil
}

// UnmarshalYAML reads a secret from a YAML scalar.
func (s *Secret) UnmarshalYAML(unmarshal func(any) error) error {
	var v string
	if err := unmarshal(&v); err != nil {
		return err
	}
	s.v = v
	return nil
}

// LogValue implements slog.LogValuer, so a Secret passed to a structured logger as
// an attribute value is redacted rather than reflected over.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.String()) }
