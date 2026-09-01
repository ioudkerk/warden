package secrets_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/warden-project/warden/internal/secrets"
)

const sentinel = "hunter2-correct-horse-battery-staple"

// A secret must survive no formatting, serialization or logging path with its value
// intact. SPEC §17: "Passwords ... never logged".
func TestSecretNeverLeaksThroughFormatting(t *testing.T) {
	s := secrets.New(sentinel)

	verbs := []string{"%s", "%v", "%+v", "%#v", "%q", "%d", "%x", "%X"}
	for _, verb := range verbs {
		t.Run(verb, func(t *testing.T) {
			if got := fmt.Sprintf(verb, s); strings.Contains(got, sentinel) {
				t.Fatalf("verb %s leaked the secret: %s", verb, got)
			}
		})
	}

	// Nested in a struct, which is how config is usually printed.
	type holder struct {
		Name  string
		Token secrets.Secret
	}
	h := holder{Name: "db", Token: s}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(verb, h); strings.Contains(got, sentinel) {
			t.Fatalf("nested %s leaked the secret: %s", verb, got)
		}
	}
	if got := fmt.Sprintf("%+v", &h); strings.Contains(got, sentinel) {
		t.Fatalf("pointer-to-struct leaked the secret: %s", got)
	}
}

func TestSecretNeverLeaksThroughSerialization(t *testing.T) {
	type holder struct {
		Token secrets.Secret `json:"token" yaml:"token"`
	}
	h := holder{Token: secrets.New(sentinel)}

	j, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if bytes.Contains(j, []byte(sentinel)) {
		t.Fatalf("JSON leaked the secret: %s", j)
	}

	y, err := yaml.Marshal(h)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if bytes.Contains(y, []byte(sentinel)) {
		t.Fatalf("YAML leaked the secret: %s", y)
	}
}

func TestSecretNeverLeaksThroughStructuredLogging(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("connecting", "dsn", secrets.New(sentinel))
	if strings.Contains(buf.String(), sentinel) {
		t.Fatalf("slog leaked the secret: %s", buf.String())
	}
	if !strings.Contains(buf.String(), secrets.Redacted) {
		t.Fatalf("expected the redaction marker in the log line: %s", buf.String())
	}
}

// "Missing" and "present" must stay distinguishable without exposing the value,
// because validation error messages depend on that distinction.
func TestSecretZeroValueRendersEmpty(t *testing.T) {
	var s secrets.Secret
	if !s.IsZero() {
		t.Fatal("zero Secret should report IsZero")
	}
	if got := fmt.Sprintf("%v", s); got != "" {
		t.Fatalf("zero Secret should render empty, got %q", got)
	}
	if got := fmt.Sprintf("%v", secrets.New(sentinel)); got != secrets.Redacted {
		t.Fatalf("set Secret should render the redaction marker, got %q", got)
	}
}

func TestSecretRoundTrip(t *testing.T) {
	var h struct {
		Token secrets.Secret `yaml:"token"`
	}
	if err := yaml.Unmarshal([]byte("token: "+sentinel+"\n"), &h); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if h.Token.Expose() != sentinel {
		t.Fatalf("Expose returned %q", h.Token.Expose())
	}

	var j struct {
		Token secrets.Secret `json:"token"`
	}
	if err := json.Unmarshal([]byte(`{"token":"`+sentinel+`"}`), &j); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if j.Token.Expose() != sentinel {
		t.Fatalf("Expose returned %q", j.Token.Expose())
	}
}
