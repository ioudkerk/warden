package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A caller-supplied request id is echoed into a response header and into log lines.
// Both are places where an unbounded, unfiltered string can do damage: a CRLF forges
// a header or a log entry, and an unbounded one fills a log.
func TestRequestIDSanitisation(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"an ordinary id passes through", "req-abc_123", "req-abc_123"},
		{"a trace-context style id passes through", "00-4bf92f-00f067-01", "00-4bf92f-00f067-01"},
		{"a carriage return is removed", "abc\r\nInjected: yes", "abcInjected:yes"},
		{"a newline is removed", "abc\ndef", "abcdef"},
		{"spaces are removed", "abc def", "abcdef"},
		{"quotes are removed", `abc"def'`, "abcdef"},
		{"nothing usable becomes empty", "\r\n\t ", ""},
		{"empty stays empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitiseRequestID(tc.in)
			if got != tc.want {
				t.Errorf("sanitiseRequestID(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.ContainsAny(got, "\r\n") {
				t.Errorf("the result still contains a line break: %q", got)
			}
		})
	}
}

// An unbounded id would let a caller write as much as they like into every log line
// about their request.
func TestRequestIDIsBounded(t *testing.T) {
	got := sanitiseRequestID(strings.Repeat("a", 500))
	if len(got) > 64 {
		t.Errorf("a 500-character id survived as %d characters", len(got))
	}
}

// A generated id must be unique, or correlation stops working exactly when two
// requests are interesting at once.
func TestGeneratedRequestIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := newRequestID()
		if seen[id] {
			t.Fatalf("newRequestID repeated %q after %d calls", id, i)
		}
		if !strings.HasPrefix(id, "req_") {
			t.Fatalf("id %q has no prefix", id)
		}
		seen[id] = true
	}
}

// A metric label taken from a URL path is unbounded cardinality, which is how a
// Prometheus server runs out of memory. Everything unrecognised collapses to one
// series.
func TestRouteLabelsAreBounded(t *testing.T) {
	known := []string{"/healthz", "/readyz", "/v1/authz/check", "/v1/authz/batch-check", "/v1/authz/explain"}
	for _, path := range known {
		if got := routeOf(requestTo(path)); got != path {
			t.Errorf("routeOf(%q) = %q", path, got)
		}
	}
	for _, path := range []string{
		"/v1/tenants/ten_acme/users/usr_maria",
		"/v1/authz/check/../../etc/passwd",
		"/" + strings.Repeat("x", 400),
		"/",
	} {
		if got := routeOf(requestTo(path)); got != "other" {
			t.Errorf("routeOf(%q) = %q; an unrecognised path must collapse to \"other\"", path, got)
		}
	}
}

func TestStatusClasses(t *testing.T) {
	cases := map[int]string{200: "2xx", 201: "2xx", 304: "3xx", 400: "4xx", 401: "4xx", 500: "5xx", 503: "5xx"}
	for code, want := range cases {
		if got := statusClass(code); got != want {
			t.Errorf("statusClass(%d) = %q, want %q", code, got, want)
		}
	}
}

func requestTo(path string) *http.Request {
	return httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
}
