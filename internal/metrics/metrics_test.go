package metrics_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/warden-project/warden/internal/metrics"
)

func gather(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape returned %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// The metric names are an operational contract: a dashboard or an alert written
// against warden_check_duration_seconds must not break because someone renamed a
// field. SPEC §16.3 names them, so this pins them.
func TestTheSpecifiedMetricsArePublished(t *testing.T) {
	m := metrics.New("v-test")
	m.ObserveCheck(true, "grant_matched", 0.002)
	m.ObserveCheck(false, "condition_failed", 0.004)
	m.AuthFailures.Inc()
	m.AssignmentsRefused.WithLabelValues("missing_permissions").Inc()
	m.DecisionLogRecords.WithLabelValues("dropped").Add(3)
	m.StoreRetries.WithLabelValues("40P01").Add(2)
	m.StoreRetriesExhausted.WithLabelValues("40001").Inc()

	body := gather(t, m)
	for _, want := range []string{
		`warden_check_duration_seconds`,
		`warden_checks_total{allowed="true",reason="grant_matched"} 1`,
		`warden_checks_total{allowed="false",reason="condition_failed"} 1`,
		`warden_auth_failures_total 1`,
		`warden_assignments_refused_total{reason="missing_permissions"} 1`,
		`warden_decision_log_records_total{disposition="dropped"} 3`,
		`warden_store_transaction_retries_total{code="40P01"} 2`,
		`warden_store_transaction_retries_exhausted_total{code="40001"} 1`,
		`warden_build_info{version="v-test"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the scrape does not contain %q", want)
		}
	}
}

// SPEC §18 targets a p50 under 3 ms and a p99 under 10 ms. Prometheus's default
// buckets start at 5 ms, which would put the whole target range in one bucket and
// make the p99 unmeasurable — so the histogram needs its own.
func TestCheckDurationHasBucketsFineEnoughForTheLatencyTargets(t *testing.T) {
	m := metrics.New("v-test")
	m.ObserveCheck(true, "grant_matched", 0.002)

	body := gather(t, m)
	for _, bound := range []string{`le="0.001"`, `le="0.0025"`, `le="0.005"`, `le="0.01"`} {
		if !strings.Contains(body, bound) {
			t.Errorf("no bucket boundary at %s; the §18 targets would not be measurable", bound)
		}
	}
}

// A private registry, not the global default. A global one collects whatever any
// linked dependency decides to publish, which makes the metric surface a function of
// the dependency graph rather than a decision.
func TestTwoInstancesDoNotShareState(t *testing.T) {
	a := metrics.New("a")
	b := metrics.New("b")
	a.AuthFailures.Add(5)

	if strings.Contains(gather(t, b), "warden_auth_failures_total 5") {
		t.Error("two metric sets share counters; they are on a shared registry")
	}
	if !strings.Contains(gather(t, a), "warden_auth_failures_total 5") {
		t.Error("the counter was not recorded on its own registry")
	}
}

func TestProcessAndRuntimeMetricsAreIncluded(t *testing.T) {
	body := gather(t, metrics.New("v"))
	// Enough to answer "is it the database or is it us?" without a second exporter.
	for _, want := range []string{"go_goroutines", "go_memstats_alloc_bytes"} {
		if !strings.Contains(body, want) {
			t.Errorf("the scrape does not include %q", want)
		}
	}
}

// With no endpoint configured, tracing must still install propagation and hand back a
// usable tracer — so call sites start spans unconditionally with no nil check to
// forget, and a caller's trace context still survives the hop.
func TestTracingWithoutAnExporterIsStillUsable(t *testing.T) {
	ctx := context.Background()
	tracing, err := metrics.StartTracing(ctx, "", "v-test", 1.0,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("StartTracing: %v", err)
	}
	if tracing.Tracer == nil {
		t.Fatal("no tracer was returned; every span call site would need a nil check")
	}

	_, span := tracing.Tracer.Start(ctx, "warden.check")
	span.SetAttributes(metrics.CheckAttributes("usr_a", "billing.invoice:read", "grant_matched", true)...)
	span.End()

	if err := tracing.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

// A trace exporter is frequently a third party with different retention and access
// rules from the decision log. Object identifiers are the part most likely to be
// sensitive, so they stay out of spans.
func TestSpanAttributesOmitTheResourceIdentifier(t *testing.T) {
	attrs := metrics.CheckAttributes("usr_a", "billing.invoice:read", "grant_matched", true)
	for _, a := range attrs {
		if strings.Contains(string(a.Key), "resource") {
			t.Errorf("span attribute %q carries resource identity", a.Key)
		}
	}
	var keys []string
	for _, a := range attrs {
		keys = append(keys, string(a.Key))
	}
	for _, want := range []string{"warden.subject", "warden.permission", "warden.reason", "warden.allowed"} {
		if !containsString(keys, want) {
			t.Errorf("span attributes are missing %q", want)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
