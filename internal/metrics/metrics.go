// Package metrics is Warden's Prometheus instrumentation (SPEC §16.3).
//
// The names come from the specification and are part of the operational contract: a
// dashboard or alert built against warden_check_duration_seconds should not have to
// be rewritten because someone renamed a variable.
//
// Everything here is registered on a private registry rather than the default global
// one. A global registry collects whatever any linked dependency decides to publish,
// which makes the metric surface a function of the dependency graph instead of a
// decision — and for a service whose metrics reveal traffic shape and denial rates,
// that is not a surface to leave to chance.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds every instrument, so a caller records through a value it was given
// rather than reaching for a package-level global. That is what lets a test observe
// its own counters instead of whatever a previous test left behind.
type Metrics struct {
	registry *prometheus.Registry

	// CheckDuration is the decision latency, the number SPEC §18's targets are
	// written against. Labelled by outcome because an allow and a deny do different
	// amounts of work, and averaging them hides which one regressed.
	CheckDuration *prometheus.HistogramVec

	// ChecksTotal counts decisions by reason. The denial reasons are the interesting
	// series: a rise in unknown_permission means someone shipped a typo, and a rise
	// in missing_attribute means an application stopped sending something.
	ChecksTotal *prometheus.CounterVec

	// ModelLoads counts how often a tenant's model had to be read from the database
	// rather than served from the revision-keyed cache. A high rate means something
	// is bumping permission_rev far more than expected.
	ModelLoads *prometheus.CounterVec

	// DecisionLogRecords tracks the buffered sink. dropped is the series to alert
	// on: it means the log is lossy, which is a capacity signal rather than an
	// error.
	DecisionLogRecords *prometheus.CounterVec

	// HTTPRequests and HTTPDuration cover the API surface.
	HTTPRequests *prometheus.CounterVec
	HTTPDuration *prometheus.HistogramVec

	// AuthFailures counts rejected credentials. A sustained rise is either a broken
	// deployment or somebody trying tokens.
	AuthFailures prometheus.Counter

	// AssignmentsRefused counts privilege-escalation refusals (SPEC §17.1 threat 3).
	// Any non-zero value is worth a human looking at the audit log.
	AssignmentsRefused *prometheus.CounterVec

	// StoreRetries counts transactions PostgreSQL aborted as transient and the store
	// reissued, by SQLSTATE. A low rate is normal and is the mechanism working. A
	// rising one is a contention signal — two code paths taking the same rows in
	// opposite orders — which is a thing to fix rather than to absorb, and it is
	// invisible without this series because the retry hides it from the caller.
	StoreRetries *prometheus.CounterVec

	// StoreRetriesExhausted counts transactions that used the whole retry budget and
	// failed anyway. Unlike StoreRetries these are user-visible errors, so this is
	// the series to alert on.
	StoreRetriesExhausted *prometheus.CounterVec

	// BuildInfo carries the version as a label on a constant 1, the conventional way
	// to make "which build is this?" answerable from a dashboard.
	BuildInfo *prometheus.GaugeVec
}

// New builds the instrument set and registers it.
func New(version string) *Metrics {
	r := prometheus.NewRegistry()

	m := &Metrics{
		registry: r,

		CheckDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "warden_check_duration_seconds",
			Help: "Time to answer an authorization check, by outcome.",
			// Buckets chosen around SPEC §18: p50 under 3 ms and p99 under 10 ms for
			// a PDP round trip. The default buckets start at 5 ms, which would put
			// the entire target range in one bucket and make the p99 unmeasurable.
			Buckets: []float64{
				0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 1,
			},
		}, []string{"allowed"}),

		ChecksTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_checks_total",
			Help: "Authorization decisions, by outcome and reason.",
		}, []string{"allowed", "reason"}),

		ModelLoads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_model_loads_total",
			Help: "Tenant authorization models loaded from the database, by result (hit or miss).",
		}, []string{"result"}),

		DecisionLogRecords: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_decision_log_records_total",
			Help: "Decision log records, by disposition (written, dropped or failed).",
		}, []string{"disposition"}),

		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_http_requests_total",
			Help: "HTTP requests, by route and status.",
		}, []string{"route", "status"}),

		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "warden_http_request_duration_seconds",
			Help:    "HTTP request duration, by route.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route"}),

		AuthFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "warden_auth_failures_total",
			Help: "Requests rejected because their service-account credential was not accepted.",
		}),

		AssignmentsRefused: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_assignments_refused_total",
			Help: "Role assignments refused by the privilege-escalation guard, by reason.",
		}, []string{"reason"}),

		StoreRetries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_store_transaction_retries_total",
			Help: "Transactions reissued after PostgreSQL aborted them as transient, by SQLSTATE.",
		}, []string{"code"}),

		StoreRetriesExhausted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "warden_store_transaction_retries_exhausted_total",
			Help: "Transactions that used the whole retry budget and still failed, by SQLSTATE.",
		}, []string{"code"}),

		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "warden_build_info",
			Help: "Build information; always 1, with the version as a label.",
		}, []string{"version"}),
	}

	r.MustRegister(
		m.CheckDuration, m.ChecksTotal, m.ModelLoads, m.DecisionLogRecords,
		m.HTTPRequests, m.HTTPDuration, m.AuthFailures, m.AssignmentsRefused,
		m.StoreRetries, m.StoreRetriesExhausted, m.BuildInfo,
		// Process and runtime metrics: memory, goroutines, file descriptors. Enough
		// to answer "is it the database or is it us?" without a second exporter.
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	)
	m.BuildInfo.WithLabelValues(version).Set(1)

	// A CounterVec with no observed labels exposes no series at all, so an alert on
	// "retries are being exhausted" would evaluate against nothing until the first
	// one happened — which is the moment it is least useful to discover the alert
	// never worked. Both retryable SQLSTATEs are known in advance, so both series
	// start at zero.
	for _, code := range []string{"40001", "40P01"} {
		m.StoreRetries.WithLabelValues(code)
		m.StoreRetriesExhausted.WithLabelValues(code)
	}

	return m
}

// Registry exposes the registry, for tests that want to gather without HTTP.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// Handler serves the exposition format.
//
// It is mounted on its own listener, not the public API: SPEC §16.3 puts metrics on
// every service, and Warden's metrics describe denial rates and traffic shape per
// route. That is operational data, and it should not be reachable from wherever the
// decision API is.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		// A scrape that fails should say so in its own body rather than being
		// swallowed, or a broken collector looks like a healthy one with no series.
		ErrorHandling: promhttp.HTTPErrorOnError,
	})
}

// ObserveCheck records one authorization decision.
func (m *Metrics) ObserveCheck(allowed bool, reason string, seconds float64) {
	label := "false"
	if allowed {
		label = "true"
	}
	m.CheckDuration.WithLabelValues(label).Observe(seconds)
	m.ChecksTotal.WithLabelValues(label, reason).Inc()
}
