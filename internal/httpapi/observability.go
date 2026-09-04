package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Every request carries an id, and every log line about it carries the same one.
// Without that, a production incident means correlating by timestamp across
// interleaved requests, which stops working at exactly the volume where it matters.

type requestIDKey struct{}

// RequestIDHeader is both read and written. Reading it lets a caller's id follow a
// request into Warden's logs, so an application's trace and Warden's line about the
// same decision can be joined.
const RequestIDHeader = "X-Request-Id"

// RequestIDFrom returns the request id, if there is one.
func RequestIDFrom(ctx context.Context) string {
	id, ok := ctx.Value(requestIDKey{}).(string)
	if !ok {
		return ""
	}
	return id
}

// LoggerFrom returns a logger already carrying the request's id.
func LoggerFrom(ctx context.Context, base *slog.Logger) *slog.Logger {
	if id := RequestIDFrom(ctx); id != "" {
		return base.With("request_id", id)
	}
	return base
}

func newRequestID() string {
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		// A request with no id is worse than one with a weak id: correlation is the
		// whole point, and nothing here is a security decision.
		return "req_" + time.Now().UTC().Format("150405.000000")
	}
	return "req_" + base64.RawURLEncoding.EncodeToString(b)
}

// observe wraps a handler with a request id, structured access logging, and metrics.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		// An id supplied by a caller is used for correlation and nothing else, so it
		// is bounded and stripped of anything that would break a log line. It never
		// reaches a query or an authorization decision.
		if id = sanitiseRequestID(id); id == "" {
			id = newRequestID()
		}

		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		w.Header().Set(RequestIDHeader, id)

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		started := time.Now()
		next.ServeHTTP(recorder, r.WithContext(ctx))
		elapsed := time.Since(started)

		// The route, not the path: a path can contain a tenant slug or a resource
		// id, and a metric label with unbounded cardinality is how a Prometheus
		// server runs out of memory.
		route := routeOf(r)
		if s.metrics != nil {
			s.metrics.HTTPRequests.WithLabelValues(route, statusClass(recorder.status)).Inc()
			s.metrics.HTTPDuration.WithLabelValues(route).Observe(elapsed.Seconds())
		}

		level := slog.LevelInfo
		if recorder.status >= 500 {
			level = slog.LevelError
		}
		s.log.LogAttrs(ctx, level, "request",
			slog.String("request_id", id),
			slog.String("method", r.Method),
			slog.String("route", route),
			slog.Int("status", recorder.status),
			slog.Duration("duration", elapsed),
		)
	})
}

// sanitiseRequestID bounds a caller-supplied id. It is echoed into logs and a
// response header, so it must not carry newlines that would forge a log line or a
// header separator that would split the response.
func sanitiseRequestID(id string) string {
	if len(id) > 64 {
		id = id[:64]
	}
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.', r == ':':
			return r
		default:
			return -1
		}
	}, id)
	return clean
}

// routeOf returns a bounded label for a request. Anything unrecognised collapses to
// "other" rather than becoming a new time series.
func routeOf(r *http.Request) string {
	switch r.URL.Path {
	case "/healthz", "/readyz",
		"/v1/authz/check", "/v1/authz/batch-check", "/v1/authz/explain", "/v1/authz/filter",
		"/v1/ui/bundle", "/v1/ui/resolve":
		return r.URL.Path
	default:
		return "other"
	}
}

// statusClass buckets a status code. Recording every code individually is rarely
// useful and 4xx from a hostile caller is unbounded.
func statusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}

// statusRecorder captures the status for logging and metrics.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.written {
		return
	}
	w.written = true
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}
