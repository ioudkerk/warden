package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Tracing (SPEC §16.3). The goal is stated there precisely: an application's trace
// should show the warden.check span inline, which needs two things — Warden must
// continue the caller's trace rather than starting its own, and it must export
// somewhere the caller's collector can also see.
//
// Continuing the caller's trace is why the W3C propagator is installed even when no
// exporter is configured: the trace and span ids still travel, so an application that
// does collect them sees the request reach Warden.

// TracerName is the instrumentation scope every Warden span is recorded under.
const TracerName = "github.com/warden-project/warden"

// Tracing holds the provider so it can be shut down and its spans flushed.
type Tracing struct {
	provider *sdktrace.TracerProvider
	Tracer   trace.Tracer
}

// StartTracing configures the tracer.
//
// With no endpoint it installs a no-op tracer rather than nothing at all: call sites
// then start spans unconditionally, with no `if tracing != nil` guard to forget, and
// the cost is a few nanoseconds per span.
func StartTracing(ctx context.Context, endpoint, serviceVersion string, sampleRatio float64, log *slog.Logger) (*Tracing, error) {
	// Propagation is installed either way, so a caller's trace context survives the
	// hop even when this deployment exports nothing.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	if endpoint == "" {
		log.Info("tracing is not exported: telemetry.tracing_otlp_endpoint is empty")
		return &Tracing{Tracer: noop.NewTracerProvider().Tracer(TracerName)}, nil
	}

	exportCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	exporter, err := otlptracehttp.New(exportCtx, otlptracehttp.WithEndpointURL(endpoint))
	if err != nil {
		return nil, fmt.Errorf("configuring the OTLP trace exporter: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		// ParentBased means a trace the caller decided to sample is sampled here
		// too. Sampling independently would produce traces with Warden's span
		// missing from exactly the requests someone chose to look at.
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRatio))),
	)
	otel.SetTracerProvider(provider)
	log.Info("tracing enabled", "endpoint", endpoint, "sample_ratio", sampleRatio)

	return &Tracing{provider: provider, Tracer: provider.Tracer(TracerName,
		trace.WithInstrumentationVersion(serviceVersion))}, nil
}

// Shutdown flushes pending spans.
func (t *Tracing) Shutdown(ctx context.Context) error {
	if t == nil || t.provider == nil {
		return nil
	}
	return t.provider.Shutdown(ctx)
}

// CheckAttributes describes an authorization decision on a span.
//
// The subject and permission are recorded; the resource id is not. A trace exporter
// is frequently a third party with different retention and access rules from the
// decision log, and object identifiers are the part most likely to be sensitive.
func CheckAttributes(subject, permission, reason string, allowed bool) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("warden.subject", subject),
		attribute.String("warden.permission", permission),
		attribute.String("warden.reason", reason),
		attribute.Bool("warden.allowed", allowed),
	}
}
