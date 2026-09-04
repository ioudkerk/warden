package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Serve runs the metrics listener until ctx is cancelled.
//
// On its own port, deliberately. SPEC §16.3 puts metrics on every service, and
// Warden's describe denial rates and per-route traffic — operational data that
// should not be reachable from wherever the decision API is exposed. Binding it
// separately lets an operator keep it on an internal interface without a proxy rule
// that someone will eventually get wrong.
func (m *Metrics) Serve(ctx context.Context, addr string, log *slog.Logger) error {
	if addr == "" {
		log.Info("metrics are not exposed: telemetry.metrics_addr is empty")
		<-ctx.Done()
		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", m.Handler())

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		log.Info("metrics listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx) //nolint:contextcheck // ctx is already cancelled; see httpapi
}
