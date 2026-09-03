package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/warden-project/warden/internal/authz"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/store"
)

// Server is Warden's HTTP surface. Today that is the decision API of SPEC §10.1 plus
// the operational endpoints; the identity and management surfaces attach here as
// their milestones land.
type Server struct {
	cfg    *config.Config
	log    *slog.Logger
	engine *authz.Engine

	// tenant serves decisions and is subject to row-level security. system exists
	// only for the one lookup that cannot be tenant-scoped: resolving a token to the
	// tenant it belongs to.
	tenant *store.Store
	system *store.Store
}

// New builds the server.
func New(cfg *config.Config, log *slog.Logger, tenant, system *store.Store) (*Server, error) {
	engine, err := authz.NewEngine(tenant)
	if err != nil {
		return nil, err
	}
	if system == nil {
		return nil, errors.New(
			"the decision API needs database.system_url: authenticating a service account " +
				"means resolving a token to a tenant, which happens before any tenant scope exists")
	}
	return &Server{cfg: cfg, log: log, engine: engine, tenant: tenant, system: system}, nil
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Operational endpoints, deliberately unauthenticated: a load balancer cannot
	// hold a credential, and neither reveals anything about policy or tenants.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)

	mux.HandleFunc("POST /v1/authz/check", s.requireCaller(s.handleCheck))
	mux.HandleFunc("POST /v1/authz/batch-check", s.requireCaller(s.handleBatchCheck))

	return s.withRequestLimits(mux)
}

// withRequestLimits applies the protections that must not depend on a handler
// remembering them: a bounded body, and a recovered panic reported as a 500 rather
// than a dropped connection.
func (s *Server) withRequestLimits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic serving a request", "path", r.URL.Path, "panic", v)
				writeProblem(w, http.StatusInternalServerError, "internal_error",
					"The request could not be processed.")
			}
		}()
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.HTTP.MaxRequestBytes)
		next.ServeHTTP(w, r)
	})
}

// ListenAndServe runs the server until ctx is cancelled, then drains.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.HTTP.Addr,
		Handler:           s.Handler(),
		ReadTimeout:       s.cfg.HTTP.ReadTimeout,
		WriteTimeout:      s.cfg.HTTP.WriteTimeout,
		IdleTimeout:       s.cfg.HTTP.IdleTimeout,
		ReadHeaderTimeout: s.cfg.HTTP.ReadTimeout,
	}

	errs := make(chan error, 1)
	go func() {
		s.log.Info("listening", "addr", s.cfg.HTTP.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	s.log.Info("draining", "grace_period", s.cfg.HTTP.ShutdownTimeout)
	// Deliberately not derived from ctx: ctx is already cancelled, which is why we
	// are here, and a shutdown context inheriting that cancellation would abandon
	// in-flight requests instead of draining them.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.HTTP.ShutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx) //nolint:contextcheck // deliberate; see above
}

// --- operational ------------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// readyz reports on dependencies, so a rolling deploy does not send traffic to an
// instance that cannot answer.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	checks := map[string]string{}
	ready := true
	if err := s.tenant.Ping(ctx); err != nil {
		checks["database"] = "unreachable"
		ready = false
	} else {
		checks["database"] = "ok"
	}
	if err := s.system.Ping(ctx); err != nil {
		checks["database_system"] = "unreachable"
		ready = false
	} else {
		checks["database_system"] = "ok"
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{"ready": ready, "checks": checks})
}

// --- responses --------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// The status line is already sent; there is nothing useful left to say to
		// the client.
		_ = err
	}
}

// writeProblem emits RFC 9457 problem details, the error format SPEC §15.1 specifies.
func writeProblem(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// The status line is already written; a failure here means the client is gone.
	if err := json.NewEncoder(w).Encode(map[string]any{
		"type":   "https://warden.dev/errors/" + code,
		"title":  code,
		"status": status,
		"detail": detail,
	}); err != nil {
		_ = err
	}
}

func badRequest(w http.ResponseWriter, format string, args ...any) {
	writeProblem(w, http.StatusBadRequest, "invalid_request", fmt.Sprintf(format, args...))
}
