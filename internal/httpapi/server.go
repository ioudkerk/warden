package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/authz"
	"github.com/warden-project/warden/internal/cache"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/decisionlog"
	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/metrics"
	"github.com/warden-project/warden/internal/oidcop"
	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
)

// Server is Warden's HTTP surface. Today that is the decision API of SPEC §10.1 plus
// the operational endpoints; the identity and management surfaces attach here as
// their milestones land.
type Server struct {
	cfg    *config.Config
	log    *slog.Logger
	engine *authz.Engine

	// tenant serves decisions and is subject to row-level security. system exists
	// for the lookups that cannot be tenant-scoped: resolving a token to the tenant
	// it belongs to, and writing the decision log.
	tenant *store.Store
	system *store.Store

	decisions *decisionlog.Sink
	metrics   *metrics.Metrics
	cache     cache.Cache
	tracer    trace.Tracer
	keys      *keys.Manager
	sessions  *authn.Sessions
	provider  *oidcop.Provider
	authn     *authn.Authenticator
	lockout   *authn.Lockout
	// level is the decision log level, read from the application's configuration.
	// Cached per tenant so the hot path does not query for it on every decision.
	levels sync.Map // tenant id -> decisionlog.Level
}

// Deps are the collaborators the server is built from.
//
// A struct rather than a parameter list because the list had reached eight and M1
// adds more: at that width every call site is a row of positional arguments whose
// meaning depends on counting commas, and swapping two *store.Store values by mistake
// is a tenant-isolation bug that compiles.
type Deps struct {
	Config *config.Config
	Log    *slog.Logger

	// Tenant serves decisions under row-level security. System is for the lookups
	// that cannot be tenant-scoped: resolving a token to its tenant, the decision
	// log, and the deployment-level signing keys.
	Tenant *store.Store
	System *store.Store

	Decisions *decisionlog.Sink
	Metrics   *metrics.Metrics
	Cache     cache.Cache
	Tracing   *metrics.Tracing

	// Keys publishes JWKS and signs tokens. Optional: a process serving only the PDP
	// role has nothing to sign, and the JWKS route is simply absent when it is nil,
	// rather than present and answering with an error.
	Keys *keys.Manager

	// Sessions serves SPEC §8.3's session management. Optional for the same reason,
	// though the routes are registered either way so that a misconfigured deployment
	// answers 503 with a reason rather than 404, which would look like a version skew.
	Sessions *authn.Sessions

	// Provider is the OpenID Provider (SPEC §7.7). Optional on the same terms.
	Provider *oidcop.Provider

	// Authn verifies passwords for the interactive login, and Lockout rate-limits it
	// (SPEC §7.2). Both are needed for the sign-in page; without them the login routes
	// answer 503 rather than serving a form that cannot work.
	Authn   *authn.Authenticator
	Lockout *authn.Lockout
}

// New builds the server.
func New(d Deps) (*Server, error) {
	engine, err := authz.NewEngine(d.Tenant)
	if err != nil {
		return nil, err
	}
	if d.System == nil {
		return nil, errors.New(
			"the decision API needs database.system_url: authenticating a service account " +
				"means resolving a token to a tenant, which happens before any tenant scope exists")
	}
	return &Server{
		cfg: d.Config, log: d.Log, engine: engine,
		tenant: d.Tenant, system: d.System, decisions: d.Decisions,
		metrics: d.Metrics, cache: d.Cache, tracer: tracerOf(d.Tracing),
		keys: d.Keys, sessions: d.Sessions, provider: d.Provider,
		authn: d.Authn, lockout: d.Lockout,
	}, nil
}

// tracerOf returns a tracer that is always safe to call. A no-op rather than a nil
// check at every span means one fewer thing to remember at a call site.
func tracerOf(t *metrics.Tracing) trace.Tracer {
	if t == nil || t.Tracer == nil {
		return noop.NewTracerProvider().Tracer(metrics.TracerName)
	}
	return t.Tracer
}

// decisionLevel returns the log level configured for a tenant's applications.
//
// SPEC §16.2 makes this per application; with one decision endpoint and no
// application in the request, the strictest level across the tenant's enrolled
// applications is used — recording more than one application asked for is a cost,
// while recording less would silently lose what someone configured it for.
func (s *Server) decisionLevel(ctx context.Context, tenantID string) decisionlog.Level {
	if cached, ok := s.levels.Load(tenantID); ok {
		if level, isLevel := cached.(decisionlog.Level); isLevel {
			return level
		}
	}

	level := decisionlog.LevelDenies
	err := s.system.InSystem(ctx, "reading the decision log level", func(ctx context.Context, tx pgx.Tx) error {
		levels, err := db.New(tx).TenantDecisionLogLevels(ctx, tenantID)
		if err != nil {
			return err
		}
		strictest := -1
		for _, raw := range levels {
			parsed, err := decisionlog.ParseLevel(raw)
			if err != nil {
				s.log.Warn("unrecognised decision_log level; using denies", "value", raw)
				continue
			}
			if rank := levelRank(parsed); rank > strictest {
				strictest, level = rank, parsed
			}
		}
		return nil
	})
	if err != nil {
		s.log.Warn("could not read the decision log level; using denies", "error", err)
		return decisionlog.LevelDenies
	}

	s.levels.Store(tenantID, level)
	return level
}

// levelRank orders levels by how much they record.
func levelRank(l decisionlog.Level) int {
	switch l {
	case decisionlog.LevelOff:
		return 0
	case decisionlog.LevelDenies:
		return 1
	case decisionlog.LevelSampled:
		return 2
	case decisionlog.LevelAll:
		return 3
	default:
		return 1
	}
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Operational endpoints, deliberately unauthenticated: a load balancer cannot
	// hold a credential, and neither reveals anything about policy or tenants.
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)

	// JWKS is unauthenticated by definition: it is how a relying party that holds no
	// Warden credential verifies a token. It carries only public key material.
	if s.keys != nil {
		mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	}

	// Discovery is unauthenticated for the same reason JWKS is: it is what a client
	// holding nothing reads in order to find everything else.
	mux.HandleFunc("GET /.well-known/openid-configuration",
		s.requireProvider(s.handleOpenIDConfiguration))

	// The authorization code flow. Unauthenticated in the service-account sense: these
	// are the endpoints through which a person and a client authenticate themselves.
	mux.HandleFunc("GET /oauth2/authorize", s.requireProvider(s.requireLogin(s.handleAuthorize)))
	mux.HandleFunc("POST /oauth2/token", s.requireProvider(s.handleToken))
	mux.HandleFunc("GET /login", s.requireLogin(s.handleLoginForm))
	mux.HandleFunc("POST /login", s.requireLogin(s.handleLoginSubmit))

	// The endpoints a client uses once it holds a token. Both methods on userinfo,
	// because OpenID Connect Core §5.3.1 requires both and relying-party libraries are
	// split down the middle about which to use.
	mux.HandleFunc("GET /oauth2/userinfo", s.requireProvider(s.handleUserinfo))
	mux.HandleFunc("POST /oauth2/userinfo", s.requireProvider(s.handleUserinfo))
	mux.HandleFunc("POST /oauth2/introspect", s.requireProvider(s.handleIntrospect))
	mux.HandleFunc("POST /oauth2/revoke", s.requireProvider(s.handleRevoke))
	mux.HandleFunc("POST /oauth2/par", s.requireProvider(s.handlePushedAuthorize))

	// RP-initiated logout. Both methods: a relying party sends the browser here with a
	// GET, and the confirmation page it may land on posts back.
	mux.HandleFunc("GET /oauth2/logout", s.requireProvider(s.handleLogout))
	mux.HandleFunc("POST /oauth2/logout", s.requireProvider(s.handleLogout))

	// The device grant. The endpoint the device talks to is under /oauth2 like the rest;
	// the page a person opens is at the root, because it is read off a screen and typed
	// into a phone and every character is one somebody can get wrong.
	mux.HandleFunc("POST /oauth2/device", s.requireProvider(s.handleDeviceAuthorization))
	mux.HandleFunc("GET /device", s.requireProvider(s.requireLogin(s.handleDeviceVerification)))
	mux.HandleFunc("POST /device", s.requireProvider(s.requireLogin(s.handleDeviceVerificationSubmit)))

	mux.HandleFunc("POST /v1/authz/check", s.requireCaller(s.handleCheck))
	mux.HandleFunc("POST /v1/authz/batch-check", s.requireCaller(s.handleBatchCheck))
	mux.HandleFunc("POST /v1/authz/explain", s.requireCaller(s.handleExplain))
	mux.HandleFunc("POST /v1/authz/filter", s.requireCaller(s.handleFilter))

	mux.HandleFunc("GET /v1/users/{id}/sessions", s.requireCaller(s.requireSessions(s.handleUserSessions)))
	mux.HandleFunc("POST /v1/sessions/{id}/revoke", s.requireCaller(s.requireSessions(s.handleRevokeSession)))
	mux.HandleFunc("POST /v1/users/{id}/revoke-all", s.requireCaller(s.requireSessions(s.handleRevokeAllSessions)))

	mux.HandleFunc("GET /v1/ui/bundle", s.requireCaller(s.handleUIBundle))
	mux.HandleFunc("POST /v1/ui/resolve", s.requireCaller(s.handleUIResolve))

	// observe wraps withRequestLimits rather than the reverse, so a request rejected
	// for an oversized body is still logged and counted. A limit that silently drops
	// traffic is indistinguishable from an outage.
	return s.observe(s.withRequestLimits(mux))
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

	// Each dependency is named individually. "not ready" alone sends an operator to
	// look at everything; naming the one that failed sends them to the right place.
	checks := map[string]string{}
	ready := true
	check := func(name string, probe func(context.Context) error) {
		if probe == nil {
			checks[name] = "not configured"
			return
		}
		if err := probe(ctx); err != nil {
			checks[name] = "unreachable"
			ready = false
			// The error itself is logged rather than returned: /readyz is
			// unauthenticated, and a connection error can name hosts and users.
			s.log.Warn("readiness probe failed", "dependency", name, "error", err)
			return
		}
		checks[name] = "ok"
	}

	check("database", s.tenant.Ping)
	if s.system != nil {
		check("database_system", s.system.Ping)
	} else {
		checks["database_system"] = "not configured"
	}
	if s.cache != nil {
		check("cache:"+s.cache.Backend(), s.cache.Ping)
	} else {
		checks["cache"] = "not configured"
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
