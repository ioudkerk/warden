// Command warden is the Warden server: one binary whose roles are selected at
// startup (SPEC §5.2).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/cache"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/decisionlog"
	"github.com/warden-project/warden/internal/httpapi"
	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/metrics"
	"github.com/warden-project/warden/internal/oidcop"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always --dirty)"
//
// It defaults to the module's build info so a `go install` build still reports
// something truthful.
var version = ""

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, config.ErrHelpRequested) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "warden: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	command, rest := splitCommand(args)

	switch command {
	case "version":
		fmt.Fprintln(stdout, buildVersion())
		return nil

	case "help", "-h", "--help":
		usage(stdout)
		return nil

	case "config":
		return runConfigCheck(rest, stdout, stderr)

	case "serve":
		return runServe(rest, stdout, stderr)

	case "init":
		return runInit(rest, stdout, stderr)
	case "seed":
		return runSeed(rest, stdout, stderr)
	case "apply":
		return runApply(rest, stdout, stderr)
	case "tenant":
		return runTenant(rest, stdout, stderr)
	case "user":
		return runUser(rest, stdout, stderr)
	case "grant":
		return runGrant(rest, stdout, stderr)
	case "resource":
		return runResource(rest, stdout, stderr)
	case "token":
		return runToken(rest, stdout, stderr)
	case "ui":
		return runUI(rest, stdout, stderr)
	case "audit":
		return runAudit(rest, stdout, stderr)
	case "keys":
		return runKeys(rest, stdout, stderr)
	case "password":
		return runPassword(rest, stdout, stderr)
	case "client":
		return runClient(rest, stdout, stderr)

	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", command)
	}
}

// splitCommand separates the subcommand from its arguments. With no arguments at
// all, or with only flags, the command is "serve" — running the server is what the
// binary is for.
func splitCommand(args []string) (command string, rest []string) {
	if len(args) == 0 {
		return "serve", nil
	}
	if args[0] == "" || args[0][0] == '-' {
		return "serve", args
	}
	return args[0], args[1:]
}

// runConfigCheck resolves the configuration and prints it. Everything it prints is
// safe to paste into an issue: secrets redact themselves.
//
// This is the command an operator runs before a deploy, and the first half of the
// `warden doctor` described in SPEC §12.5.
func runConfigCheck(args []string, stdout, stderr io.Writer) error {
	cfg, err := config.Load(config.Source{
		Args:      args,
		LookupEnv: os.LookupEnv,
		ReadFile:  os.ReadFile,
		Stderr:    stderr,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "configuration is valid\n\n")
	fmt.Fprintf(stdout, "  environment  %s\n", cfg.Environment)
	fmt.Fprintf(stdout, "  roles        %v\n", cfg.EffectiveRoles())
	fmt.Fprintf(stdout, "  issuer       %s\n", cfg.Issuer)
	fmt.Fprintf(stdout, "  http         %s\n", cfg.HTTP.Addr)
	fmt.Fprintf(stdout, "  database     %s\n", cfg.Database.URL)
	fmt.Fprintf(stdout, "  cache        %s %s\n", cfg.Cache.Backend, cfg.Cache.URL)
	if cfg.Database.SystemURL.IsZero() {
		fmt.Fprintf(stdout, "  system db    not configured — migrations, bootstrap and cross-tenant jobs are unavailable\n")
	} else {
		fmt.Fprintf(stdout, "  system db    %s\n", cfg.Database.SystemURL)
	}

	// The keyring was already built during validation; building it again here is
	// cheap and lets the command report which key is active, which is what an
	// operator checks after a rotation.
	keyring, err := cfg.Keyring(secrets.OSLookupEnv, secrets.OSReadFile)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "  kek          active %s (%d loaded)\n", keyring.ActiveKeyID(), len(keyring.KeyIDs()))
	return nil
}

func runServe(args []string, stdout, stderr io.Writer) error {
	cfg, err := config.Load(config.Source{
		Args:      args,
		LookupEnv: os.LookupEnv,
		ReadFile:  os.ReadFile,
		Stderr:    stderr,
	})
	if err != nil {
		return err
	}

	log := newLogger(cfg, stdout)
	keyring, err := cfg.Keyring(secrets.OSLookupEnv, secrets.OSReadFile)
	if err != nil {
		return err
	}

	log.Info("starting warden",
		"version", buildVersion(),
		"environment", string(cfg.Environment),
		"roles", cfg.EffectiveRoles(),
		"issuer", cfg.Issuer,
		"kek_active", keyring.ActiveKeyID(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Built before the pools, because a store's retry observer must be installed
	// before anything can run a transaction through it — the decision log below
	// starts a writer goroutine, and assigning the observer afterwards would be a
	// data race against it.
	metricSet := metrics.New(buildVersion())

	// Opening the pool verifies that the request-serving role cannot bypass
	// row-level security, and refuses to continue in production if it can. That
	// check has to happen before anything serves traffic: a deployment with the
	// wrong role has no tenant isolation and no symptom.
	db, err := store.Open(ctx, cfg, store.TenantScoped)
	if err != nil {
		return err
	}
	defer db.Close()
	observeRetries(db, metricSet, log, "tenant-scoped")

	log.Info("database connected", "role", db.Role(), "access", db.Access().String())
	if warning := db.IsolationWarning(); warning != "" {
		log.Warn("TENANT ISOLATION IS NOT ENFORCED BY THE DATABASE", "detail", warning)
	}

	// The system pool is what authentication needs: resolving a service-account
	// token to its tenant happens before any tenant scope exists.
	var system *store.Store
	if !cfg.Database.SystemURL.IsZero() {
		system, err = store.Open(ctx, cfg, store.SystemAccess)
		if err != nil {
			return err
		}
		defer system.Close()
		observeRetries(system, metricSet, log, "system")
		log.Info("system database connected", "role", system.Role())
	}

	// Signing keys are deployment-level, so key management needs the system pool.
	// Without one, this process can neither publish JWKS nor sign a token; it says so
	// once at startup rather than failing per request.
	var keyManager *keys.Manager
	if system != nil {
		keyManager, err = keys.NewManager(system, keyring, cfg, log)
		if err != nil {
			return err
		}
		if cfg.HasRole(config.RoleWorker) {
			go keyManager.RunRotation(ctx)
		}
	} else if cfg.HasRole(config.RoleAuth) {
		log.Warn("no token signing: database.system_url is not configured, " +
			"so JWKS is not published and no token can be issued")
	}

	if !cfg.HasRole(config.RolePDP) {
		log.Warn("no listener: this process serves no role that has endpoints yet",
			"roles", cfg.EffectiveRoles())
		<-ctx.Done()
		return nil
	}

	// The decision log writes through the system pool. Without one it is simply
	// absent, and the server says so rather than silently recording nothing.
	var decisions *decisionlog.Sink
	if system != nil {
		decisions, err = decisionlog.New(system, log, decisionlog.Options{})
		if err != nil {
			return err
		}
		defer func() {
			drainCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
			defer cancel()
			if closeErr := decisions.Close(drainCtx); closeErr != nil {
				log.Warn("the decision log did not drain before shutdown", "error", closeErr)
			}
			stats := decisions.Stats()
			log.Info("decision log stopped",
				"written", stats.Written.Load(), "dropped", stats.Dropped.Load(),
				"failed", stats.Failed.Load())
		}()
	} else {
		log.Warn("no decision log: database.system_url is not configured, so decisions are not recorded")
	}

	tracing, err := metrics.StartTracing(ctx, cfg.Telemetry.TracingOTLP, buildVersion(),
		cfg.Telemetry.TraceSampler, log)
	if err != nil {
		return err
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if flushErr := tracing.Shutdown(flushCtx); flushErr != nil {
			log.Warn("flushing traces", "error", flushErr)
		}
	}()

	// The cache is opened eagerly: an unreachable one should stop the process coming
	// up, not surface later as a request that needed it.
	cacheClient, err := cache.Open(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := cacheClient.Close(); closeErr != nil {
			log.Warn("closing the cache", "error", closeErr)
		}
	}()
	log.Info("cache connected", "backend", cacheClient.Backend())

	// Sessions need the cache tier for validity and the mirror for the active-sessions
	// list, so they are built after both. Without the system pool the mirror cannot be
	// purged and revocations cannot be audited, which is a degraded session store
	// rather than none — it is built either way and says what is missing.
	sessions, err := authn.NewSessions(db, system, cacheClient, authn.SessionOptions{
		AbsoluteLifetime: cfg.Security.SessionAbsoluteLifetime,
		IdleTimeout:      cfg.Security.SessionIdleTimeout,
		Log:              log,
		Audit:            audit.NewWriter(),
	})
	if err != nil {
		return err
	}
	if system == nil {
		log.Warn("session revocations will not be audited and expired sessions will not be " +
			"purged: database.system_url is not configured")
	}

	// Refresh tokens hang off sessions, so they are built after them. There is no
	// refresh endpoint yet — the token endpoint arrives with the OIDC provider in
	// M1-6 — so the only thing that drives this today is the purge below. Building it
	// here rather than at M1-6 keeps the wiring in one place and gives the mirrors a
	// sweeper from the moment they start filling.
	refreshTokens, err := authn.NewRefreshTokens(db, system, sessions, authn.RefreshTokenOptions{
		AbsoluteLifetime: cfg.Security.RefreshTokenAbsoluteLifetime,
		IdleLifetime:     cfg.Security.RefreshTokenIdleLifetime,
		Log:              log,
		Audit:            audit.NewWriter(),
		Metrics:          metricSet,
	})
	if err != nil {
		return err
	}

	if cfg.HasRole(config.RoleWorker) && system != nil {
		go authn.RunPurge(ctx, sessions, refreshTokens, log)
	}

	// The interactive login: password verification, and the rate limiting that must be
	// in front of it before any endpoint exposes it (M1-3).
	//
	// Opening the breached-password corpus here is also what validates it, and the
	// failure it catches is the quiet one: a file in the wrong format loads happily and
	// answers "not breached" to everything, turning the one mandatory check in
	// SPEC §7.2 into a no-op that looks like it is working. Until this commit the
	// corpus was opened and closed at startup purely for that check, because nothing
	// served a login; now something does.
	//
	// The limiter's pepper is
	// KEK-derived so every replica keys its counters the same way — a per-process
	// pepper would give each one its own key space and multiply the effective limit.
	breached, closeBreached, err := openBreachSet(cfg, stderr)
	if err != nil {
		return err
	}
	defer closeBreached()

	authenticator, err := authn.New(db, system, authn.Options{
		Breached: breached,
		Log:      log,
		Audit:    audit.NewWriter(),
	})
	if err != nil {
		return err
	}

	lockoutPepper, err := keyring.Derive("warden/login-lockout/pepper", 32)
	if err != nil {
		return err
	}
	lockout, err := authn.NewLockout(cacheClient, authn.LockoutOptions{
		Policy: authn.LockoutPolicy{
			FreeAttempts:  cfg.Security.Lockout.FreeAttempts,
			BaseDelay:     cfg.Security.Lockout.BaseDelay,
			MaxDelay:      cfg.Security.Lockout.MaxDelay,
			PairWindow:    cfg.Security.Lockout.PairWindow,
			AccountCap:    cfg.Security.Lockout.AccountCap,
			AccountWindow: cfg.Security.Lockout.AccountWindow,
		},
		Log:    log,
		Pepper: lockoutPepper,
	})
	if err != nil {
		return err
	}

	// The OpenID Provider. It needs the client registry, the storage adapter over both
	// pools, the refresh-token store (so a replayed token still revokes its family) and
	// the signing keys.
	var provider *oidcop.Provider
	if system != nil && keyManager != nil {
		// One set of parameters for both: the registry hashes client secrets with
		// them and the provider verifies with them, and two copies would eventually be
		// two different values.
		clientParams := authn.DefaultParams()
		clients, clientErr := oidcop.NewClients(db, system, clientParams)
		if clientErr != nil {
			return clientErr
		}
		providerStorage, storageErr := oidcop.NewStorage(db, system, clients, oidcop.StorageOptions{
			Refresh: refreshTokens, Sessions: sessions, Log: log,
		})
		if storageErr != nil {
			return storageErr
		}
		providerOpts, optErr := oidcop.ProviderOptionsFrom(cfg, keyManager, keyring, clientParams, log)
		if optErr != nil {
			return optErr
		}
		if provider, err = oidcop.NewProvider(providerStorage, providerOpts); err != nil {
			return err
		}
		log.Info("OpenID Provider ready", "issuer", cfg.Issuer)
	} else if cfg.HasRole(config.RoleAuth) {
		log.Warn("no OpenID Provider: it needs database.system_url and a signing key")
	}

	server, err := httpapi.New(httpapi.Deps{
		Config: cfg, Log: log,
		Tenant: db, System: system,
		Decisions: decisions, Metrics: metricSet, Cache: cacheClient, Tracing: tracing,
		Keys: keyManager, Sessions: sessions, Provider: provider,
		Authn: authenticator, Lockout: lockout,
	})
	if err != nil {
		return err
	}

	// The metrics listener and the API run together; either failing stops the other,
	// because a process serving decisions with no way to observe them is not a
	// healthy state to leave running.
	errs := make(chan error, 2)
	go func() { errs <- metricSet.Serve(ctx, cfg.Telemetry.MetricsAddr, log) }()
	go func() { errs <- server.ListenAndServe(ctx) }()

	if err := <-errs; err != nil {
		return err
	}
	return <-errs
}

// observeRetries points a store's transaction retries at Prometheus and the log.
//
// A retry is invisible to the caller by design — the transaction succeeds and nothing
// upstream knows it ran twice — so without this the only symptom of rising lock
// contention is latency nobody can explain. Retries are logged at debug because a
// handful are normal; an exhausted budget is a warning, because that one reached the
// user as an error.
//
// Must be called before the store serves anything: it assigns a field that every
// subsequent transaction reads.
func observeRetries(s *store.Store, m *metrics.Metrics, log *slog.Logger, pool string) {
	s.SetRetryObserver(func(info store.RetryInfo) {
		if info.Exhausted {
			m.StoreRetriesExhausted.WithLabelValues(info.Code).Inc()
			log.Warn("a transaction exhausted its retry budget",
				"pool", pool, "sqlstate", info.Code, "attempts", info.Attempt, "error", info.Err)
			return
		}
		m.StoreRetries.WithLabelValues(info.Code).Inc()
		log.Debug("retrying a transaction PostgreSQL aborted as transient",
			"pool", pool, "sqlstate", info.Code, "attempt", info.Attempt, "delay", info.Delay)
	})
}

func newLogger(cfg *config.Config, out io.Writer) *slog.Logger {
	var level slog.Level
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	if cfg.Log.Format == "text" {
		return slog.New(slog.NewTextHandler(out, opts))
	}
	return slog.New(slog.NewJSONHandler(out, opts))
}

func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "devel"
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `warden %s — identity and fine-grained authorization

Usage:
  warden [serve] [flags]   run the server (default)
  warden config [flags]    resolve and validate the configuration, then print it
  warden version           print the build version
  warden help              print this message

Administration (until the console arrives in M6). Each needs database.system_url:
  warden init -owner <email>                   bootstrap a fresh deployment; prints a one-time URL
  warden apply -f <manifest.yaml>              publish an application's permission surface
  warden seed [-f examples/warden.yaml]        development fixture: the billing app, a demo
                                               tenant and SPEC §9.9's users and invoices.
                                               Idempotent; refused in production
  warden tenant -slug <slug>                   create a tenant
  warden user -tenant <slug> -email <email>    create a user, printing its subject id
  warden grant -tenant <slug> -user <id> -role <key> [-scope <scope>] [-as <assigner>] [-until <ts>]
  warden grant -tenant <slug> -revoke <id>     remove a grant
  warden resource -tenant <slug> -ref <app.type:id> [-parent <ref>] [-attributes <json>]
  warden token -tenant <slug> -name <name>     mint a service-account token, shown once
  warden ui -tenant <slug> -application <key> -element <key> -requires <json> [-mode <mode>]
  warden audit [-tenant <slug>] [-limit N]     show recent administrative changes
  warden audit -verify                         recompute the hash chain; non-zero exit if broken
  warden keys list                             show every signing key and what is published
  warden keys show                             the active key and when it rotates
  warden keys rotate [-force]                  rotate now; the previous key keeps verifying
                                               for security.key_overlap_window
  warden password redeem -token <token>        finish "warden init": set the first owner's
                                               password from the one-time setup link
  warden password set -tenant <slug> -email <email>
                                               set a user's password
  warden password policy -tenant <slug> [-min-length N] [-check-breached false] ...
                                               show or change a tenant's password policy
  warden client register -tenant <slug> -key <key> -redirect-uri <uri> [-confidential]
                                               register an OAuth/OIDC client. Public by
                                               default; PKCE is required either way
  warden client list|show|secret|disable|enable|delete -tenant <slug> [-key <key>]
                                               manage registered clients

The password subcommands read the password from standard input, never from a flag:
arguments are visible in "ps" and land in shell history.
  printf '%%s' "$PASSWORD" | warden password redeem -token ...

Configuration is read from a file, then the environment, then flags, each layer
overriding the one before it. The file is selected with -config or WARDEN_CONFIG.

Flags:
`, buildVersion())
	config.Usage(w)
}
