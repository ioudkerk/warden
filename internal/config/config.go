// Package config loads, validates and exposes Warden's server configuration.
//
// Two rules govern everything here, both from SPEC §12.5 applied to the server
// itself: a missing or malformed setting is a startup error, never a runtime
// surprise; and no field defaults to a value that is less safe than the one an
// operator would have chosen deliberately.
package config

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/warden-project/warden/internal/secrets"
)

// Role is a selectable server role. SPEC §5.2: Warden ships as one binary whose
// tiers can be deployed together or separately.
type Role string

const (
	RoleAuth   Role = "auth"   // login flows, OIDC OP endpoints, SAML ACS, token issuance
	RolePDP    Role = "pdp"    // /v1/authz/* decision endpoints, bundle generation
	RoleMgmt   Role = "mgmt"   // management API, console assets, config sync
	RoleWorker Role = "worker" // audit shipping, group sync, assignment expiry, webhooks
	RoleAll    Role = "all"    // every role in one process: the single-binary default
)

// AllRoles lists the roles that RoleAll expands to.
var AllRoles = []Role{RoleAuth, RolePDP, RoleMgmt, RoleWorker}

// Environment names the deployment's posture. It gates behaviour that is acceptable
// in development and dangerous in production: plaintext issuers, discovery mode
// (SPEC §11.5) and the explain endpoint's derivation output (SPEC §10.3).
type Environment string

const (
	EnvDevelopment Environment = "dev"
	EnvStaging     Environment = "staging"
	EnvProduction  Environment = "prod"
)

// IsProduction reports whether production restrictions apply. Staging counts:
// staging holds real IdP connections and real secrets.
func (e Environment) IsProduction() bool {
	return e == EnvProduction || e == EnvStaging
}

// Config is the fully resolved server configuration.
type Config struct {
	// Environment gates production-only restrictions. Defaults to prod: an operator
	// who has not said otherwise gets the strict behaviour.
	Environment Environment `yaml:"environment"`

	// Roles selects which tiers this process serves.
	Roles []Role `yaml:"roles"`

	// Issuer is the public origin of this deployment, and the "iss" claim of every
	// token it signs. It has no default: guessing it produces tokens that no relying
	// party will accept, and silently wrong issuers are painful to debug.
	Issuer string `yaml:"issuer"`

	HTTP      HTTPConfig      `yaml:"http"`
	Database  DatabaseConfig  `yaml:"database"`
	Cache     CacheConfig     `yaml:"cache"`
	Security  SecurityConfig  `yaml:"security"`
	Email     EmailConfig     `yaml:"email"`
	Log       LogConfig       `yaml:"log"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
}

// EmailConfig configures delivery (docs/design-email.md).
//
// For three of the four flows that use it — magic link, password reset, invitation — the
// message *is* the credential, which makes this part of the authentication system rather
// than a notification feature. A deployment with email misconfigured is a deployment where
// nobody can recover an account, and the failure appears at the worst possible moment.
type EmailConfig struct {
	// Sender selects the backend: smtp, stdout or noop.
	Sender EmailSender `yaml:"sender"`

	// From is the envelope and header sender. Validated at startup, because a malformed
	// one fails every send and finding that out when somebody needs a password reset is
	// the worst possible time.
	From string `yaml:"from"`
	// ReplyTo is optional.
	ReplyTo string `yaml:"reply_to"`

	SMTP SMTPConfig `yaml:"smtp"`
}

// EmailSender names a delivery backend.
type EmailSender string

const (
	// EmailSMTP is the default and the only one a self-hoster needs.
	EmailSMTP EmailSender = "smtp"
	// EmailStdout writes the message as JSON. Development only, and refused in
	// production for the same reason discovery mode is: a setting that is harmless
	// locally and catastrophic in production should not be reachable there.
	EmailStdout EmailSender = "stdout"
	// EmailNoop accepts and discards. It exists so that a deployment which has turned
	// email off has done so deliberately, rather than by leaving SMTP misconfigured and
	// discovering it when nobody can reset a password.
	EmailNoop EmailSender = "noop"
)

// SMTPTLS selects how the SMTP connection is protected.
type SMTPTLS string

const (
	SMTPStartTLS SMTPTLS = "starttls"
	SMTPImplicit SMTPTLS = "implicit"
	// SMTPDisabled is permitted only for loopback hosts. An SMTP session in the clear
	// carries the credential these messages exist to deliver.
	SMTPDisabled SMTPTLS = "disabled"
)

// SMTPConfig configures the SMTP sender.
type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	// Password is resolved from a reference — env: or file: — the same way the KEK is,
	// so an SMTP password is never a literal in a configuration file.
	Password secrets.Secret `yaml:"password_ref"`
	TLS      SMTPTLS        `yaml:"tls"`
	Timeout  time.Duration  `yaml:"timeout"`
}

// HTTPConfig configures the public listener.
type HTTPConfig struct {
	Addr            string        `yaml:"addr"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	IdleTimeout     time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`

	// MaxRequestBytes caps request bodies. batch-check carries up to 1000 decisions
	// (SPEC §10.1), so this is generous but finite.
	MaxRequestBytes int64 `yaml:"max_request_bytes"`

	// TrustedProxyCIDRs lists the proxies whose X-Forwarded-For may be believed.
	// Empty means believe nobody, which is the safe default: context.ip feeds
	// authorization conditions (SPEC §9.6), so a spoofable client IP is a policy
	// bypass, not a logging inconvenience.
	TrustedProxyCIDRs []string `yaml:"trusted_proxy_cidrs"`
}

// DatabaseConfig configures the Postgres system of record.
type DatabaseConfig struct {
	// URL is a libpq connection string for the role that serves requests. No
	// default: there is no sensible guess, and a default pointing at localhost
	// invites a production process to come up against the wrong database.
	//
	// This role must NOT be able to bypass row-level security. Warden verifies that
	// at startup and refuses to serve production traffic if it can, because a
	// request-serving role with BYPASSRLS has tenant isolation switched off with no
	// outward symptom at all. See deploy/roles.sql.
	URL secrets.Secret `yaml:"url"`

	// SystemURL is the connection for work that is inherently cross-tenant:
	// migrations, `warden init`, and background jobs such as assignment expiry. The
	// role behind it holds BYPASSRLS, and everything it does is audited precisely
	// because the database is not constraining it (SPEC §6.2).
	//
	// Optional. Without it Warden serves tenant traffic normally and reports that
	// cross-tenant operations are unavailable, rather than quietly running them
	// through a connection that cannot see the rows.
	SystemURL secrets.Secret `yaml:"system_url"`

	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
	ConnectTimeout  time.Duration `yaml:"connect_timeout"`

	// StatementTimeout bounds any single query. The PDP hot path has a millisecond
	// budget (SPEC §18); an unbounded query is an availability incident.
	StatementTimeout time.Duration `yaml:"statement_timeout"`

	// There is deliberately no auto_migrate here. Migrations run as a separate
	// pre-upgrade job (SPEC §20.1), so that a rolling deploy cannot have several
	// replicas racing to apply them; `make migrate-up`, the compose file's migrate
	// service and CI all use the same pinned golang-migrate.
	//
	// The field existed from M0-4 to M0-11 and never had an implementation behind
	// it: it was written before migrations arrived in M0-5, as an entry in the
	// safe-defaults inventory, and nothing ever came back to connect it. A knob that
	// silently does nothing is worse than an absent one, and absent is enforced —
	// unknown keys in a config file are a startup error, so a leftover
	// `auto_migrate: true` now names its own line number instead of being ignored.
	// If a deployment story ever wants it, it should arrive with its behaviour.
}

// CacheBackend selects where sessions, the decision cache, SAML replay protection and
// the change stream live.
type CacheBackend string

const (
	// CacheRedis is the default and the only backend that works with more than one
	// process, because the change stream fans out through it (SPEC §10.5).
	CacheRedis CacheBackend = "redis"

	// CacheInProcess is the single-node escape hatch from SPEC §19. It is opt-in and
	// refused for multi-process deployments: silently degrading to a local cache
	// would break change propagation in a way that looks like stale permissions.
	CacheInProcess CacheBackend = "in-process"
)

// CacheConfig configures the cache and pub/sub tier.
type CacheConfig struct {
	Backend CacheBackend   `yaml:"backend"`
	URL     secrets.Secret `yaml:"url"`

	DialTimeout  time.Duration `yaml:"dial_timeout"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	PoolSize     int           `yaml:"pool_size"`
}

// SecurityConfig holds the settings that protect data at rest and in transit.
type SecurityConfig struct {
	// KEK references the key-encryption key: env:NAME, file:/path or kms:<uri>.
	// Required, always. See internal/secrets.
	KEK string `yaml:"kek"`

	// RetiredKEKs lists key references retained for decryption during a rotation.
	// Values encrypted under them stay readable; new values are written under KEK.
	RetiredKEKs []string `yaml:"retired_keks"`

	// TokenSigningAlgorithm is RS256 or ES256 (SPEC §8.2). Symmetric algorithms are
	// not offered: relying parties must be able to verify without a shared secret.
	TokenSigningAlgorithm string `yaml:"token_signing_algorithm"`

	// AccessTokenTTL is bounded to 5–15 minutes by SPEC §8.2, because a short token
	// lifetime is the backstop for revocation.
	AccessTokenTTL time.Duration `yaml:"access_token_ttl"`

	// KeyRotationInterval is the signing-key rotation schedule (SPEC §17).
	KeyRotationInterval time.Duration `yaml:"key_rotation_interval"`

	// SessionAbsoluteLifetime is how long a browser SSO session may live, however
	// active it is. SPEC §8.3 gives 30 days for the refresh token a session backs, and
	// the session is the artifact that outlives token refresh, so they match.
	SessionAbsoluteLifetime time.Duration `yaml:"session_absolute_lifetime"`

	// SessionIdleTimeout ends a session that has gone unused. It slides: every
	// successful validation extends it. The absolute lifetime is the ceiling that
	// sliding cannot push past, which is what stops a session living forever because
	// something polls it.
	SessionIdleTimeout time.Duration `yaml:"session_idle_timeout"`

	// RefreshTokenAbsoluteLifetime and RefreshTokenIdleLifetime bound the rotating
	// refresh chain (SPEC §8.3). The absolute figure is measured from the *first*
	// token in a family — the login — so rotation cannot extend a chain indefinitely
	// by issuing successors; the idle figure bounds the gap between rotations.
	//
	// SPEC §8.3 makes these per-application. They are deployment-wide here because
	// there is no per-application override to read yet; when applications grow one,
	// these become the default rather than the only answer.
	RefreshTokenAbsoluteLifetime time.Duration `yaml:"refresh_token_absolute_lifetime"`
	RefreshTokenIdleLifetime     time.Duration `yaml:"refresh_token_idle_lifetime"`

	// Lockout is SPEC §7.2's login rate limiting: exponential backoff per
	// (account, IP) plus a global per-account cap.
	Lockout LockoutConfig `yaml:"lockout"`

	// BreachedPasswordFile points at a Have I Been Pwned corpus — the "hash:count"
	// download, sorted by hash. SPEC §7.2 makes the breached-password check
	// mandatory, and Warden ships a small built-in list so that the check is never a
	// no-op; this is how a deployment gets real coverage.
	//
	// Optional, and checked at startup rather than at the first password change: a
	// path that does not open, or a file that is not in that format, is a
	// configuration error. The failure it prevents is the quiet one — a corpus that
	// loads and answers "not breached" to everything looks exactly like a corpus that
	// works.
	BreachedPasswordFile string `yaml:"breached_password_file"`

	// KeyOverlapWindow is how long a rotated-out key stays in JWKS after it stops
	// signing (SPEC §17's "overlap window"). It has to outlast every token the key
	// signed, so validation refuses a window shorter than the access token
	// lifetime: a shorter one produces tokens that expire *after* the key that
	// verifies them disappears, and the symptom is a burst of invalid-signature
	// errors at whichever relying party had not yet refetched JWKS.
	//
	// It also has to outlast the caching that relying parties do of their own
	// accord, which is why the default is a day rather than a quarter of an hour.
	KeyOverlapWindow time.Duration `yaml:"key_overlap_window"`
}

// LockoutConfig tunes login rate limiting (SPEC §7.2).
//
// The defaults are chosen so that somebody who has forgotten their password notices
// nothing for the first few tries, while an automated attempt is reduced to a handful of
// guesses per hour from any one source. Loosening them is a decision, which is why each
// is a setting rather than a constant.
type LockoutConfig struct {
	// FreeAttempts is how many failures an (account, IP) pair gets before any delay.
	FreeAttempts int `yaml:"free_attempts"`
	// BaseDelay is the first delay past the allowance; it doubles with each failure.
	BaseDelay time.Duration `yaml:"base_delay"`
	// MaxDelay caps the doubling, so that a user locked out by somebody else's
	// guessing has a bounded wait.
	MaxDelay time.Duration `yaml:"max_delay"`
	// PairWindow is how long pair failures are remembered.
	PairWindow time.Duration `yaml:"pair_window"`
	// AccountCap is the failures an account tolerates across every source before
	// attempts are refused outright. It is the backstop against a distributed attempt,
	// and it is generous because it is also the lever for locking somebody out on
	// purpose.
	AccountCap int `yaml:"account_cap"`
	// AccountWindow is the account counter's memory.
	AccountWindow time.Duration `yaml:"account_window"`
}

// LogConfig configures diagnostic output.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // json | text
}

// TelemetryConfig configures metrics and tracing (SPEC §16.3).
type TelemetryConfig struct {
	MetricsAddr  string  `yaml:"metrics_addr"`
	TracingOTLP  string  `yaml:"tracing_otlp_endpoint"`
	TraceSampler float64 `yaml:"trace_sample_ratio"`
}

// Defaults returns the configuration Warden starts from before a file, the
// environment or flags are applied.
//
// Every field set here is either operationally neutral or deliberately strict.
// Nothing that carries security weight — the issuer, the database URL, the KEK — has
// a default at all; those are required and produce a startup error when absent. The
// test suite asserts this property rather than trusting the reviewer to notice.
func Defaults() *Config {
	return &Config{
		Environment: EnvProduction, // strict unless an operator opts out
		Roles:       []Role{RoleAll},
		Issuer:      "", // required

		HTTP: HTTPConfig{
			Addr:            ":8080",
			ReadTimeout:     15 * time.Second,
			WriteTimeout:    30 * time.Second,
			IdleTimeout:     120 * time.Second,
			ShutdownTimeout: 30 * time.Second,
			MaxRequestBytes: 4 << 20, // 4 MiB
			// TrustedProxyCIDRs is empty: trust no proxy until told to.
		},

		Database: DatabaseConfig{
			// URL is required.
			MaxOpenConns:     25,
			MaxIdleConns:     5,
			ConnMaxLifetime:  30 * time.Minute,
			ConnectTimeout:   10 * time.Second,
			StatementTimeout: 5 * time.Second,
		},

		Email: EmailConfig{
			// noop by default. Not smtp: a default pointing at a host that is not there
			// would fail every send at run time, and the failure would look like a bug
			// rather than a deployment that has not configured email yet. Choosing noop
			// makes "email is off" a statement rather than an accident.
			Sender: EmailNoop,
			SMTP: SMTPConfig{
				Port:    587,
				TLS:     SMTPStartTLS,
				Timeout: 10 * time.Second,
			},
		},

		Cache: CacheConfig{
			Backend: CacheRedis, // the correct backend; in-process must be chosen
			// URL is required when the backend is redis.
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			PoolSize:     20,
		},

		Security: SecurityConfig{
			// KEK is required.
			TokenSigningAlgorithm: "RS256",
			AccessTokenTTL:        10 * time.Minute, // SPEC §8.2 default
			KeyRotationInterval:   90 * 24 * time.Hour,
			KeyOverlapWindow:      24 * time.Hour,

			Lockout: LockoutConfig{
				FreeAttempts:  5,
				BaseDelay:     time.Second,
				MaxDelay:      15 * time.Minute,
				PairWindow:    time.Hour,
				AccountCap:    100,
				AccountWindow: time.Hour,
			},

			SessionAbsoluteLifetime: 30 * 24 * time.Hour, // SPEC §8.3
			SessionIdleTimeout:      7 * 24 * time.Hour,  // SPEC §8.3

			RefreshTokenAbsoluteLifetime: 30 * 24 * time.Hour, // SPEC §8.3
			RefreshTokenIdleLifetime:     7 * 24 * time.Hour,  // SPEC §8.3
		},

		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},

		Telemetry: TelemetryConfig{
			MetricsAddr:  ":9090",
			TraceSampler: 0.01,
		},
	}
}

// HasRole reports whether this process serves the given role.
func (c *Config) HasRole(r Role) bool {
	for _, have := range c.Roles {
		if have == RoleAll || have == r {
			return true
		}
	}
	return false
}

// EffectiveRoles expands RoleAll and returns the roles in a stable order.
func (c *Config) EffectiveRoles() []Role {
	seen := map[Role]bool{}
	for _, r := range c.Roles {
		if r == RoleAll {
			for _, a := range AllRoles {
				seen[a] = true
			}
			continue
		}
		seen[r] = true
	}
	out := make([]Role, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Keyring builds the envelope-encryption keyring from the resolved KEK references.
func (c *Config) Keyring(lookupEnv secrets.LookupEnvFunc, readFile secrets.ReadFileFunc) (*secrets.Keyring, error) {
	active, err := secrets.ResolveKEK(c.Security.KEK, lookupEnv, readFile)
	if err != nil {
		return nil, err
	}
	retired := make([]secrets.KEK, 0, len(c.Security.RetiredKEKs))
	for _, ref := range c.Security.RetiredKEKs {
		k, err := secrets.ResolveKEK(ref, lookupEnv, readFile)
		if err != nil {
			return nil, fmt.Errorf("retired key: %w", err)
		}
		retired = append(retired, k)
	}
	return secrets.NewKeyring(active, retired...)
}

// String renders the configuration for diagnostics. Secrets redact themselves; this
// method exists so that logging a whole Config is a safe thing to do.
func (c *Config) String() string {
	roles := make([]string, 0, len(c.Roles))
	for _, r := range c.Roles {
		roles = append(roles, string(r))
	}
	return fmt.Sprintf(
		"Config{environment=%s roles=%s issuer=%s http=%s database=%v cache=%s/%v log=%s/%s}",
		c.Environment, strings.Join(roles, ","), c.Issuer, c.HTTP.Addr,
		c.Database.URL, c.Cache.Backend, c.Cache.URL, c.Log.Level, c.Log.Format)
}
