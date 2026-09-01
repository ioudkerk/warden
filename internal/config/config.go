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
	Log       LogConfig       `yaml:"log"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
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

	// AutoMigrate runs pending migrations at startup. Off by default: SPEC §20.1
	// runs migrations as a separate pre-upgrade job so that a rolling deploy cannot
	// have several replicas racing to migrate.
	AutoMigrate bool `yaml:"auto_migrate"`
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
			AutoMigrate:      false,
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
