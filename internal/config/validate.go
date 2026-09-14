package config

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/warden-project/warden/internal/secrets"
)

// Errors collects every configuration problem found in one pass. Reporting one
// problem at a time turns first-run setup into a guessing game; an operator should
// see the whole list and fix it once.
type Errors struct {
	Problems []Problem
}

// Problem is a single configuration failure, named by the setting that caused it and
// carrying how to set it.
type Problem struct {
	Field  string // the YAML path, e.g. "security.kek"
	Flag   string // the equivalent command-line flag, if there is one
	Env    string // the equivalent environment variable, if there is one
	Detail string // what is wrong, in the imperative
}

func (e *Errors) Error() string {
	if len(e.Problems) == 1 {
		return "invalid configuration: " + e.Problems[0].String()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "invalid configuration: %d problems\n", len(e.Problems))
	for _, p := range e.Problems {
		fmt.Fprintf(&b, "  - %s\n", p.String())
	}
	return strings.TrimRight(b.String(), "\n")
}

func (p Problem) String() string {
	s := p.Field + ": " + p.Detail
	switch {
	case p.Flag != "" && p.Env != "":
		s += fmt.Sprintf(" (set -%s or %s)", p.Flag, p.Env)
	case p.Env != "":
		s += fmt.Sprintf(" (set %s)", p.Env)
	case p.Flag != "":
		s += fmt.Sprintf(" (set -%s)", p.Flag)
	}
	return s
}

// Empty reports whether validation found nothing.
func (e *Errors) Empty() bool { return len(e.Problems) == 0 }

func (e *Errors) add(field, detail string) {
	p := Problem{Field: field, Detail: detail}
	// Attach the flag and environment variable from the binding table, so the
	// message always tells the operator how to fix the setting and the two can never
	// drift apart.
	if f, ok := fieldFor(field); ok {
		p.Flag, p.Env = f.flag, f.env
	}
	e.Problems = append(e.Problems, p)
}

// fieldToBinding maps a YAML path to its flag/env binding.
var fieldToBinding = map[string]string{
	"environment":                      "environment",
	"roles":                            "roles",
	"issuer":                           "issuer",
	"http.addr":                        "http-addr",
	"http.max_request_bytes":           "http-max-request-bytes",
	"http.trusted_proxy_cidrs":         "http-trusted-proxy-cidrs",
	"http.read_timeout":                "http-read-timeout",
	"http.write_timeout":               "http-write-timeout",
	"http.shutdown_timeout":            "http-shutdown-timeout",
	"database.url":                     "database-url",
	"database.system_url":              "database-system-url",
	"database.max_open_conns":          "database-max-open-conns",
	"database.max_idle_conns":          "database-max-idle-conns",
	"database.statement_timeout":       "database-statement-timeout",
	"cache.backend":                    "cache-backend",
	"cache.url":                        "cache-url",
	"cache.pool_size":                  "cache-pool-size",
	"security.kek":                     "security-kek",
	"security.retired_keks":            "security-retired-keks",
	"security.token_signing_algorithm": "security-token-signing-algorithm",
	"security.access_token_ttl":        "security-access-token-ttl",
	"security.key_rotation_interval":   "security-key-rotation-interval",
	"log.level":                        "log-level",
	"log.format":                       "log-format",
	"telemetry.trace_sample_ratio":     "trace-sample-ratio",
}

func fieldFor(yamlPath string) (field, bool) {
	flagName, ok := fieldToBinding[yamlPath]
	if !ok {
		return field{}, false
	}
	for _, f := range fields() {
		if f.flag == flagName {
			return f, true
		}
	}
	return field{}, false
}

// Validate checks the resolved configuration and resolves the secrets it references.
// It returns *Errors listing every problem, so one run of the server reports every
// missing setting rather than one per restart.
//
// Resolving the KEK here is deliberate: a key that cannot be read is a startup
// failure, not an error thrown the first time a client secret needs encrypting.
func (c *Config) Validate(lookupEnv secrets.LookupEnvFunc, readFile secrets.ReadFileFunc) error {
	errs := &Errors{}

	c.validateEnvironment(errs)
	c.validateRoles(errs)
	c.validateIssuer(errs)
	c.validateHTTP(errs)
	c.validateDatabase(errs)
	c.validateCache(errs)
	c.validateSecurity(errs, lookupEnv, readFile)
	c.validateLog(errs)
	c.validateTelemetry(errs)

	if errs.Empty() {
		return nil
	}
	sort.SliceStable(errs.Problems, func(i, j int) bool { return errs.Problems[i].Field < errs.Problems[j].Field })
	return errs
}

func (c *Config) validateEnvironment(errs *Errors) {
	switch c.Environment {
	case EnvDevelopment, EnvStaging, EnvProduction:
	case "":
		errs.add("environment", "must be set to dev, staging or prod")
	default:
		errs.add("environment", fmt.Sprintf("%q is not a known environment; want dev, staging or prod", c.Environment))
	}
}

func (c *Config) validateRoles(errs *Errors) {
	if len(c.Roles) == 0 {
		errs.add("roles", "at least one role must be selected")
		return
	}
	seen := map[Role]bool{}
	hasAll := false
	for _, r := range c.Roles {
		switch r {
		case RoleAuth, RolePDP, RoleMgmt, RoleWorker:
		case RoleAll:
			hasAll = true
		default:
			errs.add("roles", fmt.Sprintf("%q is not a known role; want auth, pdp, mgmt, worker or all", r))
			continue
		}
		if seen[r] {
			errs.add("roles", fmt.Sprintf("role %q is listed twice", r))
		}
		seen[r] = true
	}
	if hasAll && len(c.Roles) > 1 {
		errs.add("roles", "\"all\" already includes every role and cannot be combined with others")
	}
}

func (c *Config) validateIssuer(errs *Errors) {
	if c.Issuer == "" {
		errs.add("issuer", "must be set to this deployment's public origin, e.g. https://warden.example.com")
		return
	}
	u, err := url.Parse(c.Issuer)
	if err != nil {
		errs.add("issuer", fmt.Sprintf("%q is not a valid URL: %v", c.Issuer, err))
		return
	}
	switch {
	case u.Host == "":
		errs.add("issuer", fmt.Sprintf("%q has no host", c.Issuer))
	case u.Scheme == "http":
		// OIDC Discovery requires https for the issuer. Plaintext is tolerable on a
		// developer's laptop and nowhere else.
		if c.Environment.IsProduction() {
			errs.add("issuer", fmt.Sprintf(
				"%q uses http; the issuer must be https outside the dev environment, because tokens and discovery are served from it", c.Issuer))
		}
	case u.Scheme != "https":
		errs.add("issuer", fmt.Sprintf("%q must use https (got scheme %q)", c.Issuer, u.Scheme))
	}
	if u.RawQuery != "" || u.Fragment != "" {
		errs.add("issuer", "must not contain a query string or fragment; OIDC discovery appends to it directly")
	}
	// Normalise: the issuer is compared byte-for-byte against the "iss" claim by
	// relying parties, so a stray trailing slash is a real interoperability bug.
	c.Issuer = strings.TrimRight(c.Issuer, "/")
}

func (c *Config) validateHTTP(errs *Errors) {
	if c.HTTP.Addr == "" {
		errs.add("http.addr", "must be a listen address, e.g. :8080")
	} else if _, _, err := net.SplitHostPort(c.HTTP.Addr); err != nil {
		errs.add("http.addr", fmt.Sprintf("%q is not a host:port listen address: %v", c.HTTP.Addr, err))
	}
	if c.HTTP.MaxRequestBytes <= 0 {
		errs.add("http.max_request_bytes", "must be positive; an unbounded request body is a denial-of-service vector")
	}
	for _, cidr := range c.HTTP.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			errs.add("http.trusted_proxy_cidrs", fmt.Sprintf("%q is not a CIDR block: %v", cidr, err))
		}
	}
	for name, d := range map[string]time.Duration{
		"http.read_timeout":     c.HTTP.ReadTimeout,
		"http.write_timeout":    c.HTTP.WriteTimeout,
		"http.shutdown_timeout": c.HTTP.ShutdownTimeout,
	} {
		if d <= 0 {
			errs.add(name, "must be positive")
		}
	}
}

func (c *Config) validateDatabase(errs *Errors) {
	if c.Database.URL.IsZero() {
		errs.add("database.url", "must be set to a PostgreSQL connection string")
	} else {
		u, err := url.Parse(c.Database.URL.Expose())
		switch {
		case err != nil:
			// The error from url.Parse can quote the input, which may embed a
			// password. Report the failure without it.
			errs.add("database.url", "is not a valid PostgreSQL URL")
		case u.Scheme != "postgres" && u.Scheme != "postgresql":
			errs.add("database.url", fmt.Sprintf("must use the postgres:// or postgresql:// scheme (got %q)", u.Scheme))
		case u.Host == "":
			errs.add("database.url", "has no host")
		}
	}
	// Optional, but if given it must be well-formed: discovering at bootstrap that
	// the system connection string is malformed is discovering it too late.
	if !c.Database.SystemURL.IsZero() {
		u, err := url.Parse(c.Database.SystemURL.Expose())
		switch {
		case err != nil:
			errs.add("database.system_url", "is not a valid PostgreSQL URL")
		case u.Scheme != "postgres" && u.Scheme != "postgresql":
			errs.add("database.system_url", fmt.Sprintf("must use the postgres:// or postgresql:// scheme (got %q)", u.Scheme))
		case u.Host == "":
			errs.add("database.system_url", "has no host")
		}
		if c.Database.SystemURL.Expose() == c.Database.URL.Expose() && c.Environment.IsProduction() {
			errs.add("database.system_url",
				"is identical to database.url; the two must be different roles or row-level security is not enforced (see deploy/roles.sql)")
		}
	}

	if c.Database.MaxOpenConns <= 0 {
		errs.add("database.max_open_conns", "must be positive")
	}
	if c.Database.MaxIdleConns < 0 {
		errs.add("database.max_idle_conns", "must not be negative")
	}
	if c.Database.MaxIdleConns > c.Database.MaxOpenConns && c.Database.MaxOpenConns > 0 {
		errs.add("database.max_idle_conns", fmt.Sprintf(
			"is %d, which exceeds max_open_conns of %d", c.Database.MaxIdleConns, c.Database.MaxOpenConns))
	}
	if c.Database.StatementTimeout <= 0 {
		errs.add("database.statement_timeout", "must be positive; an unbounded query stalls the decision path")
	}
}

func (c *Config) validateCache(errs *Errors) {
	switch c.Cache.Backend {
	case CacheRedis:
		if c.Cache.URL.IsZero() {
			errs.add("cache.url", "must be set to a Redis connection string when the backend is redis")
		} else if u, err := url.Parse(c.Cache.URL.Expose()); err != nil {
			errs.add("cache.url", "is not a valid Redis URL")
		} else if u.Scheme != "redis" && u.Scheme != "rediss" {
			errs.add("cache.url", fmt.Sprintf("must use the redis:// or rediss:// scheme (got %q)", u.Scheme))
		}
	case CacheInProcess:
		// An in-process cache cannot fan out change events (SPEC §10.5), so a
		// multi-replica deployment using it would serve stale permissions after a
		// revocation — the exact failure the change stream exists to prevent.
		if c.Environment == EnvProduction {
			errs.add("cache.backend", "in-process is single-node only and cannot propagate permission changes between replicas; use redis in production")
		}
		if !c.Cache.URL.IsZero() {
			errs.add("cache.url", "must not be set when the backend is in-process")
		}
	case "":
		errs.add("cache.backend", "must be set to redis or in-process")
	default:
		errs.add("cache.backend", fmt.Sprintf("%q is not a known backend; want redis or in-process", c.Cache.Backend))
	}
	if c.Cache.PoolSize <= 0 && c.Cache.Backend == CacheRedis {
		errs.add("cache.pool_size", "must be positive")
	}
}

func (c *Config) validateSecurity(errs *Errors, lookupEnv secrets.LookupEnvFunc, readFile secrets.ReadFileFunc) {
	// The KEK is resolved, not merely checked for presence: a reference that points
	// at a missing file or a malformed key must fail now, at startup, and not later
	// when the first IdP client secret needs to be written.
	if c.Security.KEK == "" {
		errs.add("security.kek", "must reference the key-encryption key, e.g. env:WARDEN_KEK or file:/etc/warden/kek")
	} else if _, err := c.Keyring(lookupEnv, readFile); err != nil {
		errs.add("security.kek", err.Error())
	}

	switch c.Security.TokenSigningAlgorithm {
	case "RS256", "ES256":
	case "":
		errs.add("security.token_signing_algorithm", "must be RS256 or ES256")
	default:
		errs.add("security.token_signing_algorithm", fmt.Sprintf(
			"%q is not supported; want RS256 or ES256. Symmetric algorithms are not offered because relying parties must verify without a shared secret",
			c.Security.TokenSigningAlgorithm))
	}

	// SPEC §8.2 bounds the access token lifetime at 5–15 minutes. The lower bound
	// keeps refresh traffic sane; the upper bound is what makes revocation timely,
	// so it is enforced rather than advised.
	const minTTL, maxTTL = 5 * time.Minute, 15 * time.Minute
	if c.Security.AccessTokenTTL < minTTL || c.Security.AccessTokenTTL > maxTTL {
		errs.add("security.access_token_ttl", fmt.Sprintf(
			"is %s; must be between %s and %s, because token lifetime is the backstop for revocation (SPEC §8.2)",
			c.Security.AccessTokenTTL, minTTL, maxTTL))
	}

	if c.Security.KeyRotationInterval <= 0 {
		errs.add("security.key_rotation_interval", "must be positive")
	} else if c.Security.KeyRotationInterval > 365*24*time.Hour {
		errs.add("security.key_rotation_interval", fmt.Sprintf(
			"is %s; signing keys must rotate at least yearly (SPEC §17)", c.Security.KeyRotationInterval))
	}

	switch {
	case c.Security.SessionAbsoluteLifetime <= 0:
		errs.add("security.session_absolute_lifetime", "must be positive")
	case c.Security.SessionIdleTimeout <= 0:
		errs.add("security.session_idle_timeout", "must be positive")
	case c.Security.SessionIdleTimeout > c.Security.SessionAbsoluteLifetime:
		// Not merely redundant: an idle timeout above the absolute lifetime reads as
		// "sessions last a week of inactivity" while the absolute ceiling quietly ends
		// them sooner, so the setting that appears to govern does not.
		errs.add("security.session_idle_timeout", fmt.Sprintf(
			"is %s, longer than security.session_absolute_lifetime (%s); the absolute "+
				"lifetime would end every session first, making this setting inert",
			c.Security.SessionIdleTimeout, c.Security.SessionAbsoluteLifetime))
	}

	switch {
	case c.Security.RefreshTokenAbsoluteLifetime <= 0:
		errs.add("security.refresh_token_absolute_lifetime", "must be positive")
	case c.Security.RefreshTokenIdleLifetime <= 0:
		errs.add("security.refresh_token_idle_lifetime", "must be positive")
	case c.Security.RefreshTokenIdleLifetime > c.Security.RefreshTokenAbsoluteLifetime:
		errs.add("security.refresh_token_idle_lifetime", fmt.Sprintf(
			"is %s, longer than security.refresh_token_absolute_lifetime (%s); the absolute "+
				"lifetime would end every chain first, making this setting inert",
			c.Security.RefreshTokenIdleLifetime, c.Security.RefreshTokenAbsoluteLifetime))
	}

	// The overlap window is what makes rotation invisible to relying parties. Too
	// short and it stops being an overlap: a token signed a moment before the
	// rotation outlives the key that verifies it. Too long and a key that has been
	// taken out of service keeps verifying tokens for longer than anybody intended,
	// which is the same thing as not having rotated.
	switch {
	case c.Security.KeyOverlapWindow <= 0:
		errs.add("security.key_overlap_window", "must be positive")
	case c.Security.KeyOverlapWindow < c.Security.AccessTokenTTL:
		errs.add("security.key_overlap_window", fmt.Sprintf(
			"is %s, shorter than security.access_token_ttl (%s); a rotated-out key must stay in JWKS "+
				"for at least as long as the tokens it signed remain valid (SPEC §17)",
			c.Security.KeyOverlapWindow, c.Security.AccessTokenTTL))
	case c.Security.KeyOverlapWindow >= c.Security.KeyRotationInterval:
		errs.add("security.key_overlap_window", fmt.Sprintf(
			"is %s, and security.key_rotation_interval is %s; an overlap at least as long as the "+
				"rotation interval means keys are never actually retired",
			c.Security.KeyOverlapWindow, c.Security.KeyRotationInterval))
	}
}

func (c *Config) validateLog(errs *Errors) {
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs.add("log.level", fmt.Sprintf("%q is not a log level; want debug, info, warn or error", c.Log.Level))
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		errs.add("log.format", fmt.Sprintf("%q is not a log format; want json or text", c.Log.Format))
	}
}

func (c *Config) validateTelemetry(errs *Errors) {
	if c.Telemetry.MetricsAddr != "" {
		if _, _, err := net.SplitHostPort(c.Telemetry.MetricsAddr); err != nil {
			errs.add("telemetry.metrics_addr", fmt.Sprintf("%q is not a host:port listen address", c.Telemetry.MetricsAddr))
		}
	}
	if c.Telemetry.TraceSampler < 0 || c.Telemetry.TraceSampler > 1 {
		errs.add("telemetry.trace_sample_ratio", fmt.Sprintf("is %v; must be between 0.0 and 1.0", c.Telemetry.TraceSampler))
	}
}
