package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/warden-project/warden/internal/secrets"
)

// ErrHelpRequested is returned when the user asked for usage rather than a run.
var ErrHelpRequested = errors.New("help requested")

// Source supplies everything Load reads, so tests never touch the real process
// environment, filesystem or argv.
type Source struct {
	Args      []string // command-line arguments, excluding the program name
	LookupEnv secrets.LookupEnvFunc
	ReadFile  secrets.ReadFileFunc
	Stderr    io.Writer // where flag usage is written
}

// OSSource reads from the real process.
func OSSource(args []string) Source {
	return Source{
		Args:      args,
		LookupEnv: os.LookupEnv,
		ReadFile:  os.ReadFile,
		Stderr:    os.Stderr,
	}
}

// The configuration file is deliberately not named warden.yaml. That name belongs to
// an *application manifest* (SPEC §11.2, examples/warden.yaml) and having two
// different schemas share a filename would be a lasting source of confusion.
const (
	configFileFlag = "config"
	configFileEnv  = "WARDEN_CONFIG"
)

// Load resolves configuration from defaults, then a file, then the environment, then
// flags — each layer overriding the one before it — and validates the result.
//
// The returned Config is safe to log: secrets redact themselves.
func Load(src Source) (*Config, error) {
	if src.LookupEnv == nil {
		src.LookupEnv = func(string) (string, bool) { return "", false }
	}
	if src.ReadFile == nil {
		src.ReadFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	}
	if src.Stderr == nil {
		src.Stderr = io.Discard
	}

	cfg := Defaults()

	// Layer 1: the file. Its path itself comes from a flag or the environment, so it
	// is resolved before anything else.
	if path := configFilePath(src); path != "" {
		if err := applyFile(cfg, path, src.ReadFile); err != nil {
			return nil, err
		}
	}

	// Layer 2: the environment.
	if err := applyEnv(cfg, src.LookupEnv); err != nil {
		return nil, err
	}

	// Layer 3: flags. Only those the user actually set are applied, so a flag's zero
	// value never silently overrides a file or environment setting.
	if err := applyFlags(cfg, src); err != nil {
		return nil, err
	}

	if err := cfg.Validate(src.LookupEnv, src.ReadFile); err != nil {
		return nil, err
	}
	return cfg, nil
}

// field binds one configuration setting to its flag name and environment variable.
// The table is explicit rather than reflected so that every knob is greppable, its
// help text lives next to it, and adding a field to the struct without deciding how
// it is set is impossible to do by accident.
type field struct {
	flag  string
	env   string
	usage string
	set   func(*Config, string) error
}

func fields() []field {
	return []field{
		{"environment", "WARDEN_ENVIRONMENT", "deployment posture: dev, staging or prod",
			func(c *Config, v string) error { c.Environment = Environment(v); return nil }},
		{"roles", "WARDEN_ROLES", "comma-separated roles: auth, pdp, mgmt, worker, all",
			setRoles},
		{"issuer", "WARDEN_ISSUER", "public origin of this deployment; the token \"iss\" claim",
			func(c *Config, v string) error { c.Issuer = v; return nil }},

		{"http-addr", "WARDEN_HTTP_ADDR", "listen address for the public API",
			func(c *Config, v string) error { c.HTTP.Addr = v; return nil }},
		{"http-read-timeout", "WARDEN_HTTP_READ_TIMEOUT", "maximum duration for reading a request",
			durationSetter(func(c *Config) *time.Duration { return &c.HTTP.ReadTimeout })},
		{"http-write-timeout", "WARDEN_HTTP_WRITE_TIMEOUT", "maximum duration for writing a response",
			durationSetter(func(c *Config) *time.Duration { return &c.HTTP.WriteTimeout })},
		{"http-shutdown-timeout", "WARDEN_HTTP_SHUTDOWN_TIMEOUT", "grace period for in-flight requests on shutdown",
			durationSetter(func(c *Config) *time.Duration { return &c.HTTP.ShutdownTimeout })},
		{"http-max-request-bytes", "WARDEN_HTTP_MAX_REQUEST_BYTES", "maximum request body size in bytes",
			int64Setter(func(c *Config) *int64 { return &c.HTTP.MaxRequestBytes })},
		{"http-trusted-proxy-cidrs", "WARDEN_HTTP_TRUSTED_PROXY_CIDRS", "comma-separated CIDRs whose X-Forwarded-For is trusted",
			func(c *Config, v string) error { c.HTTP.TrustedProxyCIDRs = splitList(v); return nil }},

		{"database-url", "WARDEN_DATABASE_URL", "PostgreSQL connection string (required)",
			func(c *Config, v string) error { c.Database.URL = secrets.New(v); return nil }},
		{"database-system-url", "WARDEN_DATABASE_SYSTEM_URL", "PostgreSQL connection string for cross-tenant work; the role holds BYPASSRLS",
			func(c *Config, v string) error { c.Database.SystemURL = secrets.New(v); return nil }},
		{"database-max-open-conns", "WARDEN_DATABASE_MAX_OPEN_CONNS", "maximum open database connections",
			intSetter(func(c *Config) *int { return &c.Database.MaxOpenConns })},
		{"database-max-idle-conns", "WARDEN_DATABASE_MAX_IDLE_CONNS", "maximum idle database connections",
			intSetter(func(c *Config) *int { return &c.Database.MaxIdleConns })},
		{"database-conn-max-lifetime", "WARDEN_DATABASE_CONN_MAX_LIFETIME", "maximum lifetime of a pooled connection",
			durationSetter(func(c *Config) *time.Duration { return &c.Database.ConnMaxLifetime })},
		{"database-connect-timeout", "WARDEN_DATABASE_CONNECT_TIMEOUT", "timeout for establishing a database connection",
			durationSetter(func(c *Config) *time.Duration { return &c.Database.ConnectTimeout })},
		{"database-statement-timeout", "WARDEN_DATABASE_STATEMENT_TIMEOUT", "server-side statement timeout",
			durationSetter(func(c *Config) *time.Duration { return &c.Database.StatementTimeout })},
		{"cache-backend", "WARDEN_CACHE_BACKEND", "cache and pub/sub backend: redis or in-process",
			func(c *Config, v string) error { c.Cache.Backend = CacheBackend(v); return nil }},
		{"cache-url", "WARDEN_CACHE_URL", "Redis connection string (required when the backend is redis)",
			func(c *Config, v string) error { c.Cache.URL = secrets.New(v); return nil }},
		{"cache-dial-timeout", "WARDEN_CACHE_DIAL_TIMEOUT", "timeout for connecting to the cache",
			durationSetter(func(c *Config) *time.Duration { return &c.Cache.DialTimeout })},
		{"cache-pool-size", "WARDEN_CACHE_POOL_SIZE", "cache connection pool size",
			intSetter(func(c *Config) *int { return &c.Cache.PoolSize })},

		{"security-kek", "WARDEN_SECURITY_KEK", "key-encryption key reference: env:NAME, file:/path or kms:<uri> (required)",
			func(c *Config, v string) error { c.Security.KEK = v; return nil }},
		{"security-retired-keks", "WARDEN_SECURITY_RETIRED_KEKS", "comma-separated retired key references, retained for decryption",
			func(c *Config, v string) error { c.Security.RetiredKEKs = splitList(v); return nil }},
		{"security-token-signing-algorithm", "WARDEN_SECURITY_TOKEN_SIGNING_ALGORITHM", "token signing algorithm: RS256 or ES256",
			func(c *Config, v string) error { c.Security.TokenSigningAlgorithm = v; return nil }},
		{"security-access-token-ttl", "WARDEN_SECURITY_ACCESS_TOKEN_TTL", "access token lifetime (5m–15m)",
			durationSetter(func(c *Config) *time.Duration { return &c.Security.AccessTokenTTL })},
		{"security-key-rotation-interval", "WARDEN_SECURITY_KEY_ROTATION_INTERVAL", "signing key rotation interval",
			durationSetter(func(c *Config) *time.Duration { return &c.Security.KeyRotationInterval })},

		{"log-level", "WARDEN_LOG_LEVEL", "log level: debug, info, warn or error",
			func(c *Config, v string) error { c.Log.Level = v; return nil }},
		{"log-format", "WARDEN_LOG_FORMAT", "log format: json or text",
			func(c *Config, v string) error { c.Log.Format = v; return nil }},

		{"metrics-addr", "WARDEN_METRICS_ADDR", "listen address for /metrics",
			func(c *Config, v string) error { c.Telemetry.MetricsAddr = v; return nil }},
		{"tracing-otlp-endpoint", "WARDEN_TRACING_OTLP_ENDPOINT", "OTLP endpoint for traces; empty disables tracing",
			func(c *Config, v string) error { c.Telemetry.TracingOTLP = v; return nil }},
		{"trace-sample-ratio", "WARDEN_TRACE_SAMPLE_RATIO", "fraction of traces sampled, 0.0–1.0",
			floatSetter(func(c *Config) *float64 { return &c.Telemetry.TraceSampler })},
	}
}

func configFilePath(src Source) string {
	// The flag wins over the environment, matching the precedence of everything else.
	fs := flag.NewFlagSet("warden-config-probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String(configFileFlag, "", "path to the server configuration file")
	// Every other flag is declared so the probe parse does not fail on them.
	for _, f := range fields() {
		fs.String(f.flag, "", "")
	}
	if err := fs.Parse(src.Args); err != nil {
		// A real parse error is reported by applyFlags, together with usage. This
		// probe only needs to find the config-file path.
		return ""
	}
	if *path != "" {
		return *path
	}
	if v, ok := src.LookupEnv(configFileEnv); ok && v != "" {
		return v
	}
	return ""
}

func applyFile(cfg *Config, path string, readFile secrets.ReadFileFunc) error {
	raw, err := readFile(path)
	if err != nil {
		return fmt.Errorf("reading config file %s: %w", path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	// Unknown fields are an error. A typo in a config file must not silently leave a
	// setting at its default — that is how a security control ends up switched off
	// without anyone noticing.
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("parsing config file %s: %w", path, err)
	}
	return nil
}

func applyEnv(cfg *Config, lookupEnv secrets.LookupEnvFunc) error {
	for _, f := range fields() {
		v, ok := lookupEnv(f.env)
		if !ok {
			continue
		}
		if err := f.set(cfg, v); err != nil {
			return fmt.Errorf("%s: %w", f.env, err)
		}
	}
	return nil
}

func applyFlags(cfg *Config, src Source) error {
	fs := flag.NewFlagSet("warden", flag.ContinueOnError)
	fs.SetOutput(src.Stderr)
	fs.String(configFileFlag, "", "path to the server configuration file")

	all := fields()
	values := make(map[string]*string, len(all))
	byName := make(map[string]field, len(all))
	for _, f := range all {
		values[f.flag] = fs.String(f.flag, "", f.usage)
		byName[f.flag] = f
	}

	if err := fs.Parse(src.Args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ErrHelpRequested
		}
		return fmt.Errorf("parsing flags: %w", err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	// flag.Visit reports only the flags that were actually present on the command
	// line, which is what makes "flags override, but absent flags do not" work.
	var visitErr error
	fs.Visit(func(fl *flag.Flag) {
		f, ok := byName[fl.Name]
		if !ok {
			return // the config-file flag, handled earlier
		}
		if err := f.set(cfg, *values[fl.Name]); err != nil && visitErr == nil {
			visitErr = fmt.Errorf("-%s: %w", fl.Name, err)
		}
	})
	return visitErr
}

// Usage writes the flag reference to w.
func Usage(w io.Writer) {
	fs := flag.NewFlagSet("warden", flag.ContinueOnError)
	fs.SetOutput(w)
	fs.String(configFileFlag, "", "path to the server configuration file (env "+configFileEnv+")")
	for _, f := range fields() {
		fs.String(f.flag, "", f.usage+" (env "+f.env+")")
	}
	fs.PrintDefaults()
}

func setRoles(c *Config, v string) error {
	parts := splitList(v)
	if len(parts) == 0 {
		return errors.New("no roles given")
	}
	roles := make([]Role, 0, len(parts))
	for _, p := range parts {
		roles = append(roles, Role(p))
	}
	c.Roles = roles
	return nil
}

func splitList(v string) []string {
	out := []string{}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func durationSetter(get func(*Config) *time.Duration) func(*Config, string) error {
	return func(c *Config, v string) error {
		d, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("%q is not a duration (want e.g. 30s, 5m, 1h)", v)
		}
		*get(c) = d
		return nil
	}
}

func intSetter(get func(*Config) *int) func(*Config, string) error {
	return func(c *Config, v string) error {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("%q is not an integer", v)
		}
		*get(c) = n
		return nil
	}
}

func int64Setter(get func(*Config) *int64) func(*Config, string) error {
	return func(c *Config, v string) error {
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return fmt.Errorf("%q is not an integer", v)
		}
		*get(c) = n
		return nil
	}
}

// There is no boolSetter. database.auto_migrate was the only boolean in the binding
// table, and it was removed in M0-11 as a setting nothing implemented; the linter
// noticing its setter is how that was confirmed rather than assumed. Add one back with
// the first boolean that has behaviour behind it.

func floatSetter(get func(*Config) *float64) func(*Config, string) error {
	return func(c *Config, v string) error {
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return fmt.Errorf("%q is not a number", v)
		}
		*get(c) = f
		return nil
	}
}
