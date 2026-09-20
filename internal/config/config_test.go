package config_test

import (
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
)

// validKEK is 32 bytes, base64 encoded.
var validKEK = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// minimalEnv is the smallest environment that produces a valid configuration: the
// four settings that have no default because no default could be correct.
func minimalEnv() map[string]string {
	return map[string]string{
		"WARDEN_ISSUER":       "https://warden.example.com",
		"WARDEN_DATABASE_URL": "postgres://warden@db:5432/warden",
		"WARDEN_CACHE_URL":    "redis://cache:6379/0",
		"WARDEN_SECURITY_KEK": "env:WARDEN_KEK",
		"WARDEN_KEK":          validKEK,
	}
}

func src(env map[string]string, args ...string) config.Source {
	return config.Source{
		Args: args,
		LookupEnv: func(name string) (string, bool) {
			v, ok := env[name]
			return v, ok
		},
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	}
}

func load(t *testing.T, s config.Source) *config.Config {
	t.Helper()
	cfg, err := config.Load(s)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestLoadMinimalConfiguration(t *testing.T) {
	cfg := load(t, src(minimalEnv()))

	if cfg.Issuer != "https://warden.example.com" {
		t.Fatalf("issuer = %q", cfg.Issuer)
	}
	if cfg.Environment != config.EnvProduction {
		t.Fatalf("environment should default to prod, got %q", cfg.Environment)
	}
	if !cfg.HasRole(config.RolePDP) || !cfg.HasRole(config.RoleAuth) {
		t.Fatal("the default role \"all\" should cover every tier")
	}
}

// --- Precedence -----------------------------------------------------------------

func TestPrecedenceFileThenEnvThenFlags(t *testing.T) {
	file := []byte("issuer: https://from-file.example.com\nlog:\n  level: warn\n")

	s := config.Source{
		Args: []string{"-config", "/etc/warden/server.yaml", "-log-level", "debug"},
		LookupEnv: func(name string) (string, bool) {
			env := minimalEnv()
			env["WARDEN_ISSUER"] = "https://from-env.example.com"
			env["WARDEN_ENVIRONMENT"] = "dev"
			v, ok := env[name]
			return v, ok
		},
		ReadFile: func(path string) ([]byte, error) {
			if path != "/etc/warden/server.yaml" {
				return nil, os.ErrNotExist
			}
			return file, nil
		},
	}

	cfg := load(t, s)

	// The environment overrides the file.
	if cfg.Issuer != "https://from-env.example.com" {
		t.Fatalf("env should override file, got issuer %q", cfg.Issuer)
	}
	// A flag overrides both.
	if cfg.Log.Level != "debug" {
		t.Fatalf("flag should override file, got log level %q", cfg.Log.Level)
	}
}

// A flag that is not passed must not overwrite a file or environment value with its
// zero value. This is the classic flag-precedence bug and it is worth a test.
func TestUnsetFlagsDoNotOverride(t *testing.T) {
	env := minimalEnv()
	env["WARDEN_LOG_LEVEL"] = "warn"
	env["WARDEN_HTTP_ADDR"] = "127.0.0.1:9999"

	cfg := load(t, src(env, "-issuer", "https://flag.example.com"))

	if cfg.Log.Level != "warn" {
		t.Fatalf("an unset -log-level flag clobbered the environment value: %q", cfg.Log.Level)
	}
	if cfg.HTTP.Addr != "127.0.0.1:9999" {
		t.Fatalf("an unset -http-addr flag clobbered the environment value: %q", cfg.HTTP.Addr)
	}
	if cfg.Issuer != "https://flag.example.com" {
		t.Fatalf("the flag that was set did not apply: %q", cfg.Issuer)
	}
}

func TestConfigFilePathFromEnvironment(t *testing.T) {
	env := minimalEnv()
	env["WARDEN_CONFIG"] = "/srv/warden.conf"
	delete(env, "WARDEN_ISSUER")

	s := src(env)
	s.ReadFile = func(path string) ([]byte, error) {
		if path != "/srv/warden.conf" {
			return nil, os.ErrNotExist
		}
		return []byte("issuer: https://from-file.example.com\n"), nil
	}

	cfg := load(t, s)
	if cfg.Issuer != "https://from-file.example.com" {
		t.Fatalf("issuer = %q", cfg.Issuer)
	}
}

// A typo in a config file must be an error. Silently ignoring an unknown key is how
// a setting an operator believes is applied turns out never to have been read.
func TestConfigFileRejectsUnknownFields(t *testing.T) {
	s := src(minimalEnv(), "-config", "/c.yaml")
	s.ReadFile = func(string) ([]byte, error) {
		return []byte("issuer: https://x.example.com\nlog:\n  lvel: debug\n"), nil
	}
	_, err := config.Load(s)
	if err == nil {
		t.Fatal("an unknown config-file field should be an error")
	}
	if !strings.Contains(err.Error(), "lvel") {
		t.Fatalf("the error should name the offending key, got: %v", err)
	}
}

// database.auto_migrate was a real setting from M0-4 to M0-11, with a default, a flag,
// an environment variable and a rule refusing it in production — and no implementation
// anywhere. It was removed rather than implemented, because a knob that silently does
// nothing is worse than an absent one.
//
// This test is what makes the removal safe for anyone still carrying it in a file: the
// unknown-key rule above turns it into a startup error naming the line, which is a
// better outcome than the validation rule it replaced. It also fails if someone
// re-adds the field without an implementation.
func TestLeftoverAutoMigrateIsRejected(t *testing.T) {
	s := src(minimalEnv(), "-config", "/c.yaml")
	s.ReadFile = func(string) ([]byte, error) {
		return []byte("issuer: https://x.example.com\ndatabase:\n  auto_migrate: true\n"), nil
	}
	_, err := config.Load(s)
	if err == nil {
		t.Fatal("auto_migrate no longer exists; a config file still setting it must fail")
	}
	if !strings.Contains(err.Error(), "auto_migrate") {
		t.Fatalf("the error should name the setting so an operator can find it, got: %v", err)
	}
}

func TestConfigFileMissingIsAnError(t *testing.T) {
	_, err := config.Load(src(minimalEnv(), "-config", "/absent.yaml"))
	if err == nil || !strings.Contains(err.Error(), "/absent.yaml") {
		t.Fatalf("a missing config file should be a named error, got: %v", err)
	}
}

// --- Required settings ----------------------------------------------------------

// The M0-4 exit condition: starting without the settings that carry security weight
// fails, names every one of them, and says how to set each.
func TestMissingRequiredSettingsAreReportedTogether(t *testing.T) {
	_, err := config.Load(src(map[string]string{}))
	if err == nil {
		t.Fatal("an empty environment must not produce a usable configuration")
	}

	var errs *config.Errors
	if !errors.As(err, &errs) {
		t.Fatalf("expected *config.Errors, got %T: %v", err, err)
	}

	wantFields := []string{"issuer", "database.url", "cache.url", "security.kek"}
	got := map[string]config.Problem{}
	for _, p := range errs.Problems {
		got[p.Field] = p
	}
	for _, f := range wantFields {
		p, ok := got[f]
		if !ok {
			t.Fatalf("%s was not reported as missing; reported: %v", f, errs)
		}
		if p.Env == "" && p.Flag == "" {
			t.Fatalf("%s was reported without telling the operator how to set it", f)
		}
	}
	// One run, one complete list — not one problem per restart.
	if len(errs.Problems) < len(wantFields) {
		t.Fatalf("expected all problems in one pass, got %d", len(errs.Problems))
	}
}

func TestMalformedKEKIsAStartupError(t *testing.T) {
	cases := map[string]map[string]string{
		"reference has no scheme": {"WARDEN_SECURITY_KEK": "just-a-key"},
		"env var absent":          {"WARDEN_SECURITY_KEK": "env:NOT_SET"},
		"key too short":           {"WARDEN_SECURITY_KEK": "env:WARDEN_KEK", "WARDEN_KEK": "c2hvcnQ="},
		"kms unimplemented":       {"WARDEN_SECURITY_KEK": "kms://project/keyring/key"},
		"file missing":            {"WARDEN_SECURITY_KEK": "file:/etc/warden/absent"},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			env := minimalEnv()
			delete(env, "WARDEN_KEK")
			for k, v := range overrides {
				env[k] = v
			}
			_, err := config.Load(src(env))
			if err == nil {
				t.Fatal("expected a startup error")
			}
			if !strings.Contains(err.Error(), "security.kek") {
				t.Fatalf("the error should name security.kek, got: %v", err)
			}
		})
	}
}

// --- No insecure defaults -------------------------------------------------------

// Defaults() must not supply a value for anything that carries security weight. This
// walks the struct rather than listing fields, so a new secret added later is caught
// even if whoever adds it does not think to update this test.
func TestDefaultsSupplyNoSecrets(t *testing.T) {
	var walk func(v reflect.Value, path string)
	walk = func(v reflect.Value, path string) {
		if v.Type() == reflect.TypeOf(secrets.Secret{}) {
			s, ok := v.Interface().(secrets.Secret)
			if !ok {
				t.Fatalf("%s: reflect returned a %T for a Secret field", path, v.Interface())
			}
			if !s.IsZero() {
				t.Errorf("%s has a default value; secrets must always be supplied by the operator", path)
			}
			return
		}
		if v.Kind() == reflect.Struct {
			for i := 0; i < v.NumField(); i++ {
				name := v.Type().Field(i).Name
				if path != "" {
					name = path + "." + name
				}
				walk(v.Field(i), name)
			}
		}
	}
	walk(reflect.ValueOf(*config.Defaults()), "")

	d := config.Defaults()
	if d.Security.KEK != "" {
		t.Error("Security.KEK has a default; a generated or guessed KEK would orphan encrypted data on restart")
	}
	if d.Issuer != "" {
		t.Error("Issuer has a default; a wrong issuer produces tokens no relying party accepts")
	}
}

// Where a default does exist, it must be the stricter of the available choices.
func TestDefaultsChooseTheStrictOption(t *testing.T) {
	d := config.Defaults()

	if d.Environment != config.EnvProduction {
		t.Error("environment should default to prod, so an operator who says nothing gets the strict behaviour")
	}
	if len(d.HTTP.TrustedProxyCIDRs) != 0 {
		t.Error("no proxy should be trusted by default; context.ip feeds authorization conditions")
	}
	if d.Cache.Backend != config.CacheRedis {
		t.Error("the cache should default to redis; in-process cannot propagate permission changes")
	}
	if d.Security.TokenSigningAlgorithm != "RS256" {
		t.Error("token signing should default to an asymmetric algorithm")
	}
	if d.HTTP.MaxRequestBytes <= 0 {
		t.Error("request bodies must be bounded by default")
	}
	if d.Database.StatementTimeout <= 0 {
		t.Error("queries must be bounded by default")
	}
}

// --- Validation rules -----------------------------------------------------------

func TestValidationRejectsUnsafeCombinations(t *testing.T) {
	cases := []struct {
		name       string
		env        map[string]string
		wantField  string
		wantDetail string
	}{
		{
			name:       "plaintext issuer in production",
			env:        map[string]string{"WARDEN_ISSUER": "http://warden.example.com"},
			wantField:  "issuer",
			wantDetail: "must be https",
		},
		{
			name:       "in-process cache in production",
			env:        map[string]string{"WARDEN_CACHE_BACKEND": "in-process", "WARDEN_CACHE_URL": ""},
			wantField:  "cache.backend",
			wantDetail: "single-node only",
		},
		{
			name:       "access token lifetime above the spec bound",
			env:        map[string]string{"WARDEN_SECURITY_ACCESS_TOKEN_TTL": "24h"},
			wantField:  "security.access_token_ttl",
			wantDetail: "backstop for revocation",
		},
		{
			name:       "access token lifetime below the spec bound",
			env:        map[string]string{"WARDEN_SECURITY_ACCESS_TOKEN_TTL": "30s"},
			wantField:  "security.access_token_ttl",
			wantDetail: "must be between",
		},
		{
			// The window has to outlast the tokens the key it retires has signed,
			// or rotation produces tokens nothing can verify.
			name: "overlap window shorter than the token lifetime",
			env: map[string]string{
				"WARDEN_SECURITY_ACCESS_TOKEN_TTL":   "15m",
				"WARDEN_SECURITY_KEY_OVERLAP_WINDOW": "5m",
			},
			wantField:  "security.key_overlap_window",
			wantDetail: "shorter than security.access_token_ttl",
		},
		{
			name:       "overlap window as long as the rotation interval",
			env:        map[string]string{"WARDEN_SECURITY_KEY_OVERLAP_WINDOW": "2160h"},
			wantField:  "security.key_overlap_window",
			wantDetail: "never actually retired",
		},
		{
			name:       "symmetric token signing",
			env:        map[string]string{"WARDEN_SECURITY_TOKEN_SIGNING_ALGORITHM": "HS256"},
			wantField:  "security.token_signing_algorithm",
			wantDetail: "shared secret",
		},
		{
			name:       "roles combined with all",
			env:        map[string]string{"WARDEN_ROLES": "all,pdp"},
			wantField:  "roles",
			wantDetail: "cannot be combined",
		},
		{
			name:       "unknown role",
			env:        map[string]string{"WARDEN_ROLES": "pdp,frobnicator"},
			wantField:  "roles",
			wantDetail: "not a known role",
		},
		{
			name:       "non-postgres database",
			env:        map[string]string{"WARDEN_DATABASE_URL": "mysql://db/warden"},
			wantField:  "database.url",
			wantDetail: "postgres://",
		},
		{
			name:       "unbounded request body",
			env:        map[string]string{"WARDEN_HTTP_MAX_REQUEST_BYTES": "0"},
			wantField:  "http.max_request_bytes",
			wantDetail: "denial-of-service",
		},
		{
			name:       "malformed trusted proxy CIDR",
			env:        map[string]string{"WARDEN_HTTP_TRUSTED_PROXY_CIDRS": "10.0.0.1"},
			wantField:  "http.trusted_proxy_cidrs",
			wantDetail: "not a CIDR",
		},
		{
			name:       "idle connections exceed open connections",
			env:        map[string]string{"WARDEN_DATABASE_MAX_IDLE_CONNS": "50", "WARDEN_DATABASE_MAX_OPEN_CONNS": "10"},
			wantField:  "database.max_idle_conns",
			wantDetail: "exceeds max_open_conns",
		},
		{
			name:       "trace sample ratio out of range",
			env:        map[string]string{"WARDEN_TRACE_SAMPLE_RATIO": "1.5"},
			wantField:  "telemetry.trace_sample_ratio",
			wantDetail: "between 0.0 and 1.0",
		},
		{
			name:       "unknown environment",
			env:        map[string]string{"WARDEN_ENVIRONMENT": "preprod"},
			wantField:  "environment",
			wantDetail: "not a known environment",
		},
		{
			// The message being delivered in the clear is the credential itself: a
			// magic link, a reset link, an invitation. Anyone on the path between
			// Warden and a remote relay reads them and becomes the user.
			name: "cleartext SMTP to a remote relay in production",
			env: map[string]string{
				"WARDEN_EMAIL_SENDER":    "smtp",
				"WARDEN_EMAIL_FROM":      "Warden <no-reply@acme.com>",
				"WARDEN_EMAIL_SMTP_HOST": "smtp.acme.com",
				"WARDEN_EMAIL_SMTP_TLS":  "disabled",
			},
			wantField:  "email.smtp.tls",
			wantDetail: "loopback host in production",
		},
		{
			// Staging holds real addresses and sends real links, so the same rule
			// applies. Comparing against EnvProduction alone would let it through.
			name: "cleartext SMTP to a remote relay in staging",
			env: map[string]string{
				"WARDEN_ENVIRONMENT":     "staging",
				"WARDEN_EMAIL_SENDER":    "smtp",
				"WARDEN_EMAIL_FROM":      "Warden <no-reply@acme.com>",
				"WARDEN_EMAIL_SMTP_HOST": "smtp.acme.com",
				"WARDEN_EMAIL_SMTP_TLS":  "disabled",
			},
			wantField:  "email.smtp.tls",
			wantDetail: "loopback host in production",
		},
		{
			name: "stdout sender in staging",
			env: map[string]string{
				"WARDEN_ENVIRONMENT":  "staging",
				"WARDEN_EMAIL_SENDER": "stdout",
				"WARDEN_EMAIL_FROM":   "Warden <no-reply@acme.com>",
			},
			wantField:  "email.sender",
			wantDetail: "writes credentials to the log",
		},
		{
			name: "sender address that cannot be parsed",
			env: map[string]string{
				"WARDEN_EMAIL_SENDER": "smtp",
				"WARDEN_EMAIL_FROM":   "no-reply@",
			},
			wantField:  "email.from",
			wantDetail: "not a valid address",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := minimalEnv()
			for k, v := range tc.env {
				if v == "" {
					delete(env, k)
					continue
				}
				env[k] = v
			}
			_, err := config.Load(src(env))
			if err == nil {
				t.Fatal("expected a validation error")
			}
			var errs *config.Errors
			if !errors.As(err, &errs) {
				t.Fatalf("expected *config.Errors, got %T: %v", err, err)
			}
			for _, p := range errs.Problems {
				if p.Field == tc.wantField && strings.Contains(p.Detail, tc.wantDetail) {
					return
				}
			}
			t.Fatalf("no problem on %q mentioning %q; got: %v", tc.wantField, tc.wantDetail, errs)
		})
	}
}

// The same settings that are refused in production are allowed on a laptop.
func TestDevelopmentRelaxesProductionOnlyRules(t *testing.T) {
	env := minimalEnv()
	env["WARDEN_ENVIRONMENT"] = "dev"
	env["WARDEN_ISSUER"] = "http://localhost:8080"
	env["WARDEN_CACHE_BACKEND"] = "in-process"
	delete(env, "WARDEN_CACHE_URL")

	cfg := load(t, src(env))
	if cfg.Cache.Backend != config.CacheInProcess {
		t.Fatal("in-process cache should be allowed in dev")
	}
}

// The development stack reaches Mailpit by container name, which is not loopback and
// never will be — so outside production, cleartext SMTP has to be allowed to a named
// host. This is the same concession as the in-process cache above; the test exists
// because tightening the rule back to loopback-only would break `make dev-up` and
// nothing else would notice.
func TestCleartextSMTPIsAllowedOutsideProduction(t *testing.T) {
	env := minimalEnv()
	env["WARDEN_ENVIRONMENT"] = "dev"
	env["WARDEN_EMAIL_SENDER"] = "smtp"
	env["WARDEN_EMAIL_FROM"] = "Warden <no-reply@warden.test>"
	env["WARDEN_EMAIL_SMTP_HOST"] = "mailpit"
	env["WARDEN_EMAIL_SMTP_PORT"] = "1025"
	env["WARDEN_EMAIL_SMTP_TLS"] = "disabled"

	cfg := load(t, src(env))
	if cfg.Email.SMTP.Host != "mailpit" || cfg.Email.SMTP.Port != 1025 {
		t.Fatalf("SMTP host and port did not survive: %q:%d", cfg.Email.SMTP.Host, cfg.Email.SMTP.Port)
	}
	if cfg.Email.Sender != config.EmailSMTP || cfg.Email.From != "Warden <no-reply@warden.test>" {
		t.Fatalf("sender = %q, from = %q", cfg.Email.Sender, cfg.Email.From)
	}
}

// Every email setting reaches the struct. A variable the deployment sets and the loader
// ignores is silent: the server starts, and sends through whatever the default was.
func TestEmailSettingsAreBound(t *testing.T) {
	env := minimalEnv()
	env["WARDEN_EMAIL_SENDER"] = "smtp"
	env["WARDEN_EMAIL_FROM"] = "Warden <no-reply@acme.com>"
	env["WARDEN_EMAIL_REPLY_TO"] = "support@acme.com"
	env["WARDEN_EMAIL_SMTP_HOST"] = "smtp.acme.com"
	env["WARDEN_EMAIL_SMTP_PORT"] = "587"
	env["WARDEN_EMAIL_SMTP_USERNAME"] = "warden"
	env["WARDEN_EMAIL_SMTP_PASSWORD_REF"] = "env:WARDEN_SMTP_PASSWORD"
	env["WARDEN_SMTP_PASSWORD"] = "hunter2"
	env["WARDEN_EMAIL_SMTP_TLS"] = "starttls"
	env["WARDEN_EMAIL_SMTP_TIMEOUT"] = "45s"

	cfg := load(t, src(env))
	for name, got := range map[string]any{
		"sender":       string(cfg.Email.Sender),
		"from":         cfg.Email.From,
		"reply_to":     cfg.Email.ReplyTo,
		"smtp.host":    cfg.Email.SMTP.Host,
		"smtp.port":    cfg.Email.SMTP.Port,
		"smtp.tls":     string(cfg.Email.SMTP.TLS),
		"smtp.timeout": cfg.Email.SMTP.Timeout,
		"username":     cfg.Email.SMTP.Username,
	} {
		want := map[string]any{
			"sender": "smtp", "from": "Warden <no-reply@acme.com>",
			"reply_to": "support@acme.com", "smtp.host": "smtp.acme.com",
			"smtp.port": 587, "smtp.tls": "starttls",
			"smtp.timeout": 45 * time.Second, "username": "warden",
		}[name]
		if got != want {
			t.Errorf("email.%s = %v, want %v", name, got, want)
		}
	}
	// The password is a reference, resolved at load; validation already proved it
	// resolves, so all that is left is that it is held rather than dropped.
	if cfg.Email.SMTP.Password.IsZero() {
		t.Error("the SMTP password reference was dropped; every authenticated send would fail")
	}
	if strings.Contains(cfg.String(), "hunter2") {
		t.Error("the SMTP password appears in the redacted rendering of the configuration")
	}
}

// Staging holds real secrets and real IdP connections, so it is treated as production.
func TestStagingIsTreatedAsProduction(t *testing.T) {
	env := minimalEnv()
	env["WARDEN_ENVIRONMENT"] = "staging"
	env["WARDEN_ISSUER"] = "http://staging.example.com"

	_, err := config.Load(src(env))
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("staging should require an https issuer, got: %v", err)
	}
}

func TestIssuerTrailingSlashIsNormalised(t *testing.T) {
	env := minimalEnv()
	env["WARDEN_ISSUER"] = "https://warden.example.com/"
	cfg := load(t, src(env))
	if cfg.Issuer != "https://warden.example.com" {
		t.Fatalf("trailing slash should be trimmed, got %q", cfg.Issuer)
	}
}

// --- Roles ----------------------------------------------------------------------

func TestEffectiveRoles(t *testing.T) {
	cases := map[string][]config.Role{
		"all":      {config.RoleAuth, config.RoleMgmt, config.RolePDP, config.RoleWorker},
		"pdp":      {config.RolePDP},
		"pdp,auth": {config.RoleAuth, config.RolePDP},
	}
	for spec, want := range cases {
		t.Run(spec, func(t *testing.T) {
			env := minimalEnv()
			env["WARDEN_ROLES"] = spec
			cfg := load(t, src(env))
			if got := cfg.EffectiveRoles(); !reflect.DeepEqual(got, want) {
				t.Fatalf("EffectiveRoles() = %v, want %v", got, want)
			}
		})
	}
}

// --- Diagnostics ----------------------------------------------------------------

// Logging the whole configuration must be a safe thing to do, because it is the
// first thing anyone does when debugging a deployment.
func TestConfigStringRedactsSecrets(t *testing.T) {
	env := minimalEnv()
	env["WARDEN_DATABASE_URL"] = "postgres://warden:s3cr3t-password@db:5432/warden"
	env["WARDEN_CACHE_URL"] = "redis://:cache-p4ssw0rd@cache:6379/0"

	rendered := load(t, src(env)).String()
	for _, leak := range []string{"s3cr3t-password", "cache-p4ssw0rd"} {
		if strings.Contains(rendered, leak) {
			t.Fatalf("Config.String() leaked a credential: %s", rendered)
		}
	}
	if !strings.Contains(rendered, "https://warden.example.com") {
		t.Fatal("Config.String() should still show the non-secret settings")
	}
}

// A database URL that fails to parse must not be echoed back, because the reason it
// failed to parse may be a malformed password.
func TestValidationErrorsDoNotEchoSecrets(t *testing.T) {
	env := minimalEnv()
	env["WARDEN_DATABASE_URL"] = "postgres://user:p4ssw0rd@db:5432/warden\x7f"

	_, err := config.Load(src(env))
	if err == nil {
		t.Fatal("expected a validation error")
	}
	if strings.Contains(err.Error(), "p4ssw0rd") {
		t.Fatalf("the validation error leaked the password: %v", err)
	}
}

func TestKeyringRotationFromConfig(t *testing.T) {
	retired := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	env := minimalEnv()
	env["WARDEN_SECURITY_RETIRED_KEKS"] = "env:WARDEN_KEK_OLD"
	env["WARDEN_KEK_OLD"] = retired

	cfg := load(t, src(env))
	lookup := func(name string) (string, bool) { v, ok := env[name]; return v, ok }

	kr, err := cfg.Keyring(secrets.LookupEnvFunc(lookup), nil)
	if err != nil {
		t.Fatalf("Keyring: %v", err)
	}
	if len(kr.KeyIDs()) != 2 {
		t.Fatalf("expected an active and a retired key, got %v", kr.KeyIDs())
	}
}

func TestHelpIsNotAnError(t *testing.T) {
	_, err := config.Load(src(minimalEnv(), "-h"))
	if !errors.Is(err, config.ErrHelpRequested) {
		t.Fatalf("-h should return ErrHelpRequested, got %v", err)
	}
}

func TestUnexpectedPositionalArgumentIsRejected(t *testing.T) {
	_, err := config.Load(src(minimalEnv(), "serv"))
	if err == nil || !strings.Contains(err.Error(), "serv") {
		t.Fatalf("a stray argument should be rejected by name, got %v", err)
	}
}

func TestDurationFlagParsingErrorIsClear(t *testing.T) {
	_, err := config.Load(src(minimalEnv(), "-security-access-token-ttl", "ten minutes"))
	if err == nil || !strings.Contains(err.Error(), "not a duration") {
		t.Fatalf("expected a duration parse error, got %v", err)
	}
	// And the accepted form works.
	cfg := load(t, src(minimalEnv(), "-security-access-token-ttl", "7m"))
	if cfg.Security.AccessTokenTTL != 7*time.Minute {
		t.Fatalf("access token TTL = %s", cfg.Security.AccessTokenTTL)
	}
}
