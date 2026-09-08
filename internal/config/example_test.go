package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/warden-project/warden/internal/config"
)

// The shipped example configuration must load. Because the loader rejects unknown
// fields, this also catches the case where a setting is renamed in Go and the
// example — which is the documentation an operator copies — is left behind.
func TestShippedExampleConfigurationIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "warden-server.example.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the example configuration is missing: %v", err)
	}

	env := map[string]string{"WARDEN_KEK": validKEK}
	s := config.Source{
		Args:      []string{"-config", path},
		LookupEnv: func(name string) (string, bool) { v, ok := env[name]; return v, ok },
		ReadFile:  os.ReadFile,
	}

	cfg, err := config.Load(s)
	if err != nil {
		t.Fatalf("deploy/warden-server.example.yaml does not load: %v", err)
	}

	// It is meant to be a production-shaped example, not a permissive one.
	if cfg.Environment != config.EnvProduction {
		t.Errorf("the example should show a production configuration, got %q", cfg.Environment)
	}
	if cfg.Cache.Backend != config.CacheRedis {
		t.Errorf("the example should use the redis cache backend, got %q", cfg.Cache.Backend)
	}
	if len(cfg.HTTP.TrustedProxyCIDRs) != 0 {
		t.Error("the example should not trust any proxy by default")
	}
}
