package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/warden-project/warden/internal/provision"
)

// The refusal is the property worth testing without a database, because it is the one
// that matters if it ever stops holding. Seeding creates subjects with predictable
// identifiers and standing role grants; doing that to a production deployment is the
// situation `warden init` exists to prevent (SPEC §20.2).
func TestSeedRefusesInProduction(t *testing.T) {
	manifest := filepath.Join("..", "..", "examples", "warden.yaml")

	t.Setenv("WARDEN_ENVIRONMENT", "prod")
	t.Setenv("WARDEN_ISSUER", "https://warden.example.com")
	t.Setenv("WARDEN_CACHE_URL", "redis://localhost:6379/0")
	t.Setenv("WARDEN_SECURITY_KEK", "env:WARDEN_TEST_KEK")
	t.Setenv("WARDEN_TEST_KEK", "dGVzdC1rZWstdGhpcnR5LXR3by1ieXRlcy1sb25nISE=")
	// Deliberately pointed at a database that does not exist. The refusal has to come
	// before anything connects, or a production operator finds out that seeding is a
	// bad idea only after it has half happened.
	t.Setenv("WARDEN_DATABASE_URL", "postgres://app@127.0.0.1:1/nothing?sslmode=disable")
	t.Setenv("WARDEN_DATABASE_SYSTEM_URL", "postgres://system@127.0.0.1:1/nothing?sslmode=disable")

	var stdout, stderr bytes.Buffer
	err := run([]string{"seed", "-f", manifest}, &stdout, &stderr)

	if err == nil {
		t.Fatal("seeding a production deployment must be refused")
	}
	if !strings.Contains(err.Error(), "refuses to run in production") {
		t.Fatalf("the refusal should say why, got: %v", err)
	}
	// If this fails with a connection error instead, the check has drifted below the
	// point where the store is opened.
	if strings.Contains(err.Error(), "connect") {
		t.Fatalf("the refusal must precede any database connection, got: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("nothing should reach stdout on a refusal, got: %s", stdout.String())
	}
}

// Environment defaults to prod (config.Defaults: "strict unless an operator opts out"),
// so an operator who never says where they are gets the refusal rather than a seeded
// deployment. Setting the variable to the empty string is a different case and is
// rejected by configuration validation; both fail closed, which is the point.
func TestSeedRefusesWhenTheEnvironmentIsUnset(t *testing.T) {
	manifest := filepath.Join("..", "..", "examples", "warden.yaml")

	// t.Setenv registers the cleanup that restores whatever was there; unsetting
	// afterwards is what actually exercises the default.
	t.Setenv("WARDEN_ENVIRONMENT", "placeholder")
	if err := os.Unsetenv("WARDEN_ENVIRONMENT"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_ISSUER", "https://warden.example.com")
	t.Setenv("WARDEN_CACHE_URL", "redis://localhost:6379/0")
	t.Setenv("WARDEN_SECURITY_KEK", "env:WARDEN_TEST_KEK")
	t.Setenv("WARDEN_TEST_KEK", "dGVzdC1rZWstdGhpcnR5LXR3by1ieXRlcy1sb25nISE=")
	t.Setenv("WARDEN_DATABASE_URL", "postgres://app@127.0.0.1:1/nothing?sslmode=disable")
	t.Setenv("WARDEN_DATABASE_SYSTEM_URL", "postgres://system@127.0.0.1:1/nothing?sslmode=disable")

	var stdout, stderr bytes.Buffer
	err := run([]string{"seed", "-f", manifest}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "refuses to run in production") {
		t.Fatalf("an unset environment must be treated as production, got: %v", err)
	}
}

// The fixture the seed publishes has to be a manifest that actually loads, and the
// elements it binds come from that file rather than from a list in seed.go — so a
// malformed examples/warden.yaml should fail here rather than in someone's first
// `make dev`.
func TestSeedManifestLoadsAndDeclaresWhatTheFixtureNeeds(t *testing.T) {
	manifest := filepath.Join("..", "..", "examples", "warden.yaml")

	t.Setenv("WARDEN_ENVIRONMENT", "prod")
	t.Setenv("WARDEN_ISSUER", "https://warden.example.com")
	t.Setenv("WARDEN_CACHE_URL", "redis://localhost:6379/0")
	t.Setenv("WARDEN_SECURITY_KEK", "env:WARDEN_TEST_KEK")
	t.Setenv("WARDEN_TEST_KEK", "dGVzdC1rZWstdGhpcnR5LXR3by1ieXRlcy1sb25nISE=")

	// The manifest is loaded before the configuration is even read, so a broken one
	// reports itself as a manifest problem and not as a missing database.
	var stdout, stderr bytes.Buffer
	err := run([]string{"seed", "-f", filepath.Join("..", "..", "examples", "nope.yaml")}, &stdout, &stderr)
	if err == nil || strings.Contains(err.Error(), "refuses to run in production") {
		t.Fatalf("a missing manifest should be reported as such, got: %v", err)
	}

	// And the real one must declare the roles the seeded grants reference. Those role
	// keys live in seed.go; if the manifest renames one, `make dev` breaks with a
	// foreign-key error deep inside a transaction, which is a poor way to find out.
	m, err := provision.LoadManifest(manifest)
	if err != nil {
		t.Fatalf("examples/warden.yaml does not load: %v", err)
	}
	declared := map[string]bool{}
	for _, r := range m.Roles {
		declared[r.Key] = true
	}
	for _, g := range []string{"billing.viewer", "billing.approver"} {
		if !declared[g] {
			t.Errorf("examples/warden.yaml no longer declares role %q, which seed.go grants", g)
		}
	}

	// Same for the resource types the fixture registers instances of.
	types := map[string]bool{}
	for _, rt := range m.Resources {
		types[m.Application+"."+rt.Key] = true
	}
	for _, r := range seedResources {
		kind := r.ref[:strings.IndexByte(r.ref, ':')]
		if !types[kind] {
			t.Errorf("seed registers %q but the manifest declares no resource type %q", r.ref, kind)
		}
	}
}
