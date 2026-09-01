package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"version"}, &out, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.TrimSpace(out.String()) == "" {
		t.Fatal("version printed nothing")
	}
}

func TestHelpCommand(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"help"}, &out, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, want := range []string{"warden config", "-security-kek", "WARDEN_DATABASE_URL"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("usage does not mention %q:\n%s", want, out.String())
		}
	}
}

func TestUnknownCommandIsRejected(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"frobnicate"}, &out, &out)
	if err == nil || !strings.Contains(err.Error(), "frobnicate") {
		t.Fatalf("expected an error naming the unknown command, got %v", err)
	}
}

// An operator running the binary with nothing configured must get the full list of
// what is missing, not a panic and not a server that starts anyway.
func TestConfigCheckFailsClosedWithNoConfiguration(t *testing.T) {
	t.Setenv("WARDEN_ISSUER", "")
	t.Setenv("WARDEN_DATABASE_URL", "")
	t.Setenv("WARDEN_CACHE_URL", "")
	t.Setenv("WARDEN_SECURITY_KEK", "")

	var stdout, stderr bytes.Buffer
	err := run([]string{"config"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected an error with nothing configured")
	}
	for _, want := range []string{"issuer", "database.url", "security.kek"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error should name %s:\n%v", want, err)
		}
	}
	if stdout.Len() != 0 {
		t.Fatalf("nothing should be printed to stdout on failure, got: %s", stdout.String())
	}
}

func TestConfigCheckSucceedsAndRedacts(t *testing.T) {
	t.Setenv("WARDEN_ISSUER", "https://warden.example.com")
	t.Setenv("WARDEN_DATABASE_URL", "postgres://warden:s3cr3t@db:5432/warden")
	t.Setenv("WARDEN_CACHE_URL", "redis://cache:6379/0")
	t.Setenv("WARDEN_SECURITY_KEK", "env:WARDEN_KEK")
	t.Setenv("WARDEN_KEK", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"config"}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "configuration is valid") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if strings.Contains(out, "s3cr3t") {
		t.Fatalf("config output leaked the database password:\n%s", out)
	}
	if !strings.Contains(out, "kek          active") {
		t.Fatalf("config output should report the active key id:\n%s", out)
	}
}

func TestSplitCommandDefaultsToServe(t *testing.T) {
	cases := []struct {
		args     []string
		wantCmd  string
		wantRest int
	}{
		{nil, "serve", 0},
		{[]string{"-issuer", "https://x"}, "serve", 2},
		{[]string{"serve", "-issuer", "https://x"}, "serve", 2},
		{[]string{"config"}, "config", 0},
		{[]string{"version"}, "version", 0},
	}
	for _, tc := range cases {
		cmd, rest := splitCommand(tc.args)
		if cmd != tc.wantCmd || len(rest) != tc.wantRest {
			t.Fatalf("splitCommand(%v) = %q, %v; want %q with %d args", tc.args, cmd, rest, tc.wantCmd, tc.wantRest)
		}
	}
}
