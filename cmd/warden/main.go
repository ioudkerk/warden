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

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
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

	// The HTTP listener, the database pool and the role-specific services attach
	// here. They arrive with M0-6 (tenant-scoped store), M0-7 (query layer) and
	// M0-10 (health and metrics); until then this proves the startup path —
	// configuration resolved, secrets loaded, signals handled — end to end.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Warn("no server roles are implemented yet; holding until interrupted (tasks M0-6, M0-7, M0-10)")
	<-ctx.Done()
	log.Info("shutting down", "grace_period", cfg.HTTP.ShutdownTimeout)
	return nil
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

Configuration is read from a file, then the environment, then flags, each layer
overriding the one before it. The file is selected with -config or WARDEN_CONFIG.

Flags:
`, buildVersion())
	config.Usage(w)
}
