package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

// runPassword is `warden password set|redeem|policy`.
//
// Every subcommand that takes a password reads it from standard input and nowhere
// else. Not a flag, because arguments are visible in `ps` and land in shell history;
// not an environment variable, because those are readable from /proc and inherited by
// children. This is the same reason `docker login` grew --password-stdin.
func runPassword(args []string, stdout, stderr io.Writer) error {
	sub, rest := splitCommand(args)
	switch sub {
	case "set":
		return runPasswordSet(rest, stdout, stderr)
	case "redeem":
		return runPasswordRedeem(rest, stdout, stderr)
	case "policy":
		return runPasswordPolicy(rest, stdout, stderr)
	default:
		return fmt.Errorf("unknown subcommand %q; want set, redeem or policy", sub)
	}
}

// withAuthenticator opens both pools and builds an Authenticator.
//
// Both, and not just the system one the other administrative commands use: credentials
// are reached by (tenant, email) through the row-level-security-scoped pool, and a
// setup token has to be resolved before any tenant scope exists.
func withAuthenticator(
	args []string, stderr io.Writer,
	fn func(context.Context, *authn.Authenticator, *config.Config) error,
) error {
	cfg, err := config.Load(config.Source{
		Args: args, LookupEnv: os.LookupEnv, ReadFile: os.ReadFile, Stderr: stderr,
	})
	if err != nil {
		return err
	}

	ctx := context.Background()
	system, err := store.Open(ctx, cfg, store.SystemAccess)
	if err != nil {
		return err
	}
	defer system.Close()

	tenantPool, err := store.Open(ctx, cfg, store.TenantScoped)
	if err != nil {
		return err
	}
	defer tenantPool.Close()

	breached, closeBreached, err := openBreachSet(cfg, stderr)
	if err != nil {
		return err
	}
	defer closeBreached()

	// The keyring, because enrolling a second factor seals a TOTP secret with it. The
	// session and refresh stores are deliberately absent: the CLI enrols and issues, it
	// never redeems a recovery code, and a redemption is the only operation that has to
	// end sessions.
	keyring, err := cfg.Keyring(secrets.OSLookupEnv, secrets.OSReadFile)
	if err != nil {
		return err
	}

	a, err := authn.New(tenantPool, system, authn.Options{
		Breached: breached,
		Log:      slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		Audit:    audit.NewWriter(),
		Keyring:  keyring,
	})
	if err != nil {
		return err
	}
	return fn(ctx, a, cfg)
}

// openBreachSet assembles the breached-password corpus from configuration.
//
// The built-in list is always present and the configured file is layered on top, so a
// deployment that points at a partial download does not end up with *less* coverage
// than one that points at nothing.
func openBreachSet(cfg *config.Config, stderr io.Writer) (authn.BreachSet, func(), error) {
	embedded := authn.NewEmbeddedSet()
	if cfg.Security.BreachedPasswordFile == "" {
		fmt.Fprintf(stderr,
			"warning: security.breached_password_file is not set, so the breached-password "+
				"check (SPEC §7.2) is running against the %d-entry built-in list only\n", embedded.Size())
		return embedded, func() {}, nil
	}

	file, err := authn.OpenHIBPFile(cfg.Security.BreachedPasswordFile)
	if err != nil {
		return nil, nil, err
	}
	return authn.ChainedSet{embedded, file}, func() { _ = file.Close() }, nil //nolint:errcheck // closing a read-only file
}

// readPassword takes one line from standard input.
func readPassword(what string) (string, error) {
	stat, err := os.Stdin.Stat()
	if err == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
		// A terminal. There is no way to turn echo off without another dependency, and
		// a password typed in the clear ends up in a scrollback buffer and quite often
		// in a screen recording, so refuse rather than do it badly.
		return "", fmt.Errorf(
			"%s must be piped to standard input, not typed at a prompt, so that it does not "+
				"appear on screen or in shell history; for example, "+
				"printf '%%s' \"$PASSWORD\" | warden password <subcommand>", what)
	}

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading %s from standard input: %w", what, err)
	}
	// Only the line terminator is stripped. A password may legitimately begin or end
	// with a space, and silently trimming it would set a credential the user cannot
	// then type.
	password := strings.TrimRight(line, "\r\n")
	if password == "" {
		return "", fmt.Errorf("no %s was supplied on standard input", what)
	}
	return password, nil
}

func runPasswordSet(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden password set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	email := fs.String("email", "", "the user's email address")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" || *email == "" {
		return errors.New("warden password set needs -tenant and -email")
	}

	password, err := readPassword("the new password")
	if err != nil {
		return err
	}

	return withAuthenticator(rest, stderr, func(ctx context.Context, a *authn.Authenticator, _ *config.Config) error {
		tenantID := tenantIDFromSlug(*tenant)
		userID, err := a.UserIDByEmail(ctx, tenantID, *email)
		if err != nil {
			return err
		}
		if err := a.SetPassword(ctx, tenantID, userID, password); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "set the password for %s (%s)\n", *email, userID)
		return nil
	})
}

func runPasswordRedeem(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden password redeem", flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token", "", "the token from the setup URL `warden init` printed")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *token == "" {
		return errors.New("warden password redeem needs -token, from the URL `warden init` printed")
	}

	password, err := readPassword("the password to set")
	if err != nil {
		return err
	}

	return withAuthenticator(rest, stderr, func(ctx context.Context, a *authn.Authenticator, _ *config.Config) error {
		tenantID, userID, err := a.RedeemSetupToken(ctx, *token, password)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "setup complete: %s in tenant %s can now sign in\n", userID, tenantID)
		fmt.Fprintln(stdout, "the setup link has been consumed and will not work again")
		return nil
	})
}

func runPasswordPolicy(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden password policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	minLength := fs.Int("min-length", 0, "minimum length; 0 leaves it unchanged")
	maxLength := fs.Int("max-length", 0, "maximum length; 0 leaves it unchanged")
	requireUpper := fs.String("require-upper", "", "true or false")
	requireLower := fs.String("require-lower", "", "true or false")
	requireDigit := fs.String("require-digit", "", "true or false")
	requireSymbol := fs.String("require-symbol", "", "true or false")
	checkBreached := fs.String("check-breached", "", "true or false; SPEC §7.2 makes this mandatory, so turning it off is a deliberate act")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" {
		return errors.New("warden password policy needs -tenant")
	}

	return withAuthenticator(rest, stderr, func(ctx context.Context, a *authn.Authenticator, _ *config.Config) error {
		tenantID := tenantIDFromSlug(*tenant)
		policy, err := a.Policy(ctx, tenantID)
		if err != nil {
			return err
		}

		changed := false
		setInt := func(target *int, value int) {
			if value != 0 {
				*target, changed = value, true
			}
		}
		setBool := func(target *bool, value string) error {
			switch strings.ToLower(value) {
			case "":
			case "true", "yes", "on":
				*target, changed = true, true
			case "false", "no", "off":
				*target, changed = false, true
			default:
				return fmt.Errorf("%q is not true or false", value)
			}
			return nil
		}

		setInt(&policy.MinLength, *minLength)
		setInt(&policy.MaxLength, *maxLength)
		for _, pair := range []struct {
			target *bool
			value  string
		}{
			{&policy.RequireUpper, *requireUpper},
			{&policy.RequireLower, *requireLower},
			{&policy.RequireDigit, *requireDigit},
			{&policy.RequireSymbol, *requireSymbol},
			{&policy.CheckBreached, *checkBreached},
		} {
			if err := setBool(pair.target, pair.value); err != nil {
				return err
			}
		}

		if changed {
			if err := a.SetPolicy(ctx, tenantID, policy); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "updated the password policy for %s\n\n", *tenant)
		}

		fmt.Fprintf(stdout, "minimum length   %d\n", policy.MinLength)
		fmt.Fprintf(stdout, "maximum length   %d\n", policy.MaxLength)
		fmt.Fprintf(stdout, "require upper    %t\n", policy.RequireUpper)
		fmt.Fprintf(stdout, "require lower    %t\n", policy.RequireLower)
		fmt.Fprintf(stdout, "require digit    %t\n", policy.RequireDigit)
		fmt.Fprintf(stdout, "require symbol   %t\n", policy.RequireSymbol)
		fmt.Fprintf(stdout, "check breached   %t\n", policy.CheckBreached)
		if !policy.RequireUpper && !policy.RequireLower && !policy.RequireDigit && !policy.RequireSymbol {
			fmt.Fprintln(stdout,
				"\ncomposition rules are off, per NIST 800-63B: they do not improve the passwords "+
					"people choose, and they do push them towards reuse")
		}
		return nil
	})
}

// tenantIDFromSlug mirrors the derivation in internal/provision: a tenant's id is its
// slug with the separators normalised. Deriving rather than looking up keeps these
// commands from needing a query of their own for something that is a pure function.
func tenantIDFromSlug(slug string) string {
	return "ten_" + strings.NewReplacer(".", "_", "-", "_", ":", "_", "/", "_").Replace(slug)
}
