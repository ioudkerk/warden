package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

// runKeys is `warden keys list|rotate|show`.
//
// Rotation is on a schedule and the worker does it unattended, so this command exists
// for the two cases a schedule cannot serve: an operator who needs to rotate now
// because a key may have been exposed, and an operator who needs to see what is
// published before believing a relying party's complaint.
func runKeys(args []string, stdout, stderr io.Writer) error {
	sub, rest := splitCommand(args)
	switch sub {
	case "list", "":
		return runKeysList(rest, stdout, stderr)
	case "show":
		return runKeysShow(rest, stdout, stderr)
	case "rotate":
		return runKeysRotate(rest, stdout, stderr)
	default:
		return fmt.Errorf("unknown subcommand %q; want list, show or rotate", sub)
	}
}

// withKeyManager opens the system pool and builds the key manager from configuration.
func withKeyManager(args []string, stderr io.Writer, fn func(context.Context, *keys.Manager, *config.Config) error) error {
	cfg, err := config.Load(config.Source{
		Args: args, LookupEnv: os.LookupEnv, ReadFile: os.ReadFile, Stderr: stderr,
	})
	if err != nil {
		return err
	}
	keyring, err := cfg.Keyring(secrets.OSLookupEnv, secrets.OSReadFile)
	if err != nil {
		return err
	}

	ctx := context.Background()
	db, err := store.Open(ctx, cfg, store.SystemAccess)
	if err != nil {
		return err
	}
	defer db.Close()

	// Errors are the only thing a one-shot command has to say; the manager's
	// informational logging would otherwise interleave with its output.
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m, err := keys.NewManager(db, keyring, cfg, log)
	if err != nil {
		return err
	}
	return fn(ctx, m, cfg)
}

func runKeysList(args []string, stdout, stderr io.Writer) error {
	return withKeyManager(args, stderr, func(ctx context.Context, m *keys.Manager, cfg *config.Config) error {
		rows, err := m.List(ctx)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Fprintln(stdout, "no signing keys: run `warden init`")
			return nil
		}

		fmt.Fprintf(stdout, "%-24s %-8s %-9s %-20s %s\n", "KID", "ALG", "STATUS", "CREATED", "NOTE")
		for _, r := range rows {
			note := ""
			switch r.Status {
			case "active":
				if r.ExpiresAt != nil {
					note = "signs until " + r.ExpiresAt.UTC().Format(time.RFC3339)
				}
			case "previous":
				if r.RetiredAt != nil {
					// The date that matters for a 'previous' key is when it stops
					// being published, not when it stopped signing.
					note = "leaves JWKS " + r.RetiredAt.Add(cfg.Security.KeyOverlapWindow).
						UTC().Format(time.RFC3339)
				}
			case "retired":
				note = "not published"
			}
			fmt.Fprintf(stdout, "%-24s %-8s %-9s %-20s %s\n",
				r.Kid, r.Algorithm, r.Status, r.CreatedAt.UTC().Format(time.RFC3339), note)
		}
		return nil
	})
}

func runKeysShow(args []string, stdout, stderr io.Writer) error {
	return withKeyManager(args, stderr, func(ctx context.Context, m *keys.Manager, cfg *config.Config) error {
		state, err := m.State(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "active key       %s (%s)\n", state.KID, state.Algorithm)
		fmt.Fprintf(stdout, "created          %s\n", state.CreatedAt.UTC().Format(time.RFC3339))
		if state.ExpiresAt != nil {
			fmt.Fprintf(stdout, "rotates          %s\n", state.ExpiresAt.UTC().Format(time.RFC3339))
		}
		fmt.Fprintf(stdout, "overlap window   %s\n", cfg.Security.KeyOverlapWindow)
		if state.Due {
			fmt.Fprintln(stdout, "\nthis key is due for rotation")
		}
		return nil
	})
}

func runKeysRotate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden keys rotate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	force := fs.Bool("force", false,
		"rotate even if the current key is not yet due, e.g. after a suspected exposure")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}

	return withKeyManager(rest, stderr, func(ctx context.Context, m *keys.Manager, cfg *config.Config) error {
		kid, err := m.Rotate(ctx, *force)
		switch {
		case errors.Is(err, keys.ErrRotationHeld):
			fmt.Fprintln(stdout, "another process is rotating the signing key; nothing to do")
			return nil
		case err != nil:
			return err
		case kid == "":
			fmt.Fprintln(stdout,
				"the active signing key is not due for rotation; pass -force to rotate anyway")
			return nil
		}

		fmt.Fprintf(stdout, "rotated: new signing key %s\n", kid)
		// Said explicitly because it is the part an operator rotating after an
		// exposure needs to act on: the old key still verifies until the window
		// closes, and shortening that is a configuration change, not a command.
		fmt.Fprintf(stdout,
			"the previous key stays in JWKS for %s, so tokens it signed keep verifying\n",
			cfg.Security.KeyOverlapWindow)
		return nil
	})
}
