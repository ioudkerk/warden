package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/config"
)

// mfaStatus names the subcommand that reports what a user has enrolled.
const mfaStatus = "status"

// runMFA is `warden mfa enrol|confirm|codes|status|remove|require`.
//
// The console (M6) is where people will do this; the CLI exists first because an
// administrator needs some way to help somebody who has lost a phone, and because a second
// factor nobody can enrol is a feature that only exists in tests.
func runMFA(args []string, stdout, stderr io.Writer) error {
	sub, rest := splitCommand(args)
	switch sub {
	case "enrol", "enroll":
		return runMFAEnrol(rest, stdout, stderr)
	case "confirm":
		return runMFAConfirm(rest, stdout, stderr)
	case "codes":
		return runMFACodes(rest, stdout, stderr)
	case mfaStatus:
		return runMFAStatus(rest, stdout, stderr)
	case "remove":
		return runMFARemove(rest, stdout, stderr)
	case "require":
		return runMFARequire(rest, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "usage: warden mfa <enrol|confirm|codes|status|remove|require> [flags]")
		return fmt.Errorf("unknown mfa subcommand %q", sub)
	}
}

// withMFAUser resolves (tenant, email) to a user and hands it to a subcommand.
//
// The subcommand registers its own flags through `register`, so each one owns its
// arguments rather than a shared helper knowing about all of them.
func withMFAUser(
	name string, args []string, stderr io.Writer,
	register func(fs *flag.FlagSet),
	fn func(ctx context.Context, a *authn.Authenticator, cfg *config.Config, tenantID, userID, email string) error,
) error {
	fs := flag.NewFlagSet("warden mfa "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	email := fs.String("email", "", "the user's email address")
	if register != nil {
		register(fs)
	}

	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" || *email == "" {
		return fmt.Errorf("warden mfa %s needs -tenant and -email", name)
	}

	return withAuthenticator(rest, stderr, func(ctx context.Context, a *authn.Authenticator, cfg *config.Config) error {
		tenantID := tenantIDFromSlug(*tenant)
		userID, err := a.UserIDByEmail(ctx, tenantID, *email)
		if err != nil {
			return err
		}
		return fn(ctx, a, cfg, tenantID, userID, *email)
	})
}

func runMFAEnrol(args []string, stdout, stderr io.Writer) error {
	return withMFAUser("enrol", args, stderr, nil, func(
		ctx context.Context, a *authn.Authenticator, cfg *config.Config, tenantID, userID, email string,
	) error {
		enrolment, err := a.EnrolTOTP(ctx, tenantID, userID, issuerLabel(cfg), email)
		if err != nil {
			return err
		}

		fmt.Fprintf(stdout, "enrolment started for %s\n\n", email)
		fmt.Fprintf(stdout, "  secret  %s\n", enrolment.Secret)
		fmt.Fprintf(stdout, "  uri     %s\n\n", enrolment.URI)
		fmt.Fprintln(stdout, "Scan the URI as a QR code, or type the secret into an authenticator.")
		fmt.Fprintln(stdout, "It is not a second factor yet: confirm it with a code from the device.")
		fmt.Fprintf(stdout, "\n  warden mfa confirm -tenant … -email %s -code 123456\n", email)
		return nil
	})
}

func runMFAConfirm(args []string, stdout, stderr io.Writer) error {
	var code string
	register := func(fs *flag.FlagSet) {
		fs.StringVar(&code, "code", "", "the six-digit code the authenticator is showing")
	}
	return withMFAUser("confirm", args, stderr, register, func(
		ctx context.Context, a *authn.Authenticator, _ *config.Config, tenantID, userID, email string,
	) error {
		if code == "" {
			return errors.New("warden mfa confirm needs -code, from the authenticator")
		}
		if err := a.ConfirmTOTP(ctx, tenantID, userID, code); err != nil {
			if errors.Is(err, authn.ErrInvalidSecondFactor) {
				return errors.New(
					"that code was not accepted. Check the device's clock, and use the code " +
						"it is showing now rather than one that has already been used")
			}
			return err
		}

		fmt.Fprintf(stdout, "confirmed. %s now signs in with a second factor.\n\n", email)
		fmt.Fprintln(stdout, "Issue recovery codes next, or a lost phone means a lost account:")
		fmt.Fprintf(stdout, "\n  warden mfa codes -tenant … -email %s\n", email)
		return nil
	})
}

func runMFACodes(args []string, stdout, stderr io.Writer) error {
	return withMFAUser("codes", args, stderr, nil, func(
		ctx context.Context, a *authn.Authenticator, _ *config.Config, tenantID, userID, email string,
	) error {
		codes, err := a.GenerateRecoveryCodes(ctx, tenantID, userID)
		if err != nil {
			return err
		}

		fmt.Fprintf(stdout, "recovery codes for %s\n\n", email)
		for _, code := range codes {
			fmt.Fprintf(stdout, "  %s\n", code)
		}
		fmt.Fprintln(stdout, "\nShown once. Each works exactly once, and using one ends every")
		fmt.Fprintln(stdout, "session and refresh token this account holds (SPEC §7.2).")
		fmt.Fprintln(stdout, "Any codes issued earlier have just stopped working.")
		return nil
	})
}

func runMFAStatus(args []string, stdout, stderr io.Writer) error {
	return withMFAUser(mfaStatus, args, stderr, nil, func(
		ctx context.Context, a *authn.Authenticator, _ *config.Config, tenantID, userID, email string,
	) error {
		factors, err := a.Factors(ctx, tenantID, userID)
		if err != nil {
			return err
		}
		remaining, err := a.RemainingRecoveryCodes(ctx, tenantID, userID)
		if err != nil {
			return err
		}

		fmt.Fprintf(stdout, "second factors for %s\n\n", email)
		if len(factors) == 0 {
			fmt.Fprintln(stdout, "  none enrolled")
			return nil
		}

		for _, factor := range factors {
			if factor.Type == authn.FactorRecoveryCode {
				continue // summarised below rather than printed ten times
			}
			state := "pending confirmation"
			if factor.Confirmed {
				state = "confirmed"
			}
			used := "never used"
			if factor.LastUsedAt != nil {
				used = "last used " + factor.LastUsedAt.Format("2006-01-02 15:04")
			}
			fmt.Fprintf(stdout, "  %-12s %-22s %s\n", factor.Type, state, used)
			fmt.Fprintf(stdout, "  %-12s %s\n", "", factor.ID)
		}
		fmt.Fprintf(stdout, "\n  recovery codes: %d unused\n", remaining)
		if remaining == 0 {
			fmt.Fprintln(stdout, "  none left — issue a new set before this account loses its device")
		}
		return nil
	})
}

func runMFARemove(args []string, stdout, stderr io.Writer) error {
	var id string
	register := func(fs *flag.FlagSet) {
		fs.StringVar(&id, "id", "", "the credential id to remove, from `warden mfa status`")
	}
	return withMFAUser("remove", args, stderr, register, func(
		ctx context.Context, a *authn.Authenticator, _ *config.Config, tenantID, userID, email string,
	) error {
		if id == "" {
			return errors.New("warden mfa remove needs -id, from `warden mfa status`")
		}
		if err := a.RemoveFactor(ctx, tenantID, userID, id); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "removed %s from %s\n", id, email)
		return nil
	})
}

func runMFARequire(args []string, stdout, stderr io.Writer) error {
	var value string
	register := func(fs *flag.FlagSet) {
		fs.StringVar(&value, "value", "on", "on or off")
	}
	return withMFAUser("require", args, stderr, register, func(
		ctx context.Context, a *authn.Authenticator, _ *config.Config, tenantID, userID, email string,
	) error {
		on := strings.EqualFold(value, "on")
		if err := a.SetMFAEnforced(ctx, tenantID, userID, on); err != nil {
			if errors.Is(err, authn.ErrNoSecondFactor) {
				return errors.New(
					"this account has no confirmed second factor, so requiring one would lock " +
						"it out of itself. Enrol one first")
			}
			return err
		}
		if on {
			fmt.Fprintf(stdout, "%s must now present a second factor to sign in\n", email)
		} else {
			fmt.Fprintf(stdout, "%s no longer has to present a second factor\n", email)
		}
		return nil
	})
}

// issuerLabel is what an authenticator application shows above the code.
func issuerLabel(cfg *config.Config) string {
	if cfg == nil || cfg.Issuer == "" {
		return "Warden"
	}
	trimmed := strings.TrimPrefix(strings.TrimPrefix(cfg.Issuer, "https://"), "http://")
	return strings.TrimSuffix(trimmed, "/")
}
