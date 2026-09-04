package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/provision"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

// The administrative commands. They exist because the console does not (M6) and the
// management API does not (M2/M15), and without some way to declare an application
// and hand out a role, Warden cannot answer a question about anything.
//
// Each opens the system pool, which is refused unless database.system_url names a
// role that can bypass row-level security — these operations are cross-tenant by
// nature, and doing them through a tenant-scoped connection would quietly affect
// nothing.

func withProvisioner(args []string, stderr io.Writer, fn func(context.Context, *provision.Provisioner, *config.Config) error) error {
	cfg, err := config.Load(config.Source{
		Args: args, LookupEnv: os.LookupEnv, ReadFile: os.ReadFile, Stderr: stderr,
	})
	if err != nil {
		return err
	}

	ctx := context.Background()
	db, err := store.Open(ctx, cfg, store.SystemAccess)
	if err != nil {
		return err
	}
	defer db.Close()

	p, err := provision.New(db)
	if err != nil {
		return err
	}
	return fn(ctx, p, cfg)
}

// splitOwnFlags separates this command's own flags from the configuration flags,
// which are parsed by config.Load. Keeping them apart means a command's flags cannot
// silently shadow a configuration setting.
func splitOwnFlags(fs *flag.FlagSet, args []string) (own, rest []string) {
	known := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) { known[f.Name] = true })

	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			rest = append(rest, a)
			continue
		}
		name := a[1:]
		if name != "" && name[0] == '-' {
			name = name[1:]
		}
		value := ""
		hasInline := false
		for j := 0; j < len(name); j++ {
			if name[j] == '=' {
				name, value, hasInline = name[:j], name[j+1:], true
				break
			}
		}
		target := &rest
		if known[name] {
			target = &own
		}
		if hasInline {
			*target = append(*target, "-"+name+"="+value)
			continue
		}
		*target = append(*target, "-"+name)
		if i+1 < len(args) && (args[i+1] == "" || args[i+1][0] != '-') {
			i++
			*target = append(*target, args[i])
		}
	}
	return own, rest
}

func runApply(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("f", "", "path to the application manifest (warden.yaml)")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("usage: warden apply -f <manifest.yaml>")
	}

	manifest, err := provision.LoadManifest(*file)
	if err != nil {
		return err
	}

	return withProvisioner(rest, stderr, func(ctx context.Context, p *provision.Provisioner, _ *config.Config) error {
		result, err := p.Apply(ctx, manifest)
		if err != nil {
			return err
		}
		verb := "updated"
		if result.Created {
			verb = "created"
		}
		fmt.Fprintf(stdout, "application %q %s: %d permissions, %d role templates, %d ui elements\n",
			result.Application, verb, result.Permissions, result.Roles, result.UIElements)
		return nil
	})
}

func runTenant(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden tenant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	slug := fs.String("slug", "", "tenant slug, e.g. acme")
	name := fs.String("name", "", "display name (defaults to the slug)")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *slug == "" {
		return fmt.Errorf("usage: warden tenant -slug <slug> [-name <name>]")
	}

	return withProvisioner(rest, stderr, func(ctx context.Context, p *provision.Provisioner, _ *config.Config) error {
		id, err := p.CreateTenant(ctx, *slug, *name)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "tenant %s created (%s), enrolled in every registered application\n", *slug, id)
		return nil
	})
}

func runUser(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden user", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	email := fs.String("email", "", "the user's email address")
	attrsJSON := fs.String("attributes", "", `JSON attributes readable from conditions, e.g. '{"department":"finance"}'`)
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" || *email == "" {
		return fmt.Errorf("usage: warden user -tenant <slug> -email <email> [-attributes <json>]")
	}

	attrs := map[string]any{}
	if *attrsJSON != "" {
		if err := json.Unmarshal([]byte(*attrsJSON), &attrs); err != nil {
			return fmt.Errorf("-attributes is not valid JSON: %w", err)
		}
	}

	return withProvisioner(rest, stderr, func(ctx context.Context, p *provision.Provisioner, _ *config.Config) error {
		id, err := p.CreateUser(ctx, *tenant, *email, attrs)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s\n", id)
		return nil
	})
}

func runGrant(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden grant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	user := fs.String("user", "", "subject id, as printed by `warden user`")
	group := fs.String("group", "", "group id, instead of a user")
	role := fs.String("role", "", "role key, e.g. billing.approver")
	scope := fs.String("scope", "tenant", "tenant | app:<key> | app:<key>/env:<name> | <app>.<type>:<id> | <app>.<type>:<id>/**")
	condition := fs.String("condition", "", "CEL condition narrowing the grant")
	until := fs.String("until", "", "RFC 3339 expiry, for a time-boxed elevation")
	reason := fs.String("reason", "", "why this was granted; recorded for audit")
	as := fs.String("as", "", "the subject making this assignment; without it the CLI acts as the deployment operator, which bypasses the escalation guard")
	revoke := fs.String("revoke", "", "grant id to remove instead of creating one")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}

	if *revoke != "" {
		if *tenant == "" {
			return fmt.Errorf("usage: warden grant -tenant <slug> -revoke <grant id>")
		}
		return withProvisioner(rest, stderr, func(ctx context.Context, p *provision.Provisioner, _ *config.Config) error {
			if err := p.Revoke(ctx, *tenant, *revoke); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "grant %s revoked\n", *revoke)
			return nil
		})
	}

	if *tenant == "" || *role == "" || (*user == "" && *group == "") {
		return fmt.Errorf("usage: warden grant -tenant <slug> -user <id> -role <key> [-scope <scope>] [-condition <cel>] [-until <rfc3339>]")
	}

	var validUntil *time.Time
	if *until != "" {
		t, err := time.Parse(time.RFC3339, *until)
		if err != nil {
			return fmt.Errorf("-until must be an RFC 3339 timestamp: %w", err)
		}
		validUntil = &t
	}

	return withProvisioner(rest, stderr, func(ctx context.Context, p *provision.Provisioner, _ *config.Config) error {
		actor := provision.Actor{SystemOperator: true}
		if *as != "" {
			actor = provision.Actor{SubjectID: *as}
		}
		id, err := p.Grant(ctx, provision.GrantOptions{
			Actor:      actor,
			TenantSlug: *tenant, UserID: *user, GroupID: *group, RoleKey: *role,
			Scope: *scope, Condition: *condition, ValidUntil: validUntil, Reason: *reason,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s\n", id)
		return nil
	})
}

func runResource(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden resource", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	ref := fs.String("ref", "", "resource reference, e.g. billing.invoice:4711")
	parent := fs.String("parent", "", "parent reference, enabling subtree grants to cascade")
	attrsJSON := fs.String("attributes", "", `JSON attributes readable from conditions`)
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" || *ref == "" {
		return fmt.Errorf("usage: warden resource -tenant <slug> -ref <app.type:id> [-parent <ref>] [-attributes <json>]")
	}

	attrs := map[string]any{}
	if *attrsJSON != "" {
		if err := json.Unmarshal([]byte(*attrsJSON), &attrs); err != nil {
			return fmt.Errorf("-attributes is not valid JSON: %w", err)
		}
	}

	return withProvisioner(rest, stderr, func(ctx context.Context, p *provision.Provisioner, _ *config.Config) error {
		if err := p.RegisterResource(ctx, *tenant, *ref, *parent, attrs); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s registered\n", *ref)
		return nil
	})
}

func runToken(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	name := fs.String("name", "", "a name for the service account, e.g. billing-api")
	mayExplain := fs.Bool("may-explain", false, "allow POST /v1/authz/explain in production; derivations describe the policy")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" || *name == "" {
		return fmt.Errorf("usage: warden token -tenant <slug> -name <name>")
	}

	return withProvisioner(rest, stderr, func(ctx context.Context, p *provision.Provisioner, _ *config.Config) error {
		token, err := p.CreateServiceAccount(ctx, *tenant, *name, *mayExplain)
		if err != nil {
			return err
		}
		// Shown once. Only the hash is stored, so this cannot be recovered — which
		// is the point, but it means saying so plainly here.
		fmt.Fprintf(stdout, "%s\n", token)
		fmt.Fprintf(stderr, "\nThis token is shown once and is not recoverable: only its hash is stored.\n")
		return nil
	})
}

func runAudit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	verify := fs.Bool("verify", false, "recompute the hash chain and report any break")
	tenant := fs.String("tenant", "", "show only this tenant's entries")
	limit := fs.Int("limit", 20, "how many entries to show, most recent first")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}

	return withProvisioner(rest, stderr, func(ctx context.Context, p *provision.Provisioner, _ *config.Config) error {
		if *verify {
			result, err := p.VerifyAudit(ctx)
			if err != nil {
				// A broken chain is a non-zero exit, not a line of output that a
				// scheduled job would scroll past.
				fmt.Fprintf(stdout, "audit log: %d entries, chain BROKEN\n", result.Entries)
				for _, problem := range result.Problems {
					fmt.Fprintf(stdout, "  %s\n", problem)
				}
				return err
			}
			fmt.Fprintf(stdout, "audit log verified: %d entries, chain intact\n", result.Entries)
			if result.Entries > 0 {
				fmt.Fprintf(stdout, "  from %s to %s\n",
					result.First.Format(time.RFC3339), result.Last.Format(time.RFC3339))
			}
			return nil
		}

		entries, err := p.RecentAudit(ctx, *tenant, *limit)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Fprintln(stdout, "no audit entries")
			return nil
		}
		for _, e := range entries {
			fmt.Fprintf(stdout, "%s  %-28s %-14s %s\n",
				e.OccurredAt.Format(time.RFC3339), e.Action, e.TargetType, e.TargetID)
			if e.Reason != "" {
				fmt.Fprintf(stdout, "%s  reason: %s\n", strings.Repeat(" ", 20), e.Reason)
			}
		}
		return nil
	})
}

// runInit bootstraps a fresh deployment (SPEC §20.2).
func runInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	email := fs.String("owner", "", "email address of the deployment's first owner")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *email == "" {
		return fmt.Errorf("usage: warden init -owner <email>")
	}

	cfg, err := config.Load(config.Source{
		Args: rest, LookupEnv: os.LookupEnv, ReadFile: os.ReadFile, Stderr: stderr,
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

	p, err := provision.New(db)
	if err != nil {
		return err
	}

	result, err := p.Bootstrap(ctx, *email, cfg.Issuer, cfg.Security.TokenSigningAlgorithm, keyring)
	if err != nil {
		if errors.Is(err, provision.ErrAlreadyInitialised) {
			// Refused rather than repeated: a second init on a live deployment would
			// mint a fresh setup URL for an existing owner, which is a password
			// reset with no authentication in front of it.
			return fmt.Errorf("%w. To recover access to an existing deployment, "+
				"use the account recovery flow rather than re-initialising", err)
		}
		return err
	}

	fmt.Fprintf(stdout, "Warden is initialised.\n\n")
	fmt.Fprintf(stdout, "  deployment tenant  %s\n", result.TenantID)
	fmt.Fprintf(stdout, "  first owner        %s (%s), role system.owner\n", result.Email, result.OwnerID)
	fmt.Fprintf(stdout, "  signing key        %s, %s\n", result.SigningKeyID, result.SigningKeyAlg)
	fmt.Fprintf(stdout, "\nOpen this once, within %s, to set the owner's credential:\n\n  %s\n\n",
		time.Until(result.ExpiresAt).Round(time.Minute), result.SetupURL)
	fmt.Fprintf(stderr,
		"This link is shown once and is not recoverable: only its hash is stored.\n"+
			"It expires at %s. Until it is used, the owner account exists but can do nothing.\n"+
			"There is no default password to change, because there is no default password.\n",
		result.ExpiresAt.Format(time.RFC3339))
	return nil
}

func runUI(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden ui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	application := fs.String("application", "", "application key, e.g. billing")
	element := fs.String("element", "", "element key, e.g. invoices.approve_button")
	requires := fs.String("requires", "", `what the element requires, as JSON: '{"any_of":[{"permission":"billing.invoice:approve"}]}'`)
	mode := fs.String("mode", "hidden", "what not-allowed looks like: hidden, disabled or read_only")
	message := fs.String("message", "", "tooltip shown when the mode is disabled")
	environment := fs.String("environment", "", "bind only in this environment; empty means all")
	as := fs.String("as", "", "the administrator making the change; recorded for audit")
	reason := fs.String("reason", "", "why; recorded for audit")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" || *application == "" || *element == "" || *requires == "" {
		return fmt.Errorf(`usage: warden ui -tenant <slug> -application <key> -element <key> ` +
			`-requires '{"any_of":[{"permission":"..."}]}' [-mode hidden|disabled|read_only]`)
	}

	actor := provision.Actor{SystemOperator: true}
	if *as != "" {
		actor = provision.Actor{SubjectID: *as}
	}

	return withProvisioner(rest, stderr, func(ctx context.Context, p *provision.Provisioner, _ *config.Config) error {
		if err := p.BindUIElement(ctx, provision.BindOptions{
			Actor: actor, TenantSlug: *tenant, Application: *application,
			ElementKey: *element, Environment: *environment,
			Requires: *requires, Mode: *mode, Message: *message, Reason: *reason,
		}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s bound: not-allowed renders as %s\n", *element, *mode)
		return nil
	})
}
