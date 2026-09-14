package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/oidcop"
	"github.com/warden-project/warden/internal/store"
)

// runClient is `warden client register|list|show|secret|disable|enable|delete`.
//
// OAuth clients are not application manifests, and the two are easy to confuse because
// both describe "an application". A manifest declares a permission surface and is
// published with `warden apply`; a client is a thing that performs a login and receives
// tokens. One manifest may have several clients — a web front end, a mobile app, a CLI.
func runClient(args []string, stdout, stderr io.Writer) error {
	sub, rest := splitCommand(args)
	switch sub {
	case "register":
		return runClientRegister(rest, stdout, stderr)
	case "list", "":
		return runClientList(rest, stdout, stderr)
	case "show":
		return runClientShow(rest, stdout, stderr)
	case "secret":
		return runClientSecret(rest, stdout, stderr)
	case "disable":
		return runClientSetEnabled(rest, stdout, stderr, false)
	case "enable":
		return runClientSetEnabled(rest, stdout, stderr, true)
	case "delete":
		return runClientDelete(rest, stdout, stderr)
	default:
		return fmt.Errorf(
			"unknown subcommand %q; want register, list, show, secret, disable, enable or delete", sub)
	}
}

func withClients(
	args []string, stderr io.Writer,
	fn func(context.Context, *oidcop.Clients, *config.Config) error,
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

	clients, err := oidcop.NewClients(tenantPool, system, authn.DefaultParams())
	if err != nil {
		return err
	}
	return fn(ctx, clients, cfg)
}

// stringList parses a repeatable comma-separated flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			*l = append(*l, trimmed)
		}
	}
	return nil
}

func runClientRegister(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden client register", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	key := fs.String("key", "", "a short handle for this client, unique within the tenant")
	name := fs.String("name", "", "display name; defaults to the key")
	confidential := fs.Bool("confidential", false,
		"this client can keep a secret (a server-side app). Public by default, because a "+
			"single-page app or a mobile binary cannot")
	var redirects, scopes, audiences, grants, logoutRedirects stringList
	fs.Var(&redirects, "redirect-uri", "an allowed redirect_uri; repeatable. Matched exactly, no wildcards")
	fs.Var(&logoutRedirects, "post-logout-redirect-uri", "an allowed post-logout redirect_uri; repeatable")
	fs.Var(&scopes, "scope", "a scope this client may request; repeatable")
	fs.Var(&audiences, "audience", "an audience tokens may be addressed to; repeatable")
	fs.Var(&grants, "grant", "a grant type; repeatable. Defaults to authorization_code and refresh_token")

	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" || *key == "" {
		return errors.New("warden client register needs -tenant and -key")
	}

	return withClients(rest, stderr, func(ctx context.Context, clients *oidcop.Clients, _ *config.Config) error {
		client, secret, err := clients.Register(ctx, oidcop.NewClientOptions{
			TenantID:               tenantIDFromSlug(*tenant),
			Key:                    *key,
			Name:                   *name,
			Public:                 !*confidential,
			RedirectURIs:           redirects,
			GrantTypes:             grants,
			Scopes:                 scopes,
			Audiences:              audiences,
			PostLogoutRedirectURIs: logoutRedirects,
		})
		if err != nil {
			return err
		}

		fmt.Fprintf(stdout, "registered %s\n\n", client.Key)
		fmt.Fprintf(stdout, "  client_id     %s\n", client.ID)
		fmt.Fprintf(stdout, "  kind          %s\n", kindOf(client))
		fmt.Fprintf(stdout, "  redirect_uris %s\n", strings.Join(client.RedirectURIs, "\n                "))
		fmt.Fprintf(stdout, "  grant_types   %s\n", strings.Join(client.GrantTypes, ", "))
		fmt.Fprintf(stdout, "  scopes        %s\n", strings.Join(client.Scopes, ", "))
		fmt.Fprintf(stdout, "  PKCE          %s\n", pkceNote(client))

		if secret != "" {
			fmt.Fprintf(stdout, "\n  client_secret %s\n", secret)
			fmt.Fprintln(stdout,
				"\nThis secret is shown once and is not recoverable: only its hash is stored.")
		} else {
			fmt.Fprintln(stdout,
				"\nNo secret: this is a public client, so it proves itself with PKCE rather than\n"+
					"with something it would have to ship to the user's device.")
		}
		return nil
	})
}

func kindOf(c *oidcop.Client) string {
	if c.Public {
		return "public"
	}
	return "confidential"
}

func pkceNote(c *oidcop.Client) string {
	if c.Public {
		return "required (public clients may not opt out)"
	}
	if c.RequirePKCE {
		return "required"
	}
	return "optional"
}

func runClientList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden client list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" {
		return errors.New("warden client list needs -tenant")
	}

	return withClients(rest, stderr, func(ctx context.Context, clients *oidcop.Clients, _ *config.Config) error {
		rows, err := clients.List(ctx, tenantIDFromSlug(*tenant))
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Fprintf(stdout, "no OAuth clients in %s\n", *tenant)
			return nil
		}
		fmt.Fprintf(stdout, "%-20s %-28s %-13s %-8s %s\n", "KEY", "CLIENT_ID", "KIND", "STATUS", "REDIRECT URIS")
		for i := range rows {
			r := &rows[i]
			kind, status := "public", "enabled"
			if !r.Public {
				kind = "confidential"
			}
			if r.DisabledAt != nil {
				status = "disabled"
			}
			fmt.Fprintf(stdout, "%-20s %-28s %-13s %-8s %s\n",
				r.Key, r.ID, kind, status, strings.Join(r.RedirectUris, " "))
		}
		return nil
	})
}

// clientRef registers the two ways to name a client: -client takes the protocol
// client_id, -key the handle an administrator chose.
func clientRef(fs *flag.FlagSet) (id, key *string) {
	return fs.String("client", "", "the client_id"),
		fs.String("key", "", "the client's handle within the tenant")
}

func resolveClient(ctx context.Context, clients *oidcop.Clients, tenantID, id, key string) (*oidcop.Client, error) {
	switch {
	case id != "":
		return clients.ByID(ctx, tenantID, id)
	case key != "":
		return clients.ByKey(ctx, tenantID, key)
	default:
		return nil, errors.New("name the client with -client <client_id> or -key <handle>")
	}
}

func runClientShow(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden client show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	id, key := clientRef(fs)
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" {
		return errors.New("warden client show needs -tenant")
	}

	return withClients(rest, stderr, func(ctx context.Context, clients *oidcop.Clients, _ *config.Config) error {
		client, err := resolveClient(ctx, clients, tenantIDFromSlug(*tenant), *id, *key)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s (%s)\n\n", client.Name, client.Key)
		fmt.Fprintf(stdout, "  client_id       %s\n", client.ID)
		fmt.Fprintf(stdout, "  kind            %s\n", kindOf(client))
		fmt.Fprintf(stdout, "  auth method     %s\n", client.TokenEndpointAuthMethod)
		fmt.Fprintf(stdout, "  PKCE            %s\n", pkceNote(client))
		fmt.Fprintf(stdout, "  grant_types     %s\n", strings.Join(client.GrantTypes, ", "))
		fmt.Fprintf(stdout, "  response_types  %s\n", strings.Join(client.ResponseTypes, ", "))
		fmt.Fprintf(stdout, "  scopes          %s\n", strings.Join(client.Scopes, ", "))
		fmt.Fprintf(stdout, "  audiences       %s\n", strings.Join(client.GetAudience(), ", "))
		for i, uri := range client.RedirectURIs {
			label := "redirect_uris"
			if i > 0 {
				label = ""
			}
			fmt.Fprintf(stdout, "  %-15s %s\n", label, uri)
		}
		for i, uri := range client.PostLogoutRedirectURIs {
			label := "logout redirects"
			if i > 0 {
				label = ""
			}
			fmt.Fprintf(stdout, "  %-15s %s\n", label, uri)
		}
		if !client.Enabled() {
			fmt.Fprintf(stdout, "\n  DISABLED since %s\n", client.DisabledAt.UTC().Format("2006-01-02T15:04:05Z"))
		}
		return nil
	})
}

func runClientSecret(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden client secret", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	id, key := clientRef(fs)
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" {
		return errors.New("warden client secret needs -tenant")
	}

	return withClients(rest, stderr, func(ctx context.Context, clients *oidcop.Clients, _ *config.Config) error {
		tenantID := tenantIDFromSlug(*tenant)
		client, err := resolveClient(ctx, clients, tenantID, *id, *key)
		if err != nil {
			return err
		}
		if client.Public {
			return fmt.Errorf("%s is a public client and has no secret", client.Key)
		}

		secret, err := clients.SetSecret(ctx, tenantID, client.ID)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "rotated the secret for %s\n\n  %s\n\n", client.Key, secret)
		fmt.Fprintln(stdout,
			"The previous secret stopped working immediately. There is no overlap window for\n"+
				"client secrets, so deploy this before the next token request.")
		return nil
	})
}

func runClientSetEnabled(args []string, stdout, stderr io.Writer, enabled bool) error {
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	fs := flag.NewFlagSet("warden client "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	id, key := clientRef(fs)
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" {
		return fmt.Errorf("warden client %s needs -tenant", verb)
	}

	return withClients(rest, stderr, func(ctx context.Context, clients *oidcop.Clients, _ *config.Config) error {
		tenantID := tenantIDFromSlug(*tenant)
		client, err := resolveClient(ctx, clients, tenantID, *id, *key)
		if err != nil {
			return err
		}
		if err := clients.SetEnabled(ctx, tenantID, client.ID, enabled); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%sd %s (%s)\n", verb, client.Key, client.ID)
		if !enabled {
			fmt.Fprintln(stdout,
				"Existing tokens are unaffected; they expire on their own schedule. Disabling\n"+
					"stops new ones being issued.")
		}
		return nil
	})
}

func runClientDelete(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden client delete", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tenant := fs.String("tenant", "", "tenant slug")
	id, key := clientRef(fs)
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}
	if *tenant == "" {
		return errors.New("warden client delete needs -tenant")
	}

	return withClients(rest, stderr, func(ctx context.Context, clients *oidcop.Clients, _ *config.Config) error {
		tenantID := tenantIDFromSlug(*tenant)
		client, err := resolveClient(ctx, clients, tenantID, *id, *key)
		if err != nil {
			return err
		}
		if err := clients.Delete(ctx, tenantID, client.ID); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "deleted %s (%s)\n", client.Key, client.ID)
		return nil
	})
}
