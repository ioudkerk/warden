package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/provision"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
)

// The demo fixture is SPEC §9.9's worked example, which is also
// conformance/cases/001-worked-example.yaml and what examples/demo-app expects. The
// three are meant to stay the same story: a reader who follows the specification, runs
// the corpus, and then clicks through the demo should recognise the same invoices.
const (
	seedTenantSlug = "acme"
	seedTenantName = "ACME"

	// Every seeded write carries this as its audit reason, so `warden audit` tells a
	// fixture apart from something an operator did on purpose.
	seedReason = "seeded development data"
)

type seedUser struct {
	email      string
	attributes map[string]any
}

var seedUsers = []seedUser{
	{email: "maria@acme.test", attributes: map[string]any{"approval_limit": 50000}},
	{email: "bob@acme.test"},
}

type seedResource struct {
	ref, parent string
	attributes  map[string]any
}

var seedResources = []seedResource{
	{ref: "billing.project:acme-2026"},
	{ref: "billing.project:other"},
	{ref: "billing.invoice:4711", parent: "billing.project:acme-2026",
		attributes: map[string]any{"amount": 30000, "status": "pending"}},
	{ref: "billing.invoice:4712", parent: "billing.project:acme-2026",
		attributes: map[string]any{"amount": 90000, "status": "pending"}},
	{ref: "billing.invoice:9002", parent: "billing.project:other",
		attributes: map[string]any{"amount": 30000, "status": "pending"}},
}

// runSeed builds a development deployment worth looking at: the billing application,
// a tenant, two users with different authority, the §9.9 invoices, and the grants that
// make the difference between them visible.
//
// It is idempotent so that `docker compose up` twice is not an error, and it refuses
// to run in production. That refusal is the important part. Seeding creates subjects
// with predictable identifiers and standing grants, which is precisely the shape M0-9
// exists to keep out of a real deployment — the fact that none of them has a
// credential yet is not enough of a defence to leave the door open.
func runSeed(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("warden seed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("f", "examples/warden.yaml", "application manifest to publish")
	owner := fs.String("owner", "owner@warden.local",
		"first owner, used only if the deployment has not been initialised yet")
	own, rest := splitOwnFlags(fs, args)
	if err := fs.Parse(own); err != nil {
		return err
	}

	manifest, err := provision.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}

	cfg, err := config.Load(config.Source{
		Args: rest, LookupEnv: os.LookupEnv, ReadFile: os.ReadFile, Stderr: stderr,
	})
	if err != nil {
		return err
	}
	if cfg.Environment == config.EnvProduction {
		return errors.New(
			"warden seed refuses to run in production: it creates users with predictable " +
				"identifiers and standing role grants, which is the situation `warden init` " +
				"exists to prevent. Use `warden apply`, `warden tenant` and `warden grant`")
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

	// A deployment has to exist before it can be seeded. Doing it here rather than
	// making the caller run `warden init` first is what lets the compose file bring
	// everything up in one shot; init keeps its refusal to run twice, because a
	// second init on a live deployment is a password reset with no authentication in
	// front of it.
	initialised, err := p.IsInitialised(ctx)
	if err != nil {
		return err
	}
	if !initialised {
		keyring, keyErr := cfg.Keyring(secrets.OSLookupEnv, secrets.OSReadFile)
		if keyErr != nil {
			return keyErr
		}
		result, bootErr := p.Bootstrap(ctx, *owner, cfg.Issuer, cfg.Security.TokenSigningAlgorithm, keyring)
		if bootErr != nil {
			return bootErr
		}
		fmt.Fprintf(stdout, "Initialised the deployment. Open this once, within %s, "+
			"to set the owner's credential:\n\n  %s\n\n",
			time.Until(result.ExpiresAt).Round(time.Minute), result.SetupURL)
	}

	// Publishing the manifest is an upsert, so it runs whether or not the demo data
	// is already present: an edited examples/warden.yaml should take effect.
	applied, err := p.Apply(ctx, manifest)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "application %q: %d permissions, %d role templates, %d ui elements\n",
		applied.Application, applied.Permissions, applied.Roles, applied.UIElements)

	seeded, err := p.TenantExists(ctx, seedTenantSlug)
	if err != nil {
		return err
	}
	if seeded {
		fmt.Fprintf(stdout, "tenant %q already exists; leaving its users, grants and "+
			"resources alone\n", seedTenantSlug)
		fmt.Fprintf(stderr, "\nTo reseed from scratch: make dev-reset (this deletes the "+
			"development database).\n")
		return nil
	}

	if _, createErr := p.CreateTenant(ctx, seedTenantSlug, seedTenantName); createErr != nil {
		return createErr
	}

	subjects := map[string]string{}
	for _, u := range seedUsers {
		userID, createErr := p.CreateUser(ctx, seedTenantSlug, u.email, u.attributes)
		if createErr != nil {
			return fmt.Errorf("creating %s: %w", u.email, createErr)
		}
		subjects[u.email] = userID
	}

	for _, r := range seedResources {
		if regErr := p.RegisterResource(ctx, seedTenantSlug, r.ref, r.parent, r.attributes); regErr != nil {
			return fmt.Errorf("registering %s: %w", r.ref, regErr)
		}
	}

	// Bob sees invoices. Maria may also approve them, but only on one project and
	// only up to the limit on her own account — which is what makes the demo show
	// scope and conditions rather than just "admin or not".
	grants := []provision.GrantOptions{
		{TenantSlug: seedTenantSlug, UserID: subjects["bob@acme.test"], RoleKey: "billing.viewer",
			Scope: "tenant", Reason: seedReason},
		{TenantSlug: seedTenantSlug, UserID: subjects["maria@acme.test"], RoleKey: "billing.viewer",
			Scope: "tenant", Reason: seedReason},
		{TenantSlug: seedTenantSlug, UserID: subjects["maria@acme.test"], RoleKey: "billing.approver",
			Scope:     "billing.project:acme-2026/**",
			Condition: "resource.attributes.amount <= subject.attributes.approval_limit",
			Reason:    seedReason},
	}
	for i := range grants {
		g := &grants[i]
		g.Actor = provision.Actor{SystemOperator: true}
		if _, grantErr := p.Grant(ctx, *g); grantErr != nil {
			return fmt.Errorf("granting %s: %w", g.RoleKey, grantErr)
		}
	}

	// Bindings come from what the manifest suggests for each element rather than from
	// a list repeated here, so an element added to examples/warden.yaml is seeded
	// without anyone remembering to edit this file.
	bound := 0
	for i := range manifest.UI.Elements {
		e := &manifest.UI.Elements[i]
		if e.Suggests.Permission == "" {
			continue
		}
		requires, marshalErr := json.Marshal(map[string]any{
			"any_of": []map[string]string{{"permission": e.Suggests.Permission}},
		})
		if marshalErr != nil {
			return marshalErr
		}
		if bindErr := p.BindUIElement(ctx, provision.BindOptions{
			Actor: provision.Actor{SystemOperator: true}, TenantSlug: seedTenantSlug,
			Application: manifest.Application, ElementKey: e.Key,
			Requires: string(requires), Mode: e.DefaultMode,
			Reason: seedReason,
		}); bindErr != nil {
			return fmt.Errorf("binding %s: %w", e.Key, bindErr)
		}
		bound++
	}

	token, err := p.CreateServiceAccount(ctx, seedTenantSlug, "demo-app", true)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "tenant %q seeded: %d users, %d resources, %d grants, %d ui bindings\n\n",
		seedTenantSlug, len(seedUsers), len(seedResources), len(grants), bound)
	for _, u := range seedUsers {
		fmt.Fprintf(stdout, "  %-18s %s\n", u.email, subjects[u.email])
	}
	fmt.Fprintf(stdout, "\nService-account token for the demo application:\n\n  %s\n\n", token)
	fmt.Fprintf(stderr, "That token is shown once and is not recoverable: only its hash is stored.\n")
	return nil
}
