package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/authz"
	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
	"github.com/warden-project/warden/internal/uibind"
)

// Provisioner performs administrative operations over the system pool.
//
// Every operation writes an audit entry in the same transaction as the change it
// describes. Writing it separately would permit a change that committed with no
// record, or a record of a change that rolled back — and a log that is sometimes
// wrong is worse than no log, because it is trusted.
type Provisioner struct {
	db    *store.Store
	audit *audit.Writer
	// Actor identifies who is performing these operations, for the audit trail.
	// Empty means the CLI, which is recorded as such rather than as nobody.
	actor string
}

// WithActor returns a provisioner that records a different actor on its audit
// entries. The management API will use it once callers are authenticated.
func (p *Provisioner) WithActor(actor string) *Provisioner {
	clone := *p
	clone.actor = actor
	return &clone
}

// New builds a provisioner. It refuses a tenant-scoped pool: every operation here is
// either cross-tenant or runs before a tenant scope exists, and a tenant-scoped
// connection would simply see nothing and report success on zero rows.
func New(st *store.Store) (*Provisioner, error) {
	if st.Access() != store.SystemAccess {
		return nil, fmt.Errorf("provisioning requires the system pool, not the %s pool", st.Access())
	}
	return &Provisioner{db: st, audit: audit.NewWriter(), actor: "cli"}, nil
}

// record appends an audit entry inside the caller's transaction.
func (p *Provisioner) record(ctx context.Context, tx pgx.Tx, e audit.Entry) error {
	if e.ActorUserID == "" && e.ActorClientID == "" {
		e.ActorClientID = p.actor
	}
	_, err := p.audit.Append(ctx, tx, e)
	return err
}

func id(prefix, key string) string {
	return prefix + "_" + strings.NewReplacer(".", "_", "-", "_", ":", "_", "/", "_").Replace(key)
}

// ApplyResult summarises what an apply changed.
type ApplyResult struct {
	Application string
	Permissions int
	Roles       int
	UIElements  int
	Created     bool
}

// applyUIElements syncs the manifest's declared UI surface (SPEC §11.2).
//
// Elements are upserted, never deleted. One removed from a manifest has its status
// set to 'deprecated' instead, because a tenant may have bound it and dropping the row
// would take their binding with it — silently changing what their staff can see as a
// side effect of someone else's refactor.
func applyUIElements(ctx context.Context, q *db.Queries, m *Manifest, appID string, result *ApplyResult) error {
	declared := map[string]bool{}

	for i := range m.UI.Elements {
		e := &m.UI.Elements[i]
		declared[e.Key] = true

		mode := e.DefaultMode
		if mode == "" {
			mode = uibind.ModeHidden
		}
		surface := e.Surface
		if surface == "" {
			surface = "web"
		}

		var resourceTypeID *string
		if rt := e.Suggests.ResourceType; rt != "" {
			v := id("rst", m.Application+"_"+strings.TrimPrefix(rt, m.Application+"."))
			resourceTypeID = &v
		}
		var suggested *string
		if e.Suggests.Permission != "" {
			suggested = &e.Suggests.Permission
		}

		if err := q.UpsertUIElement(ctx, db.UpsertUIElementParams{
			ID: id("uie", m.Application+"_"+e.Key), ApplicationID: appID,
			Key: e.Key, Label: e.Label, Description: nullIfEmpty(e.Description),
			Surface: surface, Path: nullIfEmpty(e.Path),
			SuggestedPermission: suggested, ResourceTypeID: resourceTypeID, DefaultMode: mode,
		}); err != nil {
			return fmt.Errorf("ui element %s: %w", e.Key, err)
		}
		result.UIElements++
	}

	// Anything this application declared before and no longer does.
	keys, err := q.DeclaredUIElementKeys(ctx, appID)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if declared[key] {
			continue
		}
		if err := q.DeprecateUIElement(ctx, db.DeprecateUIElementParams{
			ApplicationID: appID, Key: key,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Apply syncs an application manifest: its resource types, actions, the materialized
// permission atoms, and its role templates.
//
// It is idempotent by construction — every write is an upsert keyed on the manifest's
// own identifiers — so re-running it after an edit converges rather than duplicating.
// It does not prune: anything an administrator created in the console is left alone,
// which is what lets GitOps and click-ops coexist (SPEC §15.2).
func (p *Provisioner) Apply(ctx context.Context, m *Manifest) (ApplyResult, error) {
	result := ApplyResult{Application: m.Application}

	err := p.db.InSystem(ctx, "applying the manifest for "+m.Application, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		appID := id("app", m.Application)

		existed, err := q.ApplicationExists(ctx, appID)
		if err != nil {
			return err
		}
		result.Created = !existed

		settings := m.Settings
		if settings.FailMode == "" {
			settings.FailMode = "closed"
		}
		if settings.CacheMode == "" {
			settings.CacheMode = "cached"
		}
		if settings.DecisionLog == "" {
			settings.DecisionLog = "denies"
		}

		if err := q.UpsertApplication(ctx, db.UpsertApplicationParams{
			ID: appID, Key: m.Application, Name: m.Name, ManifestVersion: int32(m.Version),
			FailMode: settings.FailMode, CacheMode: settings.CacheMode,
			DecisionLog: settings.DecisionLog,
		}); err != nil {
			return fmt.Errorf("application: %w", err)
		}

		for _, env := range []string{"dev", "staging", "prod"} {
			if err := q.UpsertEnvironment(ctx, db.UpsertEnvironmentParams{
				ID: id("env", m.Application+"_"+env), ApplicationID: appID, Name: env,
			}); err != nil {
				return fmt.Errorf("environment %s: %w", env, err)
			}
		}

		// Types before their parent links, so declaration order does not matter.
		for _, rt := range m.Resources {
			schema := rt.Attributes
			if schema == nil {
				schema = map[string]any{}
			}
			if err := q.UpsertResourceType(ctx, db.UpsertResourceTypeParams{
				ID: id("rst", m.Application+"_"+rt.Key), ApplicationID: appID,
				Key: rt.Key, Name: orKey(rt.Name, rt.Key), AttributeSchema: schema,
			}); err != nil {
				return fmt.Errorf("resource %s: %w", rt.Key, err)
			}
		}
		for _, rt := range m.Resources {
			var parent *string
			if rt.Parent != "" {
				v := id("rst", m.Application+"_"+rt.Parent)
				parent = &v
			}
			if err := q.SetResourceTypeParent(ctx, db.SetResourceTypeParentParams{
				ParentTypeID: parent, ID: id("rst", m.Application+"_"+rt.Key),
			}); err != nil {
				return fmt.Errorf("resource %s parent: %w", rt.Key, err)
			}
		}

		for i := range m.Resources {
			rt := &m.Resources[i]
			typeID := id("rst", m.Application+"_"+rt.Key)
			for _, a := range rt.Actions {
				implies := a.Implies
				if implies == nil {
					implies = []string{}
				}
				actionID := id("act", m.Application+"_"+rt.Key+"_"+a.Key)
				if err := q.UpsertAction(ctx, db.UpsertActionParams{
					ID: actionID, ResourceTypeID: typeID,
					Key: a.Key, Name: orKey(a.Name, a.Key), Implies: implies,
				}); err != nil {
					return fmt.Errorf("action %s:%s: %w", rt.Key, a.Key, err)
				}
				if err := q.InsertPermission(ctx, db.InsertPermissionParams{
					ID:             id("prm", m.Application+"_"+rt.Key+"_"+a.Key),
					ApplicationID:  appID,
					Key:            fmt.Sprintf("%s.%s:%s", m.Application, rt.Key, a.Key),
					ResourceTypeID: typeID, ActionID: actionID,
				}); err != nil {
					return fmt.Errorf("permission %s:%s: %w", rt.Key, a.Key, err)
				}
				result.Permissions++
			}
		}

		for i := range m.Roles {
			r := &m.Roles[i]
			roleID := id("rol", r.Key)
			constraints := map[string]any{}
			if r.Constraints.RequiresMFA {
				constraints["requires_mfa"] = true
			}
			if len(r.Constraints.SoDConflict) > 0 {
				constraints["separation_of_duties_conflicts"] = r.Constraints.SoDConflict
			}
			if r.Constraints.MaxAssignees != nil {
				constraints["max_assignees"] = *r.Constraints.MaxAssignees
			}

			templateVersion := int32(m.Version)
			if err := q.UpsertTemplateRole(ctx, db.UpsertTemplateRoleParams{
				ID: roleID, ApplicationID: &appID, Key: r.Key, Name: orKey(r.Name, r.Key),
				Description: nullIfEmpty(r.Description), TemplateVersion: &templateVersion,
				Constraints: constraints,
			}); err != nil {
				return fmt.Errorf("role %s: %w", r.Key, err)
			}

			// Replace the permission set rather than merging: a permission removed
			// from the manifest must actually be removed, or a role keeps granting
			// something its declaration no longer mentions.
			if err := q.DeleteRolePermissions(ctx, roleID); err != nil {
				return err
			}
			for _, perm := range r.Permissions {
				if err := q.InsertRolePermission(ctx, db.InsertRolePermissionParams{
					RoleID: roleID, PermissionKey: perm,
				}); err != nil {
					return fmt.Errorf("role %s permission %s: %w", r.Key, perm, err)
				}
			}
			if err := q.DeleteRoleInheritance(ctx, roleID); err != nil {
				return err
			}
			result.Roles++
		}
		for i := range m.Roles {
			r := &m.Roles[i]
			for _, parent := range r.Inherits {
				if err := q.InsertRoleInheritance(ctx, db.InsertRoleInheritanceParams{
					RoleID: id("rol", r.Key), ParentRoleID: id("rol", parent),
				}); err != nil {
					return fmt.Errorf("role %s inherits %s: %w", r.Key, parent, err)
				}
			}
		}

		if err := applyUIElements(ctx, q, m, appID, &result); err != nil {
			return err
		}

		if err := p.record(ctx, tx, audit.Entry{
			Action:     "application.manifest_applied",
			TargetType: "application",
			TargetID:   appID,
			After: map[string]any{
				"key": m.Application, "version": m.Version,
				"permissions": result.Permissions, "roles": result.Roles,
				"ui_elements": result.UIElements,
			},
			Reason: "warden apply",
		}); err != nil {
			return err
		}
		return bumpEveryTenant(ctx, tx)
	})

	return result, err
}

func orKey(name, key string) string {
	if name == "" {
		return key
	}
	return name
}

// A change to the global permission surface can change any tenant's decisions, so
// every tenant's revision moves and every cached model is rebuilt (SPEC §10.5).
func bumpEveryTenant(ctx context.Context, tx pgx.Tx) error {
	return db.New(tx).BumpEveryTenantRevision(ctx)
}

func bumpTenant(ctx context.Context, tx pgx.Tx, tenantID string) error {
	return db.New(tx).BumpTenantRevision(ctx, tenantID)
}

// CreateTenant creates a tenant and enrols it in every registered application.
func (p *Provisioner) CreateTenant(ctx context.Context, slug, name string) (string, error) {
	tenantID := id("ten", slug)
	err := p.db.InSystem(ctx, "creating tenant "+slug, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		if err := q.InsertTenant(ctx, db.InsertTenantParams{
			ID: tenantID, Slug: slug, Name: orKey(name, slug),
		}); err != nil {
			return err
		}
		if err := q.EnrolTenantInEveryApplication(ctx, tenantID); err != nil {
			return err
		}
		return p.record(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: "tenant.created",
			TargetType: "tenant", TargetID: tenantID,
			After: map[string]any{"slug": slug, "name": orKey(name, slug)},
		})
	})
	return tenantID, err
}

// CreateUser adds a user to a tenant.
func (p *Provisioner) CreateUser(ctx context.Context, tenantSlug, email string, attributes map[string]any) (string, error) {
	tenantID := id("ten", tenantSlug)
	userID := id("usr", strings.Split(email, "@")[0]+"_"+tenantSlug)
	if attributes == nil {
		attributes = map[string]any{}
	}
	err := p.db.InSystem(ctx, "creating user "+email, func(ctx context.Context, tx pgx.Tx) error {
		if err := db.New(tx).InsertUser(ctx, db.InsertUserParams{
			ID: userID, TenantID: tenantID, Email: email,
			Status: "active", Attributes: attributes,
		}); err != nil {
			return err
		}
		return p.record(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: "user.created",
			TargetType: "user", TargetID: userID,
			After: map[string]any{"email": email, "attributes": attributes},
		})
	})
	return userID, err
}

// Actor is who is performing an administrative action.
//
// Exactly one field must be set, and Grant refuses if neither is — a caller who
// forgets to say who is acting gets an error rather than a bypass. Making the
// unguarded path a named, deliberate thing is the point: SPEC §17.1 threat 3 is
// prevented by a check that cannot be omitted by accident.
type Actor struct {
	// SubjectID is the user performing the action. Their own authority bounds what
	// they can assign.
	SubjectID string

	// SystemOperator marks the deployment operator acting through the CLI or a
	// migration. It bypasses the escalation guard, which is not a loophole: this
	// caller already holds the BYPASSRLS database credential and can write any row
	// it likes. What the flag buys is that the bypass is recorded as such.
	SystemOperator bool
}

func (a Actor) validate() error {
	switch {
	case a.SubjectID != "" && a.SystemOperator:
		return errors.New("an actor is either a subject or the system operator, not both")
	case a.SubjectID == "" && !a.SystemOperator:
		return errors.New(
			"an actor is required: set Actor.SubjectID for a delegated action, or " +
				"Actor.SystemOperator to act as the deployment operator")
	}
	return nil
}

// GrantOptions describes an assignment.
type GrantOptions struct {
	Actor      Actor
	TenantSlug string
	UserID     string
	GroupID    string
	RoleKey    string
	Scope      string
	Condition  string
	ValidUntil *time.Time
	Reason     string
}

// Grant assigns a role at a scope, refusing an assignment that would confer more
// authority than the assigner holds (SPEC §17.1 threat 3).
func (p *Provisioner) Grant(ctx context.Context, o GrantOptions) (string, error) {
	if err := o.Actor.validate(); err != nil {
		return "", err
	}
	tenantID := id("ten", o.TenantSlug)
	kind, ref, err := ParseScope(o.Scope, tenantID)
	if err != nil {
		return "", err
	}

	if !o.Actor.SystemOperator {
		if refusal := p.checkAssignment(ctx, tenantID, o, kind, ref); refusal != nil {
			// An attempted escalation is exactly the thing worth having a record of,
			// and the transaction that would have carried it has rolled back — so it
			// is written separately, on its own.
			p.recordRefusal(ctx, tenantID, o, refusal)
			return "", refusal
		}
	}

	grantID := fmt.Sprintf("grn_%s", randomSuffix())
	var condition *string
	if o.Condition != "" {
		condition = &o.Condition
	}
	var user, group *string
	if o.GroupID != "" {
		group = &o.GroupID
	} else {
		user = &o.UserID
	}

	err = p.db.InSystem(ctx, "granting "+o.RoleKey, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		if execErr := q.InsertGrant(ctx, db.InsertGrantParams{
			ID: grantID, TenantID: tenantID, SubjectUserID: user, SubjectGroupID: group,
			RoleID: id("rol", o.RoleKey), ScopeKind: kind, ScopeRef: ref,
			Condition: condition, ValidUntil: o.ValidUntil, Reason: nullIfEmpty(o.Reason),
		}); execErr != nil {
			return execErr
		}
		if execErr := q.SetGrantGrantedBy(ctx, db.SetGrantGrantedByParams{
			GrantedBy: nullIfEmpty(o.Actor.SubjectID), ID: grantID,
		}); execErr != nil {
			return execErr
		}
		if recordErr := p.record(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: "role.granted",
			TargetType: "grant", TargetID: grantID,
			After: map[string]any{
				"role": o.RoleKey, "scope": o.Scope, "subject_user": o.UserID,
				"subject_group": o.GroupID, "condition": o.Condition,
				"valid_until": o.ValidUntil,
			},
			Reason: o.Reason,
		}); recordErr != nil {
			return recordErr
		}
		return bumpTenant(ctx, tx, tenantID)
	})
	return grantID, err
}

// checkAssignment loads the tenant's model and asks the guard.
//
// The model is loaded through the system pool, where row-level security does not
// apply — which is safe only because internal/authz's loader filters by tenant
// explicitly. Relying on RLS here would have silently mixed every tenant's roles into
// one assigner's apparent authority.
func (p *Provisioner) checkAssignment(
	ctx context.Context, tenantID string, o GrantOptions, scopeKind, scopeRef string,
) *authz.EscalationError {
	var refusal *authz.EscalationError

	err := p.db.InSystem(ctx, "checking an assignment for escalation", func(ctx context.Context, tx pgx.Tx) error {
		m := authz.NewModel(tenantID)
		if err := authz.LoadModelInto(ctx, tx, m); err != nil {
			return err
		}
		refusal = authz.CanAssign(m, authz.AssignmentRequest{
			Assigner:   o.Actor.SubjectID,
			RoleID:     id("rol", o.RoleKey),
			ScopeKind:  scopeKind,
			ScopeRef:   scopeRef,
			ValidUntil: o.ValidUntil,
			Now:        time.Now().UTC(),
		})
		return nil
	})
	if err != nil {
		// A guard that cannot run must refuse. Proceeding because the check failed
		// is the one outcome that turns an error into an escalation.
		return &authz.EscalationError{
			Reason: authz.RefusalNotPermitted,
			Detail: "the escalation guard could not be evaluated: " + err.Error(),
		}
	}
	return refusal
}

// recordRefusal writes a refused assignment to the audit log. It is best effort: a
// refusal that could not be recorded is still a refusal, and failing the request a
// second time would tell the caller nothing new.
func (p *Provisioner) recordRefusal(
	ctx context.Context, tenantID string, o GrantOptions, refusal *authz.EscalationError,
) {
	err := p.db.InSystem(ctx, "recording a refused assignment", func(ctx context.Context, tx pgx.Tx) error {
		return p.record(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: "role.assignment_refused",
			TargetType: "role", TargetID: id("rol", o.RoleKey),
			ActorUserID: o.Actor.SubjectID,
			After: map[string]any{
				"refusal": refusal.Reason, "detail": refusal.Detail,
				"missing": refusal.Missing, "scope": o.Scope,
				"subject_user": o.UserID, "subject_group": o.GroupID,
			},
			Reason: o.Reason,
		})
	})
	if err != nil {
		// Nowhere to report this but the process log; the caller already has their
		// refusal.
		_ = err
	}
}

// Revoke removes a grant.
func (p *Provisioner) Revoke(ctx context.Context, tenantSlug, grantID string) error {
	tenantID := id("ten", tenantSlug)
	return p.db.InSystem(ctx, "revoking "+grantID, func(ctx context.Context, tx pgx.Tx) error {
		// Read the grant before deleting it. An audit entry saying only "a grant was
		// revoked" cannot answer the question anyone actually asks a year later,
		// which is what it granted.
		q := db.New(tx)
		g, err := q.GrantBeingRevoked(ctx, db.GrantBeingRevokedParams{
			ID: grantID, TenantID: tenantID,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("no grant %s in tenant %s", grantID, tenantSlug)
			}
			return err
		}
		role, scopeKind, scopeRef := g.Key, g.ScopeKind, g.ScopeRef
		subjectUser, subjectGroup := g.SubjectUserID, g.SubjectGroupID

		if err := q.DeleteGrant(ctx, db.DeleteGrantParams{
			ID: grantID, TenantID: tenantID,
		}); err != nil {
			return err
		}
		if err := p.record(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: "role.revoked",
			TargetType: "grant", TargetID: grantID,
			Before: map[string]any{
				"role": role, "scope_kind": scopeKind, "scope_ref": scopeRef,
				"subject_user": subjectUser, "subject_group": subjectGroup,
			},
		}); err != nil {
			return err
		}
		return bumpTenant(ctx, tx, tenantID)
	})
}

// RegisterResource records a resource instance so subtree grants cascade to it and
// conditions can read its attributes (SPEC §9.5, §9.6).
func (p *Provisioner) RegisterResource(ctx context.Context, tenantSlug, ref, parentRef string, attrs map[string]any) error {
	tenantID := id("ten", tenantSlug)
	if attrs == nil {
		attrs = map[string]any{}
	}
	var parent *string
	if parentRef != "" {
		parent = &parentRef
	}
	return p.db.InSystem(ctx, "registering "+ref, func(ctx context.Context, tx pgx.Tx) error {
		if err := db.New(tx).UpsertResourceNode(ctx, db.UpsertResourceNodeParams{
			TenantID: tenantID, Ref: ref, ParentRef: parent, Attributes: attrs,
		}); err != nil {
			return err
		}
		if err := p.record(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: "resource.registered",
			TargetType: "resource", TargetID: ref,
			After: map[string]any{"parent": parentRef, "attributes": attrs},
		}); err != nil {
			return err
		}
		return bumpTenant(ctx, tx, tenantID)
	})
}

// CreateServiceAccount mints a token for an application to authenticate with. The
// token is returned once and never stored — only its SHA-256 is kept, so a copy of
// the database does not confer the ability to impersonate the application.
func (p *Provisioner) CreateServiceAccount(ctx context.Context, tenantSlug, name string, mayExplain bool) (token string, err error) {
	raw := make([]byte, 32)
	if _, readErr := rand.Read(raw); readErr != nil {
		return "", readErr
	}
	token = "wsk_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))

	tenantID := id("ten", tenantSlug)
	err = p.db.InSystem(ctx, "creating service account "+name, func(ctx context.Context, tx pgx.Tx) error {
		execErr := db.New(tx).InsertServiceAccount(ctx, db.InsertServiceAccountParams{
			ID: id("svc", tenantSlug+"_"+name), TenantID: tenantID, Name: name,
			TokenHash: sum[:], MayExplain: mayExplain,
		})
		if execErr != nil {
			return execErr
		}
		// The token itself is deliberately absent from the entry. An audit log that
		// records a credential has become a second copy of the credential store,
		// with weaker access controls and longer retention.
		return p.record(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: "service_account.created",
			TargetType: "service_account", TargetID: id("svc", tenantSlug+"_"+name),
			After: map[string]any{"name": name, "may_explain": mayExplain},
		})
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// ParseScope turns a human-written scope into the (kind, ref) pair the schema stores.
// The forms are those of SPEC §9.5.
func ParseScope(scope, tenantID string) (kind, ref string, err error) {
	switch {
	case scope == "" || scope == authz.ScopeTenant:
		return authz.ScopeTenant, tenantID, nil
	case strings.HasPrefix(scope, "app:"):
		rest := strings.TrimPrefix(scope, "app:")
		if app, env, found := strings.Cut(rest, "/env:"); found {
			return authz.ScopeEnvironment, app + "/" + env, nil
		}
		return authz.ScopeApplication, rest, nil
	case strings.HasSuffix(scope, "/**"):
		return authz.ScopeSubtree, strings.TrimSuffix(scope, "/**"), nil
	case strings.Contains(scope, ":"):
		return authz.ScopeResource, scope, nil
	default:
		return "", "", fmt.Errorf(
			"scope %q is not a recognised form; want tenant, app:<key>, app:<key>/env:<name>, "+
				"<app>.<type>:<id>, or <app>.<type>:<id>/**", scope)
	}
}

func randomSuffix() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// VerifyAudit recomputes the audit hash chain (SPEC §16.1).
func (p *Provisioner) VerifyAudit(ctx context.Context) (audit.VerifyResult, error) {
	var result audit.VerifyResult
	err := p.db.InSystem(ctx, "verifying the audit chain", func(ctx context.Context, tx pgx.Tx) error {
		var verifyErr error
		result, verifyErr = audit.VerifyOrError(ctx, tx)
		return verifyErr
	})
	return result, err
}

// AuditEntry is one row of the log, as displayed.
type AuditEntry struct {
	OccurredAt time.Time
	Action     string
	TargetType string
	TargetID   string
	TenantID   string
	Reason     string
}

// RecentAudit returns the most recent entries, optionally for one tenant.
func (p *Provisioner) RecentAudit(ctx context.Context, tenantSlug string, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 20
	}
	var tenantID *string
	if tenantSlug != "" {
		v := id("ten", tenantSlug)
		tenantID = &v
	}

	var entries []AuditEntry
	err := p.db.InSystem(ctx, "reading the audit log", func(ctx context.Context, tx pgx.Tx) error {
		rows, err := db.New(tx).RecentAuditEvents(ctx, db.RecentAuditEventsParams{
			TenantID: tenantID, RowLimit: int32(limit),
		})
		if err != nil {
			return err
		}
		for _, r := range rows {
			entries = append(entries, AuditEntry{
				OccurredAt: r.OccurredAt, Action: r.Action,
				TargetType: r.TargetType, TargetID: r.TargetID,
				TenantID: r.TenantID, Reason: r.Reason,
			})
		}
		return nil
	})
	return entries, err
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// BindOptions describes a UI element binding (SPEC §11.3).
type BindOptions struct {
	Actor       Actor
	TenantSlug  string
	Application string
	ElementKey  string
	Environment string
	// Requires is the clause set as JSON: {"any_of":[{"permission":"..."}]}.
	Requires string
	Mode     string
	Message  string
	Reason   string
}

// BindUIElement sets what a UI element requires in one tenant.
//
// Deliberately not subject to the escalation guard. A binding decides what an
// interface looks like, never what anybody may do — an administrator who hides a
// button they can see themselves has widened nothing, and one who reveals a button
// has revealed a control whose action is still checked server-side (SPEC §2.3).
// Requiring warden.ui:bind is the whole of the authorization here.
func (p *Provisioner) BindUIElement(ctx context.Context, o BindOptions) error {
	if err := o.Actor.validate(); err != nil {
		return err
	}
	switch o.Mode {
	case uibind.ModeHidden, uibind.ModeDisabled, uibind.ModeReadOnly:
	case "":
		o.Mode = uibind.ModeHidden
	default:
		return fmt.Errorf("mode %q; want hidden, disabled or read_only", o.Mode)
	}

	var requires map[string]any
	if err := json.Unmarshal([]byte(o.Requires), &requires); err != nil {
		return fmt.Errorf("-requires is not valid JSON: %w", err)
	}
	if _, hasAny := requires["any_of"]; !hasAny {
		if _, hasAll := requires["all_of"]; !hasAll {
			return fmt.Errorf(`-requires must contain any_of or all_of, e.g. ` +
				`'{"any_of":[{"permission":"billing.invoice:approve"}]}'`)
		}
	}

	tenantID := id("ten", o.TenantSlug)
	elementID := id("uie", o.Application+"_"+o.ElementKey)

	return p.db.InSystem(ctx, "binding ui element "+o.ElementKey, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		exists, err := q.UIElementExists(ctx, elementID)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("application %q declares no ui element %q; run `warden apply` first",
				o.Application, o.ElementKey)
		}

		var environmentID *string
		if o.Environment != "" {
			envID, err := q.EnvironmentID(ctx, db.EnvironmentIDParams{
				Key: o.Application, Name: o.Environment,
			})
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return fmt.Errorf("application %q has no environment %q", o.Application, o.Environment)
				}
				return err
			}
			environmentID = &envID
		}

		if err := q.UpsertUIBinding(ctx, db.UpsertUIBindingParams{
			ID: "uib_" + randomSuffix(), TenantID: tenantID, UiElementID: elementID,
			EnvironmentID: environmentID, Requires: []byte(o.Requires), Mode: o.Mode,
			Message: nullIfEmpty(o.Message), UpdatedBy: nullIfEmpty(o.Actor.SubjectID),
		}); err != nil {
			return fmt.Errorf("binding %s: %w", o.ElementKey, err)
		}

		if err := p.record(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: "ui_element.bound",
			TargetType: "ui_element", TargetID: elementID,
			ActorUserID: o.Actor.SubjectID,
			After: map[string]any{
				"element": o.ElementKey, "requires": requires,
				"mode": o.Mode, "environment": o.Environment, "message": o.Message,
			},
			Reason: o.Reason,
		}); err != nil {
			return err
		}
		// A binding change alters what an interface looks like, so a cached UI
		// bundle must be rebuilt — the revision is what tells it to.
		return bumpTenant(ctx, tx, tenantID)
	})
}
