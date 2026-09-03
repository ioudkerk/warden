package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/authz"
	"github.com/warden-project/warden/internal/store"
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
func New(db *store.Store) (*Provisioner, error) {
	if db.Access() != store.SystemAccess {
		return nil, fmt.Errorf("provisioning requires the system pool, not the %s pool", db.Access())
	}
	return &Provisioner{db: db, audit: audit.NewWriter(), actor: "cli"}, nil
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
	Created     bool
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
		appID := id("app", m.Application)

		var existed bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM application WHERE id = $1)`, appID).Scan(&existed); err != nil {
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

		if _, err := tx.Exec(ctx, `
			INSERT INTO application (id, key, name, manifest_version, fail_mode, cache_mode, decision_log)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name, manifest_version = EXCLUDED.manifest_version,
				fail_mode = EXCLUDED.fail_mode, cache_mode = EXCLUDED.cache_mode,
				decision_log = EXCLUDED.decision_log`,
			appID, m.Application, m.Name, m.Version,
			settings.FailMode, settings.CacheMode, settings.DecisionLog); err != nil {
			return fmt.Errorf("application: %w", err)
		}

		for _, env := range []string{"dev", "staging", "prod"} {
			if _, err := tx.Exec(ctx, `
				INSERT INTO environment (id, application_id, name) VALUES ($1, $2, $3)
				ON CONFLICT (application_id, name) DO NOTHING`,
				id("env", m.Application+"_"+env), appID, env); err != nil {
				return fmt.Errorf("environment %s: %w", env, err)
			}
		}

		// Types before their parent links, so declaration order does not matter.
		for _, rt := range m.Resources {
			schema := rt.Attributes
			if schema == nil {
				schema = map[string]any{}
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO resource_type (id, application_id, key, name, attribute_schema)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (application_id, key) DO UPDATE SET
					name = EXCLUDED.name, attribute_schema = EXCLUDED.attribute_schema`,
				id("rst", m.Application+"_"+rt.Key), appID, rt.Key, orKey(rt.Name, rt.Key), schema); err != nil {
				return fmt.Errorf("resource %s: %w", rt.Key, err)
			}
		}
		for _, rt := range m.Resources {
			var parent *string
			if rt.Parent != "" {
				v := id("rst", m.Application+"_"+rt.Parent)
				parent = &v
			}
			if _, err := tx.Exec(ctx, `UPDATE resource_type SET parent_type_id = $1 WHERE id = $2`,
				parent, id("rst", m.Application+"_"+rt.Key)); err != nil {
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
				if _, err := tx.Exec(ctx, `
					INSERT INTO action (id, resource_type_id, key, name, implies) VALUES ($1, $2, $3, $4, $5)
					ON CONFLICT (resource_type_id, key) DO UPDATE SET
						name = EXCLUDED.name, implies = EXCLUDED.implies`,
					actionID, typeID, a.Key, orKey(a.Name, a.Key), implies); err != nil {
					return fmt.Errorf("action %s:%s: %w", rt.Key, a.Key, err)
				}
				if _, err := tx.Exec(ctx, `
					INSERT INTO permission (id, application_id, key, resource_type_id, action_id)
					VALUES ($1, $2, $3, $4, $5) ON CONFLICT (application_id, key) DO NOTHING`,
					id("prm", m.Application+"_"+rt.Key+"_"+a.Key), appID,
					fmt.Sprintf("%s.%s:%s", m.Application, rt.Key, a.Key), typeID, actionID); err != nil {
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

			if _, err := tx.Exec(ctx, `
				INSERT INTO role (id, tenant_id, application_id, key, name, description, type,
				                  template_version, constraints)
				VALUES ($1, NULL, $2, $3, $4, $5, 'application_template', $6, $7)
				ON CONFLICT (id) DO UPDATE SET
					name = EXCLUDED.name, description = EXCLUDED.description,
					template_version = EXCLUDED.template_version, constraints = EXCLUDED.constraints`,
				roleID, appID, r.Key, orKey(r.Name, r.Key), r.Description, m.Version, constraints); err != nil {
				return fmt.Errorf("role %s: %w", r.Key, err)
			}

			// Replace the permission set rather than merging: a permission removed
			// from the manifest must actually be removed, or a role keeps granting
			// something its declaration no longer mentions.
			if _, err := tx.Exec(ctx, `DELETE FROM role_permission WHERE role_id = $1`, roleID); err != nil {
				return err
			}
			for _, perm := range r.Permissions {
				if _, err := tx.Exec(ctx,
					`INSERT INTO role_permission (role_id, tenant_id, permission_key) VALUES ($1, NULL, $2)`,
					roleID, perm); err != nil {
					return fmt.Errorf("role %s permission %s: %w", r.Key, perm, err)
				}
			}
			if _, err := tx.Exec(ctx, `DELETE FROM role_inheritance WHERE role_id = $1`, roleID); err != nil {
				return err
			}
			result.Roles++
		}
		for i := range m.Roles {
			r := &m.Roles[i]
			for _, parent := range r.Inherits {
				if _, err := tx.Exec(ctx,
					`INSERT INTO role_inheritance (role_id, parent_role_id, tenant_id) VALUES ($1, $2, NULL)
					 ON CONFLICT DO NOTHING`,
					id("rol", r.Key), id("rol", parent)); err != nil {
					return fmt.Errorf("role %s inherits %s: %w", r.Key, parent, err)
				}
			}
		}

		if err := p.record(ctx, tx, audit.Entry{
			Action:     "application.manifest_applied",
			TargetType: "application",
			TargetID:   appID,
			After: map[string]any{
				"key": m.Application, "version": m.Version,
				"permissions": result.Permissions, "roles": result.Roles,
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
	_, err := tx.Exec(ctx, `UPDATE tenant SET permission_rev = permission_rev + 1`)
	return err
}

func bumpTenant(ctx context.Context, tx pgx.Tx, tenantID string) error {
	_, err := tx.Exec(ctx, `UPDATE tenant SET permission_rev = permission_rev + 1 WHERE id = $1`, tenantID)
	return err
}

// CreateTenant creates a tenant and enrols it in every registered application.
func (p *Provisioner) CreateTenant(ctx context.Context, slug, name string) (string, error) {
	tenantID := id("ten", slug)
	err := p.db.InSystem(ctx, "creating tenant "+slug, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenant (id, slug, name) VALUES ($1, $2, $3)`,
			tenantID, slug, orKey(name, slug)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO app_enrollment (tenant_id, application_id)
			SELECT $1, id FROM application ON CONFLICT DO NOTHING`, tenantID); err != nil {
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
		if _, err := tx.Exec(ctx, `
			INSERT INTO app_user (id, tenant_id, email, status, attributes)
			VALUES ($1, $2, $3, 'active', $4)`, userID, tenantID, email, attributes); err != nil {
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
		if _, execErr := tx.Exec(ctx, `
			INSERT INTO grant_ (id, tenant_id, subject_user_id, subject_group_id, role_id,
			                    scope_kind, scope_ref, condition, valid_from, valid_until, reason)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'0001-01-01T00:00:00Z',$9,$10)`,
			grantID, tenantID, user, group, id("rol", o.RoleKey),
			kind, ref, condition, o.ValidUntil, o.Reason); execErr != nil {
			return execErr
		}
		if _, execErr := tx.Exec(ctx,
			`UPDATE grant_ SET granted_by = $1 WHERE id = $2`,
			nullIfEmpty(o.Actor.SubjectID), grantID); execErr != nil {
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
		var role, scopeKind, scopeRef string
		var subjectUser, subjectGroup *string
		err := tx.QueryRow(ctx, `
			SELECT r.key, g.scope_kind, g.scope_ref, g.subject_user_id, g.subject_group_id
			  FROM grant_ g JOIN role r ON r.id = g.role_id
			 WHERE g.id = $1 AND g.tenant_id = $2`,
			grantID, tenantID).Scan(&role, &scopeKind, &scopeRef, &subjectUser, &subjectGroup)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("no grant %s in tenant %s", grantID, tenantSlug)
			}
			return err
		}

		if _, err := tx.Exec(ctx, `DELETE FROM grant_ WHERE id = $1 AND tenant_id = $2`,
			grantID, tenantID); err != nil {
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
		if _, err := tx.Exec(ctx, `
			INSERT INTO resource_node (tenant_id, ref, parent_ref, attributes) VALUES ($1,$2,$3,$4)
			ON CONFLICT (tenant_id, ref) DO UPDATE SET
				parent_ref = EXCLUDED.parent_ref, attributes = EXCLUDED.attributes`,
			tenantID, ref, parent, attrs); err != nil {
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
		_, execErr := tx.Exec(ctx, `
			INSERT INTO service_account (id, tenant_id, name, token_hash, may_explain)
			VALUES ($1, $2, $3, $4, $5)`,
			id("svc", tenantSlug+"_"+name), tenantID, name, sum[:], mayExplain)
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
		rows, err := tx.Query(ctx, `
			SELECT occurred_at, action, coalesce(target_type,''), coalesce(target_id,''),
			       coalesce(tenant_id,''), coalesce(reason,'')
			  FROM audit_event
			 WHERE ($1::text IS NULL OR tenant_id = $1)
			 ORDER BY seq DESC LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e AuditEntry
			if err := rows.Scan(&e.OccurredAt, &e.Action, &e.TargetType,
				&e.TargetID, &e.TenantID, &e.Reason); err != nil {
				return err
			}
			entries = append(entries, e)
		}
		return rows.Err()
	})
	return entries, err
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
