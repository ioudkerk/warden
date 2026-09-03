package authz_test

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/conformance"
)

// Seeding a corpus case into PostgreSQL is what makes the differential test possible.
// The corpus speaks in keys — "maria", "billing.viewer" — and the database in ids, so
// the mapping below is deterministic and reversible: a corpus key becomes a prefixed
// id, and a corpus grant keeps its own id so that matched_grant assertions still mean
// something.
func tenantID(key string) string { return "ten_" + sanitize(key) }
func userID(key string) string   { return "usr_" + sanitize(key) }
func groupID(key string) string  { return "grp_" + sanitize(key) }
func roleID(key string) string   { return "rol_" + sanitize(key) }

func sanitize(k string) string {
	return strings.NewReplacer(".", "_", "-", "_", ":", "_").Replace(k)
}

// noLowerBound expresses "this grant has always been in force". grant_.valid_from
// defaults to now(), which would make every corpus case that evaluates at a fixed
// past instant report grant_expired.
var noLowerBound = time.Time{}

func seedCase(ctx context.Context, tx pgx.Tx, c *conformance.Case) error {
	if err := seedApplications(ctx, tx, c); err != nil {
		return err
	}
	if err := seedRoles(ctx, tx, c); err != nil {
		return err
	}
	for _, t := range c.Model.Tenants {
		if err := seedTenant(ctx, tx, t); err != nil {
			return err
		}
	}
	return nil
}

// Applications, resource types, actions and the materialized permission atoms. All
// global: an application declares its surface once (SPEC §6.1).
func seedApplications(ctx context.Context, tx pgx.Tx, c *conformance.Case) error {
	for _, app := range c.Model.Applications {
		appID := "app_" + sanitize(app.Key)
		if _, err := tx.Exec(ctx,
			`INSERT INTO application (id, key, name) VALUES ($1, $2, $3)`, appID, app.Key, app.Key); err != nil {
			return fmt.Errorf("application %s: %w", app.Key, err)
		}

		// Types first without parents, so declaration order in the case file does
		// not matter, then the parent links.
		for _, rt := range app.ResourceTypes {
			if _, err := tx.Exec(ctx,
				`INSERT INTO resource_type (id, application_id, key, name) VALUES ($1, $2, $3, $4)`,
				"rst_"+sanitize(app.Key+"_"+rt.Key), appID, rt.Key, rt.Key); err != nil {
				return fmt.Errorf("resource type %s.%s: %w", app.Key, rt.Key, err)
			}
		}
		for _, rt := range app.ResourceTypes {
			if rt.Parent == "" {
				continue
			}
			if _, err := tx.Exec(ctx,
				`UPDATE resource_type SET parent_type_id = $1 WHERE id = $2`,
				"rst_"+sanitize(app.Key+"_"+rt.Parent), "rst_"+sanitize(app.Key+"_"+rt.Key)); err != nil {
				return fmt.Errorf("resource type parent %s.%s: %w", app.Key, rt.Key, err)
			}
		}

		for _, rt := range app.ResourceTypes {
			typeID := "rst_" + sanitize(app.Key+"_"+rt.Key)
			for _, action := range rt.Actions {
				actionID := "act_" + sanitize(app.Key+"_"+rt.Key+"_"+action.Key)
				implies := action.Implies
				if implies == nil {
					implies = []string{}
				}
				if _, err := tx.Exec(ctx,
					`INSERT INTO action (id, resource_type_id, key, name, implies) VALUES ($1, $2, $3, $4, $5)`,
					actionID, typeID, action.Key, action.Key, implies); err != nil {
					return fmt.Errorf("action %s.%s:%s: %w", app.Key, rt.Key, action.Key, err)
				}
				if _, err := tx.Exec(ctx,
					`INSERT INTO permission (id, application_id, key, resource_type_id, action_id)
					 VALUES ($1, $2, $3, $4, $5)`,
					"prm_"+sanitize(app.Key+"_"+rt.Key+"_"+action.Key), appID,
					fmt.Sprintf("%s.%s:%s", app.Key, rt.Key, action.Key), typeID, actionID); err != nil {
					return fmt.Errorf("permission %s.%s:%s: %w", app.Key, rt.Key, action.Key, err)
				}
			}
		}
	}
	return nil
}

// Corpus roles are seeded as application templates: global, which also exercises the
// NULL-tenant path through the loader and its row-level security policy.
func seedRoles(ctx context.Context, tx pgx.Tx, c *conformance.Case) error {
	for _, r := range c.Model.Roles {
		constraints := "{}"
		if r.RequiresMFA {
			constraints = `{"requires_mfa": true}`
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO role (id, tenant_id, application_id, key, name, type, constraints)
			 VALUES ($1, NULL, NULL, $2, $3, 'application_template', $4::jsonb)`,
			roleID(r.Key), r.Key, r.Key, constraints); err != nil {
			return fmt.Errorf("role %s: %w", r.Key, err)
		}
		for _, p := range r.Permissions {
			if _, err := tx.Exec(ctx,
				`INSERT INTO role_permission (role_id, tenant_id, permission_key) VALUES ($1, NULL, $2)`,
				roleID(r.Key), p); err != nil {
				return fmt.Errorf("role %s permission %s: %w", r.Key, p, err)
			}
		}
	}
	for _, r := range c.Model.Roles {
		for _, parent := range r.Inherits {
			if _, err := tx.Exec(ctx,
				`INSERT INTO role_inheritance (role_id, parent_role_id, tenant_id) VALUES ($1, $2, NULL)`,
				roleID(r.Key), roleID(parent)); err != nil {
				return fmt.Errorf("role %s inherits %s: %w", r.Key, parent, err)
			}
		}
	}
	return nil
}

func seedTenant(ctx context.Context, tx pgx.Tx, t conformance.Tenant) error {
	tid := tenantID(t.Key)
	if _, err := tx.Exec(ctx,
		`INSERT INTO tenant (id, slug, name) VALUES ($1, $2, $3)`, tid, t.Key, t.Key); err != nil {
		return fmt.Errorf("tenant %s: %w", t.Key, err)
	}

	for _, u := range t.Users {
		status := u.Status
		if status == "" {
			status = "active"
		}
		attrs := u.Attributes
		if attrs == nil {
			attrs = map[string]any{}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO app_user (id, tenant_id, email, status, attributes) VALUES ($1, $2, $3, $4, $5)`,
			userID(u.Key), tid, u.Key+"@"+t.Key+".test", status, attrs); err != nil {
			return fmt.Errorf("user %s: %w", u.Key, err)
		}
	}

	for _, g := range t.Groups {
		if _, err := tx.Exec(ctx,
			`INSERT INTO group_ (id, tenant_id, key, name) VALUES ($1, $2, $3, $4)`,
			groupID(g.Key), tid, g.Key, g.Key); err != nil {
			return fmt.Errorf("group %s: %w", g.Key, err)
		}
	}
	// Membership after every group exists, so nesting can be declared in any order.
	isGroup := map[string]bool{}
	for _, g := range t.Groups {
		isGroup[g.Key] = true
	}
	for _, g := range t.Groups {
		for _, member := range g.Members {
			var err error
			if isGroup[member] {
				_, err = tx.Exec(ctx,
					`INSERT INTO group_member (group_id, member_group_id, tenant_id) VALUES ($1, $2, $3)`,
					groupID(g.Key), groupID(member), tid)
			} else {
				_, err = tx.Exec(ctx,
					`INSERT INTO group_member (group_id, member_user_id, tenant_id) VALUES ($1, $2, $3)`,
					groupID(g.Key), userID(member), tid)
			}
			if err != nil {
				return fmt.Errorf("group %s member %s: %w", g.Key, member, err)
			}
		}
	}

	// Resources without parents first, then the links: a parent must exist before a
	// child can reference it.
	for _, r := range t.Resources {
		attrs := r.Attributes
		if attrs == nil {
			attrs = map[string]any{}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO resource_node (tenant_id, ref, attributes) VALUES ($1, $2, $3)`,
			tid, r.Ref, attrs); err != nil {
			return fmt.Errorf("resource %s: %w", r.Ref, err)
		}
	}
	for _, r := range t.Resources {
		if r.Parent == "" {
			continue
		}
		if _, err := tx.Exec(ctx,
			`UPDATE resource_node SET parent_ref = $1 WHERE tenant_id = $2 AND ref = $3`,
			r.Parent, tid, r.Ref); err != nil {
			return fmt.Errorf("resource %s parent: %w", r.Ref, err)
		}
	}

	for i, g := range t.Grants {
		kind, ref, err := scopeToColumns(g.Scope, tid)
		if err != nil {
			return fmt.Errorf("grant %d: %w", i, err)
		}
		id := g.ID
		if id == "" {
			id = fmt.Sprintf("grn_%s_%d", sanitize(t.Key), i)
		}

		validFrom := noLowerBound
		if g.ValidFrom != "" {
			if validFrom, err = time.Parse(time.RFC3339, g.ValidFrom); err != nil {
				return err
			}
		}
		var validUntil *time.Time
		if g.ValidUntil != "" {
			parsed, err := time.Parse(time.RFC3339, g.ValidUntil)
			if err != nil {
				return err
			}
			validUntil = &parsed
		}

		var user, group *string
		if g.Subject.IsGroup() {
			v := groupID(g.Subject.Group)
			group = &v
		} else {
			v := userID(g.Subject.User)
			user = &v
		}
		var condition *string
		if g.Condition != "" {
			condition = &g.Condition
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO grant_ (id, tenant_id, subject_user_id, subject_group_id, role_id,
			                     scope_kind, scope_ref, condition, valid_from, valid_until)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			id, tid, user, group, roleID(g.Role), kind, ref, condition, validFrom, validUntil); err != nil {
			return fmt.Errorf("grant %s: %w", id, err)
		}
	}

	for i, d := range t.Denials {
		kind, ref, err := scopeToColumns(d.Scope, tid)
		if err != nil {
			return fmt.Errorf("denial %d: %w", i, err)
		}
		id := d.ID
		if id == "" {
			id = fmt.Sprintf("den_%s_%d", sanitize(t.Key), i)
		}
		var user, group *string
		if d.Subject.IsGroup() {
			v := groupID(d.Subject.Group)
			group = &v
		} else {
			v := userID(d.Subject.User)
			user = &v
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO denial (id, tenant_id, subject_user_id, subject_group_id,
			                     permission_key, scope_kind, scope_ref, reason)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			id, tid, user, group, d.Permission, kind, ref, d.Reason); err != nil {
			return fmt.Errorf("denial %s: %w", id, err)
		}
	}
	return nil
}

// scopeToColumns turns the corpus's single scope string into the (kind, ref) pair the
// schema stores. The forms are those of SPEC §9.5.
func scopeToColumns(scope, tid string) (kind, ref string, err error) {
	switch {
	case scope == "tenant":
		return "tenant", tid, nil
	case strings.HasPrefix(scope, "app:"):
		rest := strings.TrimPrefix(scope, "app:")
		if app, env, found := strings.Cut(rest, "/env:"); found {
			return "environment", app + "/" + env, nil
		}
		return "application", rest, nil
	case strings.HasSuffix(scope, "/**"):
		return "subtree", strings.TrimSuffix(scope, "/**"), nil
	case strings.Contains(scope, ":"):
		return "resource", scope, nil
	default:
		return "", "", fmt.Errorf("unrecognised scope %q", scope)
	}
}

// replaceCredentials swaps the user and password in a connection string.
func replaceCredentials(t testingT, dsn, user, password string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parsing the connection string: %v", err)
	}
	u.User = url.UserPassword(user, password)
	return u.String()
}

type testingT interface {
	Helper()
	Fatalf(string, ...any)
}
