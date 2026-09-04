package authz

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/store"
)

// Engine answers checks, loading each tenant's model from the database and caching it
// against that tenant's permission revision.
//
// The revision is the whole trick. Every write that can change an authorization
// outcome bumps tenant.permission_rev (SPEC §10.5), so a cached model is valid
// exactly until the next such write, and correctness does not depend on a TTL being
// short enough. Reloading is triggered by the revision changing, not by time passing.
type Engine struct {
	db    *store.Store
	conds *ConditionSet

	mu     sync.RWMutex
	cached map[string]*Model // tenant id -> model at its revision
}

// NewEngine builds an engine over a tenant-scoped store.
func NewEngine(db *store.Store) (*Engine, error) {
	if db.Access() != store.TenantScoped {
		// A PDP on the system pool would evaluate against every tenant's rows at
		// once. Refusing here is cheaper than discovering it from a decision.
		return nil, fmt.Errorf("the decision engine requires the tenant-scoped pool, not the %s pool", db.Access())
	}
	conds, err := NewConditionSet()
	if err != nil {
		return nil, err
	}
	return &Engine{db: db, conds: conds, cached: map[string]*Model{}}, nil
}

// Check answers one authorization question.
func (e *Engine) Check(ctx context.Context, tenantID string, req Request) (Decision, error) {
	model, err := e.modelFor(ctx, tenantID)
	if err != nil {
		return Decision{}, err
	}
	if req.Now.IsZero() {
		req.Now = time.Now().UTC()
	}
	return Evaluate(ctx, model, e.conds, req)
}

// Revision reports the permission revision a tenant's cached model was built at.
func (e *Engine) Revision(ctx context.Context, tenantID string) (int64, error) {
	m, err := e.modelFor(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	return m.Revision, nil
}

// Invalidate drops a tenant's cached model. Used by tests and, once the change stream
// exists (M7), by the event that announces a write.
func (e *Engine) Invalidate(tenantID string) {
	e.mu.Lock()
	delete(e.cached, tenantID)
	e.mu.Unlock()
}

func (e *Engine) modelFor(ctx context.Context, tenantID string) (*Model, error) {
	revision, err := e.currentRevision(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	e.mu.RLock()
	cached, ok := e.cached[tenantID]
	e.mu.RUnlock()
	if ok && cached.Revision == revision {
		return cached, nil
	}

	model, err := e.load(ctx, tenantID, revision)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	e.cached[tenantID] = model
	e.mu.Unlock()
	return model, nil
}

func (e *Engine) currentRevision(ctx context.Context, tenantID string) (int64, error) {
	var rev int64
	err := e.db.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT permission_rev FROM tenant WHERE id = $1`, tenantID).Scan(&rev)
	})
	if err != nil {
		// InTenant wraps whatever the callback returns, so a direct comparison would
		// never match — and the fallback message would blame the database for a
		// tenant that simply is not there.
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("tenant %q does not exist, or this connection cannot see it", tenantID)
		}
		return 0, fmt.Errorf("reading the permission revision: %w", err)
	}
	return rev, nil
}

// load reads a tenant's whole authorization model in one transaction, so the parts
// cannot disagree with one another. Reading roles in one transaction and grants in
// another could observe a role that a concurrent write has already removed.
//
// Every query names the tenant explicitly. Row-level security would filter these
// anyway on the tenant-scoped pool, but SPEC §6.2 puts RLS *behind* application-level
// filtering rather than in place of it — and relying on RLS alone means this loader
// silently returns every tenant's model if it is ever run on a connection that
// bypasses it, which is precisely what the privilege-escalation guard needs to do.
func (e *Engine) load(ctx context.Context, tenantID string, revision int64) (*Model, error) {
	m := &Model{
		TenantID:            tenantID,
		Revision:            revision,
		DeclaredPermissions: map[string]bool{},
		Subjects:            map[string]Subject{},
		Roles:               map[string]*Role{},
		Resources:           map[string]Resource{},
		GroupsOf:            map[string]map[string]bool{},
	}

	err := e.db.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return LoadModelInto(ctx, tx, m)
	})
	if err != nil {
		return nil, err
	}

	// Compile every condition now, so a malformed expression is a load error rather
	// than a per-request surprise.
	for i := range m.Grants {
		if err := e.conds.Compile(m.Grants[i].Condition); err != nil {
			return nil, err
		}
	}
	for _, r := range m.Roles {
		for _, expr := range r.PermissionConditions {
			if err := e.conds.Compile(expr); err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

// The permission surface is global: an application declares it once (SPEC §6.1).
// Action implication is expanded here, at load, and never during a check (SPEC §9.2).
// LoadModelInto reads one tenant's model using the transaction given. It is exported
// so that the privilege-escalation guard can build a model through the system pool,
// where row-level security does not apply and the explicit tenant filters below are
// the only thing keeping one tenant's roles out of another's decision.
func LoadModelInto(ctx context.Context, tx pgx.Tx, m *Model) error {
	if m.TenantID == "" {
		return fmt.Errorf("loading a model requires a tenant")
	}
	for _, load := range []func(context.Context, pgx.Tx, *Model) error{
		loadPermissionSurface, loadSubjects, loadGroups,
		loadRoles, loadGrantsAndDenials, loadResources,
	} {
		if err := load(ctx, tx, m); err != nil {
			return err
		}
	}
	return nil
}

func loadPermissionSurface(ctx context.Context, tx pgx.Tx, m *Model) error {
	rows, err := tx.Query(ctx, `SELECT key FROM permission`)
	if err != nil {
		return fmt.Errorf("loading the permission surface: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return err
		}
		m.DeclaredPermissions[key] = true
	}
	return rows.Err()
}

func loadSubjects(ctx context.Context, tx pgx.Tx, m *Model) error {
	rows, err := tx.Query(ctx,
		`SELECT id, status, attributes FROM app_user WHERE tenant_id = $1 AND deleted_at IS NULL`,
		m.TenantID)
	if err != nil {
		return fmt.Errorf("loading subjects: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s Subject
		if err := rows.Scan(&s.ID, &s.Status, &s.Attributes); err != nil {
			return err
		}
		m.Subjects[s.ID] = s
	}
	return rows.Err()
}

// Group membership is resolved with a recursive CTE walking nesting outward: a member
// of a nested group holds the outer group's roles too (SPEC §9.4).
func loadGroups(ctx context.Context, tx pgx.Tx, m *Model) error {
	const q = `
		WITH RECURSIVE membership AS (
			SELECT member_user_id AS user_id, group_id
			  FROM group_member
			 WHERE member_user_id IS NOT NULL AND tenant_id = $1
			UNION
			SELECT ms.user_id, gm.group_id
			  FROM group_member gm
			  JOIN membership ms ON gm.member_group_id = ms.group_id
			 WHERE gm.tenant_id = $1
		)
		SELECT user_id, group_id FROM membership`

	rows, err := tx.Query(ctx, q, m.TenantID)
	if err != nil {
		return fmt.Errorf("loading group membership: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var userID, groupID string
		if err := rows.Scan(&userID, &groupID); err != nil {
			return err
		}
		if m.GroupsOf[userID] == nil {
			m.GroupsOf[userID] = map[string]bool{}
		}
		m.GroupsOf[userID][groupID] = true
	}
	return rows.Err()
}

func loadRoles(ctx context.Context, tx pgx.Tx, m *Model) error {
	rows, err := tx.Query(ctx,
		`SELECT id, key, constraints FROM role WHERE tenant_id = $1 OR tenant_id IS NULL`,
		m.TenantID)
	if err != nil {
		return fmt.Errorf("loading roles: %w", err)
	}
	defer rows.Close()

	type raw struct {
		id, key    string
		constraint map[string]any
	}
	var all []raw
	for rows.Next() {
		var r raw
		if err := rows.Scan(&r.id, &r.key, &r.constraint); err != nil {
			return err
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	own := map[string][]string{}                 // role id -> permission keys as written
	conditions := map[string]map[string]string{} // role id -> permission key -> condition
	permRows, permErr := tx.Query(ctx,
		`SELECT role_id, permission_key, condition FROM role_permission
		  WHERE tenant_id = $1 OR tenant_id IS NULL`, m.TenantID)
	if permErr != nil {
		return fmt.Errorf("loading role permissions: %w", permErr)
	}
	defer permRows.Close()
	for permRows.Next() {
		var roleID, key string
		var cond *string
		if scanErr := permRows.Scan(&roleID, &key, &cond); scanErr != nil {
			return scanErr
		}
		own[roleID] = append(own[roleID], key)
		if cond != nil && *cond != "" {
			if conditions[roleID] == nil {
				conditions[roleID] = map[string]string{}
			}
			conditions[roleID][key] = *cond
		}
	}
	if permRows.Err() != nil {
		return fmt.Errorf("loading role permissions: %w", permRows.Err())
	}

	inherits := map[string][]string{}
	inhRows, inhErr := tx.Query(ctx,
		`SELECT role_id, parent_role_id FROM role_inheritance
		  WHERE tenant_id = $1 OR tenant_id IS NULL`, m.TenantID)
	if inhErr != nil {
		return fmt.Errorf("loading role inheritance: %w", inhErr)
	}
	defer inhRows.Close()
	for inhRows.Next() {
		var child, parent string
		if scanErr := inhRows.Scan(&child, &parent); scanErr != nil {
			return scanErr
		}
		inherits[child] = append(inherits[child], parent)
	}
	if inhRows.Err() != nil {
		return fmt.Errorf("loading role inheritance: %w", inhRows.Err())
	}

	implied, impErr := loadImplications(ctx, tx)
	if impErr != nil {
		return impErr
	}

	for i := range all {
		r := &all[i]
		// A constraints value that is present but not a boolean is a malformed
		// role, not a role without the constraint. Resolving it toward "no MFA
		// needed" would quietly relax a control someone meant to apply.
		requiresMFA := false
		if raw, present := r.constraint["requires_mfa"]; present {
			asBool, isBool := raw.(bool)
			if !isBool {
				return fmt.Errorf("role %s: constraints.requires_mfa is %T, want a boolean", r.id, raw)
			}
			requiresMFA = asBool
		}
		m.Roles[r.id] = &Role{
			ID: r.id, Key: r.key, RequiresMFA: requiresMFA,
			PermissionConditions: map[string]string{},
		}
	}

	// Expand each role once: its own permissions, everything it inherits
	// transitively, and the implication closure of every action it names.
	for id := range m.Roles {
		expanded, conds, expandErr := expandRole(id, own, inherits, conditions, implied, map[string]bool{})
		if expandErr != nil {
			return expandErr
		}
		m.Roles[id].Permissions = expanded
		m.Roles[id].PermissionConditions = conds
	}
	return nil
}

// loadImplications maps a concrete permission to every permission it also grants,
// following `implies` transitively (SPEC §9.2).
func loadImplications(ctx context.Context, tx pgx.Tx) (map[string][]string, error) {
	const q = `
		SELECT app.key, rt.key, a.key, a.implies
		  FROM action a
		  JOIN resource_type rt ON rt.id = a.resource_type_id
		  JOIN application app ON app.id = rt.application_id`

	rows, err := tx.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("loading action implications: %w", err)
	}
	defer rows.Close()

	// (app, type) -> action -> directly implied actions
	direct := map[string]map[string][]string{}
	for rows.Next() {
		var appKey, typeKey, actionKey string
		var implies []string
		if err := rows.Scan(&appKey, &typeKey, &actionKey, &implies); err != nil {
			return nil, err
		}
		owner := appKey + "." + typeKey
		if direct[owner] == nil {
			direct[owner] = map[string][]string{}
		}
		direct[owner][actionKey] = implies
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := map[string][]string{}
	for owner, actions := range direct {
		for action := range actions {
			seen := map[string]bool{action: true}
			queue := append([]string{}, actions[action]...)
			var closure []string
			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				if seen[cur] {
					continue
				}
				seen[cur] = true
				closure = append(closure, owner+":"+cur)
				queue = append(queue, actions[cur]...)
			}
			if len(closure) > 0 {
				sort.Strings(closure)
				out[owner+":"+action] = closure
			}
		}
	}
	return out, nil
}

func expandRole(
	id string,
	own map[string][]string,
	inherits map[string][]string,
	conditions map[string]map[string]string,
	implied map[string][]string,
	visiting map[string]bool,
) ([]Permission, map[string]string, error) {
	if visiting[id] {
		return nil, nil, fmt.Errorf("role inheritance cycle at %s", id)
	}
	visiting[id] = true
	defer delete(visiting, id)

	seen := map[string]bool{}
	var out []Permission
	conds := map[string]string{}

	add := func(key, condition string) error {
		if seen[key] {
			return nil
		}
		seen[key] = true
		p, err := ParsePermission(key)
		if err != nil {
			return fmt.Errorf("role %s: %w", id, err)
		}
		out = append(out, p)
		if condition != "" {
			conds[p.String()] = condition
		}
		return nil
	}

	for _, key := range own[id] {
		condition := conditions[id][key]
		if err := add(key, condition); err != nil {
			return nil, nil, err
		}
		// A wildcard already covers whatever the implication would add.
		for _, alsoGranted := range implied[key] {
			if err := add(alsoGranted, condition); err != nil {
				return nil, nil, err
			}
		}
	}

	for _, parent := range inherits[id] {
		inheritedPerms, inheritedConds, err := expandRole(parent, own, inherits, conditions, implied, visiting)
		if err != nil {
			return nil, nil, err
		}
		for _, p := range inheritedPerms {
			if err := add(p.String(), inheritedConds[p.String()]); err != nil {
				return nil, nil, err
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, conds, nil
}

func loadGrantsAndDenials(ctx context.Context, tx pgx.Tx, m *Model) error {
	rows, err := tx.Query(ctx, `
		SELECT id, seq, subject_user_id, subject_group_id, role_id,
		       scope_kind, scope_ref, condition, valid_from, valid_until
		  FROM grant_ WHERE tenant_id = $1 ORDER BY seq`, m.TenantID)
	if err != nil {
		return fmt.Errorf("loading grants: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var g Grant
		var user, group, condition *string
		if err := rows.Scan(&g.ID, &g.Seq, &user, &group, &g.RoleID,
			&g.ScopeKind, &g.ScopeRef, &condition, &g.ValidFrom, &g.ValidUntil); err != nil {
			return err
		}
		if user != nil {
			g.UserID = *user
		}
		if group != nil {
			g.GroupID = *group
		}
		if condition != nil {
			g.Condition = *condition
		}
		m.Grants = append(m.Grants, g)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	denialRows, denialErr := tx.Query(ctx, `
		SELECT id, subject_user_id, subject_group_id, permission_key, scope_kind, scope_ref
		  FROM denial WHERE tenant_id = $1`, m.TenantID)
	if denialErr != nil {
		return fmt.Errorf("loading denials: %w", denialErr)
	}
	defer denialRows.Close()
	for denialRows.Next() {
		var d Denial
		var user, group *string
		var permission string
		if scanErr := denialRows.Scan(&d.ID, &user, &group, &permission, &d.ScopeKind, &d.ScopeRef); scanErr != nil {
			return scanErr
		}
		p, parseErr := ParsePermission(permission)
		if parseErr != nil {
			return fmt.Errorf("denial %s: %w", d.ID, parseErr)
		}
		d.Permission = p
		if user != nil {
			d.UserID = *user
		}
		if group != nil {
			d.GroupID = *group
		}
		m.Denials = append(m.Denials, d)
	}
	return denialRows.Err()
}

func loadResources(ctx context.Context, tx pgx.Tx, m *Model) error {
	rows, err := tx.Query(ctx,
		`SELECT ref, parent_ref, attributes FROM resource_node WHERE tenant_id = $1`, m.TenantID)
	if err != nil {
		return fmt.Errorf("loading resources: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r Resource
		var parent *string
		if err := rows.Scan(&r.Ref, &parent, &r.Attributes); err != nil {
			return err
		}
		if parent != nil {
			r.ParentRef = *parent
		}
		m.Resources[r.Ref] = r
	}
	return rows.Err()
}

// HoldsRole reports whether a subject holds a role, by key, right now. A UI binding
// may require a role rather than a permission (SPEC §11.3), and "holds the role" is a
// different question from "may do the thing the role permits".
func (e *Engine) HoldsRole(ctx context.Context, tenantID, subject, roleKey string) (bool, error) {
	m, err := e.modelFor(ctx, tenantID)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	groups := m.GroupsOf[subject]

	for i := range m.Grants {
		g := &m.Grants[i]
		if g.UserID != subject && (g.GroupID == "" || !groups[g.GroupID]) {
			continue
		}
		if !validAt(g, now) {
			continue
		}
		if role, ok := m.Roles[g.RoleID]; ok && role.Key == roleKey {
			return true, nil
		}
	}
	return false, nil
}
