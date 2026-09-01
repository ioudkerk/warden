// Package reference is a deliberately simple implementation of Warden's evaluation
// algorithm (SPEC §10.2), used to validate the conformance corpus.
//
// It is NOT the PDP. It has no database, no caching, no memoization and no regard
// for the latency targets in SPEC §18; it walks the model on every check because
// that is the shape in which the algorithm is easiest to read and hardest to get
// subtly wrong.
//
// Its purpose is to give the corpus a second implementation to disagree with. A
// corpus validated only by the thing it is meant to test proves nothing; two
// independent implementations agreeing on every case is evidence. When the real PDP
// lands in M2 it is checked against the same corpus, and any divergence is a bug in
// one of them — which is the differential test this package exists to make possible.
package reference

import (
	"fmt"
	"sort"
	"strings"

	"github.com/warden-project/warden/conformance"
)

// permission is app.type:action, split once so matching does not re-parse.
type permission struct {
	app, resourceType, action string
}

func parsePermission(s string) (permission, error) {
	dot := strings.IndexByte(s, '.')
	colon := strings.IndexByte(s, ':')
	if dot <= 0 || colon <= dot+1 || colon == len(s)-1 {
		return permission{}, fmt.Errorf("permission %q is not of the form app.type:action", s)
	}
	return permission{app: s[:dot], resourceType: s[dot+1 : colon], action: s[colon+1:]}, nil
}

func (p permission) String() string { return p.app + "." + p.resourceType + ":" + p.action }

// matches reports whether p, which may contain wildcards, covers the concrete
// permission want. Wildcards are legal in grants and never in checks (SPEC §9.2).
func (p permission) matches(want permission) bool {
	return p.app == want.app &&
		(p.resourceType == "*" || p.resourceType == want.resourceType) &&
		(p.action == "*" || p.action == want.action)
}

// resourceRef is app.type:id.
type resourceRef struct {
	app, resourceType, id string
}

func parseResourceRef(s string) (resourceRef, error) {
	dot := strings.IndexByte(s, '.')
	colon := strings.IndexByte(s, ':')
	if dot <= 0 || colon <= dot+1 || colon == len(s)-1 {
		return resourceRef{}, fmt.Errorf("resource ref %q is not of the form app.type:id", s)
	}
	return resourceRef{app: s[:dot], resourceType: s[dot+1 : colon], id: s[colon+1:]}, nil
}

func (r resourceRef) String() string { return r.app + "." + r.resourceType + ":" + r.id }

// model is a case's world, flattened into the lookups a check needs.
type model struct {
	// declaredPermissions is the union of every application's permission surface. A
	// check for anything outside it denies with unknown_permission, so that a typo
	// surfaces in staging instead of silently denying in production (SPEC §9.2).
	declaredPermissions map[string]bool

	// rolePermissions holds each role's fully expanded permission set: its own
	// permissions, plus everything it inherits, plus the closure of every action's
	// `implies`. The expansion happens here, at load, never during a check
	// (SPEC §9.2).
	rolePermissions map[string][]permission
	roles           map[string]conformance.Role

	tenants map[string]*tenant
}

type tenant struct {
	key       string
	users     map[string]conformance.User
	groups    map[string]conformance.Group
	resources map[string]conformance.Resource
	grants    []conformance.Grant
	denials   []conformance.Denial
}

func build(c *conformance.Case) (*model, error) {
	m := &model{
		declaredPermissions: map[string]bool{},
		rolePermissions:     map[string][]permission{},
		roles:               map[string]conformance.Role{},
		tenants:             map[string]*tenant{},
	}

	// Applications: the permission surface, and the implies closure per resource type.
	impliedBy := map[string][]string{} // "app.type:action" -> actions it also grants
	for _, app := range c.Model.Applications {
		for _, rt := range app.ResourceTypes {
			actions := map[string]conformance.Action{}
			for _, a := range rt.Actions {
				actions[a.Key] = a
				m.declaredPermissions[fmt.Sprintf("%s.%s:%s", app.Key, rt.Key, a.Key)] = true
			}
			for _, a := range rt.Actions {
				closure := impliesClosure(a.Key, actions)
				if len(closure) > 0 {
					impliedBy[fmt.Sprintf("%s.%s:%s", app.Key, rt.Key, a.Key)] = closure
				}
			}
		}
	}

	for _, r := range c.Model.Roles {
		m.roles[r.Key] = r
	}
	for key := range m.roles {
		perms, err := m.expandRole(key, impliedBy, map[string]bool{})
		if err != nil {
			return nil, err
		}
		m.rolePermissions[key] = perms
	}

	for i := range c.Model.Tenants {
		t := c.Model.Tenants[i]
		bt := &tenant{
			key:       t.Key,
			users:     map[string]conformance.User{},
			groups:    map[string]conformance.Group{},
			resources: map[string]conformance.Resource{},
			grants:    t.Grants,
			denials:   t.Denials,
		}
		for _, u := range t.Users {
			if u.Status == "" {
				u.Status = conformance.StatusActive
			}
			bt.users[u.Key] = u
		}
		for _, g := range t.Groups {
			bt.groups[g.Key] = g
		}
		for _, r := range t.Resources {
			bt.resources[r.Ref] = r
		}
		m.tenants[t.Key] = bt
	}

	return m, nil
}

// impliesClosure returns every action reachable from start through `implies`,
// excluding start itself. Transitive: manage → write → read yields [read, write].
func impliesClosure(start string, actions map[string]conformance.Action) []string {
	seen := map[string]bool{start: true}
	out := []string{}
	queue := append([]string{}, actions[start].Implies...)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		out = append(out, cur)
		queue = append(queue, actions[cur].Implies...)
	}
	sort.Strings(out)
	return out
}

// expandRole returns a role's permissions including everything it inherits and every
// action implied by an action it grants. Cycles are rejected by case validation, but
// the visited set keeps this terminating regardless.
func (m *model) expandRole(key string, impliedBy map[string][]string, visiting map[string]bool) ([]permission, error) {
	if visiting[key] {
		return nil, fmt.Errorf("role inheritance cycle at %q", key)
	}
	visiting[key] = true
	defer delete(visiting, key)

	r, ok := m.roles[key]
	if !ok {
		return nil, fmt.Errorf("role %q is not declared", key)
	}

	seen := map[string]bool{}
	out := []permission{}
	add := func(s string) error {
		if seen[s] {
			return nil
		}
		seen[s] = true
		p, err := parsePermission(s)
		if err != nil {
			return fmt.Errorf("role %q: %w", key, err)
		}
		out = append(out, p)
		return nil
	}

	for _, s := range r.Permissions {
		if err := add(s); err != nil {
			return nil, err
		}
		// A wildcard already covers everything the implication would add.
		if strings.ContainsRune(s, '*') {
			continue
		}
		p, err := parsePermission(s)
		if err != nil {
			return nil, err
		}
		for _, implied := range impliedBy[s] {
			if err := add(fmt.Sprintf("%s.%s:%s", p.app, p.resourceType, implied)); err != nil {
				return nil, err
			}
		}
	}

	for _, parent := range r.Inherits {
		inherited, err := m.expandRole(parent, impliedBy, visiting)
		if err != nil {
			return nil, err
		}
		for _, p := range inherited {
			if err := add(p.String()); err != nil {
				return nil, err
			}
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

// groupsOf returns every group the user belongs to, following nesting transitively:
// a member of a group that is itself a member of another is in both (SPEC §9.4).
func (t *tenant) groupsOf(userKey string) map[string]bool {
	direct := map[string]bool{}
	for _, g := range t.groups {
		for _, member := range g.Members {
			if member == userKey {
				direct[g.Key] = true
			}
		}
	}

	// Walk upward: a group's memberships are also the user's.
	all := map[string]bool{}
	queue := make([]string, 0, len(direct))
	for k := range direct {
		queue = append(queue, k)
	}
	sort.Strings(queue)

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if all[cur] {
			continue
		}
		all[cur] = true
		for _, g := range t.groups {
			for _, member := range g.Members {
				if member == cur && !all[g.Key] {
					queue = append(queue, g.Key)
				}
			}
		}
	}
	return all
}

// isAncestor reports whether ancestor is at or above ref in the registered resource
// hierarchy. An unregistered resource has no ancestors, which is why an application
// that does not mirror its object graph loses only the cascade (SPEC §9.5).
func (t *tenant) isAncestor(ancestor, ref string) bool {
	if ancestor == ref {
		return true
	}
	seen := map[string]bool{}
	for cur := ref; cur != ""; {
		if seen[cur] {
			return false // cycle; rejected by validation, guarded here anyway
		}
		seen[cur] = true
		r, ok := t.resources[cur]
		if !ok {
			return false
		}
		if r.Parent == ancestor {
			return true
		}
		cur = r.Parent
	}
	return false
}
