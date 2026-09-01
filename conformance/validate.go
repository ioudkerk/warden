package conformance

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// validation accumulates problems so that one run reports every one of them, rather
// than making the author of a case fix them one at a time.
type validation struct{ problems []string }

// Validate checks that a case is internally consistent before any evaluator sees it.
//
// This exists because an invalid case is worse than a missing one: a check naming a
// role that does not exist would deny with no_grant and quietly "pass" a test whose
// author meant to prove something else entirely. Every reference in a case file must
// resolve, and every expectation must be one an implementation could produce.
func (c *Case) Validate() error {
	v := &validation{}

	if c.Suite == "" {
		v.addf("suite must be set")
	}
	if c.Description == "" {
		v.addf("description must be set: a case that does not say what it proves cannot be reviewed")
	}
	if c.Now != "" {
		if _, err := time.Parse(time.RFC3339, c.Now); err != nil {
			v.addf("now: %q is not an RFC 3339 timestamp", c.Now)
		}
	}

	perms := c.validateApplications(v)
	roles := c.validateRoles(v)
	c.validateTenants(v, perms, roles)
	c.validateChecks(v)

	return v.err()
}

var (
	keyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	// app.type:action, no wildcards. Checks use this form; grants may also use the
	// wildcard forms below.
	permPattern = regexp.MustCompile(`^[a-z0-9_-]+\.[a-z0-9_-]+:[a-z0-9_-]+$`)
	// The grant forms: billing.invoice:*, billing.*:read, billing.*:*
	permGrantPattern = regexp.MustCompile(`^[a-z0-9_-]+\.(\*|[a-z0-9_-]+):(\*|[a-z0-9_-]+)$`)
	// A resource ref: app.type:id. The id is freer than a key — it comes from the
	// application's own object space.
	refPattern = regexp.MustCompile(`^[a-z0-9_-]+\.[a-z0-9_-]+:[^\s/]+$`)
)

func (c *Case) validateApplications(v *validation) map[string]bool {
	perms := map[string]bool{}
	seenApps := map[string]bool{}

	for _, app := range c.Model.Applications {
		if !keyPattern.MatchString(app.Key) {
			v.addf("application %q: key must match %s", app.Key, keyPattern)
		}
		if seenApps[app.Key] {
			v.addf("application %q is declared twice", app.Key)
		}
		seenApps[app.Key] = true

		types := map[string]ResourceType{}
		for _, rt := range app.ResourceTypes {
			if !keyPattern.MatchString(rt.Key) {
				v.addf("%s.%s: resource type key must match %s", app.Key, rt.Key, keyPattern)
			}
			if _, dup := types[rt.Key]; dup {
				v.addf("%s.%s is declared twice", app.Key, rt.Key)
			}
			types[rt.Key] = rt

			seenActions := map[string]bool{}
			for _, act := range rt.Actions {
				if !keyPattern.MatchString(act.Key) {
					v.addf("%s.%s:%s: action key must match %s", app.Key, rt.Key, act.Key, keyPattern)
				}
				if seenActions[act.Key] {
					v.addf("%s.%s:%s is declared twice", app.Key, rt.Key, act.Key)
				}
				seenActions[act.Key] = true
				perms[fmt.Sprintf("%s.%s:%s", app.Key, rt.Key, act.Key)] = true
			}
			// implies is checked after every action of the type is known.
			for _, act := range rt.Actions {
				for _, implied := range act.Implies {
					if implied == act.Key {
						v.addf("%s.%s:%s implies itself", app.Key, rt.Key, act.Key)
					}
					if !seenActions[implied] {
						v.addf("%s.%s:%s implies %q, which is not an action on that resource type",
							app.Key, rt.Key, act.Key, implied)
					}
				}
			}
		}

		// Parents are resolved after every type of the application is known, so
		// declaration order in the file does not matter.
		for _, rt := range app.ResourceTypes {
			if rt.Parent == "" {
				continue
			}
			if rt.Parent == rt.Key {
				v.addf("%s.%s is its own parent", app.Key, rt.Key)
				continue
			}
			if _, ok := types[rt.Parent]; !ok {
				v.addf("%s.%s: parent %q is not a resource type of that application", app.Key, rt.Key, rt.Parent)
			}
		}
		v.checkTypeHierarchyAcyclic(app.Key, types)
	}
	return perms
}

func (v *validation) checkTypeHierarchyAcyclic(appKey string, types map[string]ResourceType) {
	for start := range types {
		seen := map[string]bool{start: true}
		for cur := types[start].Parent; cur != ""; cur = types[cur].Parent {
			if seen[cur] {
				v.addf("%s: resource type hierarchy has a cycle through %q", appKey, cur)
				break
			}
			seen[cur] = true
			if _, ok := types[cur]; !ok {
				break // already reported as an unresolved parent
			}
		}
	}
}

func (c *Case) validateRoles(v *validation) map[string]Role {
	roles := map[string]Role{}
	for _, r := range c.Model.Roles {
		if r.Key == "" {
			v.addf("a role has no key")
			continue
		}
		if _, dup := roles[r.Key]; dup {
			v.addf("role %q is declared twice", r.Key)
		}
		roles[r.Key] = r

		for _, p := range r.Permissions {
			if !permGrantPattern.MatchString(p) {
				v.addf("role %q: permission %q is not of the form app.type:action (wildcards allowed)", r.Key, p)
			}
		}
	}

	for _, r := range c.Model.Roles {
		for _, parent := range r.Inherits {
			if parent == r.Key {
				v.addf("role %q inherits itself", r.Key)
				continue
			}
			if _, ok := roles[parent]; !ok {
				v.addf("role %q inherits %q, which is not declared", r.Key, parent)
			}
		}
	}
	v.checkRoleGraphAcyclic(roles)
	return roles
}

// Role inheritance is a DAG; a cycle is rejected at write time by the server
// (SPEC §9.3) and must be rejected here too, or a runner would hang expanding it.
func (v *validation) checkRoleGraphAcyclic(roles map[string]Role) {
	const (
		white = 0 // unvisited
		grey  = 1 // on the current path
		black = 2 // finished
	)
	colour := map[string]int{}

	var visit func(key string, path []string) bool
	visit = func(key string, path []string) bool {
		switch colour[key] {
		case grey:
			v.addf("role inheritance has a cycle: %s → %s", strings.Join(path, " → "), key)
			return false
		case black:
			return true
		}
		colour[key] = grey
		for _, parent := range roles[key].Inherits {
			if _, ok := roles[parent]; !ok {
				continue // already reported
			}
			if !visit(parent, append(path, key)) {
				colour[key] = black
				return false
			}
		}
		colour[key] = black
		return true
	}

	for key := range roles {
		visit(key, nil)
	}
}

func (c *Case) validateTenants(v *validation, perms map[string]bool, roles map[string]Role) {
	seenTenants := map[string]bool{}
	for _, t := range c.Model.Tenants {
		if !keyPattern.MatchString(t.Key) {
			v.addf("tenant %q: key must match %s", t.Key, keyPattern)
		}
		if seenTenants[t.Key] {
			v.addf("tenant %q is declared twice", t.Key)
		}
		seenTenants[t.Key] = true

		users := map[string]bool{}
		for _, u := range t.Users {
			if users[u.Key] {
				v.addf("tenant %s: user %q is declared twice", t.Key, u.Key)
			}
			users[u.Key] = true
			if u.Status != "" && !knownStatuses[u.Status] {
				v.addf("tenant %s: user %q has status %q; want one of invited, active, suspended, deprovisioned",
					t.Key, u.Key, u.Status)
			}
		}

		groups := map[string]bool{}
		for _, g := range t.Groups {
			if groups[g.Key] {
				v.addf("tenant %s: group %q is declared twice", t.Key, g.Key)
			}
			groups[g.Key] = true
		}
		for _, g := range t.Groups {
			for _, m := range g.Members {
				if m == g.Key {
					v.addf("tenant %s: group %q contains itself", t.Key, g.Key)
					continue
				}
				if !users[m] && !groups[m] {
					v.addf("tenant %s: group %q has member %q, which is neither a user nor a group",
						t.Key, g.Key, m)
				}
			}
		}
		v.checkGroupGraphAcyclic(t)

		refs := map[string]bool{}
		for _, r := range t.Resources {
			if !refPattern.MatchString(r.Ref) {
				v.addf("tenant %s: resource ref %q is not of the form app.type:id", t.Key, r.Ref)
			}
			if refs[r.Ref] {
				v.addf("tenant %s: resource %q is declared twice", t.Key, r.Ref)
			}
			refs[r.Ref] = true
		}
		for _, r := range t.Resources {
			if r.Parent != "" && !refs[r.Parent] {
				v.addf("tenant %s: resource %q has parent %q, which is not declared", t.Key, r.Ref, r.Parent)
			}
		}
		v.checkResourceTreeAcyclic(t)

		c.validateGrants(v, t, users, groups, roles)
		c.validateDenials(v, t, users, groups, perms)
	}
}

func (v *validation) checkGroupGraphAcyclic(t Tenant) {
	members := map[string][]string{}
	isGroup := map[string]bool{}
	for _, g := range t.Groups {
		isGroup[g.Key] = true
	}
	for _, g := range t.Groups {
		for _, m := range g.Members {
			if isGroup[m] {
				members[g.Key] = append(members[g.Key], m)
			}
		}
	}

	colour := map[string]int{}
	var visit func(key string, path []string) bool
	visit = func(key string, path []string) bool {
		switch colour[key] {
		case 1:
			v.addf("tenant %s: group nesting has a cycle: %s → %s", t.Key, strings.Join(path, " → "), key)
			return false
		case 2:
			return true
		}
		colour[key] = 1
		for _, child := range members[key] {
			if !visit(child, append(path, key)) {
				colour[key] = 2
				return false
			}
		}
		colour[key] = 2
		return true
	}
	for _, g := range t.Groups {
		visit(g.Key, nil)
	}
}

func (v *validation) checkResourceTreeAcyclic(t Tenant) {
	parent := map[string]string{}
	for _, r := range t.Resources {
		parent[r.Ref] = r.Parent
	}
	for _, r := range t.Resources {
		seen := map[string]bool{r.Ref: true}
		for cur := parent[r.Ref]; cur != ""; cur = parent[cur] {
			if seen[cur] {
				v.addf("tenant %s: resource hierarchy has a cycle through %q", t.Key, cur)
				break
			}
			seen[cur] = true
		}
	}
}

func (c *Case) validateGrants(v *validation, t Tenant, users, groups map[string]bool, roles map[string]Role) {
	ids := map[string]bool{}
	for i, g := range t.Grants {
		where := fmt.Sprintf("tenant %s: grant %d", t.Key, i)
		if g.ID != "" {
			if ids[g.ID] {
				v.addf("%s: id %q is used twice", where, g.ID)
			}
			ids[g.ID] = true
			where = fmt.Sprintf("tenant %s: grant %s", t.Key, g.ID)
		}

		if err := g.Subject.validate(); err != nil {
			v.addf("%s: %v", where, err)
		} else if g.Subject.IsGroup() {
			if !groups[g.Subject.Group] {
				v.addf("%s: group %q is not declared", where, g.Subject.Group)
			}
		} else if !users[g.Subject.User] {
			v.addf("%s: user %q is not declared", where, g.Subject.User)
		}

		if _, ok := roles[g.Role]; !ok {
			v.addf("%s: role %q is not declared", where, g.Role)
		}
		v.checkScope(where, g.Scope)

		for label, raw := range map[string]string{"valid_from": g.ValidFrom, "valid_until": g.ValidUntil} {
			if raw == "" {
				continue
			}
			if _, err := time.Parse(time.RFC3339, raw); err != nil {
				v.addf("%s: %s %q is not an RFC 3339 timestamp", where, label, raw)
			}
		}
		if g.ValidFrom != "" && g.ValidUntil != "" {
			from, err1 := time.Parse(time.RFC3339, g.ValidFrom)
			until, err2 := time.Parse(time.RFC3339, g.ValidUntil)
			if err1 == nil && err2 == nil && !until.After(from) {
				v.addf("%s: valid_until is not after valid_from", where)
			}
		}
		// A grant with a validity window in a case with no clock is meaningless: the
		// result would depend on when the suite happens to run.
		if (g.ValidFrom != "" || g.ValidUntil != "") && c.Now == "" && !c.everyCheckSetsNow() {
			v.addf("%s: has a validity window, so the case must set `now` (or every check must)", where)
		}
	}
}

func (c *Case) everyCheckSetsNow() bool {
	if len(c.Checks) == 0 {
		return false
	}
	for _, chk := range c.Checks {
		if chk.Now == "" {
			return false
		}
	}
	return true
}

func (c *Case) validateDenials(v *validation, t Tenant, users, groups, perms map[string]bool) {
	for i, d := range t.Denials {
		where := fmt.Sprintf("tenant %s: denial %d", t.Key, i)
		if d.ID != "" {
			where = fmt.Sprintf("tenant %s: denial %s", t.Key, d.ID)
		}

		if err := d.Subject.validate(); err != nil {
			v.addf("%s: %v", where, err)
		} else if d.Subject.IsGroup() {
			if !groups[d.Subject.Group] {
				v.addf("%s: group %q is not declared", where, d.Subject.Group)
			}
		} else if !users[d.Subject.User] {
			v.addf("%s: user %q is not declared", where, d.Subject.User)
		}

		if !permGrantPattern.MatchString(d.Permission) {
			v.addf("%s: permission %q is not of the form app.type:action", where, d.Permission)
		} else if !strings.ContainsRune(d.Permission, '*') && !perms[d.Permission] {
			v.addf("%s: permission %q is not declared by any application", where, d.Permission)
		}
		v.checkScope(where, d.Scope)

		// SPEC §9.7: the console requires a written justification for every explicit
		// deny. A corpus case that omits it is not modelling the real thing.
		if d.Reason == "" {
			v.addf("%s: reason is required; explicit denies always carry a written justification (SPEC §9.7)", where)
		}
	}
}

var (
	scopeApp       = regexp.MustCompile(`^app:[a-z0-9_-]+$`)
	scopeAppEnv    = regexp.MustCompile(`^app:[a-z0-9_-]+/env:(dev|staging|prod)$`)
	scopeInstance  = regexp.MustCompile(`^[a-z0-9_-]+\.[a-z0-9_-]+:[^\s/]+$`)
	scopeSubtree   = regexp.MustCompile(`^[a-z0-9_-]+\.[a-z0-9_-]+:[^\s/]+/\*\*$`)
	scopeFormsHelp = "want one of: tenant; app:<key>; app:<key>/env:<dev|staging|prod>; <app>.<type>:<id>; <app>.<type>:<id>/**"
)

func (v *validation) checkScope(where, scope string) {
	switch {
	case scope == "":
		v.addf("%s: scope is required (%s)", where, scopeFormsHelp)
	case scope == "tenant":
	case scopeApp.MatchString(scope):
	case scopeAppEnv.MatchString(scope):
	case scopeSubtree.MatchString(scope):
	case scopeInstance.MatchString(scope):
	default:
		v.addf("%s: scope %q is not a recognised form; %s", where, scope, scopeFormsHelp)
	}
}

func (c *Case) validateChecks(v *validation) {
	if len(c.Checks) == 0 {
		v.addf("a case with no checks proves nothing")
	}

	tenants := map[string]Tenant{}
	for _, t := range c.Model.Tenants {
		tenants[t.Key] = t
	}
	grantIDs := map[string]bool{}
	for _, t := range c.Model.Tenants {
		for _, g := range t.Grants {
			if g.ID != "" {
				grantIDs[g.ID] = true
			}
		}
	}

	seenNames := map[string]bool{}
	for i, chk := range c.Checks {
		where := fmt.Sprintf("check %d", i)
		if chk.Name == "" {
			v.addf("%s: name is required; it is what appears in test output", where)
		} else {
			where = fmt.Sprintf("check %q", chk.Name)
			if seenNames[chk.Name] {
				v.addf("%s: two checks share this name", where)
			}
			seenNames[chk.Name] = true
		}

		t, ok := tenants[chk.Tenant]
		if !ok {
			v.addf("%s: tenant %q is not declared", where, chk.Tenant)
		} else {
			found := false
			for _, u := range t.Users {
				if u.Key == chk.Subject {
					found = true
					break
				}
			}
			// A check may deliberately name an absent subject to assert
			// subject_not_found; anything else is a typo.
			if !found && chk.Expect.Reason != ReasonSubjectNotFound {
				v.addf("%s: subject %q is not a user of tenant %s (expect reason %s if that is deliberate)",
					where, chk.Subject, chk.Tenant, ReasonSubjectNotFound)
			}
		}

		// Wildcards are legal in grants and never in checks (SPEC §9.2).
		if !permPattern.MatchString(chk.Permission) {
			v.addf("%s: permission %q must be a concrete app.type:action; wildcards are not allowed in a check",
				where, chk.Permission)
		}
		if chk.Resource != "" && !refPattern.MatchString(chk.Resource) {
			v.addf("%s: resource %q is not of the form app.type:id", where, chk.Resource)
		}
		if chk.Environment != "" && chk.Environment != "dev" && chk.Environment != "staging" && chk.Environment != "prod" {
			v.addf("%s: environment %q; want dev, staging or prod", where, chk.Environment)
		}
		if chk.Now != "" {
			if _, err := time.Parse(time.RFC3339, chk.Now); err != nil {
				v.addf("%s: now %q is not an RFC 3339 timestamp", where, chk.Now)
			}
		}

		v.checkExpectation(where, chk.Expect, grantIDs)
	}
}

func (v *validation) checkExpectation(where string, e Expect, grantIDs map[string]bool) {
	switch {
	case e.Reason == "":
		v.addf("%s: expect.reason is required; a case that does not pin the reason "+
			"passes when an implementation denies for the wrong cause", where)
	case !KnownReasons[e.Reason]:
		v.addf("%s: expect.reason %q is not a published reason code (see docs/api.md)", where, e.Reason)
	}

	// The two halves of an expectation must agree. An allow is always
	// grant_matched; every other reason is a denial.
	if e.Allowed && e.Reason != "" && e.Reason != ReasonGrantMatched {
		v.addf("%s: expects allowed with reason %q; an allow is always %s", where, e.Reason, ReasonGrantMatched)
	}
	if !e.Allowed && e.Reason == ReasonGrantMatched {
		v.addf("%s: expects a denial with reason %s, which only accompanies an allow", where, ReasonGrantMatched)
	}

	if e.MatchedGrant != "" {
		if !e.Allowed {
			v.addf("%s: matched_grant is only meaningful on an allow", where)
		}
		if !grantIDs[e.MatchedGrant] {
			v.addf("%s: matched_grant %q is not the id of any declared grant", where, e.MatchedGrant)
		}
	}
}

func (v *validation) addf(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

func (v *validation) err() error {
	if len(v.problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid case:\n  - %s", strings.Join(v.problems, "\n  - "))
}
