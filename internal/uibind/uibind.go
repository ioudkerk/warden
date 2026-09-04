// Package uibind resolves which UI elements a subject may see (SPEC §11).
//
// The premise is that an application names a component and stops there: a developer
// writes `element="invoices.approve_button"` once, and an administrator decides at
// runtime which roles see it and whether "not allowed" means hidden, disabled or
// read-only. Changing that is a console action, not a deploy.
//
// None of this is a security boundary (SPEC §2.3). Every action behind an element is
// still checked server-side, and the resolution here answers "what should the
// interface look like", never "is this permitted".
package uibind

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/warden-project/warden/internal/authz"
)

// Modes an element resolves to. `allow` is the resolved outcome and never a
// configured one: an administrator configures what happens when a subject does *not*
// qualify.
const (
	ModeAllow    = "allow"
	ModeHidden   = "hidden"
	ModeDisabled = "disabled"
	ModeReadOnly = "read_only"
)

// Element is a declared UI element, with the binding that applies to it, if any.
type Element struct {
	Key                 string
	Label               string
	DefaultMode         string
	SuggestedPermission string
	// ResourceScoped means the element cannot be resolved without an object, so it
	// is returned in the bundle's deferred list rather than answered eagerly.
	ResourceScoped bool

	// Binding is nil when no administrator has bound this element.
	Binding *Binding
}

// Binding is what an administrator decided.
type Binding struct {
	Requires  Requires
	Mode      string
	Condition string
	Message   string
	Version   int
}

// Requires is the clause set: exactly one of AnyOf or AllOf.
type Requires struct {
	AnyOf []Clause `json:"any_of,omitempty"`
	AllOf []Clause `json:"all_of,omitempty"`
}

// Clause is one requirement: a permission the subject must hold, or a role.
type Clause struct {
	Permission string `json:"permission,omitempty"`
	Role       string `json:"role,omitempty"`
}

// ParseRequires reads a binding's stored clause set.
func ParseRequires(raw []byte) (Requires, error) {
	var r Requires
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, fmt.Errorf("binding requires: %w", err)
	}
	if len(r.AnyOf) == 0 && len(r.AllOf) == 0 {
		return r, fmt.Errorf("binding requires: neither any_of nor all_of is populated")
	}
	if len(r.AnyOf) > 0 && len(r.AllOf) > 0 {
		return r, fmt.Errorf("binding requires: both any_of and all_of are populated; use one")
	}
	return r, nil
}

// Resolution is what an element resolves to for one subject.
type Resolution struct {
	Mode string `json:"mode"`
	// Message accompanies a disabled element: "Only pending invoices can be
	// approved" is a better interface than a button that does nothing.
	Message string `json:"message,omitempty"`
}

// Decider is what resolution needs from the authorization engine.
type Decider interface {
	Check(ctx context.Context, tenantID string, req authz.Request) (authz.Decision, error)
	HoldsRole(ctx context.Context, tenantID, subject, roleKey string) (bool, error)
}

// Request is the context a resolution happens in.
type Request struct {
	TenantID    string
	Subject     string
	Environment string
	// Resource is set only when resolving a resource-scoped element.
	Resource   string
	Attributes map[string]any
	Context    map[string]any
}

// Resolve computes an element's mode for one subject.
//
// The order is SPEC §13.2's: the administrator's binding decides if there is one;
// otherwise the element's own suggested permission acts as the rule, so an
// application is functional the moment it is enrolled and before anybody has
// configured anything (§11.2); otherwise the declared default.
func Resolve(ctx context.Context, d Decider, e Element, req Request) (Resolution, error) {
	if e.Binding != nil {
		satisfied, err := satisfies(ctx, d, e.Binding.Requires, req)
		if err != nil {
			return Resolution{}, err
		}
		if satisfied {
			return Resolution{Mode: ModeAllow}, nil
		}
		return Resolution{Mode: e.Binding.Mode, Message: e.Binding.Message}, nil
	}

	if e.SuggestedPermission != "" {
		decision, err := d.Check(ctx, req.TenantID, authz.Request{
			Subject:    req.Subject,
			Permission: e.SuggestedPermission,
			Resource:   req.Resource,
			Attributes: req.Attributes,
			Context:    req.Context,
			// Environment is deliberately not passed. An element's suggested
			// permission is a developer's guess at what it needs, and narrowing it by
			// environment as well would hide elements for reasons nobody configured.
		})
		if err != nil {
			return Resolution{}, err
		}
		if decision.Allowed {
			return Resolution{Mode: ModeAllow}, nil
		}
	}

	return Resolution{Mode: e.DefaultMode}, nil
}

// satisfies evaluates a clause set.
//
// A clause the engine cannot answer is an error rather than a false, and the caller
// turns that into the element's non-allowed mode. Resolving toward "visible" on an
// error would show a control the administrator meant to hide; resolving toward
// "hidden" silently is at least the safe direction, but it should still be logged
// rather than mistaken for a decision.
func satisfies(ctx context.Context, d Decider, r Requires, req Request) (bool, error) {
	clauses, all := r.AnyOf, false
	if len(r.AllOf) > 0 {
		clauses, all = r.AllOf, true
	}
	if len(clauses) == 0 {
		return false, fmt.Errorf("binding has no clauses")
	}

	for _, c := range clauses {
		ok, err := satisfiesClause(ctx, d, c, req)
		if err != nil {
			return false, err
		}
		if all && !ok {
			return false, nil
		}
		if !all && ok {
			return true, nil
		}
	}
	return all, nil
}

func satisfiesClause(ctx context.Context, d Decider, c Clause, req Request) (bool, error) {
	switch {
	case c.Permission != "" && c.Role != "":
		return false, fmt.Errorf("clause names both a permission and a role; use one per clause")

	case c.Permission != "":
		decision, err := d.Check(ctx, req.TenantID, authz.Request{
			Subject:    req.Subject,
			Permission: c.Permission,
			Resource:   req.Resource,
			Attributes: req.Attributes,
			Context:    req.Context,
		})
		if err != nil {
			return false, err
		}
		return decision.Allowed, nil

	case c.Role != "":
		return d.HoldsRole(ctx, req.TenantID, req.Subject, c.Role)

	default:
		return false, fmt.Errorf("clause names neither a permission nor a role")
	}
}
