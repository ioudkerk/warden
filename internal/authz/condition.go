package authz

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
)

// Conditions are CEL expressions (SPEC §9.6): pure, side-effect free, and bounded.
// They are compiled once and cached, because compiling on the decision path would put
// a parser between a request and its answer.

// CondResult is the outcome of evaluating a condition.
type CondResult int

const (
	CondTrue CondResult = iota
	CondFalse
	// CondMissingAttribute is returned when an expression reads an attribute that is
	// not there. SPEC §9.6 is explicit: the result is deny with reason
	// missing_attribute, never silently true.
	CondMissingAttribute
)

// ConditionSet compiles and evaluates the condition expressions of a model.
type ConditionSet struct {
	env *cel.Env

	mu       sync.RWMutex
	programs map[string]compiled
}

// compiled is a prepared expression plus the AST an explanation walks to find which
// paths it reads.
type compiled struct {
	program cel.Program
	paths   []string
}

// NewConditionSet builds an evaluator with the context of SPEC §9.6 declared.
func NewConditionSet() (*ConditionSet, error) {
	env, err := cel.NewEnv(
		cel.Variable("subject", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("context", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("environment", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("action", cel.StringType),
		inCIDR(),
	)
	if err != nil {
		return nil, err
	}
	return &ConditionSet{env: env, programs: map[string]compiled{}}, nil
}

// Compile prepares an expression, returning an error the caller can surface at write
// time rather than at decision time. A malformed condition must be rejected when an
// administrator saves it, not silently deny every request afterwards.
func (c *ConditionSet) Compile(expr string) error {
	if expr == "" {
		return nil
	}
	c.mu.RLock()
	_, done := c.programs[expr]
	c.mu.RUnlock()
	if done {
		return nil
	}

	ast, issues := c.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("condition %q: %w", expr, issues.Err())
	}
	if ast.OutputType() != cel.BoolType {
		return fmt.Errorf("condition %q evaluates to %s; a condition must be boolean", expr, ast.OutputType())
	}
	program, err := c.env.Program(ast)
	if err != nil {
		return fmt.Errorf("condition %q: %w", expr, err)
	}

	c.mu.Lock()
	c.programs[expr] = compiled{program: program, paths: referencedPaths(ast.NativeRep())}
	c.mu.Unlock()
	return nil
}

// Eval runs a condition against the assembled decision context.
//
// When explain is true it also returns what the expression read: each path it
// referenced and the value found there, including nils for paths that were absent —
// which is usually the entire explanation for a missing_attribute.
func (c *ConditionSet) Eval(
	_ context.Context, expr string, m *Model, want Permission, req Request, explain bool,
) (CondResult, *ConditionTrace, error) {
	c.mu.RLock()
	prepared, ok := c.programs[expr]
	c.mu.RUnlock()
	if !ok {
		if err := c.Compile(expr); err != nil {
			return CondFalse, nil, err
		}
		c.mu.RLock()
		prepared = c.programs[expr]
		c.mu.RUnlock()
	}

	activation := buildActivation(m, want, req)
	out, _, err := prepared.program.Eval(activation)

	var result CondResult
	switch {
	case err != nil && isMissingAttribute(err):
		result = CondMissingAttribute
	case err != nil:
		return CondFalse, nil, fmt.Errorf("condition %q: %w", expr, err)
	default:
		asBool, isBool := out.Value().(bool)
		if !isBool {
			return CondFalse, nil, fmt.Errorf("condition %q returned %T, not a bool", expr, out.Value())
		}
		if asBool {
			result = CondTrue
		} else {
			result = CondFalse
		}
	}

	if !explain {
		return result, nil, nil
	}

	values := make(map[string]any, len(prepared.paths))
	for _, path := range prepared.paths {
		values[path] = resolvePath(activation, path)
	}
	return result, &ConditionTrace{
		Expression: expr,
		Result:     map[CondResult]string{CondTrue: "true", CondFalse: "false", CondMissingAttribute: "missing_attribute"}[result],
		Values:     values,
	}, nil
}

// isMissingAttribute distinguishes "the expression asked for something that is not
// there" from a genuine evaluation error. CEL reports both as errors, and the
// difference decides between missing_attribute and a plain failed check.
func isMissingAttribute(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "no such key") ||
		strings.Contains(msg, "no such attribute") ||
		strings.Contains(msg, "no such field")
}

// buildActivation assembles the evaluation context of SPEC §9.6. Resource attributes
// follow the documented sourcing order: attributes passed inline by the caller win
// over those registered on the instance.
func buildActivation(m *Model, want Permission, req Request) map[string]any {
	subject := m.Subjects[req.Subject]

	groups := make([]any, 0, len(m.GroupsOf[req.Subject]))
	for g := range m.GroupsOf[req.Subject] {
		groups = append(groups, g)
	}

	roles := make([]any, 0)
	for i := range m.Grants {
		g := &m.Grants[i]
		if g.UserID == req.Subject || (g.GroupID != "" && m.GroupsOf[req.Subject][g.GroupID]) {
			if r, ok := m.Roles[g.RoleID]; ok {
				roles = append(roles, r.Key)
			}
		}
	}

	attrs := map[string]any{}
	resourceType, resourceID := "", ""
	if req.Resource != "" {
		if parsed, err := ParseResourceRef(req.Resource); err == nil {
			resourceType = parsed.App + "." + parsed.ResourceType
			resourceID = parsed.ID
		}
		if registered, ok := m.Resources[req.Resource]; ok {
			for k, v := range registered.Attributes {
				attrs[k] = v
			}
		}
	}
	for k, v := range req.Attributes {
		attrs[k] = v
	}

	callerContext := map[string]any{}
	for k, v := range req.Context {
		callerContext[k] = v
	}
	if _, ok := callerContext["time"]; !ok && !req.Now.IsZero() {
		callerContext["time"] = req.Now
	}
	if _, ok := callerContext["request"]; !ok {
		callerContext["request"] = map[string]any{}
	}

	return map[string]any{
		"subject": map[string]any{
			"id":         subject.ID,
			"attributes": orEmpty(subject.Attributes),
			"groups":     groups,
			"roles":      roles,
		},
		"resource": map[string]any{
			"type":       resourceType,
			"id":         resourceID,
			"attributes": attrs,
		},
		"action":      want.Action,
		"environment": map[string]any{"name": req.Environment},
		"context":     callerContext,
	}
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// inCIDR adds the string member function used in SPEC §9.6's examples:
// context.ip.inCidr("10.0.0.0/8"). A malformed address or block is an error rather
// than false, so a typo in a policy surfaces instead of silently narrowing it.
func inCIDR() cel.EnvOption {
	return cel.Function("inCidr",
		cel.MemberOverload("string_in_cidr_string",
			[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
			cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
				addr, ok := lhs.Value().(string)
				if !ok {
					return types.NewErr("inCidr: receiver is not a string")
				}
				block, ok := rhs.Value().(string)
				if !ok {
					return types.NewErr("inCidr: argument is not a string")
				}
				ip := net.ParseIP(addr)
				if ip == nil {
					return types.NewErr("inCidr: %q is not an IP address", addr)
				}
				_, network, err := net.ParseCIDR(block)
				if err != nil {
					return types.NewErr("inCidr: %q is not a CIDR block", block)
				}
				return types.Bool(network.Contains(ip))
			}),
		),
	)
}
