package reference

import (
	"fmt"
	"net"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/warden-project/warden/conformance"
)

// Conditions are CEL expressions (SPEC §9.6). They are pure and side-effect free,
// and the production PDP evaluates them under a fuel limit and a 2 ms deadline. This
// evaluator keeps the same language and the same context shape but not the limits —
// the corpus asserts semantics, not performance.

type condResult int

const (
	condTrue condResult = iota
	condFalse
	// condMissingAttribute is returned when an expression reads an attribute that is
	// not present. SPEC §9.6 is explicit: the result is deny with reason
	// missing_attribute, never silently true.
	condMissingAttribute
)

type condition struct {
	source  string
	program cel.Program
}

// compileConditions compiles every distinct expression in a case up front, so a
// malformed expression fails the case rather than one check inside it.
func compileConditions(c *conformance.Case) (map[string]*condition, error) {
	env, err := newCELEnv()
	if err != nil {
		return nil, err
	}

	out := map[string]*condition{}
	compile := func(src string) error {
		if src == "" || out[src] != nil {
			return nil
		}
		ast, issues := env.Compile(src)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("condition %q: %w", src, issues.Err())
		}
		if ast.OutputType() != cel.BoolType {
			return fmt.Errorf("condition %q evaluates to %s; a condition must be boolean", src, ast.OutputType())
		}
		program, err := env.Program(ast)
		if err != nil {
			return fmt.Errorf("condition %q: %w", src, err)
		}
		out[src] = &condition{source: src, program: program}
		return nil
	}

	for _, t := range c.Model.Tenants {
		for _, g := range t.Grants {
			if err := compile(g.Condition); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// newCELEnv declares the context of SPEC §9.6:
//
//	subject.id, subject.email, subject.roles, subject.groups, subject.attributes.*
//	resource.type, resource.id, resource.attributes.*
//	action
//	context.ip, context.time, context.request.*
//	environment.name
func newCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("subject", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("context", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("environment", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("action", cel.StringType),
		inCIDR(),
	)
}

// inCIDR adds the string member function used in SPEC §9.6's examples:
//
//	context.ip.inCidr("10.0.0.0/8")
//
// A malformed address or block is an error rather than false, so a typo in a policy
// surfaces instead of silently narrowing it to nothing.
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

// eval runs the condition against the assembled decision context.
func (c *condition) eval(t *tenant, want permission, req conformance.Request) (condResult, error) {
	activation, err := buildActivation(t, want, req)
	if err != nil {
		return condFalse, err
	}

	out, _, err := c.program.Eval(activation)
	if err != nil {
		if isMissingAttribute(err) {
			return condMissingAttribute, nil
		}
		return condFalse, fmt.Errorf("condition %q: %w", c.source, err)
	}

	result, ok := out.Value().(bool)
	if !ok {
		return condFalse, fmt.Errorf("condition %q returned %T, not a bool", c.source, out.Value())
	}
	if result {
		return condTrue, nil
	}
	return condFalse, nil
}

// isMissingAttribute distinguishes "the expression asked for something that is not
// there" from a genuine evaluation error. CEL reports both as errors, and the
// difference decides between missing_attribute and a failed check, so it is matched
// on the message CEL produces for an absent key or field.
func isMissingAttribute(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "no such key") ||
		strings.Contains(msg, "no such attribute") ||
		strings.Contains(msg, "no such field")
}

// buildActivation assembles the evaluation context. Resource attributes follow the
// sourcing order of SPEC §9.6: attributes passed inline by the caller win over those
// registered on the instance, because the application is the source of truth for its
// own objects.
func buildActivation(t *tenant, want permission, req conformance.Request) (map[string]any, error) {
	user := t.users[req.Subject]

	memberships := t.groupsOf(req.Subject)
	groups := make([]string, 0, len(memberships))
	for g := range memberships {
		groups = append(groups, g)
	}

	roles := make([]string, 0)
	for _, g := range t.grants {
		if g.Subject.IsGroup() {
			if memberships[g.Subject.Group] {
				roles = append(roles, g.Role)
			}
			continue
		}
		if g.Subject.User == req.Subject {
			roles = append(roles, g.Role)
		}
	}

	subject := map[string]any{
		"id":         user.Key,
		"email":      user.Key + "@example.test",
		"roles":      toAnySlice(roles),
		"groups":     toAnySlice(groups),
		"attributes": orEmpty(user.Attributes),
	}

	resource := map[string]any{
		"type":       "",
		"id":         "",
		"attributes": map[string]any{},
	}
	if req.Resource != "" {
		parsed, err := parseResourceRef(req.Resource)
		if err != nil {
			return nil, err
		}
		attrs := map[string]any{}
		if registered, ok := t.resources[req.Resource]; ok {
			for k, v := range registered.Attributes {
				attrs[k] = v
			}
		}
		for k, v := range req.Attributes {
			attrs[k] = v
		}
		resource["type"] = parsed.app + "." + parsed.resourceType
		resource["id"] = parsed.id
		resource["attributes"] = attrs
	} else if len(req.Attributes) > 0 {
		resource["attributes"] = orEmpty(req.Attributes)
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
		"subject":     subject,
		"resource":    resource,
		"action":      want.action,
		"environment": map[string]any{"name": req.Environment},
		"context":     callerContext,
	}, nil
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// Ensure time is linked; buildActivation puts a time.Time into the activation and
// CEL adapts it to a timestamp, which is what context.time.getHours("UTC") needs.
var _ = time.Time{}
