package authz

import (
	"reflect"
	"testing"
)

// referencedPaths is what makes an explanation useful rather than decorative: it is
// how the derivation reports the values a condition actually read. Walking the
// compiled AST rather than the source text means a path inside a string literal is
// not mistaken for a reference, and formatting cannot change the result.
func TestReferencedPaths(t *testing.T) {
	cases := []struct {
		expr string
		want []string
	}{
		{
			`resource.attributes.amount <= subject.attributes.approval_limit`,
			[]string{"resource.attributes.amount", "subject.attributes.approval_limit"},
		},
		{
			`subject.attributes.department == resource.attributes.department`,
			[]string{"resource.attributes.department", "subject.attributes.department"},
		},
		{
			`context.ip.inCidr("10.0.0.0/8")`,
			[]string{"context.ip"},
		},
		{
			// A literal that looks like a path must not be reported as one.
			`resource.attributes.status == "subject.attributes.department"`,
			[]string{"resource.attributes.status"},
		},
		{
			// The same path twice is one entry.
			`resource.attributes.amount > 0 && resource.attributes.amount < 100`,
			[]string{"resource.attributes.amount"},
		},
		{
			// Only the deepest chain: reporting subject.attributes alongside
			// subject.attributes.x is noise, and the shorter one is never what the
			// expression actually asked for.
			`subject.attributes.a == subject.attributes.b`,
			[]string{"subject.attributes.a", "subject.attributes.b"},
		},
		{
			`action == "approve" && environment.name == "prod"`,
			[]string{"environment.name"},
		},
	}

	conds, err := NewConditionSet()
	if err != nil {
		t.Fatalf("NewConditionSet: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			if err := conds.Compile(tc.expr); err != nil {
				t.Fatalf("Compile: %v", err)
			}
			conds.mu.RLock()
			got := conds.programs[tc.expr].paths
			conds.mu.RUnlock()
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("paths = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolvePath(t *testing.T) {
	activation := map[string]any{
		"subject":  map[string]any{"attributes": map[string]any{"limit": 50000}},
		"resource": map[string]any{"attributes": map[string]any{}},
	}
	cases := map[string]any{
		"subject.attributes.limit": 50000,
		// An absent path resolves to nil rather than erroring: reporting "this was
		// not there" is the entire point of a missing_attribute explanation.
		"resource.attributes.amount": nil,
		"nonexistent.thing":          nil,
		"subject.attributes":         map[string]any{"limit": 50000},
	}
	for path, want := range cases {
		if got := resolvePath(activation, path); !reflect.DeepEqual(got, want) {
			t.Errorf("resolvePath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestScopeStringRendersWhatAnAdministratorWrote(t *testing.T) {
	cases := []struct{ kind, ref, want string }{
		{"tenant", "ten_acme", "tenant"},
		{"application", "billing", "app:billing"},
		{"environment", "billing/prod", "app:billing/env:prod"},
		{"resource", "billing.invoice:4711", "billing.invoice:4711"},
		{"subtree", "billing.project:acme-2026", "billing.project:acme-2026/**"},
	}
	for _, tc := range cases {
		if got := scopeString(tc.kind, tc.ref); got != tc.want {
			t.Errorf("scopeString(%q, %q) = %q, want %q", tc.kind, tc.ref, got, tc.want)
		}
	}
}

// A disabled trace must cost nothing and record nothing: a plain check is the hot
// path, and it must not pay for a feature it did not ask for.
func TestDisabledTraceIsInert(t *testing.T) {
	tr := newTrace(false)
	if tr.enabled() {
		t.Fatal("a trace built with explain=false reports itself enabled")
	}
	// Every method must tolerate the nil receiver.
	tr.note("anything")
	tr.subject([]string{"r"}, []string{"g"})
	tr.grant(&Grant{ID: "grn_x"}, "role", OutcomeMatched, "", nil)
	tr.denial(&Denial{ID: "den_x"}, true)
	if tr.result() != nil {
		t.Fatal("a disabled trace produced an explanation")
	}
}
