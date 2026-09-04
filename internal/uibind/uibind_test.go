package uibind_test

import (
	"context"
	"errors"
	"testing"

	"github.com/warden-project/warden/internal/authz"
	"github.com/warden-project/warden/internal/uibind"
)

// fakeDecider answers from fixed sets, so resolution can be tested without a database.
type fakeDecider struct {
	permissions map[string]bool
	roles       map[string]bool
	err         error
}

func (f fakeDecider) Check(_ context.Context, _ string, req authz.Request) (authz.Decision, error) {
	if f.err != nil {
		return authz.Decision{}, f.err
	}
	return authz.Decision{Allowed: f.permissions[req.Permission], Reason: "test"}, nil
}

func (f fakeDecider) HoldsRole(_ context.Context, _, _, role string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.roles[role], nil
}

func resolve(t *testing.T, d uibind.Decider, e uibind.Element) uibind.Resolution {
	t.Helper()
	res, err := uibind.Resolve(context.Background(), d, e, uibind.Request{
		TenantID: "ten_a", Subject: "usr_a",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return res
}

// An element with no binding falls back to its suggested permission, so an
// application works the moment it is enrolled and before anybody configures anything
// (SPEC §11.2).
func TestAnUnboundElementUsesItsSuggestedPermission(t *testing.T) {
	e := uibind.Element{
		Key: "invoices.approve_button", DefaultMode: uibind.ModeDisabled,
		SuggestedPermission: "billing.invoice:approve",
	}

	holder := fakeDecider{permissions: map[string]bool{"billing.invoice:approve": true}}
	if got := resolve(t, holder, e).Mode; got != uibind.ModeAllow {
		t.Errorf("a subject holding the suggested permission got %q", got)
	}

	if got := resolve(t, fakeDecider{}, e).Mode; got != uibind.ModeDisabled {
		t.Errorf("a subject without it got %q, want the declared default", got)
	}
}

// With no binding and no suggestion there is nothing to evaluate, so the declared
// default stands.
func TestAnElementWithNothingToEvaluateUsesItsDefault(t *testing.T) {
	e := uibind.Element{Key: "nav.reports", DefaultMode: uibind.ModeHidden}
	if got := resolve(t, fakeDecider{}, e).Mode; got != uibind.ModeHidden {
		t.Errorf("mode = %q", got)
	}
}

// A binding overrides the suggestion entirely — that is the point of it. An
// administrator may bind an element to something the developer never suggested.
func TestABindingOverridesTheSuggestion(t *testing.T) {
	e := uibind.Element{
		Key: "nav.reports", DefaultMode: uibind.ModeHidden,
		SuggestedPermission: "billing.report:read",
		Binding: &uibind.Binding{
			Requires: uibind.Requires{AnyOf: []uibind.Clause{{Role: "billing.viewer"}}},
			Mode:     uibind.ModeDisabled, Message: "Ask an administrator",
		},
	}

	// Holds the suggested permission but not the required role: the binding decides.
	d := fakeDecider{permissions: map[string]bool{"billing.report:read": true}}
	res := resolve(t, d, e)
	if res.Mode != uibind.ModeDisabled {
		t.Errorf("mode = %q; the binding, not the suggestion, decides", res.Mode)
	}
	if res.Message != "Ask an administrator" {
		t.Errorf("message = %q", res.Message)
	}

	// Holds the role but not the permission: allowed.
	d = fakeDecider{roles: map[string]bool{"billing.viewer": true}}
	if got := resolve(t, d, e).Mode; got != uibind.ModeAllow {
		t.Errorf("mode = %q, want allow", got)
	}
}

func TestAnyOfAndAllOf(t *testing.T) {
	clauses := []uibind.Clause{{Permission: "a.b:read"}, {Role: "admin"}}

	cases := []struct {
		name     string
		requires uibind.Requires
		d        fakeDecider
		want     string
	}{
		{"any_of with one satisfied", uibind.Requires{AnyOf: clauses},
			fakeDecider{permissions: map[string]bool{"a.b:read": true}}, uibind.ModeAllow},
		{"any_of with the other satisfied", uibind.Requires{AnyOf: clauses},
			fakeDecider{roles: map[string]bool{"admin": true}}, uibind.ModeAllow},
		{"any_of with neither", uibind.Requires{AnyOf: clauses},
			fakeDecider{}, uibind.ModeHidden},
		{"all_of with both", uibind.Requires{AllOf: clauses},
			fakeDecider{permissions: map[string]bool{"a.b:read": true}, roles: map[string]bool{"admin": true}},
			uibind.ModeAllow},
		{"all_of with only one", uibind.Requires{AllOf: clauses},
			fakeDecider{permissions: map[string]bool{"a.b:read": true}}, uibind.ModeHidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := uibind.Element{
				Key: "x", DefaultMode: uibind.ModeHidden,
				Binding: &uibind.Binding{Requires: tc.requires, Mode: uibind.ModeHidden},
			}
			if got := resolve(t, tc.d, e).Mode; got != tc.want {
				t.Errorf("mode = %q, want %q", got, tc.want)
			}
		})
	}
}

// A clause the engine cannot answer is an error, so the caller can log the
// misconfiguration rather than mistake a hidden control for a decision.
func TestAnUnanswerableClauseIsAnError(t *testing.T) {
	e := uibind.Element{
		Key: "x", DefaultMode: uibind.ModeHidden,
		Binding: &uibind.Binding{
			Requires: uibind.Requires{AnyOf: []uibind.Clause{{Permission: "a.b:read"}}},
			Mode:     uibind.ModeHidden,
		},
	}
	_, err := uibind.Resolve(context.Background(),
		fakeDecider{err: errors.New("database down")}, e, uibind.Request{TenantID: "t", Subject: "s"})
	if err == nil {
		t.Fatal("a failing engine resolved silently")
	}
}

func TestParseRequires(t *testing.T) {
	if _, err := uibind.ParseRequires([]byte(`{"any_of":[{"permission":"a.b:c"}]}`)); err != nil {
		t.Errorf("a valid any_of was rejected: %v", err)
	}
	for _, bad := range []string{
		`{}`,            // neither
		`{"any_of":[]}`, // empty
		`{"any_of":[{"permission":"a.b:c"}],"all_of":[{"role":"x"}]}`, // both
		`not json`,
	} {
		if _, err := uibind.ParseRequires([]byte(bad)); err == nil {
			t.Errorf("ParseRequires accepted %q", bad)
		}
	}
}

// A clause naming both is ambiguous, and guessing which was meant would silently
// change what an interface shows.
func TestAClauseNamingBothIsRejected(t *testing.T) {
	e := uibind.Element{
		Key: "x", DefaultMode: uibind.ModeHidden,
		Binding: &uibind.Binding{
			Requires: uibind.Requires{AnyOf: []uibind.Clause{{Permission: "a.b:c", Role: "admin"}}},
			Mode:     uibind.ModeHidden,
		},
	}
	if _, err := uibind.Resolve(context.Background(), fakeDecider{}, e,
		uibind.Request{TenantID: "t", Subject: "s"}); err == nil {
		t.Fatal("a clause naming both a permission and a role was accepted")
	}
}

// An element nobody has resolved renders as hidden. Failing closed is the only safe
// default for something that decides whether a control appears.
func TestTheZeroElementIsHidden(t *testing.T) {
	var e uibind.Element
	if got := resolve(t, fakeDecider{}, e).Mode; got != "" && got != uibind.ModeHidden {
		t.Errorf("an element with no configuration resolved to %q", got)
	}
}
