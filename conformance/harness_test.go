package conformance_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/warden-project/warden/conformance"
	"github.com/warden-project/warden/conformance/reference"
)

const casesDir = "cases"

// --- The harness must not be vacuous ---------------------------------------------

// Every check in the corpus must genuinely constrain the outcome. If Compare
// accepted anything, every case would pass and the corpus would be decoration —
// a failure mode that is completely invisible from the outside, because the symptom
// of a broken test harness is that all the tests pass.
//
// So: for every check, feed the harness the *wrong* answer and require it to
// complain.
func TestHarnessRejectsWrongDecisions(t *testing.T) {
	cases, err := conformance.Load(casesDir)
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}

	checked := 0
	for _, c := range cases {
		for _, chk := range c.Checks {
			// Flipping the verdict must always be caught.
			flipped := conformance.Decision{
				Allowed: !chk.Expect.Allowed,
				Reason:  chk.Expect.Reason,
			}
			if problems := conformance.Compare(c, chk, flipped); len(problems) == 0 {
				t.Errorf("%s / %q: the harness accepted the opposite verdict", c.Path, chk.Name)
			}

			// So must any other reason from the vocabulary.
			for reason := range conformance.KnownReasons {
				if reason == chk.Expect.Reason {
					continue
				}
				wrong := conformance.Decision{Allowed: chk.Expect.Allowed, Reason: reason}
				if problems := conformance.Compare(c, chk, wrong); len(problems) == 0 {
					t.Errorf("%s / %q: the harness accepted reason %q where %q was expected",
						c.Path, chk.Name, reason, chk.Expect.Reason)
				}
			}

			// And where a case pins the grant, another grant must be caught too.
			if chk.Expect.MatchedGrant != "" {
				wrong := conformance.Decision{
					Allowed:      chk.Expect.Allowed,
					Reason:       chk.Expect.Reason,
					MatchedGrant: chk.Expect.MatchedGrant + "_not_this_one",
				}
				if problems := conformance.Compare(c, chk, wrong); len(problems) == 0 {
					t.Errorf("%s / %q: the harness accepted the wrong matched_grant", c.Path, chk.Name)
				}
			}
			checked++
		}
	}
	t.Logf("%d checks are each pinned to exactly one outcome", checked)
}

// The corpus's own correctness claim: the reference evaluator agrees with every
// expectation. TestCorpusAgainstReferenceEvaluator in runner_test.go runs this
// through the full harness; this one asserts the same thing without it, so a bug in
// Run cannot hide a bug in the corpus.
func TestReferenceEvaluatorMatchesEveryExpectation(t *testing.T) {
	cases, err := conformance.Load(casesDir)
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}
	ev := reference.New()
	ctx := context.Background()

	for _, c := range cases {
		decider, err := ev.Load(ctx, c)
		if err != nil {
			t.Fatalf("%s: %v", c.Path, err)
		}
		for _, chk := range c.Checks {
			now, err := c.EvaluationTime(chk)
			if err != nil {
				t.Fatalf("%s: %v", c.Path, err)
			}
			got, err := decider.Check(ctx, conformance.Request{
				Tenant: chk.Tenant, Subject: chk.Subject, Permission: chk.Permission,
				Resource: chk.Resource, Environment: chk.Environment,
				Attributes: chk.Attributes, Context: chk.Context, Now: now,
			})
			if err != nil {
				t.Fatalf("%s / %q: %v", c.Path, chk.Name, err)
			}
			for _, problem := range conformance.Compare(c, chk, got) {
				t.Error(problem)
			}
		}
	}
}

// --- Corpus coverage --------------------------------------------------------------

// A reason code that no case exercises is a reason nobody has agreed the meaning of.
// When a new one is added to the vocabulary this test says so.
func TestEveryReasonCodeIsExercised(t *testing.T) {
	cases, err := conformance.Load(casesDir)
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}

	seen := map[string]bool{}
	for _, c := range cases {
		for _, chk := range c.Checks {
			seen[chk.Expect.Reason] = true
		}
	}

	var missing []string
	for reason := range conformance.KnownReasons {
		if !seen[reason] {
			missing = append(missing, reason)
		}
	}
	if len(missing) > 0 {
		t.Errorf("no case exercises these reason codes: %s", strings.Join(missing, ", "))
	}
}

// --- Case validation ---------------------------------------------------------------

// An invalid case is worse than a missing one: a check naming a role that does not
// exist denies with no_grant and "passes" a test whose author meant to prove
// something else. Every one of these must be caught at load.
func TestInvalidCasesAreRejected(t *testing.T) {
	// The check block is the tail of the fixture, named so one subtest can remove it
	// wholesale.
	const checkBlock = `  - name: allowed
    tenant: acme
    subject: alice
    permission: billing.invoice:read
    expect: {allowed: true, reason: grant_matched, matched_grant: g1}
`

	const valid = `
suite: fixture
description: A minimal valid case, mutated by each subtest below.
model:
  applications:
    - key: billing
      resource_types:
        - key: invoice
          actions: [read, write]
  roles:
    - key: viewer
      permissions: [billing.invoice:read]
  tenants:
    - key: acme
      users: [{key: alice}]
      grants:
        - id: g1
          subject: {user: alice}
          role: viewer
          scope: tenant
checks:
  - name: allowed
    tenant: acme
    subject: alice
    permission: billing.invoice:read
    expect: {allowed: true, reason: grant_matched, matched_grant: g1}
`

	// Sanity: the unmutated fixture must load, or every subtest below is meaningless.
	if _, err := loadString(t, valid); err != nil {
		t.Fatalf("the fixture itself does not load: %v", err)
	}

	cases := []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{"unknown top-level field", "suite: fixture", "suite: fixture\nsuit: typo", "field suit not found"},
		{"missing suite", "suite: fixture\n", "", "suite must be set"},
		{"missing description", "description: A minimal valid case, mutated by each subtest below.\n", "", "description must be set"},

		{"grant names an undeclared role", "role: viewer", "role: nonexistent", `role "nonexistent" is not declared`},
		{"grant names an undeclared user", "subject: {user: alice}", "subject: {user: bob}", `user "bob" is not declared`},
		{"grant names both a user and a group", "subject: {user: alice}", "subject: {user: alice, group: g}", "exactly one of user or group"},
		{"grant names neither", "subject: {user: alice}", "subject: {}", "exactly one of user or group"},
		{"unrecognised scope form", "scope: tenant", "scope: everywhere", "not a recognised form"},
		{"grant id reused", "          scope: tenant\nchecks:", "          scope: tenant\n        - {id: g1, subject: {user: alice}, role: viewer, scope: tenant}\nchecks:", `id "g1" is used twice`},

		{"check names an undeclared tenant", "tenant: acme\n    subject: alice", "tenant: other\n    subject: alice", `tenant "other" is not declared`},
		{"check names an undeclared subject", "subject: alice\n    permission", "subject: bob\n    permission", `subject "bob" is not a user`},
		{"check uses a wildcard permission", "permission: billing.invoice:read", "permission: billing.invoice:*", "wildcards are not allowed in a check"},
		{"check has no name", "  - name: allowed\n", "  - \n", "name is required"},

		{"expectation has no reason", "reason: grant_matched, ", "", "expect.reason is required"},
		{"expectation has an invented reason", "reason: grant_matched", "reason: vibes", "not a published reason code"},
		{"allow paired with a deny reason", "reason: grant_matched", "reason: no_grant", "an allow is always grant_matched"},
		{"deny paired with grant_matched", "allowed: true", "allowed: false", "only accompanies an allow"},
		{"matched_grant names no grant", "matched_grant: g1", "matched_grant: g99", "is not the id of any declared grant"},

		{"role inherits itself", "  - key: viewer", "  - key: viewer\n      inherits: [viewer]", "inherits itself"},
		{"role inheritance cycle", "  roles:\n    - key: viewer", "  roles:\n    - key: other\n      inherits: [viewer]\n    - key: viewer\n      inherits: [other]", "cycle"},
		{"role permission is malformed", "permissions: [billing.invoice:read]", "permissions: [not-a-permission]", "is not of the form app.type:action"},

		{"action implies itself", "        - key: invoice\n          actions: [read, write]", "        - key: invoice\n          actions:\n            - key: read\n              implies: [read]", "implies itself"},
		{"action implies something undeclared", "          actions: [read, write]", "          actions:\n            - key: read\n              implies: [teleport]", "not an action on that resource type"},
		{"resource type is its own parent", "        - key: invoice\n          actions", "        - key: invoice\n          parent: invoice\n          actions", "is its own parent"},

		{"group member does not exist", "      users: [{key: alice}]", "      users: [{key: alice}]\n      groups: [{key: g, members: [ghost]}]", "neither a user nor a group"},
		{"group contains itself", "      users: [{key: alice}]", "      users: [{key: alice}]\n      groups: [{key: g, members: [g]}]", "contains itself"},

		{"user has an invented status", "users: [{key: alice}]", "users: [{key: alice, status: zombie}]", "has status"},
		{"case has no checks", checkBlock, "", "no checks proves nothing"},
		{"validity window without a clock", "scope: tenant\n", "scope: tenant\n          valid_until: \"2030-01-01T00:00:00Z\"\n", "must set `now`"},
		{"malformed timestamp", "scope: tenant\n", "scope: tenant\n          valid_until: \"next tuesday\"\n", "not an RFC 3339 timestamp"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(valid, tc.old, tc.new, 1)
			if mutated == valid {
				t.Fatalf("the mutation did not apply; %q is not in the fixture", tc.old)
			}
			_, err := loadString(t, mutated)
			if err == nil {
				t.Fatalf("this case should have been rejected:\n%s", mutated)
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error does not mention %q:\n%v", tc.wantErr, err)
			}
		})
	}
}

func loadString(t *testing.T, content string) (*conformance.Case, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "case.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return conformance.LoadFile(path)
}

// --- Corpus hygiene ----------------------------------------------------------------

func TestCorpusIsWellFormed(t *testing.T) {
	cases, err := conformance.Load(casesDir)
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}

	suites := map[string]string{}
	for _, c := range cases {
		if prior, dup := suites[c.Suite]; dup {
			t.Errorf("%s and %s share the suite name %q; test output would be ambiguous",
				prior, c.Path, c.Suite)
		}
		suites[c.Suite] = c.Path

		// The citation is what lets a reader check a case against the specification.
		if c.Spec == "" {
			t.Errorf("%s: spec is empty; every case should cite the section it pins down", c.Path)
		}
	}
}
