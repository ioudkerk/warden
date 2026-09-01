package conformance

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Request is one decision to make. It is the corpus's view of the check API in
// docs/api.md, reduced to what an evaluator needs and nothing more.
type Request struct {
	Tenant      string
	Subject     string
	Permission  string
	Resource    string
	Environment string

	// Attributes are supplied by the caller and override anything registered on the
	// resource (SPEC §9.6, attribute sourcing order).
	Attributes map[string]any
	Context    map[string]any

	// Now is the evaluation time. The zero value means the case declares no clock,
	// in which case no grant in it may carry a validity window — Validate enforces
	// that, so an evaluator may treat the zero time as "everything is valid".
	Now time.Time
}

// Decision is the outcome. MatchedGrant is set only on an allow, and only when the
// grant that produced it carries an id.
type Decision struct {
	Allowed      bool
	Reason       string
	MatchedGrant string
}

func (d Decision) String() string {
	verdict := "DENY"
	if d.Allowed {
		verdict = "ALLOW"
	}
	if d.MatchedGrant != "" {
		return fmt.Sprintf("%s(%s, via %s)", verdict, d.Reason, d.MatchedGrant)
	}
	return fmt.Sprintf("%s(%s)", verdict, d.Reason)
}

// Decider answers checks against one loaded model.
type Decider interface {
	Check(ctx context.Context, req Request) (Decision, error)
}

// Evaluator turns a case's model into something that can answer checks.
//
// This is the seam every implementation plugs into: the server's PDP, the Python
// SDK's embedded evaluator, and the reference evaluator in ./reference. They must
// all produce identical results for every case, which is the entire point.
type Evaluator interface {
	Load(ctx context.Context, c *Case) (Decider, error)
}

// Run executes every case in dir against ev, one subtest per check.
//
// A failure prints the case file, the check name, the spec section the case cites,
// and both decisions — enough to act on without opening the corpus.
func Run(t *testing.T, dir string, ev Evaluator) {
	t.Helper()

	cases, err := Load(dir)
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}

	total := 0
	for _, c := range cases {
		total += len(c.Checks)
	}
	t.Logf("corpus: %d cases, %d checks, from %s", len(cases), total, dir)

	for _, c := range cases {
		t.Run(c.Suite, func(t *testing.T) {
			RunCase(t, c, ev)
		})
	}
}

// RunCase executes one case.
func RunCase(t *testing.T, c *Case, ev Evaluator) {
	t.Helper()
	ctx := context.Background()

	decider, err := ev.Load(ctx, c)
	if err != nil {
		t.Fatalf("%s: loading the model: %v", c.Path, err)
	}

	for _, chk := range c.Checks {
		t.Run(chk.Name, func(t *testing.T) {
			now, err := c.EvaluationTime(chk)
			if err != nil {
				t.Fatalf("%s: %v", c.Path, err)
			}

			got, err := decider.Check(ctx, Request{
				Tenant:      chk.Tenant,
				Subject:     chk.Subject,
				Permission:  chk.Permission,
				Resource:    chk.Resource,
				Environment: chk.Environment,
				Attributes:  chk.Attributes,
				Context:     chk.Context,
				Now:         now,
			})
			if err != nil {
				t.Fatalf("%s: check returned an error: %v", c.Path, err)
			}

			for _, problem := range Compare(c, chk, got) {
				t.Error(problem)
			}
		})
	}
}

// Compare reports every way a decision fails to meet a check's expectation, as
// messages ready to hand to t.Error. It is separated from Run so that the harness's
// own correctness is testable: a runner that silently accepts a wrong answer would
// make the entire corpus worthless, and that failure mode is invisible from the
// outside — every test would simply pass.
func Compare(c *Case, chk Check, got Decision) []string {
	want := Decision{
		Allowed:      chk.Expect.Allowed,
		Reason:       chk.Expect.Reason,
		MatchedGrant: chk.Expect.MatchedGrant,
	}

	var problems []string
	if got.Allowed != want.Allowed || got.Reason != want.Reason {
		problems = append(problems, fmt.Sprintf(
			"\n  case:      %s (%s)\n  check:     %s\n  request:   %s may %s on %s\n  expected:  %s\n  got:       %s",
			c.Path, c.Spec, chk.Name,
			chk.Subject, chk.Permission, resourceOrNone(chk.Resource),
			want, got))
		// A wrong verdict makes the grant that produced it uninteresting.
		return problems
	}

	// matched_grant is asserted only when the case sets it; see README.md on
	// candidate ordering.
	if want.MatchedGrant != "" && got.MatchedGrant != want.MatchedGrant {
		problems = append(problems, fmt.Sprintf(
			"\n  case:      %s\n  check:     %s\n  expected the decision to come from grant %s, got %s",
			c.Path, chk.Name, want.MatchedGrant, orNone(got.MatchedGrant)))
	}
	return problems
}

func resourceOrNone(ref string) string {
	if ref == "" {
		return "(no resource)"
	}
	return ref
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
