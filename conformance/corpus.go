// Package conformance loads and runs the conformance corpus: a language-neutral set
// of (model, assignments, check, expected) cases that defines what Warden decides.
//
// The corpus is executed against the server and against every SDK's embedded
// evaluator. It is the reason "the Python SDK and the Go server agree" is a tested
// claim rather than an assumption, and the reason ADR-0001's choice of server
// language stays reversible: a port has something executable to be correct against.
//
// The format is documented in README.md. That document, not this file, is what a
// runner in another language is written from — if the two disagree, the README is
// what other implementations followed, so fix the code.
package conformance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Deny reasons, as published in docs/api.md. A runner compares against these exact
// strings, so they are part of the wire contract and not free text.
const (
	ReasonGrantMatched      = "grant_matched"
	ReasonSubjectNotFound   = "subject_not_found"
	ReasonSubjectInactive   = "subject_inactive"
	ReasonUnknownPermission = "unknown_permission"
	ReasonExplicitDeny      = "explicit_deny"
	ReasonConditionFailed   = "condition_failed"
	ReasonMissingAttribute  = "missing_attribute"
	ReasonMFARequired       = "mfa_required"
	ReasonGrantExpired      = "grant_expired"
	ReasonOutOfScope        = "out_of_scope"
	ReasonNoGrant           = "no_grant"
)

// KnownReasons is the closed vocabulary a case may expect. Restricting it is the
// point: a typo in an expected reason must fail the corpus, not silently assert
// something no implementation will ever return.
var KnownReasons = map[string]bool{
	ReasonGrantMatched:      true,
	ReasonSubjectNotFound:   true,
	ReasonSubjectInactive:   true,
	ReasonUnknownPermission: true,
	ReasonExplicitDeny:      true,
	ReasonConditionFailed:   true,
	ReasonMissingAttribute:  true,
	ReasonMFARequired:       true,
	ReasonGrantExpired:      true,
	ReasonOutOfScope:        true,
	ReasonNoGrant:           true,
}

// User lifecycle states (SPEC §7.6). Only "active" can produce an allow.
const (
	StatusInvited       = "invited"
	StatusActive        = "active"
	StatusSuspended     = "suspended"
	StatusDeprovisioned = "deprovisioned"
)

var knownStatuses = map[string]bool{
	StatusInvited: true, StatusActive: true, StatusSuspended: true, StatusDeprovisioned: true,
}

// Case is one corpus file: a complete authorization model plus the checks that must
// hold against it.
type Case struct {
	// Suite groups related cases in test output.
	Suite string `yaml:"suite"`
	// Description says what the case proves, in prose.
	Description string `yaml:"description"`
	// Spec cites the section of SPEC.md the case pins down, e.g. "§9.5".
	Spec string `yaml:"spec"`
	// Now is the evaluation time for every check that does not override it. Cases
	// involving validity windows must set it: a corpus that depends on the wall
	// clock stops being reproducible the day a grant expires.
	Now string `yaml:"now"`

	Model  Model   `yaml:"model"`
	Checks []Check `yaml:"checks"`

	// Path is the file the case was loaded from. Set by Load, not by the file.
	Path string `yaml:"-"`
}

// Model is the authorization world a case's checks run against.
type Model struct {
	Applications []Application `yaml:"applications"`
	Roles        []Role        `yaml:"roles"`
	Tenants      []Tenant      `yaml:"tenants"`
}

// Application declares a permission surface (SPEC §9.2).
type Application struct {
	Key           string         `yaml:"key"`
	ResourceTypes []ResourceType `yaml:"resource_types"`
}

// ResourceType is a kind of object an application protects.
type ResourceType struct {
	Key string `yaml:"key"`
	// Parent names another resource type in the same application. Declaring it is
	// what makes a subtree grant cascade (SPEC §9.5).
	Parent  string   `yaml:"parent"`
	Actions []Action `yaml:"actions"`
}

// Action is a verb on a resource type. It accepts either a bare string or a mapping:
//
//	actions: [read, write]
//	actions:
//	  - key: manage
//	    implies: [read, write, delete]
type Action struct {
	Key string `yaml:"key"`
	// Implies lists other actions on the same resource type. The closure is expanded
	// when the model is loaded, never during a check (SPEC §9.2).
	Implies []string `yaml:"implies"`
}

// UnmarshalYAML accepts the bare-string shorthand for an action.
func (a *Action) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		return node.Decode(&a.Key)
	}
	type plain Action // avoid recursing into this method
	var p plain
	if err := node.Decode(&p); err != nil {
		return err
	}
	*a = Action(p)
	return nil
}

// Role is a named bundle of permissions (SPEC §9.3).
type Role struct {
	Key      string   `yaml:"key"`
	Inherits []string `yaml:"inherits"`
	// Permissions may contain wildcards: billing.invoice:*, billing.*:read,
	// billing.*:*. Wildcards are legal in grants and never in checks.
	Permissions []string `yaml:"permissions"`
	// RequiresMFA means the subject must have authenticated with a second factor to
	// use this role (SPEC §9.3, role constraints).
	RequiresMFA bool `yaml:"requires_mfa"`
}

// Tenant is an isolated space with its own subjects and assignments.
type Tenant struct {
	Key       string     `yaml:"key"`
	Users     []User     `yaml:"users"`
	Groups    []Group    `yaml:"groups"`
	Resources []Resource `yaml:"resources"`
	Grants    []Grant    `yaml:"grants"`
	Denials   []Denial   `yaml:"denials"`
}

// User is a subject. Status defaults to active when omitted.
type User struct {
	Key        string         `yaml:"key"`
	Status     string         `yaml:"status"`
	Attributes map[string]any `yaml:"attributes"`
}

// Group is a set of subjects that receives assignments exactly as a user does.
// Members are user keys or other group keys; nesting forms a DAG (SPEC §9.4).
type Group struct {
	Key     string   `yaml:"key"`
	Members []string `yaml:"members"`
}

// Resource is a registered resource instance, addressed as "app.type:id".
type Resource struct {
	Ref        string         `yaml:"ref"`
	Parent     string         `yaml:"parent"`
	Attributes map[string]any `yaml:"attributes"`
}

// Subject names either a user or a group, never both.
type Subject struct {
	User  string `yaml:"user"`
	Group string `yaml:"group"`
}

// Grant binds a subject or group to a role at a scope, optionally under a condition
// and within a validity window (SPEC §9.5).
type Grant struct {
	// ID is optional and only needed by a check that asserts matched_grant.
	ID      string  `yaml:"id"`
	Subject Subject `yaml:"subject"`
	Role    string  `yaml:"role"`
	// Scope is one of: tenant; app:<key>; app:<key>/env:<name>; <app>.<type>:<id>;
	// <app>.<type>:<id>/**
	Scope string `yaml:"scope"`
	// Condition is a CEL expression evaluated with the context of SPEC §9.6.
	Condition  string `yaml:"condition"`
	ValidFrom  string `yaml:"valid_from"`
	ValidUntil string `yaml:"valid_until"`
}

// Denial is an explicit deny. It outranks every allow (SPEC §9.7).
type Denial struct {
	ID         string  `yaml:"id"`
	Subject    Subject `yaml:"subject"`
	Permission string  `yaml:"permission"`
	Scope      string  `yaml:"scope"`
	// Reason is the written justification the console requires. The corpus carries
	// it so that a case reads as the real thing an administrator would create.
	Reason string `yaml:"reason"`
}

// Check is one decision the model must produce.
type Check struct {
	Name       string `yaml:"name"`
	Tenant     string `yaml:"tenant"`
	Subject    string `yaml:"subject"`
	Permission string `yaml:"permission"`
	// Resource is a ref like "billing.invoice:4711". Omitted for a check that is not
	// about a particular object, which only tenant- and application-scoped grants
	// can satisfy.
	Resource string `yaml:"resource"`
	// Attributes are supplied inline by the caller and take precedence over any
	// registered on the resource — the application is the source of truth for its
	// own objects (SPEC §9.6, attribute sourcing order).
	Attributes  map[string]any `yaml:"attributes"`
	Environment string         `yaml:"environment"`
	// Context supplies context.* to conditions: ip, time, amr, request.*
	Context map[string]any `yaml:"context"`
	Now     string         `yaml:"now"`
	Expect  Expect         `yaml:"expect"`
}

// Expect is the required outcome.
type Expect struct {
	Allowed bool   `yaml:"allowed"`
	Reason  string `yaml:"reason"`
	// MatchedGrant asserts which grant produced an allow. Only assert it in a case
	// where exactly one grant can match; see README.md on candidate ordering.
	MatchedGrant string `yaml:"matched_grant"`
}

// Load reads and validates every case file under dir.
func Load(dir string) ([]*Case, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	ymlPaths, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil, err
	}
	paths = append(paths, ymlPaths...)
	sort.Strings(paths)

	if len(paths) == 0 {
		return nil, fmt.Errorf("no case files found in %s", dir)
	}

	cases := make([]*Case, 0, len(paths))
	for _, path := range paths {
		c, err := LoadFile(path)
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	return cases, nil
}

// LoadFile reads and validates one case file.
func LoadFile(path string) (*Case, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var c Case
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	// A misspelled key in a corpus file must be an error. Silently ignoring it would
	// leave a case asserting less than its author believed — the worst possible
	// failure for a test asset whose whole job is to be trusted.
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Path = path

	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// EvaluationTime returns the instant a check is evaluated at: the check's own now,
// else the case's, else the zero time meaning "the model has no time dependence".
func (c *Case) EvaluationTime(chk Check) (time.Time, error) {
	raw := chk.Now
	if raw == "" {
		raw = c.Now
	}
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("now %q is not an RFC 3339 timestamp: %w", raw, err)
	}
	return t, nil
}

// IsGroup reports whether the subject names a group.
func (s Subject) IsGroup() bool { return s.Group != "" }

// Key returns the subject's key, whichever kind it is.
func (s Subject) Key() string {
	if s.Group != "" {
		return s.Group
	}
	return s.User
}

// String renders a subject for diagnostics.
func (s Subject) String() string {
	if s.Group != "" {
		return "group:" + s.Group
	}
	return "user:" + s.User
}

var errNoSubject = errors.New("subject must name exactly one of user or group")

func (s Subject) validate() error {
	if (s.User == "") == (s.Group == "") {
		return errNoSubject
	}
	return nil
}
