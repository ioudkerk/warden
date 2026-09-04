// Package provision applies declarative configuration and performs the administrative
// operations that have no console yet.
//
// Everything here runs on the system pool, because it is cross-tenant by nature
// (creating a tenant, publishing a global application surface) or must run before a
// tenant scope can be established. SPEC §6.2 asks that such work be audited; the
// operations take a reason for that purpose, and the audit sink itself arrives with
// M2-12.
package provision

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/warden-project/warden/internal/uibind"
)

// Manifest is an application's declared authorization surface (SPEC §11.2, §15.2).
// It is the file an application keeps in its own repository and syncs with
// `warden apply`.
type Manifest struct {
	Application string           `yaml:"application"`
	Name        string           `yaml:"name"`
	Version     int              `yaml:"version"`
	Resources   []ManifestType   `yaml:"resources"`
	Roles       []ManifestRole   `yaml:"roles"`
	UI          ManifestUI       `yaml:"ui"`
	Settings    ManifestSettings `yaml:"settings"`
}

type ManifestType struct {
	Key        string           `yaml:"key"`
	Name       string           `yaml:"name"`
	Parent     string           `yaml:"parent"`
	Attributes map[string]any   `yaml:"attributes"`
	Actions    []ManifestAction `yaml:"actions"`
}

type ManifestAction struct {
	Key     string   `yaml:"key"`
	Name    string   `yaml:"name"`
	Implies []string `yaml:"implies"`
}

type ManifestRole struct {
	Key         string           `yaml:"key"`
	Name        string           `yaml:"name"`
	Description string           `yaml:"description"`
	Inherits    []string         `yaml:"inherits"`
	Permissions []string         `yaml:"permissions"`
	Constraints ManifestRoleCons `yaml:"constraints"`
}

type ManifestRoleCons struct {
	RequiresMFA  bool     `yaml:"requires_mfa"`
	SoDConflict  []string `yaml:"separation_of_duties_conflicts"`
	MaxAssignees *int     `yaml:"max_assignees"`
}

// The UI surface an application declares (SPEC §11.2).
type ManifestUI struct {
	Elements []ManifestUIElement `yaml:"elements"`
}

type ManifestUIElement struct {
	Key         string `yaml:"key"`
	Label       string `yaml:"label"`
	Description string `yaml:"description"`
	Surface     string `yaml:"surface"`
	Path        string `yaml:"path"`
	Suggests    struct {
		Permission   string `yaml:"permission"`
		ResourceType string `yaml:"resource_type"`
	} `yaml:"suggests"`
	DefaultMode string `yaml:"default_mode"`
}

type ManifestSettings struct {
	FailMode    string `yaml:"fail_mode"`
	CacheMode   string `yaml:"cache_mode"`
	DecisionLog string `yaml:"decision_log"`
}

var keyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// Element keys are dotted paths — invoices.approve_button — so they carry a little
// structure for the console's tree without needing a separate field.
var elementKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

// LoadManifest reads and validates an application manifest.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	// A misspelled key must be an error. A manifest is the declaration of what an
	// application can be asked about; a silently ignored line means a permission
	// nobody can grant and a check that denies with unknown_permission in production.
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// Validate checks a manifest is internally consistent before any of it is written.
func (m *Manifest) Validate() error {
	var problems []string
	addf := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if !keyPattern.MatchString(m.Application) {
		addf("application key %q must match %s", m.Application, keyPattern)
	}
	if m.Name == "" {
		m.Name = m.Application
	}

	types := map[string]bool{}
	declared := map[string]bool{}
	for i := range m.Resources {
		rt := &m.Resources[i]
		if !keyPattern.MatchString(rt.Key) {
			addf("resource key %q must match %s", rt.Key, keyPattern)
		}
		if types[rt.Key] {
			addf("resource %q is declared twice", rt.Key)
		}
		types[rt.Key] = true

		actions := map[string]bool{}
		for _, a := range rt.Actions {
			if !keyPattern.MatchString(a.Key) {
				addf("%s: action key %q must match %s", rt.Key, a.Key, keyPattern)
			}
			if actions[a.Key] {
				addf("%s: action %q is declared twice", rt.Key, a.Key)
			}
			actions[a.Key] = true
			declared[fmt.Sprintf("%s.%s:%s", m.Application, rt.Key, a.Key)] = true
		}
		for _, a := range rt.Actions {
			for _, implied := range a.Implies {
				if implied == a.Key {
					addf("%s:%s implies itself", rt.Key, a.Key)
				} else if !actions[implied] {
					addf("%s:%s implies %q, which is not an action on that resource", rt.Key, a.Key, implied)
				}
			}
		}
	}
	for _, rt := range m.Resources {
		if rt.Parent != "" && !types[rt.Parent] {
			addf("resource %q has parent %q, which is not declared", rt.Key, rt.Parent)
		}
	}

	roles := map[string]bool{}
	for i := range m.Roles {
		r := &m.Roles[i]
		if roles[r.Key] {
			addf("role %q is declared twice", r.Key)
		}
		roles[r.Key] = true
		for _, p := range r.Permissions {
			if err := checkPermission(m.Application, p, declared); err != nil {
				addf("role %s: %v", r.Key, err)
			}
		}
	}
	for i := range m.Roles {
		r := &m.Roles[i]
		for _, parent := range r.Inherits {
			if !roles[parent] {
				addf("role %q inherits %q, which is not declared in this manifest", r.Key, parent)
			}
		}
	}

	seenElements := map[string]bool{}
	for i := range m.UI.Elements {
		e := &m.UI.Elements[i]
		switch {
		case e.Key == "":
			addf("a ui element has no key")
		case !elementKeyPattern.MatchString(e.Key):
			addf("ui element key %q must match %s", e.Key, elementKeyPattern)
		case seenElements[e.Key]:
			addf("ui element %q is declared twice", e.Key)
		}
		seenElements[e.Key] = true

		if e.Label == "" {
			addf("ui element %q has no label; the console shows it to an administrator "+
				"who has never seen your code", e.Key)
		}
		switch e.DefaultMode {
		case "", uibind.ModeHidden, uibind.ModeDisabled, uibind.ModeReadOnly:
		default:
			addf("ui element %q: default_mode %q; want hidden, disabled or read_only", e.Key, e.DefaultMode)
		}
		// A suggested permission naming something the manifest does not declare is a
		// typo that would otherwise surface as a button nobody can ever see.
		if p := e.Suggests.Permission; p != "" {
			if err := checkPermission(m.Application, p, declared); err != nil {
				addf("ui element %s: suggests %v", e.Key, err)
			}
		}
		if rt := e.Suggests.ResourceType; rt != "" {
			want := m.Application + "." + strings.TrimPrefix(rt, m.Application+".")
			if !types[strings.TrimPrefix(want, m.Application+".")] {
				addf("ui element %s: resource_type %q is not declared by this manifest", e.Key, rt)
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid manifest:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// checkPermission rejects a permission that names something the manifest does not
// declare. Catching it here is the whole point of a manifest: the alternative is a
// grant nobody can use, discovered as a deny in production.
func checkPermission(app, p string, declared map[string]bool) error {
	dot := strings.IndexByte(p, '.')
	colon := strings.IndexByte(p, ':')
	if dot <= 0 || colon <= dot+1 || colon == len(p)-1 {
		return fmt.Errorf("permission %q is not of the form app.type:action", p)
	}
	if p[:dot] != app {
		return fmt.Errorf("permission %q belongs to another application; a manifest may only grant its own", p)
	}
	resourceType, action := p[dot+1:colon], p[colon+1:]
	if resourceType == "*" || action == "*" {
		return nil // a wildcard is legal in a role's permission list (SPEC §9.2)
	}
	if !declared[p] {
		return fmt.Errorf("permission %q is not declared by any resource in this manifest", p)
	}
	return nil
}
