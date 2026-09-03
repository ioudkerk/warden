package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/warden-project/warden/internal/authz"
)

// maxBatchChecks matches SPEC §10.1: up to 1000 decisions in one round trip. The cap
// is enforced rather than advised — an unbounded batch is an amplification vector,
// one cheap request turning into arbitrary work.
const maxBatchChecks = 1000

// checkRequest is the body of POST /v1/authz/check, per docs/api.md.
type checkRequest struct {
	Subject     subjectRef     `json:"subject"`
	Permission  string         `json:"permission"`
	Resource    *resourceRef   `json:"resource,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
	Environment string         `json:"environment,omitempty"`
}

type subjectRef struct {
	ID string `json:"id"`
	// Token is the other form docs/api.md defines: the PDP validates an access token
	// and derives the subject. It arrives with M1; until then a caller passes the
	// subject id from its own authentication.
	Token string `json:"token,omitempty"`
}

type resourceRef struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Ref renders the resource as app.type:id.
func (r *resourceRef) Ref() string {
	if r == nil || r.Type == "" || r.ID == "" {
		return ""
	}
	return r.Type + ":" + r.ID
}

type checkResponse struct {
	Allowed          bool      `json:"allowed"`
	Reason           string    `json:"reason"`
	MatchedGrant     string    `json:"matched_grant,omitempty"`
	ConsistencyToken string    `json:"consistency_token"`
	Cache            cacheHint `json:"cache"`
}

type cacheHint struct {
	Cacheable  bool `json:"cacheable"`
	TTLSeconds int  `json:"ttl_seconds"`
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	caller, _ := CallerFrom(r.Context())

	var req checkRequest
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "%v", err)
		return
	}
	if err := validateCheck(&req); err != nil {
		badRequest(w, "%v", err)
		return
	}

	decision, err := s.engine.Check(r.Context(), caller.TenantID, authz.Request{
		Subject:     req.Subject.ID,
		Permission:  req.Permission,
		Resource:    req.Resource.Ref(),
		Environment: req.Environment,
		Attributes:  attributesOf(req.Resource),
		Context:     req.Context,
		Now:         time.Now().UTC(),
	})
	if err != nil {
		s.log.Error("evaluating a check", "error", err, "tenant", caller.TenantID)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The decision could not be evaluated.")
		return
	}

	writeJSON(w, http.StatusOK, toResponse(decision))
}

type batchRequest struct {
	// Subject and Context may be hoisted to the top level and shared by every item,
	// which is the common case: one user, many objects.
	Subject     subjectRef     `json:"subject"`
	Context     map[string]any `json:"context,omitempty"`
	Environment string         `json:"environment,omitempty"`
	Checks      []batchItem    `json:"checks"`
}

type batchItem struct {
	Ref        string       `json:"ref"`
	Subject    *subjectRef  `json:"subject,omitempty"`
	Permission string       `json:"permission"`
	Resource   *resourceRef `json:"resource,omitempty"`
}

func (s *Server) handleBatchCheck(w http.ResponseWriter, r *http.Request) {
	caller, _ := CallerFrom(r.Context())

	var req batchRequest
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "%v", err)
		return
	}
	switch {
	case len(req.Checks) == 0:
		badRequest(w, "checks must contain at least one entry")
		return
	case len(req.Checks) > maxBatchChecks:
		badRequest(w, "a batch may contain at most %d checks, got %d", maxBatchChecks, len(req.Checks))
		return
	}

	results := make(map[string]checkResponse, len(req.Checks))
	seen := make(map[string]bool, len(req.Checks))
	now := time.Now().UTC()

	for i, item := range req.Checks {
		ref := item.Ref
		if ref == "" {
			ref = fmt.Sprintf("%d", i)
		}
		// Results come back keyed by ref, so a duplicate would silently drop an
		// answer the caller is waiting for.
		if seen[ref] {
			badRequest(w, "check ref %q appears more than once", ref)
			return
		}
		seen[ref] = true

		subject := req.Subject
		if item.Subject != nil {
			subject = *item.Subject
		}
		single := checkRequest{
			Subject: subject, Permission: item.Permission,
			Resource: item.Resource, Context: req.Context, Environment: req.Environment,
		}
		if err := validateCheck(&single); err != nil {
			badRequest(w, "check %q: %v", ref, err)
			return
		}

		decision, err := s.engine.Check(r.Context(), caller.TenantID, authz.Request{
			Subject:     single.Subject.ID,
			Permission:  single.Permission,
			Resource:    single.Resource.Ref(),
			Environment: single.Environment,
			Attributes:  attributesOf(single.Resource),
			Context:     single.Context,
			Now:         now,
		})
		if err != nil {
			s.log.Error("evaluating a batch check", "error", err, "tenant", caller.TenantID, "ref", ref)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"The decisions could not be evaluated.")
			return
		}
		results[ref] = toResponse(decision)
	}

	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func toResponse(d authz.Decision) checkResponse {
	return checkResponse{
		Allowed:      d.Allowed,
		Reason:       d.Reason,
		MatchedGrant: d.MatchedGrant,
		// The consistency token names the revision this decision was evaluated
		// against, so a caller can demand at least that freshness later (SPEC §10.5).
		ConsistencyToken: fmt.Sprintf("zt_%012d", d.Revision),
		Cache:            cacheHint{Cacheable: true, TTLSeconds: 60},
	}
}

func attributesOf(r *resourceRef) map[string]any {
	if r == nil {
		return nil
	}
	return r.Attributes
}

func validateCheck(req *checkRequest) error {
	switch {
	case req.Subject.ID == "" && req.Subject.Token != "":
		return errors.New(
			"subject.token is not supported yet: Warden does not issue tokens until milestone M1. " +
				"Pass subject.id from your own authentication instead")
	case req.Subject.ID == "":
		return errors.New("subject.id is required")
	case req.Permission == "":
		return errors.New("permission is required")
	}

	// Wildcards are legal in a grant and never in a check (SPEC §9.2). Accepting one
	// here would let a caller ask a question no grant is written to answer.
	p, err := authz.ParsePermission(req.Permission)
	if err != nil {
		return err
	}
	if p.ResourceType == "*" || p.Action == "*" {
		return fmt.Errorf("permission %q contains a wildcard; a check must name one concrete permission", req.Permission)
	}

	if req.Resource != nil {
		if (req.Resource.Type == "") != (req.Resource.ID == "") {
			return errors.New("resource requires both type and id")
		}
		if req.Resource.Type != "" {
			if _, err := authz.ParseResourceRef(req.Resource.Ref()); err != nil {
				return err
			}
		}
	}
	if req.Environment != "" && req.Environment != "dev" && req.Environment != "staging" && req.Environment != "prod" {
		return fmt.Errorf("environment %q; want dev, staging or prod", req.Environment)
	}
	return nil
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	// An unknown field is usually a typo in a client, and silently ignoring it means
	// the caller believes they sent something they did not — a resource filter, or a
	// context value a condition depends on.
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("malformed request body: %w", err)
	}
	return nil
}
