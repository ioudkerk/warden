package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/authz"
	"github.com/warden-project/warden/internal/store/db"
	"github.com/warden-project/warden/internal/uibind"
)

// --- POST /v1/authz/filter ----------------------------------------------------------

type filterRequest struct {
	Subject     subjectRef     `json:"subject"`
	Permission  string         `json:"permission"`
	Resources   []resourceRef  `json:"resources"`
	Context     map[string]any `json:"context,omitempty"`
	Environment string         `json:"environment,omitempty"`
}

// handleFilter answers "which of these may this subject see?" — the case a list view
// has, and the reason it exists separately from batch-check (SPEC §10.1).
//
// batch-check can express the same question, but its answer is a map the caller has
// to post-process, and every entry needs a ref it does not care about. This returns
// the two sets directly.
//
// It is explicitly not a substitute for filtering in the application's own query when
// the candidate set is large: the caller sends the ids it is already holding.
func (s *Server) handleFilter(w http.ResponseWriter, r *http.Request) {
	caller, _ := CallerFrom(r.Context())

	var req filterRequest
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "%v", err)
		return
	}
	switch {
	case req.Subject.ID == "":
		badRequest(w, "subject.id is required")
		return
	case len(req.Resources) == 0:
		badRequest(w, "resources must contain at least one entry")
		return
	case len(req.Resources) > maxBatchChecks:
		badRequest(w, "at most %d resources may be filtered in one call, got %d",
			maxBatchChecks, len(req.Resources))
		return
	}

	probe := checkRequest{
		Subject: req.Subject, Permission: req.Permission,
		Context: req.Context, Environment: req.Environment,
	}
	if err := validateCheck(&probe); err != nil {
		badRequest(w, "%v", err)
		return
	}

	ctx, span := s.tracer.Start(r.Context(), "warden.filter")
	defer span.End()

	// Both lists are allocated non-nil so they marshal as [] rather than null. A
	// client should not have to handle both spellings of "none".
	allowed := []string{}
	denied := []string{}
	now := time.Now().UTC()

	for i := range req.Resources {
		resource := &req.Resources[i]
		if (resource.Type == "") != (resource.ID == "") {
			badRequest(w, "each resource requires both type and id")
			return
		}

		started := time.Now()
		decision, err := s.engine.Check(ctx, caller.TenantID, authz.Request{
			Subject:     req.Subject.ID,
			Permission:  req.Permission,
			Resource:    resource.Ref(),
			Environment: req.Environment,
			Attributes:  resource.Attributes,
			Context:     req.Context,
			Now:         now,
		})
		if err != nil {
			s.log.Error("filtering", "error", err, "tenant", caller.TenantID)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"The resources could not be filtered.")
			return
		}
		elapsed := time.Since(started)
		if s.metrics != nil {
			s.metrics.ObserveCheck(decision.Allowed, decision.Reason, elapsed.Seconds())
		}
		s.recordDecision(ctx, caller, req.Subject.ID, req.Permission,
			resource.Ref(), decision, elapsed)

		if decision.Allowed {
			allowed = append(allowed, resource.ID)
		} else {
			denied = append(denied, resource.ID)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"allowed": allowed, "denied": denied,
		"consistency_token": fmt.Sprintf("zt_%012d", revisionOf(ctx, s, caller.TenantID)),
	})
}

func revisionOf(ctx context.Context, s *Server, tenantID string) int64 {
	rev, err := s.engine.Revision(ctx, tenantID)
	if err != nil {
		return 0
	}
	return rev
}

// --- GET /v1/ui/bundle --------------------------------------------------------------

type bundleElement struct {
	Mode    string `json:"mode"`
	Message string `json:"message,omitempty"`
}

// handleUIBundle returns what the interface should look like for this subject
// (SPEC §11.4).
//
// Elements that need an object to answer are not answered: they are listed in
// `deferred`, and the caller resolves them per object through /v1/ui/resolve. Guessing
// at them here would mean answering "can you approve invoices" when the question is
// always "can you approve this one".
func (s *Server) handleUIBundle(w http.ResponseWriter, r *http.Request) {
	caller, _ := CallerFrom(r.Context())

	subject := r.URL.Query().Get("subject")
	application := r.URL.Query().Get("application")
	environment := r.URL.Query().Get("environment")
	surface := r.URL.Query().Get("surface")
	if surface == "" {
		surface = "web"
	}
	switch {
	case subject == "":
		badRequest(w, "subject is required")
		return
	case application == "":
		badRequest(w, "application is required")
		return
	}

	ctx, span := s.tracer.Start(r.Context(), "warden.ui.bundle")
	defer span.End()

	// A GET cannot carry a context object, and accepting a JSON blob in a query
	// string would be worse than the one value that actually matters here. amr
	// decides whether an element bound to an MFA-constrained role renders as
	// available. Interim: with M1 this is a claim on the access token instead.
	bundleContext := map[string]any{}
	if amr := r.URL.Query()["amr"]; len(amr) > 0 {
		methods := make([]any, 0, len(amr))
		for _, m := range amr {
			methods = append(methods, m)
		}
		bundleContext["amr"] = methods
	}

	elements, err := s.loadElements(ctx, caller.TenantID, application, environment, surface)
	if err != nil {
		s.log.Error("loading ui elements", "error", err, "tenant", caller.TenantID)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The UI bundle could not be built.")
		return
	}

	resolved := map[string]bundleElement{}
	deferredKeys := []string{}

	for _, e := range elements {
		if e.ResourceScoped {
			deferredKeys = append(deferredKeys, e.Key)
			continue
		}
		res, resolveErr := uibind.Resolve(ctx, s.engine, e, uibind.Request{
			TenantID: caller.TenantID, Subject: subject,
			Environment: environment, Context: bundleContext,
		})
		if resolveErr != nil {
			// A binding that cannot be evaluated resolves to its non-allowed mode.
			// That is the safe direction, but it is a misconfiguration rather than a
			// decision, so it is logged rather than passed off as one.
			s.log.Warn("could not resolve a ui element; using its default",
				"element", e.Key, "error", resolveErr)
			resolved[e.Key] = bundleElement{Mode: e.DefaultMode}
			continue
		}
		resolved[e.Key] = bundleElement{Mode: res.Mode, Message: res.Message}
	}
	sort.Strings(deferredKeys)

	revision, _ := s.engine.Revision(ctx, caller.TenantID) //nolint:errcheck // 0 is a usable token
	body := map[string]any{
		"revision":   revision,
		"expires_at": time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339),
		"elements":   resolved,
		"deferred":   deferredKeys,
	}

	// The ETag covers the subject and the revision, so a bundle is re-fetched exactly
	// when the policy changes rather than on a timer (SPEC §11.4).
	payload, err := json.Marshal(body)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error", "The UI bundle could not be encoded.")
		return
	}
	sum := sha256.Sum256(payload)
	etag := fmt.Sprintf(`W/"%d-%s"`, revision, base64.RawURLEncoding.EncodeToString(sum[:9]))
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body["etag"] = etag
	writeJSON(w, http.StatusOK, body)
}

// --- POST /v1/ui/resolve ------------------------------------------------------------

type uiResolveRequest struct {
	Subject     subjectRef `json:"subject"`
	Application string     `json:"application"`
	Environment string     `json:"environment,omitempty"`
	Surface     string     `json:"surface,omitempty"`
	// Context supplies context.* to any condition a binding or a suggested
	// permission depends on — most importantly `amr`, since a role may require a
	// second factor to be usable and an element bound to it should render as
	// unavailable until the session has one.
	//
	// Interim. Once Warden issues tokens (M1), amr is a claim on the access token
	// and the caller will not restate it: §8.2 puts it there precisely so a client
	// cannot assert its own authentication strength.
	Context map[string]any  `json:"context,omitempty"`
	Items   []uiResolveItem `json:"items"`
}

type uiResolveItem struct {
	Ref      string       `json:"ref,omitempty"`
	Element  string       `json:"element"`
	Resource *resourceRef `json:"resource,omitempty"`
}

// handleUIResolve answers resource-scoped elements for specific objects.
//
// Batched on purpose: a table of two hundred rows, each with an approve and a void
// button, is four hundred questions, and asking them one at a time is what makes a
// list view slow enough that somebody decides to cache the answers badly.
func (s *Server) handleUIResolve(w http.ResponseWriter, r *http.Request) {
	caller, _ := CallerFrom(r.Context())

	var req uiResolveRequest
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, "%v", err)
		return
	}
	switch {
	case req.Subject.ID == "":
		badRequest(w, "subject.id is required")
		return
	case req.Application == "":
		badRequest(w, "application is required")
		return
	case len(req.Items) == 0:
		badRequest(w, "items must contain at least one entry")
		return
	case len(req.Items) > maxBatchChecks:
		badRequest(w, "at most %d items may be resolved in one call, got %d", maxBatchChecks, len(req.Items))
		return
	}
	if req.Surface == "" {
		req.Surface = "web"
	}

	ctx, span := s.tracer.Start(r.Context(), "warden.ui.resolve")
	defer span.End()

	elements, err := s.loadElements(ctx, caller.TenantID, req.Application, req.Environment, req.Surface)
	if err != nil {
		s.log.Error("loading ui elements", "error", err, "tenant", caller.TenantID)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The elements could not be resolved.")
		return
	}
	byKey := map[string]uibind.Element{}
	for _, e := range elements {
		byKey[e.Key] = e
	}

	results := map[string]bundleElement{}
	seen := map[string]bool{}

	for i, item := range req.Items {
		ref := item.Ref
		if ref == "" {
			ref = fmt.Sprintf("%d", i)
		}
		if seen[ref] {
			badRequest(w, "item ref %q appears more than once", ref)
			return
		}
		seen[ref] = true

		element, known := byKey[item.Element]
		if !known {
			// An undeclared element is a typo, and hiding it silently is how a
			// missing button becomes a half-hour of debugging. It resolves to hidden
			// — the safe rendering — and says so.
			results[ref] = bundleElement{
				Mode:    uibind.ModeHidden,
				Message: fmt.Sprintf("element %q is not declared by application %q", item.Element, req.Application),
			}
			continue
		}

		resolveReq := uibind.Request{
			TenantID: caller.TenantID, Subject: req.Subject.ID,
			Environment: req.Environment, Context: req.Context,
		}
		if item.Resource != nil {
			resolveReq.Resource = item.Resource.Ref()
			resolveReq.Attributes = item.Resource.Attributes
		}
		if element.ResourceScoped && resolveReq.Resource == "" {
			// Using a resource-scoped element without an object is a development
			// error (SPEC §11.3), and answering it anyway would give a confidently
			// wrong answer for every row.
			badRequest(w, "element %q is resource-scoped and requires a resource", item.Element)
			return
		}

		res, resolveErr := uibind.Resolve(ctx, s.engine, element, resolveReq)
		if resolveErr != nil {
			s.log.Warn("could not resolve a ui element; using its default",
				"element", element.Key, "error", resolveErr)
			results[ref] = bundleElement{Mode: element.DefaultMode}
			continue
		}
		results[ref] = bundleElement{Mode: res.Mode, Message: res.Message}
	}

	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// loadElements reads an application's declared elements together with whatever
// binding applies in this tenant and environment.
//
// An environment-specific binding wins over the one that applies to all environments,
// which is what makes a change testable in staging before it is promoted (§11.3).
func (s *Server) loadElements(ctx context.Context, tenantID, application, environment, surface string) ([]uibind.Element, error) {
	var elements []uibind.Element
	err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := db.New(tx).UIElementsWithBindings(ctx, db.UIElementsWithBindingsParams{
			Environment: environment, Application: application, Surface: surface,
		})
		if err != nil {
			return err
		}

		for i := range rows {
			r := &rows[i]
			e := uibind.Element{
				Key: r.Key, Label: r.Label, DefaultMode: r.DefaultMode,
				SuggestedPermission: r.SuggestedPermission, ResourceScoped: r.ResourceScoped,
			}
			// An empty mode means the lateral join matched no binding; the column is
			// NOT NULL and constrained to hidden/disabled/read_only, so it cannot be
			// the empty string for a binding that exists.
			if len(r.Requires) > 0 && r.Mode != "" {
				parsed, parseErr := uibind.ParseRequires(r.Requires)
				if parseErr != nil {
					// A malformed binding is not a reason to fail the whole bundle;
					// the element falls back to its default and the problem is
					// logged with the key that carries it.
					s.log.Warn("ignoring a malformed ui binding", "element", e.Key, "error", parseErr)
				} else {
					e.Binding = &uibind.Binding{
						Requires: parsed, Mode: r.Mode,
						Condition: r.Condition, Message: r.Message, Version: int(r.Version),
					}
				}
			}
			elements = append(elements, e)
		}
		return nil
	})
	return elements, err
}
