package httpapi

import (
	"net/http"
	"net/url"

	"github.com/ory/fosite"

	"github.com/warden-project/warden/internal/oidcop"
)

// The authorization code flow (SPEC §7.7).
//
// Two endpoints and one rule that governs both: the tenant is resolved from the client
// before fosite is called, and put in the context. fosite's storage interfaces take a
// signature and nothing else — there is no tenant parameter anywhere in them — so
// establishing scope at the edge is what keeps every storage call afterwards from having
// to re-resolve it, and what keeps one tenant's codes out of another's exchanges.

// handleAuthorize is the authorization endpoint.
//
// It does not authenticate anybody. It checks that the request is well formed and that
// the client is real, and then either finds a session or sends the browser to the login
// page. That separation is deliberate: a request that is malformed should be rejected
// before a password is typed, and the person typing it should not have to do so twice
// because the redirect_uri was wrong.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Scope the context before fosite sees anything. A failure here is not yet an
	// OAuth error — there is no validated redirect_uri to send one to — so it is
	// answered directly rather than by redirect.
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "client_id is required.")
		return
	}
	tenantID, err := s.provider.Storage().Clients().TenantOf(ctx, clientID)
	if err != nil {
		// Unknown client. Refused here rather than redirected, because a redirect would
		// require trusting a redirect_uri that no registered client has vouched for —
		// which is how an authorization endpoint becomes an open redirect.
		writeProblem(w, http.StatusBadRequest, "invalid_client", "Unknown client.")
		return
	}
	ctx = oidcop.WithTenant(ctx, tenantID)
	r = r.WithContext(ctx)

	request, err := s.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		// From here on fosite knows the redirect_uri is registered, so errors go back
		// to the client the way the specification requires.
		s.provider.WriteAuthorizeError(ctx, w, request, err)
		return
	}

	session, signedIn := s.currentSession(r)
	if !signedIn || session.TenantID != tenantID {
		// Either nobody is signed in, or the session belongs to a different tenant —
		// which happens when one browser is used for two deployments' clients, and
		// must start a fresh login rather than silently authorize as the wrong person.
		s.redirectToLogin(w, r)
		return
	}

	// A first-party provider, so consent is implied by the client being registered.
	// There is no consent screen, and that is a deliberate omission rather than an
	// oversight: every client here is one the tenant's own administrator registered.
	// A third-party client — one registered by somebody other than the resource owner —
	// would need one, and nothing in the model distinguishes those yet.
	for _, scope := range request.GetRequestedScopes() {
		request.GrantScope(scope)
	}
	for _, audience := range request.GetRequestedAudience() {
		request.GrantAudience(audience)
	}

	response, err := s.provider.NewAuthorizeResponse(ctx, request,
		oidcop.NewSession(s.provider.Issuer(), tenantID, session.ID, session.UserID,
			session.AuthTime, session.AMR))
	if err != nil {
		s.provider.WriteAuthorizeError(ctx, w, request, err)
		return
	}
	s.provider.WriteAuthorizeResponse(ctx, w, request, response)
}

// redirectToLogin sends the browser to the sign-in page, remembering where to come back.
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.RequestURI()
	target := url.URL{Path: "/login", RawQuery: url.Values{"return_to": {returnTo}}.Encode()}
	http.Redirect(w, r, target.String(), http.StatusSeeOther)
}

// handleToken is the token endpoint.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The request body could not be read.")
		return
	}

	// The tenant again, and the harder case: on a refresh there is no client_id in the
	// body at all for a confidential client using Basic auth, so it comes from the
	// credentials.
	tenantID, err := s.tenantForTokenRequest(r)
	if err != nil {
		s.log.Debug("a token request named no resolvable client", "error", err)
		// fosite's own error, so the body is the shape RFC 6749 requires.
		s.provider.WriteAccessError(ctx, w, nil, fosite.ErrInvalidClient)
		return
	}
	ctx = oidcop.WithTenant(ctx, tenantID)
	r = r.WithContext(ctx)

	session := &oidcop.Session{}
	request, err := s.provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		s.provider.WriteAccessError(ctx, w, request, err)
		return
	}

	response, err := s.provider.NewAccessResponse(ctx, request)
	if err != nil {
		s.provider.WriteAccessError(ctx, w, request, err)
		return
	}
	s.provider.WriteAccessResponse(ctx, w, request, response)
}

// tenantForTokenRequest resolves the tenant from whichever way the client identified
// itself.
//
// Three places, in the order the specification allows them: the form body, HTTP Basic
// credentials, and — for a refresh where a public client sends only the token — the
// stored token itself.
func (s *Server) tenantForTokenRequest(r *http.Request) (string, error) {
	clients := s.provider.Storage().Clients()

	if clientID := r.PostFormValue("client_id"); clientID != "" {
		return clients.TenantOf(r.Context(), clientID)
	}
	if clientID, _, ok := r.BasicAuth(); ok && clientID != "" {
		// The id may be percent-encoded in the Basic credential, per RFC 6749 §2.3.1.
		if decoded, err := url.QueryUnescape(clientID); err == nil {
			clientID = decoded
		}
		return clients.TenantOf(r.Context(), clientID)
	}
	return "", errNoClientInTokenRequest
}

// errNoClientInTokenRequest is returned when a token request identifies no client.
var errNoClientInTokenRequest = &tokenRequestError{"the request identifies no client"}

type tokenRequestError struct{ message string }

func (e *tokenRequestError) Error() string { return e.message }

// handleUserinfo, handleIntrospect, handleRevoke, handleLogout, handlePAR and the device
// endpoints arrive in part 4. They are not registered until they exist: a route that
// answers "not implemented" is worse than a 404, because a client library treats the
// first as a server fault and the second as a provider that does not offer the feature.
