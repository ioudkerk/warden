package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"

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

	session, signedIn := s.currentSession(r)
	authenticated := signedIn && session.TenantID == tenantID

	// A pushed request is checked for a session *before* fosite is asked to resolve it,
	// and only a pushed one. The request_uri is single use — fosite deletes the row
	// while parsing — so resolving it and then stopping to ask for a password would burn
	// it, and the browser would come back holding a reference to something that no
	// longer exists. Nothing is skipped by going early: a pushed request was fully
	// validated when it was pushed, which is the whole point of pushing it.
	if isPushedRequest(r) && !authenticated {
		s.redirectToLogin(w, r)
		return
	}

	request, err := s.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		// From here on fosite knows the redirect_uri is registered, so errors go back
		// to the client the way the specification requires.
		s.provider.WriteAuthorizeError(ctx, w, request, err)
		return
	}

	// Refused here rather than three steps later, and the difference is a person's time:
	// fosite enforces PKCE inside NewAuthorizeResponse, which runs *after* the login. A
	// client that forgot the challenge would otherwise send somebody to type a password
	// for a request that was never going to succeed.
	if pkceErr := s.requirePKCE(ctx, request); pkceErr != nil {
		s.provider.WriteAuthorizeError(ctx, w, request, pkceErr)
		return
	}

	if !authenticated {
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

// requirePKCE applies the provider's PKCE policy at the authorization endpoint.
//
// It duplicates no policy: both answers are read from the configuration fosite itself
// enforces, so switching the policy switches this with it. What it changes is *when* the
// answer is given — before the login rather than after it.
func (s *Server) requirePKCE(ctx context.Context, request fosite.AuthorizeRequester) error {
	config := s.provider.Config()
	if !config.GetEnforcePKCE(ctx) || !request.GetResponseTypes().ExactOne("code") {
		return nil
	}

	form := request.GetRequestForm()
	if form.Get("code_challenge") == "" {
		return fosite.ErrInvalidRequest.WithHint(
			"This authorization server requires PKCE: include a code_challenge.")
	}

	// RFC 7636 §4.3: an absent method means "plain", which is the one this provider does
	// not accept. Defaulting it here rather than treating empty as "fine" is the
	// difference between requiring proof and requiring a parameter.
	method := form.Get("code_challenge_method")
	if method == "" {
		method = "plain"
	}
	if method != "S256" && !config.GetEnablePKCEPlainChallengeMethod(ctx) {
		return fosite.ErrInvalidRequest.WithHintf(
			"This authorization server supports only the S256 code challenge method, not %q.",
			method)
	}
	return nil
}

// isPushedRequest reports whether this authorization request is the continuation of a
// pushed one (RFC 9126).
func isPushedRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Query().Get("request_uri"), pushedRequestURIPrefix)
}

// pushedRequestURIPrefix is the URN scheme RFC 9126 §2.2 registers, and fosite's default.
const pushedRequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// handlePushedAuthorize is the pushed authorization request endpoint (RFC 9126).
//
// It is the authorization request, sent back-channel and authenticated, in exchange for a
// single-use reference. What that buys is worth stating: the parameters never travel
// through the browser, so they cannot be read from a referrer, a history entry or a
// server log, and they cannot be tampered with between the client and Warden — the
// front-channel request carries only the reference.
//
// Offered, not required: `require_pushed_authorization_requests` is false in the
// discovery document, because insisting on it would break every client that does not
// implement it for a benefit each client can choose for itself.
func (s *Server) handlePushedAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The request body could not be read.")
		return
	}

	tenantID, err := s.tenantForClientRequest(r)
	if err != nil {
		s.log.Debug("a pushed authorization request named no resolvable client", "error", err)
		s.provider.WritePushedAuthorizeError(ctx, w, nil, fosite.ErrInvalidClient)
		return
	}
	ctx = oidcop.WithTenant(ctx, tenantID)
	r = r.WithContext(ctx)

	// Authenticated here as well as inside fosite, because the two answers have to be
	// compared. fosite's PAR handler authenticates the client and then rebuilds the
	// request from the form — and `newAuthorizeRequest` loads the client named by
	// `client_id`, overwriting the one that authenticated whenever the body carries a
	// different name. The pushed request would then belong to a client that proved
	// nothing. RFC 9126 §2 requires the opposite: the request is the authenticating
	// client's, and nobody else's.
	authenticated, err := s.provider.AuthenticateClient(ctx, r, r.PostForm)
	if err != nil {
		s.log.Debug("a pushed authorization request could not authenticate its client", "error", err)
		s.provider.WritePushedAuthorizeError(ctx, w, nil, err)
		return
	}

	request, err := s.provider.NewPushedAuthorizeRequest(ctx, r)
	if err != nil {
		// Never a redirect, whatever the request said: this is a back-channel call from
		// the client, and the error belongs in the response body.
		s.provider.WritePushedAuthorizeError(ctx, w, request, err)
		return
	}

	if request.GetClient().GetID() != authenticated.GetID() {
		s.log.Warn("a client pushed an authorization request naming a different client",
			"authenticated", authenticated.GetID(), "named", request.GetClient().GetID())
		s.provider.WritePushedAuthorizeError(ctx, w, request, fosite.ErrInvalidClient.WithHint(
			"A pushed authorization request must name the client that authenticated it."))
		return
	}

	response, err := s.provider.NewPushedAuthorizeResponse(ctx, request, oidcop.NewEmptySession())
	if err != nil {
		s.provider.WritePushedAuthorizeError(ctx, w, request, err)
		return
	}
	s.provider.WritePushedAuthorizeResponse(ctx, w, request, response)
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
	tenantID, err := s.tenantForClientRequest(r)
	if err != nil {
		s.log.Debug("a token request named no resolvable client", "error", err)
		// fosite's own error, so the body is the shape RFC 6749 requires.
		s.provider.WriteAccessError(ctx, w, nil, fosite.ErrInvalidClient)
		return
	}
	ctx = oidcop.WithTenant(ctx, tenantID)
	r = r.WithContext(ctx)

	request, err := s.provider.NewAccessRequest(ctx, r, oidcop.NewEmptySession())
	if err != nil {
		s.provider.WriteAccessError(ctx, w, request, err)
		return
	}

	// The client credentials grant needs its scopes granted here, and only it.
	//
	// fosite's handler validates the requested scopes against the client's allowlist
	// and then leaves them ungranted, because in every other grant a person decided.
	// Here there is no person: the client authenticated as itself, and the registration
	// is the decision. Without this the grant issues a token with no scopes at all,
	// which every resource server would refuse.
	if request.GetGrantTypes().ExactOne("client_credentials") {
		for _, scope := range request.GetRequestedScopes() {
			request.GrantScope(scope)
		}
		for _, audience := range request.GetRequestedAudience() {
			request.GrantAudience(audience)
		}
	}

	response, err := s.provider.NewAccessResponse(ctx, request)
	if err != nil {
		s.provider.WriteAccessError(ctx, w, request, err)
		return
	}
	s.provider.WriteAccessResponse(ctx, w, request, response)
}

// tenantForClientRequest resolves the tenant from whichever way the client identified
// itself.
//
// Two places, in the order the specification allows them: the form body and HTTP Basic
// credentials. Shared by the token, revocation and pushed-authorization endpoints, which
// all authenticate a client the same way.
func (s *Server) tenantForClientRequest(r *http.Request) (string, error) {
	clients := s.provider.Storage().Clients()

	// HTTP Basic first, and the order is not a style choice. fosite reads the credential
	// this way round — `clientCredentialsFromRequest` takes Basic when it is present and
	// only then falls back to the body — so reading it the other way round meant a
	// request carrying both could be *scoped* from the form while being *authenticated*
	// from the header. That divergence was exploitable across tenants.
	//
	// The order makes the common case right; it is not what makes it safe. The storage
	// refuses a client that does not belong to the scope whatever this returns.
	if clientID, _, ok := r.BasicAuth(); ok && clientID != "" {
		// The id may be percent-encoded in the Basic credential, per RFC 6749 §2.3.1.
		if decoded, err := url.QueryUnescape(clientID); err == nil {
			clientID = decoded
		}
		return clients.TenantOf(r.Context(), clientID)
	}
	if clientID := r.PostFormValue("client_id"); clientID != "" {
		return clients.TenantOf(r.Context(), clientID)
	}
	return "", errNoClientInTokenRequest
}

// errNoClientInTokenRequest is returned when a token request identifies no client.
var errNoClientInTokenRequest = &tokenRequestError{"the request identifies no client"}

type tokenRequestError struct{ message string }

func (e *tokenRequestError) Error() string { return e.message }

// --- introspection (RFC 7662) -------------------------------------------------------

// handleIntrospect answers "is this token still good, and what does it say?".
//
// The endpoint exists for resource servers, and the thing that makes it safe is that it
// is authenticated in both directions: the caller proves who it is, and Warden then
// decides whether that caller is entitled to know anything about this particular token.
// An introspection endpoint without the second check is a token scanner.
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		s.provider.WriteIntrospectionError(ctx, w,
			fosite.ErrInvalidRequest.WithHint("The request body could not be read."))
		return
	}

	caller, tenantID, err := s.introspectionCaller(r)
	if err != nil {
		s.log.Debug("an introspection request could not be attributed to a client", "error", err)
		s.provider.WriteIntrospectionError(ctx, w,
			fosite.ErrRequestUnauthorized.WithHint(
				"Introspection requires client credentials or an access token."))
		return
	}
	ctx = oidcop.WithTenant(ctx, tenantID)
	r = r.WithContext(ctx)

	responder, err := s.provider.NewIntrospectionRequest(ctx, r, oidcop.NewEmptySession())
	if err != nil {
		s.provider.WriteIntrospectionError(ctx, w, err)
		return
	}

	if !mayIntrospect(caller, responder) {
		// Answered as inactive rather than as an error, per RFC 7662 §2.2: "a token the
		// protected resource is not allowed to know about" is reported exactly like an
		// expired one, so the answer carries no information about whether it exists.
		s.log.Warn("a client asked about a token that was not issued to it and does not name it",
			"caller", caller.GetID(), "tenant_id", tenantID)
		s.provider.WriteIntrospectionError(ctx, w, fosite.ErrInactiveToken)
		return
	}

	s.provider.WriteIntrospectionResponse(ctx, w, responder)
}

// introspectionCaller identifies the client asking, and the tenant it belongs to.
//
// fosite accepts two credentials here — HTTP Basic, or an access token of its own — and
// this reads them the same way so that the tenant established for the request is the
// tenant of whoever fosite is about to authenticate. Resolving it any other way would
// let a caller from one tenant set the scope for a token in another.
func (s *Server) introspectionCaller(r *http.Request) (caller fosite.Client, tenantID string, err error) {
	ctx := r.Context()

	// fosite's own order, and following it exactly is the point. Its introspection
	// handler takes the bearer token when there is one and looks at Basic only
	// otherwise — so reading Basic first here meant the identity Warden authorized
	// against was not the identity fosite authenticated. With a *wrong* secret in the
	// Basic header and a valid token of one's own in the body, a caller could borrow any
	// client's entitlements: the forged header decided the authorization and fosite
	// never checked it, because it had already accepted the token.
	//
	// Every identity returned from here is one this function has itself verified.
	if token := fosite.AccessTokenFromRequest(r); token != "" {
		signature := s.provider.AccessTokenSignature(ctx, token)
		tenant, lookupErr := s.provider.Storage().TenantOfAccessToken(ctx, signature)
		if lookupErr != nil {
			return nil, "", lookupErr
		}
		use, requester, introspectErr := s.provider.IntrospectToken(
			oidcop.WithTenant(ctx, tenant), token, fosite.AccessToken, oidcop.NewEmptySession())
		if introspectErr != nil {
			return nil, "", introspectErr
		}
		if use != fosite.AccessToken {
			return nil, "", errNoClientInTokenRequest
		}
		return requester.GetClient(), tenant, nil
	}

	// HTTP Basic, authenticated rather than merely read. AuthenticateClient is fosite's
	// own, so the secret is compared with the same Argon2id hasher and the same rules
	// about which methods a client may use.
	client, err := s.provider.AuthenticateClient(ctx, r, r.PostForm)
	if err != nil {
		return nil, "", err
	}
	if client.IsPublic() {
		// A public client proves nothing by naming itself, so it cannot be the basis of
		// an authorization decision here. fosite would refuse it a moment later anyway.
		return nil, "", errNoClientInTokenRequest
	}
	tenant, err := s.provider.Storage().Clients().TenantOf(ctx, client.GetID())
	if err != nil {
		return nil, "", err
	}
	return client, tenant, nil
}

// mayIntrospect decides whether a caller is entitled to know about a token.
//
// Three ways to qualify: the token was issued to you; it names you by client id in its
// audience; or its audience includes something you are registered to serve. The last is
// the ordinary case — a resource server is not the client that obtained the token, and
// the audience is precisely how a token says which resource server it is for, usually as
// an API's URI rather than as a client id. Anything else is a stranger asking about
// somebody else's credential.
func mayIntrospect(caller fosite.Client, responder fosite.IntrospectionResponder) bool {
	if !responder.IsActive() || responder.GetAccessRequester() == nil {
		return true // nothing is disclosed by an "inactive" answer
	}
	requester := responder.GetAccessRequester()
	if requester.GetClient().GetID() == caller.GetID() {
		return true
	}
	granted := requester.GetGrantedAudience()
	if granted.Has(caller.GetID()) {
		return true
	}
	for _, registered := range caller.GetAudience() {
		if registered != "" && granted.Has(registered) {
			return true
		}
	}
	return false
}

// --- revocation (RFC 7009) ----------------------------------------------------------

// handleRevoke retires a token at the client's request.
//
// The contrast with reuse detection is the point. Both end with a family of refresh
// tokens revoked, but this one is a client behaving correctly, so it is recorded as
// oauth.refresh_token_revoked rather than raised as security.refresh_token_reuse — an
// alarm that fires on correct behaviour is an alarm somebody will learn to ignore. The
// context carries that distinction, because fosite calls the same storage method for
// both and nothing in the arguments says which is which.
//
// It also leaves the browser session alone: revoking a grant is not signing out. That
// is what /oauth2/logout is for.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		s.provider.WriteRevocationResponse(ctx, w,
			fosite.ErrInvalidRequest.WithHint("The request body could not be read."))
		return
	}

	tenantID, err := s.tenantForClientRequest(r)
	if err != nil {
		s.log.Debug("a revocation request named no resolvable client", "error", err)
		s.provider.WriteRevocationResponse(ctx, w, fosite.ErrInvalidClient)
		return
	}

	ctx = oidcop.WithClientRevocation(oidcop.WithTenant(ctx, tenantID))
	r = r.WithContext(ctx)

	// An unknown token is not an error: RFC 7009 §2.2 requires 200, because the client's
	// goal — that the token no longer works — is already met, and answering differently
	// would turn the endpoint into an oracle for which tokens exist.
	s.provider.WriteRevocationResponse(ctx, w, s.provider.NewRevocationRequest(ctx, r))
}
