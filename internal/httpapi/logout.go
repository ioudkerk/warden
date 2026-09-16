package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v3"
)

// RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0, SPEC §7.7).
//
// A relying party sends the browser here to end the session. Three things have to be
// true for that to be safe, and each is a separate defence below: the destination
// afterwards must be one the client registered, the request must be one the user or the
// client actually made rather than one a third-party page caused, and ending a session
// must end everything issued through it.

// logoutLifetime bounds how stale an id_token_hint may be.
//
// Generous on purpose. The hint is not a credential — it proves the client had a token
// for this session once, which is all it is asked to prove — and the tokens it describes
// are already short-lived. Refusing a slightly old hint would send people to a
// confirmation page for no gain.
const logoutHintMaxAge = 24 * time.Hour

// handleLogout serves GET and POST /oauth2/logout.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The request could not be read.")
		return
	}

	request := logoutRequest{
		IDTokenHint:  r.FormValue("id_token_hint"),
		ClientID:     r.FormValue("client_id"),
		PostLogoutTo: r.FormValue("post_logout_redirect_uri"),
		State:        r.FormValue("state"),
	}

	hint, hintErr := s.parseIDTokenHint(ctx, request.IDTokenHint)
	if hintErr != nil {
		// Not fatal: an unverifiable hint is treated as no hint at all, which costs the
		// user a confirmation click. Refusing outright would make a key rotation look
		// like a broken provider to every client still holding an older id token.
		s.log.Info("an id_token_hint could not be verified", "error", hintErr)
	}

	// The client, from the hint or from the parameter. When both are present they have
	// to agree: a hint for one client and a post_logout_redirect_uri belonging to
	// another is how an attacker would try to borrow somebody else's allowlist.
	clientID := request.ClientID
	if hint != nil && hint.ClientID != "" {
		if clientID != "" && clientID != hint.ClientID {
			writeProblem(w, http.StatusBadRequest, "invalid_request",
				"client_id does not match the client the id_token_hint was issued to.")
			return
		}
		clientID = hint.ClientID
	}

	// Where to go afterwards, validated before anything is revoked. Answered directly on
	// failure and never by redirect: an unregistered post_logout_redirect_uri is an open
	// redirect, and this endpoint is reached with a session cookie attached.
	destination, err := s.postLogoutDestination(ctx, clientID, request.PostLogoutTo, request.State)
	if err != nil {
		s.log.Warn("a logout named an unusable post_logout_redirect_uri",
			"client_id", clientID, "error", err)
		writeProblem(w, http.StatusBadRequest, "invalid_request",
			"post_logout_redirect_uri is not registered for this client.")
		return
	}

	session, signedIn := s.currentSession(r)

	// Whether to act now or ask first.
	//
	// A GET to this endpoint can be caused by any page on the internet — an <img> tag is
	// enough — so acting on one unconditionally is a cross-site request forgery whose
	// effect is "log this person out". The two ways to know better: the request was
	// posted with a matching CSRF token, or a relying party vouched for it with an
	// id_token_hint naming the very session the browser is presenting.
	switch {
	case r.Method == http.MethodPost:
		if csrfErr := s.checkCSRF(r); csrfErr != nil {
			s.log.Warn("a logout was posted without a matching CSRF token", "error", csrfErr)
			writeProblem(w, http.StatusBadRequest, "invalid_request",
				"Your sign-out form expired. Please try again.")
			return
		}
	case !signedIn:
		// Nothing to end. Answered as a success, because it is one: the user is not
		// signed in, which is what they asked for.
	case hint != nil && hint.SessionID != "" && session != nil && hint.SessionID == session.ID:
		// Vouched for by the client, and for this session.
	default:
		s.renderLogoutConfirmation(w, request)
		return
	}

	if signedIn && session != nil {
		if endErr := s.provider.Storage().EndSession(ctx, session.TenantID, session.ID,
			"the user signed out"); endErr != nil {
			s.log.Error("ending a session at logout", "error", endErr,
				"tenant_id", session.TenantID, "session_id", session.ID)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"The sign-out could not be completed.")
			return
		}
		s.log.Info("a user signed out",
			"tenant_id", session.TenantID, "user_id", session.UserID, "session_id", session.ID)
	}

	// Cleared whether or not there was a session: a cookie naming a session that no
	// longer exists is a cookie that will be sent on every request for nothing.
	s.clearSessionCookie(w)

	if destination != "" {
		http.Redirect(w, r, destination, http.StatusSeeOther)
		return
	}
	loginSecurityHeaders(w)
	s.renderSignedOut(w)
}

// logoutRequest is what the endpoint was asked for, carried through the confirmation
// page so that a POST says the same thing the GET did.
type logoutRequest struct {
	IDTokenHint  string
	ClientID     string
	PostLogoutTo string
	State        string
}

// postLogoutDestination validates where the browser may be sent afterwards.
//
// Exact string match against the client's registered list, the same rule redirect_uri
// follows (SPEC §17). An empty parameter is not an error: RP-initiated logout §3 allows
// a client to end the session without naming a destination, and the provider shows its
// own page instead.
func (s *Server) postLogoutDestination(ctx context.Context, clientID, target, state string) (string, error) {
	if target == "" {
		return "", nil
	}
	if clientID == "" {
		return "", errors.New(
			"a post_logout_redirect_uri was given with no client to check it against; " +
				"send client_id or an id_token_hint")
	}

	client, err := s.provider.Storage().Clients().Lookup(ctx, clientID)
	if err != nil {
		return "", fmt.Errorf("looking the client up: %w", err)
	}

	registered := false
	for _, candidate := range client.PostLogoutRedirectURIs {
		if candidate == target {
			registered = true
			break
		}
	}
	if !registered {
		return "", fmt.Errorf("%q is not registered for %s", target, clientID)
	}

	if state == "" {
		return target, nil
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("state", state)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// clearSessionCookie expires the cookie the browser holds.
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	name, _ := s.cookieNames()
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/",
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		MaxAge:   -1,
	})
}

// --- the id_token_hint --------------------------------------------------------------

// idTokenHint is what a verified hint tells us.
type idTokenHint struct {
	ClientID  string
	SessionID string
	TenantID  string
	Subject   string
}

// hintClaims is the subset of an id token this endpoint reads.
type hintClaims struct {
	Issuer    string       `json:"iss"`
	Subject   string       `json:"sub"`
	Audience  audienceList `json:"aud"`
	SessionID string       `json:"sid"`
	TenantID  string       `json:"tid"`
	IssuedAt  int64        `json:"iat"`
}

// audienceList reads "aud" in either of the two shapes RFC 7519 §4.1.3 permits.
type audienceList []string

func (a *audienceList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = audienceList{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// parseIDTokenHint verifies an id token well enough to believe what it says.
//
// The signature is checked against the published key set, which is what makes the hint
// worth anything: without it, anyone could claim any session. Expiry is deliberately
// *not* checked — RP-Initiated Logout §2 says an expired id token is still a valid hint,
// and insisting otherwise would mean a client could not log a user out using the token it
// was given ten minutes ago. An age bound stands in for it, so a token found in a log
// file a year later is not a way to target a session.
func (s *Server) parseIDTokenHint(ctx context.Context, raw string) (*idTokenHint, error) {
	if raw == "" {
		return nil, nil //nolint:nilnil // no hint is not a failure; the caller asks for confirmation
	}
	if s.keys == nil {
		return nil, errors.New("this process publishes no keys and cannot verify an id token")
	}

	parsed, err := jose.ParseSigned(raw)
	if err != nil {
		return nil, fmt.Errorf("the id_token_hint is not a signed token: %w", err)
	}
	if len(parsed.Signatures) == 0 {
		return nil, errors.New("the id_token_hint carries no signature")
	}

	body, _, err := s.keys.JWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the published keys: %w", err)
	}
	var set jose.JSONWebKeySet
	if parseErr := json.Unmarshal(body, &set); parseErr != nil {
		return nil, fmt.Errorf("parsing the published keys: %w", parseErr)
	}

	kid := parsed.Signatures[0].Header.KeyID
	candidates := set.Key(kid)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no published key with kid %q", kid)
	}
	payload, err := parsed.Verify(candidates[0])
	if err != nil {
		return nil, fmt.Errorf("the id_token_hint does not verify: %w", err)
	}

	var claims hintClaims
	if claimsErr := json.Unmarshal(payload, &claims); claimsErr != nil {
		return nil, fmt.Errorf("the id_token_hint payload is not JSON: %w", claimsErr)
	}
	if claims.Issuer != s.provider.Issuer() {
		return nil, fmt.Errorf("the id_token_hint was issued by %q, not by this provider", claims.Issuer)
	}
	if claims.IssuedAt > 0 {
		if age := time.Since(time.Unix(claims.IssuedAt, 0)); age > logoutHintMaxAge {
			return nil, fmt.Errorf("the id_token_hint is %s old", age.Truncate(time.Hour))
		}
	}

	hint := &idTokenHint{
		SessionID: claims.SessionID, TenantID: claims.TenantID, Subject: claims.Subject,
	}
	if len(claims.Audience) > 0 {
		hint.ClientID = claims.Audience[0]
	}
	return hint, nil
}

// --- the pages ----------------------------------------------------------------------

var logoutTemplate = template.Must(template.New("logout").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign out</title>
<style>
 body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background:#f6f7f9;
        margin:0; display:flex; min-height:100vh; align-items:center; justify-content:center; }
 main { background:#fff; padding:2rem; border-radius:8px; width:min(24rem, 92vw);
        box-shadow:0 1px 3px rgba(0,0,0,.12); }
 h1 { font-size:1.25rem; margin:0 0 .25rem; }
 p { margin:0 0 1.5rem; color:#666; font-size:.875rem; }
 button { width:100%; padding:.625rem; background:#1a1a2e; color:#fff; border:0;
          border-radius:4px; font-size:1rem; cursor:pointer; }
</style>
</head>
<body>
<main>
  <h1>Sign out?</h1>
  <p>You are about to sign out of your account.</p>
  <form method="post" action="/oauth2/logout">
    <input type="hidden" name="{{.CSRFField}}" value="{{.CSRFToken}}">
    <input type="hidden" name="id_token_hint" value="{{.IDTokenHint}}">
    <input type="hidden" name="client_id" value="{{.ClientID}}">
    <input type="hidden" name="post_logout_redirect_uri" value="{{.PostLogoutTo}}">
    <input type="hidden" name="state" value="{{.State}}">
    <button type="submit">Sign out</button>
  </form>
</main>
</body>
</html>`))

var signedOutTemplate = template.Must(template.New("signedout").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signed out</title>
<style>
 body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background:#f6f7f9;
        margin:0; display:flex; min-height:100vh; align-items:center; justify-content:center; }
 main { background:#fff; padding:2rem; border-radius:8px; width:min(24rem, 92vw);
        box-shadow:0 1px 3px rgba(0,0,0,.12); text-align:center; }
 h1 { font-size:1.25rem; margin:0 0 .25rem; }
 p { margin:0; color:#666; font-size:.875rem; }
</style>
</head>
<body>
<main>
  <h1>Signed out</h1>
  <p>You can close this window.</p>
</main>
</body>
</html>`))

type logoutPage struct {
	CSRFField    string
	CSRFToken    string
	IDTokenHint  string
	ClientID     string
	PostLogoutTo string
	State        string
}

// renderLogoutConfirmation asks before ending a session.
func (s *Server) renderLogoutConfirmation(w http.ResponseWriter, request logoutRequest) {
	token, err := s.issueCSRFToken(w)
	if err != nil {
		s.log.Error("issuing a CSRF token", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
		return
	}

	loginSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := logoutTemplate.Execute(w, logoutPage{
		CSRFField: csrfField, CSRFToken: token,
		IDTokenHint: request.IDTokenHint, ClientID: request.ClientID,
		PostLogoutTo: request.PostLogoutTo, State: request.State,
	}); err != nil {
		s.log.Error("rendering the sign-out page", "error", err)
	}
}

func (s *Server) renderSignedOut(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := signedOutTemplate.Execute(w, nil); err != nil {
		s.log.Error("rendering the signed-out page", "error", err)
	}
}
