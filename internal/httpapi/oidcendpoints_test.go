package httpapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The endpoints a client uses once it holds a token: userinfo, introspection and
// revocation (SPEC §7.7).
//
// Each is tested for what it must answer *and* for what it must refuse, because the
// refusals are the security properties. An introspection endpoint that answers everyone
// is a token scanner; a userinfo endpoint that accepts a refresh token turns a
// thirty-day credential into a ten-minute one's equivalent.

// --- userinfo ------------------------------------------------------------------------

// TestUserinfoReturnsWhatTheScopesGranted is the endpoint doing its job, and the reason
// scopes exist: the same user, two tokens, two different answers.
func TestUserinfoReturnsWhatTheScopesGranted(t *testing.T) {
	f := newOIDCFixture(t)

	t.Run("openid profile email", func(t *testing.T) {
		claims := f.userinfo(t, f.accessToken(t, "openid profile email", "", "state-for-userinfo-full"))
		if claims["sub"] != f.userID {
			t.Fatalf("sub = %v; want %s. A relying party compares this with the id token's "+
				"sub and rejects a mismatch", claims["sub"], f.userID)
		}
		if claims["email"] != f.email {
			t.Fatalf("email = %v; want %s", claims["email"], f.email)
		}
		if claims["tid"] == nil {
			t.Fatal("no tid: a relying party serving several tenants routes on it")
		}
	})

	t.Run("openid alone", func(t *testing.T) {
		claims := f.userinfo(t, f.accessToken(t, "openid", "", "state-for-userinfo-minimal"))
		if claims["sub"] != f.userID {
			t.Fatalf("sub = %v", claims["sub"])
		}
		if _, leaked := claims["email"]; leaked {
			t.Fatal("userinfo released the email address to a token that was never granted " +
				"the email scope; asking for a scope would mean nothing")
		}
	})
}

// TestUserinfoAcceptsBothMethods. OpenID Connect Core §5.3.1 requires GET and POST, and
// relying-party libraries are split down the middle about which they use.
func TestUserinfoAcceptsBothMethods(t *testing.T) {
	f := newOIDCFixture(t)
	token := f.accessToken(t, "openid email", "", "state-for-userinfo-methods")

	get := f.withBearer(t, http.MethodGet, "/oauth2/userinfo", token)
	if get.Code != http.StatusOK {
		t.Fatalf("GET userinfo = %d, body %s", get.Code, get.Body.String())
	}

	post := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/oauth2/userinfo", strings.NewReader(""))
	post.Header.Set("Authorization", "Bearer "+token)
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, post)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST userinfo = %d, body %s", rec.Code, rec.Body.String())
	}
}

// TestUserinfoRefusesARefreshToken is a defect this test was written to prevent rather
// than to describe.
//
// fosite's introspection falls back to the refresh-token validator when the access-token
// one does not recognise a token, so a refresh token presented at userinfo validates —
// as a refresh token. Accepting it would mean a credential that lives thirty days and is
// meant only for the token endpoint could read a profile anywhere the access token can.
// The handler checks the token *use* that comes back, and this is why.
func TestUserinfoRefusesARefreshToken(t *testing.T) {
	f := newOIDCFixture(t)

	tokens := f.tokensFor(t, "openid email offline_access", "", "state-for-userinfo-refresh")
	refresh, ok := tokens["refresh_token"].(string)
	if !ok || refresh == "" {
		t.Fatalf("no refresh token to present: %v", tokens)
	}

	rec := f.withBearer(t, http.MethodGet, "/oauth2/userinfo", refresh)
	if rec.Code == http.StatusOK {
		t.Fatalf("userinfo accepted a refresh token as a bearer credential: %s", rec.Body.String())
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("userinfo with a refresh token = %d; want 401", rec.Code)
	}
}

// TestUserinfoRefusesAnUnusableToken covers the ordinary failures, and the challenge
// header a conforming client reads to decide what to do next.
func TestUserinfoRefusesAnUnusableToken(t *testing.T) {
	f := newOIDCFixture(t)

	for name, token := range map[string]string{
		"nonsense":  "not-a-token-at-all",
		"empty":     "",
		"truncated": "ory_at_" + strings.Repeat("A", 20),
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.withBearer(t, http.MethodGet, "/oauth2/userinfo", token)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("= %d, body %s", rec.Code, rec.Body.String())
			}
			if challenge := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(challenge, "Bearer") {
				t.Fatalf("WWW-Authenticate = %q; RFC 6750 §3 requires the challenge, and a "+
					"client reads it to decide whether to refresh or to give up", challenge)
			}
		})
	}
}

// --- introspection -------------------------------------------------------------------

// TestIntrospectionRequiresCredentials. Without client authentication the endpoint is a
// scanner: anybody holding a token could ask whether it is live, and anybody guessing
// could find out which guesses were right.
func TestIntrospectionRequiresCredentials(t *testing.T) {
	f := newOIDCFixture(t)
	token := f.accessToken(t, "openid", "", "state-for-introspect-unauth")

	rec := f.postForm(t, "/oauth2/introspect", url.Values{"token": {token}}, nil)
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), `"active":true`) {
		t.Fatalf("an unauthenticated caller was told about a token: %s", rec.Body.String())
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated introspection = %d, body %s", rec.Code, rec.Body.String())
	}
}

// TestIntrospectionAnswersTheAudience is the case the endpoint exists for: a resource
// server, holding its own credentials, asking about a token that names it.
func TestIntrospectionAnswersTheAudience(t *testing.T) {
	f := newOIDCFixture(t)
	token := f.accessToken(t, "openid profile", f.audience, "state-for-introspect-audience")

	body := f.introspect(t, token, f.resource.ID, f.resourceSecret)
	if body["active"] != true {
		t.Fatalf("the audience was told its own token is inactive: %v", body)
	}
	if body["sub"] != f.userID {
		t.Fatalf("sub = %v; want %s", body["sub"], f.userID)
	}
	if body["client_id"] != f.client.ID {
		t.Fatalf("client_id = %v; want the client the token was issued to (%s)",
			body["client_id"], f.client.ID)
	}
	if scope, isString := body["scope"].(string); !isString || !strings.Contains(scope, "openid") {
		t.Fatalf("scope = %v; a resource server authorizes on it", body["scope"])
	}
	if body["sid"] == nil {
		t.Fatal("no sid in the introspection response; it is what ties a token to the " +
			"session that issued it")
	}
}

// TestIntrospectionHidesATokenFromAStranger is the other half of the same rule. The same
// resource server, the same credentials — but a token that does not name it.
//
// RFC 7662 §2.2 says a token the caller is not allowed to know about is reported exactly
// like an expired one, so the answer carries no information about whether it exists.
func TestIntrospectionHidesATokenFromAStranger(t *testing.T) {
	f := newOIDCFixture(t)
	// No audience requested, so this token is for the client alone.
	token := f.accessToken(t, "openid profile", "", "state-for-introspect-stranger")

	body := f.introspect(t, token, f.resource.ID, f.resourceSecret)
	if body["active"] != false {
		t.Fatalf("a client was told about a token that neither belongs to it nor names "+
			"it: %v", body)
	}
	if len(body) != 1 {
		t.Fatalf("an inactive answer carried more than active=false: %v", body)
	}
}

// TestIntrospectionRefusesAWrongSecret. The credential has to be checked, not merely
// presented.
func TestIntrospectionRefusesAWrongSecret(t *testing.T) {
	f := newOIDCFixture(t)
	token := f.accessToken(t, "openid", f.audience, "state-for-introspect-secret")

	rec := f.postFormWithBasic(t, "/oauth2/introspect", url.Values{"token": {token}},
		f.resource.ID, "not-the-secret")
	if strings.Contains(rec.Body.String(), `"active":true`) {
		t.Fatalf("a wrong client secret was accepted: %s", rec.Body.String())
	}
}

// --- revocation ----------------------------------------------------------------------

// TestRevokingARefreshTokenKillsItWithoutRaisingAnAlarm is the distinction the
// revocation endpoint turns on.
//
// The tokens end up in the same state a detected replay would leave them in, and that is
// where the similarity stops. A client calling RFC 7009 is behaving correctly, so the
// record says oauth.refresh_token_revoked and nothing pages. Routing this through the
// reuse path would fire security.refresh_token_reuse on correct behaviour, and an alarm
// that fires on correct behaviour is one an operator learns to ignore.
func TestRevokingARefreshTokenKillsItWithoutRaisingAnAlarm(t *testing.T) {
	f := newOIDCFixture(t)

	tokens := f.tokensFor(t, "openid offline_access", "", "state-for-revoke-refresh")
	refresh, ok := tokens["refresh_token"].(string)
	if !ok || refresh == "" {
		t.Fatalf("no refresh token: %v", tokens)
	}

	rec := f.postForm(t, "/oauth2/revoke", url.Values{
		"token": {refresh}, "token_type_hint": {"refresh_token"},
		"client_id": {f.client.ID},
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("revocation = %d, body %s", rec.Code, rec.Body.String())
	}

	// The token is dead.
	again := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {f.client.ID},
	}, nil)
	if again.Code == http.StatusOK {
		t.Fatal("a revoked refresh token still works")
	}

	if alarms := f.securityEvents(t, "security.refresh_token_reuse"); len(alarms) != 0 {
		t.Fatalf("revoking a token raised %d reuse alarms; the client did nothing wrong, "+
			"and an alarm on correct behaviour is one nobody will act on", len(alarms))
	}
	if recorded := f.securityEvents(t, "oauth.refresh_token_revoked"); len(recorded) != 1 {
		t.Fatalf("the revocation was recorded %d times; it belongs in the audit log "+
			"exactly once", len(recorded))
	}
}

// TestRevokingATokenDoesNotSignTheUserOut. Revoking a grant is not signing out: the
// tokens die and the person stays signed in to the provider, which is what RFC 7009
// describes and what makes /oauth2/logout a separate endpoint.
func TestRevokingATokenDoesNotSignTheUserOut(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)

	code, cookies := f.signInAndGetCode(t, challenge, "state-for-revoke-session")
	verifier, _ := pkcePair(t)
	tokens := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})
	refresh, ok := tokens["refresh_token"].(string)
	if !ok || refresh == "" {
		t.Fatalf("no refresh token: %v", tokens)
	}

	if rec := f.postForm(t, "/oauth2/revoke", url.Values{
		"token": {refresh}, "client_id": {f.client.ID},
	}, nil); rec.Code != http.StatusOK {
		t.Fatalf("revocation = %d", rec.Code)
	}

	// The browser session still authorizes.
	rec := f.do(t, http.MethodGet,
		authorizeURL(f.client.ID, f.redirectURI, challenge, "state-after-the-revocation"),
		nil, cookies)
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	if location.Query().Get("code") == "" {
		t.Fatalf("revoking a token ended the browser session as well; it landed at %q "+
			"instead of the client with a fresh code", location)
	}
}

// TestRevokingAnUnknownTokenSucceeds. RFC 7009 §2.2 requires 200: the client's goal is
// already met, and answering differently would make the endpoint an oracle for which
// tokens exist.
func TestRevokingAnUnknownTokenSucceeds(t *testing.T) {
	f := newOIDCFixture(t)

	rec := f.postForm(t, "/oauth2/revoke", url.Values{
		"token": {"ory_rt_" + strings.Repeat("A", 30)}, "client_id": {f.client.ID},
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoking an unknown token = %d, body %s; RFC 7009 requires 200",
			rec.Code, rec.Body.String())
	}
}

// --- the client credentials grant ----------------------------------------------------

// TestTheClientCredentialsGrantIssuesAScopedToken covers the grant a resource server
// uses to speak for itself, and the one place Warden has to grant scopes itself: there
// is no person in this flow, so the registration is the decision.
func TestTheClientCredentialsGrantIssuesAScopedToken(t *testing.T) {
	f := newOIDCFixture(t)

	rec := f.postFormWithBasic(t, "/oauth2/token", url.Values{
		"grant_type": {"client_credentials"}, "scope": {"openid profile"},
	}, f.resource.ID, f.resourceSecret)
	if rec.Code != http.StatusOK {
		t.Fatalf("the client credentials grant = %d, body %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the response is not JSON: %s", rec.Body.String())
	}
	token, ok := body["access_token"].(string)
	if !ok || token == "" {
		t.Fatalf("no access token: %v", body)
	}
	if body["refresh_token"] != nil {
		t.Fatal("the client credentials grant issued a refresh token; there is no user to " +
			"stay signed in, and the client can simply ask again")
	}

	// The scopes really are on it: a token with none would be refused by every resource
	// server, which is what happens if the grant is composed and nothing grants.
	introspected := f.introspect(t, token, f.resource.ID, f.resourceSecret)
	if introspected["active"] != true {
		t.Fatalf("the token it just issued introspects as inactive: %v", introspected)
	}
	if scope, isString := introspected["scope"].(string); !isString || !strings.Contains(scope, "profile") {
		t.Fatalf("scope = %v; want the scopes the client asked for and is allowed",
			introspected["scope"])
	}

	// And it is not a user token: there is nobody to describe.
	if rec := f.withBearer(t, http.MethodGet, "/oauth2/userinfo", token); rec.Code == http.StatusOK {
		t.Fatalf("userinfo answered for a token with no user: %s", rec.Body.String())
	}
}

// --- helpers -------------------------------------------------------------------------

// authorizeURLFor is authorizeURL with the scope and audience spelled out.
func authorizeURLFor(clientID, redirectURI, challenge, state, scope, audience string) string {
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scope},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if audience != "" {
		form.Set("audience", audience)
	}
	return "/oauth2/authorize?" + form.Encode()
}

// tokensFor signs a user in and completes one exchange, returning the token response.
func (f *oidcFixture) tokensFor(t *testing.T, scope, audience, state string) map[string]any {
	t.Helper()
	verifier, challenge := pkcePair(t)
	authorize := authorizeURLFor(f.client.ID, f.redirectURI, challenge, state, scope, audience)

	rec := f.do(t, http.MethodGet, authorize, nil, nil)
	loginURL := rec.Header().Get("Location")
	page := f.do(t, http.MethodGet, loginURL, nil, nil)
	rec = f.postForm(t, "/login", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"return_to":  {f.returnToFrom(t, loginURL)},
		"email":      {f.email}, "password": {f.password},
	}, f.cookies(page))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("signing in = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = f.do(t, http.MethodGet, authorize, nil, f.cookies(rec))
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q (error=%q)", location, location.Query().Get("error"))
	}

	return f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})
}

func (f *oidcFixture) accessToken(t *testing.T, scope, audience, state string) string {
	t.Helper()
	tokens := f.tokensFor(t, scope, audience, state)
	token, ok := tokens["access_token"].(string)
	if !ok || token == "" {
		t.Fatalf("no access token: %v", tokens)
	}
	return token
}

// userinfo calls the endpoint and decodes a successful response.
func (f *oidcFixture) userinfo(t *testing.T, token string) map[string]any {
	t.Helper()
	rec := f.withBearer(t, http.MethodGet, "/oauth2/userinfo", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo = %d, body %s", rec.Code, rec.Body.String())
	}
	var claims map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &claims); err != nil {
		t.Fatalf("userinfo did not return JSON: %s", rec.Body.String())
	}
	return claims
}

// introspect asks about a token as a client authenticating with HTTP Basic.
func (f *oidcFixture) introspect(t *testing.T, token, clientID, secret string) map[string]any {
	t.Helper()
	rec := f.postFormWithBasic(t, "/oauth2/introspect", url.Values{"token": {token}}, clientID, secret)
	if rec.Code != http.StatusOK {
		t.Fatalf("introspection = %d, body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("introspection did not return JSON: %s", rec.Body.String())
	}
	return body
}

func (f *oidcFixture) withBearer(t *testing.T, method, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *oidcFixture) postFormWithBasic(
	t *testing.T, target string, form url.Values, clientID, secret string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(clientID)+":"+url.QueryEscape(secret))))
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}
