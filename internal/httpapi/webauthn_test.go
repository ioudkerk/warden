package httpapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/authn/authntest"
)

// WebAuthn through the login, with an authenticator that signs for real.
//
// internal/authn proves the verification is correct. This proves the wiring around it: that
// a key can be enrolled through the browser endpoints at all, that an assertion finishes the
// sign-in the password started, and — the one that matters — that the endpoints are not a
// way around the second factor rather than through it.

const fixtureRPID = "warden.test"

// TestASecurityKeyCompletesTheLoginItStarted walks both browser round trips.
func TestASecurityKeyCompletesTheLoginItStarted(t *testing.T) {
	f := newOIDCFixture(t)
	key := f.enrolSecurityKey(t)

	// The password step leaves the browser at the verification page, holding nothing
	// that authorizes anything.
	authorize, cookies := f.passwordStep(t, "state-for-the-webauthn-case")
	if authorized := f.do(t, http.MethodGet, authorize, nil, cookies); !strings.HasPrefix(
		authorized.Header().Get("Location"), "/login") {
		t.Fatal("a password alone authorized a request")
	}

	// The page offers the key, and carries the one script Warden serves.
	page := f.do(t, http.MethodGet, "/login/verify", nil, cookies)
	if !strings.Contains(page.Body.String(), `id="wa-signin"`) {
		t.Fatal("the verification page does not offer the security key this account has")
	}
	csp := page.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'sha256-") {
		t.Fatalf("the page carries a script and the policy does not name its hash: %q", csp)
	}
	// Only the script-src directive matters here. style-src carries 'unsafe-inline' for
	// the page's own CSS and always has; a substring search over the whole policy would
	// find that and call it a failure.
	if scripts := directive(csp, "script-src"); strings.Contains(scripts, "unsafe-inline") {
		t.Fatalf("script-src allows unsafe-inline (%q); the hash would then be decoration, "+
			"and an injected script would run", scripts)
	}

	csrf := f.csrfFrom(t, page)
	cookies = append(cookies, f.cookies(page)...)

	// Round trip one: the challenge.
	begin := f.webAuthnPost(t, "/login/verify/webauthn/begin", csrf, "", nil, cookies)
	if begin.Code != http.StatusOK {
		t.Fatalf("begin = %d, body %s", begin.Code, begin.Body.String())
	}
	var challenge struct {
		SessionID string          `json:"session_id"`
		Options   json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("the challenge is not JSON: %s", begin.Body.String())
	}

	// Round trip two: the assertion.
	assertion := key.Assert(t, authntest.ChallengeFrom(t, challenge.Options), f.issuer, fixtureRPID)
	finish := f.webAuthnPost(t, "/login/verify/webauthn/finish", csrf, challenge.SessionID, assertion, cookies)
	if finish.Code != http.StatusOK {
		t.Fatalf("finish = %d, body %s", finish.Code, finish.Body.String())
	}

	// The session exists now, and the authorization request goes through.
	sessionCookies := f.cookies(finish)
	authorized := f.do(t, http.MethodGet, authorize, nil, sessionCookies)
	location, err := url.Parse(authorized.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	if location.Query().Get("code") == "" {
		t.Fatalf("after a security key the authorization request landed at %q", location)
	}
}

// TestTheSecurityKeyReachesTheToken. `amr` is what a role's requires_mfa constraint is
// evaluated against, so a factor that did not reach the token is a factor no decision can
// see.
func TestTheSecurityKeyReachesTheToken(t *testing.T) {
	f := newOIDCFixture(t)
	key := f.enrolSecurityKey(t)

	verifier, challenge := pkcePair(t)
	code, _ := f.signInWithSecurityKey(t, key, challenge, "state-for-the-webauthn-amr")
	tokens := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})

	idToken, ok := tokens["id_token"].(string)
	if !ok {
		t.Fatalf("no id token: %v", tokens)
	}
	amr := stringsOf(f.verifyAgainstJWKS(t, idToken)["amr"])
	for _, want := range []string{authn.AMRPassword, authn.AMRWebAuthn, authn.AMRMFA} {
		if !contains(amr, want) {
			t.Errorf("amr = %v, missing %q", amr, want)
		}
	}
}

// TestTheWebAuthnEndpointsRequireTheCSRFToken.
//
// A cross-origin request cannot set the custom header these endpoints need without a
// preflight, and the preflight fails because Warden sends no CORS headers — so they are
// already out of reach of a forged request. This is the second lock, and it is the one that
// still holds if a future change ever adds a permissive CORS policy for something else.
func TestTheWebAuthnEndpointsRequireTheCSRFToken(t *testing.T) {
	f := newOIDCFixture(t)
	f.enrolSecurityKey(t)
	_, cookies := f.passwordStep(t, "state-for-the-webauthn-csrf")
	page := f.do(t, http.MethodGet, "/login/verify", nil, cookies)
	cookies = append(cookies, f.cookies(page)...)

	for name, token := range map[string]string{
		"absent": "",
		"wrong":  "a-token-from-somewhere-else",
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.webAuthnPost(t, "/login/verify/webauthn/begin", token, "", nil, cookies)
			if rec.Code == http.StatusOK {
				t.Fatalf("a request with %s CSRF token was served: %s", name, rec.Body.String())
			}
		})
	}
}

// TestAnAssertionWithoutThePasswordIsRefused is the property the whole two-step design
// exists for, at the endpoint a script talks to rather than at the form.
func TestAnAssertionWithoutThePasswordIsRefused(t *testing.T) {
	f := newOIDCFixture(t)
	f.enrolSecurityKey(t)

	// No password step: no pending login, so no cookie naming one.
	rec := f.webAuthnPost(t, "/login/verify/webauthn/begin", "any-token", "", nil, nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("a challenge was issued to somebody who has not passed a password: %s",
			rec.Body.String())
	}
}

// TestRegisteringAKeyNeedsASession. The enrolment endpoints change what it takes to sign in
// to an account, which makes them exactly the endpoints an attacker holding a stolen browser
// would reach for first.
func TestRegisteringAKeyNeedsASession(t *testing.T) {
	f := newOIDCFixture(t)

	rec := f.webAuthnPost(t, "/account/security/webauthn/begin", "any-token", "", nil, nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("an unauthenticated caller was issued a registration challenge: %s",
			rec.Body.String())
	}
}

// --- helpers -------------------------------------------------------------------------

// directive returns one directive of a content security policy.
func directive(policy, name string) string {
	for _, part := range strings.Split(policy, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, name+" ") {
			return part
		}
	}
	return ""
}

// csrfFromScriptPage reads the token out of a page whose form is driven by script: the
// value is in a hidden input the script reads, not in a form field a browser would post.
func csrfFromScriptPage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	body := rec.Body.String()
	const marker = `id="wa-csrf" value="`
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("the page carries no wa-csrf field: %s", truncateForTest(body))
	}
	start += len(marker)
	end := strings.Index(body[start:], `"`)
	return body[start : start+end]
}

// webAuthnPost is a scripted request: the CSRF token and the challenge identifier travel in
// headers, because the body is the browser's own credential serialisation.
func (f *oidcFixture) webAuthnPost(
	t *testing.T, target, csrf, sessionID string, body []byte, cookies []*http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target,
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-Warden-Csrf", csrf)
	}
	if sessionID != "" {
		req.Header.Set("X-Warden-WebAuthn-Session", sessionID)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// enrolSecurityKey registers a virtual key through the browser endpoints.
//
// Through the endpoints rather than through the store, because the enrolment path is part of
// what M1-8 has to deliver: a key that can only be registered by a test helper is a key
// nobody can register.
func (f *oidcFixture) enrolSecurityKey(t *testing.T) *authntest.Authenticator {
	t.Helper()
	key := authntest.New(t)

	// A signed-in session to enrol from. The account has no second factor yet, so the
	// password alone still completes a login.
	_, challenge := pkcePair(t)
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-to-enrol-a-key")
	rec := f.do(t, http.MethodGet, authorize, nil, nil)
	loginURL := rec.Header().Get("Location")
	page := f.do(t, http.MethodGet, loginURL, nil, nil)
	signedIn := f.postForm(t, "/login", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"return_to":  {f.returnToFrom(t, loginURL)},
		"email":      {f.email}, "password": {f.password},
	}, f.cookies(page))
	if signedIn.Code != http.StatusSeeOther {
		t.Fatalf("signing in to enrol = %d, body %s", signedIn.Code, signedIn.Body.String())
	}
	cookies := f.cookies(signedIn)

	account := f.do(t, http.MethodGet, "/account/security", nil, cookies)
	if account.Code != http.StatusOK {
		t.Fatalf("the security page = %d, body %s", account.Code, account.Body.String())
	}
	csrf := csrfFromScriptPage(t, account)
	cookies = append(cookies, f.cookies(account)...)

	begin := f.webAuthnPost(t, "/account/security/webauthn/begin", csrf, "", nil, cookies)
	if begin.Code != http.StatusOK {
		t.Fatalf("registration begin = %d, body %s", begin.Code, begin.Body.String())
	}
	var creation struct {
		SessionID string          `json:"session_id"`
		Options   json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &creation); err != nil {
		t.Fatalf("not JSON: %s", begin.Body.String())
	}

	attestation := key.Register(t, authntest.ChallengeFrom(t, creation.Options), f.issuer, fixtureRPID)
	finish := f.webAuthnPost(t, "/account/security/webauthn/finish?label=Test+key",
		csrf, creation.SessionID, attestation, cookies)
	if finish.Code != http.StatusOK {
		t.Fatalf("registration finish = %d, body %s", finish.Code, finish.Body.String())
	}
	return key
}

// signInWithSecurityKey runs both steps and returns an authorization code.
func (f *oidcFixture) signInWithSecurityKey(
	t *testing.T, key *authntest.Authenticator, challenge, state string,
) (code string, cookies []*http.Cookie) {
	t.Helper()
	authorize, pending := f.passwordStep(t, state)
	_ = authorize

	page := f.do(t, http.MethodGet, "/login/verify", nil, pending)
	csrf := f.csrfFrom(t, page)
	pending = append(pending, f.cookies(page)...)

	begin := f.webAuthnPost(t, "/login/verify/webauthn/begin", csrf, "", nil, pending)
	var issued struct {
		SessionID string          `json:"session_id"`
		Options   json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal(begin.Body.Bytes(), &issued); err != nil {
		t.Fatalf("not JSON: %s", begin.Body.String())
	}

	assertion := key.Assert(t, authntest.ChallengeFrom(t, issued.Options), f.issuer, fixtureRPID)
	finish := f.webAuthnPost(t, "/login/verify/webauthn/finish", csrf, issued.SessionID, assertion, pending)
	if finish.Code != http.StatusOK {
		t.Fatalf("the assertion = %d, body %s", finish.Code, finish.Body.String())
	}
	cookies = f.cookies(finish)

	target := authorizeURL(f.client.ID, f.redirectURI, challenge, state+"-after")
	authorized := f.do(t, http.MethodGet, target, nil, cookies)
	location, err := url.Parse(authorized.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	code = location.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code after a security key: %q", location)
	}
	return code, cookies
}

// TestTheServedScriptMatchesTheHashInThePolicy is a silent-failure test.
//
// The hash is computed from the constant; the page renders that constant through a template.
// If the two ever differ — an added escape, a changed newline, a template helper that
// rewrites the body — the browser refuses to run the script and WebAuthn simply stops
// working, with no error anywhere on the server and every unit test still passing. The only
// place it shows is a browser console.
func TestTheServedScriptMatchesTheHashInThePolicy(t *testing.T) {
	f := newOIDCFixture(t)
	f.enrolSecurityKey(t)
	_, cookies := f.passwordStep(t, "state-for-the-csp-hash")

	page := f.do(t, http.MethodGet, "/login/verify", nil, cookies)
	declared := directive(page.Header().Get("Content-Security-Policy"), "script-src")
	if declared == "" {
		t.Fatal("the page carries a script and the policy has no script-src")
	}

	body := page.Body.String()
	start := strings.Index(body, "<script>")
	end := strings.Index(body, "</script>")
	if start < 0 || end < 0 {
		t.Fatal("the page carries no script")
	}
	served := body[start+len("<script>") : end]

	sum := sha256.Sum256([]byte(served))
	actual := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(declared, actual) {
		t.Fatalf("the policy names %s but the page serves a script hashing to %s; a browser "+
			"would refuse to run it and security keys would stop working with no error "+
			"anywhere on the server", declared, actual)
	}
}
