package httpapi_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The authorization code flow, end to end, through the real handlers.
//
// This is what M1-6's milestone exit means by "an application logs a user in and out
// using a stock off-the-shelf OIDC library, with no Warden-specific client code": every
// step below is one a library performs, in the order it performs it, with nothing but
// HTTP between the test and the server.

// pkcePair returns a verifier and its S256 challenge.
func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier = "a-code-verifier-long-enough-to-satisfy-rfc7636-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorizeURL builds the request a client would send the browser to.
//
// The state values in these tests are long deliberately: fosite enforces a minimum of
// eight characters on state and nonce, because RFC 6749 wants them unguessable. A
// shorter one is rejected at the authorization endpoint, and the symptom is an empty
// Location header several steps later rather than anything that names the cause.
func authorizeURL(clientID, redirectURI, challenge, state string) string {
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email offline_access"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return "/oauth2/authorize?" + form.Encode()
}

// TestTheAuthorizationCodeFlow walks the whole thing: an unauthenticated authorize
// request, the login page, the password, the redirect back, the code, and the exchange.
func TestTheAuthorizationCodeFlow(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)
	verifier, _ := pkcePair(t)

	// 1. The client sends the browser to the authorization endpoint. Nobody is signed
	//    in, so it is sent to the login page with somewhere to come back to.
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "client-state-value")
	rec := f.do(t, http.MethodGet, authorize, nil, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("authorize with no session = %d; want a redirect to the login page", rec.Code)
	}
	loginURL := rec.Header().Get("Location")
	if !strings.HasPrefix(loginURL, "/login?") {
		t.Fatalf("redirected to %q; want the login page", loginURL)
	}

	// 2. The login page. It carries a CSRF token and the return-to target.
	rec = f.do(t, http.MethodGet, loginURL, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("the login page = %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("the login page has no clickjacking defence: %q (SPEC §17)", got)
	}
	csrf := f.csrfFrom(t, rec)

	// 3. The password. A correct one produces a session cookie and sends the browser
	//    back to the authorization endpoint.
	form := url.Values{
		"csrf_token": {csrf},
		"return_to":  {f.returnToFrom(t, loginURL)},
		"email":      {f.email},
		"password":   {f.password},
	}
	rec = f.postForm(t, "/login", form, f.cookies(rec))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a correct password = %d, body %s", rec.Code, rec.Body.String())
	}
	sessionCookies := f.cookies(rec)
	if len(sessionCookies) == 0 {
		t.Fatal("signing in set no cookie")
	}

	// 4. Back to the authorization endpoint, now with a session. It redirects to the
	//    client with a code.
	rec = f.do(t, http.MethodGet, authorize, nil, sessionCookies)
	if rec.Code != http.StatusFound && rec.Code != http.StatusSeeOther {
		t.Fatalf("authorize with a session = %d, body %s", rec.Code, rec.Body.String())
	}
	redirected, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	if !strings.HasPrefix(redirected.String(), f.redirectURI) {
		t.Fatalf("redirected to %q; want the client's registered redirect_uri", redirected)
	}
	code := redirected.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code in %q (error=%q)",
			redirected, redirected.Query().Get("error"))
	}
	if state := redirected.Query().Get("state"); state != "client-state-value" {
		t.Fatalf("state came back as %q; a client uses it to match the response to its "+
			"request and will reject a mismatch", state)
	}

	// 5. The exchange. The verifier proves the client is the one that started the flow.
	tokens := f.exchange(t, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.redirectURI},
		"client_id":     {f.client.ID},
		"code_verifier": {verifier},
	})

	for _, claim := range []string{"access_token", "id_token", "refresh_token", "token_type"} {
		if tokens[claim] == nil {
			t.Fatalf("the token response has no %s: %v", claim, tokens)
		}
	}
	if tokens["token_type"] != "bearer" {
		t.Fatalf("token_type = %v", tokens["token_type"])
	}
}

// TestAnAuthorizationCodeCannotBeUsedTwice is the replay case. The second exchange must
// fail, and everything issued by the first must die with it.
func TestAnAuthorizationCodeCannotBeUsedTwice(t *testing.T) {
	f := newOIDCFixture(t)
	verifier, challenge := pkcePair(t)

	code, cookies := f.signInAndGetCode(t, challenge, "state-for-the-replay-case")
	_ = cookies

	first := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})
	if first["access_token"] == nil {
		t.Fatalf("the first exchange produced no token: %v", first)
	}

	rec := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	}, nil)
	if rec.Code == http.StatusOK {
		t.Fatal("an authorization code was exchanged twice; a code is single-use, and a " +
			"replay means somebody else has it")
	}
}

// TestTheWrongPKCEVerifierIsRefused is what PKCE is for: an attacker who intercepted the
// code did not see the verifier, so they cannot complete the exchange.
func TestTheWrongPKCEVerifierIsRefused(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)

	code, _ := f.signInAndGetCode(t, challenge, "state-for-the-verifier-case")

	rec := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {"a-completely-different-verifier-0123456789012345"},
	}, nil)
	if rec.Code == http.StatusOK {
		t.Fatal("the exchange succeeded with the wrong code_verifier; an intercepted code " +
			"would be enough on its own")
	}
}

// TestAnUnregisteredRedirectURIIsRefusedWithoutRedirecting. Redirecting an error to an
// unregistered URI is how an authorization endpoint becomes an open redirect (SPEC §17).
func TestAnUnregisteredRedirectURIIsRefusedWithoutRedirecting(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)

	rec := f.do(t, http.MethodGet,
		authorizeURL(f.client.ID, "https://attacker.test/collect", challenge, "state-for-the-redirect-case"), nil, nil)

	if location := rec.Header().Get("Location"); strings.Contains(location, "attacker.test") {
		t.Fatalf("the endpoint redirected to an unregistered URI (%q); that is an open "+
			"redirect, and the victim is mid-login", location)
	}
	if rec.Code == http.StatusOK {
		t.Fatal("an unregistered redirect_uri was accepted")
	}
}

// TestAnUnknownClientIsRefusedWithoutRedirecting is the same property one step earlier.
func TestAnUnknownClientIsRefusedWithoutRedirecting(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)

	rec := f.do(t, http.MethodGet,
		authorizeURL("oac_not_a_real_client", "https://attacker.test/collect", challenge, "state-for-this-case"), nil, nil)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown client_id = %d; want a direct refusal", rec.Code)
	}
	if location := rec.Header().Get("Location"); location != "" {
		t.Fatalf("an unknown client produced a redirect to %q", location)
	}
}

// TestTheRefreshTokenRotatesAndItsReuseKillsTheFamily joins M1-5 to the provider. This
// is the property that would have been lost had fosite been allowed to keep its own
// refresh tokens.
func TestTheRefreshTokenRotatesAndItsReuseKillsTheFamily(t *testing.T) {
	f := newOIDCFixture(t)
	verifier, challenge := pkcePair(t)

	code, _ := f.signInAndGetCode(t, challenge, "state-for-the-refresh-case")
	first := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})

	refresh, ok := first["refresh_token"].(string)
	if !ok || refresh == "" {
		t.Fatalf("no refresh token was issued: %v", first)
	}

	second := f.exchange(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {f.client.ID},
	})
	rotated, ok := second["refresh_token"].(string)
	if !ok || rotated == "" {
		t.Fatalf("the refresh did not return a new token: %v", second)
	}
	if rotated == refresh {
		t.Fatal("the refresh token did not rotate")
	}

	// Replaying the first token is the theft signal.
	rec := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {f.client.ID},
	}, nil)
	if rec.Code == http.StatusOK {
		t.Fatal("a consumed refresh token was accepted again")
	}

	// And the whole family is dead, including the token the legitimate client holds.
	rec = f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rotated},
		"client_id": {f.client.ID},
	}, nil)
	if rec.Code == http.StatusOK {
		t.Fatal("the live refresh token survived a detected replay; the family must die " +
			"as a unit or the thief keeps the chain (SPEC §8.3)")
	}
}

// TestOneTheftRaisesOneAlarm is a regression test with a live-run history.
//
// A replayed refresh token revokes its family, which leaves the *legitimate* client
// holding a token that is revoked but was never consumed. Reporting that as
// ErrInactiveToken sends fosite into its reuse handling a second time, and the incident
// is alarmed twice. The first live run of this flow produced exactly that: two
// security.refresh_token_reuse rows for one theft.
//
// The distinction is the one M1-5 already draws — consumed is evidence, revoked is
// collateral — and this asserts it survives the trip through fosite.
//
// Two changes defend it, and each is sufficient on its own: the storage returns
// ErrNotFound rather than ErrInactiveToken for a revoked-but-unconsumed token, so fosite
// does not enter reuse handling at all; and RevokeFamily marks a revocation that changed
// no rows as a repeat rather than an alarm. Reverting either alone leaves this test
// passing. Reverting both produces three alarms for one theft, which is what it is here
// to prevent.
func TestOneTheftRaisesOneAlarm(t *testing.T) {
	f := newOIDCFixture(t)
	verifier, challenge := pkcePair(t)

	code, _ := f.signInAndGetCode(t, challenge, "state-for-the-one-alarm-case")
	first := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})
	refresh, ok := first["refresh_token"].(string)
	if !ok || refresh == "" {
		t.Fatalf("no refresh token: %v", first)
	}

	second := f.exchange(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {f.client.ID},
	})
	rotated, ok := second["refresh_token"].(string)
	if !ok || rotated == "" {
		t.Fatalf("the refresh returned no successor: %v", second)
	}

	// The theft: the old token is replayed once.
	if rec := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {f.client.ID},
	}, nil); rec.Code == http.StatusOK {
		t.Fatal("a consumed refresh token was accepted")
	}

	// The legitimate client now retries with the token it holds, which the revocation
	// killed as collateral. Twice, as a client with a retry policy would.
	for i := 0; i < 2; i++ {
		if rec := f.postForm(t, "/oauth2/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {rotated},
			"client_id": {f.client.ID},
		}, nil); rec.Code == http.StatusOK {
			t.Fatal("a token from a revoked family was accepted")
		}
	}

	alarms := f.securityEvents(t, "security.refresh_token_reuse")
	if len(alarms) != 1 {
		t.Fatalf("one theft produced %d alarms; an alert keyed on this action would page "+
			"once per retry rather than once per incident", len(alarms))
	}
}

// TestTheIDTokenIsSignedByTheAdvertisedKey ties the flow back to M1-1: a relying party
// verifies with JWKS and nothing else.
func TestTheIDTokenIsSignedByTheAdvertisedKey(t *testing.T) {
	f := newOIDCFixture(t)
	verifier, challenge := pkcePair(t)

	code, _ := f.signInAndGetCode(t, challenge, "state-for-the-idtoken-case")
	tokens := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})

	idToken, ok := tokens["id_token"].(string)
	if !ok || idToken == "" {
		t.Fatalf("no id_token: %v", tokens)
	}

	claims := f.verifyAgainstJWKS(t, idToken)
	if claims["iss"] != f.issuer {
		t.Fatalf("iss = %v; want %s", claims["iss"], f.issuer)
	}
	if claims["sub"] != f.userID {
		t.Fatalf("sub = %v; want %s", claims["sub"], f.userID)
	}
	if claims["sid"] == nil || claims["sid"] == "" {
		t.Fatal("the id token carries no sid; SPEC §8.2 requires it, and back-channel " +
			"logout has nothing to target without it")
	}
	amr, isList := claims["amr"].([]any)
	if !isList || len(amr) == 0 || amr[0] != "pwd" {
		t.Fatalf("amr = %v; a relying party uses it to tell a password login from one "+
			"with a second factor", claims["amr"])
	}
}

// --- rate limiting (M1-3's HTTP half) ------------------------------------------------

// TestRepeatedWrongPasswordsAreRateLimited is the 429 with Retry-After that SPEC §17
// asks for.
func TestRepeatedWrongPasswordsAreRateLimited(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)

	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-for-the-ratelimit-case")
	rec := f.do(t, http.MethodGet, authorize, nil, nil)
	loginURL := rec.Header().Get("Location")
	returnTo := f.returnToFrom(t, loginURL)

	var limited bool
	for attempt := 1; attempt <= 12; attempt++ {
		page := f.do(t, http.MethodGet, loginURL, nil, nil)
		csrf := f.csrfFrom(t, page)

		rec = f.postForm(t, "/login", url.Values{
			"csrf_token": {csrf}, "return_to": {returnTo},
			"email": {f.email}, "password": {"definitely not the password"},
		}, f.cookies(page))

		if rec.Code == http.StatusTooManyRequests {
			limited = true
			if after := rec.Header().Get("Retry-After"); after == "" {
				t.Fatal("a 429 with no Retry-After leaves a client guessing when to try again")
			}
			break
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, body %s", attempt, rec.Code, rec.Body.String())
		}
	}
	if !limited {
		t.Fatal("twelve wrong passwords were never rate limited; online guessing is unbounded")
	}
}

// TestTheLoginPageDoesNotRevealWhetherAnAccountExists is the enumeration property at the
// surface a person sees.
func TestTheLoginPageDoesNotRevealWhetherAnAccountExists(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)

	rec := f.do(t, http.MethodGet, authorizeURL(f.client.ID, f.redirectURI, challenge, "state-for-this-case"), nil, nil)
	loginURL := rec.Header().Get("Location")
	returnTo := f.returnToFrom(t, loginURL)

	bodies := map[string]string{}
	for _, email := range []string{f.email, "nobody-at-all@acme.test"} {
		page := f.do(t, http.MethodGet, loginURL, nil, nil)
		csrf := f.csrfFrom(t, page)

		attempt := f.postForm(t, "/login", url.Values{
			"csrf_token": {csrf}, "return_to": {returnTo},
			"email": {email}, "password": {"the wrong password entirely"},
		}, f.cookies(page))

		if attempt.Code != http.StatusUnauthorized {
			t.Fatalf("a wrong password for %q = %d", email, attempt.Code)
		}
		// Two things legitimately differ between renders and neither is a signal: the
		// echoed address, and the CSRF token, which is fresh every time. Both are
		// normalised out so the comparison is of the parts that would actually leak.
		normalised := strings.ReplaceAll(attempt.Body.String(), email, "")
		bodies[email] = stripCSRFValue(normalised)
	}

	known, unknown := bodies[f.email], bodies["nobody-at-all@acme.test"]
	if known != unknown {
		t.Fatal("the page differs between a real account and an unknown one; the " +
			"difference is an account-existence oracle (SPEC §7.2)")
	}
}

// TestALoginWithoutACSRFTokenIsRefused covers SPEC §17's double-submit requirement.
func TestALoginWithoutACSRFTokenIsRefused(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)

	rec := f.do(t, http.MethodGet, authorizeURL(f.client.ID, f.redirectURI, challenge, "state-for-this-case"), nil, nil)
	loginURL := rec.Header().Get("Location")
	returnTo := f.returnToFrom(t, loginURL)
	page := f.do(t, http.MethodGet, loginURL, nil, nil)

	for name, form := range map[string]url.Values{
		"no token": {
			"return_to": {returnTo}, "email": {f.email}, "password": {f.password},
		},
		"wrong token": {
			"csrf_token": {"a-token-from-somewhere-else"},
			"return_to":  {returnTo}, "email": {f.email}, "password": {f.password},
		},
	} {
		t.Run(name, func(t *testing.T) {
			attempt := f.postForm(t, "/login", form, f.cookies(page))
			if attempt.Code == http.StatusSeeOther {
				t.Fatal("a cross-site form post signed the user in")
			}
			if cookie := attempt.Header().Get("Set-Cookie"); strings.Contains(cookie, "warden_session=") {
				t.Fatal("a request with no valid CSRF token set a session cookie")
			}
		})
	}
}

// TestTheLoginPageRefusesAnOffsiteReturnTo. A login page is the most valuable place to
// have an open redirect: the victim has just typed a password.
func TestTheLoginPageRefusesAnOffsiteReturnTo(t *testing.T) {
	f := newOIDCFixture(t)

	for name, target := range map[string]string{
		"absolute":          "https://attacker.test/collect",
		"protocol relative": "//attacker.test/collect",
		"backslash":         "/\\attacker.test",
		"another path":      "/v1/authz/check",
		"empty":             "",
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.do(t, http.MethodGet,
				"/login?return_to="+url.QueryEscape(target), nil, nil)
			if rec.Code == http.StatusOK {
				t.Fatalf("the login page accepted %q as a destination", target)
			}
		})
	}
}

// exchange posts to the token endpoint and decodes a successful response.
func (f *oidcFixture) exchange(t *testing.T, form url.Values) map[string]any {
	t.Helper()
	rec := f.postForm(t, "/oauth2/token", form, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("the token endpoint = %d, body %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the token response is not JSON: %s", rec.Body.String())
	}
	return body
}

// signInAndGetCode runs steps one to four and returns the authorization code.
func (f *oidcFixture) signInAndGetCode(t *testing.T, challenge, state string) (code string, cookies []*http.Cookie) {
	t.Helper()
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, state)

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
	cookies = f.cookies(rec)

	rec = f.do(t, http.MethodGet, authorize, nil, cookies)
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	code = location.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q (error=%q)", location, location.Query().Get("error"))
	}
	return code, cookies
}

// do issues a request with the given cookies.
func (f *oidcFixture) do(t *testing.T, method, target string, body *strings.Reader, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == nil {
		req = httptest.NewRequestWithContext(context.Background(), method, target, nil)
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, target, body)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *oidcFixture) postForm(t *testing.T, target string, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *oidcFixture) cookies(rec *httptest.ResponseRecorder) []*http.Cookie {
	return (&http.Response{Header: rec.Header()}).Cookies()
}

// csrfFrom pulls the token out of the rendered form.
func (f *oidcFixture) csrfFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	body := rec.Body.String()
	const marker = `name="csrf_token" value="`
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("the page carries no CSRF field: %s", truncateForTest(body))
	}
	start += len(marker)
	end := strings.Index(body[start:], `"`)
	if end < 0 {
		t.Fatal("the CSRF field is malformed")
	}
	return body[start : start+end]
}

func (f *oidcFixture) returnToFrom(t *testing.T, loginURL string) string {
	t.Helper()
	parsed, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("parsing %q: %v", loginURL, err)
	}
	return parsed.Query().Get("return_to")
}

// stripCSRFValue removes the per-render token so two pages can be compared.
func stripCSRFValue(body string) string {
	const marker = `name="csrf_token" value="`
	start := strings.Index(body, marker)
	if start < 0 {
		return body
	}
	rest := body[start+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return body
	}
	return body[:start+len(marker)] + body[start+len(marker)+end:]
}

func truncateForTest(s string) string {
	if len(s) <= 300 {
		return s
	}
	return s[:300] + "…"
}
