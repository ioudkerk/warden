package httpapi_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// RP-initiated logout (SPEC §7.7).
//
// The interesting assertions are not "the cookie is gone". They are that everything the
// session issued is gone with it, and that a third-party page cannot cause a logout.

// TestLogoutEndsEverythingTheSessionIssued is the property that makes signing out mean
// something.
//
// Nothing in fosite's storage consults a Warden session — a refresh token is valid
// because its own row says so — so a logout that only dropped the cookie would leave a
// thirty-day credential working, and the client holding it could sign the user straight
// back in. This walks the whole session's issue: the browser, the access token and the
// refresh token.
func TestLogoutEndsEverythingTheSessionIssued(t *testing.T) {
	f := newOIDCFixture(t)
	verifier, challenge := pkcePair(t)

	code, cookies := f.signInAndGetCode(t, challenge, "state-for-the-logout-case")
	tokens := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})
	idToken, _ := tokens["id_token"].(string)           //nolint:errcheck // checked together below
	accessToken, _ := tokens["access_token"].(string)   //nolint:errcheck // checked together below
	refreshToken, _ := tokens["refresh_token"].(string) //nolint:errcheck // checked together below
	if idToken == "" || accessToken == "" || refreshToken == "" {
		t.Fatalf("the exchange did not produce the three tokens: %v", tokens)
	}

	// The id token vouches for the request, so no confirmation is needed.
	logout := "/oauth2/logout?" + url.Values{
		"id_token_hint":            {idToken},
		"post_logout_redirect_uri": {f.postLogoutURI},
		"state":                    {"state-the-client-will-check"},
	}.Encode()

	rec := f.do(t, http.MethodGet, logout, nil, cookies)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout = %d, body %s", rec.Code, rec.Body.String())
	}
	destination, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	if !strings.HasPrefix(destination.String(), f.postLogoutURI) {
		t.Fatalf("logout redirected to %q; want the registered post_logout_redirect_uri",
			destination)
	}
	if destination.Query().Get("state") != "state-the-client-will-check" {
		t.Fatalf("state = %q; a client matches the response to its request with it",
			destination.Query().Get("state"))
	}

	// 1. The refresh token: the credential that outlives everything else.
	if again := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
		"client_id": {f.client.ID},
	}, nil); again.Code == http.StatusOK {
		t.Fatal("a refresh token survived the logout of the session that issued it; the " +
			"user signed out and the client can sign them back in")
	}

	// 2. The access token.
	if info := f.withBearer(t, http.MethodGet, "/oauth2/userinfo", accessToken); info.Code == http.StatusOK {
		t.Fatalf("an access token survived the logout: %s", info.Body.String())
	}

	// 3. The browser session.
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-after-the-logout")
	after := f.do(t, http.MethodGet, authorize, nil, cookies)
	if after.Code != http.StatusSeeOther || !strings.HasPrefix(after.Header().Get("Location"), "/login") {
		t.Fatalf("after signing out, an authorization request = %d to %q; want the login page",
			after.Code, after.Header().Get("Location"))
	}
}

// TestLogoutRefusesAnUnregisteredDestination. A logout endpoint that redirects anywhere
// is an open redirect reached with a session cookie attached.
func TestLogoutRefusesAnUnregisteredDestination(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)
	_, cookies := f.signInAndGetCode(t, challenge, "state-for-the-logout-redirect-case")

	rec := f.do(t, http.MethodGet, "/oauth2/logout?"+url.Values{
		"client_id":                {f.client.ID},
		"post_logout_redirect_uri": {"https://attacker.test/collect"},
	}.Encode(), nil, cookies)

	if location := rec.Header().Get("Location"); strings.Contains(location, "attacker.test") {
		t.Fatalf("logout redirected to an unregistered URI (%q)", location)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unregistered post_logout_redirect_uri = %d; want a direct refusal", rec.Code)
	}
}

// TestLogoutWithoutAHintAsksFirst is the cross-site request forgery defence.
//
// Any page on the internet can cause a GET to this endpoint — an <img> tag is enough — so
// acting on one unconditionally would let a third party sign people out of Warden. With
// no client vouching for the request, the endpoint asks, and the answer is a form post
// carrying a token that a cross-site page cannot read.
func TestLogoutWithoutAHintAsksFirst(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)
	_, cookies := f.signInAndGetCode(t, challenge, "state-for-the-logout-csrf-case")

	page := f.do(t, http.MethodGet, "/oauth2/logout", nil, cookies)
	if page.Code != http.StatusOK {
		t.Fatalf("an unvouched logout = %d; want the confirmation page", page.Code)
	}
	if !strings.Contains(page.Body.String(), "csrf_token") {
		t.Fatalf("the confirmation page carries no CSRF field: %s", truncateForTest(page.Body.String()))
	}

	// Still signed in: the GET changed nothing.
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-mid-confirmation")
	if still := f.do(t, http.MethodGet, authorize, nil, cookies); strings.HasPrefix(
		still.Header().Get("Location"), "/login") {
		t.Fatal("a GET to /oauth2/logout ended the session without asking; any third-party " +
			"page could then sign a user out")
	}

	// Confirming does end it.
	confirmed := f.postForm(t, "/oauth2/logout", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
	}, append(cookies, f.cookies(page)...))
	if confirmed.Code != http.StatusOK && confirmed.Code != http.StatusSeeOther {
		t.Fatalf("confirming the sign-out = %d, body %s", confirmed.Code, confirmed.Body.String())
	}
	after := f.do(t, http.MethodGet, authorize, nil, cookies)
	if !strings.HasPrefix(after.Header().Get("Location"), "/login") {
		t.Fatalf("after confirming, the session still authorizes (landed at %q)",
			after.Header().Get("Location"))
	}
}

// TestLogoutWithoutASessionSucceeds. Signing out when already signed out is what the
// caller asked for, so it is not an error — and answering differently would tell an
// unauthenticated caller whether a cookie names a live session.
func TestLogoutWithoutASessionSucceeds(t *testing.T) {
	f := newOIDCFixture(t)

	rec := f.do(t, http.MethodGet, "/oauth2/logout", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout with no session = %d, body %s", rec.Code, rec.Body.String())
	}
}

// TestLogoutRefusesAMismatchedClient. A hint for one client and a destination registered
// to another is how somebody would try to borrow an allowlist.
func TestLogoutRefusesAMismatchedClient(t *testing.T) {
	f := newOIDCFixture(t)
	verifier, challenge := pkcePair(t)

	code, cookies := f.signInAndGetCode(t, challenge, "state-for-the-logout-mismatch")
	tokens := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})
	idToken, ok := tokens["id_token"].(string)
	if !ok || idToken == "" {
		t.Fatalf("no id token: %v", tokens)
	}

	rec := f.do(t, http.MethodGet, "/oauth2/logout?"+url.Values{
		"id_token_hint": {idToken},
		"client_id":     {f.resource.ID},
	}.Encode(), nil, cookies)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a hint and a client_id naming different clients = %d; want a refusal", rec.Code)
	}
}

// TestLogoutIgnoresAForgedHint. The signature is what makes a hint worth acting on;
// without checking it, anyone could name any session.
func TestLogoutIgnoresAForgedHint(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)
	_, cookies := f.signInAndGetCode(t, challenge, "state-for-the-forged-hint")

	// A syntactically valid JWS with a signature over nothing this provider signed.
	forged := "eyJhbGciOiJIUzI1NiIsImtpZCI6Im1hZGUtdXAifQ." +
		"eyJpc3MiOiJodHRwOi8vd2FyZGVuLnRlc3QiLCJzaWQiOiJzZXNfd2hhdGV2ZXIifQ.c2lnbmF0dXJl"

	rec := f.do(t, http.MethodGet, "/oauth2/logout?"+url.Values{
		"id_token_hint": {forged},
	}.Encode(), nil, cookies)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "csrf_token") {
		t.Fatalf("a forged id_token_hint = %d without a confirmation page; an unverifiable "+
			"hint must not vouch for anything", rec.Code)
	}
}
