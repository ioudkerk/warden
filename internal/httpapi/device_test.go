package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// The device authorization grant (RFC 8628, SPEC §7.7).
//
// Two parties who never meet: a device with a screen and no browser, and a person with a
// browser somewhere else. Everything below is written from one side or the other, because
// that separation is the grant — a test that reached across it would be testing something
// no real device can do.

// TestTheDeviceFlow walks it end to end, in the order a television and its owner do.
func TestTheDeviceFlow(t *testing.T) {
	f := newOIDCFixture(t)

	// 1. The device asks. It has no browser, so this is a plain form post.
	start := f.startDevice(t, "openid profile email offline_access")
	if start.UserCode == "" || start.DeviceCode == "" {
		t.Fatalf("the device endpoint returned no codes: %+v", start)
	}
	if !strings.Contains(start.UserCode, "-") || len(start.UserCode) != 9 {
		t.Fatalf("user_code = %q; it is read off a screen and typed, so it is grouped "+
			"XXXX-XXXX", start.UserCode)
	}
	if start.Interval <= 0 || start.ExpiresIn <= 0 {
		t.Fatalf("the device was told neither how often to poll nor how long it has: %+v", start)
	}
	if !strings.HasSuffix(start.VerificationURI, "/device") {
		t.Fatalf("verification_uri = %q; it is typed by hand, so it is short and at the root",
			start.VerificationURI)
	}
	if !strings.Contains(start.VerificationURIComplete, "user_code=") {
		t.Fatalf("verification_uri_complete = %q; it carries the code so a QR scan needs "+
			"no typing", start.VerificationURIComplete)
	}

	// 2. The device polls. Nobody has answered, so it is told to keep waiting — and
	//    polling again immediately is told to wait longer, which is the only way a
	//    provider has to slow a device down.
	if code, _ := f.pollDevice(t, start.DeviceCode, f.device.ID); code != "authorization_pending" {
		t.Fatalf("the first poll = %q; want authorization_pending", code)
	}
	if code, _ := f.pollDevice(t, start.DeviceCode, f.device.ID); code != "slow_down" {
		t.Fatalf("polling again within the interval = %q; want slow_down (RFC 8628 §3.5)", code)
	}

	// 3. The person. Not signed in yet, so the page sends them to log in first.
	page := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, nil)
	if page.Code != http.StatusSeeOther {
		t.Fatalf("the verification page with no session = %d; approving a device is an act "+
			"performed as somebody", page.Code)
	}
	cookies := f.signIn(t, page.Header().Get("Location"))

	page = f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, cookies)
	if page.Code != http.StatusOK {
		t.Fatalf("the verification page = %d, body %s", page.Code, page.Body.String())
	}
	if !strings.Contains(page.Body.String(), f.device.Name) {
		t.Fatalf("the page does not say what is asking for access: %s",
			truncateForTest(page.Body.String()))
	}
	if !strings.Contains(page.Body.String(), "profile") {
		t.Fatalf("the page does not list the scopes being approved: %s",
			truncateForTest(page.Body.String()))
	}

	// 4. They approve.
	approved := f.postForm(t, "/device", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"user_code":  {start.UserCode},
		"decision":   {"approve"},
	}, append(cookies, f.cookies(page)...))
	if approved.Code != http.StatusOK {
		t.Fatalf("approving = %d, body %s", approved.Code, approved.Body.String())
	}

	// 5. The device's next poll gets tokens.
	tokens := f.pollDeviceForTokens(t, start.DeviceCode, f.device.ID)
	for _, claim := range []string{"access_token", "id_token", "refresh_token", "token_type"} {
		if tokens[claim] == nil {
			t.Fatalf("the device received no %s: %v", claim, tokens)
		}
	}

	// The id token says who approved it, and which session they approved it in — which
	// is what makes a later logout reach the television.
	idToken, ok := tokens["id_token"].(string)
	if !ok {
		t.Fatalf("id_token is not a string: %v", tokens["id_token"])
	}
	claims := f.verifyAgainstJWKS(t, idToken)
	if claims["sub"] != f.userID {
		t.Fatalf("sub = %v; want the person who approved it (%s)", claims["sub"], f.userID)
	}
	if claims["sid"] == nil || claims["sid"] == "" {
		t.Fatal("the device's id token carries no sid; nothing could revoke its tokens by session")
	}
	if claims["aud"] == nil {
		t.Fatalf("no audience: %v", claims)
	}

	// 6. And the code is spent.
	if code, _ := f.pollDevice(t, start.DeviceCode, f.device.ID); code != "invalid_grant" {
		t.Fatalf("a redeemed device code polled again = %q; a device code is single use", code)
	}
}

// TestDecliningADeviceIsNotTheSameAsIgnoringIt. "No" and "not yet" are different answers,
// and a device that cannot tell them apart polls until it expires.
func TestDecliningADeviceIsNotTheSameAsIgnoringIt(t *testing.T) {
	f := newOIDCFixture(t)
	start := f.startDevice(t, "openid")

	page := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, nil)
	cookies := f.signIn(t, page.Header().Get("Location"))
	page = f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, cookies)

	declined := f.postForm(t, "/device", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"user_code":  {start.UserCode},
		"decision":   {"decline"},
	}, append(cookies, f.cookies(page)...))
	if declined.Code != http.StatusOK {
		t.Fatalf("declining = %d, body %s", declined.Code, declined.Body.String())
	}

	if code, _ := f.pollDevice(t, start.DeviceCode, f.device.ID); code != "access_denied" {
		t.Fatalf("polling after a refusal = %q; want access_denied, so the device stops "+
			"asking rather than waiting out the clock", code)
	}
}

// TestADeviceCodeBelongsToOneClient. Without this, a device code intercepted on the wire
// — it is printed on a screen in a hotel lobby, after all — could be redeemed by any
// client that happened to see it.
func TestADeviceCodeBelongsToOneClient(t *testing.T) {
	f := newOIDCFixture(t)
	start := f.startDevice(t, "openid")

	page := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, nil)
	cookies := f.signIn(t, page.Header().Get("Location"))
	page = f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, cookies)
	f.postForm(t, "/device", url.Values{
		"csrf_token": {f.csrfFrom(t, page)}, "user_code": {start.UserCode}, "decision": {"approve"},
	}, append(cookies, f.cookies(page)...))

	// The other client holds the device grant too, and its own credentials, and still
	// gets nothing: the code is not its.
	rec := f.postFormWithBasic(t, "/oauth2/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {start.DeviceCode},
	}, f.resource.ID, f.resourceSecret)
	if rec.Code == http.StatusOK {
		t.Fatalf("another client redeemed a device code that was not issued to it: %s",
			rec.Body.String())
	}
	if code := errorCodeOf(t, rec); code != "invalid_grant" {
		t.Fatalf("= %q; an approved code belonging to somebody else must look exactly like "+
			"an unknown one", code)
	}

	// And the rightful client still gets its tokens: the refusal above changed nothing.
	tokens := f.pollDeviceForTokens(t, start.DeviceCode, f.device.ID)
	if tokens["access_token"] == nil {
		t.Fatalf("the device that owns the code got nothing: %v", tokens)
	}
}

// TestSigningOutStopsAnApprovedDevice.
//
// A device approved and never polled again is a live authorization sitting in a table. If
// the person signs out before the device collects its tokens, the approval has to go with
// the session — otherwise "sign out everywhere" quietly means "everywhere except the
// television in the other room".
func TestSigningOutStopsAnApprovedDevice(t *testing.T) {
	f := newOIDCFixture(t)
	start := f.startDevice(t, "openid")

	page := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, nil)
	cookies := f.signIn(t, page.Header().Get("Location"))
	page = f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, cookies)
	f.postForm(t, "/device", url.Values{
		"csrf_token": {f.csrfFrom(t, page)}, "user_code": {start.UserCode}, "decision": {"approve"},
	}, append(cookies, f.cookies(page)...))

	// Sign out before the device polls.
	logout := f.postForm(t, "/oauth2/logout", url.Values{
		"csrf_token": {f.csrfFrom(t, f.do(t, http.MethodGet, "/oauth2/logout", nil, cookies))},
	}, cookies)
	if logout.Code != http.StatusOK && logout.Code != http.StatusSeeOther {
		// The confirmation page's CSRF cookie is set on the GET above; re-fetch and post.
		confirm := f.do(t, http.MethodGet, "/oauth2/logout", nil, cookies)
		logout = f.postForm(t, "/oauth2/logout", url.Values{
			"csrf_token": {f.csrfFrom(t, confirm)},
		}, append(cookies, f.cookies(confirm)...))
		if logout.Code != http.StatusOK && logout.Code != http.StatusSeeOther {
			t.Fatalf("signing out = %d, body %s", logout.Code, logout.Body.String())
		}
	}

	if code, body := f.pollDevice(t, start.DeviceCode, f.device.ID); code == "" {
		t.Fatalf("a device approved in a session that has since ended still collected its "+
			"tokens: %s", body)
	} else if code != "invalid_grant" {
		t.Fatalf("polling after the approver signed out = %q; want invalid_grant", code)
	}
}

// TestGuessingUserCodesIsRateLimited. A user code is eight characters from a twenty-letter
// alphabet — about thirty-four bits, which is plenty against a person and nothing against
// a script. RFC 8628 §5.1 requires the limit; this is it.
func TestGuessingUserCodesIsRateLimited(t *testing.T) {
	f := newOIDCFixture(t)

	// A real flow, only so there is a code to sign in with: the login page needs a tenant,
	// and before a code is typed nothing says which tenant the person belongs to.
	start := f.startDevice(t, "openid")
	page := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, nil)
	cookies := f.signIn(t, page.Header().Get("Location"))

	// One page load for a token, then a script's worth of guesses with it. This is the
	// attack: a signed-in person, or anybody who can sign in, working through the code
	// space looking for somebody else's pending device.
	form := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, cookies)
	csrf := f.csrfFrom(t, form)
	cookies = append(cookies, f.cookies(form)...)

	var limited bool
	for attempt := 1; attempt <= 12; attempt++ {
		rec := f.postForm(t, "/device", url.Values{
			"csrf_token": {csrf},
			"user_code":  {"BCDF-GHJK"},
			"decision":   {"approve"},
		}, cookies)

		if rec.Code == http.StatusTooManyRequests {
			limited = true
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("a 429 with no Retry-After leaves a client guessing when to try again")
			}
			break
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d = %d, body %s", attempt, rec.Code, rec.Body.String())
		}
	}
	if !limited {
		t.Fatal("twelve wrong user codes were never rate limited; a short code with no " +
			"limit on guesses is a code anybody can have")
	}
}

// TestADeviceCodeIsRefusedForAClientThatMayNotUseTheGrant. The registration is what says
// which grants a client may use, and the device endpoint is not an exception to it.
func TestADeviceCodeIsRefusedForAClientThatMayNotUseTheGrant(t *testing.T) {
	f := newOIDCFixture(t)

	rec := f.postForm(t, "/oauth2/device", url.Values{
		"client_id": {f.client.ID}, "scope": {"openid"},
	}, nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("a client registered without the device grant started a device flow: %s",
			rec.Body.String())
	}
}

// --- helpers -------------------------------------------------------------------------

type deviceStart struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// startDevice is what the device does first.
func (f *oidcFixture) startDevice(t *testing.T, scope string) deviceStart {
	t.Helper()
	rec := f.postForm(t, "/oauth2/device", url.Values{
		"client_id": {f.device.ID}, "scope": {scope},
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("the device authorization endpoint = %d, body %s", rec.Code, rec.Body.String())
	}
	var start deviceStart
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("the device response is not JSON: %s", rec.Body.String())
	}
	return start
}

// pollDevice polls once and returns the OAuth error code, empty if it succeeded.
func (f *oidcFixture) pollDevice(t *testing.T, deviceCode, clientID string) (string, string) {
	t.Helper()
	rec := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode}, "client_id": {clientID},
	}, nil)
	if rec.Code == http.StatusOK {
		return "", rec.Body.String()
	}
	return errorCodeOf(t, rec), rec.Body.String()
}

// pollDeviceForTokens polls once and expects to be handed tokens.
func (f *oidcFixture) pollDeviceForTokens(t *testing.T, deviceCode, clientID string) map[string]any {
	t.Helper()
	return f.exchange(t, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode}, "client_id": {clientID},
	})
}

// signIn follows a redirect to the login page and returns the session cookies.
func (f *oidcFixture) signIn(t *testing.T, loginURL string) []*http.Cookie {
	t.Helper()
	if loginURL == "" {
		t.Fatal("no login URL to follow")
	}
	page := f.do(t, http.MethodGet, loginURL, nil, nil)
	if page.Code != http.StatusOK {
		t.Fatalf("the login page = %d, body %s", page.Code, page.Body.String())
	}
	rec := f.postForm(t, "/login", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"return_to":  {f.returnToFrom(t, loginURL)},
		"email":      {f.email}, "password": {f.password},
	}, f.cookies(page))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("signing in = %d, body %s", rec.Code, rec.Body.String())
	}
	return f.cookies(rec)
}

// errorCodeOf reads the `error` field of an OAuth error response.
func errorCodeOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("the error response is not JSON: %s", rec.Body.String())
	}
	return body.Error
}

// TestTwoSimultaneousPollsIssueOneSetOfTokens is what the single-use rule is actually
// for, and the only case that exercises it.
//
// A sequential replay is caught earlier, by the status the row already carries. The race
// is not: two polls can both read "approved" before either writes, and without the
// condition on the UPDATE both would issue tokens from one approval. The loser is the
// poll that changes no rows.
func TestTwoSimultaneousPollsIssueOneSetOfTokens(t *testing.T) {
	f := newOIDCFixture(t)
	start := f.startDevice(t, "openid")

	page := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, nil)
	cookies := f.signIn(t, page.Header().Get("Location"))
	page = f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, cookies)
	f.postForm(t, "/device", url.Values{
		"csrf_token": {f.csrfFrom(t, page)}, "user_code": {start.UserCode}, "decision": {"approve"},
	}, append(cookies, f.cookies(page)...))

	// Released together, because the window this defends is the one between reading
	// "approved" and writing "redeemed". Starting the goroutines in a loop would let the
	// first finish before the last began, and the test would pass without ever reaching
	// the code it is about.
	const polls = 8
	var (
		wg      sync.WaitGroup
		release = make(chan struct{})
	)
	codes := make([]int, polls)
	for i := range polls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			rec := f.postForm(t, "/oauth2/token", url.Values{
				"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
				"device_code": {start.DeviceCode}, "client_id": {f.device.ID},
			}, nil)
			codes[i] = rec.Code
		}()
	}
	close(release)
	wg.Wait()

	issued := 0
	for _, code := range codes {
		if code == http.StatusOK {
			issued++
		}
	}
	if issued != 1 {
		t.Fatalf("%d of %d simultaneous polls were issued tokens; one approval must produce "+
			"one set", issued, polls)
	}
}

// TestADeviceIsNotGivenARefreshTokenItCannotUse was found on a live run.
//
// A client registered for the device grant alone asked for offline_access and was handed a
// refresh token — which fosite's refresh handler then refuses, because the client does not
// hold the refresh grant. The credential was useless and the failure was invisible until a
// device developer built a refresh loop around it.
func TestADeviceIsNotGivenARefreshTokenItCannotUse(t *testing.T) {
	f := newOIDCFixture(t)

	rec := f.postForm(t, "/oauth2/device", url.Values{
		"client_id": {f.deviceOnly.ID}, "scope": {"openid offline_access"},
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("the device endpoint = %d, body %s", rec.Code, rec.Body.String())
	}
	var start deviceStart
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("not JSON: %s", rec.Body.String())
	}

	page := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, nil)
	cookies := f.signIn(t, page.Header().Get("Location"))
	page = f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, cookies)
	f.postForm(t, "/device", url.Values{
		"csrf_token": {f.csrfFrom(t, page)}, "user_code": {start.UserCode}, "decision": {"approve"},
	}, append(cookies, f.cookies(page)...))

	tokens := f.exchange(t, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {start.DeviceCode}, "client_id": {f.deviceOnly.ID},
	})
	if tokens["access_token"] == nil {
		t.Fatalf("no access token: %v", tokens)
	}
	if tokens["refresh_token"] != nil {
		t.Fatal("a client that may not use the refresh grant was issued a refresh token; " +
			"it would answer unauthorized_client for ever")
	}
}
