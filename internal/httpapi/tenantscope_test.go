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

// One request, two credentials, two readers.
//
// Every endpoint that authenticates a client has to answer two questions about the same
// HTTP request: which tenant is this, and which client is this. Warden answers the first
// at the edge, because the storage needs a scope before fosite runs; fosite answers the
// second, from whichever credential it prefers. These tests exist because the two once
// disagreed — fosite takes HTTP Basic over the form body, and Warden took the form body
// over Basic — and a request carrying both was scoped to one tenant while authenticating
// as a client of another.
//
// The consequences were not theoretical. Each test below is an attack that worked.

// authenticatedAs sends a request whose Basic credentials and form client_id deliberately
// name different clients.
func authenticatedAs(
	t *testing.T, f *oidcFixture, path string, form url.Values, basicID, basicSecret string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(url.QueryEscape(basicID)+":"+url.QueryEscape(basicSecret))))
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// TestADeviceFlowCannotBeStartedInAnotherTenant is the worst of them.
//
// A confidential client of one tenant starts a device flow whose row lands in another
// tenant's scope. A user of *that* tenant then sees the code, is shown the rival client's
// name, approves — and the rival collects an id token for somebody who is not its user.
// The whole design exists to make that impossible, and for a while it was not.
func TestADeviceFlowCannotBeStartedInAnotherTenant(t *testing.T) {
	f := newOIDCFixture(t)

	rec := authenticatedAs(t, f, "/oauth2/device", url.Values{
		"client_id": {f.device.ID}, // the scope Warden would read
		"scope":     {"openid profile"},
	}, f.rival.ID, f.rivalSecret) // the client fosite would authenticate

	// Starting a flow is not itself the failure: the rival is a real client with the
	// device grant, and a device flow of its own is its business. What must not happen is
	// that the flow lands in *this* tenant, where this tenant's users would be offered it.
	if rec.Code != http.StatusOK {
		t.Logf("the request was refused outright (%d), which is also fine", rec.Code)
		return
	}
	var start deviceStart
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("not JSON: %s", rec.Body.String())
	}

	// A user of this tenant, signed in through a device flow that really is this
	// tenant's. Signing in by way of the rival's code does not work either — the code
	// resolves to the rival's tenant, so this tenant's password is checked against a
	// tenant the user does not belong to and fails — but that is the boundary holding one
	// step earlier, and this test is about the step after it.
	cookies, ownCode := f.signInThroughADeviceOfThisTenant(t)

	page := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, cookies)
	if strings.Contains(page.Body.String(), f.rival.Name) {
		t.Fatalf("a user of this tenant was offered another tenant's device: %s",
			truncateForTest(page.Body.String()))
	}

	// Posted anyway, with a token from a page that does have one — this tenant's own
	// consent page — which is what an attacker would do rather than giving up because the
	// form was not rendered for them.
	consent := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(ownCode), nil, cookies)
	approved := f.postForm(t, "/device", url.Values{
		"csrf_token": {f.csrfFrom(t, consent)},
		"user_code":  {start.UserCode}, "decision": {"approve"},
	}, append(cookies, f.cookies(consent)...))
	if strings.Contains(approved.Body.String(), "Approved") {
		t.Fatal("a user of this tenant approved another tenant's device")
	}

	// And nothing comes of polling it, whichever client asks.
	if code, body := f.pollDevice(t, start.DeviceCode, f.device.ID); code == "" {
		t.Fatalf("tokens were issued for a cross-tenant device flow: %s", body)
	}
}

// signInThroughADeviceOfThisTenant gets a session in the fixture's own tenant, for a test
// whose own device code deliberately belongs to another.
func (f *oidcFixture) signInThroughADeviceOfThisTenant(t *testing.T) (cookies []*http.Cookie, userCode string) {
	t.Helper()
	mine := f.startDevice(t, "openid")
	page := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(mine.UserCode), nil, nil)
	if page.Code != http.StatusSeeOther {
		t.Fatalf("the verification page = %d", page.Code)
	}
	return f.signIn(t, page.Header().Get("Location")), mine.UserCode
}

// TestClientCredentialsCannotMintInAnotherTenant. The grant stores an access token, and
// the row it writes carries a tenant. It must be the client's own.
func TestClientCredentialsCannotMintInAnotherTenant(t *testing.T) {
	f := newOIDCFixture(t)

	rec := authenticatedAs(t, f, "/oauth2/token", url.Values{
		"grant_type": {"client_credentials"}, "scope": {"openid profile"},
		"client_id": {f.client.ID},
	}, f.rival.ID, f.rivalSecret)

	// The rival may have its own token — it authenticated as itself. What it may not
	// have is a token that exists inside this tenant, which is what the stored row would
	// have said.
	if rec.Code != http.StatusOK {
		return
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %s", rec.Body.String())
	}
	token, ok := body["access_token"].(string)
	if !ok || token == "" {
		t.Fatalf("no access token: %v", body)
	}

	// This tenant's resource server asks about it. A token belonging to another tenant
	// must be invisible here, exactly as an expired one would be.
	answer := f.introspect(t, token, f.resource.ID, f.resourceSecret)
	if answer["active"] == true {
		t.Fatalf("a token minted by another tenant's client is live inside this one: %v", answer)
	}
}

// TestAPushedRequestCannotBeStoredInAnotherTenant.
func TestAPushedRequestCannotBeStoredInAnotherTenant(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)

	rec := authenticatedAs(t, f, "/oauth2/par", url.Values{
		"response_type": {"code"}, "client_id": {f.client.ID},
		"redirect_uri": {f.redirectURI}, "scope": {"openid"},
		"state":          {"state-for-the-scope-case"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}, f.rival.ID, f.rivalSecret)

	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
		t.Fatalf("a client of another tenant pushed a request into this one: %s",
			rec.Body.String())
	}
}

// TestAPushedRequestBelongsToTheClientThatPushedIt is a third shape of the same mistake,
// and this one is fosite's rather than Warden's.
//
// Its PAR handler authenticates the client and then rebuilds the request from the form —
// and the rebuild loads whatever `client_id` the body names, overwriting the client that
// authenticated. So any client holding its own credentials could mint request_uri values
// bound to somebody else's client, including a confidential one whose secret it does not
// have. RFC 9126 §2 says the pushed request is the authenticating client's.
//
// Nothing is stolen by it: the authorization code still goes to the victim client's
// registered redirect URI and still needs that client's secret to exchange. What the
// attacker gains is control of the parameters — scope, nonce, the PKCE challenge — of a
// request the victim client will be asked to complete.
func TestAPushedRequestBelongsToTheClientThatPushedIt(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)

	pushing := url.Values{
		"response_type":  {"code"},
		"client_id":      {f.confidential.ID}, // a client the caller is not
		"redirect_uri":   {"https://backoffice.acme.test/callback"},
		"scope":          {"openid profile email offline_access"},
		"state":          {"state-for-the-binding-case"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}

	for name, push := range map[string]func() *httptest.ResponseRecorder{
		"another tenant's client": func() *httptest.ResponseRecorder {
			return authenticatedAs(t, f, "/oauth2/par", pushing, f.rival.ID, f.rivalSecret)
		},
		"another client of the same tenant": func() *httptest.ResponseRecorder {
			return authenticatedAs(t, f, "/oauth2/par", pushing, f.resource.ID, f.resourceSecret)
		},
		"nobody at all": func() *httptest.ResponseRecorder {
			return f.postForm(t, "/oauth2/par", pushing, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := push()
			if rec.Code == http.StatusCreated || rec.Code == http.StatusOK {
				t.Fatalf("a request was pushed for a client the caller had not "+
					"authenticated as: %s", rec.Body.String())
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("= %d; this is an authentication failure and should say so "+
					"rather than looking like a server fault", rec.Code)
			}
		})
	}
}

// TestIntrospectionAuthorizesTheClientItAuthenticated is the second bug, and a different
// shape of the same mistake.
//
// fosite's introspection endpoint takes a bearer token over Basic credentials: when a
// token is present it authenticates *that* and never looks at the header. Warden read the
// header first to decide who was asking. So a caller could put a valid token of their own
// in the body, claim in the Basic header to be a client they are not — with a secret that
// is simply wrong — and have the forged identity decide what they were allowed to see.
func TestIntrospectionAuthorizesTheClientItAuthenticated(t *testing.T) {
	f := newOIDCFixture(t)

	// The target: a token for the API's audience, issued to the web application.
	victim := f.accessToken(t, "openid profile email", f.audience, "state-for-the-scope-introspect")

	// The attacker's own credential: a token issued to the television, which is neither
	// the victim token's client nor named in its audience.
	attacker := f.deviceAccessToken(t)

	// Honestly presented, it is refused. This is the baseline the forgery has to beat.
	honest := f.postFormWithBearer(t, "/oauth2/introspect", url.Values{"token": {victim}}, attacker)
	if active(t, honest) {
		t.Fatal("a client that is neither the token's client nor its audience was told " +
			"about it; the introspection rule is not being applied at all")
	}

	// The same credential moved into the body, with a forged Basic header naming the
	// resource server and carrying a secret that is wrong.
	forged := authenticatedAs(t, f, "/oauth2/introspect", url.Values{
		"token": {victim}, "access_token": {attacker},
	}, f.resource.ID, "not-the-secret")

	if active(t, forged) {
		t.Fatalf("an unproven client identity decided the authorization: %s", forged.Body.String())
	}
}

// TestAWrongClientSecretIsNeverAnIdentity covers the same hole from the other side: Basic
// credentials that do not verify must not name the caller even when nothing else does.
func TestAWrongClientSecretIsNeverAnIdentity(t *testing.T) {
	f := newOIDCFixture(t)
	victim := f.accessToken(t, "openid", f.audience, "state-for-the-secret-case")

	rec := authenticatedAs(t, f, "/oauth2/introspect", url.Values{"token": {victim}},
		f.resource.ID, "not-the-secret")
	if active(t, rec) {
		t.Fatalf("a wrong client secret was accepted: %s", rec.Body.String())
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("= %d; unverifiable credentials are an authentication failure", rec.Code)
	}
}

// active reports whether an introspection response says the token is live.
func active(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	var body struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		return false
	}
	return body.Active
}

// postFormWithBearer presents an access token as the caller's own credential.
func (f *oidcFixture) postFormWithBearer(
	t *testing.T, target string, form url.Values, token string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, target,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// deviceAccessToken returns a token issued to the television client, through a real
// device flow. Used where a test needs a credential belonging to a client with no
// audience of its own.
func (f *oidcFixture) deviceAccessToken(t *testing.T) string {
	t.Helper()
	start := f.startDevice(t, "openid")

	page := f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, nil)
	cookies := f.signIn(t, page.Header().Get("Location"))
	page = f.do(t, http.MethodGet, "/device?user_code="+url.QueryEscape(start.UserCode), nil, cookies)
	f.postForm(t, "/device", url.Values{
		"csrf_token": {f.csrfFrom(t, page)}, "user_code": {start.UserCode}, "decision": {"approve"},
	}, append(cookies, f.cookies(page)...))

	tokens := f.pollDeviceForTokens(t, start.DeviceCode, f.device.ID)
	token, ok := tokens["access_token"].(string)
	if !ok || token == "" {
		t.Fatalf("the device flow produced no access token: %v", tokens)
	}
	return token
}
