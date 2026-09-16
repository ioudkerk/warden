package httpapi_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Certification-style conformance checks (M1-6's exit condition).
//
// Not the OpenID Foundation's suite, which is a hosted service that drives a real browser
// against a public deployment. These are the checks that suite makes, written against
// this server's own HTTP surface: the ones that catch a provider which works for the
// client it was developed against and fails for a conforming one.
//
// Two themes run through them. The document must describe the server — a provider that
// advertises what it does not serve sends every client down a path that ends in an error.
// And what is excluded must be excluded everywhere, not merely left out of the brochure.

// TestDiscoveryAdvertisesOnlyWhatItServes walks every endpoint the document names and
// asks the server for it.
//
// A 404 here is the failure this catches: a discovery document is generated, an endpoint
// is not, and nothing notices until somebody builds a client from the metadata.
func TestDiscoveryAdvertisesOnlyWhatItServes(t *testing.T) {
	f := newOIDCFixture(t)
	doc := f.discovery(t)

	for _, field := range []string{
		"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri",
		"introspection_endpoint", "revocation_endpoint", "end_session_endpoint",
		"pushed_authorization_request_endpoint", "device_authorization_endpoint",
	} {
		raw, ok := doc[field].(string)
		if !ok || raw == "" {
			t.Fatalf("the discovery document has no %s", field)
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("%s = %q, which is not a URL", field, raw)
		}

		// GET everything. A POST-only endpoint answers 405, which is the mux saying the
		// route exists — exactly what is being checked. A 404 means it does not.
		rec := f.do(t, http.MethodGet, parsed.RequestURI(), nil, nil)
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s is advertised as %s and the server has no such route; a client "+
				"built from this document would fail there", field, raw)
		}
	}
}

// TestDiscoveryCarriesWhatTheSpecificationRequires. OpenID Connect Discovery 1.0 §3 makes
// these fields REQUIRED, and a relying party library will refuse the document without
// them rather than guess.
func TestDiscoveryCarriesWhatTheSpecificationRequires(t *testing.T) {
	f := newOIDCFixture(t)
	doc := f.discovery(t)

	for _, field := range []string{
		"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
		"response_types_supported", "subject_types_supported",
		"id_token_signing_alg_values_supported",
	} {
		if doc[field] == nil {
			t.Errorf("the discovery document is missing the REQUIRED field %q", field)
		}
	}

	// The issuer is compared character for character by every conforming client, against
	// the `iss` of the id token. A trailing slash in one and not the other is the single
	// most common interoperability failure in OpenID Connect.
	issuer, _ := doc["issuer"].(string) //nolint:errcheck // asserted below
	if issuer == "" {
		t.Fatal("no issuer")
	}
	if strings.TrimSuffix(issuer, "/") != strings.TrimSuffix(f.issuer, "/") {
		t.Fatalf("issuer = %q, but this deployment is configured as %q", issuer, f.issuer)
	}

	// S256 only. "plain" sends the verifier in the clear to anybody who saw the
	// authorization request, which proves nothing.
	methods := stringsOf(doc["code_challenge_methods_supported"])
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported = %v; want S256 alone", methods)
	}
}

// TestTheExcludedGrantsAreAbsentEverywhere is M1-6's exit condition in the places a
// client can observe.
//
// Three surfaces, and all three have to agree: the document does not offer them, the
// authorization endpoint refuses the response types that carry a token through the front
// channel, and the token endpoint refuses the password grant. The fourth surface — a
// client that asks to be *registered* for one — is refused by a schema constraint, and
// is tested where that constraint lives.
func TestTheExcludedGrantsAreAbsentEverywhere(t *testing.T) {
	f := newOIDCFixture(t)
	doc := f.discovery(t)

	for _, forbidden := range []string{"implicit", "password"} {
		for _, advertised := range stringsOf(doc["grant_types_supported"]) {
			if advertised == forbidden {
				t.Errorf("grant_types_supported offers %q, which SPEC §7.7 excludes", forbidden)
			}
		}
	}
	for _, advertised := range stringsOf(doc["response_types_supported"]) {
		if advertised != "code" {
			t.Errorf("response_types_supported offers %q; every response type other than "+
				"\"code\" returns a token through the front channel, which is the implicit "+
				"grant wearing a different name", advertised)
		}
	}

	// The resource-owner password grant, at the endpoint.
	rec := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"password"}, "client_id": {f.client.ID},
		"username": {f.email}, "password": {f.password},
	}, nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("the password grant issued a token: %s", rec.Body.String())
	}
	if code := errorCodeOf(t, rec); code != "unsupported_grant_type" && code != "invalid_request" {
		t.Fatalf("the password grant = %q; no handler is composed for it, so fosite has "+
			"nothing to dispatch to", code)
	}

	// The implicit and hybrid response types, at the authorization endpoint.
	_, challenge := pkcePair(t)
	for _, responseType := range []string{"token", "id_token", "id_token token", "code id_token"} {
		form := url.Values{
			"response_type": {responseType}, "client_id": {f.client.ID},
			"redirect_uri": {f.redirectURI}, "scope": {"openid"},
			"state": {"state-for-the-exclusion-case"}, "nonce": {"nonce-for-this-case"},
			"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		}
		rec := f.do(t, http.MethodGet, "/oauth2/authorize?"+form.Encode(), nil, nil)
		location := rec.Header().Get("Location")
		if strings.Contains(location, "access_token=") || strings.Contains(location, "id_token=") {
			t.Fatalf("response_type=%q returned a token through the front channel: %s",
				responseType, location)
		}
		if strings.HasPrefix(location, "/login") {
			t.Fatalf("response_type=%q reached the login page; it must be refused before "+
				"anybody types a password", responseType)
		}
	}
}

// TestJWKSPublishesNothingPrivate.
//
// The one mistake in this area that cannot be walked back: a JWKS document containing
// the private exponent hands every reader the ability to mint tokens as this provider.
// It is a plausible mistake, too — marshalling the wrong half of a key pair is a one-word
// difference — so it is asserted rather than assumed.
func TestJWKSPublishesNothingPrivate(t *testing.T) {
	f := newOIDCFixture(t)

	rec := f.do(t, http.MethodGet, "/.well-known/jwks.json", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("JWKS = %d", rec.Code)
	}

	var raw struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("JWKS is not JSON: %s", rec.Body.String())
	}
	if len(raw.Keys) == 0 {
		t.Fatal("JWKS publishes no keys; nothing can verify a token")
	}

	// RFC 7517 §9.3: these are the members that appear only in a private key. Every one
	// of them, rather than just "d", because an EC key hides its secret in "d" and an RSA
	// key spreads it across the CRT parameters as well.
	private := []string{"d", "p", "q", "dp", "dq", "qi", "k"}
	for _, key := range raw.Keys {
		for _, member := range private {
			if _, present := key[member]; present {
				t.Fatalf("JWKS publishes the private member %q of key %v; anybody who "+
					"fetched this document could mint tokens as this provider",
					member, key["kid"])
			}
		}
		if key["kid"] == nil || key["kid"] == "" {
			t.Fatalf("a published key has no kid; a relying party would have to guess "+
				"which key signed a token and would break on the first rotation: %v", key)
		}
		if key["use"] != "sig" {
			t.Errorf("key %v has use=%v; a verifier filters on it", key["kid"], key["use"])
		}
	}
}

// TestTheIDTokenCarriesTheRequiredClaims. OpenID Connect Core §2 makes these mandatory,
// and §3.1.3.7 makes a relying party check every one of them.
func TestTheIDTokenCarriesTheRequiredClaims(t *testing.T) {
	f := newOIDCFixture(t)
	verifier, challenge := pkcePair(t)

	// nonce goes in and must come back: it is what binds an id token to the request that
	// asked for it, and a relying party that sent one rejects a token without it.
	const nonce = "a-nonce-with-enough-entropy"
	authorize := "/oauth2/authorize?" + url.Values{
		"response_type": {"code"}, "client_id": {f.client.ID},
		"redirect_uri": {f.redirectURI}, "scope": {"openid"},
		"state": {"state-for-the-claims-case"}, "nonce": {nonce},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()

	page := f.do(t, http.MethodGet, authorize, nil, nil)
	cookies := f.signIn(t, page.Header().Get("Location"))
	redirected := f.do(t, http.MethodGet, authorize, nil, cookies)
	location, err := url.Parse(redirected.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	tokens := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})

	idToken, ok := tokens["id_token"].(string)
	if !ok || idToken == "" {
		t.Fatalf("no id_token: %v", tokens)
	}

	// The header first: "none" is an algorithm in the JWS specification and a hole in
	// every implementation that accepted it.
	header := decodeJWTSegment(t, idToken, 0)
	if alg, _ := header["alg"].(string); alg == "" || strings.EqualFold(alg, "none") { //nolint:errcheck // checked
		t.Fatalf("the id token is signed with alg=%v", header["alg"])
	}

	claims := f.verifyAgainstJWKS(t, idToken)
	for _, claim := range []string{"iss", "sub", "aud", "exp", "iat"} {
		if claims[claim] == nil {
			t.Errorf("the id token is missing the REQUIRED claim %q", claim)
		}
	}
	if claims["nonce"] != nonce {
		t.Fatalf("nonce = %v; want the value the client sent. Without it a relying party "+
			"cannot bind the token to its own request", claims["nonce"])
	}

	audience := stringsOf(claims["aud"])
	if len(audience) != 1 || audience[0] != f.client.ID {
		t.Fatalf("aud = %v; want the client the token was issued to (%s)",
			claims["aud"], f.client.ID)
	}
	if claims["iss"] != f.issuer {
		t.Fatalf("iss = %v; want exactly %q, which is what a client compares against",
			claims["iss"], f.issuer)
	}
}

// TestTokenResponsesAreNotCached. OpenID Connect Core §3.1.3.4 requires no-store on the
// token response, and the reason is concrete: a shared proxy that cached one would hand
// the next person somebody else's access token.
func TestTokenResponsesAreNotCached(t *testing.T) {
	f := newOIDCFixture(t)
	verifier, challenge := pkcePair(t)

	code, _ := f.signInAndGetCode(t, challenge, "state-for-the-caching-case")
	rec := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("the exchange = %d, body %s", rec.Code, rec.Body.String())
	}
	if cache := rec.Header().Get("Cache-Control"); !strings.Contains(cache, "no-store") {
		t.Fatalf("the token response says Cache-Control: %q; a shared cache could serve "+
			"one person's tokens to the next", cache)
	}

	info := f.withBearer(t, http.MethodGet, "/oauth2/userinfo", "not-a-token")
	if cache := info.Header().Get("Cache-Control"); !strings.Contains(cache, "no-store") {
		t.Fatalf("the userinfo response says Cache-Control: %q", cache)
	}
}

// TestAnAuthorizationErrorGoesBackToTheClientWithItsState.
//
// Once the redirect URI is known to be registered, RFC 6749 §4.1.2.1 requires errors to
// travel back to the client rather than being rendered — and the state must come with
// them, because a client that cannot match the response to its request treats it as an
// attack and drops it.
func TestAnAuthorizationErrorGoesBackToTheClientWithItsState(t *testing.T) {
	f := newOIDCFixture(t)

	// A registered client and redirect URI, and a request that cannot be served: no PKCE
	// challenge, which this provider requires of everybody.
	form := url.Values{
		"response_type": {"code"}, "client_id": {f.client.ID},
		"redirect_uri": {f.redirectURI}, "scope": {"openid"},
		"state": {"state-the-client-will-match"},
	}
	rec := f.do(t, http.MethodGet, "/oauth2/authorize?"+form.Encode(), nil, nil)

	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || location.String() == "" {
		t.Fatalf("a request that cannot be served rendered a page instead of redirecting "+
			"(status %d)", rec.Code)
	}
	if !strings.HasPrefix(location.String(), f.redirectURI) {
		t.Fatalf("the error went to %q rather than to the client", location)
	}
	if location.Query().Get("error") == "" {
		t.Fatalf("no error parameter in %q", location)
	}
	if location.Query().Get("state") != "state-the-client-will-match" {
		t.Fatalf("state = %q; a client that cannot match the response to its request "+
			"discards it", location.Query().Get("state"))
	}
}

// TestPKCEIsRequiredOfEveryone. OAuth 2.1 makes it universal and RFC 8252 requires it of
// native clients; this provider enforces it for confidential clients too, because there
// is no good reason for one to skip it.
func TestPKCEIsRequiredOfEveryone(t *testing.T) {
	f := newOIDCFixture(t)

	// No challenge at all.
	form := url.Values{
		"response_type": {"code"}, "client_id": {f.client.ID},
		"redirect_uri": {f.redirectURI}, "scope": {"openid"},
		"state": {"state-for-the-pkce-case"},
	}
	rec := f.do(t, http.MethodGet, "/oauth2/authorize?"+form.Encode(), nil, nil)
	location := rec.Header().Get("Location")
	if strings.Contains(location, "code=") {
		t.Fatalf("an authorization request with no code_challenge produced a code: %s", location)
	}

	// And "plain", which proves nothing to anybody who saw the request.
	form.Set("code_challenge", "a-verifier-used-directly-as-a-challenge-0123456789")
	form.Set("code_challenge_method", "plain")
	rec = f.do(t, http.MethodGet, "/oauth2/authorize?"+form.Encode(), nil, nil)
	if strings.Contains(rec.Header().Get("Location"), "code=") {
		t.Fatalf("code_challenge_method=plain was accepted: %s", rec.Header().Get("Location"))
	}
}

// --- helpers -------------------------------------------------------------------------

func (f *oidcFixture) discovery(t *testing.T) map[string]any {
	t.Helper()
	rec := f.do(t, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("the discovery document = %d, body %s", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("the discovery document is not JSON: %s", rec.Body.String())
	}
	return doc
}

// stringsOf reads a JSON value that may be a string or a list of them.
func stringsOf(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// decodeJWTSegment decodes one part of a JWT without verifying anything, for assertions
// about the header.
func decodeJWTSegment(t *testing.T, token string, index int) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		t.Fatalf("not a JWS: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatalf("decoding segment %d: %v", index, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("segment %d is not JSON: %s", index, raw)
	}
	return out
}
