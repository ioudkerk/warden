package oidcop_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"

	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/oidcop"
)

// TestTheProviderComposesNoForbiddenGrant is the code half of M1-6's exit condition.
//
// The schema makes a client that *asks* for the implicit or password grant
// unrepresentable. This is the other end: even if a row somehow existed, no handler is
// composed that could serve one. fosite dispatches on the handlers it was given, so a
// grant with no handler is refused by the provider itself — absent, rather than disabled
// by a flag somebody could set.
func TestTheProviderComposesNoForbiddenGrant(t *testing.T) {
	ctx := context.Background()
	f := newProviderFixture(t)

	client, secret := f.confidentialClient(t)

	for _, grant := range []string{"password", "implicit"} {
		t.Run(grant, func(t *testing.T) {
			form := url.Values{
				"grant_type": {grant},
				"username":   {"maria@acme.test"},
				"password":   {"correct horse battery staple"},
				"client_id":  {client.ID},
			}
			// The tenant is established before the request is built, because that is the
			// order the real handlers work in: resolve the client, scope the context,
			// then hand both to fosite.
			scoped := oidcop.WithTenant(ctx, f.acme)
			req := httptest.NewRequestWithContext(scoped, http.MethodPost, "/oauth2/token",
				strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(client.ID, secret)

			_, err := f.provider.NewAccessRequest(scoped, req, &oidcop.Session{})
			if err == nil {
				t.Fatalf("the provider accepted the %q grant; SPEC §7.7 excludes it", grant)
			}

			rfcErr := fosite.ErrorToRFC6749Error(err)
			if rfcErr.ErrorField != "unsupported_grant_type" && rfcErr.ErrorField != "invalid_request" {
				t.Fatalf("the %q grant was refused as %q; want it to be unrecognised entirely",
					grant, rfcErr.ErrorField)
			}
		})
	}
}

// authorize drives an authorization request to the point where a code would be issued.
//
// Two calls, and the split matters: NewAuthorizeRequest only parses and validates the
// request itself — client, redirect_uri, scopes, response type — while the PKCE handler
// runs in NewAuthorizeResponse, where the code is minted. A test that asserted PKCE at
// the first stage would report the enforcement missing when it is simply later.
func (f *providerFixture) authorize(t *testing.T, client *oidcop.Client, extra url.Values) error {
	t.Helper()
	ctx := context.Background()

	form := url.Values{
		"response_type": {"code"},
		"client_id":     {client.ID},
		"redirect_uri":  {client.RedirectURIs[0]},
		"scope":         {"openid"},
		"state":         {"a-state-value-long-enough-to-pass"},
	}
	for key, values := range extra {
		form[key] = values
	}

	scoped := oidcop.WithTenant(ctx, f.acme)
	req := httptest.NewRequestWithContext(scoped, http.MethodGet,
		"/oauth2/authorize?"+form.Encode(), nil)

	ar, err := f.provider.NewAuthorizeRequest(scoped, req)
	if err != nil {
		return err
	}
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	for _, audience := range ar.GetRequestedAudience() {
		ar.GrantAudience(audience)
	}

	session := oidcop.NewSession(f.provider.Issuer(), f.acme, f.session.ID,
		f.user, time.Now().UTC(), []string{"pwd"})
	_, err = f.provider.NewAuthorizeResponse(scoped, ar, session)
	return err
}

// TestPKCEIsEnforcedForEveryClient. The schema forces it on public clients, which is
// where RFC 8252 requires it; the provider enforces it on confidential ones too, and a
// confidential client is the only kind that could otherwise omit it.
func TestPKCEIsEnforcedForEveryClient(t *testing.T) {
	f := newProviderFixture(t)
	client, _ := f.confidentialClient(t)

	err := f.authorize(t, client, nil) // no code_challenge
	if err == nil {
		t.Fatal("an authorization request with no code_challenge produced a code; " +
			"EnforcePKCE is not in effect")
	}
	rfc := fosite.ErrorToRFC6749Error(err)
	if !strings.Contains(strings.ToLower(rfc.HintField+rfc.DebugField+rfc.ErrorField), "code_challenge") &&
		!strings.Contains(strings.ToLower(rfc.HintField+rfc.DebugField+rfc.ErrorField), "pkce") {
		t.Fatalf("the refusal does not mention PKCE: error=%q hint=%q debug=%q",
			rfc.ErrorField, rfc.HintField, rfc.DebugField)
	}

	// With a proper S256 challenge it proceeds, so the test is observing PKCE rather
	// than some unrelated refusal.
	verifier := "a-code-verifier-of-respectable-length-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if err := f.authorize(t, client, url.Values{
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}); err != nil {
		t.Fatalf("a correct S256 authorization request was refused: %v", err)
	}
}

// TestPlainPKCEIsRefused. "plain" sends the verifier in the clear, so anybody who saw
// the authorization request can complete the exchange — it proves nothing.
func TestPlainPKCEIsRefused(t *testing.T) {
	f := newProviderFixture(t)
	client, _ := f.confidentialClient(t)

	err := f.authorize(t, client, url.Values{
		"code_challenge":        {"a-verifier-used-as-its-own-challenge-0123456789"},
		"code_challenge_method": {"plain"},
	})
	if err == nil {
		t.Fatal("the plain PKCE challenge method was accepted; only S256 proves anything")
	}
}

// TestAlgorithmsReportsTheKeyTheDeploymentActuallyHolds.
//
// This is the gap that let a real bug through. The discovery test below passes its own
// algorithm list, so it never called Algorithms() — and Algorithms() was switching on raw
// key types while the key manager had started returning a *jose.JSONWebKey wrapping one.
// Every unit test passed; the first request to a running server returned 503.
func TestAlgorithmsReportsTheKeyTheDeploymentActuallyHolds(t *testing.T) {
	f := newProviderFixture(t)

	algorithms, err := f.provider.Algorithms(context.Background())
	if err != nil {
		t.Fatalf("Algorithms: %v", err)
	}
	if len(algorithms) != 1 || algorithms[0] != keys.ES256 {
		t.Fatalf("Algorithms() = %v; the fixture signs with %s", algorithms, keys.ES256)
	}

	// And the document built from it says the same, which is the path a relying party
	// actually takes.
	doc := f.provider.Discovery(algorithms)
	if doc.IDTokenSigningAlgValuesSupported[0] != keys.ES256 {
		t.Fatalf("discovery advertises %v", doc.IDTokenSigningAlgValuesSupported)
	}
}

// TestDiscoveryAdvertisesOnlyWhatIsImplemented. A document that names a grant the
// provider does not compose is worse than one that omits it: a client builds against the
// advertisement and fails at the endpoint.
func TestDiscoveryAdvertisesOnlyWhatIsImplemented(t *testing.T) {
	f := newProviderFixture(t)
	doc := f.provider.Discovery([]string{"ES256"})

	for _, forbidden := range []string{"implicit", "password"} {
		for _, advertised := range doc.GrantTypesSupported {
			if advertised == forbidden {
				t.Fatalf("discovery advertises the %q grant, which is not composed", forbidden)
			}
		}
	}

	if len(doc.ResponseTypesSupported) != 1 || doc.ResponseTypesSupported[0] != "code" {
		t.Fatalf("response_types_supported = %v; every other type returns a token through "+
			"the front channel, which is the implicit grant renamed", doc.ResponseTypesSupported)
	}
	if len(doc.CodeChallengeMethodsSupported) != 1 || doc.CodeChallengeMethodsSupported[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported = %v; want S256 only",
			doc.CodeChallengeMethodsSupported)
	}

	// The endpoints must be absolute and under the issuer, or a relying party cannot
	// use them.
	for name, endpoint := range map[string]string{
		"authorization": doc.AuthorizationEndpoint,
		"token":         doc.TokenEndpoint,
		"userinfo":      doc.UserinfoEndpoint,
		"jwks":          doc.JWKSURI,
		"introspection": doc.IntrospectionEndpoint,
		"revocation":    doc.RevocationEndpoint,
		"end session":   doc.EndSessionEndpoint,
		"PAR":           doc.PushedAuthorizationRequestEndpoint,
	} {
		if !strings.HasPrefix(endpoint, "https://warden.example.com/") {
			t.Errorf("the %s endpoint is %q; it must be absolute and under the issuer",
				name, endpoint)
		}
	}

	if doc.IDTokenSigningAlgValuesSupported[0] != "ES256" {
		t.Fatalf("id_token_signing_alg_values_supported = %v; it must report the key the "+
			"deployment actually signs with", doc.IDTokenSigningAlgValuesSupported)
	}
}

// TestTheGlobalSecretIsDerivedAndStable. Every code and token signature depends on it,
// so it has to be the same on every replica and across restarts — and it must not be the
// KEK itself.
func TestTheGlobalSecretIsDerivedAndStable(t *testing.T) {
	keyring := testKeyring(t)

	first, err := oidcop.NewGlobalSecret(keyring)
	if err != nil {
		t.Fatalf("NewGlobalSecret: %v", err)
	}
	second, err := oidcop.NewGlobalSecret(keyring)
	if err != nil {
		t.Fatalf("NewGlobalSecret: %v", err)
	}

	if len(first) != 32 {
		t.Fatalf("the secret is %d bytes; fosite's HMAC wants 32", len(first))
	}
	if string(first) != string(second) {
		t.Fatal("two derivations from one keyring produced different secrets; a code issued " +
			"by one replica would not verify at another")
	}

	// Not the KEK. A leaked provider secret must not be the key that opens the signing
	// keys.
	if string(first) == string(keyringMaterial(t, keyring)) {
		t.Fatal("the provider secret is the KEK itself")
	}

	// A different purpose gives different bytes, which is what stops two uses of
	// Derive colliding.
	other, err := keyring.Derive("warden/something-else", 32)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if string(other) == string(first) {
		t.Fatal("two purposes derived the same subkey")
	}
}
