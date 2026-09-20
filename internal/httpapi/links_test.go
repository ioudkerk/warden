package httpapi_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Magic links and password resets, through HTTP (SPEC §7.2, docs/design-email.md §7).
//
// The test that matters is not that a link arrives. It is that asking for one reveals
// nothing about whether the account exists — §7.2 requires "identical response and timing
// for unknown users", and email is where that promise is most easily broken, because the
// obvious implementation looks the address up and returns early when it finds nothing.

// TestRequestingALinkRevealsNothing is that property, for both flows.
func TestRequestingALinkRevealsNothing(t *testing.T) {
	for name, path := range map[string]string{
		"magic link":     "/login/magic",
		"password reset": "/password/forgot",
	} {
		t.Run(name, func(t *testing.T) {
			f := newOIDCFixture(t)
			_, challenge := pkcePair(t)
			authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-for-the-enumeration")
			rec := f.do(t, http.MethodGet, authorize, nil, nil)
			returnTo := f.returnToFrom(t, rec.Header().Get("Location"))

			bodies := map[string]string{}
			statuses := map[string]int{}
			for _, address := range []string{f.email, "nobody-at-all@acme.test"} {
				page := f.do(t, http.MethodGet, path+"?return_to="+url.QueryEscape(returnTo), nil, nil)
				if page.Code != http.StatusOK {
					t.Fatalf("the request page = %d, body %s", page.Code, page.Body.String())
				}

				submitted := f.postForm(t, path, url.Values{
					"csrf_token": {f.csrfFrom(t, page)},
					"return_to":  {returnTo},
					"email":      {address},
				}, f.cookies(page))

				statuses[address] = submitted.Code
				// The echoed address and the per-render CSRF token legitimately differ
				// and neither is a signal; both are normalised out so the comparison is
				// of the parts that would actually leak.
				bodies[address] = stripCSRFValue(
					strings.ReplaceAll(submitted.Body.String(), address, ""))
			}

			known, unknown := bodies[f.email], bodies["nobody-at-all@acme.test"]
			if known != unknown {
				t.Fatalf("the page differs between a real address and an unknown one; the "+
					"difference is an account-existence oracle (SPEC §7.2)\nknown:\n%s\n\nunknown:\n%s",
					truncateForTest(known), truncateForTest(unknown))
			}
			if statuses[f.email] != statuses["nobody-at-all@acme.test"] {
				t.Fatalf("the status differs: %d vs %d",
					statuses[f.email], statuses["nobody-at-all@acme.test"])
			}
			if !strings.Contains(known, "Check your email") {
				t.Fatalf("the acknowledgement does not acknowledge: %s", truncateForTest(known))
			}
		})
	}
}

// TestAMagicLinkSignsYouIn walks the flow a person experiences.
func TestAMagicLinkSignsYouIn(t *testing.T) {
	f := newOIDCFixture(t)
	link := f.requestMagicLink(t)

	rec := f.do(t, http.MethodGet, link, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("following the link = %d, body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "signed in") {
		t.Fatalf("the link did not sign anybody in: %s", truncateForTest(rec.Body.String()))
	}

	// The session it created authorizes.
	_, challenge := pkcePair(t)
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-after-the-magic-link")
	authorized := f.do(t, http.MethodGet, authorize, nil, f.cookies(rec))
	location, err := url.Parse(authorized.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	if location.Query().Get("code") == "" {
		t.Fatalf("the magic link's session does not authorize (landed at %q)", location)
	}
}

// TestAMagicLinkStillMeetsTheSecondFactor.
//
// A magic link proves control of a mailbox, which is one factor. If enabling a second factor
// could be undone by asking for a link, it would not be a second factor at all.
func TestAMagicLinkStillMeetsTheSecondFactor(t *testing.T) {
	f := newOIDCFixture(t)
	f.enrolTOTP(t)

	link := f.requestMagicLink(t)
	rec := f.do(t, http.MethodGet, link, nil, nil)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login/verify" {
		t.Fatalf("a magic link for an account with a second factor = %d to %q; it must "+
			"still ask", rec.Code, rec.Header().Get("Location"))
	}

	// And what it holds does not authorize anything yet.
	_, challenge := pkcePair(t)
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-mid-magic-link")
	if authorized := f.do(t, http.MethodGet, authorize, nil, f.cookies(rec)); !strings.HasPrefix(
		authorized.Header().Get("Location"), "/login") {
		t.Fatal("a magic link alone authorized a request for an account with a second factor")
	}
}

// TestAMagicLinkWorksOnce, at the endpoint rather than in the store.
func TestAMagicLinkWorksOnce(t *testing.T) {
	f := newOIDCFixture(t)
	link := f.requestMagicLink(t)

	if first := f.do(t, http.MethodGet, link, nil, nil); first.Code != http.StatusOK {
		t.Fatalf("the first use = %d", first.Code)
	}
	second := f.do(t, http.MethodGet, link, nil, nil)
	if second.Code == http.StatusOK && strings.Contains(second.Body.String(), "signed in") {
		t.Fatal("a magic link signed somebody in twice")
	}
}

// TestAResetEndsEverySession is SPEC §7.2's requirement, and the reason a reset is not just
// a password change: somebody resetting a password may have lost control of the old one.
func TestAResetEndsEverySession(t *testing.T) {
	f := newOIDCFixture(t)
	_, challenge := pkcePair(t)

	// An existing session, and a refresh token hanging off it.
	verifier, _ := pkcePair(t)
	code, cookies := f.signInAndGetCode(t, challenge, "state-before-the-reset")
	tokens := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})
	refreshToken, ok := tokens["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatalf("no refresh token: %v", tokens)
	}

	// Reset the password through a link.
	resetLink := f.requestLink(t, "/password/forgot")
	page := f.do(t, http.MethodGet, resetLink, nil, nil)
	if page.Code != http.StatusOK {
		t.Fatalf("the reset page = %d, body %s", page.Code, page.Body.String())
	}
	done := f.postForm(t, "/password/reset", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"token":      {tokenOf(t, resetLink)},
		"password":   {"a replacement passphrase nobody has used"},
	}, f.cookies(page))
	if done.Code != http.StatusOK {
		t.Fatalf("the reset = %d, body %s", done.Code, done.Body.String())
	}

	// The old session is gone.
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-after-the-reset")
	if old := f.do(t, http.MethodGet, authorize, nil, cookies); !strings.HasPrefix(
		old.Header().Get("Location"), "/login") {
		t.Fatal("a session opened with the old password survived the reset")
	}
	// So is the refresh token.
	if again := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
		"client_id": {f.client.ID},
	}, nil); again.Code == http.StatusOK {
		t.Fatal("a refresh token survived a password reset")
	}
}

// TestAResetLinkIsNotSpentByLookingAtIt.
//
// A mail client that prefetches links would otherwise consume the token before the person
// ever saw the form, and the reset would be dead on arrival. The GET shows the form; the
// POST spends the token.
func TestAResetLinkIsNotSpentByLookingAtIt(t *testing.T) {
	f := newOIDCFixture(t)
	link := f.requestLink(t, "/password/forgot")

	// Two GETs, as a prefetch followed by a person.
	for i := range 2 {
		page := f.do(t, http.MethodGet, link, nil, nil)
		if page.Code != http.StatusOK {
			t.Fatalf("GET %d = %d; a prefetch spent the link", i+1, page.Code)
		}
	}

	page := f.do(t, http.MethodGet, link, nil, nil)
	done := f.postForm(t, "/password/reset", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"token":      {tokenOf(t, link)},
		"password":   {"another replacement passphrase entirely"},
	}, f.cookies(page))
	if done.Code != http.StatusOK || !strings.Contains(done.Body.String(), "has been changed") {
		t.Fatalf("the reset after two prefetches = %d, body %s", done.Code,
			truncateForTest(done.Body.String()))
	}
}

// --- helpers ---------------------------------------------------------------------------

// requestMagicLink asks for one and returns the URL, read from the queued message.
func (f *oidcFixture) requestMagicLink(t *testing.T) string {
	t.Helper()
	return f.requestLink(t, "/login/magic")
}

// requestLink drives the request page and returns the link that was queued.
//
// Read from the database rather than from a fake sender, because what is being tested is
// that the *queued* message can be turned back into a working link — which is where the
// sealed-token design either works or does not.
func (f *oidcFixture) requestLink(t *testing.T, path string) string {
	t.Helper()
	_, challenge := pkcePair(t)
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-to-request-a-link")
	rec := f.do(t, http.MethodGet, authorize, nil, nil)
	returnTo := f.returnToFrom(t, rec.Header().Get("Location"))

	page := f.do(t, http.MethodGet, path+"?return_to="+url.QueryEscape(returnTo), nil, nil)
	if page.Code != http.StatusOK {
		t.Fatalf("the request page = %d, body %s", page.Code, page.Body.String())
	}
	submitted := f.postForm(t, path, url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"return_to":  {returnTo},
		"email":      {f.email},
	}, f.cookies(page))
	if submitted.Code != http.StatusOK {
		t.Fatalf("requesting a link = %d, body %s", submitted.Code, submitted.Body.String())
	}

	return f.drainOneLink(t)
}

func tokenOf(t *testing.T, link string) string {
	t.Helper()
	_, token, ok := strings.Cut(link, "token=")
	if !ok || token == "" {
		t.Fatalf("no token in %q", link)
	}
	return token
}
