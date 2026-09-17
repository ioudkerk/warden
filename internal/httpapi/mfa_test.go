package httpapi_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/warden-project/warden/internal/authn"
)

// The second factor, through the login (SPEC §7.1, §7.2).
//
// The property that matters is not "the code is checked". It is that *no session exists*
// until it has been: a login that half-succeeded must leave the browser holding nothing it
// can use, or the second factor is a formality somebody will eventually find a way past.

// TestASecondFactorStandsBetweenThePasswordAndTheSession walks the whole thing.
func TestASecondFactorStandsBetweenThePasswordAndTheSession(t *testing.T) {
	f := newOIDCFixture(t)
	secret := f.enrolTOTP(t)

	_, challenge := pkcePair(t)
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-for-the-mfa-case")

	rec := f.do(t, http.MethodGet, authorize, nil, nil)
	loginURL := rec.Header().Get("Location")
	page := f.do(t, http.MethodGet, loginURL, nil, nil)

	// The password alone now ends at the verification page, not at a session.
	afterPassword := f.postForm(t, "/login", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"return_to":  {f.returnToFrom(t, loginURL)},
		"email":      {f.email}, "password": {f.password},
	}, f.cookies(page))

	if afterPassword.Code != http.StatusSeeOther {
		t.Fatalf("the password step = %d, body %s", afterPassword.Code, afterPassword.Body.String())
	}
	if location := afterPassword.Header().Get("Location"); location != "/login/verify" {
		t.Fatalf("the password led to %q; want the verification page", location)
	}

	passwordCookies := f.cookies(afterPassword)
	// The crucial one: whatever the browser is now holding must not authorize anything.
	if authorized := f.do(t, http.MethodGet, authorize, nil, passwordCookies); !strings.HasPrefix(
		authorized.Header().Get("Location"), "/login") {
		t.Fatalf("a password alone authorized a request (landed at %q); the second factor "+
			"would be a formality", authorized.Header().Get("Location"))
	}

	// The verification page, and a correct code.
	verify := f.do(t, http.MethodGet, "/login/verify", nil, passwordCookies)
	if verify.Code != http.StatusOK {
		t.Fatalf("the verification page = %d, body %s", verify.Code, verify.Body.String())
	}

	code := f.totpCode(t, secret)
	done := f.postForm(t, "/login/verify", url.Values{
		"csrf_token": {f.csrfFrom(t, verify)},
		"code":       {code},
	}, append(passwordCookies, f.cookies(verify)...))

	if done.Code != http.StatusSeeOther {
		t.Fatalf("a correct code = %d, body %s", done.Code, done.Body.String())
	}
	sessionCookies := f.cookies(done)

	// And now the authorization request succeeds.
	authorized := f.do(t, http.MethodGet, authorize, nil, sessionCookies)
	location, err := url.Parse(authorized.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	if location.Query().Get("code") == "" {
		t.Fatalf("after two steps the authorization request landed at %q", location)
	}
}

// TestTheSecondFactorReachesTheToken. `amr` is what a resource server reads to know how
// somebody authenticated, and SPEC §9.3's `requires_mfa` role constraint is evaluated
// against it — so a second factor that did not reach the token would be invisible to every
// decision that depends on it.
func TestTheSecondFactorReachesTheToken(t *testing.T) {
	f := newOIDCFixture(t)
	secret := f.enrolTOTP(t)

	verifier, challenge := pkcePair(t)
	code, cookies := f.signInWithSecondFactor(t, secret, challenge, "state-for-the-amr-case")
	tokens := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})
	_ = cookies

	idToken, ok := tokens["id_token"].(string)
	if !ok {
		t.Fatalf("no id token: %v", tokens)
	}
	amr := stringsOf(f.verifyAgainstJWKS(t, idToken)["amr"])

	for _, want := range []string{authn.AMRPassword, authn.AMROTP, authn.AMRMFA} {
		if !contains(amr, want) {
			t.Errorf("amr = %v, missing %q — a role with requires_mfa would refuse this "+
				"session even though a second factor was presented", amr, want)
		}
	}
}

// TestACodeIsSpentWhenItIsUsed is RFC 6238 §5.2. A code is valid for thirty seconds, and
// anybody who watched it being typed has those seconds unless the first use spends it.
func TestACodeIsSpentWhenItIsUsed(t *testing.T) {
	f := newOIDCFixture(t)
	secret := f.enrolTOTP(t)

	code := f.totpCode(t, secret)
	_, cookies := f.passwordStep(t, "state-for-the-replay-case-one")
	verify := f.do(t, http.MethodGet, "/login/verify", nil, cookies)
	first := f.postForm(t, "/login/verify", url.Values{
		"csrf_token": {f.csrfFrom(t, verify)}, "code": {code},
	}, append(cookies, f.cookies(verify)...))
	if first.Code != http.StatusSeeOther {
		t.Fatalf("the first use of a code = %d", first.Code)
	}

	// A second login, presenting the same code while it is still inside its window.
	_, again := f.passwordStep(t, "state-for-the-replay-case-two")
	verifyAgain := f.do(t, http.MethodGet, "/login/verify", nil, again)
	second := f.postForm(t, "/login/verify", url.Values{
		"csrf_token": {f.csrfFrom(t, verifyAgain)}, "code": {code},
	}, append(again, f.cookies(verifyAgain)...))

	if second.Code == http.StatusSeeOther {
		t.Fatal("a TOTP code was accepted twice inside its own window; anybody who saw it " +
			"typed would have ninety seconds to use it")
	}
}

// TestARecoveryCodeSignsYouInAndEndsEverythingElse is SPEC §7.2's requirement.
//
// Using a recovery code means the usual factor is gone, and the honest reading of that is
// "something has changed, possibly not in the account holder's favour". Every other session
// and every refresh token stops.
func TestARecoveryCodeSignsYouInAndEndsEverythingElse(t *testing.T) {
	f := newOIDCFixture(t)
	secret := f.enrolTOTP(t)
	codes := f.recoveryCodes(t)

	// An existing session, with a refresh token hanging off it.
	verifier, challenge := pkcePair(t)
	authCode, oldCookies := f.signInWithSecondFactor(t, secret, challenge, "state-for-the-recovery-before")
	tokens := f.exchange(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {authCode},
		"redirect_uri": {f.redirectURI}, "client_id": {f.client.ID},
		"code_verifier": {verifier},
	})
	refreshToken, _ := tokens["refresh_token"].(string) //nolint:errcheck // checked below
	if refreshToken == "" {
		t.Fatalf("no refresh token: %v", tokens)
	}

	// Now sign in again with a recovery code instead of the authenticator.
	_, cookies := f.passwordStep(t, "state-for-the-recovery-after")
	verify := f.do(t, http.MethodGet, "/login/verify", nil, cookies)
	done := f.postForm(t, "/login/verify", url.Values{
		"csrf_token": {f.csrfFrom(t, verify)}, "code": {codes[0]},
	}, append(cookies, f.cookies(verify)...))
	if done.Code != http.StatusSeeOther {
		t.Fatalf("a recovery code = %d, body %s", done.Code, done.Body.String())
	}

	// The old session is gone.
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-after-the-recovery")
	if old := f.do(t, http.MethodGet, authorize, nil, oldCookies); !strings.HasPrefix(
		old.Header().Get("Location"), "/login") {
		t.Fatal("a session that predated a recovery code survived it; §7.2 requires " +
			"recovery to invalidate every session")
	}

	// So is the refresh token.
	if again := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
		"client_id": {f.client.ID},
	}, nil); again.Code == http.StatusOK {
		t.Fatal("a refresh token survived a recovery code; §7.2 requires those to go too")
	}

	// And the new session — the one the recovery code just created — works. This is the
	// race worth testing: the revocation marker and the new session are written moments
	// apart, and a session whose auth time does not beat the marker is dead on arrival.
	newCookies := f.cookies(done)
	fresh := f.do(t, http.MethodGet, authorize, nil, newCookies)
	location, err := url.Parse(fresh.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	if location.Query().Get("code") == "" {
		t.Fatalf("the session created by the recovery code was revoked by the same "+
			"recovery code (landed at %q)", location)
	}
}

// TestARecoveryCodeIsSingleUse.
func TestARecoveryCodeIsSingleUse(t *testing.T) {
	f := newOIDCFixture(t)
	f.enrolTOTP(t)
	codes := f.recoveryCodes(t)

	_, cookies := f.passwordStep(t, "state-for-the-single-use-one")
	verify := f.do(t, http.MethodGet, "/login/verify", nil, cookies)
	first := f.postForm(t, "/login/verify", url.Values{
		"csrf_token": {f.csrfFrom(t, verify)}, "code": {codes[0]},
	}, append(cookies, f.cookies(verify)...))
	if first.Code != http.StatusSeeOther {
		t.Fatalf("the first use = %d", first.Code)
	}

	_, again := f.passwordStep(t, "state-for-the-single-use-two")
	verifyAgain := f.do(t, http.MethodGet, "/login/verify", nil, again)
	second := f.postForm(t, "/login/verify", url.Values{
		"csrf_token": {f.csrfFrom(t, verifyAgain)}, "code": {codes[0]},
	}, append(again, f.cookies(verifyAgain)...))
	if second.Code == http.StatusSeeOther {
		t.Fatal("a recovery code was accepted twice")
	}
}

// TestGuessingTheSecondFactorIsRateLimited. Six digits is a million possibilities, which is
// nothing to a script — and whoever is guessing has already passed the password, so this is
// the last thing in the way.
func TestGuessingTheSecondFactorIsRateLimited(t *testing.T) {
	f := newOIDCFixture(t)
	f.enrolTOTP(t)

	_, cookies := f.passwordStep(t, "state-for-the-mfa-ratelimit")

	var limited bool
	for attempt := 1; attempt <= 12; attempt++ {
		verify := f.do(t, http.MethodGet, "/login/verify", nil, cookies)
		rec := f.postForm(t, "/login/verify", url.Values{
			"csrf_token": {f.csrfFrom(t, verify)}, "code": {"000000"},
		}, append(cookies, f.cookies(verify)...))

		if rec.Code == http.StatusTooManyRequests {
			limited = true
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("a 429 with no Retry-After")
			}
			break
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, body %s", attempt, rec.Code, rec.Body.String())
		}
	}
	if !limited {
		t.Fatal("twelve wrong codes were never rate limited")
	}
}

// TestAnEnrolmentIsNotAFactorUntilItIsConfirmed.
//
// Somebody who opens the enrolment page, scans the QR code and closes the tab has changed
// nothing. The alternative — a factor that becomes mandatory the moment it is generated —
// locks people out of their own accounts on a mis-click.
func TestAnEnrolmentIsNotAFactorUntilItIsConfirmed(t *testing.T) {
	f := newOIDCFixture(t)
	ctx := context.Background()

	if _, err := f.deps.Authn.EnrolTOTP(ctx, f.tenantID, f.userID, "Warden", f.email); err != nil {
		t.Fatalf("enrolling: %v", err)
	}

	has, err := f.deps.Authn.HasSecondFactor(ctx, f.tenantID, f.userID)
	if err != nil {
		t.Fatalf("checking: %v", err)
	}
	if has {
		t.Fatal("an unconfirmed enrolment counts as a second factor; somebody who closed " +
			"the tab would be locked out")
	}

	// And the login still completes in one step.
	_, challenge := pkcePair(t)
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, "state-for-the-unconfirmed")
	rec := f.do(t, http.MethodGet, authorize, nil, nil)
	loginURL := rec.Header().Get("Location")
	page := f.do(t, http.MethodGet, loginURL, nil, nil)
	done := f.postForm(t, "/login", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"return_to":  {f.returnToFrom(t, loginURL)},
		"email":      {f.email}, "password": {f.password},
	}, f.cookies(page))

	if location := done.Header().Get("Location"); location == "/login/verify" {
		t.Fatal("an unconfirmed enrolment sent the login to the verification page")
	}
}

// TestEnforcingAFactorNobodyHasIsRefused. Turning the requirement on for an account with
// nothing enrolled is a lockout waiting to happen, so it is refused where it is set rather
// than discovered at the next login.
func TestEnforcingAFactorNobodyHasIsRefused(t *testing.T) {
	f := newOIDCFixture(t)
	ctx := context.Background()

	err := f.deps.Authn.SetMFAEnforced(ctx, f.tenantID, f.userID, true)
	if err == nil {
		t.Fatal("enforcing a second factor on an account with none enrolled was accepted")
	}
}

// --- helpers -------------------------------------------------------------------------

// enrolTOTP enrols and confirms an authenticator, returning the shared secret.
func (f *oidcFixture) enrolTOTP(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	enrolment, err := f.deps.Authn.EnrolTOTP(ctx, f.tenantID, f.userID, "Warden", f.email)
	if err != nil {
		t.Fatalf("enrolling a second factor: %v", err)
	}

	// Confirmed with the *previous* step's code, which is inside the acceptance window
	// and leaves the current one unspent. Not a trick: RFC 6238 §5.2 says a code accepted
	// once is never accepted again, so confirming with the current code would correctly
	// refuse the sign-in that follows a second later — and every test here would be
	// testing the replay guard rather than what it means to test.
	step := uint64(time.Now().Unix()) / 30 //nolint:gosec // a test clock
	code, err := authn.TOTPCode(enrolment.Secret, step-1)
	if err != nil {
		t.Fatalf("computing a code: %v", err)
	}
	if confirmErr := f.deps.Authn.ConfirmTOTP(ctx, f.tenantID, f.userID, code); confirmErr != nil {
		t.Fatalf("confirming: %v", confirmErr)
	}
	return enrolment.Secret
}

// recoveryCodes issues a set and returns the plaintext.
func (f *oidcFixture) recoveryCodes(t *testing.T) []string {
	t.Helper()
	codes, err := f.deps.Authn.GenerateRecoveryCodes(context.Background(), f.tenantID, f.userID)
	if err != nil {
		t.Fatalf("generating recovery codes: %v", err)
	}
	return codes
}

// totpCode returns the code for right now.
func (f *oidcFixture) totpCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := authn.TOTPCode(secret, uint64(time.Now().Unix())/30) //nolint:gosec // a test clock
	if err != nil {
		t.Fatalf("computing a code: %v", err)
	}
	return code
}

// passwordStep completes the first factor and returns the authorize URL and the cookies the
// browser is left holding.
func (f *oidcFixture) passwordStep(t *testing.T, state string) (authorize string, cookies []*http.Cookie) {
	t.Helper()
	_, challenge := pkcePair(t)
	authorize = authorizeURL(f.client.ID, f.redirectURI, challenge, state)

	rec := f.do(t, http.MethodGet, authorize, nil, nil)
	loginURL := rec.Header().Get("Location")
	page := f.do(t, http.MethodGet, loginURL, nil, nil)

	afterPassword := f.postForm(t, "/login", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"return_to":  {f.returnToFrom(t, loginURL)},
		"email":      {f.email}, "password": {f.password},
	}, f.cookies(page))
	if afterPassword.Code != http.StatusSeeOther {
		t.Fatalf("the password step = %d, body %s", afterPassword.Code, afterPassword.Body.String())
	}
	return authorize, f.cookies(afterPassword)
}

// signInWithSecondFactor runs both steps and returns an authorization code.
func (f *oidcFixture) signInWithSecondFactor(
	t *testing.T, secret, challenge, state string,
) (code string, cookies []*http.Cookie) {
	t.Helper()
	authorize := authorizeURL(f.client.ID, f.redirectURI, challenge, state)

	rec := f.do(t, http.MethodGet, authorize, nil, nil)
	loginURL := rec.Header().Get("Location")
	page := f.do(t, http.MethodGet, loginURL, nil, nil)
	afterPassword := f.postForm(t, "/login", url.Values{
		"csrf_token": {f.csrfFrom(t, page)},
		"return_to":  {f.returnToFrom(t, loginURL)},
		"email":      {f.email}, "password": {f.password},
	}, f.cookies(page))
	pendingCookies := f.cookies(afterPassword)

	verify := f.do(t, http.MethodGet, "/login/verify", nil, pendingCookies)
	done := f.postForm(t, "/login/verify", url.Values{
		"csrf_token": {f.csrfFrom(t, verify)}, "code": {f.totpCode(t, secret)},
	}, append(pendingCookies, f.cookies(verify)...))
	if done.Code != http.StatusSeeOther {
		t.Fatalf("the second factor = %d, body %s", done.Code, done.Body.String())
	}
	cookies = f.cookies(done)

	authorized := f.do(t, http.MethodGet, authorize, nil, cookies)
	location, err := url.Parse(authorized.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing the redirect: %v", err)
	}
	code = location.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code after two factors: %q", location)
	}
	return code, cookies
}

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}
