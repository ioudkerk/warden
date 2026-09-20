package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/warden-project/warden/internal/authn"
)

// The interactive login: the one page in Warden a person actually looks at.
//
// It exists to serve the authorization endpoint. A client sends the browser to
// /oauth2/authorize, that finds no session, and the browser arrives here; once a
// password (and later a second factor) has been accepted, a session is created and the
// browser goes back to where it came from, which now succeeds.

const (
	// sessionCookie carries the sid. The __Host- prefix is a browser-enforced
	// guarantee: a cookie so named must be Secure, must have no Domain, and must be
	// path "/", which together mean a subdomain cannot set or overwrite it. That last
	// part is the one that matters — without it, anything on a sibling subdomain can
	// fixate a session.
	sessionCookie = "__Host-warden_session"

	// csrfCookie is the other half of the double-submit pair (SPEC §17).
	csrfCookie = "__Host-warden_csrf"

	// csrfField is the form field the token is echoed in.
	csrfField = "csrf_token"
)

// developmentSessionCookie is used where the __Host- prefix cannot be: it requires
// Secure, and a developer on http://localhost has no certificate. The name changes with
// it so that a cookie set in development is never mistaken for one with the guarantees.
const (
	developmentSessionCookie = "warden_session"
	developmentCSRFCookie    = "warden_csrf"
)

// cookieNames returns the pair appropriate to the deployment's posture.
func (s *Server) cookieNames() (session, csrf string) {
	if s.secureCookies() {
		return sessionCookie, csrfCookie
	}
	return developmentSessionCookie, developmentCSRFCookie
}

// secureCookies reports whether cookies may carry the Secure attribute.
//
// Tied to the issuer rather than to the environment setting, because that is the thing
// that decides whether the browser will accept them: a Secure cookie set over http is
// silently dropped, and a login that silently fails to persist is a loop nobody can
// debug from the outside.
// Config already refuses a plaintext issuer outside development, so in production this
// is always true; the check is here so that a development deployment on localhost gets
// cookies a browser will actually keep.
func (s *Server) secureCookies() bool {
	return strings.HasPrefix(s.cfg.Issuer, "https://")
}

// setSessionCookie stores the sid.
func (s *Server) setSessionCookie(w http.ResponseWriter, sid string, expires time.Time) {
	name, _ := s.cookieNames()
	http.SetCookie(w, &http.Cookie{
		Name:  name,
		Value: sid,
		Path:  "/",
		// Lax, not Strict. The authorization endpoint is reached by a top-level
		// navigation from the client's site, and Strict would withhold the cookie on
		// exactly that request — the user would appear logged out every time a client
		// sent them to log in.
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		Expires:  expires,
	})
}

// currentSession resolves the browser's session, if it has a valid one.
func (s *Server) currentSession(r *http.Request) (*authn.Session, bool) {
	if s.sessions == nil {
		return nil, false
	}
	name, _ := s.cookieNames()
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	session, err := s.sessions.Validate(r.Context(), cookie.Value)
	if err != nil {
		return nil, false
	}
	return session, true
}

// --- CSRF ---------------------------------------------------------------------------

// issueCSRFToken sets the cookie half of the double-submit pair and returns the value to
// put in the form.
//
// Double-submit rather than a server-stored token: the value in the cookie and the value
// in the form must match, and a cross-site attacker can cause the cookie to be sent but
// cannot read it in order to populate the form. It needs no state, which matters for an
// endpoint that must work on any replica.
func (s *Server) issueCSRFToken(w http.ResponseWriter) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating a CSRF token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	_, name := s.cookieNames()
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: token, Path: "/",
		// Strict is right here and Lax is not: this cookie is only ever read by a form
		// posted from Warden's own page, so there is no cross-site navigation that
		// legitimately needs it.
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		MaxAge:   int((15 * time.Minute).Seconds()),
	})
	return token, nil
}

// checkCSRFHeader is checkCSRF for a request whose body is not a form.
//
// The WebAuthn endpoints carry a browser-built JSON document, so there is no field to put a
// token in and the token travels in a header instead.
//
// Belt and braces, deliberately. A cross-origin POST cannot set a custom header without a
// preflight, and the preflight fails because Warden sends no CORS headers — so those
// endpoints are already out of reach of a forged request. This is the second lock: it holds
// if a future change ever adds a permissive CORS policy, which is exactly the kind of change
// that is made for one endpoint and quietly applies to all of them.
func (s *Server) checkCSRFHeader(r *http.Request) error {
	_, name := s.cookieNames()
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return errors.New("no CSRF cookie: the page was not served by this deployment, or the cookie was dropped")
	}
	submitted := r.Header.Get(csrfHeader)
	if submitted == "" {
		return errors.New("the request carried no CSRF token")
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(submitted)) != 1 {
		return errors.New("the CSRF token does not match the cookie")
	}
	return nil
}

// csrfHeader is where a scripted request carries the double-submit token.
const csrfHeader = "X-Warden-Csrf"

// checkCSRF compares the submitted token with the cookie.
func (s *Server) checkCSRF(r *http.Request) error {
	_, name := s.cookieNames()
	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return errors.New("no CSRF cookie: the form was not served by this deployment, or the cookie was dropped")
	}
	submitted := r.PostFormValue(csrfField)
	if submitted == "" {
		return errors.New("the form carried no CSRF token")
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(submitted)) != 1 {
		return errors.New("the CSRF token does not match the cookie")
	}
	return nil
}

// --- the return-to target -------------------------------------------------------------

// safeReturnTo validates where the browser may be sent after logging in.
//
// Only a path on this deployment, and only one of the endpoints that make sense as a
// destination. An unvalidated return_to is an open redirect (SPEC §17) and a login page
// is the most valuable place to have one: the victim has just typed a password, and the
// attacker chooses where they land.
func safeReturnTo(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	// Reject anything that could be read as a scheme or an authority. "//evil.test" is
	// a protocol-relative URL, and a browser follows it off-site.
	if strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "", false
	}
	// An allowlist of destinations, not a shape test. Both are pages a person reaches
	// mid-flow and must come back to after signing in; anything else is somebody's idea
	// of where the browser should land after a password has been typed.
	if parsed.Path != devicePath && !strings.HasPrefix(parsed.Path, "/oauth2/authorize") {
		return "", false
	}
	return parsed.String(), true
}

// --- the page ---------------------------------------------------------------------

// loginTemplate is deliberately plain and self-contained.
//
// No external stylesheet, no font, no script: the content security policy below forbids
// them, and a login page that depends on a third-party origin hands that origin the
// ability to modify the form it is typed into. The console (M6) will have something
// prettier; this has to be correct.
var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
 body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background:#f6f7f9;
        margin:0; display:flex; min-height:100vh; align-items:center; justify-content:center; }
 main { background:#fff; padding:2rem; border-radius:8px; width:min(24rem, 92vw);
        box-shadow:0 1px 3px rgba(0,0,0,.12); }
 h1 { font-size:1.25rem; margin:0 0 .25rem; }
 p.sub { margin:0 0 1.5rem; color:#666; font-size:.875rem; }
 label { display:block; font-size:.8125rem; font-weight:600; margin-bottom:.25rem; }
 input { width:100%; padding:.5rem; margin-bottom:1rem; border:1px solid #ccc;
         border-radius:4px; font-size:1rem; box-sizing:border-box; }
 button { width:100%; padding:.625rem; background:#1a1a2e; color:#fff; border:0;
          border-radius:4px; font-size:1rem; cursor:pointer; }
 .error { background:#fdecec; border:1px solid #f5c2c2; color:#8a1f1f; padding:.625rem;
          border-radius:4px; font-size:.875rem; margin-bottom:1rem; }
</style>
</head>
<body>
<main>
  <h1>Sign in</h1>
  <p class="sub">{{.ClientName}}</p>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <form method="post" action="/login">
    <input type="hidden" name="{{.CSRFField}}" value="{{.CSRFToken}}">
    <input type="hidden" name="return_to" value="{{.ReturnTo}}">
    <label for="email">Email</label>
    <input id="email" name="email" type="email" autocomplete="username" required
           value="{{.Email}}" autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
</main>
</body>
</html>`))

type loginPage struct {
	ClientName string
	ReturnTo   string
	CSRFField  string
	CSRFToken  string
	Email      string
	Error      string
}

// loginSecurityHeaders applies the protections SPEC §17 names for Warden-served UI.
func loginSecurityHeaders(w http.ResponseWriter) {
	// frame-ancestors 'none' is the clickjacking defence §17 asks for by name. The rest
	// closes the page to anything it does not serve itself: a login form that can load
	// a remote script is a login form whose password field belongs to someone else.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The token travels in the query string of the page this form posts back to, so a
	// referrer would carry it to whatever the next page loads.
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}

// handleLoginForm renders the sign-in page.
func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	returnTo, ok := safeReturnTo(r.URL.Query().Get("return_to"))
	if !ok {
		// Arriving here directly rather than from an authorization request. There is
		// nowhere to send them afterwards, and inventing a destination is how an open
		// redirect gets added later.
		writeProblem(w, http.StatusBadRequest, "no_authorization_request",
			"Sign in by starting from the application you want to use.")
		return
	}

	token, err := s.issueCSRFToken(w)
	if err != nil {
		s.log.Error("issuing a CSRF token", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
		return
	}

	loginSecurityHeaders(w)
	s.renderLogin(w, loginPage{
		ClientName: s.clientNameFor(r, returnTo),
		ReturnTo:   returnTo,
		CSRFField:  csrfField,
		CSRFToken:  token,
		Email:      r.URL.Query().Get("email"),
	}, http.StatusOK)
}

func (s *Server) renderLogin(w http.ResponseWriter, page loginPage, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := loginTemplate.Execute(w, page); err != nil {
		s.log.Error("rendering the login page", "error", err)
	}
}

// clientNameFor looks up the display name of the client the login is for, so the page
// says what the user is signing in to rather than just "sign in".
func (s *Server) clientNameFor(r *http.Request, returnTo string) string {
	parsed, err := url.Parse(returnTo)
	if err != nil {
		return ""
	}
	clientID := parsed.Query().Get("client_id")
	if clientID == "" || s.provider == nil {
		return ""
	}
	client, err := s.provider.Storage().Clients().Lookup(r.Context(), clientID)
	if err != nil {
		return ""
	}
	return client.Name
}

// handleLoginSubmit authenticates and starts a session.
func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The form could not be read.")
		return
	}

	returnTo, ok := safeReturnTo(r.PostFormValue("return_to"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "no_authorization_request",
			"Sign in by starting from the application you want to use.")
		return
	}

	loginSecurityHeaders(w)

	if err := s.checkCSRF(r); err != nil {
		// Not a login failure: the request did not come from the form. Say so plainly
		// rather than reporting bad credentials, which would send the user round a
		// loop they cannot escape by typing more carefully.
		s.log.Warn("a login was submitted without a matching CSRF token", "error", err)
		s.renderLoginError(w, r, returnTo, "",
			"Your sign-in form expired. Please try again.", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	if email == "" || password == "" {
		s.renderLoginError(w, r, returnTo, email,
			"Enter your email address and password.", http.StatusBadRequest)
		return
	}

	tenantID, err := s.tenantForLogin(r, returnTo)
	if err != nil {
		s.log.Warn("a login arrived for an unresolvable client", "error", err)
		writeProblem(w, http.StatusBadRequest, "no_authorization_request",
			"Sign in by starting from the application you want to use.")
		return
	}

	ip := s.clientIP(r)

	// The limiter runs before the password is checked, which is the point of having
	// one: the expensive verification should not happen for an attempt that is already
	// refused.
	if s.lockout != nil {
		decision, checkErr := s.lockout.Check(r.Context(), tenantID, email, ip)
		if checkErr != nil {
			s.log.Error("checking the login rate limit", "error", checkErr)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"The sign-in could not be processed.")
			return
		}
		if !decision.Allowed {
			s.tooManyAttempts(w, r, returnTo, email, decision)
			return
		}
	}

	result, authErr := s.authn.Authenticate(r.Context(), tenantID, email, password)
	if authErr != nil {
		if !errors.Is(authErr, authn.ErrInvalidCredentials) {
			s.log.Error("authenticating", "error", authErr)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"The sign-in could not be processed.")
			return
		}
		if s.lockout != nil {
			if _, failErr := s.lockout.Failed(r.Context(), tenantID, email, ip); failErr != nil {
				s.log.Error("recording a failed login", "error", failErr)
			}
		}
		// One message for every cause, matching authn.ErrInvalidCredentials. The page
		// must not distinguish an unknown address from a wrong password any more than
		// the timing does.
		s.renderLoginError(w, r, returnTo, email,
			"That email address and password do not match.", http.StatusUnauthorized)
		return
	}

	if s.lockout != nil {
		if clearErr := s.lockout.Succeeded(r.Context(), tenantID, email, ip); clearErr != nil {
			s.log.Warn("clearing the login rate limit", "error", clearErr)
		}
	}

	// The password was right, which is not the same as being signed in. If this account
	// has a second factor the login stops here and continues at /login/verify; no session
	// exists until the second factor is presented, because a half-authenticated session is
	// the thing another piece of code would eventually mistake for a real one.
	needsSecondFactor, factorErr := s.requireSecondFactor(
		r.Context(), tenantID, result.UserID, result.MFAEnforced)
	if factorErr != nil {
		if errors.Is(factorErr, errMFAEnforcedWithoutFactor) {
			// Required and impossible. Refusing is the only honest answer: the tenant has
			// said this account needs a second factor and it has none, so signing them in
			// would quietly ignore the policy.
			s.log.Error("a user requires a second factor and has none enrolled",
				"tenant_id", tenantID, "user_id", result.UserID)
			s.renderLoginError(w, r, returnTo, email,
				"This account requires two-step verification, which has not been set up. "+
					"Ask an administrator to help you enrol.", http.StatusForbidden)
			return
		}
		s.log.Error("deciding whether a second factor is required", "error", factorErr)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The sign-in could not be processed.")
		return
	}
	if needsSecondFactor {
		s.beginSecondFactor(w, r, tenantID, result.UserID, email, returnTo)
		return
	}

	session, err := s.sessions.Create(r.Context(), tenantID, result.UserID,
		[]string{authn.AMRPassword}, ip, r.UserAgent())
	if err != nil {
		s.log.Error("creating a session", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The sign-in could not be completed.")
		return
	}

	s.setSessionCookie(w, session.ID, session.ExpiresAt)
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// tooManyAttempts answers a rate-limited login.
//
// 429 with Retry-After, which is what SPEC §17 asks for. The page says the same thing
// whichever counter was hit: telling a client which limit it reached describes the shape
// of the defence, and telling it that the *account* is capped confirms the account
// exists.
func (s *Server) tooManyAttempts(w http.ResponseWriter, r *http.Request, returnTo, email string, d authn.Decision) {
	seconds := int(d.RetryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))

	s.log.Info("a login was rate limited",
		"reason", d.Reason, "retry_after", d.RetryAfter, "ip", s.clientIP(r))
	if s.metrics != nil {
		s.metrics.AuthFailures.Inc()
	}

	s.renderLoginError(w, r, returnTo, email,
		"Too many sign-in attempts. Please wait a moment and try again.",
		http.StatusTooManyRequests)
}

// renderLoginError redraws the form with a message, issuing a fresh CSRF token because
// the previous one has been spent.
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, returnTo, email, message string, status int) {
	token, err := s.issueCSRFToken(w)
	if err != nil {
		s.log.Error("issuing a CSRF token", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
		return
	}
	s.renderLogin(w, loginPage{
		ClientName: s.clientNameFor(r, returnTo),
		ReturnTo:   returnTo,
		CSRFField:  csrfField,
		CSRFToken:  token,
		Email:      email,
		Error:      message,
	}, status)
}

// tenantForLogin resolves which tenant the credentials belong to.
//
// From the client in the authorization request, which is the only honest source: Warden
// is multi-tenant and an email address is unique only within a tenant, so "log in as
// maria@acme.test" is ambiguous until the client says which deployment tenant it is
// acting for.
func (s *Server) tenantForLogin(r *http.Request, returnTo string) (string, error) {
	if s.provider == nil {
		return "", errors.New("this process does not serve the OpenID Provider")
	}
	parsed, err := url.Parse(returnTo)
	if err != nil {
		return "", err
	}

	// The device verification page is the other way in, and it has no client: the person
	// typed a code off a screen, and that code is the only thing that says which tenant
	// they belong to.
	if parsed.Path == devicePath {
		return s.tenantForDeviceLogin(r, parsed.Query().Get("user_code")), nil
	}

	clientID := parsed.Query().Get("client_id")
	if clientID == "" {
		return "", errors.New("the authorization request names no client")
	}
	return s.provider.Storage().Clients().TenantOf(r.Context(), clientID)
}

// tenantForDeviceLogin resolves a typed user code to the tenant to authenticate against.
//
// An unresolvable code is not an error here, and that is the point. Refusing it — or
// rendering a different page for it — would make the login form an oracle for which user
// codes exist, and a code short enough to be typed is short enough to be enumerated. So a
// code that resolves to nothing authenticates against a tenant that does not exist, where
// the credential check does its usual constant work and fails exactly as a wrong password
// does.
func (s *Server) tenantForDeviceLogin(r *http.Request, typed string) string {
	tenantID, err := s.provider.Storage().TenantOfUserCode(r.Context(), typed)
	if err != nil {
		s.log.Debug("a device verification login named no resolvable user code", "error", err)
		return unknownTenantID
	}
	return tenantID
}

// unknownTenantID is a syntactically valid tenant that no row can belong to. Used where
// a lookup failed but the answer must be indistinguishable from a wrong password.
const unknownTenantID = "ten_no_such_tenant"

// clientIP returns the address the request came from, honouring X-Forwarded-For only
// from proxies the operator has listed.
//
// An unlisted proxy's header is ignored rather than trusted, because context.ip feeds
// authorization conditions (SPEC §9.6) and rate limiting: a spoofable address is a way
// to reset somebody else's backoff, or to avoid one's own.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !s.trustedProxy(host) {
		return host
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return host
	}
	// The left-most entry is the original client; the rest were added by proxies.
	first, _, _ := strings.Cut(forwarded, ",")
	if candidate := strings.TrimSpace(first); candidate != "" {
		return candidate
	}
	return host
}

func (s *Server) trustedProxy(host string) bool {
	if s.cfg == nil || len(s.cfg.HTTP.TrustedProxyCIDRs) == 0 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, raw := range s.cfg.HTTP.TrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// requireLogin refuses the login routes when the process cannot serve them.
func (s *Server) requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authn == nil || s.sessions == nil || s.provider == nil {
			writeProblem(w, http.StatusServiceUnavailable, "login_unavailable",
				"This process does not serve interactive login. It needs the cache tier, "+
					"database.system_url and a signing key.")
			return
		}
		next(w, r)
	}
}
