package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/warden-project/warden/internal/authn"
)

// The second-factor step of the login (SPEC §7.1, §7.2).
//
// Between the password and the session there is now a gap, and something has to be held
// across it: the fact that somebody proved the first factor. It is deliberately *not* a
// session — a half-authenticated session that other code might mistake for a real one is
// the thing this design most needs to avoid — and deliberately not a signed cookie, because
// a signed cookie cannot be withdrawn once issued.
//
// So it is a short-lived record in the cache under a random identifier, and the browser
// holds the identifier. Revocable, expiring on its own, and worthless to anyone who has not
// already passed the password.

const (
	// pendingCookie carries the identifier of a half-finished login.
	pendingCookie            = "__Host-warden_pending"
	developmentPendingCookie = "warden_pending"

	// pendingLifetime is how long somebody has to reach for their phone. Five minutes is
	// generous for the task and short enough that an abandoned attempt on a shared
	// machine is not waiting there afterwards.
	pendingLifetime = 5 * time.Minute

	// pendingField is the form field the identifier is echoed in, for the case where the
	// cookie is unavailable.
	pendingCodeField = "code"
)

// pendingLogin is what survives between the two steps.
//
// It holds no credential: the password has already been verified and is not kept, and the
// second factor has not been presented yet. What it holds is an assertion — "this user
// passed the first factor at this time" — which is exactly as valuable as the identifier
// that names it, and no more.
type pendingLogin struct {
	TenantID  string    `json:"tid"`
	UserID    string    `json:"sub"`
	Email     string    `json:"email"`
	AMR       []string  `json:"amr"`
	ReturnTo  string    `json:"return_to"`
	StartedAt time.Time `json:"started_at"`
	IP        string    `json:"ip"`
}

func (s *Server) pendingCookieName() string {
	if s.secureCookies() {
		return pendingCookie
	}
	return developmentPendingCookie
}

// beginSecondFactor stores the half-finished login and sends the browser to the code page.
func (s *Server) beginSecondFactor(
	w http.ResponseWriter, r *http.Request, tenantID, userID, email, returnTo string,
) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		s.log.Error("generating a pending-login identifier", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The sign-in could not be continued.")
		return
	}
	id := base64.RawURLEncoding.EncodeToString(raw)

	pending := pendingLogin{
		TenantID: tenantID, UserID: userID, Email: email,
		AMR:      []string{authn.AMRPassword},
		ReturnTo: returnTo, StartedAt: time.Now().UTC(), IP: s.clientIP(r),
	}
	encoded, err := json.Marshal(pending)
	if err != nil {
		s.log.Error("encoding a pending login", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The sign-in could not be continued.")
		return
	}
	if err := s.cache.Set(r.Context(), pendingKey(id), encoded, pendingLifetime); err != nil {
		s.log.Error("storing a pending login", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The sign-in could not be continued.")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: s.pendingCookieName(), Value: id, Path: "/",
		// Strict: this cookie is only ever read by a form Warden served, so no
		// cross-site navigation legitimately needs it.
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		MaxAge:   int(pendingLifetime.Seconds()),
	})

	s.log.Info("a password was accepted and a second factor is required",
		"tenant_id", tenantID, "user_id", userID)
	http.Redirect(w, r, "/login/verify", http.StatusSeeOther)
}

// currentPending reads the half-finished login the browser is carrying.
func (s *Server) currentPending(r *http.Request) (*pendingLogin, string, bool) {
	cookie, err := r.Cookie(s.pendingCookieName())
	if err != nil || cookie.Value == "" {
		return nil, "", false
	}
	raw, err := s.cache.Get(r.Context(), pendingKey(cookie.Value))
	if err != nil {
		// Expired, revoked, or never existed. All three mean "start again".
		return nil, "", false
	}
	var pending pendingLogin
	if err := json.Unmarshal(raw, &pending); err != nil {
		s.log.Error("a stored pending login could not be parsed", "error", err)
		return nil, "", false
	}
	return &pending, cookie.Value, true
}

// handleSecondFactorForm serves GET /login/verify.
func (s *Server) handleSecondFactorForm(w http.ResponseWriter, r *http.Request) {
	pending, _, ok := s.currentPending(r)
	if !ok {
		// Nothing half-finished. Sending them to /login with no authorization request
		// would be a dead end, so this says what happened.
		loginSecurityHeaders(w)
		writeProblem(w, http.StatusBadRequest, "no_pending_login",
			"Your sign-in has expired. Start again from the application you want to use.")
		return
	}

	token, err := s.issueCSRFToken(w)
	if err != nil {
		s.log.Error("issuing a CSRF token", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
		return
	}

	hasKey := s.securityKeyAvailable(r, pending.TenantID, pending.UserID)
	if hasKey {
		s.scriptedSecurityHeaders(w)
	} else {
		loginSecurityHeaders(w)
	}
	s.renderSecondFactor(w, secondFactorPage{
		CSRFField: csrfField, CSRFToken: token,
		Email: pending.Email, HasSecurityKey: hasKey,
	}, http.StatusOK)
}

// handleSecondFactorSubmit serves POST /login/verify.
func (s *Server) handleSecondFactorSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The form could not be read.")
		return
	}
	pending, pendingID, ok := s.currentPending(r)
	if !ok {
		loginSecurityHeaders(w)
		writeProblem(w, http.StatusBadRequest, "no_pending_login",
			"Your sign-in has expired. Start again from the application you want to use.")
		return
	}

	loginSecurityHeaders(w)
	if err := s.checkCSRF(r); err != nil {
		s.log.Warn("a second factor was submitted without a matching CSRF token", "error", err)
		s.renderSecondFactorError(w, pending.Email,
			"Your sign-in form expired. Please try again.", http.StatusBadRequest)
		return
	}

	// The limiter matters more here than at the password step. A six-digit code is a
	// million possibilities, which is nothing to a script — and whoever is guessing has
	// already passed the password, so this is the last thing between them and the
	// account. Keyed on the user rather than the address they typed, because by this
	// point the account is known.
	ip := s.clientIP(r)
	limitKey := "second_factor:" + pending.UserID
	if s.lockout != nil {
		decision, checkErr := s.lockout.Check(ctx, pending.TenantID, limitKey, ip)
		if checkErr != nil {
			s.log.Error("checking the second-factor rate limit", "error", checkErr)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"The sign-in could not be processed.")
			return
		}
		if !decision.Allowed {
			seconds := int(decision.RetryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
			s.renderSecondFactorError(w, pending.Email,
				"Too many attempts. Please wait a moment and try again.",
				http.StatusTooManyRequests)
			return
		}
	}

	code := r.PostFormValue(pendingCodeField)
	method, err := s.authn.VerifySecondFactor(ctx, pending.TenantID, pending.UserID, code)
	if err != nil {
		if s.lockout != nil {
			if _, failErr := s.lockout.Failed(ctx, pending.TenantID, limitKey, ip); failErr != nil {
				s.log.Error("recording a failed second factor", "error", failErr)
			}
		}
		if !errors.Is(err, authn.ErrInvalidSecondFactor) && !errors.Is(err, authn.ErrNoSecondFactor) {
			s.log.Error("verifying a second factor", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"The sign-in could not be processed.")
			return
		}
		s.log.Info("a second factor was refused",
			"tenant_id", pending.TenantID, "user_id", pending.UserID)
		s.renderSecondFactorError(w, pending.Email,
			"That code is not right. Try the current code from your authenticator, or a recovery code.",
			http.StatusUnauthorized)
		return
	}

	if s.lockout != nil {
		if clearErr := s.lockout.Succeeded(ctx, pending.TenantID, limitKey, ip); clearErr != nil {
			s.log.Warn("clearing the second-factor rate limit", "error", clearErr)
		}
	}

	destination, ok := s.completeSecondFactor(w, r, pending, pendingID, method)
	if !ok {
		return
	}
	http.Redirect(w, r, destination, http.StatusSeeOther)
}

// completeSecondFactor spends the pending login and creates the session.
//
// Shared by the code form and by WebAuthn, because the part that must not differ between
// them is exactly this part: which record is spent, what `amr` says, and the fact that the
// session is created once and only after a factor has been verified.
func (s *Server) completeSecondFactor(
	w http.ResponseWriter, r *http.Request, pending *pendingLogin, pendingID, method string,
) (destination string, ok bool) {
	ctx := r.Context()

	// Spent first: the pending record is single use, whatever happens next. Removed
	// before the session is created so that a failure after this point cannot leave a
	// usable one behind.
	if delErr := s.cache.Delete(ctx, pendingKey(pendingID)); delErr != nil {
		s.log.Warn("could not remove a spent pending login", "error", delErr)
	}
	s.clearPendingCookie(w)

	amr := append(append([]string{}, pending.AMR...), method, authn.AMRMFA)
	session, err := s.sessions.Create(ctx, pending.TenantID, pending.UserID, amr,
		s.clientIP(r), r.UserAgent())
	if err != nil {
		s.log.Error("creating a session after a second factor", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The sign-in could not be completed.")
		return "", false
	}

	s.log.Info("a user signed in with a second factor",
		"tenant_id", pending.TenantID, "user_id", pending.UserID, "method", method)

	s.setSessionCookie(w, session.ID, session.ExpiresAt)
	return pending.ReturnTo, true
}

func (s *Server) clearPendingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.pendingCookieName(), Value: "", Path: "/",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		MaxAge:   -1,
	})
}

func pendingKey(id string) string { return "warden:pending_login:" + id }

// requireSecondFactor decides whether a password alone is enough.
//
// Enrolment is the signal, not only the `mfa_enforced` flag: somebody who set up an
// authenticator expects to be asked for it, and a login that skipped the factor because a
// tenant setting was off would be a factor in name only. The flag is what makes it
// mandatory — it is checked separately, because "has one" and "must have one" fail
// differently.
func (s *Server) requireSecondFactor(
	ctx context.Context, tenantID, userID string, enforced bool,
) (required bool, err error) {
	has, err := s.authn.HasSecondFactor(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	if has {
		return true, nil
	}
	if enforced {
		// Required and impossible. Nothing good happens next, but signing them in would
		// be worse: the tenant has said this account needs a second factor and it does
		// not have one.
		return false, errMFAEnforcedWithoutFactor
	}
	return false, nil
}

var errMFAEnforcedWithoutFactor = errors.New(
	"this account requires a second factor and has none enrolled")

// --- the page --------------------------------------------------------------------------

type secondFactorPage struct {
	CSRFField string
	CSRFToken string
	Email     string
	Error     string
	// HasSecurityKey decides whether the page offers the button at all. A button that
	// prompts for a key the account does not have is a dead end somebody will press
	// first, every time.
	HasSecurityKey bool
	Script         template.JS
}

func (s *Server) renderSecondFactor(w http.ResponseWriter, page secondFactorPage, status int) {
	if page.HasSecurityKey {
		page.Script = template.JS(webAuthnScript) //nolint:gosec // a compile-time constant, hashed into the CSP
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := secondFactorTemplate.Execute(w, page); err != nil {
		s.log.Error("rendering the second-factor page", "error", err)
	}
}

// securityKeyAvailable reports whether this account has a key to be asked for.
func (s *Server) securityKeyAvailable(r *http.Request, tenantID, userID string) bool {
	factors, err := s.authn.Factors(r.Context(), tenantID, userID)
	if err != nil {
		s.log.Error("listing second factors", "error", err)
		return false
	}
	for _, factor := range factors {
		if factor.Type == authn.FactorWebAuthn && factor.Confirmed {
			return true
		}
	}
	return false
}

func (s *Server) renderSecondFactorError(w http.ResponseWriter, email, message string, status int) {
	token, err := s.issueCSRFToken(w)
	if err != nil {
		s.log.Error("issuing a CSRF token", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
		return
	}
	s.renderSecondFactor(w, secondFactorPage{
		CSRFField: csrfField, CSRFToken: token, Email: email, Error: message,
	}, status)
}

// secondFactorTemplate follows the login page: no external anything, and inputmode set so a
// phone offers a number pad for six digits without forbidding a recovery code's letters.
var secondFactorTemplate = template.Must(template.New("verify").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Two-step verification</title>
<style>
 body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background:#f6f7f9;
        margin:0; display:flex; min-height:100vh; align-items:center; justify-content:center; }
 main { background:#fff; padding:2rem; border-radius:8px; width:min(24rem, 92vw);
        box-shadow:0 1px 3px rgba(0,0,0,.12); }
 h1 { font-size:1.25rem; margin:0 0 .25rem; }
 p.sub { margin:0 0 1.5rem; color:#666; font-size:.875rem; }
 label { display:block; font-size:.8125rem; font-weight:600; margin-bottom:.25rem; }
 input { width:100%; padding:.5rem; margin-bottom:1rem; border:1px solid #ccc;
         border-radius:4px; font-size:1.125rem; box-sizing:border-box; letter-spacing:.15em; }
 button { width:100%; padding:.625rem; background:#1a1a2e; color:#fff; border:0;
          border-radius:4px; font-size:1rem; cursor:pointer; }
 .error { background:#fdecec; border:1px solid #f5c2c2; color:#8a1f1f; padding:.625rem;
          border-radius:4px; font-size:.875rem; margin-bottom:1rem; }
 .hint { color:#666; font-size:.8125rem; margin:0; }
 button.key { background:#fff; color:#1a1a2e; border:1px solid #1a1a2e; margin-bottom:.75rem; }
 .divider { text-align:center; color:#999; font-size:.8125rem; margin:0 0 .75rem; }
 .status { background:#eef2ff; border:1px solid #c7d2fe; color:#1e3a8a; padding:.625rem;
           border-radius:4px; font-size:.875rem; margin-bottom:1rem; }
</style>
</head>
<body>
<main>
  <h1>Two-step verification</h1>
  <p class="sub">{{.Email}}</p>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  {{if .HasSecurityKey}}
  <input type="hidden" id="wa-csrf" value="{{.CSRFToken}}">
  <button type="button" id="wa-signin" class="key">Use a security key</button>
  <div id="wa-status" class="status" hidden></div>
  <p class="divider">or</p>
  {{end}}
  <form method="post" action="/login/verify">
    <input type="hidden" name="{{.CSRFField}}" value="{{.CSRFToken}}">
    <label for="code">Code</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
           autofocus required>
    <button type="submit">Verify</button>
  </form>
  <p class="hint">Enter the code from your authenticator, or one of your recovery codes.</p>
</main>
{{if .HasSecurityKey}}<script>{{.Script}}</script>{{end}}
</body>
</html>`))
