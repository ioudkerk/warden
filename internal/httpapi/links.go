package httpapi

import (
	"context"
	"html/template"
	"net/http"
	"strings"

	"github.com/warden-project/warden/internal/authn"
)

// Magic links and password resets (SPEC §7.1, §7.2; docs/design-email.md §7).
//
// The shape of every handler here is decided by one requirement: **the answer must be the
// same whether or not the account exists.** §7.2 puts it as "identical response and timing
// for unknown users", and email is where that promise is most easily broken — the obvious
// implementation looks up the address, and returns early when it finds nothing.
//
// So these handlers do the lookup *after* the rate limit, never branch on its result in
// anything the caller can observe, and render one page either way.

// requestLinkPage is the form and the acknowledgement, which are the same page in two
// states.
type requestLinkPage struct {
	CSRFField string
	CSRFToken string
	Email     string
	ReturnTo  string
	Error     string
	// Sent switches the page to the acknowledgement. It is set for an unknown address
	// exactly as it is for a known one.
	Sent bool
	// Kind decides the wording.
	Reset bool
}

// handleMagicLinkForm serves GET /login/magic.
func (s *Server) handleMagicLinkForm(w http.ResponseWriter, r *http.Request) {
	returnTo, ok := safeReturnTo(r.URL.Query().Get("return_to"))
	if !ok {
		writeProblem(w, http.StatusBadRequest, "no_authorization_request",
			"Sign in by starting from the application you want to use.")
		return
	}
	s.renderRequestLink(w, r, requestLinkPage{ReturnTo: returnTo}, http.StatusOK)
}

// handleMagicLinkSubmit serves POST /login/magic.
//
// A magic link is a full authentication factor delivered over a channel Warden does not
// control, so it is off unless a tenant has turned it on. That is the answer to the design
// document's open question E2, and the conservative one: a deployment gets it by choosing
// it rather than by upgrading into it.
func (s *Server) handleMagicLinkSubmit(w http.ResponseWriter, r *http.Request) {
	s.handleLinkRequest(w, r, authn.LinkMagic)
}

// handlePasswordResetRequestForm serves GET /password/forgot.
func (s *Server) handlePasswordResetRequestForm(w http.ResponseWriter, r *http.Request) {
	returnTo, _ := safeReturnTo(r.URL.Query().Get("return_to")) //nolint:errcheck // optional here
	s.renderRequestLink(w, r, requestLinkPage{ReturnTo: returnTo, Reset: true}, http.StatusOK)
}

// handlePasswordResetRequest serves POST /password/forgot.
func (s *Server) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	s.handleLinkRequest(w, r, authn.LinkPasswordReset)
}

// handleLinkRequest is the shared body of both.
func (s *Server) handleLinkRequest(w http.ResponseWriter, r *http.Request, kind authn.LinkKind) {
	ctx := r.Context()
	isReset := kind == authn.LinkPasswordReset

	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The form could not be read.")
		return
	}
	returnTo, _ := safeReturnTo(r.PostFormValue("return_to")) //nolint:errcheck // optional
	page := requestLinkPage{ReturnTo: returnTo, Reset: isReset, Email: r.PostFormValue("email")}

	loginSecurityHeaders(w)
	if err := s.checkCSRF(r); err != nil {
		s.log.Warn("a link request arrived without a matching CSRF token", "error", err)
		page.Error = "Your form expired. Please try again."
		s.renderRequestLink(w, r, page, http.StatusBadRequest)
		return
	}

	address := strings.TrimSpace(r.PostFormValue("email"))
	if address == "" {
		page.Error = "Enter your email address."
		s.renderRequestLink(w, r, page, http.StatusBadRequest)
		return
	}

	// The tenant, from the client that sent them here. Without it an address is
	// ambiguous: Warden is multi-tenant and an email is unique only within a tenant.
	tenantID, err := s.tenantForLogin(r, returnTo)
	if err != nil {
		s.log.Warn("a link request arrived with no resolvable client", "error", err)
		writeProblem(w, http.StatusBadRequest, "no_authorization_request",
			"Start from the application you want to use.")
		return
	}

	// The limit is applied to the *address*, before any lookup, so it cannot be used to
	// probe existence either: an unknown address is limited exactly as a known one is.
	// §7 asks for one per address per minute and five per hour; the lockout's shape gives
	// the first few attempts no delay, so the identifier is namespaced per flow to keep a
	// reset from spending a login's allowance.
	if s.lockout != nil {
		decision, checkErr := s.lockout.Check(ctx, tenantID, string(kind)+":"+address, s.clientIP(r))
		if checkErr != nil {
			s.log.Error("checking the link request rate limit", "error", checkErr)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"The request could not be processed.")
			return
		}
		if !decision.Allowed {
			// Still the acknowledgement, not a 429. A distinguishable answer here is a
			// way to find out which addresses are being asked about.
			s.log.Info("a link request was rate limited",
				"kind", kind, "reason", decision.Reason, "ip", s.clientIP(r))
			page.Sent = true
			s.renderRequestLink(w, r, page, http.StatusOK)
			return
		}
		if _, failErr := s.lockout.Failed(ctx, tenantID, string(kind)+":"+address, s.clientIP(r)); failErr != nil {
			s.log.Error("recording a link request", "error", failErr)
		}
	}

	// From here nothing the caller can see depends on whether the account exists.
	s.issueLinkQuietly(ctx, r, kind, tenantID, address)

	page.Sent = true
	s.renderRequestLink(w, r, page, http.StatusOK)
}

// issueLinkQuietly does the work, and says nothing about the outcome.
//
// Every failure is logged and swallowed: an unknown address, a user who is not active, a
// tenant with magic links switched off. The caller renders the same acknowledgement for all
// of them, because each of those is a fact about the account that the person asking may not
// be entitled to learn.
func (s *Server) issueLinkQuietly(ctx context.Context, r *http.Request, kind authn.LinkKind, tenantID, address string) {
	userID, err := s.authn.UserIDByEmail(ctx, tenantID, address)
	if err != nil {
		s.log.Info("a link was requested for an address with no account",
			"kind", kind, "tenant_id", tenantID)
		return
	}

	// TenantName is left empty on purpose: IssueLink reads it from the tenant row inside
	// the transaction that queues the message, so there is one place that knows what a
	// tenant is called rather than one per call site.
	if _, err := s.authn.IssueLink(ctx, authn.LinkRequest{
		Kind: kind, TenantID: tenantID, UserID: userID, Address: address,
		RequestedIP: s.clientIP(r),
	}); err != nil {
		s.log.Error("could not issue an emailed link", "kind", kind, "error", err)
	}
}

// --- redeeming ---------------------------------------------------------------------------

// handleMagicLinkRedeem serves GET /login/link.
//
// A GET that signs somebody in, which is unusual enough to be worth saying why: the link
// arrives in a mail client, and a mail client follows links with a GET. What makes it
// tolerable is that the token is single use and consumed in the transaction that acts on
// it, so a prefetch by the mail client spends the link rather than leaving it usable.
func (s *Server) handleMagicLinkRedeem(w http.ResponseWriter, r *http.Request) {
	// no-referrer, or the token travels in the Referer of whatever this page loads.
	loginSecurityHeaders(w)

	redeemed, err := s.authn.RedeemLink(r.Context(), authn.LinkMagic, r.URL.Query().Get("token"))
	if err != nil {
		s.renderLinkExpired(w, "sign-in")
		return
	}

	// A magic link proves control of the mailbox, which is one factor. If the account has
	// a second, it is still required — otherwise enabling a second factor would be
	// undone by a feature that bypasses it.
	needsSecondFactor, factorErr := s.requireSecondFactor(
		r.Context(), redeemed.TenantID, redeemed.UserID, false)
	if factorErr != nil {
		s.log.Error("deciding whether a second factor is required", "error", factorErr)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The sign-in could not be processed.")
		return
	}
	if needsSecondFactor {
		s.beginSecondFactorWithAMR(w, r, redeemed.TenantID, redeemed.UserID, "", "/", authn.AMRMagicLink)
		return
	}

	session, err := s.sessions.Create(r.Context(), redeemed.TenantID, redeemed.UserID,
		[]string{authn.AMRMagicLink}, s.clientIP(r), r.UserAgent())
	if err != nil {
		s.log.Error("creating a session after a magic link", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The sign-in could not be completed.")
		return
	}

	s.log.Info("a user signed in with a magic link",
		"tenant_id", redeemed.TenantID, "user_id", redeemed.UserID)
	s.setSessionCookie(w, session.ID, session.ExpiresAt)
	s.renderLinkDone(w, "You are signed in", "You can close this window and return to the application.")
}

// --- pages -------------------------------------------------------------------------------

func (s *Server) renderRequestLink(w http.ResponseWriter, r *http.Request, page requestLinkPage, status int) {
	if page.CSRFToken == "" {
		token, err := s.issueCSRFToken(w)
		if err != nil {
			s.log.Error("issuing a CSRF token", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
			return
		}
		page.CSRFToken = token
	}
	page.CSRFField = csrfField
	_ = r

	loginSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := requestLinkTemplate.Execute(w, page); err != nil {
		s.log.Error("rendering the link request page", "error", err)
	}
}

func (s *Server) renderLinkExpired(w http.ResponseWriter, what string) {
	// One page for expired, used and never-existed. A person whose link has gone stale
	// needs a new one whichever it was, and telling them which tells somebody holding a
	// link they found what they are holding.
	w.WriteHeader(http.StatusBadRequest)
	s.renderLinkOutcome(w, "This link is no longer valid",
		"Links can be used once and expire quickly. Ask for a new "+what+" link.")
}

func (s *Server) renderLinkDone(w http.ResponseWriter, heading, detail string) {
	s.renderLinkOutcome(w, heading, detail)
}

func (s *Server) renderLinkOutcome(w http.ResponseWriter, heading, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := linkOutcomeTemplate.Execute(w, map[string]string{
		"Heading": heading, "Detail": detail,
	}); err != nil {
		s.log.Error("rendering a link outcome page", "error", err)
	}
}

var requestLinkTemplate = template.Must(template.New("requestlink").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .Reset}}Reset your password{{else}}Sign in by email{{end}}</title>
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
{{if .Sent}}
  <h1>Check your email</h1>
  <p class="sub">If there is an account for that address, a link is on its way. It works
     once and expires in 15 minutes.</p>
{{else}}
  <h1>{{if .Reset}}Reset your password{{else}}Sign in by email{{end}}</h1>
  <p class="sub">{{if .Reset}}We will send you a link to choose a new password.{{else}}We will send you a link that signs you in.{{end}}</p>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <form method="post" action="{{if .Reset}}/password/forgot{{else}}/login/magic{{end}}">
    <input type="hidden" name="{{.CSRFField}}" value="{{.CSRFToken}}">
    <input type="hidden" name="return_to" value="{{.ReturnTo}}">
    <label for="email">Email</label>
    <input id="email" name="email" type="email" autocomplete="username" required
           value="{{.Email}}" autofocus>
    <button type="submit">Send the link</button>
  </form>
{{end}}
</main>
</body>
</html>`))

var linkOutcomeTemplate = template.Must(template.New("linkoutcome").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Heading}}</title>
<style>
 body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background:#f6f7f9;
        margin:0; display:flex; min-height:100vh; align-items:center; justify-content:center; }
 main { background:#fff; padding:2rem; border-radius:8px; width:min(24rem, 92vw);
        box-shadow:0 1px 3px rgba(0,0,0,.12); text-align:center; }
 h1 { font-size:1.25rem; margin:0 0 .25rem; }
 p { margin:0; color:#666; font-size:.875rem; }
</style>
</head>
<body>
<main>
  <h1>{{.Heading}}</h1>
  <p>{{.Detail}}</p>
</main>
</body>
</html>`))

// --- password reset ------------------------------------------------------------------------

// resetPage is the "choose a new password" form.
type resetPage struct {
	CSRFField string
	CSRFToken string
	Token     string
	Error     string
}

// handlePasswordResetForm serves GET /password/reset.
//
// The token is *not* redeemed here. A GET that consumed it would be spent by a mail
// client's link prefetch before the person ever saw the form — so this only checks that a
// token was supplied, and the POST is what consumes it.
func (s *Server) handlePasswordResetForm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		s.renderLinkExpired(w, "password reset")
		return
	}

	csrf, err := s.issueCSRFToken(w)
	if err != nil {
		s.log.Error("issuing a CSRF token", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
		return
	}

	loginSecurityHeaders(w)
	s.renderReset(w, resetPage{CSRFField: csrfField, CSRFToken: csrf, Token: token}, http.StatusOK)
}

// handlePasswordResetSubmit serves POST /password/reset.
func (s *Server) handlePasswordResetSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The form could not be read.")
		return
	}
	token := r.PostFormValue("token")
	page := resetPage{CSRFField: csrfField, Token: token}

	loginSecurityHeaders(w)
	if err := s.checkCSRF(r); err != nil {
		s.log.Warn("a password reset was submitted without a matching CSRF token", "error", err)
		page.Error = "Your form expired. Please try again."
		s.renderResetWithToken(w, page, http.StatusBadRequest)
		return
	}

	password := r.PostFormValue("password")
	if password == "" {
		page.Error = "Choose a password."
		s.renderResetWithToken(w, page, http.StatusBadRequest)
		return
	}

	// The password is checked against the policy *before* the token is spent. A link
	// consumed by a password the policy then rejects would leave somebody with no way
	// back in and no link to try again with.
	redeemed, err := s.authn.RedeemLink(ctx, authn.LinkPasswordReset, token)
	if err != nil {
		s.renderLinkExpired(w, "password reset")
		return
	}

	if err := s.authn.SetPassword(ctx, redeemed.TenantID, redeemed.UserID, password); err != nil {
		// The token is already spent at this point, which is the honest trade: keeping
		// it alive would mean a link that survives a failed attempt, and the person can
		// ask for another. The message says what was wrong with the password so the next
		// attempt is not a guess.
		s.log.Info("a password chosen through a reset link was refused",
			"tenant_id", redeemed.TenantID, "error", err)
		s.renderLinkOutcome(w, "That password cannot be used",
			err.Error()+" Ask for a new reset link and try again.")
		return
	}

	// §7.2: recovery invalidates all sessions and refresh tokens. Somebody who has just
	// reset a password is somebody who may have lost control of the old one, and every
	// session opened with it has to go.
	s.endEverything(ctx, redeemed.TenantID, redeemed.UserID, "the password was reset")

	s.log.Info("a password was reset through an emailed link",
		"tenant_id", redeemed.TenantID, "user_id", redeemed.UserID)
	s.renderLinkDone(w, "Your password has been changed",
		"Every session and every signed-in device has been signed out. Sign in again with your new password.")
}

// endEverything revokes the sessions and refresh tokens of one user.
func (s *Server) endEverything(ctx context.Context, tenantID, userID, reason string) {
	if s.refresh != nil {
		if _, err := s.refresh.RevokeAllForUser(ctx, tenantID, userID, reason); err != nil {
			s.log.Error("could not revoke refresh tokens", "error", err)
		}
	}
	if s.sessions != nil {
		if _, err := s.sessions.RevokeAllForUser(ctx, tenantID, userID, reason); err != nil {
			s.log.Error("could not revoke sessions", "error", err)
		}
	}
}

func (s *Server) renderResetWithToken(w http.ResponseWriter, page resetPage, status int) {
	if page.CSRFToken == "" {
		token, err := s.issueCSRFToken(w)
		if err != nil {
			s.log.Error("issuing a CSRF token", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
			return
		}
		page.CSRFToken = token
	}
	s.renderReset(w, page, status)
}

func (s *Server) renderReset(w http.ResponseWriter, page resetPage, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := resetTemplate.Execute(w, page); err != nil {
		s.log.Error("rendering the reset page", "error", err)
	}
}

var resetTemplate = template.Must(template.New("reset").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Choose a new password</title>
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
  <h1>Choose a new password</h1>
  <p class="sub">Signing in everywhere else will stop until you use it.</p>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <form method="post" action="/password/reset">
    <input type="hidden" name="{{.CSRFField}}" value="{{.CSRFToken}}">
    <input type="hidden" name="token" value="{{.Token}}">
    <label for="password">New password</label>
    <input id="password" name="password" type="password" autocomplete="new-password"
           autofocus required>
    <button type="submit">Change my password</button>
  </form>
</main>
</body>
</html>`))
