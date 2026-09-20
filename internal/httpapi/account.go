package httpapi

import (
	"html/template"
	"net/http"

	"github.com/warden-project/warden/internal/authn"
)

// The one page a signed-in person has of their own: their second factors.
//
// The console of M6 will own this properly, with the rest of an account's settings. It
// exists now because a security key cannot be enrolled from a command line — the enrolment
// *is* a browser API call — so without a page there is no way to register one at all, and a
// factor nobody can enrol is a feature that only exists in tests.

// handleAccountSecurity serves GET /account/security.
func (s *Server) handleAccountSecurity(w http.ResponseWriter, r *http.Request) {
	session, ok := s.currentSession(r)
	if !ok {
		// No authorization request to come back to, so this cannot use the login
		// redirect: it says what to do instead.
		loginSecurityHeaders(w)
		writeProblem(w, http.StatusUnauthorized, "unauthenticated",
			"Sign in first, then open this page again.")
		return
	}

	factors, err := s.authn.Factors(r.Context(), session.TenantID, session.UserID)
	if err != nil {
		s.log.Error("listing second factors", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The page could not be served.")
		return
	}
	remaining, err := s.authn.RemainingRecoveryCodes(r.Context(), session.TenantID, session.UserID)
	if err != nil {
		s.log.Error("counting recovery codes", "error", err)
		remaining = -1
	}

	token, err := s.issueCSRFToken(w)
	if err != nil {
		s.log.Error("issuing a CSRF token", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
		return
	}

	page := accountSecurityPage{
		CSRFToken:       token,
		RecoveryCodes:   remaining,
		WebAuthnOffered: s.webAuthnOffered(),
		Script:          template.JS(webAuthnScript), //nolint:gosec // a compile-time constant, hashed into the CSP
	}
	for _, factor := range factors {
		if factor.Type == authn.FactorRecoveryCode {
			continue // counted, not listed ten times
		}
		page.Factors = append(page.Factors, accountFactor{
			ID: factor.ID, Type: factor.Type, Label: factor.Label,
			Confirmed: factor.Confirmed,
		})
	}

	s.scriptedSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := accountSecurityTemplate.Execute(w, page); err != nil {
		s.log.Error("rendering the account security page", "error", err)
	}
}

// webAuthnOffered asks the authenticator, rather than deciding again.
//
// Whether keys are offered is settled where the relying party is configured — which is also
// where the "browsers refuse WebAuthn outside a secure context" rule is applied. A page that
// re-derived it from the issuer would be a second rule to keep in step, and the symptom of
// their disagreeing is a button that cannot work.
func (s *Server) webAuthnOffered() bool {
	return s.authn != nil && s.authn.WebAuthnAvailable()
}

type accountFactor struct {
	ID        string
	Type      string
	Label     string
	Confirmed bool
}

type accountSecurityPage struct {
	CSRFToken       string
	Factors         []accountFactor
	RecoveryCodes   int64
	WebAuthnOffered bool
	Script          template.JS
}

var accountSecurityTemplate = template.Must(template.New("account").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security</title>
<style>
 body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background:#f6f7f9;
        margin:0; display:flex; min-height:100vh; align-items:center; justify-content:center; }
 main { background:#fff; padding:2rem; border-radius:8px; width:min(30rem, 92vw);
        box-shadow:0 1px 3px rgba(0,0,0,.12); }
 h1 { font-size:1.25rem; margin:0 0 1.5rem; }
 h2 { font-size:.9375rem; margin:1.5rem 0 .5rem; }
 ul { list-style:none; padding:0; margin:0 0 1rem; }
 li { border:1px solid #eee; border-radius:4px; padding:.625rem .75rem; margin-bottom:.5rem;
      font-size:.875rem; display:flex; justify-content:space-between; align-items:center; }
 .kind { color:#666; font-size:.75rem; text-transform:uppercase; letter-spacing:.05em; }
 .pending { color:#8a5a1f; }
 input { width:100%; padding:.5rem; margin-bottom:.75rem; border:1px solid #ccc;
         border-radius:4px; font-size:1rem; box-sizing:border-box; }
 button { width:100%; padding:.625rem; background:#1a1a2e; color:#fff; border:0;
          border-radius:4px; font-size:1rem; cursor:pointer; }
 .status { background:#eef2ff; border:1px solid #c7d2fe; color:#1e3a8a; padding:.625rem;
           border-radius:4px; font-size:.875rem; margin-top:1rem; }
 p.note { color:#666; font-size:.8125rem; }
</style>
</head>
<body>
<main>
  <h1>Security</h1>

  <h2>Second factors</h2>
  {{if .Factors}}
  <ul>
    {{range .Factors}}
    <li>
      <span>{{if .Label}}{{.Label}}{{else}}{{.Type}}{{end}}
        {{if not .Confirmed}}<span class="pending"> — not confirmed</span>{{end}}</span>
      <span class="kind">{{.Type}}</span>
    </li>
    {{end}}
  </ul>
  {{else}}
  <p class="note">Nothing enrolled. This account signs in with a password alone.</p>
  {{end}}

  {{if .WebAuthnOffered}}
  <h2>Add a security key</h2>
  <input type="hidden" id="wa-csrf" value="{{.CSRFToken}}">
  <input id="wa-label" placeholder="Name it, so you can tell it apart later" maxlength="60">
  <button type="button" id="wa-register">Add a security key</button>
  <div id="wa-status" class="status" hidden></div>
  {{else}}
  <p class="note">Security keys need https. This deployment is serving over plain http,
     where browsers refuse them.</p>
  {{end}}

  <h2>Recovery codes</h2>
  {{if lt .RecoveryCodes 0}}
  <p class="note">Could not be counted.</p>
  {{else if eq .RecoveryCodes 0}}
  <p class="note">None left. Ask an administrator to issue a new set before this account
     loses its device.</p>
  {{else}}
  <p class="note">{{.RecoveryCodes}} unused.</p>
  {{end}}
</main>
<script>{{.Script}}</script>
</body>
</html>`))
