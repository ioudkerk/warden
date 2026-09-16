package httpapi

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/oidcop"
)

// The device authorization grant's two HTTP surfaces (RFC 8628, SPEC §7.7).
//
// One for the device, which has no browser and speaks JSON; one for the person, who has
// a browser and is somewhere else entirely. The whole design of the grant is that these
// two never meet: the device shows a code, the person types it on their phone, and the
// only thing connecting them is a row in a table.

// handleDeviceAuthorization is the device authorization endpoint (RFC 8628 §3.1).
//
// The device posts its client id and the scopes it wants, and receives two codes and the
// address to send its user to.
func (s *Server) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The request body could not be read.")
		return
	}

	tenantID, err := s.tenantForClientRequest(r)
	if err != nil {
		s.log.Debug("a device authorization request named no resolvable client", "error", err)
		s.provider.WriteAccessError(ctx, w, nil, fosite.ErrInvalidClient)
		return
	}
	ctx = oidcop.WithTenant(ctx, tenantID)
	r = r.WithContext(ctx)

	// Authenticated through fosite, so a confidential device client is held to the same
	// rules here as at the token endpoint it will poll in a moment.
	client, err := s.provider.AuthenticateClient(ctx, r, r.PostForm)
	if err != nil {
		s.log.Debug("a device authorization request could not authenticate its client", "error", err)
		s.provider.WriteAccessError(ctx, w, nil, err)
		return
	}
	if !client.GetGrantTypes().Has(oidcop.GrantDeviceCode) {
		s.provider.WriteAccessError(ctx, w, nil, fosite.ErrUnauthorizedClient.WithHint(
			"The OAuth 2.0 Client is not allowed to use the device authorization grant."))
		return
	}

	scopes := fosite.RemoveEmpty(strings.Split(r.PostForm.Get("scope"), " "))
	strategy := s.provider.Config().GetScopeStrategy(ctx)
	for _, scope := range scopes {
		if !strategy(client.GetScopes(), scope) {
			// Refused now rather than after somebody has approved it: a scope the client
			// may not have is not going to become allowed because a person said yes.
			s.provider.WriteAccessError(ctx, w, nil, fosite.ErrInvalidScope.WithHintf(
				"The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
			return
		}
	}

	audiences := fosite.GetAudiences(r.PostForm)
	if audienceErr := s.provider.Config().GetAudienceStrategy(ctx)(
		client.GetAudience(), audiences); audienceErr != nil {
		s.provider.WriteAccessError(ctx, w, nil, audienceErr)
		return
	}

	codes, err := s.provider.Storage().CreateDeviceAuthorization(ctx, tenantID, client.GetID(), scopes, audiences)
	if err != nil {
		s.log.Error("creating a device authorization", "error", err)
		s.provider.WriteAccessError(ctx, w, nil, fosite.ErrServerError)
		return
	}

	verification := s.verificationURI()
	formatted := oidcop.FormatUserCode(codes.UserCode)

	s.log.Info("a device authorization was issued",
		"tenant_id", tenantID, "client_id", client.GetID(), "scopes", scopes)

	writeJSON(w, http.StatusOK, map[string]any{
		"device_code": codes.DeviceCode,
		"user_code":   formatted,
		// Both forms. The plain one is what a device prints on a screen for somebody to
		// type; the complete one is what it puts in a QR code, and §3.3.1 is explicit
		// that offering the second does not excuse omitting the first — a phone camera
		// is not always the way in.
		"verification_uri":          verification,
		"verification_uri_complete": verification + "?user_code=" + url.QueryEscape(formatted),
		"expires_in":                int(codes.ExpiresAt.Sub(nowUTC()).Seconds()),
		"interval":                  int(codes.Interval.Seconds()),
	})
}

// verificationURI is the address a person is asked to open.
//
// Deliberately short and at the root rather than under /oauth2: it is read off a
// television screen and typed into a phone, and every character is one somebody can get
// wrong.
func (s *Server) verificationURI() string {
	return strings.TrimSuffix(s.cfg.Issuer, "/") + devicePath
}

const devicePath = "/device"

// nowUTC is the clock these handlers read. A function rather than time.Now() inline so
// the expiry arithmetic has one source.
func nowUTC() time.Time { return time.Now().UTC() }

// --- the page a person sees ----------------------------------------------------------

// handleDeviceVerification serves GET /device.
//
// Three states: no code yet, so ask for one; a code that resolves, so describe what is
// being asked for; and a code that does not, which is answered the same way whether it
// was never real or has expired.
func (s *Server) handleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	session, signedIn := s.currentSession(r)
	typed := r.URL.Query().Get("user_code")

	if !signedIn {
		// The order matters, and it is the order a person actually goes in: the code
		// first, the password second. Signing in needs a tenant, and before the code is
		// typed there is nothing that says which tenant this person belongs to — the
		// deployment is multi-tenant and an email address is unique only within one.
		if typed == "" {
			s.renderDevice(w, devicePage{}, http.StatusOK)
			return
		}
		// Now there is. Approving a device is an act performed *as* somebody, so the
		// password comes next and the browser returns here afterwards.
		s.redirectToLogin(w, r)
		return
	}

	token, err := s.issueCSRFToken(w)
	if err != nil {
		s.log.Error("issuing a CSRF token", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
		return
	}

	page := devicePage{CSRFField: csrfField, CSRFToken: token}
	if typed == "" {
		s.renderDevice(w, page, http.StatusOK)
		return
	}

	page.UserCode = typed
	record, err := s.provider.Storage().DeviceByUserCode(r.Context(), session.TenantID, typed)
	if err != nil {
		page.Error = "That code is not valid. Check it and try again."
		s.renderDevice(w, page, http.StatusOK)
		return
	}
	s.describeDevice(&page, r, record)
	s.renderDevice(w, page, http.StatusOK)
}

// handleDeviceVerificationSubmit serves POST /device: approve, or decline.
func (s *Server) handleDeviceVerificationSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	session, signedIn := s.currentSession(r)
	if !signedIn {
		s.redirectToLogin(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The form could not be read.")
		return
	}
	if err := s.checkCSRF(r); err != nil {
		s.log.Warn("a device approval was submitted without a matching CSRF token", "error", err)
		s.renderDeviceError(w, r, "", "Your form expired. Please try again.")
		return
	}

	typed := r.PostFormValue("user_code")
	decision := r.PostFormValue("decision")

	// The rate limit is the whole defence here, and it is not optional: a user code is
	// eight characters from a twenty-letter alphabet, which is about thirty-four bits —
	// enough that nobody guesses one by hand, and nothing at all against a script.
	// RFC 8628 §5.1 requires this, and the counter is the same one the login page uses
	// so that a limiter outage fails closed in both places rather than one.
	ip := s.clientIP(r)
	limitKey := "device_verification:" + session.UserID
	if s.lockout != nil {
		allowed, checkErr := s.lockout.Check(ctx, session.TenantID, limitKey, ip)
		if checkErr != nil {
			s.log.Error("checking the device verification rate limit", "error", checkErr)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"The request could not be processed.")
			return
		}
		if !allowed.Allowed {
			s.deviceTooManyAttempts(w, r, allowed)
			return
		}
	}

	record, err := s.provider.Storage().DeviceByUserCode(ctx, session.TenantID, typed)
	if err != nil {
		if s.lockout != nil {
			if _, failErr := s.lockout.Failed(ctx, session.TenantID, limitKey, ip); failErr != nil {
				s.log.Error("recording a failed device verification", "error", failErr)
			}
		}
		s.renderDeviceError(w, r, typed, "That code is not valid. Check it and try again.")
		return
	}
	if s.lockout != nil {
		if clearErr := s.lockout.Succeeded(ctx, session.TenantID, limitKey, ip); clearErr != nil {
			s.log.Warn("clearing the device verification rate limit", "error", clearErr)
		}
	}

	if record.Status != oidcop.DeviceStatusPending || record.Expired(nowUTC()) {
		// Already answered, already used, or out of time. One message for all three: the
		// person's next move is the same in each case, which is to start again on the
		// device.
		s.renderDeviceError(w, r, typed,
			"That code has expired or has already been used. Start again on the device.")
		return
	}

	if decision != "approve" {
		if denyErr := s.provider.Storage().DenyDevice(ctx, session.TenantID, record.ID); denyErr != nil {
			s.log.Error("declining a device authorization", "error", denyErr)
		}
		s.log.Info("a device authorization was declined",
			"tenant_id", session.TenantID, "user_id", session.UserID, "client_id", record.ClientID)
		s.renderDeviceOutcome(w, "Declined", "The device has not been given access.")
		return
	}

	// Approved as this person, in this session. The session is what the issued tokens
	// hang off, so signing out later reaches the device too.
	if approveErr := s.provider.Storage().ApproveDevice(ctx, session.TenantID, record.ID,
		session.UserID, session.ID, record.RequestedScope, record.RequestedAudience); approveErr != nil {
		if errors.Is(approveErr, oidcop.ErrNoSuchDeviceCode) {
			s.renderDeviceError(w, r, typed,
				"That code has expired or has already been used. Start again on the device.")
			return
		}
		s.log.Error("approving a device authorization", "error", approveErr)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The approval could not be recorded.")
		return
	}

	s.log.Info("a device authorization was approved",
		"tenant_id", session.TenantID, "user_id", session.UserID,
		"client_id", record.ClientID, "scopes", record.RequestedScope)
	s.renderDeviceOutcome(w, "Approved",
		"You can go back to the device. It will finish signing in on its own.")
}

// deviceTooManyAttempts answers a rate-limited verification.
func (s *Server) deviceTooManyAttempts(w http.ResponseWriter, r *http.Request, d authn.Decision) {
	seconds := int(d.RetryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
	s.log.Info("a device verification was rate limited", "reason", d.Reason, "ip", s.clientIP(r))

	token, err := s.issueCSRFToken(w)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
		return
	}
	s.renderDevice(w, devicePage{
		CSRFField: csrfField, CSRFToken: token,
		Error: "Too many attempts. Please wait a moment and try again.",
	}, http.StatusTooManyRequests)
}

// describeDevice fills in what the person is being asked to approve.
func (s *Server) describeDevice(page *devicePage, r *http.Request, record *oidcop.DeviceAuthorization) {
	if record.Status != oidcop.DeviceStatusPending || record.Expired(nowUTC()) {
		page.Error = "That code has expired or has already been used. Start again on the device."
		return
	}
	page.Found = true
	page.Scopes = record.RequestedScope
	page.ClientName = record.ClientID
	if client, err := s.provider.Storage().Clients().Lookup(r.Context(), record.ClientID); err == nil {
		page.ClientName = client.Name
	}
}

func (s *Server) renderDeviceError(w http.ResponseWriter, r *http.Request, typed, message string) {
	token, err := s.issueCSRFToken(w)
	if err != nil {
		s.log.Error("issuing a CSRF token", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error", "The page could not be served.")
		return
	}
	_ = r
	s.renderDevice(w, devicePage{
		CSRFField: csrfField, CSRFToken: token, UserCode: typed, Error: message,
	}, http.StatusOK)
}

func (s *Server) renderDevice(w http.ResponseWriter, page devicePage, status int) {
	loginSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := deviceTemplate.Execute(w, page); err != nil {
		s.log.Error("rendering the device page", "error", err)
	}
}

func (s *Server) renderDeviceOutcome(w http.ResponseWriter, heading, message string) {
	loginSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := deviceOutcomeTemplate.Execute(w, map[string]string{
		"Heading": heading, "Message": message,
	}); err != nil {
		s.log.Error("rendering the device outcome page", "error", err)
	}
}

type devicePage struct {
	CSRFField  string
	CSRFToken  string
	UserCode   string
	ClientName string
	Scopes     []string
	Found      bool
	Error      string
}

// deviceTemplate asks for the code, or describes what it found.
//
// Same rules as the login page: no external stylesheet, no script, nothing the content
// security policy would have to allow. The scopes are listed rather than summarised,
// because "approve" should mean approving something the person can see.
var deviceTemplate = template.Must(template.New("device").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect a device</title>
<style>
 body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; background:#f6f7f9;
        margin:0; display:flex; min-height:100vh; align-items:center; justify-content:center; }
 main { background:#fff; padding:2rem; border-radius:8px; width:min(26rem, 92vw);
        box-shadow:0 1px 3px rgba(0,0,0,.12); }
 h1 { font-size:1.25rem; margin:0 0 .25rem; }
 p.sub { margin:0 0 1.5rem; color:#666; font-size:.875rem; }
 label { display:block; font-size:.8125rem; font-weight:600; margin-bottom:.25rem; }
 input { width:100%; padding:.5rem; margin-bottom:1rem; border:1px solid #ccc;
         border-radius:4px; font-size:1.125rem; box-sizing:border-box;
         letter-spacing:.15em; text-transform:uppercase; }
 ul { margin:0 0 1.5rem; padding-left:1.25rem; color:#333; font-size:.875rem; }
 button { width:100%; padding:.625rem; border:0; border-radius:4px; font-size:1rem;
          cursor:pointer; margin-bottom:.5rem; }
 button.approve { background:#1a1a2e; color:#fff; }
 button.decline { background:#eee; color:#333; }
 .error { background:#fdecec; border:1px solid #f5c2c2; color:#8a1f1f; padding:.625rem;
          border-radius:4px; font-size:.875rem; margin-bottom:1rem; }
</style>
</head>
<body>
<main>
{{if .Found}}
  <h1>Connect {{.ClientName}}?</h1>
  <p class="sub">A device is asking to sign in as you.</p>
  {{if .Scopes}}<ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>{{end}}
  <form method="post" action="/device">
    <input type="hidden" name="{{.CSRFField}}" value="{{.CSRFToken}}">
    <input type="hidden" name="user_code" value="{{.UserCode}}">
    <button type="submit" name="decision" value="approve" class="approve">Connect</button>
    <button type="submit" name="decision" value="decline" class="decline">Not now</button>
  </form>
{{else}}
  <h1>Connect a device</h1>
  <p class="sub">Type the code shown on the device.</p>
  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
  <form method="get" action="/device">
    <label for="user_code">Code</label>
    <input id="user_code" name="user_code" value="{{.UserCode}}" autofocus
           autocomplete="off" autocapitalize="characters" required>
    <button type="submit" class="approve">Continue</button>
  </form>
{{end}}
</main>
</body>
</html>`))

var deviceOutcomeTemplate = template.Must(template.New("deviceoutcome").Parse(`<!doctype html>
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
  <p>{{.Message}}</p>
</main>
</body>
</html>`))
