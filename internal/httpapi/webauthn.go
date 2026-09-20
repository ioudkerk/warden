package httpapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/warden-project/warden/internal/authn"
)

// WebAuthn over HTTP: the two round trips a browser needs (SPEC §7.1).
//
// Every other page Warden serves is a form post, and this one cannot be. `navigator
// .credentials.get` is a JavaScript API — there is no HTML element that speaks to a
// security key — so the verification page carries a script, and the script talks to the
// two JSON endpoints below.
//
// That script is the only JavaScript in Warden's own UI, and it is kept to the shape that
// lets the content security policy stay strict: inline, with its SHA-256 in `script-src`,
// so the browser runs exactly the bytes Warden compiled and nothing a subsequent injection
// could add.

// webAuthnBeginResponse is what the script receives to hand to the browser.
type webAuthnBeginResponse struct {
	// SessionID names the stored challenge and comes back with the answer.
	SessionID string `json:"session_id"`
	// Options is the WebAuthn PublicKeyCredentialRequestOptions, verbatim.
	Options json.RawMessage `json:"options"`
}

// maxWebAuthnBody bounds an assertion. Real ones are a couple of kilobytes; the limit is
// generous enough for an attestation statement and small enough that the endpoint is not a
// way to make the server allocate.
const maxWebAuthnBody = 64 << 10

// handleWebAuthnLoginBegin issues a challenge for somebody who has passed their password.
func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.scriptedRequestIsOurs(w, r) {
		return
	}
	pending, _, ok := s.currentPending(r)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "no_pending_login",
			"Your sign-in has expired. Start again from the application you want to use.")
		return
	}

	challenge, err := s.authn.BeginWebAuthnLogin(r.Context(), pending.TenantID, pending.UserID)
	if err != nil {
		s.webAuthnError(w, "beginning a WebAuthn login", err)
		return
	}

	writeJSON(w, http.StatusOK, webAuthnBeginResponse{
		SessionID: challenge.SessionID, Options: challenge.Options,
	})
}

// handleWebAuthnLoginFinish verifies an assertion and finishes the sign-in.
func (s *Server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !s.scriptedRequestIsOurs(w, r) {
		return
	}
	pending, pendingID, ok := s.currentPending(r)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "no_pending_login",
			"Your sign-in has expired. Start again from the application you want to use.")
		return
	}

	sessionID, body, ok := s.readWebAuthnAnswer(w, r)
	if !ok {
		return
	}

	// The same limiter the code form uses, and for the same reason: this is the last
	// thing between somebody holding a password and the account. An assertion is far
	// harder to guess than six digits, but the endpoint is also a way to make the server
	// do public-key work, and that deserves a bound of its own.
	ip := s.clientIP(r)
	limitKey := "second_factor:" + pending.UserID
	if s.lockout != nil {
		decision, checkErr := s.lockout.Check(r.Context(), pending.TenantID, limitKey, ip)
		if checkErr != nil {
			s.log.Error("checking the second-factor rate limit", "error", checkErr)
			writeProblem(w, http.StatusInternalServerError, "internal_error",
				"The sign-in could not be processed.")
			return
		}
		if !decision.Allowed {
			writeProblem(w, http.StatusTooManyRequests, "too_many_attempts",
				"Too many attempts. Please wait a moment and try again.")
			return
		}
	}

	err := s.authn.FinishWebAuthnLogin(r.Context(), pending.TenantID, pending.UserID, sessionID, body)
	if err != nil {
		if s.lockout != nil {
			if _, failErr := s.lockout.Failed(r.Context(), pending.TenantID, limitKey, ip); failErr != nil {
				s.log.Error("recording a failed second factor", "error", failErr)
			}
		}
		if errors.Is(err, authn.ErrCredentialCloned) {
			// The one WebAuthn failure worth telling the person about plainly: their key
			// is answering with a counter that went backwards, and the honest reading is
			// that a copy of it exists somewhere.
			writeProblem(w, http.StatusUnauthorized, "authenticator_cloned",
				"This security key could not be trusted. Contact an administrator.")
			return
		}
		s.log.Info("a WebAuthn assertion was refused at login",
			"tenant_id", pending.TenantID, "user_id", pending.UserID)
		writeProblem(w, http.StatusUnauthorized, "invalid_second_factor",
			"That security key was not accepted.")
		return
	}

	if s.lockout != nil {
		if clearErr := s.lockout.Succeeded(r.Context(), pending.TenantID, limitKey, ip); clearErr != nil {
			s.log.Warn("clearing the second-factor rate limit", "error", clearErr)
		}
	}

	destination, ok := s.completeSecondFactor(w, r, pending, pendingID, authn.AMRWebAuthn)
	if !ok {
		return
	}
	// JSON rather than a redirect: the caller is a fetch, and a 303 here would be
	// followed by the script rather than by the browser's address bar. The script does
	// the navigating.
	writeJSON(w, http.StatusOK, map[string]any{"redirect_to": destination})
}

// --- enrolment ---------------------------------------------------------------------------

// handleWebAuthnRegisterBegin issues a registration challenge for a signed-in person.
func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if !s.scriptedRequestIsOurs(w, r) {
		return
	}
	session, ok := s.currentSession(r)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthenticated", "Sign in first.")
		return
	}

	challenge, err := s.authn.BeginWebAuthnRegistration(
		r.Context(), session.TenantID, session.UserID,
		s.accountLabel(r, session.TenantID, session.UserID))
	if err != nil {
		s.webAuthnError(w, "beginning a WebAuthn registration", err)
		return
	}

	writeJSON(w, http.StatusOK, webAuthnBeginResponse{
		SessionID: challenge.SessionID, Options: challenge.Options,
	})
}

// handleWebAuthnRegisterFinish stores a key the browser has just created.
func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if !s.scriptedRequestIsOurs(w, r) {
		return
	}
	session, ok := s.currentSession(r)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthenticated", "Sign in first.")
		return
	}

	sessionID, body, ok := s.readWebAuthnAnswer(w, r)
	if !ok {
		return
	}
	label := r.URL.Query().Get("label")
	if label == "" {
		label = "Security key"
	}

	if err := s.authn.FinishWebAuthnRegistration(
		r.Context(), session.TenantID, session.UserID, sessionID, label, body); err != nil {
		if errors.Is(err, authn.ErrInvalidSecondFactor) {
			writeProblem(w, http.StatusBadRequest, "invalid_second_factor",
				"That security key could not be registered.")
			return
		}
		s.webAuthnError(w, "finishing a WebAuthn registration", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"registered": true})
}

// scriptedRequestIsOurs applies the double-submit check to a JSON endpoint.
func (s *Server) scriptedRequestIsOurs(w http.ResponseWriter, r *http.Request) bool {
	if err := s.checkCSRFHeader(r); err != nil {
		s.log.Warn("a WebAuthn request arrived without a matching CSRF token", "error", err)
		writeProblem(w, http.StatusBadRequest, "invalid_request",
			"Your page expired. Reload and try again.")
		return false
	}
	return true
}

// readWebAuthnAnswer pulls the session identifier and the raw credential out of a request.
//
// The identifier travels in a header rather than inside the JSON, because the JSON is the
// browser's own `PublicKeyCredential` serialisation and adding a field to it would mean
// rebuilding the object in script — more JavaScript to audit for no gain.
func (s *Server) readWebAuthnAnswer(w http.ResponseWriter, r *http.Request) (sessionID string, body []byte, ok bool) {
	sessionID = r.Header.Get("X-Warden-WebAuthn-Session")
	if sessionID == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request",
			"This request carries no challenge identifier.")
		return "", nil, false
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxWebAuthnBody))
	if err != nil || len(raw) == 0 {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "The request body could not be read.")
		return "", nil, false
	}
	return sessionID, raw, true
}

// webAuthnError answers the failures that are the deployment's rather than the person's.
func (s *Server) webAuthnError(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, authn.ErrWebAuthnUnavailable):
		// Not an error on this request: this deployment does not offer security keys,
		// which a browser on plain http could not use anyway.
		writeProblem(w, http.StatusNotImplemented, "webauthn_unavailable",
			"This deployment does not offer security keys.")
	case errors.Is(err, authn.ErrNoSecondFactor):
		writeProblem(w, http.StatusBadRequest, "no_security_key",
			"There is no security key registered for this account.")
	default:
		s.log.Error(what, "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The request could not be processed.")
	}
}

// accountLabel is the name an authenticator shows for this account.
//
// The email address, because that is what a person recognises in a list of keys on their
// phone. Falls back to the subject identifier rather than failing: a label is for humans,
// and an enrolment must not fail because a profile lookup did.
func (s *Server) accountLabel(r *http.Request, tenantID, userID string) string {
	if s.provider == nil {
		return userID
	}
	profile, err := s.provider.Storage().Profile(r.Context(), tenantID, userID)
	if err != nil || profile.Email == "" {
		return userID
	}
	return profile.Email
}

// --- the script -----------------------------------------------------------------------------

// webAuthnScript is the only JavaScript Warden serves.
//
// Deliberately small and deliberately inline. Small, because every line of it is a line
// somebody has to read before trusting the login page; inline with a hash in the content
// security policy, because that is what lets `script-src` name the exact bytes allowed to
// run rather than a source that could serve different ones tomorrow.
//
// It does three things: turn the base64url the server sends into the ArrayBuffers the
// WebAuthn API requires, call the API, and turn the result back. There is no framework, no
// polyfill and no error reporting to anywhere.
const webAuthnScript = `
(function () {
  var b64 = {
    decode: function (value) {
      var padded = value.replace(/-/g, '+').replace(/_/g, '/');
      while (padded.length % 4) { padded += '='; }
      var binary = atob(padded);
      var bytes = new Uint8Array(binary.length);
      for (var i = 0; i < binary.length; i++) { bytes[i] = binary.charCodeAt(i); }
      return bytes.buffer;
    },
    encode: function (buffer) {
      var bytes = new Uint8Array(buffer), binary = '';
      for (var i = 0; i < bytes.length; i++) { binary += String.fromCharCode(bytes[i]); }
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
  };

  function say(message) {
    var box = document.getElementById('wa-status');
    if (box) { box.textContent = message; box.hidden = false; }
  }

  function csrf() {
    var holder = document.getElementById('wa-csrf');
    return holder ? holder.value : '';
  }

  function post(url, sessionId, payload) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-Warden-WebAuthn-Session': sessionId,
        'X-Warden-Csrf': csrf()
      },
      body: JSON.stringify(payload)
    });
  }

  function begin(url) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-Warden-Csrf': csrf() }
    }).then(function (response) {
      if (!response.ok) { throw new Error('unavailable'); }
      return response.json();
    });
  }

  function assertionFrom(credential) {
    return {
      id: credential.id,
      rawId: b64.encode(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: b64.encode(credential.response.clientDataJSON),
        authenticatorData: b64.encode(credential.response.authenticatorData),
        signature: b64.encode(credential.response.signature),
        userHandle: credential.response.userHandle ? b64.encode(credential.response.userHandle) : null
      }
    };
  }

  function attestationFrom(credential) {
    return {
      id: credential.id,
      rawId: b64.encode(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: b64.encode(credential.response.clientDataJSON),
        attestationObject: b64.encode(credential.response.attestationObject)
      }
    };
  }

  var signIn = document.getElementById('wa-signin');
  if (signIn) {
    signIn.addEventListener('click', function () {
      if (!window.PublicKeyCredential) { say('This browser cannot use security keys.'); return; }
      say('Follow your browser’s prompt…');
      begin('/login/verify/webauthn/begin').then(function (data) {
        var options = data.options.publicKey || data.options;
        options.challenge = b64.decode(options.challenge);
        (options.allowCredentials || []).forEach(function (c) { c.id = b64.decode(c.id); });
        return navigator.credentials.get({ publicKey: options }).then(function (credential) {
          return post('/login/verify/webauthn/finish', data.session_id, assertionFrom(credential));
        });
      }).then(function (response) {
        if (!response.ok) { throw new Error('refused'); }
        return response.json();
      }).then(function (result) {
        window.location = result.redirect_to;
      }).catch(function () {
        say('That security key was not accepted. Use a code instead, or try again.');
      });
    });
  }

  var register = document.getElementById('wa-register');
  if (register) {
    register.addEventListener('click', function () {
      if (!window.PublicKeyCredential) { say('This browser cannot use security keys.'); return; }
      var label = (document.getElementById('wa-label') || {}).value || 'Security key';
      say('Follow your browser’s prompt…');
      begin('/account/security/webauthn/begin').then(function (data) {
        var options = data.options.publicKey || data.options;
        options.challenge = b64.decode(options.challenge);
        options.user.id = b64.decode(options.user.id);
        (options.excludeCredentials || []).forEach(function (c) { c.id = b64.decode(c.id); });
        return navigator.credentials.create({ publicKey: options }).then(function (credential) {
          return post('/account/security/webauthn/finish?label=' + encodeURIComponent(label),
            data.session_id, attestationFrom(credential));
        });
      }).then(function (response) {
        if (!response.ok) { throw new Error('refused'); }
        window.location.reload();
      }).catch(function () {
        say('That security key could not be registered.');
      });
    });
  }
})();
`

// webAuthnScriptHash is the CSP source expression for the script above.
//
// Computed from the bytes rather than written down, so the policy and the script cannot
// drift: edit the script and the hash follows. A mismatch would not fail loudly — the
// browser would simply refuse to run it — which is exactly the kind of breakage a computed
// value prevents.
var webAuthnScriptHash = func() string {
	sum := sha256.Sum256([]byte(webAuthnScript))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

// scriptedSecurityHeaders is loginSecurityHeaders for the two pages that carry the script.
//
// The same policy, with one addition: `script-src` naming the hash of the one script, and
// `connect-src 'self'` so that script may reach the endpoints it was written for. Still no
// 'unsafe-inline', so an injected script does not run even on the pages that have one.
func (s *Server) scriptedSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src "+webAuthnScriptHash+
			"; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}
