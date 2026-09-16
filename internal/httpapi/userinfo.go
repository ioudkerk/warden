package httpapi

import (
	"errors"
	"net/http"

	"github.com/ory/fosite"

	"github.com/warden-project/warden/internal/oidcop"
)

// The userinfo endpoint (OpenID Connect Core §5.3, SPEC §7.7).
//
// A relying party that holds an access token asks who it belongs to. What comes back is
// decided by the scopes that were *granted*, not by what the client would like: a token
// granted only "openid" yields the subject and nothing else, which is what makes asking
// for "email" mean something.

// handleUserinfo serves GET and POST /oauth2/userinfo.
//
// Both methods, because §5.3.1 requires both and a relying party library will use
// whichever its author preferred. The token may arrive in the Authorization header or,
// on a POST, as an access_token form field — RFC 6750 allows both, and fosite's
// AccessTokenFromRequest reads them the same way it does everywhere else.
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token := fosite.AccessTokenFromRequest(r)
	if token == "" {
		// No credential at all. A bare challenge rather than an error code: RFC 6750 §3
		// distinguishes "you sent nothing" from "what you sent is not valid", and a
		// client library uses the first to decide to go and get a token.
		s.bearerError(w, http.StatusUnauthorized, "", "An access token is required.")
		return
	}

	// "openid" is required, and it is checked here rather than after the fact: a token
	// issued for an API call with no openid scope is not a token for asking who the
	// user is.
	session := oidcop.NewEmptySession()
	use, requester, err := s.provider.IntrospectToken(ctx, token, fosite.AccessToken, session, "openid")
	if err != nil {
		if fosite.ErrorToRFC6749Error(err).ErrorField == "invalid_scope" {
			s.bearerError(w, http.StatusForbidden, "insufficient_scope",
				"This token was not granted the openid scope.")
			return
		}
		s.log.Debug("a userinfo request presented an unusable token", "error", err)
		s.bearerError(w, http.StatusUnauthorized, "invalid_token",
			"The access token is expired, revoked, or invalid.")
		return
	}
	if use != fosite.AccessToken {
		// fosite falls back to the refresh-token validator when the access-token one
		// does not recognise a token, so a refresh token presented here validates
		// successfully as a *refresh* token. It must not be accepted: it is a
		// credential for the token endpoint, is not audience-restricted the same way,
		// and lives thirty days rather than ten minutes.
		s.log.Warn("a userinfo request presented a token that is not an access token", "token_use", use)
		s.bearerError(w, http.StatusUnauthorized, "invalid_token",
			"The access token is expired, revoked, or invalid.")
		return
	}

	wardenSession, ok := requester.GetSession().(*oidcop.Session)
	if !ok || wardenSession.TenantID == "" || wardenSession.GetSubject() == "" {
		// A token with no subject: the client credentials grant issues one, and it
		// describes a program rather than a person. There is no userinfo for it.
		s.bearerError(w, http.StatusForbidden, "insufficient_scope",
			"This token does not represent a user.")
		return
	}

	profile, err := s.provider.Storage().Profile(ctx, wardenSession.TenantID, wardenSession.GetSubject())
	if errors.Is(err, oidcop.ErrSubjectUnavailable) {
		// The account was suspended, deprovisioned or deleted after the token was
		// issued. Answered as an invalid token, which is the truth: it names somebody
		// who may no longer act.
		s.log.Info("a userinfo request named a subject that can no longer be served",
			"tenant_id", wardenSession.TenantID, "user_id", wardenSession.GetSubject())
		s.bearerError(w, http.StatusUnauthorized, "invalid_token",
			"The access token is expired, revoked, or invalid.")
		return
	}
	if err != nil {
		s.log.Error("reading a profile for userinfo", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The request could not be processed.")
		return
	}

	writeJSON(w, http.StatusOK,
		oidcop.UserInfoClaims(profile, requester.GetGrantedScopes(), wardenSession.TenantID))
}

// bearerError answers with the WWW-Authenticate challenge RFC 6750 §3 defines.
//
// The header matters more than the body: a conforming client reads the error code from
// it to decide whether to refresh the token, ask for more scope, or give up, and a bare
// 401 with a JSON body leaves it guessing.
func (s *Server) bearerError(w http.ResponseWriter, status int, code, detail string) {
	challenge := `Bearer realm="warden"`
	if code != "" {
		challenge += `, error="` + code + `", error_description="` + detail + `"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	if code == "" {
		code = "unauthorized"
	}
	writeProblem(w, status, code, detail)
}
