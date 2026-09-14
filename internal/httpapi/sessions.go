package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/warden-project/warden/internal/authn"
)

// The session management surface of SPEC §8.3.
//
// Every handler here takes its tenant from the authenticated caller and never from the
// request, so there is no tenant parameter to tamper with. That is necessary and it is
// not sufficient, which is worth stating because it was briefly assumed to be:
// revoking a session also touches the cache tier, where keys are named by sid alone,
// and a delete issued there before the tenant had been checked ended another tenant's
// session perfectly well. Threat 5 of §17.1 is enforced in authn.Sessions, against the
// record; TestSessionEndpointsAreTenantScoped is what caught the gap.

// sessionView is a session as the API renders it.
//
// It carries no secret. A sid is a capability inside Warden but not outside it: an
// active-sessions screen has to name the sessions in order to offer to end them.
type sessionView struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	AMR       []string  `json:"amr"`
	AuthTime  time.Time `json:"auth_time"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

func viewOf(s *authn.Session) sessionView {
	return sessionView{
		ID: s.ID, UserID: s.UserID, AMR: s.AMR,
		AuthTime: s.AuthTime, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt,
		IP: s.IP, UserAgent: s.UserAgent,
	}
}

// handleUserSessions lists a user's active sessions.
func (s *Server) handleUserSessions(w http.ResponseWriter, r *http.Request) {
	caller, _ := CallerFrom(r.Context())
	userID := r.PathValue("id")
	if userID == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "A user id is required.")
		return
	}

	sessions, err := s.sessions.ActiveForUser(r.Context(), caller.TenantID, userID)
	if err != nil {
		s.log.Error("listing sessions", "error", err, "user_id", userID)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The sessions could not be listed.")
		return
	}

	views := make([]sessionView, 0, len(sessions))
	for i := range sessions {
		views = append(views, viewOf(&sessions[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": views})
}

// revokeRequest is the optional body on either revoke endpoint.
type revokeRequest struct {
	// Reason is recorded in the audit log. Optional, and worth supplying: "why was
	// this person signed out of everything at 03:00?" is a question asked after the
	// fact, when whoever did it is not available to answer.
	Reason string `json:"reason"`
}

func decodeRevokeRequest(r *http.Request) revokeRequest {
	var body revokeRequest
	// A missing or malformed body is not an error. Revocation is the safe direction,
	// and refusing to sign somebody out because their JSON was untidy is the wrong
	// trade on an endpoint that exists for incidents.
	_ = json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck // deliberately tolerant
	return body
}

// handleRevokeSession ends one session.
func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	caller, _ := CallerFrom(r.Context())
	sid := r.PathValue("id")
	if sid == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "A session id is required.")
		return
	}

	if err := s.sessions.Revoke(r.Context(), caller.TenantID, sid, decodeRevokeRequest(r).Reason); err != nil {
		s.log.Error("revoking a session", "error", err, "sid", sid)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The session could not be revoked.")
		return
	}

	// 200 whether or not the session existed. Revocation is idempotent, and a 404 for
	// an unknown sid would tell a caller which session ids are real.
	writeJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

// handleRevokeAllSessions is SPEC §8.3's "log out everywhere", and M1-4's exit
// condition: it must take effect on every replica within a second.
//
// It does so in single-digit milliseconds, and by construction rather than by timing.
// The revocation marker is written to the cache tier before this returns, no replica
// caches sessions in process, so the next validation anywhere reads the marker and
// refuses. There is no propagation step to be slow.
func (s *Server) handleRevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	caller, _ := CallerFrom(r.Context())
	userID := r.PathValue("id")
	if userID == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "A user id is required.")
		return
	}

	count, err := s.sessions.RevokeAllForUser(r.Context(), caller.TenantID, userID,
		decodeRevokeRequest(r).Reason)
	if err != nil {
		s.log.Error("revoking all sessions", "error", err, "user_id", userID)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The sessions could not be revoked.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"revoked": count})
}

// requireSessions refuses the session routes when the server was built without a
// session store, rather than panicking on a nil.
func (s *Server) requireSessions(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.sessions == nil {
			writeProblem(w, http.StatusServiceUnavailable, "sessions_unavailable",
				"This process does not serve sessions. They need the cache tier and "+
					"database.system_url.")
			return
		}
		next(w, r)
	}
}
