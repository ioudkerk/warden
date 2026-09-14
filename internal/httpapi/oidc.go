package httpapi

import (
	"net/http"
)

// The OpenID Provider's metadata endpoint (SPEC §7.7).
//
// The rest of the provider surface — authorize, token, userinfo and the others — lands
// with the flows that use them. This is here now because it is what a relying party
// fetches first, and because publishing it is what makes the endpoints discoverable
// rather than documented.

// handleOpenIDConfiguration serves /.well-known/openid-configuration.
//
// Unauthenticated, like JWKS: it is how a client that holds nothing learns where to send
// people. It carries no tenant-specific information, which is why one document serves a
// whole deployment — the issuer is deployment-wide and the tenant is resolved from the
// client id at the endpoints themselves.
func (s *Server) handleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	algorithms, err := s.provider.Algorithms(r.Context())
	if err != nil {
		// The document names the signing algorithm, and guessing it would tell a
		// relying party to expect something the deployment may not produce. A
		// deployment with no key is unfinished rather than broken, so it says so.
		s.log.Error("serving the discovery document", "error", err)
		writeProblem(w, http.StatusServiceUnavailable, "not_initialised",
			"This deployment has no signing key yet. Run `warden init`.")
		return
	}

	// Short, and not zero. Relying parties cache this aggressively and some fetch it
	// once per process lifetime; a long max-age makes a changed endpoint take days to
	// propagate, and no max-age makes a busy fleet refetch it per login.
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, s.provider.Discovery(algorithms))
}

// requireProvider refuses the OpenID Provider routes when this process was not built
// with one, rather than panicking on a nil.
func (s *Server) requireProvider(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.provider == nil {
			writeProblem(w, http.StatusServiceUnavailable, "provider_unavailable",
				"This process does not serve the OpenID Provider. It needs the cache tier, "+
					"database.system_url and a signing key.")
			return
		}
		next(w, r)
	}
}
