package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/warden-project/warden/internal/keys"
)

// jwksMaxAge is what relying parties are told to cache JWKS for.
//
// It is short because it is the floor on how quickly a relying party notices a new
// key, and long enough that a busy fleet does not refetch it per request. Rotation
// does not depend on it — the overlap window is what makes rotation safe, and it is
// measured in hours while this is measured in minutes — so this figure trades
// freshness against load and nothing else.
const jwksMaxAge = 5 * time.Minute

// handleJWKS publishes the signing keys a relying party should accept.
//
// Deliberately unauthenticated. The whole point of asymmetric signing (SPEC §17) is
// that verification requires nothing secret, so requiring a credential here would buy
// no security and would break every stock OIDC library, which is precisely the
// outcome M1's milestone exit rules out.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	body, etag, err := s.keys.JWKS(r.Context())
	if err != nil {
		if errors.Is(err, keys.ErrNotInitialised) {
			// 503 rather than 500: the deployment is not broken, it is not finished.
			// A relying party retrying is the correct response to it.
			writeProblem(w, http.StatusServiceUnavailable, "not_initialised",
				"This deployment has no signing key yet. Run `warden init`.")
			return
		}
		s.log.Error("publishing JWKS", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal_error",
			"The key set could not be read.")
		return
	}

	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(jwksMaxAge.Seconds())))
	if matchesETag(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		s.log.Debug("writing JWKS", "error", err)
	}
}

// matchesETag implements the If-None-Match comparison for a single strong tag.
//
// The header is a list, and a client that has seen two versions may send both. The
// weak prefix is accepted on the request side because some proxies add it; Warden
// never generates one, since the bytes it serves for a given tag are identical.
func matchesETag(header, etag string) bool {
	if header == "" {
		return false
	}
	if strings.TrimSpace(header) == "*" {
		return true
	}
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == etag {
			return true
		}
	}
	return false
}
