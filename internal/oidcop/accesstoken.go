package oidcop

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/jwt"
)

// The access token, as SPEC §8.2 specifies it: a JWT, signed by the rotating key, with
// Warden's authorization facts in a `wd` block.
//
// It is a trade, and worth naming. A JWT access token is verified by signature, so a
// resource server can check one without asking Warden anything — which is the point, and
// which also means Warden cannot take it back. Revocation reaches the introspection
// endpoint and the session, not a resource server that only checks a signature. What
// bounds the damage is the lifetime, which configuration holds between five and fifteen
// minutes, and `wd.perm_rev`, which lets a reader notice that its view of the tenant is
// older than the token in its hand.

// GetJWTClaims implements oauth2.JWTSessionContainer: it is where the access token's
// claims come from.
//
// Separate from IDTokenClaims, and deliberately so. An id token says who somebody is and
// is issued to a client that asked for `openid`; an access token says what they may do and
// goes to a resource server. Putting `wd.roles` in the id token would send authorization
// facts to whoever is holding an identity assertion, which is a different audience.
func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.AccessClaims == nil {
		s.AccessClaims = &jwt.JWTClaims{}
	}
	return s.AccessClaims
}

// GetJWTHeader implements oauth2.JWTSessionContainer.
//
// The `kid` is not set here: the signer adds it from the key it actually signed with,
// which is the only value that can be right across a rotation.
func (s *Session) GetJWTHeader() *jwt.Headers {
	if s.AccessHeaders == nil {
		s.AccessHeaders = &jwt.Headers{Extra: map[string]any{}}
	}
	return s.AccessHeaders
}

// accessTokenStrategy issues the access token, assembling its claims first.
//
// A wrapper around fosite's JWT strategy rather than a replacement for it, and the seam is
// chosen for one reason: GenerateAccessToken is the only place that has a context, the
// request and the moment of issuance all at once. Assembling claims when the *session* is
// created would freeze them, and a refresh an hour later would mint a token describing the
// roles the user had when they logged in — which is exactly the staleness `perm_rev`
// exists to advertise, reintroduced as a bug.
type accessTokenStrategy struct {
	oauth2.CoreStrategy

	storage *Storage
	issuer  string
	log     *slog.Logger
}

var _ oauth2.CoreStrategy = (*accessTokenStrategy)(nil)

// GenerateAccessToken assembles the claims, then issues a token that fits.
func (a *accessTokenStrategy) GenerateAccessToken(
	ctx context.Context, requester fosite.Requester,
) (token, signature string, err error) {
	session, ok := requester.GetSession().(*Session)
	if !ok {
		// Not a Warden session. Nothing to assemble; fosite's own claims still apply.
		return a.CoreStrategy.GenerateAccessToken(ctx, requester)
	}

	subject := session.GetSubject()
	if subject == "" {
		// No user: the client credentials grant, which describes a program. RFC 9068 §5
		// asks for the client id as the subject, so the token names something rather
		// than nothing.
		a.baseClaims(session, requester, requester.GetClient().GetID(), nil)
		return a.CoreStrategy.GenerateAccessToken(ctx, requester)
	}

	tenantID := session.TenantID
	if tenantID == "" {
		if scoped, scopedOK := TenantFrom(ctx); scopedOK {
			tenantID = scoped
		} else {
			return "", "", errors.New("assembling access token claims needs a tenant")
		}
	}

	grant := ClaimGrantFor(requester.GetClient())
	facts, err := a.storage.AccessTokenFactsFor(ctx, tenantID, subject, grant)
	if errors.Is(err, ErrSubjectNotIssuable) {
		// The account was suspended, deprovisioned or deleted since the session began.
		// Refused here rather than at any one endpoint, because this is the single place
		// every grant passes through on its way to a token — and a token issued now
		// would outlive the suspension by its whole lifetime, with no way to recall it.
		a.log.Warn("refused an access token for a subject that may no longer act",
			"tenant_id", tenantID, "user_id", subject)
		return "", "", fosite.ErrInvalidGrant.WithHint(
			"This account is not active. Sign in again.")
	}
	if err != nil {
		return "", "", fmt.Errorf("assembling access token claims: %w", err)
	}

	// Generate, measure, and give something up if it does not fit. Measuring the real
	// token rather than estimating it is the whole reason this loop exists: the cap in
	// SPEC §8.2 is on the token, and the difference between the claims and the token is
	// base64, a header and a signature whose size depends on the algorithm in use.
	//
	// The extra signatures are paid only by the tokens that need them. A user with three
	// groups signs once; a user with five thousand signs twice.
	for level := keepEverything; level <= dropAttrs; level++ {
		a.baseClaims(session, requester, subject, wardenClaims(facts, grant, level))

		issued, sig, genErr := a.CoreStrategy.GenerateAccessToken(ctx, requester)
		if genErr != nil {
			return "", "", genErr
		}
		if len(issued) <= MaxAccessTokenBytes {
			if level != keepEverything {
				a.log.Info("an access token was truncated to fit the size cap",
					"tenant_id", tenantID, "user_id", subject, "dropped", level.String(),
					"bytes", len(issued), "groups", len(facts.Groups))
			}
			return issued, sig, nil
		}
		if level == dropAttrs {
			// Everything droppable is gone and it still does not fit. The remainder is
			// roles, and dropping those would leave a token that says nothing — so this
			// is refused rather than issued oversized or issued empty. It takes roughly
			// two hundred roles on one user to get here.
			a.log.Error("an access token exceeds the size cap with nothing left to drop",
				"tenant_id", tenantID, "user_id", subject,
				"bytes", len(issued), "roles", len(facts.Roles))
			return "", "", fosite.ErrServerError.WithHint(
				"This account holds too many roles to fit in an access token.")
		}
	}
	return "", "", errors.New("unreachable: the truncation loop did not terminate")
}

// baseClaims fills in everything SPEC §8.2 names apart from what fosite sets itself.
//
// fosite supplies iss, aud, exp, iat and scope from the request; these are the ones only
// Warden knows. `jti` is ours rather than fosite's generated UUID so that a token
// identifier looks like every other identifier in the system.
func (a *accessTokenStrategy) baseClaims(
	session *Session, requester fosite.Requester, subject string, wd map[string]any,
) {
	extra := map[string]any{
		"tid": session.TenantID,
		"azp": requester.GetClient().GetID(),
	}
	if session.SessionID != "" {
		extra["sid"] = session.SessionID
	}
	if claims := session.Claims; claims != nil {
		if len(claims.AuthenticationMethodsReferences) > 0 {
			extra["amr"] = claims.AuthenticationMethodsReferences
		}
		if !claims.AuthTime.IsZero() {
			extra["auth_time"] = claims.AuthTime.Unix()
		}
	}
	if wd != nil {
		extra["wd"] = wd
	}

	jti, err := randomID("tok")
	if err != nil {
		// Not fatal: fosite generates a UUID when the field is empty, which is a
		// perfectly good identifier and differs only in shape.
		a.log.Warn("could not generate a token identifier; falling back to fosite's", "error", err)
	}

	session.AccessClaims = &jwt.JWTClaims{
		Subject: subject,
		Issuer:  a.issuer,
		JTI:     jti,
		Extra:   extra,
	}
	if expiry := session.GetExpiresAt(fosite.AccessToken); !expiry.IsZero() {
		session.AccessClaims.ExpiresAt = expiry
	}
	session.AccessClaims.IssuedAt = time.Now().UTC()
}
