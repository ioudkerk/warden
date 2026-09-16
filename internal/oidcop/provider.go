package oidcop

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/secrets"
)

// Session is what Warden puts in a fosite session.
//
// It embeds fosite's OIDC session — which carries the id-token claims and the headers —
// and adds the two things Warden needs to find later: which browser session the tokens
// belong to, so a logout can end them, and which tenant, so a revocation knows where to
// look.
type Session struct {
	*openid.DefaultSession
	TenantID  string `json:"wd_tid"`
	SessionID string `json:"wd_sid"`
}

// WardenSessionID satisfies the interface the storage adapter looks for when deciding
// what to put in oauth_session.session_id.
func (s *Session) WardenSessionID() string { return s.SessionID }

// NewSession builds a session for a user who has authenticated.
//
// `sid` and `tid` go in Extra, which fosite flattens to the top level of the token
// rather than nesting under "ext" — so they appear exactly as SPEC §8.2 writes them.
// `sid` is not decoration: it is what back-channel logout and "which session issued
// this token?" both target, and an id token without one leaves a relying party unable
// to tie a token to the session it came from.
func NewSession(issuer, tenantID, sessionID, subject string, authTime time.Time, amr []string) *Session {
	return &Session{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Issuer:                          issuer,
				Subject:                         subject,
				RequestedAt:                     time.Now().UTC(),
				AuthTime:                        authTime,
				AuthenticationMethodsReferences: amr,
				Extra: map[string]any{
					"sid": sessionID,
					"tid": tenantID,
				},
			},
			Headers: &jwt.Headers{Extra: map[string]any{}},
			Subject: subject,
		},
		TenantID:  tenantID,
		SessionID: sessionID,
	}
}

// GetExtraClaims makes Warden's own identifiers visible to token introspection.
//
// fosite's introspection response copies whatever a session offers here, skipping the
// names RFC 7662 reserves. What Warden adds is `sid` and `tid`: a resource server that
// introspects a token can then tie it to the session that issued it — which is what
// makes "this token came from a session that has since been ended" answerable — without
// a second lookup and without Warden inventing a private extension field.
//
// fosite's own DefaultSession implements this and openid.DefaultSession does not, so
// without this method the two identifiers are in the id token and nowhere else.
func (s *Session) GetExtraClaims() map[string]any {
	extra := map[string]any{}
	if s.TenantID != "" {
		extra["tid"] = s.TenantID
	}
	if s.SessionID != "" {
		extra["sid"] = s.SessionID
	}
	return extra
}

// NewEmptySession returns a session of the concrete type the storage decodes into.
//
// fosite hands the storage whatever session the caller supplied and expects its own type
// back; an endpoint that passed a bare &Session{} would depend on the stored JSON having
// populated every embedded pointer, which is true until a session is stored without
// claims. Building it here means one place knows the shape.
func NewEmptySession() *Session {
	return &Session{
		DefaultSession: &openid.DefaultSession{
			Claims:  &jwt.IDTokenClaims{Extra: map[string]any{}},
			Headers: &jwt.Headers{Extra: map[string]any{}},
		},
	}
}

// Clone is required by fosite, which copies sessions between requests.
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	cloned, ok := s.DefaultSession.Clone().(*openid.DefaultSession)
	if !ok {
		return nil
	}
	return &Session{DefaultSession: cloned, TenantID: s.TenantID, SessionID: s.SessionID}
}

// Provider is Warden's OpenID Provider: fosite, configured.
type Provider struct {
	fosite.OAuth2Provider

	issuer  string
	storage *Storage
	keys    *keys.Manager
	log     *slog.Logger

	// config is retained so the discovery document and the handlers can answer from
	// the same values fosite enforces, rather than from a second copy that drifts.
	config *fosite.Config

	// strategy is the token strategy the provider was composed with. The introspection
	// endpoint needs it to derive a signature from a presented token.
	strategy *oauth2.HMACSHAStrategy
}

// ProviderOptions configure a Provider.
type ProviderOptions struct {
	Issuer string
	// AccessTokenTTL comes from security.access_token_ttl, which SPEC §8.2 bounds to
	// 5–15 minutes.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is the idle lifetime of a refresh chain.
	RefreshTokenTTL time.Duration
	Keys            *keys.Manager
	Log             *slog.Logger
	// GlobalSecret keys fosite's HMAC token strategy, which is what produces the
	// signatures the storage adapter stores. It must be stable across replicas and
	// across restarts: change it and every outstanding code and token stops verifying.
	GlobalSecret []byte
	// SecretParams are the Argon2id parameters client secrets are hashed with. They
	// must match the registry's, which is the only thing that writes them.
	SecretParams authn.Params
}

// NewProvider builds the provider.
//
// The factory list is the specification of what Warden implements, and what is absent
// from it is as deliberate as what is present. There is no OAuth2AuthorizeImplicitFactory
// and no ResourceOwnerPasswordCredentialsFactory: SPEC §7.7 excludes both grants, and
// M1-6 requires them *absent rather than disabled*. A handler that is never composed
// cannot be switched on by configuration, and a client that asked for one would already
// have been refused by oauth_client_no_forbidden_grants.
func NewProvider(storage *Storage, opts ProviderOptions) (*Provider, error) {
	switch {
	case storage == nil:
		return nil, errors.New("the provider requires its storage")
	case opts.Issuer == "":
		return nil, errors.New("the provider requires an issuer")
	case opts.Keys == nil:
		return nil, errors.New("the provider requires the signing key manager")
	case len(opts.GlobalSecret) < 32:
		return nil, errors.New(
			"the provider requires at least 32 bytes of global secret: it keys the HMAC " +
				"that produces every code and token signature")
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	accessTTL := opts.AccessTokenTTL
	if accessTTL <= 0 {
		accessTTL = 10 * time.Minute
	}
	refreshTTL := opts.RefreshTokenTTL
	if refreshTTL <= 0 {
		refreshTTL = 7 * 24 * time.Hour
	}

	cfg := &fosite.Config{
		IDTokenIssuer:     opts.Issuer,
		AccessTokenIssuer: opts.Issuer,

		AccessTokenLifespan:   accessTTL,
		RefreshTokenLifespan:  refreshTTL,
		AuthorizeCodeLifespan: authorizeCodeLifetime,
		IDTokenLifespan:       accessTTL,

		// PKCE for everyone. The schema already forces it on public clients, which is
		// where RFC 8252 and OAuth 2.1 require it; enforcing it globally means a
		// confidential client cannot quietly omit it either, and there is no good
		// reason for one to.
		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false, // S256 only: "plain" is not a proof of anything

		// Exact-match redirect URIs (SPEC §17). fosite's default already compares
		// exactly; this is the setting that keeps a future default from loosening it.
		ScopeStrategy:            fosite.ExactScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,

		GlobalSecret: opts.GlobalSecret,

		// The lifetime the PAR response advertises. Set explicitly so that the
		// expires_in a client is told matches the expires_at the row carries; with
		// fosite's default they would be two different numbers describing one deadline.
		PushedAuthorizeContextLifespan: parLifetime,

		// Refresh tokens are rotated and their reuse is detected, so a grace period
		// would be a window in which a stolen token is honoured. Warden has none, and
		// the storage adapter's RevokeRefreshTokenMaybeGracePeriod says the same.
		RefreshTokenScopes: []string{"offline", "offline_access"},

		SendDebugMessagesToClients: false,

		// Warden's own hasher, not fosite's bcrypt. The registry writes client secrets
		// as Argon2id, so the provider has to read them the same way; without this
		// every confidential client fails authentication at every endpoint.
		ClientSecretsHasher: NewSecretHasher(opts.SecretParams),
	}

	// The signing key is fetched per request rather than pinned here, so a rotation
	// (M1-1) takes effect without restarting the process.
	keyGetter := func(ctx context.Context) (any, error) {
		return opts.Keys.SigningKey(ctx)
	}

	// Retained rather than passed anonymously: the introspection endpoint has to turn
	// a bearer token back into the signature the storage is keyed by, and doing that
	// with a second strategy built from the same configuration would be one more place
	// for the two to disagree about what a token looks like.
	strategy := compose.NewOAuth2HMACStrategy(cfg)

	provider := compose.Compose(
		cfg,
		storage,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
		compose.PushedAuthorizeHandlerFactory,
		func(c fosite.Configurator, s any, _ any) any {
			return compose.OpenIDConnectExplicitFactory(c, s,
				compose.NewOpenIDConnectStrategy(keyGetter, c))
		},
		func(c fosite.Configurator, s any, _ any) any {
			return compose.OpenIDConnectRefreshFactory(c, s,
				compose.NewOpenIDConnectStrategy(keyGetter, c))
		},
	)

	return &Provider{
		OAuth2Provider: provider,
		issuer:         opts.Issuer,
		storage:        storage,
		keys:           opts.Keys,
		log:            log,
		config:         cfg,
		strategy:       strategy,
	}, nil
}

// AccessTokenSignature returns the storage key for a presented access token.
//
// Warden's tokens are opaque: the half after the dot is the signature, and it is what
// oauth_session is keyed by. Callers use it to resolve a token to its tenant before the
// provider is asked to do anything with it — introspection needs a scope in order to
// refuse a token belonging to somebody else's tenant, and it has only the token.
func (p *Provider) AccessTokenSignature(ctx context.Context, token string) string {
	return p.strategy.AccessTokenSignature(ctx, token)
}

// RefreshTokenSignature is the same for a refresh token.
func (p *Provider) RefreshTokenSignature(ctx context.Context, token string) string {
	return p.strategy.RefreshTokenSignature(ctx, token)
}

// Issuer returns the provider's issuer, which is the "iss" of every token it signs.
func (p *Provider) Issuer() string { return p.issuer }

// Storage returns the adapter, for the handlers that need it directly.
func (p *Provider) Storage() *Storage { return p.storage }

// NewGlobalSecret derives fosite's HMAC secret from the deployment's KEK.
//
// Derived rather than configured, and that is the point: it has to be identical on every
// replica and stable across restarts, and an operator asked to generate and distribute
// one more secret will eventually not. The KEK already has both properties, is already
// required at startup, and is already the thing whose loss makes a deployment
// unrecoverable — so binding this to it adds no new failure mode.
//
// It is derived, not used directly, so that the value fosite holds in memory is not the
// key that opens the signing keys.
func NewGlobalSecret(keyring *secrets.Keyring) ([]byte, error) {
	if keyring == nil {
		return nil, errors.New("deriving the provider secret requires the keyring")
	}
	return keyring.Derive("warden/oidc-provider/hmac", 32)
}

// --- discovery ---------------------------------------------------------------------

// Discovery is the OpenID Provider Metadata of RFC 8414 and OIDC Discovery 1.0.
//
// Only what Warden actually implements appears. A discovery document that advertises a
// grant the provider does not compose is worse than one that omits it: a client will
// build against the advertisement and fail at the endpoint.
type Discovery struct {
	Issuer                             string `json:"issuer"`
	AuthorizationEndpoint              string `json:"authorization_endpoint"`
	TokenEndpoint                      string `json:"token_endpoint"`
	UserinfoEndpoint                   string `json:"userinfo_endpoint"`
	JWKSURI                            string `json:"jwks_uri"`
	IntrospectionEndpoint              string `json:"introspection_endpoint"`
	RevocationEndpoint                 string `json:"revocation_endpoint"`
	EndSessionEndpoint                 string `json:"end_session_endpoint"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`

	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	ResponseModesSupported []string `json:"response_modes_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
	SubjectTypesSupported  []string `json:"subject_types_supported"`

	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`

	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	ClaimsSupported               []string `json:"claims_supported"`

	// RequirePushedAuthorizationRequests is false: PAR is offered, not compulsory.
	RequirePushedAuthorizationRequests bool `json:"require_pushed_authorization_requests"`
}

// Discovery renders the metadata document.
func (p *Provider) Discovery(algorithms []string) Discovery {
	base := strings.TrimSuffix(p.issuer, "/")
	if len(algorithms) == 0 {
		algorithms = []string{AlgRS256}
	}
	return Discovery{
		Issuer:                             base + "/",
		AuthorizationEndpoint:              base + "/oauth2/authorize",
		TokenEndpoint:                      base + "/oauth2/token",
		UserinfoEndpoint:                   base + "/oauth2/userinfo",
		JWKSURI:                            base + "/.well-known/jwks.json",
		IntrospectionEndpoint:              base + "/oauth2/introspect",
		RevocationEndpoint:                 base + "/oauth2/revoke",
		EndSessionEndpoint:                 base + "/oauth2/logout",
		PushedAuthorizationRequestEndpoint: base + "/oauth2/par",

		ScopesSupported: []string{"openid", "profile", "email", "offline_access"},

		// "code" alone. Every other response type in OIDC Core returns a token
		// through the front channel, which is the implicit grant wearing a different
		// name, and SPEC §7.7 excludes it.
		ResponseTypesSupported: []string{"code"},
		ResponseModesSupported: []string{"query", "form_post"},

		GrantTypesSupported: []string{
			GrantAuthorizationCode,
			GrantRefreshToken,
			GrantClientCredentials,
		},

		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: algorithms,
		TokenEndpointAuthMethodsSupported: []string{
			AuthMethodNone, AuthMethodClientSecretBasic, AuthMethodClientSecretPost,
		},

		// S256 only. "plain" sends the verifier in the clear, which proves nothing to
		// anyone who saw the authorization request.
		CodeChallengeMethodsSupported: []string{"S256"},

		ClaimsSupported: []string{
			"iss", "sub", "aud", "exp", "iat", "jti", "auth_time", "nonce",
			"amr", "azp", "sid", "tid", "email", "email_verified", "name",
		},
	}
}

// signingAlgorithmOf reports what the active key signs with, for the discovery document.
//
// The JSON Web Key case comes first and is the one that actually happens: the key manager
// returns a *jose.JSONWebKey so that fosite puts the right `kid` in the id-token header.
// Its Algorithm field is what the database recorded, which is more authoritative than
// inferring one from the key type — an RSA key could in principle be used with PS256.
// The bare-key cases remain for a caller that has unwrapped it.
func signingAlgorithmOf(key any) (string, error) {
	switch typed := key.(type) {
	case *jose.JSONWebKey:
		if typed.Algorithm != "" {
			return typed.Algorithm, nil
		}
		return signingAlgorithmOf(typed.Key)
	case *rsa.PrivateKey:
		return AlgRS256, nil
	case *ecdsa.PrivateKey:
		return AlgES256, nil
	default:
		return "", fmt.Errorf("unsupported signing key type %T", key)
	}
}

// Algorithms reports the signing algorithms a relying party should expect.
func (p *Provider) Algorithms(ctx context.Context) ([]string, error) {
	key, err := p.keys.SigningKey(ctx)
	if err != nil {
		return nil, err
	}
	algorithm, err := signingAlgorithmOf(key)
	if err != nil {
		return nil, err
	}
	return []string{algorithm}, nil
}

// Config exposes fosite's configuration, so a handler answers from the values fosite
// enforces rather than from a second copy.
func (p *Provider) Config() *fosite.Config { return p.config }

// providerConfigFromWarden maps Warden's configuration onto the provider's.
func ProviderOptionsFrom(
	cfg *config.Config, km *keys.Manager, keyring *secrets.Keyring,
	params authn.Params, log *slog.Logger,
) (ProviderOptions, error) {
	secret, err := NewGlobalSecret(keyring)
	if err != nil {
		return ProviderOptions{}, err
	}
	return ProviderOptions{
		Issuer:          cfg.Issuer,
		AccessTokenTTL:  cfg.Security.AccessTokenTTL,
		RefreshTokenTTL: cfg.Security.RefreshTokenIdleLifetime,
		Keys:            km,
		Log:             log,
		GlobalSecret:    secret,
		SecretParams:    params,
	}, nil
}
