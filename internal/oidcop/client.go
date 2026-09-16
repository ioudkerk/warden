// Package oidcop is Warden acting as an OpenID Provider (SPEC §7.7).
//
// The protocol machinery is fosite's; what lives here is the part fosite cannot know:
// where clients are stored, how they are authenticated, which tenant a request belongs
// to, and what Warden is prepared to issue.
package oidcop

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/jackc/pgx/v5"
	"github.com/ory/fosite"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
)

// Grant types and response types Warden implements.
//
// SPEC §7.7 excludes the implicit grant and the resource-owner password grant, and
// M1-6's exit condition sharpens that to *absent, not disabled*. The schema enforces it
// — oauth_client_no_forbidden_grants rejects the row — and these constants are the
// other half: there is no name here to configure a client with.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"

	ResponseTypeCode = "code"
)

// Signing algorithms, matching internal/keys. SPEC §8.2 makes RS256 the default and
// ES256 selectable; symmetric algorithms are deliberately absent, because a relying
// party must be able to verify without holding anything that could mint.
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
)

// Token endpoint authentication methods.
const (
	AuthMethodNone              = "none"
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodPrivateKeyJWT     = "private_key_jwt"
)

// ErrNoSuchClient is returned when a client id resolves to nothing, or to something in
// another tenant. The two are the same answer on purpose: a caller able to tell them
// apart could enumerate which client ids exist across the deployment.
var ErrNoSuchClient = errors.New("no such client")

// Client is a registered OAuth 2.0 / OIDC client.
//
// It implements fosite.Client and fosite.OpenIDConnectClient, so the value that comes
// out of the store is the value fosite works with — no adapter type in between to fall
// out of step with the row.
type Client struct {
	ID       string
	TenantID string
	Key      string
	Name     string

	Public     bool
	SecretHash string

	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	Scopes                  []string
	Audiences               []string
	TokenEndpointAuthMethod string
	PostLogoutRedirectURIs  []string
	RequirePKCE             bool

	DisabledAt *time.Time
	CreatedAt  time.Time
}

// Enabled reports whether the client may be used.
func (c *Client) Enabled() bool { return c.DisabledAt == nil }

// --- fosite.Client -----------------------------------------------------------------

func (c *Client) GetID() string { return c.ID }

// GetHashedSecret returns the stored secret hash.
//
// fosite compares this with its own hasher, and Warden's is Argon2id from
// internal/authn, so the provider is configured with a hasher that delegates there
// rather than to fosite's bcrypt default. See newSecretHasher.
func (c *Client) GetHashedSecret() []byte { return []byte(c.SecretHash) }

func (c *Client) GetRedirectURIs() []string       { return c.RedirectURIs }
func (c *Client) GetGrantTypes() fosite.Arguments { return fosite.Arguments(c.GrantTypes) }
func (c *Client) GetResponseTypes() fosite.Arguments {
	return fosite.Arguments(c.ResponseTypes)
}
func (c *Client) GetScopes() fosite.Arguments { return fosite.Arguments(c.Scopes) }
func (c *Client) IsPublic() bool              { return c.Public }

// GetAudience returns what tokens for this client may be addressed to.
//
// Empty in the row means "this client only", which is the safe reading: a token with no
// stated audience that some resource server accepts anyway is how one service's token
// ends up being honoured by another.
func (c *Client) GetAudience() fosite.Arguments {
	if len(c.Audiences) == 0 {
		return fosite.Arguments{c.ID}
	}
	return fosite.Arguments(c.Audiences)
}

// --- fosite.OpenIDConnectClient ----------------------------------------------------

// GetRequestURIs returns the pre-registered request_uri values.
//
// Empty, and deliberately so: request_uri makes the provider fetch a URL the client
// names, which is a server-side request forgery primitive (SPEC §17, "SSRF"). Pushed
// Authorization Requests give the same benefit without Warden fetching anything.
func (c *Client) GetRequestURIs() []string { return nil }

// GetJSONWebKeys returns the client's keys for private_key_jwt. Not yet stored;
// SPEC §8.4 lists private_key_jwt for high-assurance clients and the schema has a place
// for the method, but key material is not modelled until a client needs it.
func (c *Client) GetJSONWebKeys() *jose.JSONWebKeySet { return nil }

// GetJSONWebKeysURI returns nothing, for the SSRF reason GetRequestURIs gives.
func (c *Client) GetJSONWebKeysURI() string { return "" }

// GetRequestObjectSigningAlgorithm pins the algorithm for signed request objects.
func (c *Client) GetRequestObjectSigningAlgorithm() string { return AlgRS256 }

func (c *Client) GetTokenEndpointAuthMethod() string { return c.TokenEndpointAuthMethod }

func (c *Client) GetTokenEndpointAuthSigningAlgorithm() string { return AlgRS256 }

// --- registry ----------------------------------------------------------------------

// Clients is the client registry.
type Clients struct {
	tenant *store.Store
	system *store.Store
	// params are the Argon2id parameters client secrets are hashed with — the same
	// ones user passwords use. A client secret is a password that belongs to a program.
	params authn.Params
}

// NewClients builds the registry.
func NewClients(tenant, system *store.Store, params authn.Params) (*Clients, error) {
	if tenant == nil {
		return nil, errors.New("the client registry requires the tenant-scoped connection")
	}
	if params == (authn.Params{}) {
		params = authn.DefaultParams()
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	return &Clients{tenant: tenant, system: system, params: params}, nil
}

// TenantOf resolves a client id to its tenant.
//
// The system pool, and the only registry call that uses it: the token endpoint is
// handed a client_id and has to find the tenant before a tenant scope can exist. The
// same chicken-and-egg refresh tokens have, solved the same way.
func (r *Clients) TenantOf(ctx context.Context, clientID string) (string, error) {
	if r.system == nil {
		return "", errors.New(
			"resolving a client needs database.system_url: a client_id arrives before any " +
				"tenant scope exists")
	}
	var tenantID string
	err := r.system.InSystem(ctx, "resolving an OAuth client to its tenant",
		func(ctx context.Context, tx pgx.Tx) error {
			var resolveErr error
			tenantID, resolveErr = db.New(tx).OAuthClientTenant(ctx, clientID)
			return resolveErr
		}, store.ReadOnly())
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoSuchClient
	}
	return tenantID, err
}

// ByID loads a client within a tenant.
func (r *Clients) ByID(ctx context.Context, tenantID, clientID string) (*Client, error) {
	var client *Client
	err := r.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		row, queryErr := db.New(tx).OAuthClientByID(ctx, db.OAuthClientByIDParams{
			TenantID: tenantID, ID: clientID,
		})
		if queryErr != nil {
			return queryErr
		}
		client = clientFromRow(row)
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoSuchClient
	}
	return client, err
}

// Lookup resolves a client id with no tenant known, which is what the protocol
// endpoints have. It is TenantOf followed by ByID, and it exists so that call sites do
// not each reimplement the two-step.
func (r *Clients) Lookup(ctx context.Context, clientID string) (*Client, error) {
	tenantID, err := r.TenantOf(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return r.ByID(ctx, tenantID, clientID)
}

// ByKey loads a client by its human handle, for administrative commands.
func (r *Clients) ByKey(ctx context.Context, tenantID, key string) (*Client, error) {
	var client *Client
	err := r.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		row, queryErr := db.New(tx).OAuthClientByKey(ctx, db.OAuthClientByKeyParams{
			TenantID: tenantID, Key: key,
		})
		if queryErr != nil {
			return queryErr
		}
		client = clientFromKeyRow(row)
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoSuchClient
	}
	return client, err
}

// List returns a tenant's clients.
func (r *Clients) List(ctx context.Context, tenantID string) ([]db.ListOAuthClientsRow, error) {
	var rows []db.ListOAuthClientsRow
	err := r.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var listErr error
		rows, listErr = db.New(tx).ListOAuthClients(ctx, tenantID)
		return listErr
	})
	return rows, err
}

// NewClientOptions describes a client to register.
type NewClientOptions struct {
	TenantID string
	Key      string
	Name     string
	// Public clients get no secret and are forced to use PKCE.
	Public                 bool
	RedirectURIs           []string
	GrantTypes             []string
	Scopes                 []string
	Audiences              []string
	PostLogoutRedirectURIs []string
}

// Register creates a client, returning the generated secret for a confidential one.
//
// The secret is returned once and never again: only its Argon2id hash is stored, for
// the same reason a user's password is.
func (r *Clients) Register(ctx context.Context, o NewClientOptions) (client *Client, secret string, err error) {
	if validateErr := validateNewClient(&o); validateErr != nil {
		return nil, "", validateErr
	}

	id, err := newClientID()
	if err != nil {
		return nil, "", err
	}

	authMethod, secretHash := AuthMethodNone, ""
	if !o.Public {
		secret, err = newClientSecret()
		if err != nil {
			return nil, "", err
		}
		// Hashed before the transaction opens: the store's retry loop re-runs a
		// callback from the top, and a secret generated inside would differ between
		// attempts — the caller would be handed one value and the database would hold
		// another. The same convention M0-7 records and M1-5 relies on.
		secretHash, err = authn.Hash(secret, r.params)
		if err != nil {
			return nil, "", err
		}
		authMethod = AuthMethodClientSecretBasic
	}

	var storedHash *string
	if secretHash != "" {
		storedHash = &secretHash
	}

	if insertErr := r.tenant.InTenant(ctx, o.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return db.New(tx).InsertOAuthClient(ctx, db.InsertOAuthClientParams{
			ID: id, TenantID: o.TenantID, Key: o.Key, Name: o.Name,
			Public: o.Public, SecretHash: storedHash,
			RedirectUris: o.RedirectURIs, GrantTypes: o.GrantTypes,
			ResponseTypes: []string{ResponseTypeCode}, Scopes: o.Scopes,
			Audiences: o.Audiences, TokenEndpointAuthMethod: authMethod,
			PostLogoutRedirectUris: o.PostLogoutRedirectURIs,
			// Public clients are forced to PKCE by the schema; confidential ones get
			// it anyway, because there is no good reason not to and OAuth 2.1 makes it
			// universal.
			RequirePkce: true,
		})
	}); insertErr != nil {
		return nil, "", insertErr
	}

	registered, err := r.ByID(ctx, o.TenantID, id)
	if err != nil {
		return nil, "", err
	}
	return registered, secret, nil
}

// AuthenticateSecret verifies a confidential client's secret.
//
// Constant work whether or not the client exists, for the reason authn.Authenticate
// gives at length: a token endpoint that answers faster for an unknown client_id is an
// enumeration oracle for client ids.
func (r *Clients) AuthenticateSecret(ctx context.Context, client *Client, presented string) (bool, error) {
	stored := ""
	if client != nil {
		stored = client.SecretHash
	}
	if stored == "" {
		// No client, or a public one. Verify against a decoy so the timing matches.
		decoy, err := authn.DecoyHash(r.params)
		if err != nil {
			return false, err
		}
		if _, verifyErr := authn.Verify(presented, decoy); verifyErr != nil {
			return false, verifyErr
		}
		return false, nil
	}
	return authn.Verify(presented, stored)
}

// SetSecret rotates a confidential client's secret, returning the new value once.
func (r *Clients) SetSecret(ctx context.Context, tenantID, clientID string) (string, error) {
	secret, err := newClientSecret()
	if err != nil {
		return "", err
	}
	hash, err := authn.Hash(secret, r.params)
	if err != nil {
		return "", err
	}

	var affected int64
	if err := r.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var updateErr error
		affected, updateErr = db.New(tx).SetOAuthClientSecret(ctx, db.SetOAuthClientSecretParams{
			TenantID: tenantID, ID: clientID, SecretHash: &hash,
		})
		return updateErr
	}); err != nil {
		return "", err
	}
	if affected == 0 {
		return "", fmt.Errorf("%w, or it is a public client and has no secret", ErrNoSuchClient)
	}
	return secret, nil
}

// SetEnabled disables or re-enables a client.
func (r *Clients) SetEnabled(ctx context.Context, tenantID, clientID string, enabled bool) error {
	var disabledAt *time.Time
	if !enabled {
		now := time.Now().UTC()
		disabledAt = &now
	}
	var affected int64
	if err := r.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var updateErr error
		affected, updateErr = db.New(tx).SetOAuthClientDisabled(ctx, db.SetOAuthClientDisabledParams{
			TenantID: tenantID, ID: clientID, DisabledAt: disabledAt,
		})
		return updateErr
	}); err != nil {
		return err
	}
	if affected == 0 {
		return ErrNoSuchClient
	}
	return nil
}

// Delete removes a client.
func (r *Clients) Delete(ctx context.Context, tenantID, clientID string) error {
	var affected int64
	if err := r.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var deleteErr error
		affected, deleteErr = db.New(tx).DeleteOAuthClient(ctx, db.DeleteOAuthClientParams{
			TenantID: tenantID, ID: clientID,
		})
		return deleteErr
	}); err != nil {
		return err
	}
	if affected == 0 {
		return ErrNoSuchClient
	}
	return nil
}

// --- validation --------------------------------------------------------------------

// forbiddenGrants are the ones SPEC §7.7 excludes. The schema rejects them too; this
// is the earlier, friendlier refusal, and it names the reason.
var forbiddenGrants = map[string]string{
	"implicit": "the implicit grant returns tokens in the URL fragment, where they reach " +
		"browser history and referrer headers; use the code flow with PKCE",
	"password": "the resource-owner password grant requires the client to handle the " +
		"user's password, which defeats the point of having an authorization server",
}

func validateNewClient(o *NewClientOptions) error {
	switch {
	case o.TenantID == "":
		return errors.New("a client needs a tenant")
	case o.Key == "":
		return errors.New("a client needs a key")
	case o.Name == "":
		o.Name = o.Key
	}

	if len(o.GrantTypes) == 0 {
		o.GrantTypes = []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	for _, grant := range o.GrantTypes {
		if reason, forbidden := forbiddenGrants[grant]; forbidden {
			return fmt.Errorf("the %q grant is not implemented: %s (SPEC §7.7)", grant, reason)
		}
	}

	if len(o.Scopes) == 0 {
		o.Scopes = []string{"openid", "profile", "email"}
	}

	// A nil slice reaches Postgres as NULL, not as the column's empty-array default, so
	// a caller who simply did not set Audiences would hit a not-null violation rather
	// than getting the default. Normalising here means the zero value of
	// NewClientOptions is usable.
	if o.Audiences == nil {
		o.Audiences = []string{}
	}
	if o.PostLogoutRedirectURIs == nil {
		o.PostLogoutRedirectURIs = []string{}
	}
	if o.RedirectURIs == nil {
		o.RedirectURIs = []string{}
	}

	usesCode := false
	for _, grant := range o.GrantTypes {
		if grant == GrantAuthorizationCode {
			usesCode = true
		}
	}
	if usesCode && len(o.RedirectURIs) == 0 {
		return errors.New("a client using the authorization code flow needs at least one redirect_uri")
	}
	for _, raw := range o.RedirectURIs {
		if err := validateRedirectURI(raw); err != nil {
			return err
		}
	}
	for _, raw := range o.PostLogoutRedirectURIs {
		if err := validateRedirectURI(raw); err != nil {
			return err
		}
	}
	return nil
}

// validateRedirectURI rejects the forms that make an allowlist stop being one.
//
// SPEC §17 requires exact match with no wildcards in production. The comparison at
// request time is string equality, so a registered value containing a wildcard would
// simply never match — a silent failure. Refusing it here says so instead.
func validateRedirectURI(raw string) error {
	if strings.ContainsAny(raw, "*?") {
		return fmt.Errorf(
			"redirect_uri %q contains a wildcard. Redirect URIs are matched exactly "+
				"(SPEC §17); register each one in full", raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri %q is not a URL: %w", raw, err)
	}
	if parsed.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf(
			"redirect_uri %q has a fragment. The authorization response appends its own, "+
				"so a registered fragment cannot survive", raw)
	}
	switch {
	case parsed.Scheme == "":
		return fmt.Errorf("redirect_uri %q has no scheme; it must be absolute", raw)
	case parsed.Scheme == "http" && !isLoopback(parsed.Hostname()):
		// RFC 8252 §8.3 allows http only for loopback, where there is no network to
		// intercept. Anywhere else it hands the code to whoever is between.
		return fmt.Errorf(
			"redirect_uri %q is http on a non-loopback host. Use https, or "+
				"http://127.0.0.1 for a native app (RFC 8252 §8.3)", raw)
	}
	return nil
}

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// --- identifiers -------------------------------------------------------------------

// newClientID generates the opaque protocol client_id.
func newClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "oac_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// newClientSecret generates a confidential client's secret: 256 bits, like every other
// bearer credential Warden mints.
func newClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ocs_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func clientFromRow(r db.OAuthClientByIDRow) *Client {
	c := &Client{
		ID: r.ID, TenantID: r.TenantID, Key: r.Key, Name: r.Name,
		Public: r.Public, RedirectURIs: r.RedirectUris, GrantTypes: r.GrantTypes,
		ResponseTypes: r.ResponseTypes, Scopes: r.Scopes, Audiences: r.Audiences,
		TokenEndpointAuthMethod: r.TokenEndpointAuthMethod,
		PostLogoutRedirectURIs:  r.PostLogoutRedirectUris,
		RequirePKCE:             r.RequirePkce,
		DisabledAt:              r.DisabledAt, CreatedAt: r.CreatedAt,
	}
	if r.SecretHash != nil {
		c.SecretHash = *r.SecretHash
	}
	return c
}

func clientFromKeyRow(r db.OAuthClientByKeyRow) *Client {
	return clientFromRow(db.OAuthClientByIDRow(r))
}

// --- the secret hasher fosite uses --------------------------------------------------

// secretHasher lets fosite compare client secrets with Warden's hasher instead of its
// own.
//
// fosite's default is bcrypt. Warden's credentials are Argon2id with the parameters
// SPEC §7.2 fixes, and a provider holding two hashing schemes would eventually store a
// secret under one and verify it under the other. Since the registry writes the hash,
// the provider has to read it the same way — so this delegates to internal/authn, and
// there is exactly one place that knows what a Warden secret hash looks like.
//
// The symptom when this is missing is worth recording: every confidential client fails
// authentication with "client credentials are invalid", at every endpoint, while public
// clients keep working — so a deployment using only public clients never notices.
type secretHasher struct{ params authn.Params }

// errSecretMismatch is what fosite tests for; it only checks for non-nil.
var errSecretMismatch = errors.New("the client secret does not match")

func (h secretHasher) Compare(_ context.Context, hash, data []byte) error {
	if len(hash) == 0 {
		// A public client, or a confidential one with no secret stored. Comparing
		// nothing must fail rather than succeed.
		return errSecretMismatch
	}
	ok, err := authn.Verify(string(data), string(hash))
	if err != nil {
		return err
	}
	if !ok {
		return errSecretMismatch
	}
	return nil
}

func (h secretHasher) Hash(_ context.Context, data []byte) ([]byte, error) {
	encoded, err := authn.Hash(string(data), h.params)
	if err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}

// NewSecretHasher returns the hasher the provider is configured with.
func NewSecretHasher(params authn.Params) fosite.Hasher { return secretHasher{params: params} }
