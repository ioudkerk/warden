package oidcop

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ory/fosite"

	"github.com/warden-project/warden/internal/authn"
	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
	"github.com/warden-project/warden/internal/store/dbtypes"
)

// The kinds of artifact the provider stores. They are the `kind` column of
// oauth_session, and they exist as constants so a typo is a compile error rather than a
// row nothing will ever find.
const (
	kindAuthorizeCode   = "authorize_code"
	kindAccessToken     = "access_token"
	kindPKCE            = "pkce"
	kindOpenID          = "openid"
	kindPAR             = "par"
	kindClientAssertion = "client_assertion"
)

// tenantKey carries the tenant through fosite.
//
// fosite's storage interfaces take (ctx, signature, session) and nothing else — it has
// no notion of a tenant and no place to put one. The HTTP handlers resolve the client to
// its tenant before calling fosite and put it here, so the storage methods have a scope
// without re-resolving it on every call. Without this, each of the several storage calls
// in one token exchange would need its own lookup on the system pool.
type tenantKey struct{}

// WithTenant returns a context carrying the tenant the request belongs to.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenantID)
}

// TenantFrom returns the tenant a request was resolved to.
func TenantFrom(ctx context.Context) (string, bool) {
	tenantID, ok := ctx.Value(tenantKey{}).(string)
	return tenantID, ok && tenantID != ""
}

// Storage implements the fosite interfaces Warden's provider needs:
// fosite.ClientManager, oauth2.CoreStorage, openid.OpenIDConnectRequestStorage,
// pkce.PKCERequestStorage and fosite.PARStorage.
//
// Everything it stores is keyed by a *signature*, which is fosite's term for the half of
// a token it keeps rather than the half it hands out — and Warden hashes even that, on
// the principle that a copy of the database should not be a working set of tokens.
type Storage struct {
	tenant   *store.Store
	system   *store.Store
	clients  *Clients
	refresh  *authn.RefreshTokens
	sessions *authn.Sessions
	log      *slog.Logger
}

// StorageOptions configure a Storage.
type StorageOptions struct {
	// Refresh carries M1-5's family rotation and reuse detection. Required: fosite's
	// refresh storage is implemented against Warden's refresh_token table so that a
	// replayed token revokes its family and raises the security event, rather than
	// fosite maintaining a second set of tokens with no such behaviour.
	Refresh  *authn.RefreshTokens
	Sessions *authn.Sessions
	Log      *slog.Logger
}

// NewStorage builds the provider's storage adapter.
func NewStorage(tenant, system *store.Store, clients *Clients, opts StorageOptions) (*Storage, error) {
	switch {
	case tenant == nil:
		return nil, errors.New("provider storage requires the tenant-scoped connection")
	case clients == nil:
		return nil, errors.New("provider storage requires the client registry")
	case opts.Refresh == nil:
		return nil, errors.New(
			"provider storage requires the refresh-token store: refresh tokens are kept in " +
				"refresh_token so that reuse revokes the family (SPEC §8.3)")
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	return &Storage{
		tenant: tenant, system: system, clients: clients,
		refresh: opts.Refresh, sessions: opts.Sessions, log: log,
	}, nil
}

// Clients returns the registry, for handlers that need to resolve a client to its
// tenant before fosite is involved.
func (s *Storage) Clients() *Clients { return s.clients }

// signatureHash is what actually goes in the database.
func signatureHash(signature string) []byte {
	sum := sha256.Sum256([]byte(signature))
	return sum[:]
}

// tenantOf returns the tenant for a request, preferring the one the handler resolved.
//
// The fallback exists for the paths fosite reaches without a handler having established
// scope — introspection of a token whose client is not the caller, for one. It costs a
// round trip on the system pool, which is why the context value is the normal route.
func (s *Storage) tenantOf(ctx context.Context, kind, signature string) (string, error) {
	if tenantID, ok := TenantFrom(ctx); ok {
		return tenantID, nil
	}
	if s.system == nil {
		return "", errors.New(
			"resolving an OAuth artifact needs database.system_url when the request has no tenant scope")
	}
	var tenantID string
	err := s.system.InSystem(ctx, "resolving an OAuth artifact to its tenant",
		func(ctx context.Context, tx pgx.Tx) error {
			var resolveErr error
			tenantID, resolveErr = db.New(tx).OAuthSessionTenant(ctx, db.OAuthSessionTenantParams{
				Kind: kind, SignatureHash: signatureHash(signature),
			})
			return resolveErr
		}, store.ReadOnly())
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fosite.ErrNotFound
	}
	return tenantID, err
}

// --- fosite.ClientManager ----------------------------------------------------------

// GetClient loads a client for fosite.
func (s *Storage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	client, err := s.clients.Lookup(ctx, id)
	if errors.Is(err, ErrNoSuchClient) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !client.Enabled() {
		// Disabled is answered as absent. A caller able to tell them apart learns that
		// a client id is real, which is the one thing a disabled client should stop
		// telling people.
		return nil, fosite.ErrNotFound
	}
	return client, nil
}

// ClientAssertionJWTValid reports whether a private_key_jwt assertion has been seen.
//
// Replay protection for client authentication: an assertion is single-use, so a jti
// already recorded means somebody is presenting one twice.
func (s *Storage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	tenantID, ok := TenantFrom(ctx)
	if !ok {
		// No scope yet: the assertion is being validated before the client is known.
		// Resolving it would need the system pool, and there is nothing to find unless
		// it has been seen, so treat an unknown scope as unseen.
		return nil
	}

	var found bool
	err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		row, queryErr := db.New(tx).OAuthSessionBySignature(ctx, db.OAuthSessionBySignatureParams{
			Kind: kindClientAssertion, SignatureHash: signatureHash(jti),
		})
		if errors.Is(queryErr, pgx.ErrNoRows) {
			return nil
		}
		if queryErr != nil {
			return queryErr
		}
		found = time.Now().Before(row.ExpiresAt)
		return nil
	})
	if err != nil {
		return err
	}
	if found {
		return fosite.ErrJTIKnown
	}
	return nil
}

// SetClientAssertionJWT records a jti so it cannot be presented again.
func (s *Storage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	tenantID, ok := TenantFrom(ctx)
	if !ok {
		return errors.New("recording a client assertion needs a tenant scope")
	}
	clientID, _ := ctx.Value(assertionClientKey{}).(string) //nolint:errcheck // absent is the empty string, which the column allows

	return s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return db.New(tx).InsertOAuthSession(ctx, db.InsertOAuthSessionParams{
			SignatureHash: signatureHash(jti), Kind: kindClientAssertion,
			TenantID: tenantID, RequestID: jti, ClientID: clientID,
			Form: dbtypes.JSONMap{}, SessionData: dbtypes.JSONMap{},
			RequestedScope: []string{}, GrantedScope: []string{},
			RequestedAudience: []string{}, GrantedAudience: []string{},
			RequestedAt: time.Now().UTC(), ExpiresAt: exp,
		})
	})
}

// assertionClientKey carries the client a JWT assertion belongs to, for the row's
// foreign key. fosite does not pass it to SetClientAssertionJWT.
type assertionClientKey struct{}

// WithAssertionClient notes which client an assertion is being validated for.
func WithAssertionClient(ctx context.Context, clientID string) context.Context {
	return context.WithValue(ctx, assertionClientKey{}, clientID)
}

// --- the generic session store -----------------------------------------------------

// create writes one artifact.
func (s *Storage) create(ctx context.Context, kind, signature string, request fosite.Requester, expires time.Time) error {
	tenantID, ok := TenantFrom(ctx)
	if !ok {
		resolved, err := s.clients.TenantOf(ctx, request.GetClient().GetID())
		if err != nil {
			return err
		}
		tenantID = resolved
	}

	form := encodeForm(request.GetRequestForm())
	sessionData, err := encodeSession(request.GetSession())
	if err != nil {
		return err
	}

	subject, wardenSession := subjectAndSession(request.GetSession())

	return s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return db.New(tx).InsertOAuthSession(ctx, db.InsertOAuthSessionParams{
			SignatureHash: signatureHash(signature), Kind: kind,
			TenantID: tenantID, RequestID: request.GetID(),
			ClientID: request.GetClient().GetID(),
			Subject:  subject, SessionID: wardenSession,
			RequestedScope:    orEmpty(request.GetRequestedScopes()),
			GrantedScope:      orEmpty(request.GetGrantedScopes()),
			RequestedAudience: orEmpty(request.GetRequestedAudience()),
			GrantedAudience:   orEmpty(request.GetGrantedAudience()),
			Form:              form, SessionData: sessionData,
			RequestedAt: request.GetRequestedAt(), ExpiresAt: expires,
		})
	})
}

// get reads one artifact and rehydrates it into a fosite.Request.
//
// An inactive row is returned *with* fosite.ErrInvalidatedAuthorizeCode rather than as
// an error alone, because fosite needs the request in order to revoke everything
// descended from it. Returning only the error would report the replay and leave the
// tokens it produced alive — the same trap M1-5 fell into and climbed out of.
func (s *Storage) get(ctx context.Context, kind, signature string, session fosite.Session) (fosite.Requester, error) {
	tenantID, err := s.tenantOf(ctx, kind, signature)
	if err != nil {
		return nil, err
	}

	var row db.OauthSession
	err = s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var queryErr error
		row, queryErr = db.New(tx).OAuthSessionBySignature(ctx, db.OAuthSessionBySignatureParams{
			Kind: kind, SignatureHash: signatureHash(signature),
		})
		return queryErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	request, err := s.hydrate(ctx, row, session)
	if err != nil {
		return nil, err
	}
	if !row.Active {
		switch kind {
		case kindAuthorizeCode:
			return request, fosite.ErrInvalidatedAuthorizeCode
		default:
			return request, fosite.ErrInactiveToken
		}
	}
	return request, nil
}

// hydrate rebuilds a fosite.Request from a stored row.
func (s *Storage) hydrate(ctx context.Context, row db.OauthSession, session fosite.Session) (fosite.Requester, error) {
	client, err := s.clients.ByID(ctx, row.TenantID, row.ClientID)
	if err != nil {
		return nil, err
	}

	form := decodeForm(row.Form)
	// The caller supplies an empty session of the right concrete type; decoding into it
	// is how fosite gets its own type back rather than a map.
	if session != nil && len(row.SessionData) > 0 {
		if err := decodeSession(row.SessionData, session); err != nil {
			return nil, err
		}
	}

	return &fosite.Request{
		ID:                row.RequestID,
		RequestedAt:       row.RequestedAt,
		Client:            client,
		RequestedScope:    fosite.Arguments(row.RequestedScope),
		GrantedScope:      fosite.Arguments(row.GrantedScope),
		RequestedAudience: fosite.Arguments(row.RequestedAudience),
		GrantedAudience:   fosite.Arguments(row.GrantedAudience),
		Form:              form,
		Session:           session,
	}, nil
}

func (s *Storage) deactivate(ctx context.Context, kind, signature string) error {
	tenantID, err := s.tenantOf(ctx, kind, signature)
	if err != nil {
		return err
	}
	return s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, updateErr := db.New(tx).DeactivateOAuthSession(ctx, db.DeactivateOAuthSessionParams{
			Kind: kind, SignatureHash: signatureHash(signature),
		})
		return updateErr
	})
}

func (s *Storage) remove(ctx context.Context, kind, signature string) error {
	tenantID, err := s.tenantOf(ctx, kind, signature)
	if errors.Is(err, fosite.ErrNotFound) {
		// Deleting something already gone is not a failure.
		return nil
	}
	if err != nil {
		return err
	}
	return s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, deleteErr := db.New(tx).DeleteOAuthSession(ctx, db.DeleteOAuthSessionParams{
			Kind: kind, SignatureHash: signatureHash(signature),
		})
		return deleteErr
	})
}

// --- oauth2.AuthorizeCodeStorage ---------------------------------------------------

// authorizeCodeLifetime bounds how long a code may sit unredeemed.
//
// OAuth 2.1 recommends a maximum of ten minutes and notes that one is usually enough.
// A code is exchanged within seconds of the redirect in every working flow; a longer
// window only widens the period in which an intercepted code is worth something.
const authorizeCodeLifetime = time.Minute

func (s *Storage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	return s.create(ctx, kindAuthorizeCode, code, request,
		time.Now().UTC().Add(authorizeCodeLifetime))
}

func (s *Storage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	return s.get(ctx, kindAuthorizeCode, code, session)
}

// InvalidateAuthorizeCodeSession marks a code used. Deactivated, not deleted: a second
// presentation must be distinguishable from an unknown code, because the first is a
// replay and revokes the exchange while the second is a typo.
func (s *Storage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return s.deactivate(ctx, kindAuthorizeCode, code)
}

// --- oauth2.AccessTokenStorage -----------------------------------------------------

func (s *Storage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	expires := request.GetSession().GetExpiresAt(fosite.AccessToken)
	if expires.IsZero() {
		expires = time.Now().UTC().Add(10 * time.Minute)
	}
	return s.create(ctx, kindAccessToken, signature, request, expires)
}

func (s *Storage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.get(ctx, kindAccessToken, signature, session)
}

func (s *Storage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.remove(ctx, kindAccessToken, signature)
}

// --- pkce.PKCERequestStorage -------------------------------------------------------

func (s *Storage) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	// The challenge lives exactly as long as the code it protects; a PKCE record
	// outliving its code would be a verifier waiting for a code that can no longer be
	// redeemed.
	return s.create(ctx, kindPKCE, signature, request,
		time.Now().UTC().Add(authorizeCodeLifetime))
}

func (s *Storage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.get(ctx, kindPKCE, signature, session)
}

func (s *Storage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.remove(ctx, kindPKCE, signature)
}

// --- openid.OpenIDConnectRequestStorage --------------------------------------------

func (s *Storage) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, request fosite.Requester) error {
	return s.create(ctx, kindOpenID, authorizeCode, request,
		time.Now().UTC().Add(authorizeCodeLifetime))
}

func (s *Storage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, request fosite.Requester) (fosite.Requester, error) {
	stored, err := s.get(ctx, kindOpenID, authorizeCode, request.GetSession())
	if errors.Is(err, fosite.ErrNotFound) {
		// fosite's own sentinel for this storage, which its handler tests for.
		return nil, fosite.ErrNotFound
	}
	return stored, err
}

func (s *Storage) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return s.remove(ctx, kindOpenID, authorizeCode)
}

// --- fosite.PARStorage -------------------------------------------------------------

// parLifetime bounds a pushed authorization request. RFC 9126 suggests between five and
// sixty seconds; a minute matches the authorization code, which is the next step.
const parLifetime = time.Minute

func (s *Storage) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	return s.create(ctx, kindPAR, requestURI, request, time.Now().UTC().Add(parLifetime))
}

func (s *Storage) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	stored, err := s.get(ctx, kindPAR, requestURI, nil)
	if err != nil {
		return nil, err
	}
	request, ok := stored.(*fosite.Request)
	if !ok {
		return nil, errors.New("the stored pushed authorization request has the wrong type")
	}
	return &fosite.AuthorizeRequest{Request: *request}, nil
}

func (s *Storage) DeletePARSession(ctx context.Context, requestURI string) error {
	return s.remove(ctx, kindPAR, requestURI)
}

// --- serialization -----------------------------------------------------------------

// encodeForm stores a url.Values as JSON.
func encodeForm(form url.Values) dbtypes.JSONMap {
	if len(form) == 0 {
		return dbtypes.JSONMap{}
	}
	out := make(dbtypes.JSONMap, len(form))
	for key, values := range form {
		// The client secret can arrive in the form on a client_secret_post exchange,
		// and this row is long-lived compared with the request. Storing it would make
		// oauth_session a second copy of the credential store.
		if key == "client_secret" || key == "password" || key == "client_assertion" {
			continue
		}
		out[key] = values
	}
	return out
}

func decodeForm(stored dbtypes.JSONMap) url.Values {
	form := url.Values{}
	for key, raw := range stored {
		switch typed := raw.(type) {
		case []any:
			for _, v := range typed {
				if str, ok := v.(string); ok {
					form.Add(key, str)
				}
			}
		case string:
			form.Add(key, typed)
		}
	}
	return form
}

func encodeSession(session fosite.Session) (dbtypes.JSONMap, error) {
	if session == nil {
		return dbtypes.JSONMap{}, nil
	}
	encoded, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("encoding the session: %w", err)
	}
	var out dbtypes.JSONMap
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, fmt.Errorf("encoding the session: %w", err)
	}
	return out, nil
}

func decodeSession(stored dbtypes.JSONMap, into fosite.Session) error {
	encoded, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, into)
}

// orEmpty turns a nil slice into an empty one.
//
// A nil []string reaches Postgres as NULL, not as the column's empty-array default, so a
// request with no audience would violate a not-null constraint rather than store an
// empty array. fosite returns nil for every unset Arguments, which makes this the normal
// case rather than an edge one.
func orEmpty(values fosite.Arguments) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// subjectAndSession pulls Warden's own identifiers out of a fosite session.
//
// They are stored as columns rather than left inside the JSON because they are what
// revocation queries by: "end every token of this session" is an indexed lookup, not a
// scan with a JSON path in it.
func subjectAndSession(session fosite.Session) (subject string, wardenSession *string) {
	if session == nil {
		return "", nil
	}
	subject = session.GetSubject()
	if carrier, ok := session.(interface{ WardenSessionID() string }); ok {
		if sid := carrier.WardenSessionID(); sid != "" {
			return subject, &sid
		}
	}
	return subject, nil
}
