package keys

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
)

// rotationLockKey serialises rotation across replicas. Any constant would do; this
// one is derived from a name so that a second advisory lock added later cannot
// collide with it by both authors picking 1.
var rotationLockKey = advisoryKey("warden/signing-key-rotation")

func advisoryKey(name string) int64 {
	sum := sha256.Sum256([]byte(name))
	return int64(binary.BigEndian.Uint64(sum[:8])) //nolint:gosec // a lock id, not a number
}

// defaultCacheTTL bounds how long this process may keep using a key set another
// replica has since changed.
//
// Staleness here is safe in one direction and not the other, which is what makes a
// short TTL sufficient rather than a change-stream subscription. Signing with a key
// that another replica has just demoted to 'previous' produces a token that verifies
// fine, because a demoted key stays in JWKS for the whole overlap window. Serving a
// JWKS that is a minute behind is likewise harmless: it can only ever be a superset
// of the keys in use, never missing one, because a key is published from the moment
// it is created and removed only after the overlap.
const defaultCacheTTL = time.Minute

// Manager owns the deployment's signing keys: it hands out the signer, publishes
// JWKS, and performs rotation.
//
// It runs on the system pool. Signing keys are deployment-level, not tenant-scoped —
// one issuer signs every tenant's tokens — and signing_key is registered as a
// deliberate exception to row-level security for exactly that reason.
type Manager struct {
	system  *store.Store
	keyring *secrets.Keyring
	log     *slog.Logger

	algorithm        string
	rotationInterval time.Duration
	overlap          time.Duration

	// now is injectable so that tests can move a 90-day rotation interval past
	// without waiting 90 days.
	now func() time.Time

	cacheTTL time.Duration

	mu      sync.Mutex
	signer  *cachedSigner
	jwksDoc *cachedJWKS
}

type cachedSigner struct {
	kid       string
	algorithm string
	signer    jose.Signer
	// private is the parsed key itself, for callers that sign with something other
	// than this package's Sign — the OpenID Provider hands it to fosite, which has its
	// own JWT machinery.
	private  crypto.PrivateKey
	loadedAt time.Time
}

type cachedJWKS struct {
	body     []byte
	etag     string
	loadedAt time.Time
}

// NewManager builds the key manager from resolved configuration.
//
// system must be the BYPASSRLS pool: every statement here is deployment-level, and a
// tenant-scoped connection would see no signing keys at all.
func NewManager(system *store.Store, keyring *secrets.Keyring, cfg *config.Config, log *slog.Logger) (*Manager, error) {
	if system == nil {
		return nil, errors.New("key management requires the system connection")
	}
	if keyring == nil {
		return nil, errors.New("key management requires the keyring; check security.kek")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		system:           system,
		keyring:          keyring,
		log:              log,
		algorithm:        cfg.Security.TokenSigningAlgorithm,
		rotationInterval: cfg.Security.KeyRotationInterval,
		overlap:          cfg.Security.KeyOverlapWindow,
		now:              time.Now,
		cacheTTL:         defaultCacheTTL,
	}, nil
}

// SetClock replaces the manager's notion of the current time. For tests.
func (m *Manager) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

// SetCacheTTL replaces the cache lifetime. For tests, which need rotation to be
// visible on the next call rather than a minute later.
func (m *Manager) SetCacheTTL(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheTTL = d
}

// ---------------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------------

// Sign produces a compact JWS over claims, signed by the active key.
//
// The "kid" header is always set. A relying party that has to guess which key signed
// a token is a relying party that breaks the moment the second key exists, which is
// to say on the first rotation.
func (m *Manager) Sign(ctx context.Context, claims any) (string, error) {
	s, err := m.activeSigner(ctx)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encoding the claims: %w", err)
	}
	sig, err := s.signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return sig.CompactSerialize()
}

// ActiveKID reports which key new tokens are being signed by.
func (m *Manager) ActiveKID(ctx context.Context) (string, error) {
	s, err := m.activeSigner(ctx)
	if err != nil {
		return "", err
	}
	return s.kid, nil
}

func (m *Manager) activeSigner(ctx context.Context) (*cachedSigner, error) {
	m.mu.Lock()
	if m.signer != nil && m.now().Sub(m.signer.loadedAt) < m.cacheTTL {
		s := m.signer
		m.mu.Unlock()
		return s, nil
	}
	m.mu.Unlock()

	var (
		kid, algorithm string
		privateDER     []byte
	)
	err := m.system.InSystem(ctx, "loading the active signing key", func(ctx context.Context, tx pgx.Tx) error {
		var err error
		kid, privateDER, algorithm, err = Active(ctx, tx, m.keyring)
		return err
	})
	if err != nil {
		return nil, err
	}
	// The DER is opened afresh on every cache miss and dropped as soon as it is
	// parsed; what stays in memory is the parsed key the signer holds, which it needs
	// anyway.
	priv, err := parsePrivateDER(privateDER)
	zero(privateDER)
	if err != nil {
		return nil, err
	}

	signer, err := newJOSESigner(algorithm, kid, priv)
	if err != nil {
		return nil, err
	}
	loaded := &cachedSigner{
		kid: kid, algorithm: algorithm, signer: signer,
		private: priv, loadedAt: m.now(),
	}

	m.mu.Lock()
	m.signer = loaded
	m.mu.Unlock()
	return loaded, nil
}

func newJOSESigner(algorithm, kid string, priv crypto.PrivateKey) (jose.Signer, error) {
	var alg jose.SignatureAlgorithm
	switch algorithm {
	case RS256:
		alg = jose.RS256
	case ES256:
		alg = jose.ES256
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", algorithm)
	}
	return jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: algorithm}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
}

// SigningKey returns the active private key as a JSON Web Key, for callers with their
// own JWT machinery.
//
// A JWK rather than the bare key, because it carries the `kid`. The OpenID Provider
// hands this to fosite, and fosite puts the key id straight into the id-token header —
// so a relying party can select the right key from JWKS without Warden having to
// remember to set the header itself. Getting that wrong is invisible until the first
// rotation, at which point every id token stops verifying.
//
// It follows the same cache as Sign, so a rotation is picked up within the cache TTL
// without restarting the process.
func (m *Manager) SigningKey(ctx context.Context) (any, error) {
	s, err := m.activeSigner(ctx)
	if err != nil {
		return nil, err
	}
	return &jose.JSONWebKey{
		Key:       s.private,
		KeyID:     s.kid,
		Algorithm: s.algorithm,
		Use:       "sig",
	}, nil
}

// ---------------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------------

// JWKS returns the published key set and its ETag.
//
// It sweeps expired overlap windows first, so a key leaves JWKS on the schedule the
// configuration describes rather than whenever the rotation worker last ran. The
// sweep is one indexed UPDATE that usually matches nothing; doing it here means the
// published document is correct even in a deployment running no worker at all.
func (m *Manager) JWKS(ctx context.Context) (body []byte, etag string, err error) {
	m.mu.Lock()
	if m.jwksDoc != nil && m.now().Sub(m.jwksDoc.loadedAt) < m.cacheTTL {
		doc := m.jwksDoc
		m.mu.Unlock()
		return doc.body, doc.etag, nil
	}
	m.mu.Unlock()

	var set []PublicKey
	err = m.system.InSystem(ctx, "publishing JWKS", func(ctx context.Context, tx pgx.Tx) error {
		if _, sweepErr := db.New(tx).RetireOverlappedSigningKeys(ctx, m.cutoff()); sweepErr != nil {
			return fmt.Errorf("retiring keys past their overlap window: %w", sweepErr)
		}
		var readErr error
		set, readErr = PublicSet(ctx, tx)
		return readErr
	})
	if err != nil {
		return nil, "", err
	}

	body, etag, err = MarshalJWKS(set)
	if err != nil {
		return nil, "", err
	}

	m.mu.Lock()
	m.jwksDoc = &cachedJWKS{body: body, etag: etag, loadedAt: m.now()}
	m.mu.Unlock()
	return body, etag, nil
}

func (m *Manager) cutoff() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now().Add(-m.overlap)
}

// ---------------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------------

// RotationState describes where the deployment stands relative to its schedule.
type RotationState struct {
	KID       string
	Algorithm string
	CreatedAt time.Time
	// ExpiresAt is when the key stops signing. Nil means it was written before
	// rotation had a schedule, which is treated as due.
	ExpiresAt *time.Time
	Due       bool
}

// State reports the active key and whether it is due for rotation.
func (m *Manager) State(ctx context.Context) (RotationState, error) {
	var out RotationState
	err := m.system.InSystem(ctx, "reading the signing key schedule", func(ctx context.Context, tx pgx.Tx) error {
		row, err := db.New(tx).ActiveSigningKeyMeta(ctx)
		if err != nil {
			return err
		}
		out = RotationState{
			KID: row.Kid, Algorithm: row.Algorithm,
			CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt,
			Due: row.ExpiresAt == nil || !m.now().Before(*row.ExpiresAt),
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return RotationState{}, ErrNotInitialised
	}
	return out, err
}

// ErrNotInitialised is returned when the deployment has no signing key at all.
var ErrNotInitialised = errors.New(
	"no active signing key: the deployment has not been initialised (run `warden init`)")

// ErrRotationHeld is returned when another replica holds the rotation lock. It is not
// a failure: the other replica is doing the work.
var ErrRotationHeld = errors.New("another process is rotating the signing key")

// Rotate generates a new signing key, demotes the current one, and retires anything
// whose overlap window has passed.
//
// All three happen in one transaction under an advisory lock, so a concurrent rotation
// on another replica waits and then finds the key no longer due rather than generating
// a second one. force skips the due check, which is what `warden keys rotate` uses:
// an operator rotating after a suspected compromise is not asking whether it is time.
func (m *Manager) Rotate(ctx context.Context, force bool) (newKID string, err error) {
	// Generating the key before the transaction opens is deliberate. It is the
	// expensive part — an RSA-3072 keygen is tens of milliseconds — and the store's
	// retry loop re-runs a callback from the top on a serialization failure, so work
	// done inside would be repeated. It also means the transaction holds the advisory
	// lock for a query's worth of time rather than a keygen's.
	key, err := Generate(m.algorithm, m.keyring)
	if err != nil {
		return "", err
	}
	// Generate stamps the wall clock; the schedule has to run on the manager's clock,
	// which is the same thing in production and a test's clock under test. Everything
	// downstream — expires_at, "is this key due?", the overlap cutoff — is derived
	// from this one timestamp, so having two sources for it is how a rotation ends up
	// due a few milliseconds after it was performed.
	key.CreatedAt = m.now().UTC()

	err = m.system.InSystem(ctx, "rotating the signing key", func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)

		held, lockErr := q.TryLockKeyRotation(ctx, rotationLockKey)
		if lockErr != nil {
			return fmt.Errorf("taking the rotation lock: %w", lockErr)
		}
		if !held {
			return ErrRotationHeld
		}

		if !force {
			row, metaErr := q.ActiveSigningKeyMeta(ctx)
			switch {
			case errors.Is(metaErr, pgx.ErrNoRows):
				// No active key at all: rotating into one is the right repair.
			case metaErr != nil:
				return metaErr
			case row.ExpiresAt != nil && m.now().Before(*row.ExpiresAt):
				return errNotDue
			}
		}

		if insertErr := Insert(ctx, tx, key, m.rotationInterval); insertErr != nil {
			return insertErr
		}
		// Swept in the same transaction as the demotion, so JWKS never shows a
		// moment with three generations of key in it.
		_, sweepErr := q.RetireOverlappedSigningKeys(ctx, m.cutoff())
		return sweepErr
	})
	switch {
	case errors.Is(err, errNotDue):
		return "", nil
	case err != nil:
		return "", err
	}

	m.invalidate()
	m.log.Info("rotated the signing key",
		"kid", key.KID, "algorithm", key.Algorithm,
		"overlap_window", m.overlap, "next_rotation", key.CreatedAt.Add(m.rotationInterval))
	return key.KID, nil
}

// errNotDue unwinds the transaction when the active key turns out to be current. It
// never reaches a caller: Rotate translates it to "nothing to do".
var errNotDue = errors.New("the active signing key is not due for rotation")

// Sweep retires keys whose overlap window has passed, without rotating.
func (m *Manager) Sweep(ctx context.Context) (retired int64, err error) {
	err = m.system.InSystem(ctx, "retiring keys past their overlap window", func(ctx context.Context, tx pgx.Tx) error {
		var sweepErr error
		retired, sweepErr = db.New(tx).RetireOverlappedSigningKeys(ctx, m.cutoff())
		return sweepErr
	})
	if retired > 0 {
		m.invalidate()
	}
	return retired, err
}

// List returns every key the deployment has held, newest first, for `warden keys list`.
func (m *Manager) List(ctx context.Context) ([]db.ListSigningKeysRow, error) {
	var rows []db.ListSigningKeysRow
	err := m.system.InSystem(ctx, "listing the signing keys", func(ctx context.Context, tx pgx.Tx) error {
		var listErr error
		rows, listErr = db.New(tx).ListSigningKeys(ctx)
		return listErr
	})
	return rows, err
}

func (m *Manager) invalidate() {
	m.mu.Lock()
	m.signer, m.jwksDoc = nil, nil
	m.mu.Unlock()
}
