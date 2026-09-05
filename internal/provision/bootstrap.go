package provision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/authz"
	"github.com/warden-project/warden/internal/keys"
	"github.com/warden-project/warden/internal/secrets"
	"github.com/warden-project/warden/internal/store/db"
)

// SystemTenantID is the reserved tenant holding deployment operators (SPEC §6.3).
const (
	SystemTenantID   = "ten_system"
	SystemTenantSlug = "system"
)

// setupTokenLifetime bounds the one-time URL. Short on purpose: a setup link that
// stays valid for a week is a password with extra steps, and it is emailed, pasted
// into chat, and left in a terminal buffer like any other string.
const setupTokenLifetime = 30 * time.Minute

// ErrAlreadyInitialised is returned when the deployment has already been bootstrapped.
var ErrAlreadyInitialised = errors.New("this deployment is already initialised")

// BootstrapResult is what `warden init` produces.
type BootstrapResult struct {
	TenantID string
	OwnerID  string
	Email    string

	// SetupURL is shown once. Only its hash is stored, so it cannot be recovered —
	// which is the point, and the reason the command says so plainly.
	SetupURL  string
	ExpiresAt time.Time

	SigningKeyID  string
	SigningKeyAlg string
}

// Bootstrap prepares a fresh deployment: the system tenant, its first owner, a
// signing key, and a single-use URL for the owner to establish a credential.
//
// There is no default password, and never was one to change. SPEC §20.2 states this
// as a rule; the reason it is a rule is that a default credential is the single most
// reliably exploited thing in self-hosted software, because the deployment that
// forgets to change it looks exactly like the one that did.
//
// It refuses to run twice. Running it again on a live deployment would otherwise mint
// a fresh setup URL for an existing owner — which is a password reset with no
// authentication in front of it.
func (p *Provisioner) Bootstrap(ctx context.Context, ownerEmail, issuer, algorithm string, keyring *secrets.Keyring) (*BootstrapResult, error) {
	if _, err := mail.ParseAddress(ownerEmail); err != nil {
		return nil, fmt.Errorf("owner email %q is not a valid address: %w", ownerEmail, err)
	}
	if keyring == nil {
		return nil, errors.New("bootstrapping requires the keyring; check security.kek")
	}
	base, err := url.Parse(issuer)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("issuer %q is not a usable URL", issuer)
	}

	// Generated before the transaction: an RSA key takes long enough that holding a
	// transaction open across it is needless.
	key, err := keys.Generate(algorithm, keyring)
	if err != nil {
		return nil, err
	}

	token, tokenHash, err := newSetupToken()
	if err != nil {
		return nil, err
	}

	result := &BootstrapResult{
		TenantID:      SystemTenantID,
		Email:         ownerEmail,
		ExpiresAt:     time.Now().UTC().Add(setupTokenLifetime),
		SigningKeyID:  key.KID,
		SigningKeyAlg: key.Algorithm,
	}

	err = p.db.InSystem(ctx, "bootstrapping the deployment", func(ctx context.Context, tx pgx.Tx) error {
		// The check and the writes are in one transaction, so two concurrent inits
		// cannot both decide the deployment is empty.
		q := db.New(tx)
		initialised, scanErr := q.TenantExists(ctx, SystemTenantID)
		if scanErr != nil {
			return scanErr
		}
		if initialised {
			return ErrAlreadyInitialised
		}

		if execErr := q.InsertTenant(ctx, db.InsertTenantParams{
			ID: SystemTenantID, Slug: SystemTenantSlug, Name: "Deployment",
		}); execErr != nil {
			return fmt.Errorf("creating the system tenant: %w", execErr)
		}
		if execErr := q.EnrolTenantInEveryApplication(ctx, SystemTenantID); execErr != nil {
			return execErr
		}

		ownerID := id("usr", "owner_system")
		result.OwnerID = ownerID
		// status stays 'invited' until the setup URL is redeemed. An owner who never
		// redeems it can therefore do nothing, rather than existing as an active
		// account with no credential.
		if execErr := q.InsertUserWithoutAttributes(ctx, db.InsertUserWithoutAttributesParams{
			ID: ownerID, TenantID: SystemTenantID, Email: ownerEmail, Status: "invited",
		}); execErr != nil {
			return fmt.Errorf("creating the first owner: %w", execErr)
		}

		grantID := "grn_" + randomSuffix()
		if execErr := q.InsertBootstrapGrant(ctx, db.InsertBootstrapGrantParams{
			ID: grantID, TenantID: SystemTenantID,
			SubjectUserID: &ownerID, ScopeKind: authz.ScopeTenant,
		}); execErr != nil {
			return fmt.Errorf("granting system.owner: %w", execErr)
		}

		if insertErr := keys.Insert(ctx, tx, key, 90*24*time.Hour); insertErr != nil {
			return insertErr
		}

		setupID := "stk_" + randomSuffix()
		if execErr := q.InsertSetupToken(ctx, db.InsertSetupTokenParams{
			ID: setupID, TenantID: SystemTenantID, UserID: ownerID,
			TokenHash: tokenHash, ExpiresAt: result.ExpiresAt,
		}); execErr != nil {
			return fmt.Errorf("storing the setup token: %w", execErr)
		}

		// The audit log's first entry. Deliberately records the owner's address and
		// the key id, and deliberately records neither the token nor the private key.
		return p.record(ctx, tx, audit.Entry{
			TenantID: SystemTenantID, Action: "deployment.initialised",
			TargetType: "tenant", TargetID: SystemTenantID,
			ActorClientID: "warden init",
			After: map[string]any{
				"owner_email": ownerEmail, "owner_id": ownerID,
				"signing_key_kid": key.KID, "signing_key_algorithm": key.Algorithm,
				"setup_token_expires_at": result.ExpiresAt,
			},
			Reason: "deployment bootstrap",
		})
	})
	if err != nil {
		return nil, err
	}

	base.Path = strings.TrimRight(base.Path, "/") + "/setup"
	q := base.Query()
	q.Set("token", token)
	base.RawQuery = q.Encode()
	result.SetupURL = base.String()

	return result, nil
}

// IsInitialised reports whether the deployment has been bootstrapped.
func (p *Provisioner) IsInitialised(ctx context.Context) (bool, error) {
	var yes bool
	err := p.db.InSystem(ctx, "checking whether the deployment is initialised", func(ctx context.Context, tx pgx.Tx) error {
		var err error
		yes, err = db.New(tx).TenantExists(ctx, SystemTenantID)
		return err
	})
	return yes, err
}

// newSetupToken returns the token to print and the hash to store. 256 bits from
// crypto/rand: this is the only thing standing between a fresh deployment and its
// first administrator.
func newSetupToken() (token string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = "wst_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}
