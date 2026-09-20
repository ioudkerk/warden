package authn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/store/db"
	"github.com/warden-project/warden/internal/store/dbtypes"
)

// WebAuthn as a second factor (SPEC §7.1).
//
// The one factor here that a phishing page cannot relay. A TOTP code is six digits a person
// will type wherever they are asked to, including into a convincing copy of this login page;
// a WebAuthn assertion is signed over the *origin* the browser is actually talking to, so an
// assertion collected by warden-login.example is worthless against warden.example. That is
// the property, and it is why the origin check below is not a detail.
//
// Unlike TOTP, this is not hand-written. The credential format is CBOR wrapped in COSE with
// attestation statements in half a dozen formats, none of which is sixty lines, and none of
// which has published test vectors that would prove an implementation correct. The library
// is pinned to the last release that holds ADR-0001's Go floor.

// The library is asked for a second factor, not a passkey.
//
// v1 uses WebAuthn to *confirm* somebody who has already presented a password, which is what
// SPEC §7.1 lists as supported; passwordless arrives in v1.1. So: no resident key, and user
// verification is discouraged rather than required — asking a security key for a PIN when a
// password has just been typed is a second factor twice, and the people it inconveniences are
// the ones who bought a key with no keypad.
const (
	// webAuthnSessionLifetime bounds how long a challenge is worth answering.
	webAuthnSessionLifetime = 5 * time.Minute

	// webAuthnUserHandleBytes is the opaque user handle. WebAuthn §5.4.3 recommends the
	// full 64 bytes and requires it not be derived from anything displayable — so it is
	// not the user id, which appears in logs, in tokens and in URLs.
	webAuthnUserHandleBytes = 32
)

// ErrWebAuthnUnavailable is returned when the provider was not configured.
var ErrWebAuthnUnavailable = errors.New(
	"WebAuthn is not configured: it needs an https issuer to derive a relying-party id from")

// ErrCredentialCloned is raised when an authenticator's signature counter goes backwards.
//
// WebAuthn §6.1.1 says this is evidence that a credential has been copied: a real
// authenticator's counter only ever increases, so two of them answering for one credential
// is the signature of a clone. Refused rather than logged, because the alternative is
// accepting one.
var ErrCredentialCloned = errors.New("this authenticator appears to have been cloned")

// webAuthnUser adapts a Warden user to the library's interface.
//
// The handle is stored rather than derived. Deriving it from the user id would be simpler
// and would also publish the user id to every authenticator the person registers, which
// §5.4.3 asks implementations not to do.
type webAuthnUser struct {
	handle      []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return u.handle }
func (u *webAuthnUser) WebAuthnName() string                       { return u.name }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// WebAuthnOptions configure the relying party.
type WebAuthnOptions struct {
	// RPDisplayName is what an authenticator shows when it asks the person to confirm.
	RPDisplayName string
	// RPID is the domain the credential is bound to. A credential registered for one is
	// useless at another, which is the anti-phishing property; it must be the effective
	// domain of the issuer, not a path or a port.
	RPID string
	// Origins are the exact origins a browser may present. Derived from the issuer.
	Origins []string
}

// WebAuthnOptionsFromIssuer derives the relying-party configuration from the issuer.
//
// Derived rather than configured, for the same reason the provider's HMAC secret is: an
// operator asked to keep a second copy of "which domain is this" in step with the first will
// eventually not, and the failure mode is that every registered key stops working.
func WebAuthnOptionsFromIssuer(issuer, displayName string) (WebAuthnOptions, error) {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return WebAuthnOptions{}, fmt.Errorf("the issuer is not a URL: %w", err)
	}
	host := parsed.Hostname()
	if host == "" {
		return WebAuthnOptions{}, ErrWebAuthnUnavailable
	}
	if displayName == "" {
		displayName = host
	}

	// The origin carries the scheme and the port; the relying-party id carries neither.
	// Getting that backwards is the most common way a WebAuthn deployment fails, and it
	// fails at registration time on a real browser and nowhere else.
	origin := parsed.Scheme + "://" + parsed.Host
	return WebAuthnOptions{RPDisplayName: displayName, RPID: host, Origins: []string{origin}}, nil
}

// webAuthnProvider builds the library's handle.
func (a *Authenticator) webAuthnProvider() (*webauthn.WebAuthn, error) {
	if a.webAuthn.RPID == "" {
		return nil, ErrWebAuthnUnavailable
	}
	return webauthn.New(&webauthn.Config{
		RPDisplayName: a.webAuthn.RPDisplayName,
		RPID:          a.webAuthn.RPID,
		RPOrigins:     a.webAuthn.Origins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// A second factor, so no resident key and no demand for a PIN. See the note
			// on the constants above.
			ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
			UserVerification: protocol.VerificationDiscouraged,
		},
		// None: Warden does not run an attestation metadata service, and asking for a
		// statement it will not verify would collect the authenticator's model and serial
		// characteristics for nothing. Requesting none is also what keeps the browser
		// from showing a privacy prompt that most people answer wrongly.
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce: true, Timeout: webAuthnSessionLifetime,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce: true, Timeout: webAuthnSessionLifetime,
			},
		},
	})
}

// --- registration ---------------------------------------------------------------------

// WebAuthnChallenge is what the browser needs, plus the identifier that names the stored
// session.
type WebAuthnChallenge struct {
	// Options is the JSON a browser passes to navigator.credentials.create or .get.
	Options json.RawMessage
	// SessionID names the stored challenge. It goes back to the browser and comes back
	// with the answer.
	SessionID string
}

// BeginWebAuthnRegistration starts enrolling a security key.
func (a *Authenticator) BeginWebAuthnRegistration(
	ctx context.Context, tenantID, userID, displayName string,
) (*WebAuthnChallenge, error) {
	provider, err := a.webAuthnProvider()
	if err != nil {
		return nil, err
	}
	if a.cache == nil {
		return nil, errors.New("WebAuthn needs the cache tier to hold a challenge between two requests")
	}

	user, err := a.webAuthnUserFor(ctx, tenantID, userID, displayName)
	if err != nil {
		return nil, err
	}

	// Excluding what is already registered: an authenticator that is asked to create a
	// credential it already holds says so, rather than silently making a second one the
	// person will later be unable to tell apart.
	exclude := make([]protocol.CredentialDescriptor, 0, len(user.credentials))
	for i := range user.credentials {
		exclude = append(exclude, user.credentials[i].Descriptor())
	}

	creation, session, err := provider.BeginRegistration(user,
		webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, fmt.Errorf("beginning a WebAuthn registration: %w", err)
	}

	sessionID, err := a.storeWebAuthnSession(ctx, tenantID, userID, session, user.handle)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(creation.Response)
	if err != nil {
		return nil, fmt.Errorf("encoding the creation options: %w", err)
	}
	return &WebAuthnChallenge{Options: encoded, SessionID: sessionID}, nil
}

// FinishWebAuthnRegistration stores a key the browser has just created.
//
// The label is what the person will see in their security settings. It is theirs to choose,
// and it is the only way to tell two identical-looking keys apart when one of them has to
// be removed.
func (a *Authenticator) FinishWebAuthnRegistration(
	ctx context.Context, tenantID, userID, sessionID, label string, response []byte,
) error {
	provider, err := a.webAuthnProvider()
	if err != nil {
		return err
	}

	stored, err := a.takeWebAuthnSession(ctx, sessionID, tenantID, userID)
	if err != nil {
		return err
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		a.log.Info("a WebAuthn registration response could not be parsed",
			"tenant_id", tenantID, "user_id", userID, "error", err)
		return ErrInvalidSecondFactor
	}

	user, err := a.webAuthnUserFor(ctx, tenantID, userID, "")
	if err != nil {
		return err
	}
	user.handle = stored.UserID

	credential, err := provider.CreateCredential(user, *stored, parsed)
	if err != nil {
		// Includes the origin and relying-party checks, which is where a relayed
		// assertion fails. Logged at info with the reason and answered generically.
		a.log.Info("a WebAuthn registration was refused",
			"tenant_id", tenantID, "user_id", userID, "error", err)
		return ErrInvalidSecondFactor
	}

	id, err := newID("crd")
	if err != nil {
		return err
	}
	params := webAuthnParams(credential, stored.UserID, time.Now().UTC())

	if err := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return db.New(tx).InsertSecondFactor(ctx, db.InsertSecondFactorParams{
			ID: id, UserID: userID, TenantID: tenantID, Type: FactorWebAuthn,
			// The public half of a key pair. Public, so not a secret — but it is what
			// every future assertion is checked against, so an attacker who could
			// replace it could authenticate as this person, and it is protected as
			// integrity-critical rather than as confidential.
			SecretHash: base64.RawURLEncoding.EncodeToString(credential.PublicKey),
			Params:     params,
			Label:      ptrIfNotEmpty(label),
		})
	}); err != nil {
		return fmt.Errorf("storing the WebAuthn credential: %w", err)
	}

	a.recordFactorEvent(ctx, tenantID, userID, ActionSecondFactorEnrolled, FactorWebAuthn,
		"a security key was enrolled")
	return nil
}

// --- assertion ---------------------------------------------------------------------------

// BeginWebAuthnLogin starts the second step for somebody who has passed their password.
func (a *Authenticator) BeginWebAuthnLogin(
	ctx context.Context, tenantID, userID string,
) (*WebAuthnChallenge, error) {
	provider, err := a.webAuthnProvider()
	if err != nil {
		return nil, err
	}

	user, err := a.webAuthnUserFor(ctx, tenantID, userID, "")
	if err != nil {
		return nil, err
	}
	if len(user.credentials) == 0 {
		return nil, ErrNoSecondFactor
	}

	assertion, session, err := provider.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("beginning a WebAuthn login: %w", err)
	}

	sessionID, err := a.storeWebAuthnSession(ctx, tenantID, userID, session, user.handle)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(assertion.Response)
	if err != nil {
		return nil, fmt.Errorf("encoding the assertion options: %w", err)
	}
	return &WebAuthnChallenge{Options: encoded, SessionID: sessionID}, nil
}

// FinishWebAuthnLogin verifies an assertion and reports the method for `amr`.
func (a *Authenticator) FinishWebAuthnLogin(
	ctx context.Context, tenantID, userID, sessionID string, response []byte,
) error {
	provider, err := a.webAuthnProvider()
	if err != nil {
		return err
	}

	stored, err := a.takeWebAuthnSession(ctx, sessionID, tenantID, userID)
	if err != nil {
		return err
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		a.log.Info("a WebAuthn assertion could not be parsed",
			"tenant_id", tenantID, "user_id", userID, "error", err)
		return ErrInvalidSecondFactor
	}

	user, err := a.webAuthnUserFor(ctx, tenantID, userID, "")
	if err != nil {
		return err
	}
	user.handle = stored.UserID
	if len(user.credentials) == 0 {
		return ErrNoSecondFactor
	}

	credential, err := provider.ValidateLogin(user, *stored, parsed)
	if err != nil {
		a.log.Info("a WebAuthn assertion was refused",
			"tenant_id", tenantID, "user_id", userID, "error", err)
		return ErrInvalidSecondFactor
	}

	// WebAuthn §6.1.1: a counter that has not advanced is evidence of a copied
	// credential. Many authenticators — passkeys in particular — report zero forever and
	// cannot be checked this way; a counter that moves and then goes backwards can be,
	// and is refused.
	if credential.Authenticator.CloneWarning {
		a.log.Error("a WebAuthn authenticator reported a signature counter that went backwards",
			"tenant_id", tenantID, "user_id", userID,
			"credential", base64.RawURLEncoding.EncodeToString(credential.ID))
		a.recordFactorEvent(ctx, tenantID, userID, ActionSecondFactorCloned, FactorWebAuthn,
			"an authenticator's signature counter went backwards, which WebAuthn §6.1.1 "+
				"treats as evidence the credential has been copied")
		return ErrCredentialCloned
	}

	a.updateWebAuthnCounter(ctx, tenantID, userID, credential)
	return nil
}

// updateWebAuthnCounter stores the advanced signature counter.
//
// A failure here is logged rather than returned: the assertion was valid, and refusing a
// correct login because a bookkeeping write failed would turn a database blip into a
// lockout. What is lost is one round of clone detection.
func (a *Authenticator) updateWebAuthnCounter(
	ctx context.Context, tenantID, userID string, credential *webauthn.Credential,
) {
	rows, err := a.loadFactors(ctx, tenantID, userID, FactorWebAuthn)
	if err != nil {
		a.log.Error("could not reload a WebAuthn credential", "error", err)
		return
	}

	target := base64.RawURLEncoding.EncodeToString(credential.ID)
	for _, row := range rows {
		if fmt.Sprint(row.Params["credential_id"]) != target {
			continue
		}
		params := cloneParams(row.Params)
		params["sign_count"] = credential.Authenticator.SignCount
		params["backup_state"] = credential.Flags.BackupState

		now := time.Now().UTC()
		if err := a.updateFactor(ctx, tenantID, row.ID, params, &now); err != nil {
			a.log.Error("could not record a WebAuthn signature counter",
				"tenant_id", tenantID, "credential_id", row.ID, "error", err)
		}
		return
	}
}

// --- the stored challenge -----------------------------------------------------------------

// webAuthnSessionRecord is what is held between the two requests.
type webAuthnSessionRecord struct {
	TenantID string               `json:"tid"`
	UserID   string               `json:"sub"`
	Session  webauthn.SessionData `json:"session"`
}

// storeWebAuthnSession puts a challenge in the cache and returns its identifier.
//
// In the cache rather than in a cookie, for the same reason the pending login is: a
// challenge has to be *spent*, and a value the browser holds cannot be taken away. Scoped to
// the user it was issued for, so an identifier cannot be carried from one login into
// another's.
func (a *Authenticator) storeWebAuthnSession(
	ctx context.Context, tenantID, userID string, session *webauthn.SessionData, handle []byte,
) (string, error) {
	if a.cache == nil {
		return "", errors.New("WebAuthn needs the cache tier to hold a challenge between two requests")
	}
	session.UserID = handle

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating a WebAuthn session identifier: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(raw)

	encoded, err := json.Marshal(webAuthnSessionRecord{
		TenantID: tenantID, UserID: userID, Session: *session,
	})
	if err != nil {
		return "", fmt.Errorf("encoding a WebAuthn session: %w", err)
	}
	if err := a.cache.Set(ctx, webAuthnSessionKey(id), encoded, webAuthnSessionLifetime); err != nil {
		return "", fmt.Errorf("storing a WebAuthn session: %w", err)
	}
	return id, nil
}

// takeWebAuthnSession reads a challenge and spends it.
//
// Spent on read, whatever happens next. A challenge that survived a failed attempt would be
// a challenge somebody could keep answering, which is the one thing a challenge exists to
// prevent.
func (a *Authenticator) takeWebAuthnSession(
	ctx context.Context, sessionID, tenantID, userID string,
) (*webauthn.SessionData, error) {
	if a.cache == nil || sessionID == "" {
		return nil, ErrInvalidSecondFactor
	}

	raw, err := a.cache.Get(ctx, webAuthnSessionKey(sessionID))
	if err != nil {
		return nil, ErrInvalidSecondFactor
	}
	if delErr := a.cache.Delete(ctx, webAuthnSessionKey(sessionID)); delErr != nil {
		a.log.Warn("could not spend a WebAuthn challenge", "error", delErr)
	}

	var record webAuthnSessionRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, ErrInvalidSecondFactor
	}
	if record.TenantID != tenantID || record.UserID != userID {
		// The identifier belongs to somebody else's attempt.
		a.log.Warn("a WebAuthn challenge was presented for a different user",
			"tenant_id", tenantID, "user_id", userID)
		return nil, ErrInvalidSecondFactor
	}
	return &record.Session, nil
}

func webAuthnSessionKey(id string) string { return "warden:webauthn_session:" + id }

// --- storage mapping ------------------------------------------------------------------------

// webAuthnUserFor assembles the library's view of a user from the credential rows.
func (a *Authenticator) webAuthnUserFor(
	ctx context.Context, tenantID, userID, displayName string,
) (*webAuthnUser, error) {
	rows, err := a.loadFactors(ctx, tenantID, userID, FactorWebAuthn)
	if err != nil {
		return nil, err
	}

	user := &webAuthnUser{name: displayName, displayName: displayName}
	if user.name == "" {
		user.name = userID
		user.displayName = userID
	}

	for _, row := range rows {
		credential, handle, convErr := credentialFromRow(row)
		if convErr != nil {
			// One unreadable row must not make the others unusable: a person with two
			// keys should still be able to use the second.
			a.log.Error("a stored WebAuthn credential could not be read",
				"tenant_id", tenantID, "credential_id", row.ID, "error", convErr)
			continue
		}
		user.credentials = append(user.credentials, *credential)
		if len(user.handle) == 0 {
			user.handle = handle
		}
	}

	if len(user.handle) == 0 {
		// First registration: a fresh opaque handle, which every later credential for
		// this user shares.
		handle := make([]byte, webAuthnUserHandleBytes)
		if _, err := rand.Read(handle); err != nil {
			return nil, fmt.Errorf("generating a WebAuthn user handle: %w", err)
		}
		user.handle = handle
	}
	return user, nil
}

// webAuthnParams renders a credential's non-key fields for storage.
func webAuthnParams(credential *webauthn.Credential, handle []byte, confirmedAt time.Time) dbtypes.JSONMap {
	transports := make([]string, 0, len(credential.Transport))
	for _, transport := range credential.Transport {
		transports = append(transports, string(transport))
	}

	return dbtypes.JSONMap{
		"credential_id":    base64.RawURLEncoding.EncodeToString(credential.ID),
		"user_handle":      base64.RawURLEncoding.EncodeToString(handle),
		"sign_count":       credential.Authenticator.SignCount,
		"aaguid":           base64.RawURLEncoding.EncodeToString(credential.Authenticator.AAGUID),
		"attestation_type": credential.AttestationType,
		"transports":       strings.Join(transports, ","),
		"backup_eligible":  credential.Flags.BackupEligible,
		"backup_state":     credential.Flags.BackupState,
		// Confirmed on creation: unlike a TOTP secret, the browser has already proved the
		// authenticator answered this challenge. There is nothing further to demonstrate.
		"confirmed_at": confirmedAt.Format(time.RFC3339Nano),
	}
}

// credentialFromRow rebuilds what the library needs from a stored row.
func credentialFromRow(row db.SecondFactorsForUserRow) (*webauthn.Credential, []byte, error) {
	publicKey, err := base64.RawURLEncoding.DecodeString(row.SecretHash)
	if err != nil {
		return nil, nil, fmt.Errorf("the stored public key is not base64: %w", err)
	}
	credentialID, err := decodeParamBytes(row.Params, "credential_id")
	if err != nil {
		return nil, nil, err
	}
	handle, err := decodeParamBytes(row.Params, "user_handle")
	if err != nil {
		return nil, nil, err
	}
	aaguid, _ := decodeParamBytes(row.Params, "aaguid") //nolint:errcheck // optional

	credential := &webauthn.Credential{
		ID:              credentialID,
		PublicKey:       publicKey,
		AttestationType: fmt.Sprint(orEmptyParam(row.Params, "attestation_type")),
		Authenticator: webauthn.Authenticator{
			AAGUID:    aaguid,
			SignCount: uint32(paramUint(row.Params, "sign_count")), //nolint:gosec // a counter
		},
		Flags: webauthn.CredentialFlags{
			BackupEligible: paramBool(row.Params, "backup_eligible"),
			BackupState:    paramBool(row.Params, "backup_state"),
		},
	}
	if raw := fmt.Sprint(orEmptyParam(row.Params, "transports")); raw != "" {
		for _, transport := range strings.Split(raw, ",") {
			credential.Transport = append(credential.Transport,
				protocol.AuthenticatorTransport(transport))
		}
	}
	return credential, handle, nil
}

func decodeParamBytes(params dbtypes.JSONMap, key string) ([]byte, error) {
	raw, present := params[key]
	if !present {
		return nil, fmt.Errorf("the stored credential has no %s", key)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(fmt.Sprint(raw))
	if err != nil {
		return nil, fmt.Errorf("%s is not base64: %w", key, err)
	}
	return decoded, nil
}

func orEmptyParam(params dbtypes.JSONMap, key string) any {
	if value, ok := params[key]; ok {
		return value
	}
	return ""
}

func paramUint(params dbtypes.JSONMap, key string) uint64 {
	switch value := params[key].(type) {
	case float64:
		if value < 0 {
			return 0
		}
		return uint64(value)
	case int64:
		if value < 0 {
			return 0
		}
		return uint64(value)
	default:
		return 0
	}
}

func paramBool(params dbtypes.JSONMap, key string) bool {
	value, _ := params[key].(bool) //nolint:errcheck // absent is false
	return value
}

// ActionSecondFactorCloned records the one WebAuthn event worth an alarm.
const ActionSecondFactorCloned = "security.authenticator_cloned"

// WebAuthnAvailable reports whether this deployment offers security keys.
//
// One source of truth, and that is the point of having it: whether keys are on is decided
// once, where the relying party is configured, and every page asks here rather than
// re-deriving it from the issuer. Two places applying "is this a secure context?" would
// eventually disagree, and the visible symptom would be a button that cannot work.
func (a *Authenticator) WebAuthnAvailable() bool {
	return a.webAuthn.RPID != "" && a.cache != nil
}
