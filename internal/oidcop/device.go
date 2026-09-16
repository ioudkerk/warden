package oidcop

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
)

// The device authorization grant's state (RFC 8628, SPEC §7.7).
//
// Two codes for one authorization, because they are handed to two different parties for
// two different purposes. The device code is a machine credential — full entropy, sent
// back and forth over TLS, never read aloud. The user code is typed by a person off a
// television screen, so it is short, and the shortness is the reason §5.1 requires the
// verification endpoint to rate-limit guesses rather than trusting the code alone.

const (
	// deviceCodeBytes is the entropy in a device code. The same figure as a refresh
	// token, and for the same reason: it is a bearer credential that exchanges for one.
	deviceCodeBytes = 32

	// userCodeAlphabet is RFC 8628 §6.1's suggestion, and every character in it is one
	// a person can read off a screen and type without ambiguity. No vowels, so the
	// generator cannot produce a word; no 0/O, 1/I/L, 5/S, 8/B, which are the pairs
	// people mistype.
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

	// userCodeLength is eight characters: 20^8, a little over 34 bits. Not enough on its
	// own — nothing a person types is — which is why the verification endpoint limits
	// attempts. Grouped as XXXX-XXXX when shown, and the separator is ignored on input.
	userCodeLength = 8

	// deviceCodeLifetime is how long the device has. Long enough to walk to a laptop,
	// short enough that a code left on a screen in a lobby expires before the meeting
	// after next.
	deviceCodeLifetime = 10 * time.Minute

	// devicePollInterval is the minimum gap between polls the device is told to keep.
	devicePollInterval = 5 * time.Second
)

// Device statuses, matching device_authorization_status_valid.
const (
	DeviceStatusPending  = "pending"
	DeviceStatusApproved = "approved"
	DeviceStatusDenied   = "denied"
	DeviceStatusRedeemed = "redeemed"
)

// ErrNoSuchDeviceCode is returned when neither code matches anything.
//
// One error for an unknown code and for one belonging to another tenant: a caller able
// to tell them apart could map which codes exist.
var ErrNoSuchDeviceCode = errors.New("no such device authorization")

// DeviceAuthorization is one device's request, from its creation to its redemption.
type DeviceAuthorization struct {
	ID       string
	TenantID string
	ClientID string

	RequestedScope    []string
	GrantedScope      []string
	RequestedAudience []string
	GrantedAudience   []string

	Status    string
	Subject   string
	SessionID string

	Interval     time.Duration
	LastPolledAt *time.Time
	ExpiresAt    time.Time
}

// Expired reports whether the device has run out of time.
func (d *DeviceAuthorization) Expired(now time.Time) bool { return !now.Before(d.ExpiresAt) }

// NewDeviceCodes is what the device is handed. The plaintext exists here and nowhere
// else: only the hashes are stored.
type NewDeviceCodes struct {
	DeviceCode string
	UserCode   string
	Interval   time.Duration
	ExpiresAt  time.Time
	Record     *DeviceAuthorization
}

// CreateDeviceAuthorization starts a device flow.
func (s *Storage) CreateDeviceAuthorization(
	ctx context.Context, tenantID, clientID string, scopes, audiences []string,
) (*NewDeviceCodes, error) {
	// Generated before the transaction opens, per M0-7: the store's retry loop re-runs
	// the callback from the top, and a code minted inside it would be a different code
	// on the second attempt — the device would be handed one value and the database
	// would hold another.
	deviceCode, err := newDeviceCode()
	if err != nil {
		return nil, err
	}
	userCode, err := newUserCode()
	if err != nil {
		return nil, err
	}
	id, err := randomID("dev")
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expires := now.Add(deviceCodeLifetime)

	if err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return db.New(tx).InsertDeviceAuthorization(ctx, db.InsertDeviceAuthorizationParams{
			ID: id, TenantID: tenantID, ClientID: clientID,
			DeviceCodeHash: hashCode(deviceCode), UserCodeHash: hashCode(userCode),
			RequestedScope: orEmptyStrings(scopes), RequestedAudience: orEmptyStrings(audiences),
			IntervalSeconds: int32(devicePollInterval / time.Second), //nolint:gosec // a constant of five
			ExpiresAt:       expires,
		})
	}); err != nil {
		return nil, fmt.Errorf("storing the device authorization: %w", err)
	}

	return &NewDeviceCodes{
		DeviceCode: deviceCode, UserCode: userCode,
		Interval: devicePollInterval, ExpiresAt: expires,
		Record: &DeviceAuthorization{
			ID: id, TenantID: tenantID, ClientID: clientID,
			RequestedScope: scopes, RequestedAudience: audiences,
			Status: DeviceStatusPending, Interval: devicePollInterval, ExpiresAt: expires,
		},
	}, nil
}

// DeviceByUserCode finds the authorization a person is about to approve.
//
// The code is normalised first, because it is typed: the XXXX-XXXX grouping is a display
// convention and a person who types the dash, or lower case, or a space, has typed the
// right code.
func (s *Storage) DeviceByUserCode(ctx context.Context, tenantID, userCode string) (*DeviceAuthorization, error) {
	normalised := NormaliseUserCode(userCode)
	if normalised == "" {
		return nil, ErrNoSuchDeviceCode
	}

	var row db.DeviceAuthorizationByUserCodeRow
	err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var queryErr error
		row, queryErr = db.New(tx).DeviceAuthorizationByUserCode(ctx,
			db.DeviceAuthorizationByUserCodeParams{
				TenantID: tenantID, UserCodeHash: hashCode(normalised),
			})
		return queryErr
	}, store.ReadOnly())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoSuchDeviceCode
	}
	if err != nil {
		return nil, err
	}
	return deviceFromUserCodeRow(row), nil
}

// TenantOfUserCode resolves a typed code to the tenant it belongs to.
//
// On the system pool, because this is asked *before* the person has signed in: they have
// typed a code and nothing else, and which tenant to authenticate them against is exactly
// what the code has to answer. The same shape as resolving a client id or a refresh token
// to its tenant, and the one column it reads opens the scope for everything after.
//
// The caller must not let the difference between "resolved" and "did not" reach the
// response. A login page that renders only for a real code would be an oracle for which
// codes exist, and a user code is short enough for that to matter — so an unresolvable
// code authenticates against a tenant that does not exist, and fails the way a wrong
// password does.
func (s *Storage) TenantOfUserCode(ctx context.Context, userCode string) (string, error) {
	normalised := NormaliseUserCode(userCode)
	if normalised == "" {
		return "", ErrNoSuchDeviceCode
	}
	if s.system == nil {
		return "", errors.New("resolving a user code needs database.system_url")
	}

	var tenantID string
	err := s.system.InSystem(ctx, "resolving a device user code to its tenant",
		func(ctx context.Context, tx pgx.Tx) error {
			var queryErr error
			tenantID, queryErr = db.New(tx).DeviceAuthorizationTenant(ctx, hashCode(normalised))
			return queryErr
		}, store.ReadOnly())
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoSuchDeviceCode
	}
	return tenantID, err
}

// ApproveDevice records that a person said yes.
//
// The scopes are passed in rather than copied from the request inside the query: what is
// granted is a decision, and the caller is where that decision is made.
func (s *Storage) ApproveDevice(
	ctx context.Context, tenantID, id, subject, sessionID string, scopes, audiences []string,
) error {
	var affected int64
	err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var updateErr error
		affected, updateErr = db.New(tx).ApproveDeviceAuthorization(ctx,
			db.ApproveDeviceAuthorizationParams{
				TenantID: tenantID, ID: id, Subject: subject, SessionID: &sessionID,
				GrantedScope: orEmptyStrings(scopes), GrantedAudience: orEmptyStrings(audiences),
				At: ptr(time.Now().UTC()),
			})
		return updateErr
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		// Somebody else answered first, or it expired and was swept. Either way this
		// approval is not the one that counts, and saying so is better than reporting a
		// success the device will never see.
		return ErrNoSuchDeviceCode
	}
	return nil
}

// DenyDevice records that a person said no.
//
// Kept as a state rather than deleted, because "denied" and "nobody has answered yet"
// are different answers to the device's next poll: the first ends the flow and the
// second asks it to keep waiting.
func (s *Storage) DenyDevice(ctx context.Context, tenantID, id string) error {
	var affected int64
	err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var updateErr error
		affected, updateErr = db.New(tx).DenyDeviceAuthorization(ctx,
			db.DenyDeviceAuthorizationParams{TenantID: tenantID, ID: id})
		return updateErr
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNoSuchDeviceCode
	}
	return nil
}

// pollDevice reads the row a device's poll is about and records the poll.
//
// Read and write in one transaction: the answer to "is this device polling too fast?" is
// the gap between this poll and the previous one, so a read that could be overtaken by
// another poll's write would compare against the wrong instant.
func (s *Storage) pollDevice(ctx context.Context, tenantID, deviceCode string) (*DeviceAuthorization, error) {
	var record *DeviceAuthorization
	err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		row, queryErr := q.DeviceAuthorizationByDeviceCode(ctx,
			db.DeviceAuthorizationByDeviceCodeParams{
				TenantID: tenantID, DeviceCodeHash: hashCode(deviceCode),
			})
		if queryErr != nil {
			return queryErr
		}
		record = deviceFromDeviceCodeRow(row)
		return q.TouchDeviceAuthorizationPoll(ctx, db.TouchDeviceAuthorizationPollParams{
			TenantID: tenantID, ID: row.ID, At: ptr(time.Now().UTC()),
		})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoSuchDeviceCode
	}
	if err != nil {
		return nil, err
	}
	return record, nil
}

// redeemDevice marks an approved authorization as spent.
//
// Keyed by the code rather than by the row id, and the single-use rule lives in the
// WHERE clause rather than in the caller: two polls arriving together must not both issue
// tokens, and the one that updates no rows is the one that loses.
func (s *Storage) redeemDevice(ctx context.Context, tenantID, deviceCode string) error {
	var affected int64
	err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var updateErr error
		affected, updateErr = db.New(tx).RedeemDeviceAuthorization(ctx,
			db.RedeemDeviceAuthorizationParams{
				TenantID: tenantID, DeviceCodeHash: hashCode(deviceCode),
			})
		return updateErr
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNoSuchDeviceCode
	}
	return nil
}

// PurgeExpiredDeviceAuthorizations removes rows nobody will ever poll again.
func (s *Storage) PurgeExpiredDeviceAuthorizations(ctx context.Context, before time.Time) (int64, error) {
	if s.system == nil {
		return 0, errors.New("sweeping device authorizations needs database.system_url")
	}
	var removed int64
	err := s.system.InSystem(ctx, "sweeping expired device authorizations",
		func(ctx context.Context, tx pgx.Tx) error {
			var deleteErr error
			removed, deleteErr = db.New(tx).DeleteExpiredDeviceAuthorizations(ctx, before)
			return deleteErr
		})
	return removed, err
}

// --- codes ---------------------------------------------------------------------------

func hashCode(code string) []byte {
	sum := sha256.Sum256([]byte(code))
	return sum[:]
}

func newDeviceCode() (string, error) {
	raw := make([]byte, deviceCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating a device code: %w", err)
	}
	return "wdc_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

// newUserCode draws from the reduced alphabet, uniformly.
//
// crypto/rand and rand.Int rather than a modulo of a random byte: a modulo over a
// 256-value range and a 20-character alphabet is biased towards the first sixteen
// letters, which would cost about a bit of the little entropy this code has.
func newUserCode() (string, error) {
	out := make([]byte, userCodeLength)
	size := big.NewInt(int64(len(userCodeAlphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, size)
		if err != nil {
			return "", fmt.Errorf("generating a user code: %w", err)
		}
		out[i] = userCodeAlphabet[n.Int64()]
	}
	return string(out), nil
}

// FormatUserCode groups a code for display: XXXX-XXXX.
func FormatUserCode(code string) string {
	if len(code) != userCodeLength {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// NormaliseUserCode turns what a person typed into what was stored.
//
// Upper-cased, with everything outside the alphabet dropped — which covers the grouping
// dash, spaces pasted from a screen, and the lower case a keyboard produces by default.
// Being strict here would mean rejecting people who typed the right code.
func NormaliseUserCode(typed string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(typed)) {
		if strings.ContainsRune(userCodeAlphabet, r) {
			b.WriteRune(r)
		}
	}
	normalised := b.String()
	if len(normalised) != userCodeLength {
		return ""
	}
	return normalised
}

// --- row mapping ---------------------------------------------------------------------

func deviceFromDeviceCodeRow(row db.DeviceAuthorizationByDeviceCodeRow) *DeviceAuthorization {
	return &DeviceAuthorization{
		ID: row.ID, TenantID: row.TenantID, ClientID: row.ClientID,
		RequestedScope: row.RequestedScope, GrantedScope: row.GrantedScope,
		RequestedAudience: row.RequestedAudience, GrantedAudience: row.GrantedAudience,
		Status: row.Status, Subject: row.Subject, SessionID: derefOr(row.SessionID, ""),
		Interval:     time.Duration(row.IntervalSeconds) * time.Second,
		LastPolledAt: row.LastPolledAt, ExpiresAt: row.ExpiresAt,
	}
}

func deviceFromUserCodeRow(row db.DeviceAuthorizationByUserCodeRow) *DeviceAuthorization {
	return &DeviceAuthorization{
		ID: row.ID, TenantID: row.TenantID, ClientID: row.ClientID,
		RequestedScope: row.RequestedScope, GrantedScope: row.GrantedScope,
		RequestedAudience: row.RequestedAudience, GrantedAudience: row.GrantedAudience,
		Status: row.Status, Subject: row.Subject, SessionID: derefOr(row.SessionID, ""),
		Interval:     time.Duration(row.IntervalSeconds) * time.Second,
		LastPolledAt: row.LastPolledAt, ExpiresAt: row.ExpiresAt,
	}
}

// orEmptyStrings is orEmpty for a plain slice: a nil one reaches Postgres as NULL rather
// than as the column's empty-array default.
func orEmptyStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
