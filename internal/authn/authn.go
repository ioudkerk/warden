package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
	"github.com/warden-project/warden/internal/store/dbtypes"
)

// ErrInvalidCredentials is the single answer to every failed password login.
//
// One error for "no such user", "no password set", "wrong password", "account
// suspended" and "credential expired" is not laziness — it is SPEC §7.2's requirement
// that a login endpoint never reveal whether an account exists. Distinguishing them
// here would mean a caller could distinguish them, and a caller that can will
// eventually put the difference in a response body, a log line or a metric label.
//
// The distinctions still exist internally, on Result.reason, for the audit log and for
// the lockout counters M1-3 will attach. They must not reach the caller.
var ErrInvalidCredentials = errors.New("invalid credentials")

// Result is a successful authentication.
type Result struct {
	UserID string
	// MFAEnforced tells the caller a second factor is still required. The password
	// was correct; the user is not yet authenticated (M1-8).
	MFAEnforced bool
	// Rehashed reports that the stored hash was replaced with one under current
	// parameters, which happens at most once per user per parameter change.
	Rehashed bool
}

// Audit target types. The audit log is queried by these, so they are constants rather
// than literals repeated at each call site: a typo'd "users" is a row that no
// investigation will find.
const (
	targetUser    = "user"
	targetSession = "session"
)

// failureReason names why a login failed, for the audit log only.
type failureReason string

const (
	reasonNoSuchUser       failureReason = "no_such_user"
	reasonNoPassword       failureReason = "no_password_credential"
	reasonWrongPassword    failureReason = "wrong_password"
	reasonUserNotActive    failureReason = "user_not_active"
	reasonCredentialExpiry failureReason = "credential_expired"
	reasonMalformedHash    failureReason = "malformed_hash"
)

// Authenticator verifies passwords and sets them.
type Authenticator struct {
	// tenant is row-level-security scoped and serves everything reached by
	// (tenant, email). system is for setup tokens, which must be resolved before a
	// tenant scope can exist.
	tenant *store.Store
	system *store.Store

	params   Params
	breached BreachSet
	log      *slog.Logger

	audit *audit.Writer

	// policies caches per-tenant policy. A password change is rare and this is not on
	// any hot path; the cache exists so that a login attempt against a tenant with a
	// configured policy does not differ in timing from one against a tenant without,
	// by making the read a map lookup in both cases.
	policies sync.Map // tenant id -> Policy
}

// Options configure an Authenticator.
type Options struct {
	// Params defaults to DefaultParams().
	Params Params
	// Breached defaults to the built-in corpus. Pass DisabledSet{} to switch the
	// check off deliberately.
	Breached BreachSet
	Log      *slog.Logger
	// Audit records password changes and failed logins. Optional; without it those
	// events are logged but not written to the hash-chained log.
	Audit *audit.Writer
}

// New builds an Authenticator.
func New(tenant, system *store.Store, opts Options) (*Authenticator, error) {
	if tenant == nil {
		return nil, errors.New("authentication requires the tenant-scoped connection")
	}
	a := &Authenticator{
		tenant: tenant, system: system,
		params:   opts.Params,
		breached: opts.Breached,
		log:      opts.Log,
		audit:    opts.Audit,
	}
	if a.params == (Params{}) {
		a.params = DefaultParams()
	}
	if err := a.params.Validate(); err != nil {
		return nil, err
	}
	if a.breached == nil {
		a.breached = NewEmbeddedSet()
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	return a, nil
}

// Params reports the cost parameters new hashes are written with.
func (a *Authenticator) Params() Params { return a.params }

// ---------------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------------

// Authenticate verifies a password for (tenant, email).
//
// Every failure path does the same Argon2id work as the success path and returns the
// same error. That is the whole point of the function and the reason it is not three
// smaller ones: the moment "look the user up" and "verify the password" are separable,
// a caller can skip the second when the first finds nothing, and the difference — tens
// of milliseconds of 64 MiB hashing — is measurable across the network by anyone who
// wants a list of which addresses have accounts.
//
// What is deliberately NOT equalised is the database lookup, which differs slightly
// between a hit and a miss. It is microseconds against Argon2id's tens of
// milliseconds, and burying it would mean padding every login to a fixed floor, which
// leaks differently: the floor has to exceed the slowest case, so it either slows every
// login to the worst case or fails to cover it.
func (a *Authenticator) Authenticate(ctx context.Context, tenantID, email, password string) (Result, error) {
	result, reason, err := a.authenticate(ctx, tenantID, email, password)
	if err != nil {
		return Result{}, err
	}
	if reason != "" {
		a.recordFailure(ctx, tenantID, email, result.UserID, reason)
		return Result{}, ErrInvalidCredentials
	}
	return result, nil
}

func (a *Authenticator) authenticate(ctx context.Context, tenantID, email, password string) (Result, failureReason, error) {
	decoy, err := a.decoyHash()
	if err != nil {
		return Result{}, "", err
	}

	var row db.PasswordCredentialByEmailRow
	lookupErr := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var qErr error
		row, qErr = db.New(tx).PasswordCredentialByEmail(ctx, db.PasswordCredentialByEmailParams{
			TenantID: tenantID, Email: email,
		})
		return qErr
	})

	// stored is what will actually be verified against. When there is no credential to
	// verify — no such user, or a user with no password — it is the decoy, so that the
	// expensive branch is taken either way.
	stored, reason := decoy, failureReason("")
	switch {
	case errors.Is(lookupErr, pgx.ErrNoRows):
		reason = reasonNoSuchUser
	case lookupErr != nil:
		// A real database failure is an error, not a denial. Answering
		// ErrInvalidCredentials here would lock every user out of a healthy
		// deployment during a blip and look exactly like a password problem.
		return Result{}, "", fmt.Errorf("looking up the credential: %w", lookupErr)
	case row.SecretHash == nil:
		reason = reasonNoPassword
	default:
		stored = *row.SecretHash
	}

	// The verification itself. It runs before the status and expiry checks, and
	// unconditionally, because skipping it for a suspended account would make
	// suspension detectable from the outside.
	matched, verifyErr := Verify(password, stored)
	switch {
	case errors.Is(verifyErr, ErrMalformedHash):
		// A stored hash that will not parse is a storage bug. It is logged loudly and
		// still answered as an ordinary failure, so the user learns nothing and the
		// operator learns everything.
		a.log.Error("a stored password credential could not be parsed",
			"tenant_id", tenantID, "user_id", row.UserID, "error", verifyErr)
		return Result{UserID: row.UserID}, reasonMalformedHash, nil
	case verifyErr != nil:
		return Result{}, "", verifyErr
	}

	// Now fold in every other reason this login fails. Ordering matters only for which
	// reason lands in the audit log; all of them return the same error to the caller.
	switch {
	case reason != "":
		// Already failed at lookup. The decoy comparison above was the point.
	case !matched:
		reason = reasonWrongPassword
	case row.UserStatus != "active":
		// SPEC §7.6: anything but active denies. A suspended user with the right
		// password is still refused, and told exactly what a wrong password is told.
		reason = reasonUserNotActive
	case row.CredentialExpiresAt != nil && !time.Now().Before(*row.CredentialExpiresAt):
		reason = reasonCredentialExpiry
	}
	if reason != "" {
		return Result{UserID: row.UserID}, reason, nil
	}

	result := Result{UserID: row.UserID, MFAEnforced: row.MfaEnforced}

	// Rehash on a parameter change (SPEC §7.2). This is the only moment the plaintext
	// exists, so it is the only moment the upgrade can happen.
	if needs, rehashErr := NeedsRehash(stored, a.params); rehashErr == nil && needs {
		if err := a.storeHash(ctx, tenantID, row.UserID, password, "rehash on parameter change"); err != nil {
			// A failed rehash must not fail the login: the user typed the right
			// password and the old hash is still perfectly valid.
			a.log.Warn("could not rehash a password under the current parameters",
				"tenant_id", tenantID, "user_id", row.UserID, "error", err)
		} else {
			result.Rehashed = true
		}
	}

	if row.CredentialID != nil {
		a.touch(ctx, tenantID, *row.CredentialID)
	}
	return result, "", nil
}

// decoyHash returns a hash to verify against when there is no real one.
func (a *Authenticator) decoyHash() (string, error) { return DecoyHash(a.params) }

// decoys caches one decoy per parameter set. Parameters change about once a year, so
// this holds one or two entries for the life of the process.
var decoys sync.Map // Params -> *decoyCache

type decoyCache struct {
	once sync.Once
	hash string
	err  error
}

// DecoyHash returns a hash to verify a presented credential against when there is no
// real one to check — an unknown user, an account with no password, an unregistered
// client id.
//
// Verifying against it costs exactly what verifying a real credential costs, which is
// what makes the two paths indistinguishable by timing (SPEC §7.2).
//
// **It is cached, and the caching is part of the security property rather than an
// optimisation.** Generating a fresh decoy per call would mean hashing once to build it
// and once to verify against it — twice the work of the path it is imitating, making
// the miss reliably *slower* than the hit and just as good an oracle as being faster.
//
// One known imperfection, stated rather than hidden: a credential still stored under
// *older* parameters verifies faster than a decoy built from the current ones, so
// between raising the parameters and the population having logged in once, a timing
// difference exists between "unknown" and "known, on an old hash". It is bounded by the
// rehash-on-login rollout, which is what NeedsRehash exists for.
func DecoyHash(p Params) (string, error) {
	entry, _ := decoys.LoadOrStore(p, &decoyCache{})
	cached, ok := entry.(*decoyCache)
	if !ok {
		return "", errors.New("the decoy cache holds the wrong type")
	}
	cached.once.Do(func() {
		filler := make([]byte, 32)
		if _, err := rand.Read(filler); err != nil {
			cached.err = fmt.Errorf("generating the decoy credential: %w", err)
			return
		}
		cached.hash, cached.err = Hash(base64.RawStdEncoding.EncodeToString(filler), p)
	})
	return cached.hash, cached.err
}

// touch records that a credential was used, outside the authentication transaction.
func (a *Authenticator) touch(ctx context.Context, tenantID, credentialID string) {
	err := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return db.New(tx).TouchCredential(ctx, credentialID)
	})
	if err != nil {
		a.log.Warn("could not record credential use", "credential_id", credentialID, "error", err)
	}
}

// recordFailure writes a failed login to the audit log.
//
// The reason is recorded because an operator investigating an incident needs to tell
// "someone is guessing passwords for a real account" from "someone is enumerating
// addresses", and those look identical from outside by design. The email is recorded
// as given; the password never appears anywhere, including here.
func (a *Authenticator) recordFailure(ctx context.Context, tenantID, email, userID string, reason failureReason) {
	a.log.Info("password authentication failed",
		"tenant_id", tenantID, "reason", string(reason), "user_id", userID)

	if a.audit == nil || a.system == nil {
		return
	}
	err := a.system.InSystem(ctx, "recording a failed login", func(ctx context.Context, tx pgx.Tx) error {
		_, appendErr := a.audit.Append(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: "authn.password.failed",
			TargetType: targetUser, TargetID: userID,
			Reason: string(reason),
			After:  map[string]any{"email": email, "reason": string(reason)},
		})
		return appendErr
	})
	if err != nil {
		a.log.Warn("could not record a failed login in the audit log", "error", err)
	}
}

// ---------------------------------------------------------------------------------
// Setting a password
// ---------------------------------------------------------------------------------

// SetPassword stores a password for a user, after checking it against the tenant's
// policy.
//
// It does not verify the *old* password: that is a decision for the caller, because
// the three paths that reach here differ. An administrator setting a password has
// already been authorized; a reset link has already been redeemed; a self-service
// change must present the current password, and the endpoint that offers it is
// responsible for calling Authenticate first.
func (a *Authenticator) SetPassword(ctx context.Context, tenantID, userID, password string) error {
	policy, err := a.Policy(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := policy.Check(password, a.breached); err != nil {
		return err
	}
	return a.storeHash(ctx, tenantID, userID, password, "password set")
}

// storeHash writes the credential. It skips the policy check, so it is also the path a
// rehash takes: a stored password that no longer satisfies a tightened policy must
// still be re-hashable, or raising the policy would lock out everyone whose existing
// password no longer qualifies.
func (a *Authenticator) storeHash(ctx context.Context, tenantID, userID, password, label string) error {
	encoded, err := Hash(password, a.params)
	if err != nil {
		return err
	}
	id, err := newID("crd")
	if err != nil {
		return err
	}

	return a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return db.New(tx).UpsertPasswordCredential(ctx, db.UpsertPasswordCredentialParams{
			ID: id, UserID: userID, TenantID: tenantID,
			SecretHash: encoded,
			// The PHC string already carries the parameters. This records when they
			// were written, which is what makes "how much of the population is still
			// on the old cost?" answerable without parsing every hash.
			Params: dbtypes.JSONMap{"hashed_at": time.Now().UTC().Format(time.RFC3339)},
			Label:  &label,
		})
	})
}

// ---------------------------------------------------------------------------------
// Per-tenant policy
// ---------------------------------------------------------------------------------

// Policy returns the tenant's password policy, or the default if it has none.
func (a *Authenticator) Policy(ctx context.Context, tenantID string) (Policy, error) {
	if cached, ok := a.policies.Load(tenantID); ok {
		if p, isPolicy := cached.(Policy); isPolicy {
			return p, nil
		}
	}

	var raw dbtypes.JSONMap
	err := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var qErr error
		raw, qErr = db.New(tx).TenantPasswordPolicy(ctx, tenantID)
		return qErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, fmt.Errorf("no such tenant %q", tenantID)
	}
	if err != nil {
		return Policy{}, err
	}

	policy := DefaultPolicy()
	if len(raw) > 0 {
		encoded, marshalErr := json.Marshal(raw)
		if marshalErr != nil {
			return Policy{}, marshalErr
		}
		// Unmarshalling onto the default means a stored policy that sets only
		// min_length keeps the default answers for everything else, rather than
		// silently switching the breach check off by omitting it.
		if unmarshalErr := json.Unmarshal(encoded, &policy); unmarshalErr != nil {
			return Policy{}, fmt.Errorf("tenant %s has a malformed password policy: %w", tenantID, unmarshalErr)
		}
		if validateErr := policy.Validate(); validateErr != nil {
			return Policy{}, fmt.Errorf("tenant %s has an invalid password policy: %w", tenantID, validateErr)
		}
	}

	a.policies.Store(tenantID, policy)
	return policy, nil
}

// SetPolicy stores a tenant's password policy.
func (a *Authenticator) SetPolicy(ctx context.Context, tenantID string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	// Through a map rather than straight to bytes: the generated parameter is
	// dbtypes.JSONMap, because sqlc.yaml maps every jsonb column to it. The round trip
	// is one allocation on a path taken when an administrator changes a policy.
	encoded, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var asMap dbtypes.JSONMap
	if unmarshalErr := json.Unmarshal(encoded, &asMap); unmarshalErr != nil {
		return unmarshalErr
	}
	err = a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return db.New(tx).SetTenantPasswordPolicy(ctx, db.SetTenantPasswordPolicyParams{
			TenantID: tenantID, Policy: asMap,
		})
	})
	if err != nil {
		return err
	}
	a.policies.Store(tenantID, p)
	return nil
}

// ---------------------------------------------------------------------------------
// Setup tokens
// ---------------------------------------------------------------------------------

// ErrInvalidSetupToken is returned for a token that is unknown, already used, or
// expired. One error for all three, for the same reason ErrInvalidCredentials is one
// error: a setup link is a bearer credential, and telling a holder which of those
// applies tells them whether they have found a real one.
var ErrInvalidSetupToken = errors.New("this setup link is not valid, or has already been used")

// RedeemSetupToken exchanges the one-time URL from `warden init` for a password.
//
// This is what finishes the bootstrap SPEC §20.2 describes: `warden init` creates an
// owner with no credential and prints a link, and until that link is redeemed the
// account is 'invited' and can do nothing. Redemption sets the password, activates the
// user, and burns every other outstanding link for them.
func (a *Authenticator) RedeemSetupToken(ctx context.Context, token, password string) (tenantID, userID string, err error) {
	if a.system == nil {
		return "", "", errors.New(
			"redeeming a setup token needs database.system_url: the token has to be resolved " +
				"to its tenant before a tenant scope can exist")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", "", ErrInvalidSetupToken
	}
	sum := sha256.Sum256([]byte(token))

	var row db.SetupTokenByHashRow
	err = a.system.InSystem(ctx, "resolving a setup token", func(ctx context.Context, tx pgx.Tx) error {
		var qErr error
		row, qErr = db.New(tx).SetupTokenByHash(ctx, sum[:])
		return qErr
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", "", ErrInvalidSetupToken
	case err != nil:
		return "", "", err
	case row.ConsumedAt != nil:
		return "", "", ErrInvalidSetupToken
	case !time.Now().Before(row.ExpiresAt):
		return "", "", ErrInvalidSetupToken
	}

	// The policy is checked before anything is written, so a rejected password leaves
	// the link still usable. Burning a one-time setup link because the password was
	// eight characters would be an unrecoverable bootstrap.
	policy, err := a.Policy(ctx, row.TenantID)
	if err != nil {
		return "", "", err
	}
	if checkErr := policy.Check(password, a.breached); checkErr != nil {
		return "", "", checkErr
	}

	encoded, err := Hash(password, a.params)
	if err != nil {
		return "", "", err
	}
	credentialID, err := newID("crd")
	if err != nil {
		return "", "", err
	}

	// One transaction for the whole redemption. ConsumeSetupToken's row count is what
	// settles a race between two redemptions of the same link: the loser updates zero
	// rows and is refused, rather than both succeeding and the second overwriting the
	// first's password.
	label := "set from a setup link"
	err = a.system.InSystem(ctx, "redeeming a setup token", func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)

		consumed, consumeErr := q.ConsumeSetupToken(ctx, row.ID)
		if consumeErr != nil {
			return consumeErr
		}
		if consumed == 0 {
			return ErrInvalidSetupToken
		}
		if _, invalidateErr := q.InvalidateOtherSetupTokens(ctx, db.InvalidateOtherSetupTokensParams{
			UserID: row.UserID, ID: row.ID,
		}); invalidateErr != nil {
			return invalidateErr
		}

		if upsertErr := q.UpsertPasswordCredential(ctx, db.UpsertPasswordCredentialParams{
			ID: credentialID, UserID: row.UserID, TenantID: row.TenantID,
			SecretHash: encoded,
			Params:     dbtypes.JSONMap{"hashed_at": time.Now().UTC().Format(time.RFC3339)},
			Label:      &label,
		}); upsertErr != nil {
			return upsertErr
		}

		if activateErr := q.ActivateUser(ctx, db.ActivateUserParams{
			TenantID: row.TenantID, ID: row.UserID,
		}); activateErr != nil {
			return activateErr
		}

		if a.audit != nil {
			if _, appendErr := a.audit.Append(ctx, tx, audit.Entry{
				TenantID: row.TenantID, Action: "authn.setup_token.redeemed",
				TargetType: "user", TargetID: row.UserID,
				After: map[string]any{"credential_type": "password"},
			}); appendErr != nil {
				return appendErr
			}
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return row.TenantID, row.UserID, nil
}

// UserIDByEmail resolves an address within a tenant, for administrative commands.
// It is NOT part of any login path: an endpoint that used it would be an existence
// oracle by construction.
func (a *Authenticator) UserIDByEmail(ctx context.Context, tenantID, email string) (string, error) {
	var id string
	err := a.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var qErr error
		id, qErr = db.New(tx).UserIDByEmail(ctx, db.UserIDByEmailParams{TenantID: tenantID, Email: email})
		return qErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("no user with address %q in tenant %s", email, tenantID)
	}
	return id, err
}

func newID(prefix string) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b), nil
}
