package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/cache"
	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
)

// Session is the browser-level SSO artifact of SPEC §8.3: the thing a `sid` names, the
// thing that survives token refresh, and the thing "log out everywhere" targets.
type Session struct {
	ID        string    `json:"sid"`
	TenantID  string    `json:"tid"`
	UserID    string    `json:"sub"`
	AMR       []string  `json:"amr"`
	AuthTime  time.Time `json:"auth_time"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"ua,omitempty"`
	CreatedAt time.Time `json:"iat"`
	// ExpiresAt is the absolute ceiling. The idle timeout lives in the cache key's
	// time to live and is not stored here, because a sliding value written into the
	// record would have to be rewritten on every validation.
	ExpiresAt time.Time `json:"exp"`
}

// ErrNoSession is returned for a session that does not exist, has expired, has gone
// idle, or has been revoked.
//
// One error for all four, as with ErrInvalidCredentials: a caller that could
// distinguish "revoked" from "never existed" would eventually put the difference in a
// response, and "this session was revoked" tells whoever stole the cookie that they
// had the right value.
var ErrNoSession = errors.New("no valid session")

// Sessions creates, validates and revokes sessions.
//
// Redis is authoritative for validity and Postgres is the mirror, which is the split
// SPEC §8.3 asks for. The consequence worth stating plainly: **nothing caches a
// session in process**. Every validation reads the cache tier. That is what makes
// revocation take effect within milliseconds on every replica rather than within
// whatever a local time-to-live happened to be, and it is why the exit condition for
// this task is measured in seconds while the implementation answers in single-digit
// milliseconds. A local cache added later for throughput would silently convert that
// guarantee into a promise about a TTL.
type Sessions struct {
	tenant *store.Store
	system *store.Store
	cache  cache.Cache
	log    *slog.Logger
	audit  *audit.Writer

	absoluteLifetime time.Duration
	idleTimeout      time.Duration

	now func() time.Time
}

// SessionOptions configure a Sessions.
type SessionOptions struct {
	AbsoluteLifetime time.Duration
	IdleTimeout      time.Duration
	Log              *slog.Logger
	Audit            *audit.Writer
}

// NewSessions builds the session store.
func NewSessions(tenant, system *store.Store, c cache.Cache, opts SessionOptions) (*Sessions, error) {
	switch {
	case tenant == nil:
		return nil, errors.New("sessions require the tenant-scoped connection")
	case c == nil:
		return nil, errors.New("sessions require the cache tier (SPEC §8.3)")
	case opts.AbsoluteLifetime <= 0:
		return nil, errors.New("sessions require a positive absolute lifetime")
	case opts.IdleTimeout <= 0:
		return nil, errors.New("sessions require a positive idle timeout")
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	return &Sessions{
		tenant: tenant, system: system, cache: c, log: log, audit: opts.Audit,
		absoluteLifetime: opts.AbsoluteLifetime,
		idleTimeout:      opts.IdleTimeout,
		now:              time.Now,
	}, nil
}

// SetClock replaces the store's notion of the current time. For tests.
func (s *Sessions) SetClock(now func() time.Time) { s.now = now }

// sessionKey is where a session record lives in the cache tier.
func sessionKey(sid string) string { return "warden:session:" + sid }

// revocationKey holds the instant everything issued to a user before it became
// invalid.
//
// This is what makes "log out everywhere" airtight rather than merely thorough.
// Deleting the sessions a query found leaves a race: a login that commits between the
// enumeration and the delete produces a session the revocation never saw. A marker
// that says "nothing authenticated before time T is valid" has no such gap, because a
// session created after T has an auth_time after T and survives correctly, while one
// created before it is dead however the enumeration went.
func revocationKey(tenantID, userID string) string {
	return "warden:revoked-before:" + tenantID + ":" + userID
}

// Create starts a session for a user who has just authenticated.
//
// amr is the list of methods used, in OIDC's vocabulary — "pwd", "otp", "webauthn" —
// and it lands in the access token unchanged (SPEC §8.2), so a relying party can tell
// a password login from one that presented a second factor.
func (s *Sessions) Create(ctx context.Context, tenantID, userID string, amr []string, ip, userAgent string) (*Session, error) {
	sid, err := newID("ses")
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	session := &Session{
		ID: sid, TenantID: tenantID, UserID: userID,
		AMR: amr, AuthTime: now, IP: ip, UserAgent: userAgent,
		CreatedAt: now, ExpiresAt: now.Add(s.absoluteLifetime),
	}

	// The mirror is written first. If the cache write then fails the session simply
	// does not work — the user logs in again — whereas the other order can leave a
	// live session in Redis that the active-sessions UI cannot show and revoke-all
	// cannot find, which is a session nobody can end.
	if err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var ipValue *string
		if ip != "" {
			ipValue = &ip
		}
		var agentValue *string
		if userAgent != "" {
			agentValue = &userAgent
		}
		return db.New(tx).InsertSession(ctx, db.InsertSessionParams{
			ID: sid, TenantID: tenantID, UserID: userID,
			Amr: amr, AuthTime: now, Ip: ipValue, UserAgent: agentValue,
			ExpiresAt: session.ExpiresAt,
		})
	}); err != nil {
		return nil, fmt.Errorf("recording the session: %w", err)
	}

	if err := s.writeToCache(ctx, session); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *Sessions) writeToCache(ctx context.Context, session *Session) error {
	encoded, err := json.Marshal(session)
	if err != nil {
		return err
	}
	// The time to live is the shorter of the idle timeout and whatever remains of the
	// absolute lifetime, so the cache never holds a session past its ceiling even if
	// nothing ever validates it again.
	ttl := s.idleTimeout
	if remaining := session.ExpiresAt.Sub(s.now()); remaining < ttl {
		ttl = remaining
	}
	if ttl <= 0 {
		return ErrNoSession
	}
	if err := s.cache.Set(ctx, sessionKey(session.ID), encoded, ttl); err != nil {
		return fmt.Errorf("storing the session: %w", err)
	}
	return nil
}

// Validate resolves a sid to its session, or reports that there is none.
//
// Two reads of the cache tier, not one: the revocation marker is keyed by tenant and
// user, and those are only known once the session record has been read. Pipelining
// them would mean keying the marker by sid, which would put it back to one marker per
// session and lose the property that makes revoke-all raceless.
func (s *Sessions) Validate(ctx context.Context, sid string) (*Session, error) {
	if sid == "" {
		return nil, ErrNoSession
	}

	raw, err := s.cache.Get(ctx, sessionKey(sid))
	if errors.Is(err, cache.ErrMiss) {
		return nil, ErrNoSession
	}
	if err != nil {
		// A cache that is down is an error, not a denial. Answering ErrNoSession would
		// log out every user of a healthy deployment during a blip, and it would look
		// exactly like mass session expiry.
		return nil, fmt.Errorf("reading the session: %w", err)
	}

	var session Session
	if unmarshalErr := json.Unmarshal(raw, &session); unmarshalErr != nil {
		// A record that will not parse is a storage bug. The session is refused, and
		// the key is removed so the user can log in again rather than being wedged.
		s.log.Error("a stored session could not be parsed", "sid", sid, "error", unmarshalErr)
		_ = s.cache.Delete(ctx, sessionKey(sid)) //nolint:errcheck // best effort
		return nil, ErrNoSession
	}

	now := s.now()
	if !now.Before(session.ExpiresAt) {
		return nil, ErrNoSession
	}

	// The revocation marker is read second rather than in the same pipeline because it
	// needs the tenant and user from the record. It is one extra round trip on a path
	// that is already doing one, and it is what closes the revoke-all race.
	revoked, err := s.revokedBefore(ctx, session.TenantID, session.UserID)
	if err != nil {
		return nil, err
	}
	if !revoked.IsZero() && !session.AuthTime.After(revoked) {
		// Tidy the key away so the next validation is a single miss.
		_ = s.cache.Delete(ctx, sessionKey(sid)) //nolint:errcheck // best effort
		return nil, ErrNoSession
	}

	// Slide the idle timeout. A failure here is not fatal: the session stays valid
	// until its current time to live runs out, which is a shorter session rather than
	// a broken one.
	ttl := s.idleTimeout
	if remaining := session.ExpiresAt.Sub(now); remaining < ttl {
		ttl = remaining
	}
	if ttl > 0 {
		if _, err := s.cache.Expire(ctx, sessionKey(sid), ttl); err != nil {
			s.log.Warn("could not extend a session's idle timeout", "sid", sid, "error", err)
		}
	}
	return &session, nil
}

// revokedBefore reads the user's revocation marker.
func (s *Sessions) revokedBefore(ctx context.Context, tenantID, userID string) (time.Time, error) {
	raw, err := s.cache.Get(ctx, revocationKey(tenantID, userID))
	if errors.Is(err, cache.ErrMiss) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("reading the revocation marker: %w", err)
	}
	nanos, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		s.log.Error("a revocation marker could not be parsed",
			"tenant_id", tenantID, "user_id", userID, "value", string(raw))
		// Unparseable means unknown, and unknown must not mean "nothing was revoked".
		// Treating it as "everything up to now" fails closed: the user logs in again.
		// The error is deliberately swallowed — it has been logged, and propagating it
		// would turn a corrupt marker into a hard failure on every validation for this
		// user rather than a forced re-login.
		return s.now(), nil //nolint:nilerr // fail closed, see above
	}
	return time.Unix(0, nanos).UTC(), nil
}

// Revoke ends one session.
//
// tenantID is the caller's tenant and it is enforced, not decoration. A session key is
// named by its sid alone — sids are unique across the deployment, so scoping the key
// would buy nothing — which means deleting one without checking who it belongs to lets
// any tenant end any other tenant's session by id. That is threat 5 of SPEC §17.1, and
// it is not hypothetical: this function had exactly that hole, because the Postgres
// update is tenant-scoped and the cache delete that preceded it was not.
func (s *Sessions) Revoke(ctx context.Context, tenantID, sid, reason string) error {
	// Read before delete, so the ownership check happens against the record rather
	// than against a row that the delete has already made unreachable.
	owned, err := s.belongsToTenant(ctx, sid, tenantID)
	if err != nil {
		return err
	}
	if !owned {
		// Answered as a success. A caller that could tell "not yours" from "already
		// gone" could enumerate which sids exist in other tenants.
		return nil
	}

	// The cache first from here, and deliberately the opposite order from Create.
	// Revocation must take effect even if the mirror update fails; a row that still
	// says "active" is a stale UI, while a live cache entry is a session that should
	// have ended.
	if err := s.cache.Delete(ctx, sessionKey(sid)); err != nil {
		return fmt.Errorf("removing the session: %w", err)
	}

	var affected int64
	if err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var revokeErr error
		// Tenant-scoped too, so the mirror is defended even if the check above ever
		// stops being: two independent guards on the same boundary is the right number
		// for the one SPEC §17.1 names.
		affected, revokeErr = db.New(tx).RevokeSession(ctx, db.RevokeSessionParams{
			TenantID: tenantID, ID: sid,
		})
		return revokeErr
	}); err != nil {
		return fmt.Errorf("recording the revocation: %w", err)
	}
	if affected == 0 {
		// Already revoked, or never existed. Not an error: revocation is idempotent,
		// and a caller retrying after a timeout must not get a failure for succeeding.
		return nil
	}

	s.recordRevocation(ctx, tenantID, "", sid, 1, reason)
	return nil
}

// belongsToTenant reports whether a session is the given tenant's to act on.
//
// The cache is consulted first because it is authoritative for validity and is where
// the record lives; the mirror answers for a session whose cache entry has already
// gone, so that revoking an idle-but-not-expired session still updates the row.
func (s *Sessions) belongsToTenant(ctx context.Context, sid, tenantID string) (bool, error) {
	raw, err := s.cache.Get(ctx, sessionKey(sid))
	switch {
	case err == nil:
		var session Session
		if unmarshalErr := json.Unmarshal(raw, &session); unmarshalErr != nil {
			// Unparseable: fall through to the mirror rather than trusting it.
			break
		}
		return session.TenantID == tenantID, nil
	case errors.Is(err, cache.ErrMiss):
		// Not in the cache. The mirror decides.
	default:
		return false, fmt.Errorf("reading the session: %w", err)
	}

	var found bool
	if err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, queryErr := db.New(tx).SessionByID(ctx, db.SessionByIDParams{TenantID: tenantID, ID: sid})
		if errors.Is(queryErr, pgx.ErrNoRows) {
			return nil
		}
		if queryErr != nil {
			return queryErr
		}
		found = true
		return nil
	}); err != nil {
		return false, err
	}
	return found, nil
}

// RevokeAllForUser is SPEC §8.3's "log out everywhere".
//
// The revocation marker is written first and it is the part that matters: from that
// moment every replica refuses every session the user had, including any this function
// never enumerated. Deleting the individual keys afterwards is housekeeping — it keeps
// the cache from holding records nothing will ever accept again.
func (s *Sessions) RevokeAllForUser(ctx context.Context, tenantID, userID, reason string) (int, error) {
	marker := strconv.FormatInt(s.now().UTC().UnixNano(), 10)
	// The marker outlives the longest possible session, or a session created just
	// before the revocation could outlive the marker that invalidates it.
	if err := s.cache.Set(ctx, revocationKey(tenantID, userID),
		[]byte(marker), s.absoluteLifetime+time.Hour); err != nil {
		return 0, fmt.Errorf("writing the revocation marker: %w", err)
	}

	var revoked []string
	if err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var revokeErr error
		revoked, revokeErr = db.New(tx).RevokeAllSessionsForUser(ctx, db.RevokeAllSessionsForUserParams{
			TenantID: tenantID, UserID: userID,
		})
		return revokeErr
	}); err != nil {
		return 0, fmt.Errorf("recording the revocations: %w", err)
	}

	if len(revoked) > 0 {
		keys := make([]string, 0, len(revoked))
		for _, sid := range revoked {
			keys = append(keys, sessionKey(sid))
		}
		if err := s.cache.Delete(ctx, keys...); err != nil {
			// Not fatal, because the marker already did the work.
			s.log.Warn("could not remove revoked sessions from the cache",
				"tenant_id", tenantID, "user_id", userID, "count", len(keys), "error", err)
		}
	}

	s.recordRevocation(ctx, tenantID, userID, "", len(revoked), reason)
	return len(revoked), nil
}

// ActiveForUser lists a user's live sessions, for the active-sessions UI.
//
// It reads the mirror rather than the cache, which is what the mirror is for: Redis
// answers "is this session valid?" in one lookup and cannot enumerate without a scan.
// A row here may in principle have been revoked on another replica moments ago; the
// list is a view, not an authorization decision, and Validate is the authority.
func (s *Sessions) ActiveForUser(ctx context.Context, tenantID, userID string) ([]Session, error) {
	var rows []db.ActiveSessionsForUserRow
	if err := s.tenant.InTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var queryErr error
		rows, queryErr = db.New(tx).ActiveSessionsForUser(ctx, db.ActiveSessionsForUserParams{
			TenantID: tenantID, UserID: userID,
		})
		return queryErr
	}); err != nil {
		return nil, err
	}

	// Sessions invalidated by a revocation marker are still rows until the mirror
	// catches up, so they are filtered here too. Otherwise "log out everywhere"
	// followed by a refresh of the devices list shows the devices still signed in.
	revoked, err := s.revokedBefore(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	out := make([]Session, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		if !revoked.IsZero() && !r.AuthTime.After(revoked) {
			continue
		}
		session := Session{
			ID: r.ID, TenantID: r.TenantID, UserID: r.UserID, AMR: r.Amr,
			AuthTime: r.AuthTime, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
			IP: r.Ip,
		}
		if r.UserAgent != nil {
			session.UserAgent = *r.UserAgent
		}
		out = append(out, session)
	}
	return out, nil
}

// PurgeExpired removes mirror rows for sessions that ended. The cache expires its own
// records; this is the mirror's equivalent, and it is a worker-role job.
func (s *Sessions) PurgeExpired(ctx context.Context, olderThan time.Duration) (int64, error) {
	if s.system == nil {
		return 0, errors.New("purging sessions needs database.system_url: it is cross-tenant by nature")
	}
	var deleted int64
	err := s.system.InSystem(ctx, "purging expired sessions", func(ctx context.Context, tx pgx.Tx) error {
		var purgeErr error
		deleted, purgeErr = db.New(tx).DeleteExpiredSessions(ctx, s.now().Add(-olderThan))
		return purgeErr
	})
	return deleted, err
}

// recordRevocation writes a revocation to the audit log. SPEC §16 wants every
// administrative action recorded, and "somebody was signed out of everything" is one
// of the first things asked about after an incident.
func (s *Sessions) recordRevocation(ctx context.Context, tenantID, userID, sid string, count int, reason string) {
	if s.audit == nil || s.system == nil {
		return
	}
	action, targetType, targetID := "session.revoked", "session", sid
	if sid == "" {
		action, targetType, targetID = "session.revoked_all", "user", userID
	}
	err := s.system.InSystem(ctx, "recording a session revocation", func(ctx context.Context, tx pgx.Tx) error {
		_, appendErr := s.audit.Append(ctx, tx, audit.Entry{
			TenantID: tenantID, Action: action,
			TargetType: targetType, TargetID: targetID,
			Reason: reason,
			After:  map[string]any{"sessions_revoked": count},
		})
		return appendErr
	})
	if err != nil {
		s.log.Warn("could not record a session revocation in the audit log", "error", err)
	}
}
