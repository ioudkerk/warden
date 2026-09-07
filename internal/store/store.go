// Package store owns Warden's access to PostgreSQL.
//
// Its central concern is tenant isolation. Every tenant-scoped table carries a
// row-level security policy keyed on the `warden.tenant_id` session setting
// (migration 000005), and the only supported way to run a tenant-scoped query is
// through Store.InTenant, which sets that variable for the duration of a
// transaction. A query issued outside one sees no rows at all — unset means denied.
//
// SPEC §6.2 describes this as defence in depth behind application-level filtering.
// It is worth being precise about what it defends against: not a clever attacker, but
// the ordinary WHERE clause that someone forgets to write.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/store/db"
)

// Access describes what a connection pool is permitted to do.
type Access int

const (
	// TenantScoped is the pool that serves requests. Row-level security applies to
	// it, and Warden refuses to start if the role behind it could bypass that.
	TenantScoped Access = iota

	// SystemAccess is the pool used for migrations, bootstrap and the cross-tenant
	// background jobs. It is expected to hold BYPASSRLS, and everything it does is
	// audited precisely because the database is not constraining it (SPEC §6.2).
	SystemAccess
)

func (a Access) String() string {
	if a == SystemAccess {
		return "system"
	}
	return "tenant-scoped"
}

// Store is a pool of connections with one access level.
type Store struct {
	pool   *pgxpool.Pool
	access Access

	// role and privileges are captured at open, for diagnostics and for the startup
	// verification in VerifyIsolation.
	role       string
	canBypass  bool
	isSuper    bool
	isOwnerOfN int

	isolationWarning string

	// retry and onRetry govern what happens when PostgreSQL aborts a transaction as
	// transient. Both are set at startup and read on every transaction thereafter;
	// see SetRetryPolicy and SetRetryObserver for why they are not safe to change
	// once traffic is flowing.
	retry   RetryPolicy
	onRetry func(RetryInfo)
}

// Open connects, verifies the connection's privileges against the access level it
// claims, and returns a ready pool.
//
// The verification is not optional and not deferred. A deployment whose
// request-serving role can bypass row-level security has tenant isolation switched
// off with no outward symptom whatsoever: every query still works, every test still
// passes, and the boundary is simply not there. The only moment that can be caught
// cheaply is startup.
func Open(ctx context.Context, cfg *config.Config, access Access) (*Store, error) {
	url := cfg.Database.URL
	if access == SystemAccess {
		if cfg.Database.SystemURL.IsZero() {
			return nil, ErrNoSystemAccess
		}
		url = cfg.Database.SystemURL
	}

	poolCfg, err := pgxpool.ParseConfig(url.Expose())
	if err != nil {
		// The error can quote the connection string, which carries a password.
		return nil, fmt.Errorf("database %s url is not a valid connection string", access)
	}

	poolCfg.MaxConns = int32(cfg.Database.MaxOpenConns)
	poolCfg.MinConns = int32(cfg.Database.MaxIdleConns)
	poolCfg.MaxConnLifetime = cfg.Database.ConnMaxLifetime
	poolCfg.ConnConfig.ConnectTimeout = cfg.Database.ConnectTimeout

	// A server-side statement timeout bounds every query, including ones that reach
	// the database through a path nobody remembered to give a context deadline. The
	// PDP has a millisecond budget (SPEC §18); an unbounded query is an availability
	// incident waiting for the right row count.
	if poolCfg.ConnConfig.RuntimeParams == nil {
		poolCfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	poolCfg.ConnConfig.RuntimeParams["statement_timeout"] =
		fmt.Sprintf("%d", cfg.Database.StatementTimeout.Milliseconds())
	poolCfg.ConnConfig.RuntimeParams["application_name"] = "warden-" + access.String()

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to the database: %w", err)
	}

	s := &Store{pool: pool, access: access, retry: DefaultRetryPolicy()}
	if err := s.describeRole(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := s.VerifyIsolation(ctx, cfg.Environment); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// ErrNoSystemAccess is returned when an operation needs the system pool and
// database.system_url is not configured.
var ErrNoSystemAccess = errors.New(
	"this operation is cross-tenant and needs database.system_url, which is not configured (see deploy/roles.sql)")

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Pool exposes the underlying pool for the query layer built in M0-7. Callers that
// touch tenant-scoped tables must go through InTenant instead.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Access reports what this pool is permitted to do.
func (s *Store) Access() Access { return s.access }

// Role reports the database role the pool authenticated as.
func (s *Store) Role() string { return s.role }

// Ping checks the pool can reach the database. Used by /readyz.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// describeRole is the one query in Warden that is not generated by sqlc, and
// deliberately so: it reads the PostgreSQL catalog rather than Warden's own schema.
// sqlc's catalog is built from internal/store/migrations, which contains no pg_class,
// and teaching it otherwise means pointing code generation at a live database — which
// would make `make sqlc` require a running PostgreSQL and break the M0-1 promise that
// a clean clone needs only Go, Node and Python.
func (s *Store) describeRole(ctx context.Context) error {
	const q = `
		SELECT current_user,
		       rolbypassrls,
		       rolsuper,
		       (SELECT count(*) FROM pg_class c
		         JOIN pg_namespace n ON n.oid = c.relnamespace
		        WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relowner = r.oid)
		  FROM pg_roles r
		 WHERE r.rolname = current_user`

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := s.pool.QueryRow(ctx, q).Scan(&s.role, &s.canBypass, &s.isSuper, &s.isOwnerOfN)
	if err != nil {
		return fmt.Errorf("reading the connection's privileges: %w", err)
	}
	return nil
}

// VerifyIsolation checks that the pool's privileges match the access level it claims.
//
// For a tenant-scoped pool this is a refusal, not a warning: continuing would serve
// traffic with an isolation boundary that exists in the schema and not in fact.
// Outside production the check still runs and still explains itself, but it does not
// stop a developer whose local database has one superuser role and no ambitions.
func (s *Store) VerifyIsolation(ctx context.Context, env config.Environment) error {
	switch s.access {
	case SystemAccess:
		// A system pool that cannot bypass row-level security will fail later, in the
		// middle of a migration or a background job, with an error that looks like
		// missing data rather than missing privilege.
		if !s.canBypass && !s.isSuper {
			return fmt.Errorf(
				"database.system_url authenticates as %q, which has neither BYPASSRLS nor superuser; "+
					"cross-tenant work would silently see nothing. See deploy/roles.sql", s.role)
		}
		return nil

	case TenantScoped:
		if !s.canBypass && !s.isSuper {
			return nil // the expected, correct configuration
		}

		detail := "BYPASSRLS"
		if s.isSuper {
			detail = "superuser"
		}
		problem := fmt.Sprintf(
			"database.url authenticates as %q, which is %s: row-level security does not apply to it, "+
				"so tenant isolation is not enforced by the database at all",
			s.role, detail)

		if env.IsProduction() {
			return fmt.Errorf("%s. Configure a separate application role; see deploy/roles.sql", problem)
		}
		// Non-production: proceed, but the caller logs this loudly.
		s.isolationWarning = problem + " (permitted outside production)"
		return nil

	default:
		return fmt.Errorf("unknown access level %d", s.access)
	}
}

// IsolationWarning returns a non-empty string when the pool is running with tenant
// isolation unenforced because the environment permits it. Callers must log it.
func (s *Store) IsolationWarning() string { return s.isolationWarning }

// InTenant runs fn inside a transaction scoped to one tenant.
//
// It sets `warden.tenant_id` with SET LOCAL semantics, so the setting lives exactly
// as long as the transaction and cannot leak to the next user of a pooled connection
// — which, with a connection pool, is the failure that would matter most.
//
// Every query fn issues against a tenant-scoped table is filtered by the row-level
// security policies of migration 000005. A query that forgets its WHERE clause
// returns that tenant's rows, not everyone's.
func (s *Store) InTenant(ctx context.Context, tenantID string, fn func(context.Context, pgx.Tx) error, opts ...TxOption) error {
	if tenantID == "" {
		// An empty tenant id would set the variable to '', which matches no row, so
		// the query would return nothing rather than everything. That is safe but
		// baffling to debug; refusing outright is kinder.
		return errors.New("InTenant requires a tenant id")
	}
	if s.access == SystemAccess {
		return errors.New(
			"InTenant was called on the system pool, which bypasses row-level security; " +
				"use the tenant-scoped pool so the database enforces the boundary")
	}

	return s.inTx(ctx, opts, func(ctx context.Context, tx pgx.Tx) error {
		if err := db.New(tx).SetTenantScope(ctx, tenantID); err != nil {
			return fmt.Errorf("setting the tenant scope: %w", err)
		}
		return fn(ctx, tx)
	})
}

// InSystem runs fn inside a transaction on the system pool, which is not constrained
// by row-level security.
//
// The reason parameter is required and is not decoration: SPEC §6.2 says cross-tenant
// work "is itself audited". Once the audit log exists (M2-12) this is what it records.
func (s *Store) InSystem(ctx context.Context, reason string, fn func(context.Context, pgx.Tx) error, opts ...TxOption) error {
	if s.access != SystemAccess {
		return errors.New("InSystem was called on a tenant-scoped pool")
	}
	if reason == "" {
		return errors.New("InSystem requires a reason; cross-tenant work is audited (SPEC §6.2)")
	}
	return s.inTx(ctx, opts, fn)
}
