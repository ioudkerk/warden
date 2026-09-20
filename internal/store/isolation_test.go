package store_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/store"
)

// tenantScopedTables asks the database which tables hold tenant-scoped data, rather
// than trusting a list in this file.
//
// This is the whole point of the exercise. A hand-maintained list is a list someone
// forgets to update, and the symptom of forgetting is a table with no isolation and
// no test — silently, because nothing references the table that ought to have been
// added. Discovering the list from the schema means a new table is covered the moment
// it exists, or the cross-check below fails.
func tenantScopedTables(t *testing.T, ctx context.Context, conn *pgx.Conn) []string {
	t.Helper()

	// A table is tenant-scoped when it carries tenant_id (or is the tenant table
	// itself, keyed on id) AND the registry says it holds tenant data.
	//
	// Both halves are needed. The column is what makes protection possible; the
	// registry is what records the intent. A table may carry tenant_id and still be
	// a deliberate exemption — service_account is, because resolving a token to its
	// tenant necessarily happens before any tenant scope exists. The registry forces
	// that exemption to be written down with a reason, and
	// TestEveryTableIsClassified fails on a table that has the column and no entry.
	// relkind 'p' is a partitioned table and 'r' an ordinary one; both can hold
	// tenant data. Partitions themselves are excluded here and covered by
	// TestEveryPartitionOfAProtectedTableIsProtected, because they are not
	// separately classified — they belong to their parent.
	const discover = `
		SELECT c.relname
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  JOIN tenant_isolation_registry r ON r.table_name = c.relname
		 WHERE n.nspname = 'public'
		   AND c.relkind IN ('r', 'p')
		   AND NOT c.relispartition
		   AND r.tenant_scoped
		   AND (c.relname = 'tenant'
		        OR EXISTS (SELECT 1 FROM pg_attribute a
		                    WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND a.attnum > 0))
		 ORDER BY c.relname`

	rows, err := conn.Query(ctx, discover)
	if err != nil {
		t.Fatalf("discovering tenant-scoped tables: %v", err)
	}
	defer rows.Close()

	var found []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		found = append(found, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("discovering tenant-scoped tables: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("no tenant-scoped tables were discovered; the query is wrong or the schema is empty")
	}
	return found
}

// The registry in migration 000005 records, per table, whether it holds tenant data.
// Comparing it against the schema catches a new table from both directions: one that
// carries tenant_id but was never classified, and one classified as global that has
// since grown a tenant_id.
func TestEveryTableIsClassified(t *testing.T) {
	ctx := context.Background()
	systemURL, _ := setupDatabase(t)

	conn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx)

	type row struct {
		name        string
		classified  bool
		scoped      *bool
		hasTenantID bool
		rationale   *string
	}

	// Read the whole result before issuing another query: a pgx connection carries
	// one cursor at a time, and holding this one open while discovering the table
	// list fails with "conn busy".
	var all []row
	rows, err := conn.Query(ctx, `
		SELECT c.relname,
		       r.tenant_scoped,
		       (r.table_name IS NOT NULL),
		       EXISTS (SELECT 1 FROM pg_attribute a
		                WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND a.attnum > 0),
		       r.rationale
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  LEFT JOIN tenant_isolation_registry r ON r.table_name = c.relname
		 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND NOT c.relispartition
		 ORDER BY c.relname`)
	if err != nil {
		t.Fatalf("querying the registry: %v", err)
	}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.name, &r.scoped, &r.classified, &r.hasTenantID, &r.rationale); err != nil {
			rows.Close()
			t.Fatalf("scanning: %v", err)
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("querying the registry: %v", err)
	}

	for _, r := range all {
		if !r.classified {
			t.Errorf("table %q is not in tenant_isolation_registry. Classify it in the migration "+
				"that creates it: either it holds tenant data and needs a policy, or it is exempt "+
				"and needs a written reason", r.name)
			continue
		}
		if r.scoped == nil {
			continue
		}
		// The case that matters: a table that carries tenant data but is marked
		// exempt. That is allowed — service_account is — but only deliberately, and
		// the reason has to be recorded rather than assumed.
		if r.hasTenantID && !*r.scoped && (r.rationale == nil || *r.rationale == "") {
			t.Errorf("table %q has a tenant_id column but is registered as not tenant-scoped, "+
				"with no rationale. An exemption from row-level security must say why", r.name)
		}
		if !r.hasTenantID && *r.scoped && r.name != "tenant" {
			t.Errorf("table %q is registered as tenant-scoped but has no tenant_id column, "+
				"so no policy can key on one", r.name)
		}
	}
}

// Every tenant-scoped table must have row-level security ENABLED, FORCED, and
// carrying a policy. All three are needed and each fails differently:
// without ENABLE there is no filtering; without FORCE the table's owner is exempt,
// which is invisible; without a policy, ENABLE alone denies everything.
func TestEveryTenantScopedTableIsProtected(t *testing.T) {
	ctx := context.Background()
	systemURL, _ := setupDatabase(t)

	conn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx)

	tables := tenantScopedTables(t, ctx, conn)
	t.Logf("checking %d tenant-scoped tables: %s", len(tables), strings.Join(tables, ", "))

	for _, table := range tables {
		t.Run(table, func(t *testing.T) {
			var enabled, forced bool
			var policies int
			err := conn.QueryRow(ctx, `
				SELECT c.relrowsecurity,
				       c.relforcerowsecurity,
				       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
				  FROM pg_class c
				  JOIN pg_namespace n ON n.oid = c.relnamespace
				 WHERE n.nspname = 'public' AND c.relname = $1`, table).Scan(&enabled, &forced, &policies)
			if err != nil {
				t.Fatalf("reading row-level security state: %v", err)
			}

			if !enabled {
				t.Errorf("row-level security is not enabled; add ENABLE ROW LEVEL SECURITY")
			}
			if !forced {
				t.Errorf("row-level security is not forced; without FORCE the table owner is exempt " +
					"and a deployment serving traffic as the owner would have no isolation at all")
			}
			if policies == 0 {
				t.Errorf("no policy is defined; with security enabled and no policy the table denies everything")
			}

			// The policy must govern writes, not only reads. A policy scoped to one
			// command — FOR SELECT, say — filters reads and leaves INSERT entirely
			// unconstrained, so a tenant could write rows it cannot read.
			//
			// Note this is not about the WITH CHECK clause: where a FOR ALL policy
			// omits it, Postgres reuses the USING expression for writes. What matters
			// is that the policy covers every command, which is what polcmd = '*'
			// means.
			var governsEveryCommand bool
			err = conn.QueryRow(ctx, `
				SELECT bool_and(p.polcmd = '*' AND p.polqual IS NOT NULL)
				  FROM pg_policy p
				  JOIN pg_class c ON c.oid = p.polrelid
				  JOIN pg_namespace n ON n.oid = c.relnamespace
				 WHERE n.nspname = 'public' AND c.relname = $1`, table).Scan(&governsEveryCommand)
			if err != nil {
				t.Fatalf("reading the policy's command scope: %v", err)
			}
			if !governsEveryCommand {
				t.Errorf("the policy does not apply to every command; a policy scoped to SELECT " +
					"would leave writes across the tenant boundary unconstrained")
			}
		})
	}
}

// --- The exit condition -----------------------------------------------------------

const (
	tenantA = "ten_aaaaaaaaaaaaaaaaaaaaaaaa"
	tenantB = "ten_bbbbbbbbbbbbbbbbbbbbbbbb"
)

// seedTwoTenants writes one row into every tenant-scoped table for each of two
// tenants, using the system connection, which bypasses row-level security.
func seedTwoTenants(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()

	for _, tn := range []string{tenantA, tenantB} {
		suffix := tn[4:8]
		stmts := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO tenant (id, slug, name) VALUES ($1, $2, $3)`,
				[]any{tn, "slug-" + suffix, "Tenant " + suffix}},
			{`INSERT INTO app_user (id, tenant_id, email, status) VALUES ($1, $2, $3, 'active')`,
				[]any{"usr_" + suffix, tn, "user@" + suffix + ".test"}},
			{`INSERT INTO credential (id, user_id, tenant_id, type, secret_hash) VALUES ($1, $2, $3, 'password', '$argon2id$fake')`,
				[]any{"crd_" + suffix, "usr_" + suffix, tn}},
			{`INSERT INTO idp_connection (id, tenant_id, kind, name, config) VALUES ($1, $2, 'oidc', $3, '{}')`,
				[]any{"idp_" + suffix, tn, "conn-" + suffix}},
			{`INSERT INTO identity (id, tenant_id, user_id, connection_id, external_subject) VALUES ($1, $2, $3, $4, $5)`,
				[]any{"idn_" + suffix, tn, "usr_" + suffix, "idp_" + suffix, "ext-" + suffix}},
			{`INSERT INTO session (id, tenant_id, user_id, auth_time, expires_at) VALUES ($1, $2, $3, now(), now() + interval '1 hour')`,
				[]any{"ses_" + suffix, tn, "usr_" + suffix}},
			{`INSERT INTO refresh_token (id, session_id, tenant_id, family_id, token_hash, client_id, expires_at)
			  VALUES ($1, $2, $3, $4, sha256($5::bytea), 'client', now() + interval '30 days')`,
				[]any{"rft_" + suffix, "ses_" + suffix, tn, "fam_" + suffix, []byte(suffix)}},
			{`INSERT INTO group_ (id, tenant_id, key, name) VALUES ($1, $2, $3, $4)`,
				[]any{"grp_" + suffix, tn, "group-" + suffix, "Group " + suffix}},
			{`INSERT INTO group_member (group_id, member_user_id, tenant_id) VALUES ($1, $2, $3)`,
				[]any{"grp_" + suffix, "usr_" + suffix, tn}},
			{`INSERT INTO app_enrollment (tenant_id, application_id) VALUES ($1, 'app_shared')`,
				[]any{tn}},
			{`INSERT INTO role (id, tenant_id, application_id, key, name, type)
			  VALUES ($1, $2, 'app_shared', $3, 'Viewer', 'tenant_custom')`,
				[]any{"rol_v_" + suffix, tn, "viewer-" + suffix}},
			{`INSERT INTO role (id, tenant_id, application_id, key, name, type)
			  VALUES ($1, $2, 'app_shared', $3, 'Approver', 'tenant_custom')`,
				[]any{"rol_a_" + suffix, tn, "approver-" + suffix}},
			{`INSERT INTO role_inheritance (role_id, parent_role_id, tenant_id) VALUES ($1, $2, $3)`,
				[]any{"rol_a_" + suffix, "rol_v_" + suffix, tn}},
			{`INSERT INTO role_permission (role_id, tenant_id, permission_key) VALUES ($1, $2, 'billing.invoice:read')`,
				[]any{"rol_v_" + suffix, tn}},
			{`INSERT INTO resource_node (tenant_id, ref) VALUES ($1, $2)`,
				[]any{tn, "billing.invoice:" + suffix}},
			{`INSERT INTO grant_ (id, tenant_id, subject_user_id, role_id, scope_kind, scope_ref)
			  VALUES ($1, $2, $3, $4, 'tenant', $2)`,
				[]any{"grn_" + suffix, tn, "usr_" + suffix, "rol_v_" + suffix}},
			{`INSERT INTO denial (id, tenant_id, subject_user_id, permission_key, scope_kind, scope_ref, reason)
			  VALUES ($1, $2, $3, 'billing.invoice:void', 'tenant', $2, 'seeded for the isolation test')`,
				[]any{"den_" + suffix, tn, "usr_" + suffix}},
			{`INSERT INTO decision_event (id, tenant_id, subject_id, permission_key, allowed, reason)
			  VALUES ($1, $2, $3, 'billing.invoice:read', true, 'grant_matched')`,
				[]any{"dec_" + suffix, tn, "usr_" + suffix}},
			{`INSERT INTO ui_binding (id, tenant_id, ui_element_id, requires, mode)
			  VALUES ($1, $2, 'uie_shared', '{"any_of":[{"permission":"billing.invoice:read"}]}', 'hidden')`,
				[]any{"uib_" + suffix, tn}},
			{`INSERT INTO oauth_client (id, tenant_id, key, name, redirect_uris)
			  VALUES ($1, $2, $3, $4, '{https://app.example.test/callback}')`,
				[]any{"oac_" + suffix, tn, "client-" + suffix, "Client " + suffix}},
			{`INSERT INTO oauth_session (signature_hash, kind, tenant_id, request_id,
			                             client_id, subject, expires_at)
			  VALUES (sha256($1::bytea), 'access_token', $2, $3, $4, $5, now() + interval '1 hour')`,
				[]any{[]byte("sig-" + suffix), tn, "req_" + suffix, "oac_" + suffix, "usr_" + suffix}},
			{`INSERT INTO device_authorization (id, tenant_id, client_id, device_code_hash,
			                                    user_code_hash, expires_at)
			  VALUES ($1, $2, $3, sha256($4::bytea), sha256($5::bytea), now() + interval '10 minutes')`,
				[]any{"dev_" + suffix, tn, "oac_" + suffix,
					[]byte("device-" + suffix), []byte("user-" + suffix)}},
			{`INSERT INTO outbound_email (id, tenant_id, to_address, template)
			  VALUES ($1, $2, $3, 'magic_link')`,
				[]any{"eml_" + suffix, tn, "person@" + suffix + ".test"}},
		}

		// One shared, global application, so app_enrollment has something to point
		// at, plus a global role template — the row with a NULL tenant_id that both
		// tenants must be able to read and neither may create.
		if tn == tenantA {
			for _, stmt := range []string{
				`INSERT INTO application (id, key, name) VALUES ('app_shared', 'billing', 'Billing')`,
				`INSERT INTO role (id, tenant_id, application_id, key, name, type)
				 VALUES ('rol_global', NULL, 'app_shared', 'billing.viewer', 'Billing Viewer', 'application_template')`,
				`INSERT INTO role_permission (role_id, tenant_id, permission_key)
				 VALUES ('rol_global', NULL, 'billing.invoice:read')`,
				`INSERT INTO ui_element (id, application_id, key, label, default_mode)
				 VALUES ('uie_shared', 'app_shared', 'nav.reports', 'Reports', 'hidden')`,
			} {
				if _, err := conn.Exec(ctx, stmt); err != nil {
					t.Fatalf("seeding the shared application: %v", err)
				}
			}
		}

		for _, s := range stmts {
			if _, err := conn.Exec(ctx, s.sql, s.args...); err != nil {
				t.Fatalf("seeding %s: %v", tn, err)
			}
		}
	}
}

// tenantColumn is the column that carries the tenant on each table. The tenant table
// itself is keyed on id.
func tenantColumn(table string) string {
	if table == "tenant" {
		return "id"
	}
	return "tenant_id"
}

// The exit condition for M0-6: a connection scoped to tenant A must see none of
// tenant B's rows, on every tenant-scoped table, with the table list generated from
// the schema so a new table cannot be forgotten.
//
// The test asserts both halves. Seeing zero of B's rows is only half the claim: a
// broken policy that returns nothing at all would satisfy it while making the
// database useless. So each table must also return exactly A's own row.
func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	sysConn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting as the system role: %v", err)
	}
	defer sysConn.Close(ctx)

	seedTwoTenants(t, ctx, sysConn)
	tables := tenantScopedTables(t, ctx, sysConn)

	cfg := testConfig(t, systemURL, applicationURL, config.EnvProduction)
	app := openStore(t, cfg, store.TenantScoped)

	for _, table := range tables {
		t.Run(table, func(t *testing.T) {
			col := tenantColumn(table)

			err := app.InTenant(ctx, tenantA, func(ctx context.Context, tx pgx.Tx) error {
				var mine, theirs, global, total int
				// Some tables permit a NULL tenant — a global role template, which
				// every tenant may read and none may write. Those rows are counted
				// separately so they cannot mask a leak.
				q := fmt.Sprintf(`
					SELECT count(*) FILTER (WHERE %[1]s = $1),
					       count(*) FILTER (WHERE %[1]s = $2),
					       count(*) FILTER (WHERE %[1]s IS NULL),
					       count(*)
					  FROM %[2]s`, col, pgx.Identifier{table}.Sanitize())
				if err := tx.QueryRow(ctx, q, tenantA, tenantB).Scan(&mine, &theirs, &global, &total); err != nil {
					return err
				}

				if theirs != 0 {
					t.Errorf("a connection scoped to tenant A can see %d of tenant B's rows", theirs)
				}
				if total != mine+global {
					t.Errorf("saw %d rows in total but only %d of tenant A's and %d global", total, mine, global)
				}
				// Without this, a policy denying everything would pass the test above.
				if mine == 0 {
					t.Errorf("a connection scoped to tenant A sees none of its own rows either; " +
						"the policy is denying everything rather than isolating")
				}
				return nil
			})
			if err != nil {
				t.Fatalf("querying %s: %v", table, err)
			}
		})
	}
}

// A connection that has not declared a tenant must see no tenant-owned row. Unset
// means denied: the alternative reading — an absent setting meaning "unrestricted" —
// is how a forgotten scope becomes a cross-tenant read.
//
// Rows with a NULL tenant are exempt, and deliberately so. They are application role
// templates: part of the declared surface an application publishes once and every
// tenant adopts (SPEC §6.1), in the same category as the application, resource_type
// and permission tables, which carry no policy at all. Holding them to a stricter
// standard than the rest of that surface would be inconsistent, not safer.
func TestQueryWithoutATenantSeesNothing(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	sysConn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer sysConn.Close(ctx)
	seedTwoTenants(t, ctx, sysConn)
	tables := tenantScopedTables(t, ctx, sysConn)

	cfg := testConfig(t, systemURL, applicationURL, config.EnvProduction)
	app := openStore(t, cfg, store.TenantScoped)

	// Straight to the pool, deliberately bypassing InTenant — this is the mistake
	// being guarded against.
	for _, table := range tables {
		var n int
		q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s IS NOT NULL`,
			pgx.Identifier{table}.Sanitize(), tenantColumn(table))
		if err := app.Pool().QueryRow(ctx, q).Scan(&n); err != nil {
			t.Fatalf("querying %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s: a query with no tenant scope returned %d tenant-owned rows; it must return none",
				table, n)
		}
	}
}

// role, role_inheritance and role_permission are the only tables where a policy's
// USING and WITH CHECK differ: a tenant may read a global template and must not be
// able to create one. Reusing USING for writes — which is what Postgres does when
// WITH CHECK is omitted — would let any tenant publish a role to every other tenant.
func TestATenantCanReadGlobalTemplatesButNotCreateThem(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	sysConn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer sysConn.Close(ctx)
	seedTwoTenants(t, ctx, sysConn)

	cfg := testConfig(t, systemURL, applicationURL, config.EnvProduction)
	app := openStore(t, cfg, store.TenantScoped)

	if err := app.InTenant(ctx, tenantA, func(ctx context.Context, tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM role WHERE tenant_id IS NULL`).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			t.Error("a tenant cannot see the global role templates it is meant to adopt")
		}
		return nil
	}); err != nil {
		t.Fatalf("reading templates: %v", err)
	}

	writeErr := app.InTenant(ctx, tenantA, func(ctx context.Context, tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx,
			`INSERT INTO role (id, tenant_id, application_id, key, name, type)
			 VALUES ('rol_planted', NULL, 'app_shared', 'planted', 'Planted', 'application_template')`)
		return execErr
	})
	if writeErr == nil {
		t.Fatal("a tenant created a global role template, which every other tenant would then see")
	}
	if !strings.Contains(writeErr.Error(), "row-level security") {
		t.Fatalf("the write failed, but not because of the policy: %v", writeErr)
	}
}

// The tenant setting must not survive its transaction. With a connection pool the
// next user of a connection is a different request, quite possibly a different
// tenant, and a leaked setting there would be the worst kind of cross-tenant read:
// intermittent, and dependent on pool scheduling.
func TestTenantScopeDoesNotLeakBetweenTransactions(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	sysConn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer sysConn.Close(ctx)
	seedTwoTenants(t, ctx, sysConn)

	cfg := testConfig(t, systemURL, applicationURL, config.EnvProduction)
	cfg.Database.MaxOpenConns = 1 // force the same connection to be reused
	app := openStore(t, cfg, store.TenantScoped)

	if err := app.InTenant(ctx, tenantA, func(ctx context.Context, tx pgx.Tx) error {
		var n int
		return tx.QueryRow(ctx, `SELECT count(*) FROM app_user`).Scan(&n)
	}); err != nil {
		t.Fatalf("first transaction: %v", err)
	}

	// Same pooled connection, no scope declared.
	var setting *string
	if err := app.Pool().QueryRow(ctx, `SELECT current_setting('warden.tenant_id', true)`).Scan(&setting); err != nil {
		t.Fatalf("reading the setting: %v", err)
	}
	if setting != nil && *setting != "" {
		t.Fatalf("warden.tenant_id survived its transaction as %q; SET LOCAL semantics are not in effect", *setting)
	}

	var n int
	if err := app.Pool().QueryRow(ctx, `SELECT count(*) FROM app_user`).Scan(&n); err != nil {
		t.Fatalf("querying: %v", err)
	}
	if n != 0 {
		t.Fatalf("a later query on the same connection saw %d rows", n)
	}
}

// A policy's USING clause governs reads. Without WITH CHECK, a tenant could write
// rows it cannot read — planting data in another tenant's space.
func TestWritingAcrossTheTenantBoundaryIsRefused(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	sysConn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer sysConn.Close(ctx)
	seedTwoTenants(t, ctx, sysConn)

	cfg := testConfig(t, systemURL, applicationURL, config.EnvProduction)
	app := openStore(t, cfg, store.TenantScoped)

	// Insert into another tenant.
	insertErr := app.InTenant(ctx, tenantA, func(ctx context.Context, tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx,
			`INSERT INTO app_user (id, tenant_id, email) VALUES ('usr_planted', $1, 'planted@evil.test')`, tenantB)
		return execErr
	})
	if insertErr == nil {
		t.Fatal("tenant A inserted a row belonging to tenant B; writes are not constrained by the policy")
	}
	if !strings.Contains(insertErr.Error(), "row-level security") && !strings.Contains(insertErr.Error(), "policy") {
		t.Fatalf("the insert failed, but not because of row-level security: %v", insertErr)
	}

	// Move one of A's own rows into B.
	updateErr := app.InTenant(ctx, tenantA, func(ctx context.Context, tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `UPDATE app_user SET tenant_id = $1`, tenantB)
		return execErr
	})
	if updateErr == nil {
		t.Fatal("tenant A moved one of its own rows into tenant B")
	}

	// And confirm nothing landed.
	var n int
	if countErr := sysConn.QueryRow(ctx,
		`SELECT count(*) FROM app_user WHERE tenant_id = $1`, tenantB).Scan(&n); countErr != nil {
		t.Fatalf("counting: %v", countErr)
	}
	if n != 1 {
		t.Fatalf("tenant B has %d users; the seed created exactly 1", n)
	}
}

// Deleting across the boundary is governed by USING, which the read tests already
// exercise — but a row invisible to a DELETE is silently skipped rather than
// rejected, so the outcome deserves its own assertion.
func TestDeletingAcrossTheTenantBoundaryAffectsNothing(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	sysConn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer sysConn.Close(ctx)
	seedTwoTenants(t, ctx, sysConn)

	cfg := testConfig(t, systemURL, applicationURL, config.EnvProduction)
	app := openStore(t, cfg, store.TenantScoped)

	if err := app.InTenant(ctx, tenantA, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM app_user WHERE tenant_id = $1`, tenantB)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 0 {
			t.Errorf("tenant A deleted %d of tenant B's rows", tag.RowsAffected())
		}
		return nil
	}); err != nil {
		t.Fatalf("deleting: %v", err)
	}

	var n int
	if err := sysConn.QueryRow(ctx, `SELECT count(*) FROM app_user WHERE tenant_id = $1`, tenantB).Scan(&n); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if n != 1 {
		t.Fatalf("tenant B has %d users after A's delete; expected 1", n)
	}
}

// The composite foreign keys exist so that a child row cannot claim a different
// tenant from its parent. Without them the denormalized tenant_id would be a comment
// rather than a constraint, and a bug in application code could put a credential in
// one tenant and its user in another.
func TestChildRowsCannotSpanTenants(t *testing.T) {
	ctx := context.Background()
	systemURL, _ := setupDatabase(t)

	conn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx)
	seedTwoTenants(t, ctx, conn)

	// Even as the system role, which bypasses row-level security entirely, the
	// referential constraint holds.
	cases := []struct {
		name, sql string
		args      []any
	}{
		{
			"a credential in a different tenant from its user",
			`INSERT INTO credential (id, user_id, tenant_id, type, secret_hash) VALUES ('crd_bad', $1, $2, 'password', 'x')`,
			[]any{"usr_aaaa", tenantB},
		},
		{
			"a refresh token in a different tenant from its session",
			`INSERT INTO refresh_token (id, session_id, tenant_id, family_id, token_hash, client_id, expires_at)
			 VALUES ('rft_bad', $1, $2, 'fam', sha256('x'::bytea), 'c', now() + interval '1 day')`,
			[]any{"ses_aaaa", tenantB},
		},
		{
			"a membership whose group is in another tenant",
			`INSERT INTO group_member (group_id, member_user_id, tenant_id) VALUES ($1, $2, $3)`,
			[]any{"grp_aaaa", "usr_bbbb", tenantB},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := conn.Exec(ctx, tc.sql, tc.args...); err == nil {
				t.Fatal("the cross-tenant row was accepted; the composite foreign key is missing")
			}
		})
	}
}

// A partitioned table's policies apply when a query names the parent, and NOT when it
// names a partition directly. With the parent protected and its partitions bare,
// `SELECT * FROM decision_event` correctly returns one tenant's rows while
// `SELECT * FROM decision_event_2026_09` returns everyone's — and the partition is an
// ordinary table with an ordinary grant, so any role that can read the parent can name
// it.
//
// This was a real hole when the decision log was first written. It is the kind that
// reopens by itself: a partition created next month by a maintenance job would arrive
// unprotected, months after anyone last looked.
func TestEveryPartitionOfAProtectedTableIsProtected(t *testing.T) {
	ctx := context.Background()
	systemURL, _ := setupDatabase(t)

	conn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx, `
		SELECT child.relname, parent.relname,
		       child.relrowsecurity, child.relforcerowsecurity,
		       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = child.oid)
		  FROM pg_inherits i
		  JOIN pg_class child  ON child.oid  = i.inhrelid
		  JOIN pg_class parent ON parent.oid = i.inhparent
		 WHERE parent.relrowsecurity
		 ORDER BY parent.relname, child.relname`)
	if err != nil {
		t.Fatalf("listing partitions: %v", err)
	}
	defer rows.Close()

	found := 0
	for rows.Next() {
		var child, parent string
		var enabled, forced bool
		var policies int
		if err := rows.Scan(&child, &parent, &enabled, &forced, &policies); err != nil {
			t.Fatalf("scanning: %v", err)
		}
		found++
		if !enabled || !forced || policies == 0 {
			t.Errorf("partition %q of protected table %q is not protected "+
				"(enabled=%v forced=%v policies=%d); reading it directly bypasses the parent's policy",
				child, parent, enabled, forced, policies)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("listing partitions: %v", err)
	}
	if found == 0 {
		t.Fatal("no partitions of a protected table were found; the query is wrong, " +
			"or decision_event lost its partitions")
	}
	t.Logf("checked %d partitions", found)
}

// The behavioural half: a partition read directly must obey the tenant scope.
func TestReadingAPartitionDirectlyRespectsTheTenantScope(t *testing.T) {
	ctx := context.Background()
	systemURL, applicationURL := setupDatabase(t)

	sysConn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer sysConn.Close(ctx)
	seedTwoTenants(t, ctx, sysConn)

	// One decision for each tenant, both landing in the current month's partition.
	for _, tn := range []string{tenantA, tenantB} {
		if _, err := sysConn.Exec(ctx, `
			INSERT INTO decision_event (id, tenant_id, subject_id, permission_key, allowed, reason)
			VALUES ($1, $2, 'usr_x', 'billing.invoice:read', true, 'grant_matched')`,
			"dec_"+tn[4:8], tn); err != nil {
			t.Fatalf("seeding a decision for %s: %v", tn, err)
		}
	}

	var partition string
	if err := sysConn.QueryRow(ctx, `
		SELECT c.relname FROM pg_inherits i
		  JOIN pg_class c ON c.oid = i.inhrelid
		 WHERE i.inhparent = 'decision_event'::regclass
		   AND EXISTS (SELECT 1 FROM decision_event_default) IS NOT NULL
		 ORDER BY c.relname DESC LIMIT 1`).Scan(&partition); err != nil {
		t.Fatalf("finding a partition: %v", err)
	}

	cfg := testConfig(t, systemURL, applicationURL, config.EnvProduction)
	app := openStore(t, cfg, store.TenantScoped)

	if err := app.InTenant(ctx, tenantA, func(ctx context.Context, tx pgx.Tx) error {
		var theirs int
		q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE tenant_id = $1`,
			pgx.Identifier{partition}.Sanitize())
		if err := tx.QueryRow(ctx, q, tenantB).Scan(&theirs); err != nil {
			return err
		}
		if theirs != 0 {
			t.Errorf("reading partition %s directly, tenant A saw %d of tenant B's decisions",
				partition, theirs)
		}
		return nil
	}); err != nil {
		t.Fatalf("querying the partition: %v", err)
	}
}

func TestTenantListIsStable(t *testing.T) {
	ctx := context.Background()
	systemURL, _ := setupDatabase(t)
	conn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx)

	got := tenantScopedTables(t, ctx, conn)
	want := []string{
		"app_enrollment", "app_user", "credential", "decision_event", "denial",
		"device_authorization", "grant_", "group_", "group_member", "identity",
		"idp_connection", "oauth_client", "oauth_session", "outbound_email",
		"refresh_token", "resource_node", "role", "role_inheritance", "role_permission",
		"session", "tenant", "ui_binding",
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the set of tenant-scoped tables changed.\n  got:  %v\n  want: %v\n"+
			"If this is intentional, update this list and confirm the new table has a policy.",
			got, want)
	}
}
