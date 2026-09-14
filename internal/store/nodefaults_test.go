package store_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// SPEC §20.2: no default credentials, ever.
//
// The strong form of that claim is behavioural rather than textual: a database that
// has been migrated but not initialised must contain nothing anybody can log in or
// authenticate with. A grep can be fooled by a credential assembled at runtime; this
// cannot.
//
// It matters because a default credential is the most reliably exploited thing in
// self-hosted software — the deployment that forgot to change it is indistinguishable
// from the one that did.
func TestAMigratedDatabaseContainsNoUsableCredential(t *testing.T) {
	ctx := context.Background()
	systemURL, _ := setupDatabase(t)

	conn, err := pgx.Connect(ctx, systemURL)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx)

	// Every table that could hold something an attacker could authenticate with.
	credentialTables := map[string]string{
		"credential":      "a password, TOTP seed or passkey",
		"service_account": "an API token",
		"setup_token":     "a one-time setup link",
		"refresh_token":   "a refresh token",
		"session":         "an active session",
		"signing_key":     "a key that could mint tokens",
		"identity":        "a federated identity to log in through",
	}
	for table, what := range credentialTables {
		var count int
		q := fmt.Sprintf(`SELECT count(*) FROM %s`, pgx.Identifier{table}.Sanitize())
		if err := conn.QueryRow(ctx, q).Scan(&count); err != nil {
			t.Fatalf("counting %s: %v", table, err)
		}
		if count != 0 {
			t.Errorf("a migrated database ships %d rows in %s — %s", count, table, what)
		}
	}

	// And no account that could be active without one.
	var users int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM app_user`).Scan(&users); err != nil {
		t.Fatalf("counting users: %v", err)
	}
	if users != 0 {
		t.Errorf("a migrated database ships %d user accounts", users)
	}

	// Migrations do seed roles, applications and permissions. Those are a permission
	// vocabulary, not authority: a role nobody is granted confers nothing.
	var grants int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM grant_`).Scan(&grants); err != nil {
		t.Fatalf("counting grants: %v", err)
	}
	if grants != 0 {
		t.Errorf("a migrated database ships %d role assignments; a role nobody holds is harmless, "+
			"but an assignment is authority", grants)
	}
}

// The textual half, scoped to where a shipped credential would actually live. Test
// files legitimately contain throwaway passwords, and deploy/dev-roles.sql is
// documented as local-only, so both are out of scope — the risk is a credential in
// something an operator runs in production.
func TestNoCredentialLiteralsInMigrationsOrServerCode(t *testing.T) {
	// Patterns that would indicate a shipped credential rather than a reference to
	// one. Deliberately narrow: a broad scan produces noise nobody reads.
	// The assigned value is captured, because it is what decides whether a match is a
	// finding. Narrowing the *name* side instead — demanding a word boundary before
	// "password" — would stop this firing on GrantRefreshToken at the cost of no longer
	// seeing clientSecret or apiToken, which is the wrong trade on a tripwire.
	assignment := regexp.MustCompile(
		`(?i)(password|passwd|secret|token)\s*(:?=|:)\s*["']([^"'\n]{6,})["']`)
	createRole := regexp.MustCompile(`(?i)CREATE\s+ROLE\s+\w+.*PASSWORD\s+'[^']+'`)

	// Protocol vocabulary that matches the shape of a credential assignment and is not
	// one. Every entry is a name defined by an RFC, so the list grows only when a
	// standard does — which is the property that keeps it from becoming a place to hide
	// an inconvenient finding.
	notSecrets := map[string]bool{
		"refresh_token":       true, // RFC 6749 grant type and token type
		"authorization_code":  true, // RFC 6749 grant type
		"client_credentials":  true, // RFC 6749 grant type
		"client_secret_basic": true, // RFC 8414 auth method
		"client_secret_post":  true, // RFC 8414 auth method
		"private_key_jwt":     true, // RFC 8414 auth method
		"access_token":        true, // RFC 6749 token type
		"id_token":            true, // OIDC Core response and token type
		"urn:ietf:params:oauth:grant-type:device_code": true, // RFC 8628
	}
	// A migration that seeds a credential table is the specific thing SPEC §20.2
	// forbids: it would ship in every deployment. The same statement in Go is how
	// `warden token` and `warden init` legitimately create one at an operator's
	// request, so this applies to migrations alone.
	migrationOnly := regexp.MustCompile(
		`(?i)INSERT\s+INTO\s+(credential|service_account|setup_token|signing_key|app_user|grant_)\b`)
	// Documented exceptions, each of which must stay justified.
	allowed := map[string]string{
		"deploy/dev-roles.sql": "local development only; creates throwaway roles for `make dev-up`",
		"deploy/roles.sql":     "a template an operator edits; the passwords read 'change-me'",
	}

	roots := []string{"internal", "cmd", filepath.Join("internal", "store", "migrations"), "deploy"}
	seen := map[string]bool{}

	for _, root := range roots {
		walkErr := filepath.Walk(filepath.Join("..", "..", root), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil //nolint:nilerr // an unreadable path is not this test's business
			}
			rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
			if seen[rel] {
				return nil
			}
			seen[rel] = true

			ext := filepath.Ext(path)
			if ext != ".go" && ext != ".sql" && ext != ".yaml" && ext != ".yml" {
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil // throwaway credentials in tests are fine and necessary
			}
			if reason, ok := allowed[rel]; ok {
				t.Logf("skipping %s: %s", rel, reason)
				return nil
			}

			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil //nolint:nilerr // unreadable files are not findings
			}
			for _, match := range assignment.FindAllSubmatch(content, -1) {
				if notSecrets[string(match[3])] {
					continue
				}
				t.Errorf("%s appears to contain a shipped credential: %q", rel, string(match[0]))
			}
			if match := createRole.Find(content); match != nil {
				t.Errorf("%s appears to contain a shipped credential: %q", rel, string(match))
			}
			if strings.Contains(rel, "store/migrations") {
				if match := migrationOnly.Find(content); match != nil {
					t.Errorf("migration %s seeds a credential or an account: %q — "+
						"that would ship in every deployment (SPEC §20.2)", rel, string(match))
				}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walking %s: %v", root, walkErr)
		}
	}
}
