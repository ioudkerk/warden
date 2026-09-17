package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/jackc/pgx/v5"
)

// The access token (SPEC §8.2).
//
// It is a JWT now, which changes who has to trust whom: a resource server verifies a
// signature rather than asking Warden. That is the point and it is also the risk, so these
// tests are about what the token says, what it refuses to say, and what happens when it
// says too much to fit.

// TestTheAccessTokenCarriesWhatTheSpecificationSays walks the claim list in §8.2.
func TestTheAccessTokenCarriesWhatTheSpecificationSays(t *testing.T) {
	f := newOIDCFixture(t)
	f.grantRole(t, "finance.viewer")

	token := f.accessToken(t, "openid profile email", f.audience, "state-for-the-claims-case")
	claims := f.verifyAgainstJWKS(t, token)

	for _, claim := range []string{"iss", "sub", "aud", "exp", "iat", "jti", "tid", "sid",
		"scope", "azp", "amr", "auth_time", "wd"} {
		if claims[claim] == nil {
			t.Errorf("the access token has no %q (SPEC §8.2)", claim)
		}
	}

	if claims["sub"] != f.userID {
		t.Errorf("sub = %v; want %s", claims["sub"], f.userID)
	}
	if claims["iss"] != f.issuer {
		t.Errorf("iss = %v; want %s", claims["iss"], f.issuer)
	}
	if claims["azp"] != f.client.ID {
		t.Errorf("azp = %v; want the client the token was issued to", claims["azp"])
	}
	if jti, _ := claims["jti"].(string); !strings.HasPrefix(jti, "tok_") { //nolint:errcheck // checked
		t.Errorf("jti = %v; Warden's identifiers are prefixed", claims["jti"])
	}

	// scope is a space-delimited string, not a list. fosite's default is the other one,
	// under a different name, and a resource server reading §8.2 would find neither.
	scope, isString := claims["scope"].(string)
	if !isString {
		t.Fatalf("scope = %T %v; §8.2 and RFC 9068 §2.2.3 both say a space-delimited string",
			claims["scope"], claims["scope"])
	}
	if !strings.Contains(scope, "openid") {
		t.Errorf("scope = %q", scope)
	}

	wd, isMap := claims["wd"].(map[string]any)
	if !isMap {
		t.Fatalf("wd = %T; want an object", claims["wd"])
	}
	roles := stringsOf(wd["roles"])
	if len(roles) != 1 || roles[0] != "finance.viewer" {
		t.Errorf("wd.roles = %v; want the tenant-wide role the user was granted", wd["roles"])
	}
	if wd["perm_rev"] == nil {
		t.Error("wd.perm_rev is absent; without it an SDK cannot tell whether its cached " +
			"model predates the token, which is what makes local evaluation safe")
	}
	if wd["truncated"] != nil {
		t.Errorf("wd.truncated is set on a token that fits: %v", wd["truncated"])
	}
}

// TestAUserWithFiveThousandGroupsGetsAUsableToken is M1-7's exit condition.
//
// The interesting part is not that the token is small. It is that it is still a *valid*
// token: signed by the published key, carrying the claims a resource server authorizes on,
// and honest about what it gave up.
func TestAUserWithFiveThousandGroupsGetsAUsableToken(t *testing.T) {
	f := newOIDCFixture(t)
	f.grantRole(t, "finance.viewer")
	f.joinGroups(t, 5000)

	token := f.accessToken(t, "openid profile email", f.audience, "state-for-the-big-case")

	if len(token) > 4096 {
		t.Fatalf("the access token is %d bytes; SPEC §8.2 caps it at 4096", len(token))
	}

	// Verified the way a relying party does: fetch JWKS, select by kid, check the
	// signature. A small token that does not verify is worse than a large one.
	claims := f.verifyAgainstJWKS(t, token)
	if claims["sub"] != f.userID {
		t.Fatalf("sub = %v", claims["sub"])
	}

	wd, isMap := claims["wd"].(map[string]any)
	if !isMap {
		t.Fatalf("wd = %T", claims["wd"])
	}
	if wd["truncated"] != true {
		t.Fatalf("wd.truncated = %v; a reader must be able to tell an absent claim from an "+
			"empty one", wd["truncated"])
	}
	if wd["groups"] != nil {
		t.Fatalf("wd.groups survived truncation: %d entries", len(stringsOf(wd["groups"])))
	}
	if roles := stringsOf(wd["roles"]); len(roles) != 1 {
		t.Fatalf("wd.roles = %v; roles are never dropped — they are what is left when "+
			"everything else goes", wd["roles"])
	}
	if wd["perm_rev"] == nil {
		t.Fatal("wd.perm_rev was dropped; it is what an SDK checks its cache against")
	}
	t.Logf("5000 groups → %d-byte token, groups dropped, roles and perm_rev kept", len(token))
}

// TestTheAttributeAllowlistDecidesWhatIsDisclosed. Attributes are tenant-defined data:
// a department, a cost centre, sometimes something a good deal more personal. A client
// sees what it was registered to see and nothing else.
func TestTheAttributeAllowlistDecidesWhatIsDisclosed(t *testing.T) {
	f := newOIDCFixture(t)
	f.setAttributes(t, map[string]any{"department": "finance", "home_address": "12 Rose Street"})

	t.Run("a client with no allowlist", func(t *testing.T) {
		claims := f.verifyAgainstJWKS(t,
			f.accessToken(t, "openid profile", "", "state-for-the-attrs-none"))
		wd, _ := claims["wd"].(map[string]any) //nolint:errcheck // asserted below
		if wd == nil {
			t.Fatal("no wd claim")
		}
		if wd["attrs"] != nil {
			t.Fatalf("attributes were disclosed to a client that was granted none: %v", wd["attrs"])
		}
	})

	t.Run("a client allowlisted for one", func(t *testing.T) {
		f.allowAttributes(t, f.client.ID, "department")
		claims := f.verifyAgainstJWKS(t,
			f.accessToken(t, "openid profile", "", "state-for-the-attrs-one"))
		wd, _ := claims["wd"].(map[string]any) //nolint:errcheck // asserted below
		attrs, isMap := wd["attrs"].(map[string]any)
		if !isMap {
			t.Fatalf("wd.attrs = %T %v; want the allowlisted attribute", wd["attrs"], wd["attrs"])
		}
		if attrs["department"] != "finance" {
			t.Errorf("wd.attrs.department = %v", attrs["department"])
		}
		if _, leaked := attrs["home_address"]; leaked {
			t.Fatal("an attribute outside the allowlist was disclosed; the list is an " +
				"allowlist precisely so that the next attribute somebody adds is not")
		}
	})
}

// TestARefreshedTokenDescribesTheUserNow is why claims are assembled at issuance rather
// than when the session was created.
//
// A session lasts thirty days and a token ten minutes. If the claims were frozen with the
// session, a refresh a week later would describe the roles the user had when they signed
// in — and `perm_rev` would say the token was current, which is worse than saying nothing.
func TestARefreshedTokenDescribesTheUserNow(t *testing.T) {
	f := newOIDCFixture(t)

	tokens := f.tokensFor(t, "openid offline_access", "", "state-for-the-freshness-case")
	first, _ := tokens["access_token"].(string)         //nolint:errcheck // checked below
	refreshToken, _ := tokens["refresh_token"].(string) //nolint:errcheck // checked below
	if first == "" || refreshToken == "" {
		t.Fatalf("no tokens: %v", tokens)
	}
	if roles := f.rolesIn(t, first); len(roles) != 0 {
		t.Fatalf("wd.roles = %v before any grant", roles)
	}

	// The role is granted after the session began and after the first token was issued.
	f.grantRole(t, "billing.approver")

	refreshed := f.exchange(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
		"client_id": {f.client.ID},
	})
	second, _ := refreshed["access_token"].(string) //nolint:errcheck // checked below
	if second == "" {
		t.Fatalf("the refresh produced no access token: %v", refreshed)
	}

	roles := f.rolesIn(t, second)
	if len(roles) != 1 || roles[0] != "billing.approver" {
		t.Fatalf("wd.roles = %v after the refresh; a refreshed token must describe the user "+
			"as they are now, not as they were when the session began", roles)
	}
}

// TestASuspendedUserGetsNoFurtherTokens closes a gap the security review recorded.
//
// Nothing consulted the subject's status at issuance: the session was valid, so a refresh
// minted a new token. Suspension was to be enforced by revoking sessions when the status
// changes (M1-10) — which is right, and is not enough on its own, because a revocation
// that fails leaves a suspended user with a live session and no second check. A JWT access
// token cannot be recalled once issued, so the check belongs at the moment of issuing.
func TestASuspendedUserGetsNoFurtherTokens(t *testing.T) {
	f := newOIDCFixture(t)

	tokens := f.tokensFor(t, "openid offline_access", "", "state-for-the-suspension-case")
	refreshToken, _ := tokens["refresh_token"].(string) //nolint:errcheck // checked below
	if refreshToken == "" {
		t.Fatalf("no refresh token: %v", tokens)
	}

	f.exec(t, `UPDATE app_user SET status = 'suspended' WHERE id = $1`, f.userID)

	rec := f.postForm(t, "/oauth2/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
		"client_id": {f.client.ID},
	}, nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("a suspended user was issued a fresh access token, which no revocation "+
			"can reach for its whole lifetime: %s", rec.Body.String())
	}
}

// TestAnAccessTokenIsSignedByThePublishedKeyAndNotByNone. An access token is now a
// bearer credential that resource servers verify themselves, so the header matters as much
// as the payload.
func TestAnAccessTokenIsSignedByThePublishedKeyAndNotByNone(t *testing.T) {
	f := newOIDCFixture(t)
	token := f.accessToken(t, "openid", "", "state-for-the-signing-case")

	header := decodeJWTSegment(t, token, 0)
	if alg, _ := header["alg"].(string); alg == "" || strings.EqualFold(alg, "none") { //nolint:errcheck // checked
		t.Fatalf("alg = %v", header["alg"])
	}
	if header["kid"] == nil {
		t.Fatal("no kid: a resource server would have to guess which key signed it")
	}

	// The same key set the id token is verified against, so a resource server needs one
	// document and one rule.
	parsed, err := jose.ParseSigned(token)
	if err != nil {
		t.Fatalf("the access token is not a JWS: %v", err)
	}
	_ = parsed
	f.verifyAgainstJWKS(t, token)
}

// --- helpers -------------------------------------------------------------------------

// rolesIn returns wd.roles from an access token.
func (f *oidcFixture) rolesIn(t *testing.T, token string) []string {
	t.Helper()
	claims := f.verifyAgainstJWKS(t, token)
	wd, isMap := claims["wd"].(map[string]any)
	if !isMap {
		t.Fatalf("wd = %T", claims["wd"])
	}
	return stringsOf(wd["roles"])
}

// exec runs a statement against the test database as the owning role.
//
// Direct SQL, because these tests need states the API cannot yet produce: five thousand
// group memberships, a suspended user, a granted role. The alternative is to wait for the
// milestones that add those endpoints, and to leave the token untested until then.
func (f *oidcFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv(dsnEnv))
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck // teardown

	if _, execErr := conn.Exec(ctx, sql, args...); execErr != nil {
		t.Fatalf("%s: %v", sql, execErr)
	}
}

// grantRole gives the fixture's user a tenant-wide role.
func (f *oidcFixture) grantRole(t *testing.T, key string) {
	t.Helper()
	f.exec(t, `INSERT INTO application (id, key, name) VALUES ('app_claims', 'claims', 'Claims')
	           ON CONFLICT (id) DO NOTHING`)
	roleID := "rol_" + strings.ReplaceAll(key, ".", "_")
	f.exec(t, `INSERT INTO role (id, tenant_id, application_id, key, name, type)
	           VALUES ($1, $2, 'app_claims', $3, $4, 'tenant_custom')
	           ON CONFLICT (id) DO NOTHING`, roleID, f.tenantID, key, key)
	f.exec(t, `INSERT INTO grant_ (id, tenant_id, subject_user_id, role_id, scope_kind, scope_ref)
	           VALUES ($1, $2, $3, $4, 'tenant', $2)`,
		"grn_"+roleID, f.tenantID, f.userID, roleID)
}

// joinGroups puts the user in n groups, which is the exit condition's whole difficulty.
func (f *oidcFixture) joinGroups(t *testing.T, n int) {
	t.Helper()
	f.exec(t, fmt.Sprintf(`
		INSERT INTO group_ (id, tenant_id, key, name)
		SELECT 'grp_bulk_' || lpad(i::text, 6, '0'), $1,
		       'engineering-department-team-' || i, 'Team ' || i
		  FROM generate_series(1, %d) AS i`, n), f.tenantID)
	f.exec(t, fmt.Sprintf(`
		INSERT INTO group_member (group_id, member_user_id, tenant_id)
		SELECT 'grp_bulk_' || lpad(i::text, 6, '0'), $2, $1
		  FROM generate_series(1, %d) AS i`, n), f.tenantID, f.userID)
}

// setAttributes replaces the user's attribute map.
func (f *oidcFixture) setAttributes(t *testing.T, attrs map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(attrs)
	if err != nil {
		t.Fatalf("encoding attributes: %v", err)
	}
	f.exec(t, `UPDATE app_user SET attributes = $2 WHERE id = $1`, f.userID, string(encoded))
}

// allowAttributes adds keys to a client's token attribute allowlist.
func (f *oidcFixture) allowAttributes(t *testing.T, clientID string, keys ...string) {
	t.Helper()
	f.exec(t, `UPDATE oauth_client SET token_attributes = $2 WHERE id = $1`, clientID, keys)
}

// TestGroupsSurviveWhenTheyFit. Truncation that always fired would pass the exit
// condition and make `wd.groups` useless.
func TestGroupsSurviveWhenTheyFit(t *testing.T) {
	f := newOIDCFixture(t)
	f.joinGroups(t, 20)

	claims := f.verifyAgainstJWKS(t,
		f.accessToken(t, "openid profile", "", "state-for-the-small-group-case"))
	wd, isMap := claims["wd"].(map[string]any)
	if !isMap {
		t.Fatalf("wd = %T", claims["wd"])
	}
	if groups := stringsOf(wd["groups"]); len(groups) != 20 {
		t.Fatalf("wd.groups has %d of 20 entries; a token with room for them should carry "+
			"them", len(groups))
	}
	if wd["truncated"] != nil {
		t.Fatal("a token that fits was marked truncated")
	}
}

// TestAttributesGoAfterGroups is the order SPEC §8.2 fixes, and the reason for it: a
// condition can be evaluated locally against wd.attrs, so attributes are worth more per
// byte than the group list that assigned the roles in the first place.
func TestAttributesGoAfterGroups(t *testing.T) {
	f := newOIDCFixture(t)
	f.allowAttributes(t, f.client.ID, "department", "dossier")
	// Sized so that groups and attributes together do not fit and attributes alone do.
	// Base64 is the reason the numbers look generous: a 4096-byte token holds about
	// 3000 bytes of JSON once the encoding, the header and the signature are paid for.
	f.setAttributes(t, map[string]any{
		"department": "finance",
		"dossier":    strings.Repeat("x", 1500),
	})

	t.Run("groups alone are enough", func(t *testing.T) {
		f.joinGroups(t, 60)
		claims := f.verifyAgainstJWKS(t,
			f.accessToken(t, "openid profile", "", "state-for-the-order-case-one"))
		wd, _ := claims["wd"].(map[string]any) //nolint:errcheck // asserted below
		if wd == nil {
			t.Fatal("no wd")
		}
		if wd["groups"] != nil {
			t.Fatal("groups were kept in a token that needed the room")
		}
		if wd["attrs"] == nil {
			t.Fatal("attributes were dropped before groups; §8.2 fixes the other order")
		}
		if wd["truncated"] != true {
			t.Fatalf("truncated = %v", wd["truncated"])
		}
	})

	t.Run("and when they are not", func(t *testing.T) {
		// A dossier no token can hold: groups go, then attributes, and what is left is
		// the identity and the roles.
		f.setAttributes(t, map[string]any{"dossier": strings.Repeat("x", 5000)})
		token := f.accessToken(t, "openid profile", "", "state-for-the-order-case-two")
		if len(token) > 4096 {
			t.Fatalf("token is %d bytes", len(token))
		}
		claims := f.verifyAgainstJWKS(t, token)
		wd, _ := claims["wd"].(map[string]any) //nolint:errcheck // asserted below
		if wd["attrs"] != nil || wd["groups"] != nil {
			t.Fatalf("something droppable survived a token that had to lose everything: %v", wd)
		}
		if wd["truncated"] != true {
			t.Fatalf("truncated = %v", wd["truncated"])
		}
		if wd["perm_rev"] == nil {
			t.Fatal("perm_rev was dropped")
		}
	})
}
