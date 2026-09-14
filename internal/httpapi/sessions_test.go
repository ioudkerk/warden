package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// get issues an authenticated GET, mirroring the fixture's post helper.
func (f fixture) get(t *testing.T, path, token string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	var decoded map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("response is not JSON: %s", rec.Body.String())
		}
	}
	return rec.Code, decoded
}

// sessionIDs pulls the ids out of a /sessions response.
func sessionIDs(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, ok := body["sessions"].([]any)
	if !ok {
		t.Fatalf("response has no sessions array: %v", body)
	}
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		session, isMap := entry.(map[string]any)
		if !isMap {
			t.Fatalf("session entry is not an object: %v", entry)
		}
		id, isString := session["id"].(string)
		if !isString {
			t.Fatalf("session has no id: %v", session)
		}
		out = append(out, id)
	}
	return out
}

// TestRevokeAllOverHTTP is M1-4's exit condition at the surface the task names.
func TestRevokeAllOverHTTP(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if f.sessions == nil {
		t.Skip("this fixture has no session store")
	}

	for _, device := range []string{"laptop", "phone"} {
		if _, err := f.sessions.Create(ctx, "ten_acme", f.maria, []string{"pwd"}, "", device); err != nil {
			t.Fatalf("Create(%s): %v", device, err)
		}
	}

	status, body := f.get(t, "/v1/users/"+f.maria+"/sessions", f.acmeTok)
	if status != http.StatusOK {
		t.Fatalf("GET sessions = %d: %v", status, body)
	}
	if got := sessionIDs(t, body); len(got) != 2 {
		t.Fatalf("listed %d sessions; want 2", len(got))
	}

	status, body = f.post(t, "/v1/users/"+f.maria+"/revoke-all", f.acmeTok, `{"reason":"password changed"}`)
	if status != http.StatusOK {
		t.Fatalf("revoke-all = %d: %v", status, body)
	}
	if count, ok := body["revoked"].(float64); !ok || int(count) != 2 {
		t.Fatalf("revoked = %v; want 2", body["revoked"])
	}

	status, body = f.get(t, "/v1/users/"+f.maria+"/sessions", f.acmeTok)
	if status != http.StatusOK {
		t.Fatalf("GET sessions after revoke-all = %d: %v", status, body)
	}
	if got := sessionIDs(t, body); len(got) != 0 {
		t.Fatalf("after revoke-all the list still shows %d sessions", len(got))
	}
}

// TestRevokeOneSessionOverHTTP covers the device-list case.
func TestRevokeOneSessionOverHTTP(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if f.sessions == nil {
		t.Skip("this fixture has no session store")
	}

	laptop, err := f.sessions.Create(ctx, "ten_acme", f.maria, []string{"pwd"}, "", "laptop")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.sessions.Create(ctx, "ten_acme", f.maria, []string{"pwd"}, "", "phone"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	status, body := f.post(t, "/v1/sessions/"+laptop.ID+"/revoke", f.acmeTok, `{"reason":"lost device"}`)
	if status != http.StatusOK {
		t.Fatalf("revoke = %d: %v", status, body)
	}

	status, body = f.get(t, "/v1/users/"+f.maria+"/sessions", f.acmeTok)
	if status != http.StatusOK {
		t.Fatalf("GET sessions = %d: %v", status, body)
	}
	remaining := sessionIDs(t, body)
	if len(remaining) != 1 {
		t.Fatalf("listed %d sessions after revoking one of two", len(remaining))
	}
	if remaining[0] == laptop.ID {
		t.Fatal("the revoked session is the one still listed")
	}
}

// TestRevokingAnUnknownSessionIsNotAnOracle keeps the endpoint from confirming which
// session ids exist.
func TestRevokingAnUnknownSessionIsNotAnOracle(t *testing.T) {
	f := newFixture(t)
	if f.sessions == nil {
		t.Skip("this fixture has no session store")
	}

	status, body := f.post(t, "/v1/sessions/ses_definitely_not_real/revoke", f.acmeTok, `{}`)
	if status != http.StatusOK {
		t.Fatalf("revoking an unknown session = %d: %v. It must answer exactly as revoking a "+
			"real one does, or the status code enumerates session ids", status, body)
	}
}

// TestSessionEndpointsAreTenantScoped is threat 5 of SPEC §17.1 on these routes: a
// token for one tenant must not reach another's sessions.
func TestSessionEndpointsAreTenantScoped(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if f.sessions == nil {
		t.Skip("this fixture has no session store")
	}

	acmeSession, err := f.sessions.Create(ctx, "ten_acme", f.maria, []string{"pwd"}, "", "laptop")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The rival tenant's token, against acme's user and acme's session.
	status, body := f.get(t, "/v1/users/"+f.maria+"/sessions", f.rivalTok)
	if status != http.StatusOK {
		t.Fatalf("cross-tenant list = %d: %v", status, body)
	}
	if got := sessionIDs(t, body); len(got) != 0 {
		t.Fatalf("a token for one tenant listed %d of another tenant's sessions", len(got))
	}

	status, body = f.post(t, "/v1/users/"+f.maria+"/revoke-all", f.rivalTok, `{}`)
	if status != http.StatusOK {
		t.Fatalf("cross-tenant revoke-all = %d: %v", status, body)
	}
	if count, ok := body["revoked"].(float64); !ok || int(count) != 0 {
		t.Fatalf("a token for one tenant revoked %v of another tenant's sessions", body["revoked"])
	}

	status, _ = f.post(t, "/v1/sessions/"+acmeSession.ID+"/revoke", f.rivalTok, `{}`)
	if status != http.StatusOK {
		t.Fatalf("cross-tenant revoke = %d", status)
	}

	// The session survived all three, which is the point.
	if _, err := f.sessions.Validate(ctx, acmeSession.ID); err != nil {
		t.Fatalf("another tenant's token ended this session: %v", err)
	}
}

// TestSessionEndpointsRequireACredential is the baseline every route shares.
func TestSessionEndpointsRequireACredential(t *testing.T) {
	f := newFixture(t)

	for _, route := range []struct {
		method, path string
	}{
		{http.MethodGet, "/v1/users/usr_someone/sessions"},
		{http.MethodPost, "/v1/users/usr_someone/revoke-all"},
		{http.MethodPost, "/v1/sessions/ses_something/revoke"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			var status int
			if route.method == http.MethodGet {
				status, _ = f.get(t, route.path, "")
			} else {
				status, _ = f.post(t, route.path, "", `{}`)
			}
			if status != http.StatusUnauthorized {
				t.Fatalf("got %d without a token; want 401", status)
			}
		})
	}
}

// TestRevokeAllToleratesAnUntidyBody: this endpoint exists for incidents, and refusing
// to sign someone out because the JSON was malformed is the wrong trade.
func TestRevokeAllToleratesAnUntidyBody(t *testing.T) {
	f := newFixture(t)
	if f.sessions == nil {
		t.Skip("this fixture has no session store")
	}

	for name, body := range map[string]string{
		"empty":      "",
		"not json":   "this is not json",
		"wrong type": `{"reason":42}`,
	} {
		t.Run(name, func(t *testing.T) {
			status, response := f.post(t, "/v1/users/"+f.maria+"/revoke-all", f.acmeTok, body)
			if status != http.StatusOK {
				t.Fatalf("got %d for a %s body: %v", status, name, response)
			}
		})
	}
}
