package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	jose "github.com/go-jose/go-jose/v3"
)

// TestJWKSIsServedWithoutACredential is M1's milestone exit in miniature: a stock
// OIDC library fetches this URL holding nothing, and everything else depends on that
// working.
func TestJWKSIsServedWithoutACredential(t *testing.T) {
	f := newFixture(t)

	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/.well-known/jwks.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /.well-known/jwks.json = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/jwk-set+json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if rec.Header().Get("ETag") == "" {
		t.Fatal("no ETag, so every relying party refetches the whole set every time")
	}

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("parsing the key set: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("published %d keys; want the one the fixture created", len(set.Keys))
	}
	k := set.Keys[0]
	if !k.IsPublic() {
		t.Fatal("the published key carries private material")
	}
	if k.KeyID == "" {
		t.Fatal("the published key has no kid, so a token cannot name it")
	}
	if k.Use != "sig" {
		t.Fatalf(`published key use = %q, want "sig"`, k.Use)
	}
}

// TestJWKSHonoursIfNoneMatch keeps a fleet of relying parties from refetching an
// unchanged key set on every poll.
func TestJWKSHonoursIfNoneMatch(t *testing.T) {
	f := newFixture(t)

	first := httptest.NewRecorder()
	f.handler.ServeHTTP(first, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/.well-known/jwks.json", nil))
	etag := first.Header().Get("ETag")

	second := httptest.NewRecorder()
	conditional := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/.well-known/jwks.json", nil)
	conditional.Header.Set("If-None-Match", etag)
	f.handler.ServeHTTP(second, conditional)

	if second.Code != http.StatusNotModified {
		t.Fatalf("conditional GET = %d; want 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Fatalf("304 carried a body of %d bytes", second.Body.Len())
	}

	// After a rotation the same conditional request must produce the new set:
	// a client that keeps getting 304 through a rotation will reject every token
	// signed by the new key.
	if _, err := f.keys.Rotate(context.Background(), true); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	third := httptest.NewRecorder()
	stale := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/.well-known/jwks.json", nil)
	stale.Header.Set("If-None-Match", etag)
	f.handler.ServeHTTP(third, stale)

	if third.Code != http.StatusOK {
		t.Fatalf("conditional GET after rotation = %d; want 200 with the new key set", third.Code)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(third.Body.Bytes(), &set); err != nil {
		t.Fatalf("parsing the key set: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("published %d keys after a rotation; want the active and the previous key", len(set.Keys))
	}
}
