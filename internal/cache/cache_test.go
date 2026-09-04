package cache_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/warden-project/warden/internal/cache"
	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
)

func testConfig(backend config.CacheBackend, url string) *config.Config {
	cfg := config.Defaults()
	cfg.Environment = config.EnvDevelopment
	cfg.Cache.Backend = backend
	cfg.Cache.URL = secrets.New(url)
	cfg.Cache.DialTimeout = 2 * time.Second
	cfg.Cache.ReadTimeout = 2 * time.Second
	cfg.Cache.WriteTimeout = 2 * time.Second
	cfg.Cache.PoolSize = 2
	return cfg
}

// The in-process backend is a real implementation of the same interface, not a nil
// check at every call site: a single-node deployment takes the same code path as any
// other.
func TestInProcessBackendIsAlwaysReachable(t *testing.T) {
	c, err := cache.Open(context.Background(), testConfig(config.CacheInProcess, ""))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = c.Close() }() //nolint:errcheck // nothing to release

	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("the in-process cache reported itself unreachable: %v", err)
	}
	if c.Backend() != "in-process" {
		t.Errorf("backend = %q", c.Backend())
	}
}

// An unreachable cache should stop the process coming up, not surface later as the
// first request that needed it.
func TestOpenFailsFastOnAnUnreachableRedis(t *testing.T) {
	// Port 1 is reserved and nothing listens there.
	cfg := testConfig(config.CacheRedis, "redis://127.0.0.1:1/0")
	cfg.Cache.DialTimeout = 500 * time.Millisecond

	started := time.Now()
	c, err := cache.Open(context.Background(), cfg)
	if err == nil {
		_ = c.Close() //nolint:errcheck // teardown
		t.Fatal("Open succeeded against a port nothing is listening on")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("Open took %s to fail; it should give up on the dial timeout", elapsed)
	}
}

// The error must not echo the connection string, which can carry a password.
func TestOpenDoesNotLeakTheConnectionString(t *testing.T) {
	cfg := testConfig(config.CacheRedis, "redis://:sup3r-s3cret@127.0.0.1:1/0")
	cfg.Cache.DialTimeout = 500 * time.Millisecond

	_, err := cache.Open(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected a failure")
	}
	if strings.Contains(err.Error(), "sup3r-s3cret") {
		t.Errorf("the error leaked the cache password: %v", err)
	}
}

func TestOpenRejectsAMalformedURL(t *testing.T) {
	_, err := cache.Open(context.Background(), testConfig(config.CacheRedis, "not-a-url"))
	if err == nil {
		t.Fatal("a malformed cache URL was accepted")
	}
}

// The real thing, when one is available.
func TestRedisBackendAgainstARealServer(t *testing.T) {
	url := os.Getenv("WARDEN_TEST_REDIS_URL")
	if url == "" {
		t.Skip("set WARDEN_TEST_REDIS_URL to exercise the Redis backend")
	}
	c, err := cache.Open(context.Background(), testConfig(config.CacheRedis, url))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = c.Close() }() //nolint:errcheck // teardown

	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("Ping: %v", err)
	}
	if c.Backend() != "redis" {
		t.Errorf("backend = %q", c.Backend())
	}
}
