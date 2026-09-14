// Package cache is Warden's connection to the cache and pub/sub tier.
//
// SPEC §19 puts sessions, the decision cache, SAML replay protection and the change
// stream here. Today only the health check and the metrics use it; the point of
// having it now is that /readyz cannot honestly say a deployment is ready while one
// of its dependencies is unreachable, and until this existed it was saying so anyway.
package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/warden-project/warden/internal/config"
)

// ErrMiss is returned by Get when a key is absent or has expired.
//
// Absent and expired are deliberately the same answer. A caller that could tell them
// apart would be tempted to treat one as recoverable, and for a session key both mean
// the same thing: this session is not valid.
var ErrMiss = errors.New("no such key in the cache")

// Cache is the tier's client. The in-process backend is a real implementation of the
// same interface rather than a nil check at every call site — a single-node
// deployment should take the same code path as any other.
//
// The primitives are deliberately few. Sessions (M1-4), the decision cache (M3-5) and
// SAML replay protection (M4) all want the same four operations over keys with a time
// to live, and keeping the surface at that size is what makes a second backend
// possible to write correctly.
type Cache interface {
	// Ping reports whether the tier is reachable.
	Ping(ctx context.Context) error
	// Backend names the implementation, for diagnostics and for /readyz.
	Backend() string
	// Close releases resources.
	Close() error

	// Get returns a stored value, or ErrMiss.
	Get(ctx context.Context, key string) ([]byte, error)
	// GetMany returns several values in one round trip. A missing key yields a nil
	// entry rather than an error, because the common caller — session validation —
	// reads a session and its user's revocation marker together and expects at most
	// one of them to be absent.
	GetMany(ctx context.Context, keys ...string) ([][]byte, error)
	// Set stores a value with a time to live. A ttl of zero stores it without one,
	// which for this tier means "until evicted" and should be rare.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Delete removes keys. Removing a key that is not there is not an error.
	Delete(ctx context.Context, keys ...string) error
	// Expire resets a key's time to live, for the sliding idle timeout of a session.
	// It reports whether the key existed.
	Expire(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// Open connects to the configured backend.
func Open(ctx context.Context, cfg *config.Config) (Cache, error) {
	switch cfg.Cache.Backend {
	case config.CacheInProcess:
		return newInProcess(), nil

	case config.CacheRedis:
		opts, err := redis.ParseURL(cfg.Cache.URL.Expose())
		if err != nil {
			// The error can quote the URL, which may carry a password.
			return nil, errors.New("cache.url is not a valid Redis connection string")
		}
		opts.DialTimeout = cfg.Cache.DialTimeout
		opts.ReadTimeout = cfg.Cache.ReadTimeout
		opts.WriteTimeout = cfg.Cache.WriteTimeout
		opts.PoolSize = cfg.Cache.PoolSize
		opts.ClientName = "warden"

		client := redis.NewClient(opts)
		// Connect eagerly. A cache that is unreachable at startup is something an
		// operator should learn from the process failing to come up, not from the
		// first request that needed it.
		pingCtx, cancel := context.WithTimeout(ctx, cfg.Cache.DialTimeout)
		defer cancel()
		if err := client.Ping(pingCtx).Err(); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("connecting to the cache: %w", err)
		}
		return &redisCache{client: client}, nil

	default:
		return nil, fmt.Errorf("unknown cache backend %q", cfg.Cache.Backend)
	}
}

type redisCache struct{ client *redis.Client }

func (c *redisCache) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return c.client.Ping(ctx).Err()
}

func (c *redisCache) Backend() string { return string(config.CacheRedis) }
func (c *redisCache) Close() error    { return c.client.Close() }

func (c *redisCache) Get(ctx context.Context, key string) ([]byte, error) {
	value, err := c.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrMiss
	}
	return value, err
}

func (c *redisCache) GetMany(ctx context.Context, keys ...string) ([][]byte, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	values, err := c.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}
	out := make([][]byte, len(values))
	for i, v := range values {
		switch typed := v.(type) {
		case nil:
			out[i] = nil
		case string:
			out[i] = []byte(typed)
		case []byte:
			out[i] = typed
		default:
			return nil, fmt.Errorf("unexpected %T for key %q", v, keys[i])
		}
	}
	return out, nil
}

func (c *redisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return c.client.Set(ctx, key, value, ttl).Err()
}

func (c *redisCache) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	return c.client.Del(ctx, keys...).Err()
}

func (c *redisCache) Expire(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return c.client.Expire(ctx, key, ttl).Result()
}

// inProcess is the single-node backend of SPEC §19. It is always reachable, because
// it is this process — which is exactly why it cannot propagate a change to another
// replica, and why config refuses it in production.
type inProcess struct {
	mu      sync.Mutex
	entries map[string]inProcessEntry
}

type inProcessEntry struct {
	value []byte
	// expires is zero when the entry has no time to live.
	expires time.Time
}

func newInProcess() *inProcess { return &inProcess{entries: map[string]inProcessEntry{}} }

func (c *inProcess) Ping(context.Context) error { return nil }
func (c *inProcess) Backend() string            { return string(config.CacheInProcess) }
func (c *inProcess) Close() error               { return nil }

// live returns an entry if it exists and has not expired, removing it if it has.
// Expiry is evaluated on read rather than by a sweeper: this backend is for a single
// node, the key sets are small, and a goroutine per cache is a worse trade.
func (c *inProcess) live(key string) ([]byte, bool) {
	entry, found := c.entries[key]
	if !found {
		return nil, false
	}
	if !entry.expires.IsZero() && !time.Now().Before(entry.expires) {
		delete(c.entries, key)
		return nil, false
	}
	return entry.value, true
}

func (c *inProcess) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, found := c.live(key)
	if !found {
		return nil, ErrMiss
	}
	// Copied, so a caller mutating what it read cannot reach into the cache. Redis
	// hands back a fresh slice every time and the two backends must not differ in
	// whether that is safe.
	return append([]byte(nil), value...), nil
}

func (c *inProcess) GetMany(_ context.Context, keys ...string) ([][]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(keys))
	for i, key := range keys {
		if value, found := c.live(key); found {
			out[i] = append([]byte(nil), value...)
		}
	}
	return out, nil
}

func (c *inProcess) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := inProcessEntry{value: append([]byte(nil), value...)}
	if ttl > 0 {
		entry.expires = time.Now().Add(ttl)
	}
	c.entries[key] = entry
	return nil
}

func (c *inProcess) Delete(_ context.Context, keys ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, key := range keys {
		delete(c.entries, key)
	}
	return nil
}

func (c *inProcess) Expire(_ context.Context, key string, ttl time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, found := c.live(key)
	if !found {
		return false, nil
	}
	entry := inProcessEntry{value: value}
	if ttl > 0 {
		entry.expires = time.Now().Add(ttl)
	}
	c.entries[key] = entry
	return true, nil
}
