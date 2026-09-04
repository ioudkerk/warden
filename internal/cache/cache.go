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
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/warden-project/warden/internal/config"
)

// Cache is the tier's client. The in-process backend is a real implementation of the
// same interface rather than a nil check at every call site — a single-node
// deployment should take the same code path as any other.
type Cache interface {
	// Ping reports whether the tier is reachable.
	Ping(ctx context.Context) error
	// Backend names the implementation, for diagnostics and for /readyz.
	Backend() string
	// Close releases resources.
	Close() error
}

// Open connects to the configured backend.
func Open(ctx context.Context, cfg *config.Config) (Cache, error) {
	switch cfg.Cache.Backend {
	case config.CacheInProcess:
		return &inProcess{}, nil

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

// inProcess is the single-node backend of SPEC §19. It is always reachable, because
// it is this process — which is exactly why it cannot propagate a change to another
// replica, and why config refuses it in production.
type inProcess struct{}

func (c *inProcess) Ping(context.Context) error { return nil }
func (c *inProcess) Backend() string            { return string(config.CacheInProcess) }
func (c *inProcess) Close() error               { return nil }
