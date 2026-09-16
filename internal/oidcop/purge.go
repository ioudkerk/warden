package oidcop

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/store/db"
)

// Sweeping the provider's short-lived rows.
//
// Everything the OpenID Provider stores has a deadline: an authorization code lives a
// minute, a pushed request a minute, an access token ten, a device authorization ten.
// None of them is read after it expires, and none of them deletes itself. A deployment
// issuing tokens for a year accumulates a row per login per client per device, and the
// first symptom is a query plan that used to be fine.
//
// Unlike sessions and refresh tokens, these are swept to zero rather than kept for a
// retention window: there is no question anybody asks later that an expired
// authorization code answers.

// PurgeInterval is how often the sweep runs. Nothing depends on the timing — an expired
// row is refused by the reader whether or not it has been deleted yet.
const PurgeInterval = 15 * time.Minute

// PurgeExpiredOAuthSessions removes codes, tokens and pushed requests past their expiry.
func (s *Storage) PurgeExpiredOAuthSessions(ctx context.Context, before time.Time) (int64, error) {
	if s.system == nil {
		return 0, errors.New("sweeping provider sessions needs database.system_url")
	}
	var removed int64
	err := s.system.InSystem(ctx, "sweeping expired provider sessions",
		func(ctx context.Context, tx pgx.Tx) error {
			var deleteErr error
			removed, deleteErr = db.New(tx).DeleteExpiredOAuthSessions(ctx, before)
			return deleteErr
		})
	return removed, err
}

// RunPurge sweeps the provider's expired rows until ctx is cancelled.
//
// Safe on every replica: both sweeps are single DELETE statements whose effect does not
// depend on how many processes issue them. Nothing here can fail the deployment, so an
// error is logged and the loop continues.
func RunPurge(ctx context.Context, storage *Storage, log *slog.Logger) {
	if storage == nil {
		return
	}
	if log == nil {
		log = slog.Default()
	}

	sweep := func() {
		now := time.Now().UTC()
		if removed, err := storage.PurgeExpiredOAuthSessions(ctx, now); err != nil {
			log.Error("could not sweep expired provider sessions", "error", err)
		} else if removed > 0 {
			log.Info("swept expired provider sessions", "count", removed)
		}
		if removed, err := storage.PurgeExpiredDeviceAuthorizations(ctx, now); err != nil {
			log.Error("could not sweep expired device authorizations", "error", err)
		} else if removed > 0 {
			log.Info("swept expired device authorizations", "count", removed)
		}
	}

	// One pass at startup, so a deployment that has been down does not wait a quarter of
	// an hour to catch up.
	sweep()

	ticker := time.NewTicker(PurgeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("provider session purge stopped")
			return
		case <-ticker.C:
			sweep()
		}
	}
}
