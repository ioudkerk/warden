package authn

import (
	"context"
	"log/slog"
	"time"
)

// PurgeInterval is how often the worker sweeps ended sessions and spent refresh
// tokens out of their mirrors.
//
// Hourly, because nothing depends on the timing. The cache expires its own session
// records; these rows persist only so that the active-sessions UI and the audit trail
// can be honest about recent activity, and nothing goes wrong if they linger an extra
// hour. What does go wrong is never sweeping at all: a deployment issuing tokens for a
// year accumulates a row per refresh per user per device, and the first symptom is a
// query plan that used to be fine.
const PurgeInterval = time.Hour

// PurgeRetention is how long an ended session or spent token stays in its mirror after
// it expires.
//
// Not zero, deliberately. "Which devices was this account signed in from last week?" is
// a question asked during an incident, and answering it needs the rows to have outlived
// the sessions. A month is long enough to investigate and short enough that the table
// tracks active use rather than all history.
const PurgeRetention = 30 * 24 * time.Hour

// RunPurge sweeps expired sessions and refresh tokens until ctx is cancelled.
//
// A worker-role job, and safe to run on every replica: both sweeps are single DELETE
// statements whose effect does not depend on how many processes issue them. Nothing
// here can fail the deployment — a mirror that is a few hours behind is untidy, not
// broken — so every error is logged and the loop continues.
func RunPurge(ctx context.Context, sessions *Sessions, tokens *RefreshTokens, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}

	sweep := func() {
		if sessions != nil {
			deleted, err := sessions.PurgeExpired(ctx, PurgeRetention)
			switch {
			case err != nil:
				log.Error("could not purge expired sessions", "error", err)
			case deleted > 0:
				log.Info("purged expired sessions", "count", deleted)
			}
		}
		if tokens != nil {
			deleted, err := tokens.PurgeExpired(ctx, PurgeRetention)
			switch {
			case err != nil:
				log.Error("could not purge expired refresh tokens", "error", err)
			case deleted > 0:
				log.Info("purged expired refresh tokens", "count", deleted)
			}
		}
	}

	// One pass at startup, so a deployment that has been down for a while does not wait
	// an hour to catch up.
	sweep()

	ticker := time.NewTicker(PurgeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("session and refresh token purge stopped")
			return
		case <-ticker.C:
			sweep()
		}
	}
}
