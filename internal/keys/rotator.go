package keys

import (
	"context"
	"errors"
	"time"
)

// CheckInterval is how often the worker asks whether the active key is due.
//
// Rotation intervals are measured in weeks, so checking hourly is already two orders
// of magnitude more often than needed. What the frequency actually buys is the
// overlap sweep: a key leaves JWKS within an hour of its window closing rather than
// whenever the next rotation happens to come round.
const CheckInterval = time.Hour

// RunRotation rotates the signing key on schedule until ctx is cancelled.
//
// It is a worker-role job and it is safe to run on every replica: rotation takes an
// advisory lock, and a replica that loses the race finds the key no longer due and
// does nothing. Nothing here fails the process — a deployment that cannot rotate today
// is still a deployment that must keep serving, and the log plus the metrics are how
// an operator learns about it. What is *not* survivable is silent failure, so every
// error is logged at error level rather than debug.
func (m *Manager) RunRotation(ctx context.Context) {
	// One pass immediately, so a process that starts up holding a key that fell due
	// while it was down does not wait an hour to notice.
	m.rotateIfDue(ctx)

	ticker := time.NewTicker(CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.log.Info("signing key rotation stopped")
			return
		case <-ticker.C:
			m.rotateIfDue(ctx)
		}
	}
}

func (m *Manager) rotateIfDue(ctx context.Context) {
	state, err := m.State(ctx)
	switch {
	case errors.Is(err, ErrNotInitialised):
		// Not an error worth alarming about: a process can outlive `warden init` not
		// having been run yet, and every endpoint that needs a key already says so.
		m.log.Debug("no signing key to rotate yet")
		return
	case err != nil:
		m.log.Error("could not read the signing key schedule", "error", err)
		return
	}

	if !state.Due {
		// Even when nothing is due, the overlap window may have closed on the
		// previous key, and that is this worker's other job.
		if retired, sweepErr := m.Sweep(ctx); sweepErr != nil {
			m.log.Error("could not retire keys past their overlap window", "error", sweepErr)
		} else if retired > 0 {
			m.log.Info("retired signing keys past their overlap window", "count", retired)
		}
		return
	}

	m.log.Info("the signing key is due for rotation",
		"kid", state.KID, "created_at", state.CreatedAt, "expires_at", state.ExpiresAt)

	kid, err := m.Rotate(ctx, false)
	switch {
	case errors.Is(err, ErrRotationHeld):
		m.log.Info("another replica is rotating the signing key")
	case err != nil:
		m.log.Error("could not rotate the signing key", "error", err, "kid", state.KID)
	case kid == "":
		// Another replica committed a rotation between the due check and the lock,
		// so by the time this transaction looked, the key was current again.
		m.log.Info("the signing key was rotated by another replica")
	default:
		m.log.Info("signing key rotated", "previous_kid", state.KID, "kid", kid)
	}
}
