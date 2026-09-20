package email

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
	"github.com/warden-project/warden/internal/store/dbtypes"
)

// The durable queue and the worker that drains it (docs/design-email.md §5).

// backoff is the retry schedule: 1 m, 5 m, 15 m, 1 h, 6 h, 24 h.
//
// Six attempts over a day, front-loaded. A mail server that is briefly unreachable is back
// within minutes, and a person waiting for a reset link should not wait an hour for the
// first retry; a server that is still refusing after a day is not going to accept it on the
// seventh attempt either.
var backoff = []time.Duration{
	time.Minute, 5 * time.Minute, 15 * time.Minute,
	time.Hour, 6 * time.Hour, 24 * time.Hour,
}

// Queue writes messages to be sent and drains them.
type Queue struct {
	// tenant writes; system reads. Enqueueing happens inside the transaction that creates
	// the token, which is tenant-scoped; draining is deployment work across every tenant,
	// the same split the decision log uses.
	tenant *store.Store
	system *store.Store

	sender   Sender
	renderer *Renderer
	log      *slog.Logger

	// tokenFor supplies the credential at send time. The queue row does not hold one, so
	// something has to fetch it — and this is the seam that keeps the token out of the
	// queue without making the queue know what a token is.
	tokenFor TokenFunc
}

// TokenFunc returns the link for one queued message, or an error if it can no longer be
// sent — because the token was consumed, revoked, or has expired while the message sat in
// the queue.
//
// Returning an error is not a failure to retry: a message whose token has been used is a
// message that should never be delivered, and delivering it would send somebody a link that
// does nothing.
type TokenFunc func(ctx context.Context, msg QueuedMessage) (link string, err error)

// ErrNotSendable means a queued message should be dropped rather than retried.
var ErrNotSendable = errors.New("this message can no longer be sent")

// QueuedMessage is one row of the queue.
type QueuedMessage struct {
	ID       string
	TenantID string
	To       string
	Template Template
	Locale   string
	Payload  map[string]any
	Attempts int
}

// QueueOptions configure a Queue.
type QueueOptions struct {
	Sender   Sender
	Renderer *Renderer
	Log      *slog.Logger
	// TokenFor is required for any template whose message carries a link. Without it a
	// magic link renders with an empty address, which is worse than not sending.
	TokenFor TokenFunc
}

// NewQueue builds the queue.
func NewQueue(tenant, system *store.Store, opts QueueOptions) (*Queue, error) {
	if opts.Sender == nil {
		return nil, errors.New("the email queue needs a sender")
	}
	renderer := opts.Renderer
	if renderer == nil {
		renderer = NewRenderer()
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	return &Queue{
		tenant: tenant, system: system,
		sender: opts.Sender, renderer: renderer, log: log, tokenFor: opts.TokenFor,
	}, nil
}

// EnqueueTx writes a message inside a caller's transaction.
//
// Inside the caller's transaction, and that is the whole design: the token and the intent to
// email it commit together or neither does. A queue with its own transaction would leave two
// ways to be wrong — a token nobody was told about, and a message promising a link that was
// never stored.
func EnqueueTx(ctx context.Context, tx pgx.Tx, msg QueuedMessage) error {
	payload := dbtypes.JSONMap{}
	for k, v := range msg.Payload {
		payload[k] = v
	}
	locale := msg.Locale
	if locale == "" {
		locale = "en"
	}

	var tenantID *string
	if msg.TenantID != "" {
		tenantID = &msg.TenantID
	}

	return db.New(tx).EnqueueEmail(ctx, db.EnqueueEmailParams{
		ID: newEmailID(), TenantID: tenantID, ToAddress: msg.To,
		Template: string(msg.Template), Locale: locale, Payload: payload,
	})
}

// Drain sends one batch and returns how many messages it handled.
func (q *Queue) Drain(ctx context.Context, batchSize int32) (int, error) {
	if q.system == nil {
		return 0, errors.New("draining the email queue needs database.system_url")
	}

	var rows []db.ClaimOutboundEmailRow
	// One transaction for the whole batch: the rows stay locked until it commits, which
	// is what stops a second worker picking up a message this one is sending.
	err := q.system.InSystem(ctx, "draining the email queue", func(ctx context.Context, tx pgx.Tx) error {
		q2 := db.New(tx)
		claimed, claimErr := q2.ClaimOutboundEmail(ctx, batchSize)
		if claimErr != nil {
			return claimErr
		}
		rows = claimed

		for _, row := range claimed {
			q.deliver(ctx, q2, row)
		}
		return nil
	})
	return len(rows), err
}

// deliver sends one message and records what happened.
//
// Errors are recorded rather than returned: one undeliverable message must not stop the
// batch, and the row carries the reason for whoever looks later.
func (q *Queue) deliver(ctx context.Context, queries *db.Queries, row db.ClaimOutboundEmailRow) {
	msg := QueuedMessage{
		ID: row.ID, TenantID: derefOr(row.TenantID), To: row.ToAddress,
		Template: Template(row.Template), Locale: row.Locale,
		Payload: map[string]any(row.Payload), Attempts: int(row.Attempts),
	}

	if row.Suppressed {
		// Recorded rather than attempted. Sending to an address that hard-bounced is how
		// a sending domain gets blocked for every tenant on the deployment.
		q.log.Info("a queued message was not sent: the address is suppressed",
			"template", row.Template, "to", redactAddress(row.ToAddress))
		if err := queries.MarkEmailSuppressed(ctx, row.ID); err != nil {
			q.log.Error("could not mark a message suppressed", "id", row.ID, "error", err)
		}
		return
	}

	link := ""
	if q.tokenFor != nil {
		resolved, err := q.tokenFor(ctx, msg)
		switch {
		case errors.Is(err, ErrNotSendable):
			// The token was used, revoked or expired while the message waited. Sending
			// it now would deliver a link that does nothing.
			q.log.Info("a queued message was dropped: its token is no longer valid",
				"template", row.Template, "to", redactAddress(row.ToAddress))
			q.fail(ctx, queries, row.ID, "the token is no longer valid")
			return
		case err != nil:
			q.retry(ctx, queries, row, fmt.Sprintf("resolving the link: %v", err))
			return
		}
		link = resolved
	}

	data := dataFrom(msg.Payload)
	data.Link = link

	rendered, err := q.renderer.Render(msg.Template, msg.To, data)
	if err != nil {
		// A template that does not render will not render on a retry.
		q.fail(ctx, queries, row.ID, fmt.Sprintf("rendering: %v", err))
		return
	}
	rendered.TenantID = msg.TenantID

	if err := q.sender.Send(ctx, rendered); err != nil {
		if IsPermanent(err) {
			q.log.Warn("a message was permanently rejected",
				"template", row.Template, "to", redactAddress(row.ToAddress), "error", err)
			q.fail(ctx, queries, row.ID, err.Error())
			return
		}
		q.retry(ctx, queries, row, err.Error())
		return
	}

	// Audited with the template, the address and the outcome — never the body.
	q.log.Info("email sent",
		"template", row.Template, "to", redactAddress(row.ToAddress), "sender", q.sender.Name())
	if err := queries.MarkEmailSent(ctx, row.ID); err != nil {
		q.log.Error("could not mark a message sent", "id", row.ID, "error", err)
	}
}

// retry schedules the next attempt, or gives up when the schedule is exhausted.
func (q *Queue) retry(ctx context.Context, queries *db.Queries, row db.ClaimOutboundEmailRow, reason string) {
	attempt := int(row.Attempts)
	if attempt >= len(backoff) {
		q.log.Error("a message exhausted its retries",
			"template", row.Template, "to", redactAddress(row.ToAddress), "error", reason)
		q.fail(ctx, queries, row.ID, reason)
		return
	}

	next := time.Now().UTC().Add(backoff[attempt])
	q.log.Warn("a message will be retried",
		"template", row.Template, "to", redactAddress(row.ToAddress),
		"attempt", attempt+1, "next", next, "error", reason)

	if err := queries.MarkEmailRetrying(ctx, db.MarkEmailRetryingParams{
		ID: row.ID, NextAttemptAt: next, LastError: &reason,
	}); err != nil {
		q.log.Error("could not schedule a retry", "id", row.ID, "error", err)
	}
}

func (q *Queue) fail(ctx context.Context, queries *db.Queries, id, reason string) {
	if err := queries.MarkEmailFailed(ctx, db.MarkEmailFailedParams{ID: id, LastError: &reason}); err != nil {
		q.log.Error("could not mark a message failed", "id", id, "error", err)
	}
}

// Depth reports how many messages are waiting.
//
// A rising queue depth is the signal that delivery has stopped, and it has to be visible
// before users report it.
func (q *Queue) Depth(ctx context.Context) (int64, error) {
	var depth int64
	err := q.system.InSystem(ctx, "reading the email queue depth", func(ctx context.Context, tx pgx.Tx) error {
		var queryErr error
		depth, queryErr = db.New(tx).EmailQueueDepth(ctx)
		return queryErr
	}, store.ReadOnly())
	return depth, err
}

// Suppress stops further delivery to an address.
func (q *Queue) Suppress(ctx context.Context, address, reason, note string) error {
	return q.system.InSystem(ctx, "suppressing an email address", func(ctx context.Context, tx pgx.Tx) error {
		var notePtr *string
		if note != "" {
			notePtr = &note
		}
		return db.New(tx).SuppressEmailAddress(ctx, db.SuppressEmailAddressParams{
			Address: address, Reason: reason, Note: notePtr,
		})
	})
}

// dataFrom turns a stored payload into template data.
func dataFrom(payload map[string]any) Data {
	get := func(key string) string {
		if value, ok := payload[key]; ok {
			if s, isString := value.(string); isString {
				return s
			}
		}
		return ""
	}
	return Data{
		TenantName:  get("tenant_name"),
		Address:     get("address"),
		ExpiresIn:   get("expires_in"),
		InviterName: get("inviter_name"),
		Headline:    get("headline"),
		Detail:      get("detail"),
	}
}

func derefOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// newEmailID returns the queue row's identifier.
func newEmailID() string { return "eml_" + randomToken(12) }

// MarshalPayload is a convenience for callers building a payload.
func MarshalPayload(values map[string]any) (map[string]any, error) {
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DrainInterval is how often the worker looks for something to send.
//
// Five seconds. A person who has just asked for a password reset is watching their inbox,
// and the delay before the first attempt is the delay they experience; anything longer is
// felt. It is short enough to matter and long enough that an idle deployment is not
// polling constantly.
const DrainInterval = 5 * time.Second

// DrainBatch is how many messages one pass claims.
const DrainBatch = 20

// Run drains the queue until ctx is cancelled.
//
// Safe on every replica: the claim query takes its rows FOR UPDATE SKIP LOCKED, so two
// workers racing take different messages rather than the same one twice. Nothing here can
// fail the deployment — a queue that is briefly behind is a delay, not an outage — so every
// error is logged and the loop continues.
func (q *Queue) Run(ctx context.Context) {
	q.log.Info("email worker started", "sender", q.sender.Name(), "interval", DrainInterval)

	// One pass immediately, so a deployment that has just started does not make somebody
	// wait for the first tick.
	q.drainOnce(ctx)

	ticker := time.NewTicker(DrainInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			q.log.Info("email worker stopped")
			return
		case <-ticker.C:
			q.drainOnce(ctx)
		}
	}
}

func (q *Queue) drainOnce(ctx context.Context) {
	sent, err := q.Drain(ctx, DrainBatch)
	if err != nil {
		q.log.Error("could not drain the email queue", "error", err)
		return
	}
	if sent == DrainBatch {
		// A full batch means there is probably more waiting. Said once per pass rather
		// than measured, because the depth query is a second round trip for a number
		// that only matters when it is large.
		q.log.Info("the email queue returned a full batch; more is waiting", "batch", sent)
	}
}
