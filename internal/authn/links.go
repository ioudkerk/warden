package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/warden-project/warden/internal/audit"
	"github.com/warden-project/warden/internal/email"
	"github.com/warden-project/warden/internal/store"
	"github.com/warden-project/warden/internal/store/db"
)

// Emailed links: magic sign-in, password reset, address verification, invitation
// (SPEC §7.1, §7.2; docs/design-email.md §8).
//
// One mechanism for four flows, because they are one object with four lifetimes: a value
// from crypto/rand, sent to an address, good once, for a bounded time. What differs is how
// long it lives and what redeeming it does.
//
// The property that took the most care is the last one. A link is *consumed in the same
// transaction that acts on it*, so two requests racing with the same URL do not both
// succeed — the second loses the race at the database rather than at a check in Go with a
// window after it.

// LinkKind names a flow. The values match link_token_kind_valid.
type LinkKind string

const (
	LinkMagic         LinkKind = "magic_link"
	LinkPasswordReset LinkKind = "password_reset"
	LinkVerifyEmail   LinkKind = "verify_email"
	LinkInvitation    LinkKind = "invitation"
)

// Lifetimes, from docs/design-email.md §1.
//
// Fifteen minutes for the two that authenticate, because they are credentials in a mailbox
// and a mailbox is a channel Warden does not control. Longer for the two that do not: a
// verification proves an address and an invitation is a piece of onboarding somebody may
// open on Monday.
var linkLifetimes = map[LinkKind]time.Duration{
	LinkMagic:         15 * time.Minute,
	LinkPasswordReset: 15 * time.Minute,
	LinkVerifyEmail:   24 * time.Hour,
	LinkInvitation:    7 * 24 * time.Hour,
}

// linkPaths are where each kind lands.
var linkPaths = map[LinkKind]string{
	LinkMagic:         "/login/link",
	LinkPasswordReset: "/password/reset",
	LinkVerifyEmail:   "/verify",
	LinkInvitation:    "/invite",
}

// linkTemplates map a kind to the message that carries it.
var linkTemplates = map[LinkKind]email.Template{
	LinkMagic:         email.TemplateMagicLink,
	LinkPasswordReset: email.TemplatePasswordReset,
	LinkVerifyEmail:   email.TemplateVerifyEmail,
	LinkInvitation:    email.TemplateInvitation,
}

// linkTokenBytes is 256 bits, as §8 requires.
const linkTokenBytes = 32

// ErrInvalidLink is every way a link can fail: unknown, expired, already used, or for a
// user who no longer exists.
//
// One error, and the page that renders it says one thing. Distinguishing "expired" from
// "already used" tells whoever is holding a link they found somewhere which of the two it
// is, and neither answer helps a person who simply needs a new one.
var ErrInvalidLink = errors.New("this link is no longer valid")

// LinkRequest describes a link to issue.
type LinkRequest struct {
	Kind     LinkKind
	TenantID string
	UserID   string
	// Address is where the message goes. For verification it is the address being
	// proved, which may not yet be the user's.
	Address string
	// TenantName and InviterName are for the message body.
	TenantName  string
	InviterName string
	// RequestedIP is recorded on the row, so a burst is visible afterwards.
	RequestedIP string
}

// IssueLink creates a token and queues the message in one transaction.
//
// One transaction, and that is the design rather than an optimisation: the token and the
// intent to email it commit together or neither does. The alternative leaves two ways to be
// wrong — a token nobody was ever told about, and a message promising a link that was never
// stored.
//
// The plaintext is returned for tests and for the stdout sender to be useful in
// development. In production nothing reads it: the queue resolves the link at send time.
func (a *Authenticator) IssueLink(ctx context.Context, req LinkRequest) (string, error) {
	lifetime, ok := linkLifetimes[req.Kind]
	if !ok {
		return "", fmt.Errorf("unknown link kind %q", req.Kind)
	}
	if a.issuer == "" {
		return "", errors.New(
			"issuing a link needs the issuer: the URL in the message is rooted at it")
	}
	if a.keyring == nil {
		return "", errors.New(
			"issuing a link needs the keyring: the token is sealed under it while the " +
				"message waits in the queue")
	}

	// Generated before the transaction opens, per M0-7's convention: the store's retry
	// loop re-runs the callback, and a token minted inside it would differ between
	// attempts — the message would carry one value and the database would hold another.
	token, hash, err := newLinkToken()
	if err != nil {
		return "", err
	}
	id, err := newID("lnk")
	if err != nil {
		return "", err
	}

	var address *string
	if req.Address != "" {
		address = &req.Address
	}
	var requestedIP *string
	if req.RequestedIP != "" {
		requestedIP = &req.RequestedIP
	}

	expires := time.Now().UTC().Add(lifetime)

	err = a.tenant.InTenant(ctx, req.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		// The name the message greets somebody with. Read here rather than taken from the
		// caller, because a caller that forgets sends "Sign in to ten_acme" to a real
		// person — which is what the first live run of this flow actually produced.
		tenantName := req.TenantName
		if tenantName == "" {
			name, nameErr := db.New(tx).TenantDisplayName(ctx, req.TenantID)
			if nameErr != nil {
				return fmt.Errorf("reading the tenant's name: %w", nameErr)
			}
			tenantName = name
		}

		if insertErr := db.New(tx).InsertLinkToken(ctx, db.InsertLinkTokenParams{
			ID: id, Kind: string(req.Kind), TenantID: req.TenantID, UserID: req.UserID,
			TokenHash: hash, Address: address, ExpiresAt: expires, RequestedIp: requestedIP,
		}); insertErr != nil {
			return insertErr
		}

		// The same transaction: the token and the intent to email it commit together.
		//
		// The token is sealed under the KEK rather than stored in the clear, and the
		// payload is emptied when the message is sent. See EmailLinkResolver for why the
		// token has to be here at all — link_token holds a hash, so there is nothing to
		// read back at send time.
		sealed, sealErr := a.keyring.EncryptString(token, linkAAD(req.TenantID, req.Address))
		if sealErr != nil {
			return fmt.Errorf("sealing the link token: %w", sealErr)
		}

		return email.EnqueueTx(ctx, tx, email.QueuedMessage{
			TenantID: req.TenantID,
			To:       req.Address,
			Template: linkTemplates[req.Kind],
			Payload: map[string]any{
				"tenant_name":  tenantName,
				"address":      req.Address,
				"inviter_name": req.InviterName,
				"expires_in":   email.HumanDuration(lifetime),
				"token":        sealed,
			},
		})
	})
	if err != nil {
		return "", fmt.Errorf("issuing a %s link: %w", req.Kind, err)
	}

	a.log.Info("an emailed link was issued",
		"kind", req.Kind, "tenant_id", req.TenantID, "user_id", req.UserID,
		"to", email.RedactAddress(req.Address), "expires_in", lifetime)

	return a.LinkURL(req.Kind, token), nil
}

// LinkURL assembles what goes in the message.
func (a *Authenticator) LinkURL(kind LinkKind, token string) string {
	return strings.TrimSuffix(a.issuer, "/") + linkPaths[kind] + "?token=" + token
}

// RedeemedLink is what a valid link resolved to.
type RedeemedLink struct {
	TenantID string
	UserID   string
	Kind     LinkKind
	// Address is the one being proved, for verification.
	Address string
}

// RedeemLink consumes a token and returns who it belongs to.
//
// The lookup is by hash on the system pool, necessarily: the token arrives in a URL with
// nothing else attached, so there is no tenant to scope the read by until it returns one.
// That is the same exception setup_token and service_account are registered for.
//
// Consuming happens in the same transaction as the read, and the UPDATE carries the
// single-use rule in its WHERE clause. Two requests racing with the same link both see an
// unconsumed row; exactly one changes it.
func (a *Authenticator) RedeemLink(ctx context.Context, kind LinkKind, token string) (*RedeemedLink, error) {
	if token == "" {
		return nil, ErrInvalidLink
	}
	if a.system == nil {
		return nil, errors.New("redeeming a link needs database.system_url")
	}

	hash := hashLinkToken(token)
	var redeemed *RedeemedLink

	err := a.system.InSystem(ctx, "redeeming an emailed link", func(ctx context.Context, tx pgx.Tx) error {
		q := db.New(tx)
		row, queryErr := q.LinkTokenByHash(ctx, hash)
		if queryErr != nil {
			return queryErr
		}

		// The kind is checked, not assumed. Without this a reset link would work at the
		// magic-link endpoint: both are valid tokens for the same user, and the one with
		// the weaker consequence would let somebody take the stronger action.
		if LinkKind(row.Kind) != kind {
			a.log.Warn("a link was presented at the wrong endpoint",
				"presented_as", kind, "actual", row.Kind, "tenant_id", row.TenantID)
			return ErrInvalidLink
		}
		if row.ConsumedAt != nil {
			// Worth saying out loud: either somebody is retrying a link that already
			// worked, or a link has been found by somebody it was not sent to.
			a.log.Warn("an already-used link was presented again",
				"kind", row.Kind, "tenant_id", row.TenantID, "user_id", row.UserID)
			return ErrInvalidLink
		}
		if !time.Now().Before(row.ExpiresAt) {
			return ErrInvalidLink
		}

		consumed, consumeErr := q.ConsumeLinkToken(ctx, row.ID)
		if consumeErr != nil {
			return consumeErr
		}
		if consumed == 0 {
			// Somebody else consumed it between the read and the write. At this point
			// that is a race with a second click, or with somebody else holding the
			// same URL; either way this request does not get it.
			return ErrInvalidLink
		}

		// §8: redeeming invalidates every other outstanding token of the same kind for
		// this user. Two live reset links is one more than anyone needs, and the extra
		// one is usually the older message still sitting in a mailbox.
		if _, otherErr := q.ConsumeOtherLinkTokens(ctx, db.ConsumeOtherLinkTokensParams{
			TenantID: row.TenantID, UserID: row.UserID, Kind: row.Kind, KeepID: row.ID,
		}); otherErr != nil {
			// Not fatal: this link is already spent and the caller may proceed. The
			// others expire on their own.
			a.log.Warn("could not invalidate the other outstanding links", "error", otherErr)
		}

		redeemed = &RedeemedLink{
			TenantID: row.TenantID, UserID: row.UserID, Kind: LinkKind(row.Kind),
			Address: derefOrEmpty(row.Address),
		}
		return nil
	}, store.Isolation(pgx.Serializable))

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, ErrInvalidLink
	case errors.Is(err, ErrInvalidLink):
		return nil, ErrInvalidLink
	case err != nil:
		return nil, err
	}

	a.recordLinkEvent(ctx, redeemed)
	return redeemed, nil
}

// recordLinkEvent writes the redemption to the audit log.
func (a *Authenticator) recordLinkEvent(ctx context.Context, link *RedeemedLink) {
	a.log.Info("an emailed link was redeemed",
		"kind", link.Kind, "tenant_id", link.TenantID, "user_id", link.UserID)

	if a.audit == nil || a.system == nil {
		return
	}
	err := a.system.InSystem(ctx, "recording a link redemption", func(ctx context.Context, tx pgx.Tx) error {
		_, appendErr := a.audit.Append(ctx, tx, audit.Entry{
			TenantID: link.TenantID, Action: ActionLinkRedeemed,
			TargetType: targetUser, TargetID: link.UserID,
			Reason: "an emailed link was redeemed",
			After:  map[string]any{"kind": string(link.Kind)},
		})
		return appendErr
	})
	if err != nil {
		a.log.Error("could not record a link redemption in the audit log", "error", err)
	}
}

// ActionLinkRedeemed records a link being used.
const ActionLinkRedeemed = "security.link_redeemed"

// EmailLinkResolver is the queue's TokenFunc: it turns a queued message back into a link.
//
// **This is where the design document and reality had to be reconciled.** §5 says the queue
// row holds no token and that the token is "read from its own table at send time" — but
// link_token stores only a SHA-256, by design, so there is nothing to read back. The two
// requirements cannot both hold literally.
//
// What holds instead: the token travels in the queue payload *sealed under the deployment
// KEK*, and the payload is emptied the moment the message is sent or permanently fails. So
// a database copy without the KEK yields no usable link; a row that is no longer waiting to
// be sent carries nothing; and the window in which the sealed value exists is the minutes a
// message spends in the queue rather than the lifetime of the row.
//
// The alternative — rendering the message at enqueue time and storing the body — is worse in
// the same direction: it keeps the credential *and* the whole message, and for longer.
func (a *Authenticator) EmailLinkResolver() email.TokenFunc {
	return func(ctx context.Context, msg email.QueuedMessage) (string, error) {
		kind, ok := kindForTemplate(msg.Template)
		if !ok {
			// A message with no link: a security alert. Rendering it needs nothing.
			return "", nil
		}

		sealed, _ := msg.Payload["token"].(string) //nolint:errcheck // checked below
		if sealed == "" {
			// The payload has been emptied, which happens when the message has already
			// been sent or has permanently failed. Either way there is nothing to send.
			return "", email.ErrNotSendable
		}
		if a.keyring == nil {
			return "", errors.New("resolving a queued link needs the keyring")
		}

		token, err := a.keyring.DecryptString(sealed, linkAAD(msg.TenantID, msg.To))
		if err != nil {
			return "", fmt.Errorf("opening a queued link token: %w", err)
		}
		return a.LinkURL(kind, token), nil
	}
}

// kindForTemplate maps a queued template back to the flow that produced it.
func kindForTemplate(template email.Template) (LinkKind, bool) {
	for kind, name := range linkTemplates {
		if name == template {
			return kind, true
		}
	}
	return "", false
}

// linkAAD binds a sealed token to the message it belongs to, so a payload lifted from one
// queue row cannot be replanted in another addressed somewhere else.
func linkAAD(tenantID, address string) []byte {
	return []byte("warden/link-token/" + tenantID + "/" + strings.ToLower(address))
}

// newLinkToken returns the value and its stored hash.
func newLinkToken() (token string, hash []byte, err error) {
	raw := make([]byte, linkTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generating a link token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

func hashLinkToken(token string) []byte {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return sum[:]
}
