// Package email delivers Warden's authentication messages (docs/design-email.md).
//
// The framing that decides everything here: for three of the four flows that use it — the
// magic link, the password reset, the invitation — **the message is the credential**. That
// makes delivery part of the authentication system rather than a notification feature
// attached to it, and it is why sending is durable, why the body is never logged, and why
// the token is not stored in the queue alongside the intent to send it.
package email

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// Message is one email, rendered and ready to send.
type Message struct {
	To      string
	Subject string
	// Text and HTML are both required. A text alternative is not politeness: a client
	// that renders only text and is given only HTML shows a login link as markup, and
	// the security-conscious clients are exactly the ones configured that way.
	Text string
	HTML string

	// Template names what produced this, for metrics and the audit log. Never the body.
	Template string
	TenantID string
}

// Validate refuses a message that cannot be delivered.
func (m Message) Validate() error {
	switch {
	case m.To == "":
		return errors.New("the message has no recipient")
	case m.Subject == "":
		return errors.New("the message has no subject")
	case m.Text == "" || m.HTML == "":
		return errors.New(
			"a message needs both a text and an HTML part: a client that renders only text " +
				"would otherwise show the link as markup")
	}
	if _, err := mail.ParseAddress(m.To); err != nil {
		return fmt.Errorf("the recipient %q is not a valid address: %w", redactAddress(m.To), err)
	}
	return nil
}

// Sender delivers one message. Implementations must be safe for concurrent use.
type Sender interface {
	Send(ctx context.Context, msg Message) error
	// Name identifies the backend, for logs and metrics.
	Name() string
}

// PermanentError marks a failure that will not succeed on a retry.
//
// The distinction is the whole of the retry policy: a 5xx from a mail server is a server
// having a bad afternoon and is worth trying again, while a 4xx is the server saying the
// address does not exist — and retrying that for a day teaches the receiving domain that
// Warden sends to addresses that bounce.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent wraps an error as unretryable.
func Permanent(err error) error { return &PermanentError{Err: err} }

// IsPermanent reports whether retrying is pointless.
func IsPermanent(err error) bool {
	var permanent *PermanentError
	return errors.As(err, &permanent)
}

// redactAddress keeps an address out of a log while leaving enough to debug with.
//
// Logs are read by more people than the mailbox is, and an address is personal data even
// when the message it was going to is not. The domain survives because "every send to
// example.com is failing" is the thing an operator needs to see.
func redactAddress(address string) string {
	local, domain, ok := strings.Cut(address, "@")
	if !ok || local == "" {
		return "(malformed)"
	}
	if len(local) <= 2 {
		return "…@" + domain
	}
	return local[:1] + "…@" + domain
}

// RedactAddress is redactAddress, for callers outside this package that log a recipient.
func RedactAddress(address string) string { return redactAddress(address) }
