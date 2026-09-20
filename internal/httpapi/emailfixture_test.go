package httpapi_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/warden-project/warden/internal/email"
)

// Draining the queue in a test, so the link a test follows is the link a person would get.
//
// The alternative — having the fixture call IssueLink and use its return value — would skip
// the part most likely to be wrong: the token is sealed into the queue payload, and the
// worker has to open it again at send time. A test that never drained the queue would pass
// with that broken.

// captureSender keeps what it was asked to send.
type captureSender struct {
	mu       sync.Mutex
	messages []email.Message
}

func (s *captureSender) Name() string { return "capture" }

func (s *captureSender) Send(_ context.Context, msg email.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, msg)
	return nil
}

func (s *captureSender) last() (email.Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.messages) == 0 {
		return email.Message{}, false
	}
	return s.messages[len(s.messages)-1], true
}

// drainOneLink runs the worker once and returns the link from the message it sent.
func (f *oidcFixture) drainOneLink(t *testing.T) string {
	t.Helper()

	sent, err := f.queue.Drain(context.Background(), 10)
	if err != nil {
		t.Fatalf("draining the email queue: %v", err)
	}
	if sent == 0 {
		t.Fatal("nothing was queued; the request did not result in a message")
	}

	msg, ok := f.sender.last()
	if !ok {
		t.Fatal("the queue drained but sent nothing")
	}

	// From the text part, which is where §8 requires the full URL to appear so that a
	// recipient can read where it goes before following it.
	link := linkIn(msg.Text)
	if link == "" {
		t.Fatalf("the message carries no link:\n%s", msg.Text)
	}
	// Relative, because the fixture's issuer is not the test server's address.
	return strings.TrimPrefix(link, f.issuer)
}

// linkIn finds the first URL in a rendered text body.
func linkIn(body string) string {
	for _, field := range strings.Fields(body) {
		if strings.Contains(field, "://") && strings.Contains(field, "token=") {
			return strings.TrimRight(field, ".,)")
		}
	}
	return ""
}
