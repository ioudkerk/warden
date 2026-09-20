package email

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"strings"
	"time"
)

// Building the message itself.
//
// A multipart/alternative body with a text part and an HTML part, in that order: RFC 2046
// §5.1.4 says the *last* part is the one a client should prefer, so the order is what makes
// a graphical client show the HTML and a text-only client show the text.

// render produces the RFC 5322 message, headers and body.
func (s *SMTPSender) render(msg Message) []byte {
	boundary := newBoundary()

	var b strings.Builder
	header := func(name, value string) {
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteString("\r\n")
	}

	header("From", s.from)
	header("To", msg.To)
	if s.replyTo != "" {
		header("Reply-To", s.replyTo)
	}
	// Encoded, because a subject may carry a tenant's name and a tenant's name may carry
	// anything. A raw non-ASCII byte in a header is a malformed message.
	header("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	header("Date", time.Now().UTC().Format(time.RFC1123Z))
	header("MIME-Version", "1.0")

	// Asks intermediaries not to file this under promotions and not to auto-reply to it.
	// A password reset that lands in a bulk folder is a password reset that did not
	// arrive, and an out-of-office reply to a no-reply address is noise for somebody.
	header("Auto-Submitted", "auto-generated")
	header("X-Auto-Response-Suppress", "All")

	header("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")

	// A note for the client that understands neither part. It never reaches a person who
	// can act on it, which is why it says nothing about the message.
	b.WriteString("This is a message in MIME format.\r\n")

	writePart(&b, boundary, `text/plain; charset="utf-8"`, msg.Text)
	writePart(&b, boundary, `text/html; charset="utf-8"`, msg.HTML)

	b.WriteString("--")
	b.WriteString(boundary)
	b.WriteString("--\r\n")
	return []byte(b.String())
}

// writePart appends one alternative.
//
// Quoted-printable rather than raw, and that is not decoration: SMTP lines are limited to
// 998 characters and a rendered HTML template has no such limit, so an unencoded long line
// is a message some servers reject and others truncate — losing the end of the link.
func writePart(b *strings.Builder, boundary, contentType, body string) {
	b.WriteString("--")
	b.WriteString(boundary)
	b.WriteString("\r\n")
	b.WriteString("Content-Type: ")
	b.WriteString(contentType)
	b.WriteString("\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")

	writer := quotedprintable.NewWriter(b)
	_, _ = writer.Write([]byte(normaliseNewlines(body))) //nolint:errcheck // a strings.Builder does not fail
	_ = writer.Close()                                   //nolint:errcheck // likewise
	b.WriteString("\r\n")
}

// normaliseNewlines turns the template's \n into the \r\n a message needs.
func normaliseNewlines(body string) string {
	return strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")
}

// newBoundary returns a delimiter that cannot appear in the body.
//
// Random rather than fixed: a fixed boundary appearing inside a rendered template — which a
// user-controlled display name could arrange — would split the message where the sender did
// not intend.
func newBoundary() string {
	return fmt.Sprintf("warden-%s", randomToken(16))
}

// randomToken returns hex from crypto/rand. Used only for MIME boundaries here; the tokens
// that authenticate people are generated where they are stored, not in this package.
func randomToken(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand does not fail in practice, and a boundary that repeated would
		// produce a malformed message rather than an insecure one. Falling back to the
		// clock keeps a send working instead of failing on something unreachable.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw)
}
