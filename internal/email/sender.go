package email

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"sync"
	"time"

	"github.com/warden-project/warden/internal/config"
	"github.com/warden-project/warden/internal/secrets"
)

// The three senders of docs/design-email.md §2. The interface is deliberately narrow so
// that adding a webhook or a provider API in v2 is a file rather than a refactor.

// NewSender builds the sender the configuration names.
func NewSender(cfg *config.Config, lookupEnv secrets.LookupEnvFunc, readFile secrets.ReadFileFunc, log *slog.Logger) (Sender, error) {
	if log == nil {
		log = slog.Default()
	}
	switch cfg.Email.Sender {
	case config.EmailNoop:
		return &NoopSender{log: log}, nil
	case config.EmailStdout:
		return &StdoutSender{out: nil, log: log}, nil
	case config.EmailSMTP:
		password := ""
		if !cfg.Email.SMTP.Password.IsZero() {
			resolved, err := secrets.ResolveReference(cfg.Email.SMTP.Password.Expose(), lookupEnv, readFile)
			if err != nil {
				return nil, fmt.Errorf("email.smtp.password_ref: %w", err)
			}
			password = resolved.Expose()
		}
		return &SMTPSender{
			addr:     net.JoinHostPort(cfg.Email.SMTP.Host, fmt.Sprint(cfg.Email.SMTP.Port)),
			host:     cfg.Email.SMTP.Host,
			username: cfg.Email.SMTP.Username,
			password: password,
			tlsMode:  cfg.Email.SMTP.TLS,
			timeout:  cfg.Email.SMTP.Timeout,
			from:     cfg.Email.From,
			replyTo:  cfg.Email.ReplyTo,
			log:      log,
		}, nil
	default:
		return nil, fmt.Errorf("unknown email sender %q", cfg.Email.Sender)
	}
}

// --- noop --------------------------------------------------------------------------------

// NoopSender accepts and discards.
//
// It exists so that "this deployment does not send email" is a decision somebody made
// rather than a misconfiguration nobody noticed until a password reset was needed.
type NoopSender struct{ log *slog.Logger }

func (s *NoopSender) Name() string { return "noop" }

func (s *NoopSender) Send(_ context.Context, msg Message) error {
	// Logged at info, not debug: a deployment discarding authentication emails should
	// say so in its ordinary output, because the symptom otherwise is a user who never
	// receives anything and an operator with nothing to look at.
	s.log.Info("email discarded: the sender is noop",
		"template", msg.Template, "to", redactAddress(msg.To))
	return nil
}

// --- stdout ------------------------------------------------------------------------------

// StdoutSender writes the message as JSON, body included.
//
// For development, and refused in production by configuration validation: this is the one
// sender that deliberately puts a credential in the log.
type StdoutSender struct {
	out io.Writer
	mu  sync.Mutex
	log *slog.Logger
}

// NewStdoutSender writes to the given writer. Used by tests; production builds this through
// NewSender, which writes to standard output.
func NewStdoutSender(out io.Writer, log *slog.Logger) *StdoutSender {
	if log == nil {
		log = slog.Default()
	}
	return &StdoutSender{out: out, log: log}
}

func (s *StdoutSender) Name() string { return "stdout" }

func (s *StdoutSender) Send(_ context.Context, msg Message) error {
	encoded, err := json.MarshalIndent(map[string]any{
		"to": msg.To, "subject": msg.Subject, "template": msg.Template,
		"text": msg.Text, "html": msg.HTML,
	}, "", "  ")
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.out
	if out == nil {
		out = stdoutWriter
	}
	if _, err := fmt.Fprintf(out, "%s\n", encoded); err != nil {
		return err
	}
	return nil
}

// --- smtp --------------------------------------------------------------------------------

// SMTPSender is the default and the only backend a self-hoster needs.
type SMTPSender struct {
	addr     string
	host     string
	username string
	password string
	tlsMode  config.SMTPTLS
	timeout  time.Duration
	from     string
	replyTo  string
	log      *slog.Logger
}

func (s *SMTPSender) Name() string { return "smtp" }

// Send delivers one message over SMTP.
//
// Written against net/smtp rather than a mail library, and the reason is the same one that
// governs the rest of this codebase: what is needed here is a MIME multipart body and a
// session, both of which are short, and the alternative is a dependency whose transitive
// tree has to be audited for a binary that handles credentials.
func (s *SMTPSender) Send(ctx context.Context, msg Message) error {
	if err := msg.Validate(); err != nil {
		// A message that cannot be addressed will not become addressable on a retry.
		return Permanent(err)
	}

	client, err := s.dial(ctx)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", s.addr, err)
	}
	defer func() {
		if quitErr := client.Quit(); quitErr != nil {
			_ = client.Close()
		}
	}()

	if authErr := s.authenticate(client); authErr != nil {
		return authErr
	}

	fromAddress, err := addressOf(s.from)
	if err != nil {
		return Permanent(err)
	}
	toAddress, err := addressOf(msg.To)
	if err != nil {
		return Permanent(err)
	}

	if mailErr := client.Mail(fromAddress); mailErr != nil {
		return classifySMTP(mailErr)
	}
	if rcptErr := client.Rcpt(toAddress); rcptErr != nil {
		// A rejected recipient is where a bad address shows up, and it is the one
		// failure worth never retrying: repeating it is how a sending domain gets
		// blocked for everybody.
		return classifySMTP(rcptErr)
	}

	writer, err := client.Data()
	if err != nil {
		return classifySMTP(err)
	}
	if _, err := writer.Write(s.render(msg)); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return classifySMTP(err)
	}
	return nil
}

// dial opens the session, with the protection the configuration asks for.
func (s *SMTPSender) dial(ctx context.Context) (*smtp.Client, error) {
	dialer := &net.Dialer{Timeout: s.timeout}

	if s.tlsMode == config.SMTPImplicit {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12},
		}
		conn, err := tlsDialer.DialContext(ctx, "tcp", s.addr)
		if err != nil {
			return nil, err
		}
		return smtp.NewClient(conn, s.host)
	}

	conn, err := dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, err
	}
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if s.tlsMode == config.SMTPStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok { //nolint:errcheck // the bool is the answer
			_ = client.Close()
			// Not a downgrade: the configuration asked for STARTTLS, and continuing in
			// the clear would deliver a credential over a connection somebody else may
			// be on.
			return nil, errors.New(
				"the SMTP server does not offer STARTTLS, and this deployment requires it")
		}
		if err := client.StartTLS(&tls.Config{
			ServerName: s.host, MinVersion: tls.VersionTLS12,
		}); err != nil {
			_ = client.Close()
			return nil, err
		}
	}
	return client, nil
}

// authenticate logs in when credentials were configured.
func (s *SMTPSender) authenticate(client *smtp.Client) error {
	if s.username == "" {
		return nil
	}
	ok, _ := client.Extension("AUTH") //nolint:errcheck // the bool is the answer
	if !ok {
		return errors.New("the SMTP server offers no AUTH extension but a username was configured")
	}
	if err := client.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
		// Wrong credentials will be wrong again in an hour.
		return Permanent(fmt.Errorf("SMTP authentication failed: %w", err))
	}
	return nil
}

// classifySMTP decides whether a failure is worth retrying.
//
// RFC 5321 splits replies at the first digit: 4xx is transient and 5xx is permanent. Getting
// this backwards is expensive in both directions — retrying a permanent rejection for a day
// harms the sending reputation, and giving up on a transient one loses somebody's password
// reset.
func classifySMTP(err error) error {
	var smtpErr *textprotoError
	if errors.As(err, &smtpErr) && smtpErr.Code >= 500 && smtpErr.Code < 600 {
		return Permanent(err)
	}
	if code := leadingCode(err); code >= 500 && code < 600 {
		return Permanent(err)
	}
	return err
}

// leadingCode reads a reply code out of an error string, for the errors net/smtp returns as
// plain text rather than as a typed value.
func leadingCode(err error) int {
	text := err.Error()
	if len(text) < 3 {
		return 0
	}
	code := 0
	for i := range 3 {
		digit := text[i]
		if digit < '0' || digit > '9' {
			return 0
		}
		code = code*10 + int(digit-'0')
	}
	return code
}

// addressOf extracts the bare address from a "Name <addr>" form.
//
// The envelope carries the address alone; the display name belongs in the header. Sending
// the whole string as an envelope recipient is rejected by some servers and silently
// mangled by others.
func addressOf(value string) (string, error) {
	parsed, err := mail.ParseAddress(value)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid address: %w", value, err)
	}
	return parsed.Address, nil
}

// stdoutWriter is where StdoutSender writes when it was not given a writer. A variable so
// that a test can replace it without the sender reaching for os.Stdout directly.
var stdoutWriter io.Writer = os.Stdout

// textprotoError mirrors net/textproto.Error without importing it into every call site.
type textprotoError struct {
	Code int
	Msg  string
}

func (e *textprotoError) Error() string { return fmt.Sprintf("%d %s", e.Code, e.Msg) }
