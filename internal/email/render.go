package email

import (
	"embed"
	"fmt"
	"strings"
	"sync"
	"time"

	htmltemplate "html/template"
	texttemplate "text/template"
)

// Rendering (docs/design-email.md §3).
//
// Two template engines, and using the wrong one is the bug this file exists to prevent:
// `text/template` does not escape, so building HTML with it turns a display name of
// `<script>` into a script tag in somebody's mail client. Every interpolated value here is
// user-controlled — display names, tenant names, the inviter's name — so the HTML part goes
// through `html/template` and the text part through `text/template`, never the reverse.

//go:embed templates/*.txt templates/*.html
var templateFiles embed.FS

// Template names the message to render.
type Template string

const (
	TemplateMagicLink     Template = "magic_link"
	TemplatePasswordReset Template = "password_reset"
	TemplateVerifyEmail   Template = "verify_email"
	TemplateInvitation    Template = "invitation"
	TemplateSecurityAlert Template = "security_alert"
)

// subjects are fixed per template.
//
// Not rendered from tenant data, deliberately: a subject line carrying a tenant-supplied
// name is a subject line a tenant can use to make a message look like it came from
// somewhere else.
var subjects = map[Template]string{
	TemplateMagicLink:     "Your sign-in link",
	TemplatePasswordReset: "Reset your password",
	TemplateVerifyEmail:   "Confirm your email address",
	TemplateInvitation:    "You have been invited",
	TemplateSecurityAlert: "Security alert",
}

// Data is what a template may interpolate.
//
// One struct for every template rather than one per template: the set is small, the fields
// are shared, and a missing field renders as empty rather than failing a send. What it does
// not contain is a token — the link is assembled by the caller, which is the only place that
// has read one.
type Data struct {
	TenantName  string
	Address     string
	Link        string
	ExpiresIn   string
	InviterName string
	Headline    string
	Detail      string
}

// Renderer turns a template and its data into a message.
type Renderer struct {
	once sync.Once
	text map[Template]*texttemplate.Template
	html map[Template]*htmltemplate.Template
	err  error
}

// NewRenderer returns a renderer over the embedded templates.
func NewRenderer() *Renderer { return &Renderer{} }

// Render produces the message for one recipient.
func (r *Renderer) Render(name Template, to string, data Data) (Message, error) {
	r.once.Do(r.load)
	if r.err != nil {
		return Message{}, r.err
	}

	textTemplate, ok := r.text[name]
	if !ok {
		return Message{}, fmt.Errorf("no text template named %q", name)
	}
	htmlTemplate, ok := r.html[name]
	if !ok {
		return Message{}, fmt.Errorf("no HTML template named %q", name)
	}

	var text, html strings.Builder
	if err := textTemplate.Execute(&text, data); err != nil {
		return Message{}, fmt.Errorf("rendering %s.txt: %w", name, err)
	}
	if err := htmlTemplate.Execute(&html, data); err != nil {
		return Message{}, fmt.Errorf("rendering %s.html: %w", name, err)
	}

	subject, ok := subjects[name]
	if !ok {
		return Message{}, fmt.Errorf("no subject for template %q", name)
	}

	return Message{
		To: to, Subject: subject,
		Text: text.String(), HTML: html.String(),
		Template: string(name),
	}, nil
}

// load parses every embedded template once.
//
// Parsed at first use rather than at init so that a malformed template is an error a caller
// can report rather than a panic during package initialisation — but parsed for *all* of
// them together, so a broken template is found on the first send of any kind rather than on
// the first send of that one.
func (r *Renderer) load() {
	r.text = map[Template]*texttemplate.Template{}
	r.html = map[Template]*htmltemplate.Template{}

	for _, name := range []Template{
		TemplateMagicLink, TemplatePasswordReset, TemplateVerifyEmail,
		TemplateInvitation, TemplateSecurityAlert,
	} {
		textSource, err := templateFiles.ReadFile("templates/" + string(name) + ".txt")
		if err != nil {
			r.err = fmt.Errorf("reading %s.txt: %w", name, err)
			return
		}
		// Option("missingkey=error") is not set: Data is a struct, so a field that does
		// not exist is a compile-time problem rather than a run-time one.
		parsedText, err := texttemplate.New(string(name)).Parse(string(textSource))
		if err != nil {
			r.err = fmt.Errorf("parsing %s.txt: %w", name, err)
			return
		}
		r.text[name] = parsedText

		htmlSource, err := templateFiles.ReadFile("templates/" + string(name) + ".html")
		if err != nil {
			r.err = fmt.Errorf("reading %s.html: %w", name, err)
			return
		}
		parsedHTML, err := htmltemplate.New(string(name)).Parse(string(htmlSource))
		if err != nil {
			r.err = fmt.Errorf("parsing %s.html: %w", name, err)
			return
		}
		r.html[name] = parsedHTML
	}
}

// HumanDuration renders a lifetime the way a person reads one.
//
// "15 minutes" rather than "15m0s". The string appears in a message somebody is reading
// while trying to get into their account, and Go's default duration format is for logs.
func HumanDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		days := int(d.Hours() / 24)
		return plural(days, "day")
	case d >= time.Hour:
		return plural(int(d.Hours()), "hour")
	case d >= time.Minute:
		return plural(int(d.Minutes()), "minute")
	default:
		return plural(int(d.Seconds()), "second")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
