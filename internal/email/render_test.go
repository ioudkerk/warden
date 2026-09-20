package email_test

import (
	"strings"
	"testing"
	"time"

	"github.com/warden-project/warden/internal/email"
)

// Every template, rendered with hostile input (docs/design-email.md §10).
//
// The values interpolated into these messages are user-controlled — a display name, a tenant
// name, the name of whoever sent an invitation — and the message goes to somebody's mail
// client, which is a rendering engine with a long history of being one. The test that
// matters is not that the templates render; it is that they render *these* inputs safely.

var templates = []email.Template{
	email.TemplateMagicLink, email.TemplatePasswordReset, email.TemplateVerifyEmail,
	email.TemplateInvitation, email.TemplateSecurityAlert,
}

// TestEveryTemplateEscapesHostileInput.
//
// The `<script>` case is the one that decides whether the HTML part was built with
// html/template or with text/template. Using the text engine for HTML renders the tag
// through untouched, and the message becomes a script in the recipient's client.
func TestEveryTemplateEscapesHostileInput(t *testing.T) {
	renderer := email.NewRenderer()

	hostile := map[string]string{
		"a script tag":          `<script>alert(1)</script>`,
		"an image with onerror": `<img src=x onerror=alert(1)>`,
		"an attribute break":    `" onmouseover="alert(1)`,
		"an entity":             `&lt;script&gt;`,
		"a very long name":      strings.Repeat("A", 10000),
		"right-to-left marks":   "\u202egnitset\u202d",
		"a null byte":           "before\x00after",
	}

	for _, name := range templates {
		for what, value := range hostile {
			t.Run(string(name)+"/"+what, func(t *testing.T) {
				msg, err := renderer.Render(name, "person@example.test", email.Data{
					TenantName: value, InviterName: value, Address: value,
					Headline: value, Detail: value,
					Link:      "https://warden.example.com/link?token=abc",
					ExpiresIn: "15 minutes",
				})
				if err != nil {
					t.Fatalf("rendering: %v", err)
				}

				// The value must not appear verbatim in the HTML part when it carries
				// anything markup-significant. Searching for a fragment like "onerror="
				// would be a false positive — it appears inside the *escaped* text,
				// which is exactly the safe outcome — so the test asks the precise
				// question: did the raw value survive?
				if strings.ContainsAny(value, `<>"`) && strings.Contains(msg.HTML, value) {
					t.Fatalf("the HTML part carries a user-controlled value verbatim, so it "+
						"was built with text/template rather than html/template:\n%s",
						truncate(msg.HTML))
				}
				if msg.Text == "" || msg.HTML == "" {
					t.Fatal("a part is empty")
				}
			})
		}
	}
}

// TestTheLinkSurvivesEscaping is the other half of the same concern.
//
// A URL carries `?` and `=` and often base64 with `-` and `_`. A template that escaped them
// into entities would produce a link that looks right and goes nowhere — and it would only
// be noticed by somebody trying to use it.
func TestTheLinkSurvivesEscaping(t *testing.T) {
	renderer := email.NewRenderer()
	const link = "https://warden.example.com/login/link?token=aB-c_D1234567890"

	for _, name := range templates {
		t.Run(string(name), func(t *testing.T) {
			msg, err := renderer.Render(name, "person@example.test", email.Data{
				TenantName: "ACME", Link: link, ExpiresIn: "15 minutes",
			})
			if err != nil {
				t.Fatalf("rendering: %v", err)
			}
			if name == email.TemplateSecurityAlert {
				return // an alert carries no link
			}
			if !strings.Contains(msg.Text, link) {
				t.Fatalf("the text part does not carry the link verbatim; a recipient "+
					"cannot read where it goes before following it:\n%s", truncate(msg.Text))
			}
			// The HTML part may escape & into &amp; inside an attribute, which is
			// correct — but the token itself must survive intact.
			if !strings.Contains(msg.HTML, "aB-c_D1234567890") {
				t.Fatalf("the token did not survive HTML escaping:\n%s", truncate(msg.HTML))
			}
		})
	}
}

// TestBothPartsArePresent. A client that renders only text and is given only HTML shows the
// link as markup — and the clients configured that way are the security-conscious ones.
func TestBothPartsArePresent(t *testing.T) {
	renderer := email.NewRenderer()
	for _, name := range templates {
		msg, err := renderer.Render(name, "person@example.test", email.Data{
			TenantName: "ACME", Link: "https://warden.example.com/x", ExpiresIn: "15 minutes",
			Headline: "Something happened", Detail: "Here is what.",
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := msg.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if msg.Subject == "" {
			t.Fatalf("%s has no subject", name)
		}
	}
}

// TestNoTemplateLoadsAnythingRemote.
//
// A tracking pixel in a password-reset email tells whoever serves it when the reset was
// read, and from which network. The rule is easier to keep than to audit later, so it is
// asserted rather than documented.
func TestNoTemplateLoadsAnythingRemote(t *testing.T) {
	renderer := email.NewRenderer()
	for _, name := range templates {
		msg, err := renderer.Render(name, "person@example.test", email.Data{
			TenantName: "ACME", Link: "https://warden.example.com/x", ExpiresIn: "15 minutes",
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, forbidden := range []string{"<img", "<iframe", "@import", "<link ", "<script"} {
			if strings.Contains(strings.ToLower(msg.HTML), forbidden) {
				t.Errorf("%s contains %q; a remote resource in an authentication email "+
					"tells its host when the message was read", name, forbidden)
			}
		}
	}
}

// TestHumanDuration. The string appears in a message somebody is reading while trying to get
// into their account; Go's "15m0s" is for logs.
func TestHumanDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		15 * time.Minute:   "15 minutes",
		time.Minute:        "1 minute",
		time.Hour:          "1 hour",
		2 * time.Hour:      "2 hours",
		24 * time.Hour:     "1 day",
		7 * 24 * time.Hour: "7 days",
		30 * time.Second:   "30 seconds",
	} {
		if got := email.HumanDuration(d); got != want {
			t.Errorf("HumanDuration(%s) = %q, want %q", d, got, want)
		}
	}
}

func truncate(s string) string {
	if len(s) <= 400 {
		return s
	}
	return s[:400] + "…"
}
