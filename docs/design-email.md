# Warden — email delivery design

**Status:** Design. Nothing here is built; M1 depends on all of it.

SPEC §22 gives M1 "email delivery" in a single clause, and the four flows that need it
— verification, invitation, magic link, password reset — are each specified in §7.2
without saying how a message gets sent. This fills that gap.

The framing that matters: **for three of the four flows, the email *is* the
credential.** A magic link, a reset link and an invitation are all bearer tokens
delivered over a channel Warden does not control. That makes the delivery path part of
the authentication system rather than a notification feature bolted onto it.

---

## 1. What must be sent

| Flow | Contains | Lifetime | Single use | Spec |
| --- | --- | --- | --- | --- |
| **Email verification** | A link proving control of an address | 24 h | Yes | §7.2 |
| **Invitation** | A link to join a tenant and set a credential | 7 d | Yes | §7.2 |
| **Magic link** | A link that authenticates directly | 15 min | Yes | §7.1 |
| **Password reset** | A link to set a new password | 15 min | Yes | §7.2 |
| **Setup (bootstrap)** | The first owner's credential link | 30 min | Yes | §20.2 — *built; not yet emailed* |

Security notifications — a new sign-in, a changed password, refresh-token reuse
detected — are sent on the same path but are not credentials. They must never be
suppressed by a preference, because their purpose is to tell someone that something
happened to their account without their involvement.

## 2. The provider abstraction

```go
// Sender delivers one message. Implementations must be safe for concurrent use.
type Sender interface {
    Send(ctx context.Context, msg Message) error
    // Name identifies the backend for logs and metrics.
    Name() string
}
```

Three implementations at v1:

- **`smtp`** — the default and the only one a self-hoster needs. STARTTLS required
  unless the host is a loopback address; implicit TLS supported.
- **`stdout`** — writes the message as JSON. For development, and refused when
  `environment` is `prod` for the same reason discovery mode is (§11.5): a
  configuration that is harmless locally and catastrophic in production should not be
  reachable in production.
- **`noop`** — accepts and discards. Exists so a deployment that has deliberately
  turned email off does so explicitly, rather than by leaving SMTP misconfigured and
  discovering it when nobody can reset a password.

A webhook sender and an SES/Postmark sender are v2. The interface is deliberately
narrow so adding one is a file, not a refactor.

### Configuration

```yaml
email:
  sender: smtp                        # smtp | stdout | noop
  from: "Warden <no-reply@acme.com>"  # required unless sender is noop
  reply_to: ""                        # optional
  smtp:
    host: smtp.acme.com
    port: 587
    username: warden
    password_ref: env:WARDEN_SMTP_PASSWORD   # a secrets.Secret reference, not a literal
    tls: starttls                     # starttls | implicit | disabled (loopback only)
    timeout: 10s
```

`password_ref` follows the same `env:` / `file:` form as `security.kek`, so an SMTP
password is never a literal in a config file. `from` is validated at startup: a
malformed one fails every send, and discovering that when someone needs a password
reset is the worst possible time.

## 3. Templates

Plain text and HTML, both required. A text/plain alternative is not politeness — a
client that renders only text and receives only HTML shows a login link as markup, and
some security-conscious mail clients are exactly that.

```
internal/email/templates/
  verify_email.{txt,html}
  invitation.{txt,html}
  magic_link.{txt,html}
  password_reset.{txt,html}
  security_alert.{txt,html}
```

Embedded with `go:embed`, so a binary is self-contained (§19's single-binary story) and
a template cannot be edited on a running host without a deploy.

**Rendering rules**

- `html/template` for HTML and `text/template` for text, never the reverse. Using
  `text/template` to build HTML is how an injected display name becomes markup.
- Every interpolated value is user-controlled: display names, tenant names,
  application names. All escaped by the template engine, none by hand.
- No remote images or fonts. A tracking pixel in a password-reset email tells a
  network observer when the reset was read.
- The link is shown as a full URL in the text part, so a recipient can read where it
  goes before following it.

**Per-tenant branding** is v2. A tenant-supplied template is a template-injection
surface, and getting it wrong means one tenant rendering content into another
tenant's authentication email.

## 4. Internationalisation

English ships in v1; the framework supports more (§14.4). Templates are keyed by
`(name, locale)` with fallback to `en`. Locale comes from `user.locale`, mapped from
an IdP claim per §7.5, defaulting to the tenant's setting and then to `en`.

Deliberately excluded from v1: right-to-left layout in HTML, and per-locale `from`
display names.

## 5. Delivery, failure and retry

Sending is **asynchronous and durable**, unlike the decision log. The decision log may
drop under load because a lost record is an observability gap; a lost password-reset
email is a user who cannot get in.

```
outbound_email
  id, tenant_id, to_address, template, locale, payload jsonb,
  status: pending | sent | failed | suppressed,
  attempts int, next_attempt_at, last_error, created_at, sent_at
```

- Written in the **same transaction** as the state it describes, so a reset token and
  the intent to email it commit together. Neither can exist without the other.
- A worker (`--role=worker`) claims rows with `FOR UPDATE SKIP LOCKED`, so several
  workers can drain the queue without sending anything twice.
- Retry with exponential backoff for 24 hours: 1 m, 5 m, 15 m, 1 h, 6 h, 24 h. A 4xx
  SMTP response is permanent and is not retried; a 5xx is transient and is.
- `payload` holds what the template needs and **not the token itself**. The token is
  read from its own table at send time, so a queue row is not a second copy of a
  credential with a different retention.

## 6. Bounces and suppression

Delivering repeatedly to an address that hard-bounces gets a sending domain blocked,
and then nobody's reset arrives.

```
email_suppression
  address citext primary key, reason: hard_bounce | complaint | manual,
  suppressed_at, last_bounce_at, note
```

- A hard bounce or a spam complaint suppresses the address. Further sends are recorded
  `suppressed` rather than attempted.
- Suppression is **per deployment, not per tenant**: a bounce is a property of the
  address, and the sending reputation being protected is shared.
- The console must show it (M6). "The invitation was never delivered" is otherwise
  indistinguishable from "the user ignored it", and the two need different responses.
- Bounce ingestion needs a provider webhook. With the SMTP sender, only synchronous
  rejections are visible; asynchronous bounces arrive at the envelope-sender mailbox
  and are **not** parsed in v1. This is a real gap and should be stated in the docs
  rather than discovered.

## 7. Rate limiting and enumeration

§7.2 requires that a login, reset or invite endpoint never reveal whether an account
exists — "identical response and timing for unknown users". Email is where that
promise is most easily broken.

- **The response is identical either way.** Requesting a reset for an unknown address
  returns exactly what a known one does, and sends nothing.
- **The timing must match too.** The known path does argon2 work and a database write;
  the unknown path must not return in a fraction of that. Either do equivalent work,
  or gate both on a fixed floor.
- **Per-address limits**: at most one reset or magic link per address per 60 seconds,
  and 5 per hour. Applied on the *address*, before the account lookup, so the limit
  cannot be used to probe existence either.
- **Per-tenant send quota**, to bound the damage from a compromised service account
  used to mail thousands of addresses from a customer's own domain.
- Requests refused by any of these are recorded in the audit log, because a burst is a
  signal.

## 8. Link construction

- Rooted at `issuer`, matching `warden init`'s setup URL.
- The token is a query parameter, generated from `crypto/rand`, at least 256 bits,
  stored only as a SHA-256, and single use — `consumed_at` set in the same transaction
  that acts on it, so a replayed link fails even in a race.
- `Referrer-Policy: no-referrer` on every page the link lands on, or the token travels
  in the `Referer` header of whatever that page loads.
- Redemption invalidates every other outstanding token of the same kind for that user.
  Two live reset links is one more than anyone needs.

## 9. Observability

- `warden_email_sent_total{template,result}`, `warden_email_queue_depth`,
  `warden_email_suppressed_total{reason}`. A rising queue depth is the signal that
  delivery has stopped, and it needs to be visible before users report it.
- Every send is audited with the template, the address and the outcome — never the
  token.
- The message body is never logged. It contains a credential.

## 10. Testing

- Mailpit is already in `deploy/docker-compose.yml`; the integration tests assert
  against its API that a message was delivered, to the right address, containing a
  link that works exactly once.
- A template test renders every template in every locale with hostile inputs — a
  display name of `<script>`, one of 10 000 characters, one of RTL control characters
  — and asserts the output escapes them and stays well-formed.
- An enumeration test asserts the known and unknown paths return identical bodies and
  that their timings are within a bound of each other.

## 11. Open questions

| # | Question | Blocks |
| --- | --- | --- |
| E1 | Asynchronous bounce handling needs a provider webhook. Ship SMTP-only in v1 and accept blind sends, or require a provider that reports bounces? | M1 scope |
| E2 | Are magic links enabled by default per tenant, or opt-in? They are a full authentication factor delivered over a channel Warden does not control. | M1 |
| E3 | Should a security alert be sendable to a second, admin-configured address, so a compromised mailbox does not also swallow the warning? | M1.1 |
