# Warden — Frontend SDK design (React)

Companion to [`../SPEC.md`](../SPEC.md) §11 and §13.

> **Read this first.** Everything here is about *user experience*, not security. A hidden
> button is a hidden button, not a protected action. Every element guarded on the client must
> have a corresponding server-side check. The SDK actively helps you notice when it doesn't
> (see [Unprotected-endpoint detection](#unprotected-endpoint-detection)).

## Packages

| Package | Contents |
| --- | --- |
| `@warden/browser` | Framework-agnostic core. OIDC PKCE client, in-memory token store, silent refresh, bundle fetch/cache, batched resolution, SSE change stream. No React dependency. |
| `@warden/react` | Provider, components and hooks. Peer dep on React 18/19. |
| `@warden/vue`, `@warden/svelte`, `@warden/angular` | v2, thin wrappers on the core. |

Bundle-size budget for `@warden/react` + `@warden/browser`: **< 18 kB gzipped**, tree-shakable,
zero runtime dependencies beyond `jose` for JWT verification.

## Setup

```tsx
import { WardenProvider } from "@warden/react";

<WardenProvider
  config={{
    issuer: "https://warden.acme.com",
    clientId: "billing-web",
    application: "billing",
    environment: "prod",
    redirectUri: window.location.origin + "/callback",
    scope: "openid profile email",
    tokenStorage: "memory",          // "memory" | "bff"; localStorage is refused
    onSessionExpired: () => router.push("/login"),
  }}
>
  <App />
</WardenProvider>
```

The provider:

1. restores or starts a session (PKCE authorization code flow, or a BFF cookie session);
2. fetches the **UI bundle** for `(application, environment, subject)`;
3. opens the change stream and re-fetches the bundle on `permissions.changed`;
4. exposes everything through context.

## `<Guard>`

The single component developers need to learn.

```tsx
// 1. Permission stated in code — simple, static.
<Guard permission="billing.invoice:void">
  <VoidButton />
</Guard>

// 2. Element declared in code, permission decided by an administrator — the point of Warden.
<Guard element="invoices.approve_button">
  <ApproveButton />
</Guard>

// 3. Resource-scoped: the same element resolves differently per object.
<Guard element="invoices.approve_button" resource={{ type: "billing.invoice", id: invoice.id,
                                                     attributes: { status: invoice.status } }}>
  <ApproveButton onClick={() => approve(invoice.id)} />
</Guard>

// 4. With alternatives.
<Guard element="nav.reports" fallback={<UpgradePrompt />} loading={<Skeleton />}>
  <ReportsNav />
</Guard>

// 5. Render-prop form for full control.
<Guard element="invoices.approve_button" resource={r}>
  {({ mode, message, loading }) => (
    <Button disabled={mode !== "allow"} title={message} loading={loading}>Approve</Button>
  )}
</Guard>
```

### Props

| Prop | Type | Notes |
| --- | --- | --- |
| `element` | `string` | Element key from the manifest. Server decides the requirement. |
| `permission` | `string \| string[]` | Explicit permission(s). Used when `element` is absent, or as a fallback if the element has no binding. |
| `mode` | `"any" \| "all"` | For multiple permissions. Default `"any"`. |
| `resource` | `{type, id, attributes?}` | Required when the element is resource-scoped. |
| `fallback` | `ReactNode` | Rendered when hidden. Default: nothing. |
| `loading` | `ReactNode` | Rendered while resolving. Default: nothing (fail-closed — never flash the control). |
| `onDenied` | `(reason) => void` | Telemetry hook. |
| `children` | `ReactNode \| (state) => ReactNode` | — |

### Resolution order

`server binding for element` → `explicit permission prop` → `manifest default_mode` →
`hidden`.

### Modes

| Mode | Behaviour |
| --- | --- |
| `allow` | Children render normally. |
| `hidden` | `fallback` or nothing. |
| `disabled` | Children render inside a wrapper with `aria-disabled="true"`, `pointer-events: none` on interactive descendants, focus removed from the tab order, and `message` shown as an accessible tooltip. |
| `read_only` | Children render inside a context; form primitives from the SDK read it automatically, custom components opt in via `useGuardState()`. |

The `disabled` wrapper is a genuine accessibility surface: it must announce *why*, not merely
be inert. `message` from the binding is the announcement.

## Hooks

```tsx
const { allowed, loading } = usePermission("billing.invoice:approve",
                                           { type: "billing.invoice", id });

const { mode, message, loading } = useUIElement("invoices.approve_button",
                                                { type: "billing.invoice", id });

const { user, tenant, roles, login, logout, refresh } = useWarden();

// Bulk resolution for lists — one request for the whole table
const states = useUIElements("invoices.approve_button",
                             invoices.map(i => ({ type: "billing.invoice", id: i.id })));
```

`useWarden().user` is `null` while unauthenticated; `<Authenticated>` and `<Unauthenticated>`
components exist for the common branches.

## Batching

Resource-scoped resolutions are coalesced: every `<Guard>` that mounts within one animation
frame contributes to a single `POST /v1/ui/resolve`. A 200-row table with three guarded
buttons per row produces **one** request, not 600. Results are memoized by
`(element, resourceRef, revision)` and dropped on `permissions.changed`.

## Token handling

- Authorization code + PKCE. No implicit flow. No client secret in the browser.
- Access tokens live **in memory only**; a page reload re-authenticates silently
  (`prompt=none`) or via the BFF cookie.
- `tokenStorage: "localStorage"` is not implemented and the provider throws if it is
  configured — this is deliberate.
- **Recommended production pattern: BFF.** Your server holds the refresh token in a
  `Secure; HttpOnly; SameSite=Lax` cookie and proxies token acquisition. The SDK supports this
  with `tokenStorage: "bff"` and a `/auth/*` route contract documented in the integration
  guide.
- The UI bundle (not a credential) may be cached in `sessionStorage`, keyed by subject +
  revision, so a reload does not flash a partially-rendered UI.

## SSR / Next.js

```tsx
// app/layout.tsx (server component)
import { getWardenSession, getUIBundle } from "@warden/react/server";

const session = await getWardenSession();
const bundle = session ? await getUIBundle(session, { application: "billing" }) : null;

return <WardenProvider initialSession={session} initialBundle={bundle}>{children}</WardenProvider>;
```

The first paint is already correct — no flash of hidden-then-shown controls — and the client
skips the initial fetch. A `middleware.ts` helper gates route segments, and
`requirePermission()` is available in server actions (where it *is* a real enforcement point,
because it runs on the server).

## Discovery mode

```tsx
<WardenProvider config={{ ..., discovery: true }}>   // refused when environment === "prod"
```

Any `<Guard element="...">` whose key is unknown to the server is reported (debounced,
batched, deduplicated) with its component name and route. The console lists them under
**Undeclared elements**; one click promotes an entry to a real element and emits the
`warden.yaml` snippet to commit. This is how a developer gets from "I wrapped a component"
to "an admin can configure it" without editing YAML first.

## Unprotected-endpoint detection

The SDK tags outbound requests made from within a `<Guard>`'s subtree (opt-in, via a fetch
wrapper) with the element key. Warden correlates: an element that is guarded in the UI but
whose corresponding permission is never seen in the backend's decision stream is flagged in
the console as *"guarded in the UI, apparently unenforced on the server"*. It is a heuristic,
not a proof — but it catches the single most common and most dangerous mistake this product
invites.

## Testing

```tsx
import { WardenTestProvider } from "@warden/react/testing";

render(
  <WardenTestProvider
    user={{ id: "usr_test", roles: ["billing.viewer"] }}
    elements={{ "invoices.approve_button": { mode: "disabled", message: "No approval rights" } }}
  >
    <InvoiceDetail invoice={invoice} />
  </WardenTestProvider>
);
expect(screen.getByRole("button", { name: /approve/i })).toHaveAttribute("aria-disabled", "true");
```

No network, no tokens, deterministic. Playwright fixtures for the full login → guard flow ship
in `@warden/react/testing/e2e`.
