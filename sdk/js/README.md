# JavaScript SDKs

| Package | Contents | Milestone |
| --- | --- | --- |
| `@warden/browser` | Framework-agnostic core: OIDC PKCE client, token storage, silent refresh, bundle fetching and caching, change-stream subscription, request batching. | M5 |
| `@warden/react` | `WardenProvider`, `<Guard>`, `<Authenticated>`, `usePermission`, `useUIElement`, `useWarden`. | M5 |
| `@warden/vue`, `@warden/svelte`, `@warden/angular` | Thin wrappers over the core. | v2 |

Design: [`../../docs/sdk-frontend-react.md`](../../docs/sdk-frontend-react.md).

The npm workspace is declared in the repository root `package.json`. Packages are
added here as M5 starts; the workspace exists from M0 so the Node toolchain is wired
into CI before there is anything to break.
