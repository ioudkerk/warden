# ADR-0002 — Permissions in tokens vs. runtime decisions

**Status:** Accepted
**Date:** 2026-08-21

## Context

An application needs to know what a user may do. There are two families of answers: put the
answer in the access token, or ask a decision service at the moment of the action.

## Options

### A. Fat tokens — embed the full permission set
- Zero latency, zero coupling, works when Warden is down.
- Breaks on size: a user with resource-scoped grants across thousands of objects cannot be
  encoded. Header limits (typically 8 KB) are reached quickly.
- Breaks on revocation: a revoked role stays effective until the token expires.
- Cannot express conditions that depend on the resource being acted upon.

### B. Thin tokens + PDP calls
- Correct and revocable; resource-scoped and conditional decisions become possible.
- Adds a network hop to the hot path and a hard dependency on Warden's availability.

### C. Hybrid (chosen)
- The token carries identity, session, tenant-wide **roles**, a small allowlist of subject
  attributes, and a **permission revision counter**.
- Fine-grained and resource-scoped decisions come from the PDP.
- The SDK caches decisions with a server-supplied TTL and drops them on change-stream events,
  so the steady-state cost is an in-process map lookup.
- A high-volume application may opt into `embedded` mode: pull a signed policy bundle and
  evaluate locally with the same CEL semantics, verified by a shared conformance corpus.

## Decision

**C.** Coarse context in the token, fine decisions from the PDP, aggressive but invalidatable
caching in the SDK, and an embedded escape hatch for extreme volume.

## Consequences

- Tokens stay small (hard cap 4 KB) and short-lived (10 min default).
- Revocation is fast: change stream p95 < 1 s, bounded by token lifetime in the worst case.
- Warden availability becomes a production dependency for its consumers. Mitigated by the
  per-application `fail_mode` (`closed` / `open_read` / `stale`), by SDK circuit breakers, and
  by making the PDP a horizontally scalable, read-replica-backed, stateless tier.
- The SDK cache is now a correctness-relevant component and must be tested as such: cache
  keys include the resource attribute hash and the tenant revision.
