# ADR-0001 — Server implementation language

**Status:** Proposed (needs the user's decision — SPEC §23 Q1)
**Date:** 2026-08-21

## Context

The Warden server does two very different jobs: identity flows (moderate volume, protocol
heavy, IO bound) and authorization decisions (very high volume, latency sensitive, CPU and
cache bound). The stated SDK order is Python → Node → Go, which says nothing about the
server, and the team's existing expertise is unknown.

## Options

### A. Go
- Single static binary; the self-host story is `docker run` or one file on a VM.
- Goroutine-per-request handles the decision fan-out cheaply; predictable latency, low
  memory per connection.
- `cel-go` is the reference CEL implementation — the condition language is native.
- Mature `crewjam/saml`, `go-oidc`, `ory/fosite` ecosystem.
- Cost: a Python-first team pays a learning tax on the largest codebase in the project.

### B. Python (FastAPI + SQLAlchemy)
- Matches the first SDK's language and, plausibly, the team's.
- Fastest path to a working M1/M2.
- Cost: the PDP hot path needs roughly 3–5× the hardware for the §18 targets; the
  single-binary distribution story is replaced by "a container plus a WSGI/ASGI server";
  `cel-python` is less mature than `cel-go`.

### C. Rust
- Best latency and lowest resource use.
- Cost: slowest to build, smallest hiring pool, SAML/OIDC library ecosystem is the weakest
  of the three.

## Decision

**Recommend A (Go)**, because the product's differentiator is a low-latency decision service
that other teams depend on, and because self-hostability is a stated goal that a single
binary serves better than anything else.

Escape hatch: if the team is Python-only and time-to-first-customer dominates, B is viable
for 1.0 provided the decision endpoints are isolated behind their own service boundary
(`--role=pdp`) so they can be rewritten in Go later without touching callers. The SDK
contract and the conformance corpus make that rewrite mechanical.

## Consequences

- If Go: the console and SDKs stay TypeScript/Python; contributors need two toolchains.
- If Python: budget capacity per §18 accordingly and keep the PDP module dependency-light.
- Either way, the **conformance corpus** (SPEC §21) is written first and is language-neutral,
  so this decision is reversible at a known cost.
