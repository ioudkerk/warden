# ADR-0001 — Server implementation language

**Status:** Accepted
**Date:** 2026-08-21 (proposed) / 2026-08-31 (accepted)

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

**A (Go)**, ratified 2026-08-31. The product's differentiator is a low-latency decision
service that other teams depend on, and self-hostability is a stated goal that a single
static binary serves better than anything else. Option B was considered and rejected: the
§18 targets would cost 3–5× the hardware and the single-binary story is the self-host
story.

The reversal path survives regardless. The decision endpoints stay behind their own service
boundary (`--role=pdp`), and the **conformance corpus** (SPEC §21) is language-neutral and
written before the PDP, so a port in either direction is mechanical rather than a rewrite of
semantics.

## Consequences

- The console and SDKs stay TypeScript/Python, so contributors need three toolchains (Go,
  Node, Python). CI must set all three up and the contributor docs must say so.
- Go 1.23+, `golang-migrate` for schema, `cel-go` for conditions, `ory/fosite` for the OIDC
  OP, `crewjam/saml` for the SAML SP. Each is pinned in `go.mod` at M0.
- Distribution is a single static binary plus a distroless container image (SPEC §19).
- The conformance corpus is written first and is language-neutral, so this decision stays
  reversible at a known cost.
