# Benchmarks

k6 scenarios for the targets in SPEC §18, run in CI on every release with regression
gates (task M8).

The numbers that matter most:

| Metric | Target |
| --- | --- |
| `check` p99, SDK cache hit | < 200 µs |
| `check` p99, PDP round trip, same region | < 10 ms |
| `batch-check` of 100, p99 | < 25 ms |
| Throughput per PDP instance | ≥ 5 000 checks/s |
| Change propagation to SDK caches, p95 | < 1 s |

A regression here is a product regression: the PDP sits in the request path of every
application that trusts it.
