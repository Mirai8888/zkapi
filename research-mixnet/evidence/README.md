# Transport validation evidence

Only synthetic loopback experiments belong here. Never add packet captures,
prompts, wallet data, API credentials, private keys or SURB decryption material.

The checked-in aggregate baseline will record toolchain, source pins, test scope,
cell size, synthetic completion/latency, scheduled bandwidth, and aggregate
per-link slot counters. These measurements do not establish anonymity, remote
network performance, model quality, rewritten-content privacy or zkAPI safety.

## Baseline: 2026-10-16

Local Apple Silicon macOS; Go 1.27.2; CGO enabled. The measured executable was
built with `go build -o bin/research-mixnet ./cmd/research-mixnet` without the race
detector. A separate race-enabled build with `-trimpath` also passed compilation.
The binaries and ephemeral keys are not committed. Source dependencies are in
`go.mod`, `go.sum` and `source-lock.json`.

All 13 tests passed with `go test -race -count=1 ./...`. `go vet ./...` and
`go mod verify` passed. The final cancellation-accounting test adjustment also
passed independently. Tests exercise cryptographic round trips, fixed sizes and
layer transformation, wrong keys/tampered headers, SURB key erasure, delay and
pool bounds/reordering, no catch-up, no redirect/retry, literal loopback routing,
replay/cache exhaustion, malformed cells, idle bidirectional cover, multiple
clients and joined cancellation.

| Scenario | Client rate per direction | Mean residence | Synthetic completions | Round trips | Scheduled client upload + download |
| --- | --- | --- | --- | --- | --- |
| [Active](baseline-active.json), 6 seconds | 8 cells/s | 50 ms | 2/2 | 987 and 1,868 ms | 248.40 MiB/hour |
| [Idle](baseline-idle.json), 6 seconds | 8 cells/s | 50 ms | 0/0 | No jobs | 248.40 MiB/hour |
| [Lower rate](baseline-lower-rate.json), 12 seconds | 4 cells/s | 100 ms | 2/2 | 1,739 and 2,245 ms | 124.20 MiB/hour |

All three used 4,522-byte cells and two clients. They recorded zero non-cancellation
failed slots, missed clock slots and queue drops. Active/idle runs recorded five
cancellation-interrupted sends; the lower-rate run recorded four. Those are
ambiguous sends at epoch shutdown, not automatically retried transmissions.
Client upload and download cover was already flowing before any jobs.

These are two samples per active configuration, not latency percentiles or a
controlled causal comparison: the lower-rate run changes both rate and delay.
The cell budget excludes HTTP/TCP overhead; aggregate relay traffic is higher.

## Dependency scan

`govulncheck` v1.9.0, scanned on 2026-10-16 with Go 1.27.2, reported zero reachable
symbol vulnerabilities and zero vulnerabilities in imported packages. It found
one module advisory, [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), for the
unmaintained `golang.org/x/crypto/openpgp` package. This experiment does not import
that package. The module is required for other cryptographic functions; the
advisory has no fixed version. This is not a C-code audit or cryptographic audit.

Reproduce locally:

```sh
make test
make vet
make build
./bin/research-mixnet demo
./bin/research-mixnet demo --jobs 0
```
