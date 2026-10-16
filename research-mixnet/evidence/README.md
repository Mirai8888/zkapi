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

## Separate-process comparison: 2026-10-16

The [aggregate Markdown report](process-comparison/report.md) and
[JSON report](process-comparison/report.json) record eight actual trials: direct
and covered transports, each with clean traffic, synthetic provider delays,
worker-ingress loss and client disconnects. These are single runs, not a statistical
privacy evaluation. The JSON records the complete public configuration.

Each trial uses 16 client processes and a worker. Covered trials add six relay
processes, verified as distinct OS PIDs. They share one Apple Silicon macOS host
and one OS user; there are no containers, independent operators or remote hosts.
Disposable private keys are generated inside their owning peer and never serialized.
The executable was built with Go 1.27.2, CGO and `-trimpath`, without the race detector.
The race suite, vet, module verification and vulnerability scan passed separately.
New tests cover real subprocess request/reply traffic, canceled child reaping,
in-flight handler shutdown, environment isolation, invalid configuration and
attack scores that cannot use synthetic ground-truth labels as observations.

Defaults: four sequential jobs/client, 2 cells/second/client/direction, a fixed
24-second epoch, 50 ms mean relay residence, a maximum 750 ms provider delay,
2% worker-ingress loss and two clients disconnecting after eight seconds.
The fault cases change one factor at a time. Cryptographic randomness changes
between trials; the public seed does not make results byte-for-byte reproducible.
No other prototype build, test or dependency scan ran during the benchmark.
Other host activity was not controlled.

Completion is measured against all 64 planned jobs. A missing reply stops later
jobs from that client, so submitted and planned counts differ in fault cases.
Latency percentiles include completed jobs only. TCP stream counters include
HTTP but exclude packet headers, retransmissions and physical wire overhead.
Hourly client traffic extrapolates the observed fixed epoch across the configured
population, including idle periods and time after a client disconnects.

The two attacker scores are fixed nearest-event rules with a five-second search
window. Followup samples require a subsequent submitted round. They do not train
a classifier, measure long-term intersection attacks or prove anonymity. Observer
timestamps and synthetic truth are used only in supervisor memory; reports contain
aggregates. Dropped observations invalidate attack scores.

The complete Katzenpost/Pigeonhole reference was not run because its stock
identity/link key files conflict with the user's credential-file rule. See
[the inspected source and constraint](../REFERENCE.md). The measured backends
must not be described as a three-way comparison.

### Observed results and next engineering work

All eight trials finalized with zero dropped observation events. In the clean
case, direct transport completed 64/64 jobs and covered transport completed 63/64.
The covered median/p95 completed-job round trips were 1,476/4,475 ms, with
64.18 MiB/client-hour of observed TCP stream traffic. The direct control used
5.46 MiB/client-hour for this particular workload and epoch; that ratio changes
with workload, epoch and cover rate and is not a service cost estimate.

The passive rule matched 63/64 direct requests and 3/64 covered requests. The
followup rule matched 28/48 direct samples and 3/48 covered samples, against a
6.25% uniform-guess baseline. Covered provider-delay trials completed 64/64,
with the same rounded match rates. Small correlated samples and weak fixed rules
do not establish resistance to a trained, active or long-term adversary.

Loss cases completed 56/64 direct and 57/64 covered jobs. Disconnect cases
completed 64/64 direct and 63/64 covered jobs; the direct workload finished before
the scheduled disconnect. Covered loss trials also recorded seven failed sends
and five missed slots, so their result cannot be attributed to injected loss
alone. Covered disconnect trials recorded 68 failed sends and three missed slots.
Every trial had zero queue drops and worker-concurrency drops.

The clean covered run ended with 106 cells across its bounded pools, including
cover, and an unfinished job. This is evidence to investigate queue pressure,
especially random return-cover fanout whose per-client mean arrival rate equals
its send capacity. It does not identify the unfinished cell's location. Next,
evaluate cover routing and fixed bandwidth headroom, then bounded acknowledgements
and recovery on predetermined slots. Do not make retries depend directly on job
completion or loss detection. A full transport reference and stronger attacker
models remain necessary before making privacy claims.

Reproduce the full process comparison headlessly:

```sh
make compare
```

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
