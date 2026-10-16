# Headless research mixnet experiment

This is the first transport prototype for our private research daemon, based on
[Vitalik's zkAPI/Tor/rewriting experiment](https://x.com/VitalikButerin/status/2111046730959433793)
and his suggestion to trade bandwidth and latency for continuous cover traffic.
The fork starts at `vbuterin/zkapi` commit
`0fb263b0da04986cfe5c63b12340c1581018ae9b`.

It is a working **loopback transport experiment**, not a production anonymity
service. It runs headlessly, uses synthetic jobs, and emits aggregate JSON.

## Run

Requirements: Go 1.27.2, CGO enabled, a C compiler, and `make`. The upstream
Katzenpost algorithm registry includes C-backed dependencies even though this
experiment selects classical X25519. First builds can take several minutes.
Go module checksums remain enabled; no external services run during tests/demo.

```sh
cd research-mixnet
make test
make vet
make build
./bin/research-mixnet demo

# Same fixed schedules, with no jobs at all:
./bin/research-mixnet demo --jobs 0 --duration 6s

# Explore the latency/bandwidth tradeoff, without inference charges:
./bin/research-mixnet demo --rate 4 --mean-delay 100ms --duration 12s
```

Build dependencies download over the network. The experiment itself binds only
literal `127.0.0.1` addresses and contacts only those listeners. It accepts no
real prompts, keys or wallet profiles. It does not launch a browser or GUI.
Ctrl+C cancels the run and joins workers. Successful runs print a JSON report;
incomplete synthetic jobs return a nonzero exit status after printing the report.

## What runs

```text
client upload clocks -> mix F1 -> mix F2 -> mix F3 -> synthetic worker
client download clocks <- mix R3 <- mix R2 <- mix R1 <- worker return clock
```

Two synthetic clients share the relays by default. All edges use actual loopback
HTTP with constant-size Sphinx bodies. Each outgoing edge has its own clock,
bounded pool, and cover generator. The worker uses an opaque single-use reply
block (SURB), not a client callback URL. A fixed run duration keeps both traffic
directions active before, during and after a job.

- Unmodified [Katzenpost Sphinx](https://github.com/katzenpost/katzenpost/tree/v0.0.107/core/sphinx)
  packet and SURB implementation; pinned Go modules and checksums.
- Four-hop packet geometry: three mixes plus the worker or client terminal.
  Cover, forward work and replies have the same cell length.
- CSPRNG-selected eligible packets and capped exponential residence delays.
- Fixed scheduled send slots. Work replaces cover; it does not trigger a send.
  Expired slots are skipped. Failed sends have no retry, redirect or direct route.
- Queue, terminal-work and replay-cache bounds. Replay entries are retained for
  the whole disposable key epoch; a full cache fails closed rather than evicting.
- No plaintext, IDs, keys or per-cell timestamps in the report. Keys live in
  memory. The report contains aggregate lab diagnostics, not a production metric API.

## Read the measurements correctly

The rate is **scheduled application cells**, not a physical constant-bit-rate
link. HTTP/TCP overhead, kernel buffering, clock jitter, losses, pauses and setup
are not hidden. `missed_clock_slots` and `failed_slots` expose these limitations.
`cancellation_interrupted_slots` separates ambiguous sends interrupted by the
fixed epoch ending or cancellation; those sends are not retried either.
`successful_cells` means HTTP acceptance; the receiver deliberately does not
reveal whether a cell was invalid, replayed, dropped or accepted internally.
End-to-end synthetic reply completion is checked separately.

For cell length `C` and client rate `r`, the scheduled upload-plus-download
cell budget is `2 × C × r × 3600` bytes/hour per client, including idle periods.
The report gives this in MiB. Relay hops add more aggregate network traffic.
This is not a cap on TCP wire bytes and not a provider-cost estimate.

## Limits and next work

Every node currently runs in one process under one operator on one machine.
This demonstrates protocol plumbing, **not an anonymity set**, and does not
defeat a colluding provider and guard. There is no directory/PKI, remote link
authentication, packet-expiry protocol, persistent replay store, SURB replenishment,
delivery/retry protocol, real inference, local LLM rewriter or zkAPI integration.
Payloads are bounded to one cell. Long answers and source documents need a
reviewed fragmentation/reassembly protocol with independent response scheduling.
X25519 here is not post-quantum protection.

See [architecture and production milestones](ARCHITECTURE.md),
[candidate applications](APPLICATIONS.md), and [validation evidence](evidence/README.md).
The [prepared CI workflow](ci/README.md) needs an authorized workflow upload
before it can run on GitHub; the current credential can publish source only.
Do not connect a funded wallet to this lab. The existing native app and its
custody, Tor and funding configuration are untouched.

## Provenance and licensing

This directory's prototype source is AGPL-3.0-or-later; see [LICENSE](LICENSE).
It links Katzenpost's AGPL Sphinx implementation. Upstream `zkapi-clientd` keeps
its own MIT license. This does not apply a new license to the rest of zkapi.
Review the complete distribution's notices and licenses before packaging it.

Loopix and Echomix supply prior designs and analysis; their guarantees do not
automatically apply to this experiment:

- [The Loopix Anonymity System](https://arxiv.org/abs/1703.00536)
- [Echomix: a Strong Anonymity System with Messaging](https://arxiv.org/abs/2501.02933)
