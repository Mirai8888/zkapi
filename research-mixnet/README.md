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

# Separate OS processes; 16 clients and four fault scenarios (~4 minutes):
make compare

# Smaller process smoke run; aggregate files only:
./bin/research-mixnet compare --clients 4 --disconnect-clients 1 \
  --jobs-per-client 2 --rate 4 --duration 12s --cases clean \
  --output-dir evidence/local-process-smoke

./bin/research-mixnet reference-check
```

Build dependencies download over the network. The experiment itself binds only
literal `127.0.0.1` addresses and contacts only those listeners. It accepts no
real prompts, keys or wallet profiles. It does not launch a browser or GUI.
Ctrl+C cancels the run and joins workers and peer subprocesses. The `demo` command
returns a nonzero status for incomplete jobs. The `compare` command records
incomplete jobs as measurements, since loss and disconnection are deliberate.
Dropped observation events invalidate that trial's attack scores.

## What runs

```text
client upload clocks -> mix F1 -> mix F2 -> mix F3 -> synthetic worker
client download clocks <- mix R3 <- mix R2 <- mix R1 <- worker return clock
```

The single-process `demo` uses two synthetic clients by default. All edges use actual loopback
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

## Separate-process comparison

`compare` runs 16 independent client processes, six relay processes and one worker
for the covered backend. The direct control uses 17 processes and the same
4,522-byte Sphinx geometry on one-hop request/reply paths, without cover or mix
delays. This controls cell framing; it is not a typical unpadded Internet request.
Every peer generates its own disposable private key in memory. Only public
directory data crosses the bootstrap pipe. Children receive a minimal environment
and do not inherit wallet profiles or application credentials.

Clients issue four sequential synthetic jobs, with 20 ms of synthetic thinking
between a reply and its followup. Initial arrivals are staggered. The fixed
24-second epoch includes idle cover after work finishes. Cases change one factor:

- `clean`: no injected faults.
- `watermark`: a synthetic provider delays each reply by 0, 375 or 750 ms.
- `loss`: seeded 2% loss at worker ingress, affecting work and cover alike.
- `disconnect`: two clients stop one-third into the epoch.

The public seed controls workload, fault selection and predefined clock phases;
packet entropy and pool selection always use the OS CSPRNG. Jobs are not retried.
A lost reply stops that client's remaining sequential jobs. The report separates
planned, submitted and completed jobs, and reports latency for completed jobs only.
Synthetic nonces change between runs, so the exact watermark pattern also changes.

Two deliberately limited attacker rules match provider receive times to the
nearest preceding client-edge full write, or provider release times to the nearest
following write. Inputs contain no client-edge job label. The supervisor joins
synthetic ground truth only to score guesses. Followup scoring includes only jobs
whose next round was actually submitted. The report includes sample counts and
the average uniform-guess baseline for the connected population. These are fixed,
untrained heuristics with a five-second search window, not a comprehensive
colluding provider/guard attack. Raw observations remain in memory.

Reports contain actual TCP stream read/write counters, including HTTP. They omit
TCP/IP headers, retransmission and physical wire overhead. Per-link pending cells,
rejected cells, failed slots and missed slots help explain availability limits.
Single runs have small, correlated samples and do not establish anonymity.

The complete Katzenpost reference is **not run**: its pinned stock generator and
server persist identity/link private keys, conflicting with the instruction to
keep credentials out of files. `reference-check` reports that constraint; it does
not fabricate a third backend. See [reference assessment](REFERENCE.md).

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

The demo uses one process; the comparison uses separate address spaces under one
OS user on one machine. Those processes are not a sandbox or independent operators.
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
