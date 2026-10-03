# Operating the v2 escape challenge service

`zkapi-challenged` is the repository's event-to-submission implementation. It
polls `EscapeWithdrawalInitiated`, looks up the escaped nullifier in the API
server's database, and challenges only when the server holds a finalized
request transcript for it. It rebuilds the archived v2 request and its 256-byte
Groth16 proof, obtains a current zero-slot Merkle path, simulates the vault
call, and submits `challengeEscapeWithdrawal` as an EIP-1559 transaction whose
fees rise as the deadline approaches. It never signs a balance or changes usage
accounting.

Build and run it separately from the API server:

```sh
cargo build --release -p zkapi-serverd --bin zkapi-challenged
RUST_LOG=info target/release/zkapi-challenged \
  --rpc-url "$OPERATOR_SIGNER_RPC_URL" \
  --indexer-url http://127.0.0.1:3001 \
  --sender "$DEDICATED_CHALLENGE_ACCOUNT" \
  --chain-id "$CHAIN_ID" \
  --contract-address "$VAULT_ADDRESS" \
  --from-block "$VAULT_DEPLOYMENT_BLOCK" \
  --db-path /var/lib/zkapi/server.db \
  --checkpoint /var/lib/zkapi/challenges.json \
  --proof-setup-dir /var/lib/zkapi/setup/v2 \
  --confirmations 2 \
  --max-fee-per-gas-wei 100000000000 \
  --max-priority-fee-per-gas-wei 10000000000 \
  --status-listen 127.0.0.1:3002
```

All deployment and signer settings are explicit. The RPC must implement
`eth_sendTransaction` using an operator-controlled signer for the dedicated,
funded sender address. A public read-only RPC is insufficient. Configure signing
permissions at that RPC; do not expose an unlocked account over a public RPC.
Use one service and one exclusive sender per deployment. The daemon locks
`<checkpoint>.lock` (`challenges.lock` above) so two instances cannot share a
checkpoint.

| Flag | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--rpc-url` | `ZKAPI_CHALLENGE_RPC_URL` | required | Signer RPC for `--sender`. |
| `--indexer-url` | `ZKAPI_CHALLENGE_INDEXER_URL` | required | The deployment's indexer. |
| `--sender` | `ZKAPI_CHALLENGE_SENDER` | required | Dedicated gas-paying account. |
| `--chain-id`, `--contract-address`, `--from-block` | | required | The deployment. Never start `--from-block` at the current head. |
| `--confirmations` | | 2 | Depth for scanning events and for retiring obligations. |
| `--db-path` | | required | The API server's database, opened read-only. |
| `--checkpoint`, `--proof-setup-dir` | | required | Durable state; the deployment's proof setup. |
| `--max-fee-per-gas-wei` | `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` | required | Highest `maxFeePerGas` the daemon proposes; at most the signer's fee cap. |
| `--max-priority-fee-per-gas-wei` | `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI` | required | Highest tip; at most the signer's tip cap and `--max-fee-per-gas-wei`, at least twice `--priority-fee-per-gas-wei`. |
| `--priority-fee-per-gas-wei` | `ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI` | 2 gwei | Tip of a first attempt. |
| `--fee-bump-after-blocks`, `--fee-bump-percent` | | 3, 25 | Replacement pace and fee-cap step (10 to 100 percent). |
| `--status-listen` | `ZKAPI_CHALLENGE_STATUS_LISTEN` | `127.0.0.1:3002` | Internal `/livez`, `/health` and `/status`. Never publish it. |
| `--warning-remaining-seconds`, `--critical-remaining-seconds` | | `challengePeriod()` / 2, / 4 | Deadline escalation thresholds. |
| `--blocked-warning-seconds`, `--critical-blocked-seconds` | | 120, 1800 | Escalation of a blocked obligation. |
| `--settlement-overdue-seconds` | | 3600 | Warning when a reserved request's settlement is this late. |
| `--indexer-divergence-seconds`, `--indexer-divergence-polls`, `--indexer-lag-warning-blocks` | | 600, 3, 64 | Divergence heuristic for indexers without block metadata; lag warning. |
| `--stale-poll-seconds`, `--startup-grace-seconds` | | 300, 300 | Liveness and first-poll grace. |
| `--observe-interval-seconds` | | 15 | Sender balance and indexer root observations. |
| `--min-sender-balance-wei` | | 7.6M gas x `--max-fee-per-gas-wei` | Balance warning threshold. |

For the AWS deployment, [the bounded signer sidecar](../docker/aws/signer/README.md)
provides the signer RPC on a private container network, and
[the Docker guide](../docker/aws/README.md) passes these settings. The sidecar
requires an explicit `ZKAPI_CHALLENGE_CHAIN_ID` of 1 (Mainnet) or 11155111
(Sepolia), accepts only zero-value challenge calls for that chain and vault,
checks the full ABI and a live simulation, and preserves the daemon's nonce. It
signs EIP-1559 (type 2) transactions with the fees the daemon proposes, within
its own fee and tip caps, and refuses with a structured reason
(`fee_out_of_bounds`, `base_fee_above_max_fee`, `insufficient_balance`) before
anything is broadcast. Its dedicated private key belongs only in the signer's
environment. Keep its port unpublished; the public API reverse proxy must never
route to it.

The server, browser/client proving keys, verifier, and daemon must all use the
same deployment and circuit setup. The circuit identifier is
`zkapi-v2-note-bound-v1`. The key loader requires this circuit header. The
vault's immutable verifier must match the selected keys. The archived request
root is intentionally preserved while the restoration path uses the current root.

## Database access and startup

The daemon opens `--db-path` read-only and never writes to it. It requires the
`deployment_binding` row that the API server records after checking its signing
keys against the vault. At startup it checks that the row names its chain and
vault, then reads the vault's `stateSigningKeyX()` and `stateSigningKeyY()`
(after an `eth_chainId` check) and requires them to equal the recorded state
key. A missing row, another deployment or a different key exits non-zero: start
the upgraded API server on this database first, and give every deployment its
own database. An unreachable RPC is retried every 5 seconds without polling, and
`/status` shows `deployment binding not verified` meanwhile. A database whose
schema predates the reader is refused with `server database schema is older
than this reader; upgrade and start the API server first`. If the API server
crashed in the middle of a write, evidence reads can fail (`evidence_db_error`)
until the API server restarts and recovers the database.

## Challenge evidence

Only a finalized transcript is evidence: a `Finalized` nullifier record whose
archived proof is exactly 256 bytes and whose archived request inputs carry the
escaped nullifier. A transcript that charged zero is evidence too. A request
that is still reserved, including an issued lease that is active, retiring,
disabled or revoking, is `awaiting_settlement`: the daemon challenges it only
after the API server finalizes it. Lease rows are read for status only and
never build calldata.

The API server bounds that wait. Every lease has a write-once settlement
deadline, issuance + TTL + grace + `--openrouter-settlement-deadline-seconds`
(default 21600). A lease that may have been delivered is finalized by then at
its measured usage or, failing that, at its proof's solvency bound; a lease
that was never delivered is finalized at zero. The server refuses to start
unless TTL + grace + deadline + twice the settlement poll + 600 seconds fits in
half of `challengePeriod()`, which leaves the other half for the challenge. See
[settlement terminality](native-eth-billing.md#settlement-terminality).

Other cases:

- An escape whose nullifier has no record, or only a withdrawal clearance, is an
  honest exit (`no_evidence`). It is tracked and never alerts.
- A reservation without a lease row (issuance never completed) or with a
  `cancelled` lease (a corrupt binding the server never signs) never yields
  evidence. It is a warning, and at the deadline it becomes
  `expired_without_evidence`, not missed.
- A finalized record with a missing or malformed proof or inputs is
  `evidence_invalid`, and a database read failure is `evidence_db_error`. Both
  are critical at once; neither is ever treated as "no evidence".

An escape made at an anchor whose request was finalized, even at zero charge, is
challenged. Owners exit from the signed successor state, which they recover from
the API server.

A successful challenge on a hardened vault clears `usedNullifiers` for that
nullifier and sets `challengedNullifiers` for it. An escape with that nullifier
can never be submitted again (`ChallengedNullifier()`), so no second challenge
is needed, while a mutual close with a server clearance still accepts it. On a
vault deployed before this release the challenge leaves the nullifier consumed.

## Building and sending a challenge

Each poll verifies the RPC chain ID. Before sending, the daemon checks the
on-chain pending withdrawal and its deadline, the archived proof and its
deployment binding (its state key must be the vault's), the indexer's current
zero-slot path against the vault root, and the complete call with `eth_call`. It
does not rewrite a historical public root. The gas limit is the estimate plus
20%.

Every send carries both `maxFeePerGas` and `maxPriorityFeePerGas`, so the daemon
needs a signer that accepts them (the bundled signer from this release). The
first bid is the lower of the fee cap and twice the base fee plus the priority
fee. The pending challenge at the head of the sender's queue is replaced on the
same nonce when it is not mined after `--fee-bump-after-blocks`, when the base
fee rises above its fee cap, when it or a challenge queued behind it becomes
critical, or when the vault root moved since it was built (the replacement then
carries fresh siblings). A replacement raises the tip by 10% (rounded up) and
the fee cap by `--fee-bump-percent`, and at least to twice the base fee plus the
tip; geth and reth accept a replacement only when both rise by at least 10%.
Critical obligations bid 10/11 of both caps first, keeping room for one more
replacement, then the caps themselves. Fees on a nonce never decrease. The note,
request inputs and proof are fixed per nonce (a persisted digest is compared on
every send); only siblings, gas and fees may change.

When no valid bid remains, the obligation reports `base_fee_above_fee_cap`
(nothing is sent while the base fee exceeds the daemon's fee cap),
`fee_cap_reached`, `tip_cap_reached` or `insufficient_balance` (the fee cap is
also limited to balance / gas). Raise the signer's caps in `signer.env` and
restart the signer first, then raise the daemon's caps (never above the
signer's) and restart the daemon; it then replaces its pending challenge. Fund
the sender for every challenge that may be pending at once plus reverted
attempts: about 7.6M gas x fee cap each. Status warns when the balance cannot
cover the outstanding obligations at the proposed fee cap, or is below
`--min-sender-balance-wei`. There is no spending budget beyond the
per-transaction caps and the sender balance. The
[signer README](../docker/aws/signer/README.md#fee-spike-runbook) has the fee
spike runbook.

Signer errors other than `broadcast_ambiguous` mean nothing was broadcast. A
`broadcast_ambiguous` error carries the candidate transaction hash, which the
daemon keeps. A transport error or a timeout (the send waits up to 95 seconds)
is treated as possibly broadcast: the next send on that nonce must outbid the
highest fees that may be in a pool, by at least 10% on both, and is paced like a
replacement. Definitive refusals roll the attempt back, and the nonce is
released only when no attempt on it can be in a pool.

A challenge reverts `StaleRoot()` (`0x607447de`) when an unrelated deposit,
close or expiry claim changes the vault root after the simulation: the vault
restores the leaf against the live root, and it verifies the proof first, so
the reverted transaction still pays most of its gas. The daemon rebuilds the
zero-path and replaces or resends within the deadline. Anyone can cause such a
race at their own gas cost, so fund the sender for reverted attempts.
`NotPendingWithdrawal()` and `ReplayedNullifier()` mean the withdrawal was
already resolved (`resolved_unconfirmed`, checked again next poll), and
`UnknownRoot()`, `ChallengeExpired()` and `ChallengedNullifier()` are reported
as `simulation_reverted`. The bundled signer does not forward revert data from
its simulation, so through it these all appear as transient simulation
failures and are retried.

Private or MEV-protection relays may hide pending transactions from
`eth_getTransactionByHash` and may delay, refuse or drop same-nonce
replacements. The daemon then sees nonces as held by unknown attempts and keeps
re-bidding at the replacement pace. Prefer a full-node RPC, and verify a relay's
pending visibility and replacement behaviour on Sepolia first.

## Recovery and verification

The checkpoint records the deployment and sender, next scan block, block hash,
pending nullifiers and deadlines, reserved transaction nonces, every candidate
transaction hash with the highest fees that may be in a pool, the evidence
digest, and the missed-deadline count. It is written before each send, with
atomic replacement after syncing the file. Older checkpoints load unchanged;
older binaries ignore the new fields. Never delete it: it holds reserved nonces.
The service refuses checkpoints from another chain, vault or starting block.
Scans are bounded to 1,000 blocks. A changed checkpoint block hash causes replay
from the deployment block; pending entries are reconciled against the current
vault state before submission.

Returned transaction hashes suppress duplicate submissions while the RPC still
knows the unmined transaction; confirmed nonce consumption allows an outstanding
withdrawal to refresh its path and retry. Dropped or orphaned transactions are
resubmitted on their reserved nonce once the RPC no longer knows their hashes.
Ambiguous send errors retain the nonce across restart. Successful challenges are
retired only after the pending withdrawal also disappears at the configured
confirmation depth, preventing a tip reorg from silently losing the obligation.

Nonce reconciliation runs before checking a withdrawal's deadline, evidence or
continued existence. A reserved nonce consumed in the latest block no longer
blocks other notes, even when the original send returned no hash and its
challenge has expired. Its ownership remains in the checkpoint until consumption
reaches the configured confirmation depth; a tip reorg therefore cannot silently
forget the reservation. A reverted transaction is eligible for a fresh nonce
after that confirmation depth. If a withdrawal disappears or a replayed event
replaces its nullifier, the checkpoint retains its outstanding nonce separately
until confirmed consumption.

An **unmined** nonce whose withdrawal has expired or been replaced still
prevents new allocations, because the original signed transaction may still be
pending. It is reported as critical: the operator must resolve the existing
transaction at that nonce outside the sidecar. The daemon does not reuse the
nonce for another note or send a cancellation. This restriction is distinct
from an expired obligation whose nonce has already mined; that obligation
cannot starve the remaining queue. The bounded signer does not expose general
cancellation calls.

## Escape completeness

The event scan can miss an escape when the RPC's `eth_getLogs` lags its head.
Every poll therefore also reads the indexer's internal
`GET /v1/escapes/pending` list. An escape on that list but missing from the
checkpoint is added once the vault's `pendingWithdrawals(noteId)` confirms it;
the nullifier and deadline come from the vault, not the indexer. At most 64 such
checks run per poll. An indexer without the endpoint shows a permanent
`unsupported` warning, and an unavailable list warns after
`--blocked-warning-seconds`.

## Status, health and alerting

The status listener serves three internal routes, all with
`Cache-Control: no-store`:

- `GET /livez`: 200 `{"status":"alive"}` while the poll loop started or finished
  an iteration within `--stale-poll-seconds`, or within `--startup-grace-seconds`
  of start; otherwise 503 `{"status":"stale"}`. Use it for container
  healthchecks only.
- `GET /health`: 503 when anything is critical, otherwise 200 (`ok` or
  `warning`), with `{status, generated_at, poll_age_seconds, obligations,
  critical_obligations, alarms}`. Alert on it.
- `GET /status`: the full snapshot, schema `zkapi-challenged-status/v1`: overall
  `status` and `alarms`, the thresholds in force, chain head and scan progress,
  poll timing, sender balance and nonces, indexer state, every obligation,
  detached nonces, `missed_total` and `last_missed`. Wei values are decimal
  strings. It contains no client request IDs.

Remaining time and severity are recomputed at request time from the absolute
deadlines and the latest block timestamp, so escalation continues while polls
stall. Each obligation has a `state`: `unevaluated`, `no_evidence`,
`awaiting_settlement`, `ready`, `submitted`, `mined_unconfirmed`,
`resolved_unconfirmed`, `missed` or `expired_without_evidence`. Its `severity`
is:

- critical for `missed`;
- for obligations with evidence, or expected evidence, by remaining time:
  warning within `--warning-remaining-seconds`, critical within
  `--critical-remaining-seconds`;
- critical at once when blocked by `evidence_invalid`, `evidence_db_error`,
  `indexer_invalid_response`, `indexer_diverged` or `signer_refused`; other
  blocked reasons (`indexer_unavailable`, `indexer_path_behind`, `rpc_error`,
  `simulation_reverted`, `send_ambiguous`, `base_fee_above_fee_cap`,
  `fee_cap_reached`, `tip_cap_reached`, `insufficient_balance`,
  `nonce_conflict`, `nonce_blocked`) warn after `--blocked-warning-seconds` and
  turn critical after `--critical-blocked-seconds`;
- for `awaiting_settlement`, a warning once settlement is
  `--settlement-overdue-seconds` late, and critical at once when the lease is
  not due to finalize before the critical threshold.

Stale polls, no successful poll after the startup grace, no new head block for
600 seconds, an event scan 300 blocks behind, a diverged indexer and an unmined
detached nonce are also critical. State changes are logged as `challenge
obligation status changed` at info, warn or error level, and critical items are
logged again every 300 seconds. A deadline that passes while evidence existed or
was expected logs `MISSED escape challenge deadline` once and increments
`missed_total`. The window cannot be extended: page a human at the warning
threshold.

Never route the status listener through a public proxy; it tells an attacker
when challenges are blocked.

## Indexer divergence

A diverged indexer serves Merkle paths that do not match the vault, so no
challenge can be built from them, and deposits and withdrawals fail too. The
daemon compares the indexer's `/v1/tree/root` with the vault's `currentRoot()`.
When the indexer reports a block hash, it reads `currentRoot()` at that block
(EIP-1898): equal roots mean the indexer is only lagging, different roots mean
it diverged. Older indexers without block metadata fall back to a heuristic: a
mismatch lasting `--indexer-divergence-seconds` over
`--indexer-divergence-polls` polls. An indexer `/health` status of `diverged`
also counts. Divergence is critical and logs
`indexer mirror diverged from vault currentRoot; challenges cannot be built until the indexer is resynced`.

Symptoms: indexer `/health` 503 with `diverged`, or `syncing`, `stale` or
`rebuilding` for longer than a replay takes; obligations blocked by
`indexer_diverged` or, persistently, `indexer_path_behind`; clients failing with
`indexer_root_lag` or vault reverts `StaleRoot()`. Waiting never repairs a
divergence. Compare the indexer's root with the vault through an independent
RPC, then resync it as described in
[the Docker guide](../docker/aws/README.md#indexer-resync). A replay takes
about (head − deployment block) / 1000 log requests at 100 ms each plus
verification; start it well before the nearest challenge deadline.

## Availability

Keep the API server, indexer, database, checkpoint, signer and sender funding
available throughout every challenge window. The API server's settlement writes
the finalized transcripts that are the only evidence, so an outage of its
settler delays evidence; include API downtime in the challenge-period budget.
The API's `GET /v2/nullifiers/{nullifier}` and `GET /v2/requests/{id}` are also
how an owner recovers the signed successor state after a challenge, and the
browser SDK consults them before discarding a request journal. Never take the
API down while the challenger runs. RPC, indexer and signing latency,
confirmation depth, and any restart or replay time must fit within the vault's
challenge window.
