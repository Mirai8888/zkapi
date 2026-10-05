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
| `--tx-fee-cap-wei` | `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` | 1 ETH | Highest gas limit x `maxFeePerGas` of one challenge, in decimal wei (empty means the default); the upstream node's RPC fee cap. The signer's lower value applies too. |
| `--fee-bump-after-blocks`, `--fee-bump-percent` | | 3, 25 | Replacement pace and fee-cap step (10 to 100 percent). |
| `--status-listen` | `ZKAPI_CHALLENGE_STATUS_LISTEN` | `127.0.0.1:3002` | Internal `/livez`, `/health` and `/status`. Never publish it. |
| `--warning-remaining-seconds`, `--critical-remaining-seconds` | | `challengePeriod()` / 2, / 4 | Deadline escalation thresholds. |
| `--blocked-warning-seconds`, `--critical-blocked-seconds` | | 120, 1800 | Escalation of a blocked obligation. |
| `--settlement-overdue-seconds` | | 3600 | Warning when a reserved request's settlement is this late. |
| `--indexer-divergence-seconds`, `--indexer-divergence-polls`, `--indexer-lag-warning-blocks` | | 600, 3, 64 | Divergence heuristic for indexers without block metadata; lag warning. |
| `--stale-poll-seconds`, `--startup-grace-seconds` | | 300, 300 | Liveness and first-poll grace. |
| `--observe-interval-seconds` | | 15 | Sender balance and indexer root observations. |
| `--min-sender-balance-wei` | | 7.6M gas x `--max-fee-per-gas-wei`, at most `--tx-fee-cap-wei` | Balance warning threshold. |

For the AWS deployment, [the bounded signer sidecar](../docker/aws/signer/README.md)
provides the signer RPC on a private container network, and
[the Docker guide](../docker/aws/README.md) passes these settings. The sidecar
requires an explicit `ZKAPI_CHALLENGE_CHAIN_ID` of 1 (Mainnet) or 11155111
(Sepolia), accepts only zero-value challenge calls for that chain and vault,
checks the full ABI and a live simulation, and preserves the daemon's nonce. It
signs EIP-1559 (type 2) transactions with the fees the daemon proposes, within
its own fee and tip caps and transaction fee cap, and refuses with a structured
reason (`fee_out_of_bounds`, `base_fee_above_max_fee`, `insufficient_balance`,
`tx_fee_above_cap`) before anything is broadcast, or with `upstream_tx_fee_cap`
when its node refuses the transaction fee. Its dedicated private key belongs
only in the signer's environment. Keep its port unpublished; the public API
reverse proxy must never route to it.

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
  `cancelled` lease (a corrupt binding the server does not sign unless the
  operator reopens the lease) never yields evidence. It is a warning, and at the
  deadline it becomes `expired_without_evidence`, not missed. A reopened lease
  is awaiting settlement again, and its signed transcript is evidence.
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
first bid is twice the base fee plus the priority fee, within the limits below
and the [transaction fee ceiling](#transaction-fee-ceiling). The pending
challenge at the head of the sender's queue is replaced on the
same nonce when it is not mined after `--fee-bump-after-blocks`, when the base
fee rises above its fee cap, when it or a challenge queued behind it becomes
critical, or when the vault root moved since it was built (the replacement then
carries fresh siblings). A replacement raises the tip by 10% (rounded up) and
the fee cap by `--fee-bump-percent`, and at least to twice the base fee plus the
tip; geth and reth accept a replacement only when both rise by at least 10%.
Fees on a nonce never decrease, with one exception: a nonce that no attempt
holds (the RPC knows none of its hashes and the pending count has not passed it)
is re-sent at its earlier fees, lowered to the current caps, ceiling and balance
where they exceed them, which is logged at warn level. The note, request inputs
and proof are fixed per nonce (a persisted digest is compared on every send);
only siblings, gas and fees may change.

Because both fees must rise by 10%, the caps allow a limited number of
replacements on a nonce: about seven when the tip cap is twice the first tip.
Two of them are kept for the critical threshold. The caps here are the daemon's
tip cap and its effective fee cap, min(fee cap, ceiling / gas limit). Until an
obligation (or one queued behind it) is critical, bids stay within 100/121 of
both caps, that is 10/11 twice, and only go higher when the base fee needs it.
When only those two are left, the pending challenge is kept and reported as
blocked by `fee_reserve_held`, with the detail `the remaining fee headroom is
reserved for the critical threshold`. It is not replaced again before the
critical threshold (`challengePeriod()` / 4 before the deadline by default)
unless the base fee rises above it, so a market that needs a higher tip delays
its inclusion until then. Like an exhausted cap, the hold therefore warns after
`--blocked-warning-seconds` and turns critical after
`--critical-blocked-seconds`. The limit that holds it is 100/121 of the tip cap
and of the effective fee cap. Raising both caps (the signer's first, restarting
each service) lets the next poll replace the challenge once 100/121 of the new
caps is at least 10% above both of its fees. A 10% raise is enough for a bid at
that limit. A bid placed higher while the base fee needed it cannot be replaced
once the base fee falls back: from 10/11 of the caps it is held, and from the
caps themselves it reports `fee_cap_reached`, `tip_cap_reached` or, when the
ceiling limits the effective fee cap, `tx_fee_cap_reached` (then
`fee_reserve_held` after a smaller raise). It needs just over 21% or 33% more
on both caps (1.21 or 1.1 x 1.21 times them). The effective fee cap follows
the fee cap only up to the ceiling / gas limit,
`sender.tx_fee_cap_max_fee_per_gas_wei` on `/status`; to raise it further, also
raise the node's `--rpc.txfeecap` and
`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` for the signer and the daemon. Without such a
change, the challenge is replaced at the critical threshold. A critical
obligation bids 10/11 of both caps, then the caps themselves. A pending bid that
the base fee has risen above may spend the reserve earlier, since it cannot be
included otherwise. Stale-root replacements do not spend the reserve either:
when only the reserve is left, a pending challenge with outdated siblings is
kept, and if it reverts the daemon resubmits on a new nonce after the
confirmation depth. With the tip cap at twice the first tip, about five
replacements come before the critical threshold; a tip cap of 5 to 10 times the
first tip leaves room for more.

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

## Transaction fee ceiling

geth and reth refuse `eth_sendRawTransaction` before the transaction reaches
their pool when its gas limit x `maxFeePerGas` exceeds `--rpc.txfeecap`, 1 ETH
by default. Every bid (the first, each replacement and re-send, and the critical
bids) is therefore bounded by a transaction fee ceiling divided by the exact gas
limit it is sent with. The ceiling is the lowest of `--tx-fee-cap-wei` /
`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` (default 1 ETH), the signer's
`tx_fee_cap_wei`, which the bundled signer reports in `zkapi_signerStatus` (read
every `--observe-interval-seconds`) and in its `tx_fee_above_cap` refusals, and
a bound learned from the node's own refusals (`upstream_tx_fee_cap`, below). A
signer that reports none leaves the daemon's own value. At 1 ETH the ceiling
allows about 132 gwei for a 7.53M-gas challenge, whatever the fee cap. Set both
variables to the RPC fee cap of the node behind the signer; in
[the Docker deployment](../docker/aws/README.md#challenge-signer-and-daemon) the
daemon reads it from `deployment.env` and the signer from `signer.env`. Raising
the caps beyond that needs the node's `--rpc.txfeecap` raised together with both
variables.

`/status` warns when the daemon's and the signer's values differ, and when 7.6M
gas x `--max-fee-per-gas-wei` exceeds the ceiling: that part of the fee cap is
never used. It shows the ceiling in force as `sender.effective_tx_fee_cap_wei`,
the signer's value as `sender.signer_tx_fee_cap_wei` (with
`sender.signer_status_detail` when it cannot be read), the bound learned from
the node as `sender.node_tx_fee_cap_bound_wei`, and the highest fee per gas the
ceiling allows at the latest gas limit as
`sender.tx_fee_cap_max_fee_per_gas_wei`.

## When no valid bid remains

The obligation reports:

- `base_fee_above_fee_cap`: the base fee exceeds the daemon's fee cap; nothing
  is sent.
- `tx_fee_cap_reached`: the base fee exceeds the most the transaction fee
  ceiling allows per gas, or the ceiling keeps the pending challenge's max fee
  from rising by the 10% a replacement needs (reported even when the tip cap is
  reached too). Nothing is sent, the pending challenge stays in the pool, and an
  alarm shows the ceiling, the fee per gas it allows and the base fee. A
  challenge that a daemon without the ceiling bid above it is kept and observed
  in the same way while a node may hold it. Once the RPC knows none of its
  hashes, no send on its nonce had an unknown outcome, and the pending count has
  not passed the nonce, it is re-sent within the ceiling, provided its
  obligation is still pending and a bid within the ceiling is includable before
  the deadline. A nonce that such a daemon locked at a refused bid, with
  candidate hashes no node knows, is otherwise not recovered automatically, and
  it blocks later notes until it is consumed. If the escape was finalized or
  replaced before the upgrade, the nonce is reported as `unmined nonce N of a
  completed or replaced note M requires signer intervention`. If the deadline
  passes first (for example while the base fee stays above the ceiling), the
  missed obligation is first reported as blocked by `nonce_blocked` (alarm
  `note M missed (nonce_blocked)`), with the detail `expired obligation retains
  unmined reserved nonce N, which an attempt may hold; resolve it at the
  signer` and its bid in the obligation's `max_fee_per_gas_wei`. Only once the
  escape is finalized is the nonce reported as `unmined nonce N of a completed
  or replaced note M requires signer intervention`. The daemon cannot tell those
  hashes from a broadcast transaction; see
  [Recovery and verification](#recovery-and-verification).
- `fee_reserve_held`: the pending challenge spent the replacements allowed
  before the critical threshold (see
  [Building and sending a challenge](#building-and-sending-a-challenge)).
- `fee_cap_reached` or `tip_cap_reached`: no valid replacement within the caps.
- `insufficient_balance`: the fee cap is also limited to balance / gas.

Raise the signer's caps in `signer.env` and restart the signer first, then raise
the daemon's caps (never above the signer's) and restart the daemon; it then
replaces its pending challenge. For `tx_fee_cap_reached`, raise the ceiling as
described above, starting with the node's RPC fee cap; raising only the fee cap
changes nothing. Fund the sender for every challenge that may be pending at
once plus reverted attempts: each needs gas limit x fee cap (about 7.6M gas x
fee cap), but never more than the ceiling. Status warns when the balance cannot
cover the outstanding obligations at the proposed fee cap, or is below
`--min-sender-balance-wei`. There is no spending budget beyond the
per-transaction caps, the ceiling and the sender balance. The
[signer README](../docker/aws/signer/README.md#fee-spike-runbook) has the fee
spike runbook.

Signer errors other than `broadcast_ambiguous` mean nothing was broadcast. This
includes `tx_fee_above_cap` (refused before any upstream call) and
`upstream_tx_fee_cap` (the node refused the broadcast before its pool). A
`broadcast_ambiguous` error carries the candidate transaction hash, which the
daemon keeps. A transport error or a timeout (the send waits up to 95 seconds)
is treated as possibly broadcast: the next send on that nonce must outbid the
highest fees that may be in a pool, by at least 10% on both, and is paced like a
replacement. The other errors roll the attempt back. Refusals report their own
reason:

- `base_fee_above_max_fee`: the base fee rose above the bid before the signer
  checked it; the next poll bids from the new base fee.
- `tx_fee_above_cap`: the bid exceeded the signer's transaction fee cap. The
  daemon learns that cap from the refusal (its `tx_fee_cap_wei`, or
  `max_fee_per_gas_allowed` x `gas_limit`) and stays within it from the next
  bid. Give the signer and the daemon the same value.
- `upstream_tx_fee_cap`: the signer's node refused the transaction fee, because
  its RPC fee cap is below the ceiling. This is critical at once. The node never
  reports its cap, so the daemon lowers the ceiling to 10/11 of the lowest
  transaction fee it refused (`sender.node_tx_fee_cap_bound_wei`). The refused
  fee is the refusal's `gas_limit` x `max_fee_per_gas`, each taken from the
  refused bid when the signer omits it. A product that leaves no bound, such
  as zero, is ignored like a zero `tx_fee_cap_wei`, and the refused bid's own
  gas limit x `maxFeePerGas` is used instead. Each refusal lowers the next bid
  by at least 9% until the node accepts one, usually within a few polls. The
  bound stays above 10/11 of the node's cap, so at most about 9% of that cap
  goes unused. It lasts until the daemon restarts, with a
  `/status` warning that names the refused fee. Lower
  `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` for both services to the node's cap and
  restart both, or raise the node's cap and restart the daemon.
- `insufficient_balance`, and `signer_refused` for any other refusal.

A nonce on which no attempt was broadcast is released, as long as neither the
latest nor the pending transaction count has passed it. That applies when every
attempt on it was refused, failed before the signer broadcast it
(`simulation_failed`, `upstream_*`, `base_fee_unavailable`), or never reached
the signer (connection refused). The release happens at once, or when the plan
cannot send, at the deadline, at retirement, or once the nonce is detached.
Later notes then use it. A nonce reserved by a daemon from an earlier release
without an attempt record is never released this way.

## Recovery and verification

The checkpoint records the deployment and sender, next scan block, block hash,
pending nullifiers and deadlines, reserved transaction nonces, every candidate
transaction hash with the latest attempt's fees and gas limit, the evidence
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

An **unmined** nonce whose withdrawal has expired or been replaced is released
when nothing was broadcast on it (see
[When no valid bid remains](#when-no-valid-bid-remains)). Otherwise it still
prevents new allocations, because a transaction signed for it may still be
pending: it has a candidate hash, a send's outcome was unknown, or a daemon from
an earlier release reserved it without a record. While the expired escape is
still pending, its obligation is blocked by `nonce_blocked` (`expired obligation
retains unmined reserved nonce N, which an attempt may hold; resolve it at the
signer`). Once the escape is finalized or replaced, the detached nonce is
reported as critical (`unmined nonce N of a completed or replaced note M
requires signer intervention`). The daemon does not reuse the nonce for another
note or send a cancellation, and the bounded signer does not expose cancellation
calls. Look up the candidate hashes on `/status` (`detached_nonces`, or the
obligation's `transaction_hash` and `superseded_hashes`) on a full node: a
pending one mines or reverts by itself, and the queue then continues. Only when
no node knows any of them and the nonce stays unmined, consume the nonce with
the sender's key outside the sidecar, for example with a zero-value transfer
from the sender to itself at exactly that nonce. Each detached nonce on
`/status` also shows the latest recorded bid (`max_fee_per_gas_wei`,
`max_priority_fee_per_gas_wei`, and `gas_limit`, which records from earlier
releases lack; a challenge needs about 7.53M gas). When gas limit x
`maxFeePerGas` exceeds the node's RPC fee cap, the node refused that bid before
its pool, although a signer from an earlier release reported the refusal as
possibly broadcast: this is the usual cause of a nonce that no node knows, left
by a daemon that bid above the transaction fee ceiling. This restriction is
distinct from an expired obligation whose nonce has already mined; that
obligation cannot starve the remaining queue.

## Escape completeness

The event scan can miss an escape when the RPC's `eth_getLogs` lags its head.
Every poll therefore also reads the indexer's internal `GET /v1/escapes/pending`
list. Only its note IDs count: for each listed note that the checkpoint does not
track under the listed nullifier, the daemon reads the vault's
`pendingWithdrawals(noteId)` and tracks the escape the vault holds, with the
vault's nullifier and deadline, whatever the list says. The list describes the
indexer's view at its `block_hash`, and the vault can change after that block.
The indexer verifies only its root and next note ID, so the listed nullifier and
deadline are hints. A challenge and a re-escape of the same note leave the root
unchanged: if the indexer's log source dropped such a pair, it keeps listing the
older, challenged escape until the note's next challenge or finalization, which
it then applies and counts in `missed_re_escape_count`. A dropped finalization,
or a challenge and a later mutual close or expiry claim of the note that were
both dropped, also leave the root unchanged; the note then stays listed with no
escape in the vault until the indexer is resynced. (If only the challenge is
dropped, the indexer cannot apply the close or claim, and its view diverges
instead.) A listed nullifier or deadline that differs from the vault's is shown
as `indexer.pending_escapes_disagreement` on `/status`, is logged at warn
level, and warns after `--blocked-warning-seconds`; if it persists, resync the
indexer.

Per poll the daemon reads the vault for at most 64 listed notes it does not
track. Each poll starts where the previous one stopped and wraps around, so
every listed note due for a read is read within ceil(n / 64) polls. A listed
note that the checkpoint does not track and whose escape the vault does not
hold, a dead entry, is still read on every poll until reads 60 seconds apart
have found none: the indexer's head view can be ahead of the daemon's RPC, so
a fresh escape can read as absent at first. After that it is read again only
every 16 listings (polls that read the list), so dead entries cannot crowd out
the escapes listed after them. A later escape of that note that the event scan
misses is still tracked within about 16 polls, or at once when the list names
its new nullifier. A dead entry means that the list lags the vault, or that the
indexer's log source missed how that escape ended (for example, a dropped
finalization), in which case the indexer keeps the entry until a resync. The
note is shown in `indexer.pending_escapes_disagreement` as `N listed note(s)
with no pending escape in the vault: note ID listed with nullifier 0x…`, and
the same warning to resync the indexer is raised, once two conditions hold:

- reads `--blocked-warning-seconds` apart have found no escape;
- a list served at a block between two of those reads still names the note:
  at or above the daemon's RPC head at the poll after the first read, and at
  or below its head at a later read that finds no escape.

A list served below the first read may only lag the vault, and one served
beyond the daemon's head may hold an escape that its RPC does not show yet;
neither is reported. A stalled indexer's dead entry therefore stays unreported
until its list passes the first read; watch the indexer's own `/health`
(`stale`) and `head_age_seconds` for that. A list served without
`block_number` is judged on time alone. The daemon reads such a note again as
soon as that period has passed and a listing can complete the report, so the
report waits for a confirming read. A note the checkpoint
tracks is never reported this way, because its vault record is read on every
poll. The read position and the dead entries are kept in memory only: after a
restart every listed note is read again within ceil(n / 64) polls, and a
report waits another warning period. The check in
[the Docker guide](../docker/aws/README.md#indexer-resync), step 1, also finds
dead entries, through another RPC; resync an indexer that lists any. An
indexer without the endpoint shows a permanent `unsupported` warning, and an
unavailable list warns after `--blocked-warning-seconds`.

The daemon also reads `pendingWithdrawals(noteId)` for every tracked note on
every poll. When the vault holds a different escape (the owner escaped again
after a challenge, or a replayed event tracked an older one), it tracks the
vault's escape and logs `the vault holds a different escape than the one
tracked for this note; tracking the vault's` at warn level. The old
obligation's nonce stays reserved until it is consumed, or is released when
nothing was broadcast on it.

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
  poll timing, sender balance and nonces, the fee caps and the transaction fee
  ceiling (`tx_fee_cap_wei`, `signer_tx_fee_cap_wei`,
  `node_tx_fee_cap_bound_wei`, `effective_tx_fee_cap_wei`,
  `challenge_gas_limit`, `tx_fee_cap_max_fee_per_gas_wei`), indexer state,
  every obligation, detached nonces with their latest recorded bid,
  `missed_total` and `last_missed`. Wei values are decimal strings. It contains
  no client request IDs.

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
  `indexer_invalid_response`, `indexer_diverged`, `signer_refused` or
  `upstream_tx_fee_cap`; other blocked reasons (`indexer_unavailable`,
  `indexer_path_behind`, `rpc_error`, `simulation_reverted`, `send_ambiguous`,
  `base_fee_above_fee_cap`, `base_fee_above_max_fee`, `fee_cap_reached`,
  `tip_cap_reached`, `fee_reserve_held`, `tx_fee_cap_reached`,
  `tx_fee_above_cap`, `insufficient_balance`, `nonce_conflict`,
  `nonce_blocked`) warn after `--blocked-warning-seconds` and turn critical
  after `--critical-blocked-seconds`;
- for `awaiting_settlement`, a warning once settlement is
  `--settlement-overdue-seconds` late, and critical at once when the lease is
  not due to finalize before the critical threshold.

Stale polls, no successful poll after the startup grace, no new head block for
600 seconds, an event scan 300 blocks behind, a diverged indexer and an unmined
detached nonce are also critical. An obligation blocked by
`tx_fee_cap_reached` also raises a warning with the ceiling, the fee per gas it
allows at the latest gas limit and the base fee, and a bound learned from
`upstream_tx_fee_cap` refusals warns with the refused fee until the daemon
restarts. State changes are logged as
`challenge obligation status changed` at info, warn or error level, and critical
items are logged again every 300 seconds. A deadline that passes while evidence
existed or was expected logs `MISSED escape challenge deadline` once and
increments `missed_total`. The window cannot be extended: page a human at the
warning threshold.

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

The indexer verifies only its root and next note ID, so escape events its
RPC's `eth_getLogs` dropped in a pair that leaves the root unchanged, such as a
challenge and a re-escape of the same note, leave its `/health` `ok`. Its
pending-escapes list then keeps the challenged escape until the note's next
challenge or finalization, which the indexer applies, logs (at error level for
a finalization) and counts in `missed_re_escape_count` and
`zkapi_indexer_missed_re_escapes_total`. A dropped finalization, or a challenge
and a later mutual close or expiry claim of the note that were both dropped,
leave the note listed until a resync. The daemon reports such a note in
`indexer.pending_escapes_disagreement`, with the resync warning, once reads
`--blocked-warning-seconds` apart find no escape for it and a list served after
the first such read still names it (see
[Escape completeness](#escape-completeness)), and the daily dead-entry check in
the Docker guide finds it too. If that count
rises, a dead entry appears, or `indexer.pending_escapes_disagreement`
persists, fix or replace the indexer RPC's log index, then resync. Meanwhile
the daemon follows the vault's escape for every note it tracks.

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
