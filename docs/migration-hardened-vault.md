# Migrating to the hardened vault

This release fixes nine findings from a security review. Most of the fixes are
in the API server, indexer, challenger, signer, gateway and clients, and they
also protect the vaults that are deployed today. Four need contract changes.
`ZkApiVault` is immutable, so those take effect only on a newly deployed vault,
called the hardened vault below (`vault_revision` 2 in client manifests). Vaults
deployed before this release are called legacy vaults; this includes the
published Mainnet vault `0x4386FDbdA35D995beB3BF8625118Ec5982ec81fe` and Sepolia
vault `0x49fA19f9bdECe7A48Ebc7749fD69aD40F577590F`.

Notes cannot move between vaults. The migration therefore runs in phases, in
this order:

1. [Phase 0](#phase-0-upgrade-the-existing-deployment-in-place): upgrade the
   existing deployment's services in place, against its legacy vault.
2. [Phase 1](#phase-1-deploy-the-hardened-vault): deploy the hardened vault as a
   separate deployment.
3. [Phase 2](#phase-2-publish-clients): publish client releases, first for the
   legacy deployment, then for the hardened one.
4. [Phase 3](#phase-3-stop-deposits-to-the-legacy-vault-and-drain-it): stop new
   deposits to the legacy vault and drain it.
5. [Phase 4](#phase-4-disable-legacy-clearance-and-retire-the-legacy-stack):
   disable legacy clearance, then retire the legacy stack.

The circuit (`zkapi-v2-note-bound-v1`), proving and verifying keys, WASM and the
Groth16 adapter are unchanged. Some items are not fixed by this release; see
[residual risks](#residual-risks-and-items-not-fixed) before announcing dates.

## What changed and why

**Published default signing seeds.** `zkapi serverd` used to derive its state
and clearance keys from the published seeds `0x1` and `0x2` whenever the seeds
were missing or empty, and never compared its keys with the vault's, so anyone
could forge state signatures and obtain provider keys. `ZKAPI_STATE_SEED` and
`ZKAPI_CLEAR_SEED` are now required, with no fallback. `zkapi serverd` and
`zkapi signing-keys` refuse zero and subgroup-order multiples, the development
keys in any spelling and either role, secrets within 2^128 of zero or of the
subgroup order, and one key for both roles. Before opening its database the
server checks the native billing RPC's chain ID, compares its derived keys with
the vault's `stateSigningKeyX/Y()` and `clearanceSigningKeyX/Y()`, and records a
`deployment_binding` row. The bypassable string check in `run-daemon.sh` is
gone. This protects legacy deployments as soon as the server is upgraded.

**Unauthenticated clearance reservations.** `POST /v2/withdraw/clearance` used
to reserve any nullifier it was given, permanently and without proof. It now
requires an `ownership_proof`: an escape-form withdrawal proof
(`has_clearance: false`) for the same nullifier, with the deployment's keys and
a root the server saw within `--clearance-root-window-seconds` (3600) or the
vault's current root. Nothing is reserved without it
(`400 clearance_ownership_required`). The transitional `--allow-legacy-clearance`
(`ZKAPI_ALLOW_LEGACY_CLEARANCE`) still signs proof-less requests from older
clients, at most `--legacy-clearance-max-per-minute` (60) new reservations per
minute per server process, and `/health` reports
`clearance_ownership_proof_required`. That budget is one pool shared by every
caller, so anyone can exhaust it with random nullifiers, and every junk request
leaves a permanent `ClearanceReserved` row. A proof-less request that finds it
spent gets `503 legacy_clearance_capacity` (with `Retry-After` until the next
minute). A request with an ownership proof never uses the budget. `/health`
reports `legacy_clearance_window_used`, `legacy_clearance_window_limit` and
`legacy_clearance_rejected_total`. The server logs
`legacy clearance budget exhausted` at most once a minute. The Rust wallet
always sends an ownership proof. The `zkapi-clientd` companion does too, except
on a vault below `vault_revision` 2 at a note state from which it sent a
request that never settled (one in its `request_archive/`). There it asks for
a clearance without a proof. When that is refused it stops with
`409 unsettled_request_state` (one chat request settles the state) or, when the
server already holds a clearance for the state,
`409 unsettled_clearance_reserved`. From such a state it sends the proof only
after the owner types `send` at the guided withdrawal's risk warning, offered
once the note has expired or for `unsettled_clearance_reserved`. The browser
SDK sends one when its profile declares the capability, or after a proof-less
request is refused, except on a vault without `vault_revision` 2 at a state
whose request proof left the device: there it sends only the proof-less
request, and refuses with `409 transmitted_anchor_ownership_unsafe` when the
server asks for a proof. The reason for both exceptions: an ownership proof is
a valid escape, and on such a vault a challenge with a request proof for the
same state burns the nullifier. For the same reason, on such a vault neither
client sends a request proof from a state once a clearance request carrying
its ownership proof has left, even when the answer is a gateway 429 or is
lost: the SDK keeps the note withdrawal-only, and `zkapi-clientd` keeps the
withdrawal reserved and refuses to release it (`409 ownership_proof_sent`).
Retrying the close completes it. The gateway now limits POST floods per
source.
Reservations stay permanent, because a clearance signature has no expiry.

**Unsettleable leases.** A lease could fail settlement forever, on an
over-reported usage figure that overflowed the gwei conversion or after a change
to the `--native-price-*` settings, leaving its note state reserved and every
SDK withdrawal refused. Settlement now clamps usage to the proof's solvency
bound before converting it, checks the saved quote only for internal
consistency, finalizes never-delivered leases at zero, and finalizes every other
lease by a write-once deadline (`ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS`),
at worst at the solvency bound, with an operator review record. The server
refuses to start unless that deadline fits in half the vault's
`challengePeriod()`. The zero settlement of a never-delivered lease takes the
key issuance lock, so no key is returned for such a lease; `/expire` checks no
longer hold that lock across their oracle reads, and a lease past its deadline
queues for it. A
lease the server cannot sign because its record is corrupt can be repaired and
reopened with `zkapi settlement reopen`, and a pending lease whose saved
request cannot be decoded, which no tick settles, is restored with
`zkapi settlement reopen --saved-request`. Each settlement tick attempts the
lease nearest its deadline first, alternating with the least recently
attempted one; a receipt the OA org reports as pending waits for its retry
time without counting as a failure; and each lease settles under its own lock,
so retirements of one lease cannot delay the others. The server refuses to
start under another lease key source while leases or key deletions of the
previous one still need its credential
([Changing the key source](native-eth-billing.md#changing-the-key-source)).
The CLI default of
`--native-price-max-age-seconds` is now 4500, matching the container launcher.
The SDK installs clamped and worst-case receipts. The SDK and the
`zkapi-clientd` companion (in a release built with the updated
`companion.patch`) validate journal quotes without the live manifest. A request
the server never admitted under earlier pins is refused until its quote
expires; the wallet then retires it once the server confirms that it expired
unaccepted. The SDK does so in the recovery before its next lease;
`zkapi-clientd` does so on its next lease at the request's original model
budget, or when a withdrawal settles, and reports `lease_pending` for a lease
at another budget. This applies to legacy deployments too. See
[settlement terminality](native-eth-billing.md#settlement-terminality).

**Nullifier burn after an escape challenge.** On a legacy vault a successful
challenge leaves the escape's nullifier consumed, and the challenger used to
treat a merely reserved lease as evidence. Together, a settlement that never
completed, or an operator that withheld it, could exhaust every nullifier the
owner can prove and leave the deposit to the expiry sweep. The challenger now
uses only finalized transcripts as evidence, and settlement always finalizes.
On the hardened vault a successful challenge also clears `usedNullifiers` and
sets `challengedNullifiers` for the nullifier: no escape can use it again
(`ChallengedNullifier()`), a mutual close with a server clearance still can, and
the note keeps at least one `challengePeriod()` of unpaused time before an
expiry claim. On legacy vaults the burn remains in the contract, so the
finalized-only rule is the protection there.

**Discarded write-ahead journal.** The browser SDK deleted its request journal
when the server answered `stale_root` or `clearance_reserved`, then could build
an escape at an anchor whose request proof the server already held. The SDK now
keeps an append-only archive of transmitted requests, committed with the journal
before the request is sent, and discards a journal only after corroboration (the
pinned vault RPC's `currentRoot()`, then `GET /v2/nullifiers/{nullifier}`). On a
vault without `vault_revision` 2 it refuses any escape at a transmitted anchor
and sends no ownership proof from one (strict mode). An archived request keeps
its full journal while its note state
is current. Past 16 unresolved requests at one state the SDK only sets expired,
corroborated discards aside (`evicted`, still installable). At 64 it refuses
new chats with `request_archive_limit` instead of discarding anything; chats at
that state resume only if the server settles one of its requests, and otherwise
the balance has to be withdrawn. An `/expire` answer is saved as an
`unaccepted` observation, never as a nullifier reading. On a `vault_revision` 2
vault the time-gated escape override covers every unsettled state,
`receipt_journal_missing` included: only a receipt that verifies vetoes it,
because a lying server or gateway can claim `finalized` with a receipt the
browser cannot apply. For that code the override needs its own
acknowledgement, `overrideUnsettledRequest: 'receipt_journal_missing'`, given
after that code's own warning; `true` is refused there. Once saved, such a
claim stands until a reading saved after it reports the nullifier `unknown` or
`clearance_reserved`, so a later failed or different read keeps that
requirement. "After" is the order in which the browser saved the readings, not
the device clock. A pre-release build of this archive that predates that save
order, open in another tab of the same site, drops it from the records it
writes, which can let `true` suffice again after a failed read; builds from
earlier releases write no archive records.

The `zkapi-clientd` companion no longer deletes a transmitted request journal.
After `stale_root`, and when withdrawal settlement finds the request unknown to
the server, it first reads the pinned vault's `currentRoot()`. While that still
equals the request's root, or cannot be read, the journal stays pending and the
identical request is resent. Only once the root moved and the server reports
the request's nullifier unknown does the journal move, whole, into the
companion's append-only `request_archive/`, from which recovery installs a
later finalized receipt that verifies. Withdrawal settlement also moves a
request there, without reading the root, when the server reports its
nullifier `clearance_reserved`: the server refuses every request at such a
nullifier, so it can never settle. Chats at such a state stop with
`409 clearance_reserved_state` and send no new request from it. Journals that
`zkapi-clientd` 0.1.6 and earlier, or pre-release builds of this companion,
deleted left no record; such a note reports `receipt_journal_missing` (see
Operations runbooks).

**Indexer divergence.** The indexer applied unconfirmed logs with no block
continuity, only warned when its root diverged from the vault, kept reporting
healthy, and persisted the bad state, which silently disabled challenges and
exits. It now commits a checkpoint only at `--confirmations` depth after
verifying the vault's `currentRoot()` and `nextNoteId()` by block hash
(EIP-1898), serves a restored checkpoint only once it verifies and a head view
verified the same way, answers 503 otherwise, rebuilds automatically after a
divergence or deep reorganization, supports `--resync`, and reports a frozen
RPC head as stale. The challenger detects divergence and alerts. It fills gaps
in its own event scan from the indexer's `/v1/escapes/pending`, whose
nullifiers and deadlines are hints: for each listed note it tracks the escape
that the vault's `pendingWithdrawals(noteId)` holds. The indexer counts escapes
closed that it never saw initiated (`missed_re_escape_count`): its RPC's logs
dropped vault events, or a reorganization below its checkpoint replaced an
escape. On the hardened vault withdrawals accept a proof against any root from
the last day (`UnknownRoot()` for older roots, `StaleRoot()` only for siblings
that do not match the live root), and the SDK refreshes siblings without
proving again.

**Default gas-price cap.** The challenge signer signed legacy transactions only
while `eth_gasPrice` was under its cap (10 gwei by default, even on Mainnet),
with no escalation and only a log line as the deadline passed. It now signs
EIP-1559 transactions within explicit fee and tip caps (an explicit cap is
required on Mainnet), keeps gas limit x `maxFeePerGas` within
`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`, which matches its node's `--rpc.txfeecap` (1
ETH by default), refuses with structured reasons before broadcasting, and
reports `zkapi_signerStatus`. The daemon proposes fees within the same ceiling,
replaces its pending challenge on the same nonce with rising fees while keeping
two replacements for the critical threshold, bids its caps near the deadline,
releases a nonce on which nothing was broadcast, and reports every obligation
with its severity on `/health` and `/status`.

**Pause blocks exits while the expiry claim stays open.** On a legacy vault the
owner's `pause()` blocks every new exit while `claimExpired` and an instant
`setTreasury` keep working, so the owner can force every note to expiry and
sweep it to a treasury chosen at that moment. On the hardened vault
`claimExpired` is blocked while paused, paused time extends each note's claim
time, and after an unpause claims wait `unpauseClaimGrace()`. Treasury changes
are two-step (`setTreasury`, then `acceptTreasury` after `treasuryChangeDelay()`
of unpaused time, blocked while paused), pause and unpause emit events,
ownership transfers are two-step (`transferOwnership` nominates
`pendingOwner()`, which must call `acceptOwnership()`), and `Deploy.s.sol`
requires an explicit `OWNER` off local chains. A pause still has
no time limit: the owner can freeze but not seize. Legacy vaults keep the
defect; only the owner policy in Phase 0 mitigates it.

**Escape payouts a destination rejects.** On a legacy vault
`finalizeEscapeWithdrawal` pays the destination and the treasury in one call,
so an escape to a destination that rejects ETH can never finalize: the note,
including the operator's share, stays locked. On the hardened vault
withdrawals to the vault itself revert `InvalidDestination()`, and
finalization pushes the user's balance with at most `ESCAPE_PAYOUT_GAS()`
(100,000). If the destination rejects it or needs more gas, the escape still
closes and the treasury share is paid; the balance is credited to
`escapePayoutCredits(destination)` with an `EscapePayoutDeferred` event, and
anyone can deliver it with `claimEscapePayout(destination)`, also while paused.
A mutual close to a destination that rejects ETH still reverts (it forwards
all gas, so a destination that only needs more gas is paid): its submitter can
prove the close again to another destination. The browser SDK from this
release reports such an escape, when this browser started it, as credited
rather than returned, and offers its claim (`claimEscapePayout`).
`zkapi-clientd` reports an independently relayed escape it accepts as payout
evidence as credited (`payout_credited`), with the claim's calldata; its
pinned manifests are still legacy vaults, which never credit. On a legacy
vault the SDK refuses, before proving, an escape to a destination that
rejects a plain ETH transfer from the vault (`escape_destination_unpayable`),
unless the caller overrides that check. See
[Escape payout credits](#operations-runbooks).

**Unpinned funding RPC.** `zkapi-clientd` trusted one third-party RPC for
receipts and note IDs, and did not compare the companion's RPC with its pinned
manifest. It now requires the companion's RPC, indexer and protocol server
endpoints to equal the pinned ones, activates a deposit only when the vault's
`notes(noteId)` at the receipt block and the indexer's tree agree, refuses to
retire or retry a reverted deposit whose note the indexer shows, corroborates
withdrawals the same way, and offers a **repair** action
(`zkapi-clientd config --menu`, then repair) to fix a wrong binding or to bind a
deposit reported as reverted that landed. It keeps the slot of every deposit it
signs for a note, with the run of empty slots right below it in the indexer
tree the deposit was built from. A deposit built on a short-lived fork of the
indexer's head view can land in that run. It signs a retry only when a bounded
search of the indexer tree the retry is built from finds none of the note's
earlier deposits. So a deposit that the RPC withheld, and relayed after its
revert was retired, cannot land beside the retry. The search runs on chain
time: from the block time of the indexer view each slot was built from to the
block time of the view it searches. Each comes from the pinned RPC's header
for the view's block hash and is accepted only when the header hashes to it.
It misses such a deposit in three cases only. Either challenges restored 64 or
more escaped notes between its slot (or the start of that run) and its landing
slot after it landed. Or it landed about 63 or more days before the retry. Or
its slot was saved by an earlier release, which recorded only the device
clock's preparation time, on a clock more than 6 days fast, and the deposit
landed within that much of its preparation. It needs the
upgraded indexer, whose snapshot carries block metadata. These checks are only
as independent as the indexer's own RPC, which must be a provider other than
the pinned `rpc_url` (Before you start, item 7).

## Breaking changes

API server (`zkapi serverd`):

- Both seeds are required; empty values, an explicitly empty flag, weak or
  development seeds, and seeds whose keys differ from the vault's stop startup.
  There is no override.
- The first start on a database, and every start after a crash that left a
  SQLite journal, needs `--native-billing-rpc-url` to serve `--chain-id` and to
  allow `eth_chainId` and the vault getters listed in the
  [Docker guide](../docker/aws/README.md#signing-seeds). A database bound to
  another chain or vault is refused.
- Startup refuses lease settings that do not fit
  TTL + grace + `--openrouter-settlement-deadline-seconds` + 2 x poll + 600 <=
  `challengePeriod()` / 2.
- `POST /v2/withdraw/clearance` needs `ownership_proof` unless
  `--allow-legacy-clearance` is set. There are two new errors:
  `clearance_ownership_required` (400), and `legacy_clearance_capacity` (503,
  retriable, `Retry-After` of at most 60 seconds): the legacy proof-less budget
  is spent and nothing was reserved. `capacity_exhausted` (503) now means only
  that ownership-proof verification is busy; it is retriable. `stale_root`
  (409) reports the vault's root. `/health` adds
  `legacy_clearance_window_used`, `legacy_clearance_window_limit` and
  `legacy_clearance_rejected_total`.
- Lease status `cancelled` (corrupt binding, never signed unless the operator
  repairs the record and reopens the lease with `zkapi settlement reopen`);
  lease status responses add `charge_basis` and `settlement_deadline`, and
  recovery responses add `settlement_deadline`; settlement payloads add
  `charge_basis` (`measured`, `clamped`, `worst_case`, `unissued` or
  `operator_conceded`) and, for fallbacks and concessions, `settlement_reason`
  (`settlement_deadline`, `unsettleable` or `operator_conceded`). Payload `type`
  strings are unchanged.
- Lease routes answer a lease row that cannot be decoded with
  `404 lease_record_unreadable` (not retriable; read
  `GET /v2/nullifiers/{request_nullifier}`), and a pending lease in that state
  is not settled, not even at its deadline, until the operator restores its
  saved request with `zkapi settlement reopen --saved-request`. A store that
  cannot be read answers recovery (`GET /v2/nullifiers/{nullifier}`,
  `GET /v2/requests/{id}`), lease status, retirement, a lease retry and
  `/expire` with retriable `500 database_error`: only a 200 `not_found` with
  `nullifier_status: "unknown"` means unknown. See the
  [API specification](api-spec.md).
- Startup refuses to switch the lease key source (direct OpenRouter or an OA
  org) while the database holds possibly delivered leases of the other source
  without a committed charge, or, when leaving direct OpenRouter, queued
  deletions of unexpired keys. Drain them first, as in
  [Changing the key source](native-eth-billing.md#changing-the-key-source);
  `--allow-key-source-switch` (`ZKAPI_ALLOW_KEY_SOURCE_SWITCH=true`) starts
  anyway and charges each such lease at its settlement deadline without a
  usage measurement.
- `--native-price-max-age-seconds` defaults to 4500 instead of 3600, and the CLI
  reads `ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS` and
  `ZKAPI_NATIVE_PRICE_FEED_DECIMALS`. Direct launches that relied on 3600 must
  pass it explicitly or match the manifest.
- The OA issuer reconciliation call (`POST /api/zkapi/reconcile_key`) is no
  longer made.

Challenger (`zkapi-challenged`):

- `--max-fee-per-gas-wei` and `--max-priority-fee-per-gas-wei` (or
  `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` and
  `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI`) are required, and the second
  must be at least twice `--priority-fee-per-gas-wei` (default 2 gwei).
- Every send proposes `maxFeePerGas` and `maxPriorityFeePerGas`, which the
  signer from earlier releases refuses. Deploy the new signer first.
- It opens the database read-only and requires the `deployment_binding` row.
  Upgrade and start the API server first.
- It listens on `--status-listen`, default `127.0.0.1:3002`; give each daemon on
  one host its own address.
- Reserved requests are no longer evidence.
- `missed_total` now also counts an escape found paid out past its deadline
  with evidence (see
  [Recovery and verification](challenge-service.md#recovery-and-verification)),
  and the checkpoint records the nullifier of every miss, so none is counted
  twice. A checkpoint from an earlier release records only its latest miss's
  nullifier (`last_missed`). An escape found paid out past its deadline is
  taken for one of that release's other misses, and not counted again, only
  while such misses remain and only if that release can have counted it. That
  means all three of these hold:
  - it was not pending in the checkpoint at the upgrade;
  - its deadline is no later than that release's last recorded miss
    (`last_missed.recorded_at` plus 15 minutes, or that miss's deadline if
    later);
  - its event lies below the checkpoint's scan cursor at the upgrade (not
    checked when the cursor had been reset for a replay).

  This is logged at warn level as `taken for a miss the earlier release
  counted in missed_total without its nullifier, so not counted again`,
  typically when a replay tracks such a retired escape again. Any other payout
  past its deadline is counted (`MISSED`, critical for an hour). That includes
  an escape initiated and paid out while the earlier daemon was down or its
  scan failed, which the upgraded daemon's first scan finds: treat it as a
  real missed challenge. Residuals: an escape the earlier release scanned and
  retired without counting it (it did not record a payout first seen after
  the deadline), with a deadline before its last recorded miss, is taken for
  one of those misses if a replay finds it; if the checkpoint was saved
  mid-replay, a miss that release counted of an escape between the replay
  position and the block it had scanned before is counted again. A rollback
  drops the recorded nullifiers: after a re-upgrade, misses the new daemon had
  counted are treated like the earlier release's.
- A zero path that does not hash to the vault's root and comes from an
  indexer view consistent with the vault at its block is `indexer_path_behind`
  (a warning that escalates with time), not `indexer_invalid_response`; see
  [Building and sending a challenge](challenge-service.md#building-and-sending-a-challenge).
  A checkpoint block that an RPC answers with null is retried, not replayed.
- Every bid keeps gas limit x `maxFeePerGas` within `--tx-fee-cap-wei` /
  `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` (default 1 ETH, the default `--rpc.txfeecap`
  of geth and reth). It also stays within the signer's `tx_fee_cap_wei` when
  that is lower, and, after the signer's node refuses a fee
  (`upstream_tx_fee_cap`), within 10/11 of the lowest refused fee until the
  daemon restarts. At 1 ETH a 7.53M-gas challenge bids at most about 132.7
  gwei. Set the same value in `deployment.env` and `signer.env`. A base fee
  above that is reported as `tx_fee_cap_reached`.
- Until an obligation is critical, bids stay within 100/121 of the tip cap and
  of the lower of the fee cap and the ceiling / gas limit, unless the base fee
  needs more, so two replacements remain for the critical threshold. A pending
  challenge that used the others is reported as `fee_reserve_held` and
  escalates with blocked time. Raising both caps lets it be replaced earlier
  once 100/121 of the new caps is at least 10% above its fees: 10% more for a
  bid at that limit, just over 21% to 33% more for one placed nearer the caps
  while the base fee needed it. The fee cap counts only up to the ceiling /
  gas limit; beyond that, also raise the node's `--rpc.txfeecap` and
  `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`, or wait for the critical threshold.
- A reserved nonce on which nothing was broadcast is released automatically:
  at once, when the plan cannot send, at the deadline, at retirement or once
  the nonce is detached. A nonce reserved by the earlier release's daemon has
  no attempt record and is never released this way.
- The challenger tracks the escape that the vault's `pendingWithdrawals(noteId)`
  holds, even when the indexer lists another nullifier, and shows such a listing
  as `indexer.pending_escapes_disagreement` on `/status`. A listed note that
  the vault holds no escape for is shown there too, once reads
  `--blocked-warning-seconds` apart have found none and a list served after
  the first such read still names it.
- `/status` reports each blocked obligation's reason, including
  `tx_fee_cap_reached`, `tx_fee_above_cap`, `upstream_tx_fee_cap` (critical at
  once), `base_fee_above_max_fee` and `fee_reserve_held`; see
  [status, health and alerting](challenge-service.md#status-health-and-alerting).

Signer (`docker/aws/signer`):

- `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI` is refused, even when empty. The cap is
  `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI`, required when
  `ZKAPI_CHALLENGE_CHAIN_ID=1`.
- Transactions are type 2. The sender must hold gas limit x `maxFeePerGas` for
  each pending transaction: about 0.075 ETH per challenge at the Sepolia
  default cap of 10 gwei, ten times what legacy pricing at 1 gwei needed.
- An empty `ZKAPI_CHALLENGE_LISTEN_HOST` now means `127.0.0.1`.
- `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` (default 1 ETH, the default
  `--rpc.txfeecap` of geth and reth) bounds gas limit x `maxFeePerGas` of every
  bid, proposed or default. A larger bid is refused with `tx_fee_above_cap`
  before any upstream call, and a node's own fee-cap refusal is reported as
  `upstream_tx_fee_cap` (nothing broadcast); any other failed broadcast is
  `broadcast_ambiguous` with its candidate hash. `zkapi_signerStatus` reports
  `tx_fee_cap_wei`, and warns `tx_fee_cap_below_fee_cap` while
  `ZKAPI_CHALLENGE_MAX_GAS` x fee cap exceeds it.

Indexer (`zkapi-indexerd`, `zkapi indexer`):

- The first start archives a version-1 checkpoint as
  `<cursor>.v1-<unix_ms>.bak` and replays from `--from-block`; tree routes
  answer 503 until the replay verifies. A checkpoint is bound to its chain and
  vault, and a restored one is served only after it verifies against the vault.
- The RPC must support `eth_call` by block hash (EIP-1898) and
  `eth_getBlockByHash`, and the host clock must be accurate.
- Not-ready tree routes return a JSON 503 body with `Retry-After: 5`; `/health`
  returns 200 only when the status is `ok`. Tree responses add `root`,
  `block_number` and `block_hash`.
- The internal `GET /v1/escapes/pending` lists the open escapes of the
  verified view, each with the nullifier and deadline last applied from the
  vault's logs. The root check covers the list only through the notes' leaves:
  it leaves no open escape out, but a listed nullifier or deadline can be stale
  and a closed escape can stay listed. Consumers read
  `pendingWithdrawals(noteId)` from the vault.
- `/health` adds `missed_re_escape_count` and its subset
  `missed_re_escape_finalized_count`, and `/metrics` adds
  `zkapi_indexer_missed_re_escapes_total{event="challenged"}` and
  `{event="finalized"}`: escapes challenged or finalized that the indexer never
  saw initiated. Each is logged once, a challenge at WARN and a finalization at
  ERROR (`escape finalized that the indexer never saw initiated`). The counters
  reset on restart.

Docker deployment (`docker/aws`):

- `deployment.env` gains `ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS`,
  `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`, `INDEXER_CONFIRMATIONS` and
  `INDEXER_MAX_HEAD_AGE_SECS`; `challenge.env` needs the two fee caps;
  `signer.env` changes as above.
- The server and challenger no longer wait for a healthy indexer; the
  challenger's healthcheck reads `/livez`.
- The gateway limits POST requests per source and answers
  `429 gateway_rate_limited`.

Hardened vault (existing signatures and events are unchanged):

- `challengeEscapeWithdrawal` clears `usedNullifiers(n)` and sets
  `challengedNullifiers(n)`; `initiateEscapeWithdrawal` reverts
  `ChallengedNullifier()` for such an `n`.
- Withdrawals revert `InvalidDestination()` for the zero address or the vault
  itself and `UnknownRoot()` for a root neither current nor retired within
  `ROOT_HISTORY_WINDOW()`.
- `claimExpired` reverts `Paused()` while paused and `NoteNotExpired()` before
  `effectiveExpiry(noteId)`; `notes(noteId)` keeps the nominal expiry.
- `setTreasury` only schedules; `acceptTreasury()` and `cancelTreasuryChange()`
  are new; a failed treasury payout accrues to `treasuryArrears()`.
- `pause()` and `unpause()` emit `Paused` and `Unpaused` and revert when
  redundant; `renounceOwnership()` reverts while paused and clears any pending
  owner.
- Ownership is two-step: `transferOwnership(address)` only sets
  `pendingOwner()` and emits `OwnershipTransferStarted(address,address)`, and
  the nominee completes the transfer with `acceptOwnership()`; `owner()` does
  not change until then. Both work while paused.
  `transferOwnership(address(0))` now cancels a nomination instead of reverting.
  New: `acceptOwnership()` `0x79ba5097`, `pendingOwner()` `0xe30c3978`, event
  topic `0x38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e22700`.
- `Deploy.s.sol` requires `OWNER` except on chains 31337 and 1337.
- `finalizeEscapeWithdrawal` pushes the user's balance with at most
  `ESCAPE_PAYOUT_GAS()` (100,000, `0x3e210f18`). A destination that rejects it
  or needs more gas no longer blocks the escape: the note closes, the treasury
  share is paid, and the balance is credited to `escapePayoutCredits(address)`
  (`0x91f6e93a`) with
  `EscapePayoutDeferred(uint32 indexed noteId, address indexed destination, uint128 amount)`
  (topic `0x1bd006af…a942`), emitted before `EscapeWithdrawalFinalized`. The new
  `claimEscapePayout(address)` (`0x88c10aee`) pays a credit to its destination
  with all gas; anyone can call it, also while paused, and it emits
  `EscapePayoutClaimed(address indexed, uint128)` (topic `0x6bf75371…be27`).
  `EscapeWithdrawalFinalized` is unchanged but no longer proves on its own that
  the payout arrived. The full topics are in the
  [vault reference](../docs-site/content/docs/api-reference/vault.mdx#views-errors-and-events).

Browser SDK:

- New 409 codes `request_settlement_pending`, `transmitted_anchor_unconfirmed`,
  `transmitted_anchor_escape_unsafe`, `anchor_challenged`,
  `nullifier_challenged`, `receipt_journal_missing`, `receipt_response_missing`,
  `receipt_pending_install`, `request_archive_limit` and
  `withdrawal_submission_pending`; vault reverts map to `unknown_root`,
  `challenged_nullifier`, `invalid_destination` and `vault_paused`.
- On a `vault_revision` 2 vault, `withdraw('escape', …,
  { overrideUnsettledRequest })` takes `true` (after the general warning) or
  `'receipt_journal_missing'` (after that code's own warning). Refusals that
  offer the override carry `escape_override_after`, `escape_override_warning`
  and `escape_override_acknowledgement`, and `snapshot().config.escape_override`
  carries `warning` and `acknowledgement`. Pass the acknowledgement these give,
  whatever the refusal's code: while a saved receipt claim stands, a refusal
  such as `transmitted_anchor_unconfirmed` also asks for
  `'receipt_journal_missing'`.
- Behaviour depends on `trusted_deployment.vault_revision` and
  `trusted_deployment.clearance_ownership_proof` in `browser-config.json`; see
  the [SDK README](../sdk/README.md).
- A mutual close generates two withdrawal proofs.
- Without a declared capability, a mutual close first asks for clearance
  without a proof. It marks the note withdrawal-only before that request,
  because a server with legacy clearance on may reserve on it. If the server
  answers `400 clearance_ownership_required` or
  `503 legacy_clearance_capacity`, nothing was reserved: the SDK restores the
  wallet's previous withdrawal state. At a state whose request proof never
  left the device, it proves locally, marks the note withdrawal-only again and
  sends the ownership proof. At a transmitted state it does so only on a
  `vault_revision` 2 vault, after the server reports the nullifier `unknown`
  or `clearance_reserved`. On any other vault it sends no proof there and
  refuses with `409 transmitted_anchor_ownership_unsafe`. A proving failure, a
  refused check or that refusal leaves the previous state in place, so a note
  that was usable stays usable. After
  any other failure of the proof-less request (a lost connection, or a 5xx
  without one of these codes), the note stays withdrawal-only, because the
  server may have reserved it; retrying the mutual close completes it.
- New `409 transmitted_anchor_ownership_unsafe` (`data.clearance_error_code`
  names the server's answer): a strict-mode mutual close at a transmitted state
  that the server would grant only with an ownership proof. The note stays
  usable for chat; a request from that state that settles moves it to a state
  that closes normally.
- `429 gateway_rate_limited` on a mutual close is retried with the same body
  within a 15 s budget, honouring `retry_after_seconds`. When it outlasts that
  budget, the previous withdrawal state is restored only for a proof-less
  request or on a `vault_revision` 2 vault. After an ownership proof on any
  other vault the note stays withdrawal-only, and the error carries
  `data.withdrawal_only: true`: offer to try the close again, or to escape,
  not a chat.
- `trusted_deployment.deposits` (`"open"` or `"closed"`). Closed deployments
  refuse new deposits with `409 deposits_closed`, and
  `snapshot().config.deposits` reports the setting.
- A `vault_revision` 2 profile is checked on chain at initialization
  (`ROOT_HISTORY_WINDOW()` must be 86400). A mismatch fails with
  `vault_revision_mismatch`. JSON-RPC reverts carry `rpc_call_reverted`, and
  an empty vault word carries `vault_value_invalid`.
- The store exports `readBrowserWalletHoldings`, `browserWalletHoldings`,
  `browserRuntimeHoldsState` and `isOpenBrowserWithdrawal`.
  `readBrowserWalletSnapshot(id)` adds `otherDeploymentWithdrawals`, and
  `snapshot().config.other_deployment_withdrawals` lists other deployments'
  open withdrawals. The store also exports `readBrowserWalletPayoutCredits`,
  `browserWalletPayoutCredits` and `isUnclaimedPayoutCredit`;
  `readBrowserWalletSnapshot(id)` adds `otherDeploymentCredits`, and
  `snapshot().config.other_deployment_credits` lists other deployments'
  unclaimed escape payout credits, which do not block a deposit.
- An escape whose finalization receipt carries `EscapePayoutDeferred` for its
  note and destination is reported as credited: its withdrawal record gets
  `payoutCredited: true`, `payoutVerified: false`, `creditedAmount` (vault
  units) and `payoutCreditEvidence: "receipt"`, the status message says the
  destination did not accept the payout, and `finalizeEscape` returns
  `payoutCredited: true`. Without a readable receipt (another device or a
  third party finalized it), a `vault_revision` 2 vault's nonzero
  `escapePayoutCredits(destination)` at the block where the note reads Closed
  marks it credited with `payoutCreditEvidence: "vault_credit"` and
  `creditedAmount: null`; this escape's own receipt proving the push later
  turns it into `payoutCredited: false`, `payoutVerified: true`. A close that
  a reorganization removed resets the payout, credit and claim fields.
  Records written by earlier builds have no credit fields and keep their
  meaning.
- `client.creditedEscapePayouts` lists credited records not yet seen
  delivered, and `client.claimEscapePayout(recordId, onStatus)` reads
  `escapePayoutCredits(destination)` and sends
  `claimEscapePayout(destination)` from the connected account, which pays
  only gas. It returns `{ status: "claimed" }`, or `{ status: "pending" }`
  while an earlier claim for that destination is pending, or throws with a
  `shortMessage` (`native_transfer_failed` while the destination still
  rejects ETH; the credit stays). A delivered credit sets
  `payoutClaimed: true`, `payoutVerified: true` and `payoutClaimEvidence`
  (`"claim_receipt"`, or `"credit_cleared"` when a zero credit shows that
  someone else claimed it). `client.readEscapePayoutCredit(destination)` reads
  the credit, and a manual signer's claim carries
  `zkapiRecovery.kind: "escape-payout-claim"`, which
  `resumeExternalTransaction` accepts. Vault reverts also map
  `ZeroAmount()` to `zero_amount`.
- Before proving an escape, the SDK simulates the vault's push to the
  destination; `client.checkEscapeDestination(destination, { finalBalance })`
  runs the same check and returns `{ destination, accepts, warning }`
  (`accepts: null` when the RPC cannot tell, which never refuses). On a
  `vault_revision` 2 vault a failing destination only warns: `onStatus`
  shows the warning and the result carries `destinationWarning`. On any other
  vault `withdraw('escape')` refuses that destination with
  `escape_destination_unpayable`, because such an escape could never
  finalize; its `error.data.override_option` is `"overrideDestinationCheck"`,
  and `withdraw('escape', onStatus, { destination, overrideDestinationCheck: true })`
  proceeds. The runtime adds `currentWithdrawals()`.

`zkapi-clientd`:

- The companion must report the pinned `rpc_url`, `indexer_url` and
  `protocol_server_url`; funding stops otherwise.
- The pinned `rpc_url` must serve `eth_getBlockByHash` for the block of the
  indexer view a deposit is built from or searched in, with a header format
  this release can hash, and the device clock must be within one day of that
  block's time. Otherwise no deposit is signed and no reported revert is
  retired.
- The companion reads the vault's `currentRoot()` over the same RPC before it
  sets aside a lease request rejected as `stale_root`, or reported unknown at
  withdrawal settlement; while it cannot, the request stays pending
  (`lease_pending`). A request whose nullifier the server reports
  `clearance_reserved` is set aside at withdrawal settlement without that read.
- Deposits and withdrawals wait (`confirming`, stage `verifying`) until the
  vault and the indexer agree; a disagreement is phase
  `verification_conflict`. The indexer must serve snapshot block metadata.
- A retry of a deposit reported as reverted is refused while the indexer shows
  an earlier deposit of the same note: phase `verification_conflict` with no
  pending transaction and no `transaction_hash`, resolved by **repair**.
  Management clients must not expect a transaction hash in that phase.
- Each withdrawal generates two withdrawal proofs. A manifest declaring
  `clearance_ownership_proof` or `vault_revision` 2 requires a companion that
  reports `clearance_ownership_proof_version`.
- On a vault below `vault_revision` 2, `/oa/v1/withdraw/prepare` at a note
  state with an unsettled request can answer `409 unsettled_request_state` or
  `409 unsettled_clearance_reserved`. It accepts
  `accept_unsettled_request_risk` (advertised as
  `unsettled_request_override_version` 1 in `/oa/v1/status`). A management
  client may send it only after showing the owner the challenge risk and
  getting an explicit acknowledgement. `409 receipt_journal_missing` carries
  the state's nullifier in `error.nullifier`. The daemon's management API
  forwards these three codes, and `ownership_proof_sent` (below), in its
  error body's `code` field; its `POST /admin/withdrawal/quote` accepts
  `accept_unsettled_request_risk`,
  `POST /admin/withdrawal` refuses it, and withdrawal status adds
  `note_expiry`.
- The companion's `/oa/v1/lease` answers `409 clearance_reserved_state` when
  the server holds a clearance for the note's current state (for example after
  the operator's release): no chat request can settle it. `zkapi-clientd`
  shows that code in the chat error with the remedy, **withdraw**.
- On a vault below `vault_revision` 2 the companion records in its
  reservation (`ownership_proof_sent` in `oa-withdrawal.json`), before a
  clearance request carrying the ownership proof leaves, that the proof may
  have left; the generic `/wallet/withdraw` close records it in
  `oa-ownership-proof-sent.json`. Such a reservation is never released:
  `/oa/v1/withdraw/release`, and so **repair**, refuse it with
  `409 ownership_proof_sent`, even after the server reports the nullifier
  unknown, and no chat request is made from that state (while the
  reservation stands, `/oa/v1/lease` answers `409 withdrawal_conflict`, as for
  any reservation, which the daemon's chat API reports as
  `409 withdrawal_pending`; after the generic close, chats there answer
  `409 ownership_proof_sent`). Choosing **withdraw** again completes the
  close. A reservation saved before the field existed
  counts as sent when the indexer holds the reserved state's note leaf at its
  note ID, unless that state had an unsettled request whose risk the owner
  never acknowledged; while the indexer cannot answer, nothing is released.
- A relayed escape accepted as withdrawal evidence whose receipt also carries
  `EscapePayoutDeferred` for the note and destination (only a
  `vault_revision` 2 vault emits it) completes as credited, not paid: the
  withdrawal status adds `payout_credited`, `vault_address` and
  `claim_calldata` (`claimEscapePayout(destination)`, selector `0x88c10aee`),
  and the companion's withdrawal status adds `escape_payout_credited`. A later
  deposit keeps the credit in the funding record's `credited_payouts`
  (validated on load; a damaged entry is refused, not dropped), and funding
  and withdrawal statuses list it under `escape_payout_credits` until
  `escapePayoutCredits(destination)` reads zero.

## Compatibility

Clients against each server state (`legacy clearance` is
`ZKAPI_ALLOW_LEGACY_CLEARANCE`):

| Client | Legacy deployment, server not upgraded | Legacy deployment, upgraded, legacy clearance on | Legacy deployment, upgraded, legacy clearance off | Hardened deployment |
| --- | --- | --- | --- | --- |
| Browser SDK from earlier releases | All flows, with the old risks | All flows, but mutual close fails with `503 legacy_clearance_capacity` while anyone keeps the shared proof-less budget exhausted; escape still works | Mutual close fails with `400 clearance_ownership_required`; escape still works | Not usable: pinned to the legacy vault |
| Browser SDK from this release, legacy profile (no capability keys) | All flows; clearance without proof | All flows; when the proof-less budget is spent (`503 legacy_clearance_capacity`) the proof is sent instead, except at a state whose request proof left the device and never settled, where mutual close then refuses with `409 transmitted_anchor_ownership_unsafe` | All flows: the proof is sent after the `400`, except at a state whose request proof left the device and never settled, where mutual close refuses with `409 transmitted_anchor_ownership_unsafe` and escape is refused, until a request from that state settles | Not usable |
| Browser SDK from this release, legacy profile with `"clearance_ownership_proof": "optional"` (required once the server is upgraded, Phase 2) | All flows; the old server ignores the proof | All flows; the proof is sent except at a transmitted state, where only the proof-less clearance is sent (it uses the shared budget, and `503 legacy_clearance_capacity` there refuses with `transmitted_anchor_ownership_unsafe`) | All flows, except at a state whose request proof left the device and never settled, where mutual close refuses with `409 transmitted_anchor_ownership_unsafe` and escape is refused, until a request from that state settles | Not usable |
| Browser SDK from this release, hardened profile (`vault_revision` 2) | Not usable | Not usable | Not usable | All flows |
| `zkapi-clientd` 0.1.6 and earlier | All flows | All flows, but withdrawals fail with `503 legacy_clearance_capacity` while anyone keeps the shared proof-less budget exhausted (clientd has no escape) | Withdrawals fail with `400 clearance_ownership_required`; the note stays reserved locally and recovers after an upgrade (clientd has no escape) | Not usable |
| `zkapi-clientd` built from this release, current manifests | Needs the upgraded indexer; ownership proof ignored by the old server | All flows | All flows; at a note state with an unsettled request (in `request_archive/`) a withdrawal first needs one chat request, or, once the note expired or the server holds a clearance for the state, the owner's acknowledged ownership proof | Not usable |
| `zkapi-clientd` pinned to the hardened vault | Not usable | Not usable | Not usable | Needs the manifest work listed under Phase 2 |

Services:

| Pair | Compatible |
| --- | --- |
| Signer from this release + earlier challenger | Yes, while a challenge's gas limit (about 7.53M) x the signer's fee cap fits both `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` and the node's `--rpc.txfeecap` (1 ETH each by default, so a fee cap of at most about 132.7 gwei). With no fee proposals it bids the fee cap and the default tip. A larger bid is refused (`tx_fee_above_cap`, or `upstream_tx_fee_cap` from the node); that challenger retries it on the same nonce and holds back later challenges. |
| Earlier signer + challenger from this release | No: the signer refuses the fee fields (`signer_refused`, critical). |
| Challenger from this release + earlier API server database | No: there is no `deployment_binding` row and the schema is older; the challenger exits. |
| Earlier challenger + API server from this release | Do not run it: it writes to the database and treats reserved leases as evidence, which burns nullifiers on a legacy vault. |
| Indexer from this release + earlier server, challenger or clients | Yes: response changes are additive. |
| Earlier indexer + challenger from this release | Works with a heuristic divergence check and a permanent `unsupported` warning. |
| Earlier indexer + `zkapi-clientd` from this release | Deposits are not signed and withdrawals wait: the snapshot has no block metadata. |

## Before you start

Run these checks against the legacy deployment before Phase 0. The examples
assume the Docker deployment; set:

```sh
export VAULT=0xREPLACE_WITH_VAULT RPC_URL=https://REPLACE_WITH_READ_RPC DEPLOY_BLOCK=REPLACE
dc() { sudo docker compose -f docker/aws/compose.yml --profile challenge "$@"; }
DATA_DIR=/var/lib/zkapi API_URL=http://127.0.0.1:8080
```

Use for `RPC_URL` a read RPC independent of the indexer's. `DATA_DIR` is the
deployment's data directory (`ZKAPI_DATA_DIR`) and `API_URL` its gateway on the
VM (`ZKAPI_HTTP_PORT`, 8080 by default). On a VM shared with the hardened
deployment, `dc`, `DATA_DIR` and `API_URL` change for the legacy deployment in
Phase 1. Item 7 also uses `INDEXER_RPC_URL` (the `RPC_URL` of `indexer.env`)
and `NATIVE_BILLING_RPC_URL` (`ZKAPI_NATIVE_BILLING_RPC_URL` of
`deployment.env`).

1. **Vault state.**

   ```sh
   for getter in 'owner()(address)' 'paused()(bool)' 'treasury()(address)' \
       'challengePeriod()(uint64)' 'noteTtl()(uint64)' 'nextNoteId()(uint32)'; do
     printf '%s ' "$getter"; cast call "$VAULT" "$getter" --rpc-url "$RPC_URL"
   done
   TREASURY=$(cast call "$VAULT" 'treasury()(address)' --rpc-url "$RPC_URL")
   cast call "$TREASURY" --value 1gwei --from "$VAULT" --rpc-url "$RPC_URL"
   ```

   The last call simulates a payment from the vault to its treasury. It prints
   `0x` while the treasury accepts ETH (an account without code also prints a
   warning). `execution reverted` means that every exit with an operator share
   and every expiry claim on the legacy vault reverts; see Phase 0, step 8.

2. **Pending escapes and their evidence.** List every pending escape with its
   deadline and the server's record for its nullifier:

   ```sh
   N=$(cast call --json "$VAULT" 'nextNoteId()(uint32)' --rpc-url "$RPC_URL" | jq -r '.[0]')
   for i in $(seq 0 $((N - 1))); do
     status=$(cast call --json "$VAULT" 'notes(uint32)(bytes32,uint128,uint64,uint8)' "$i" --rpc-url "$RPC_URL" | jq -r '.[3]')
     [ "$status" = 2 ] || continue
     pending=$(cast call --json "$VAULT" 'pendingWithdrawals(uint32)(bool,uint256,uint256,uint128,address,uint64)' "$i" --rpc-url "$RPC_URL")
     nullifier=$(cast to-hex "$(echo "$pending" | jq -r '.[2]')")
     echo "note $i deadline $(echo "$pending" | jq -r '.[5]') nullifier $nullifier"
     sudo sqlite3 -readonly "$DATA_DIR/server.db" \
       "SELECT n.status, n.reservation_kind, l.status, l.key_source, l.key_hash IS NOT NULL FROM nullifiers n LEFT JOIN openrouter_leases l ON l.request_nullifier = n.nullifier WHERE n.nullifier = '$nullifier';"
   done
   ```

   Take numbers for shell arithmetic from `cast call --json`, as here: plain
   `cast call` annotates a decoded number of 10,000 or more (`10000 [1e4]`),
   which breaks the arithmetic, and the loop would then list nothing.

   The upgraded challenger contests an escape whose nullifier has a `Finalized`
   record. It waits on a `Reserved` record until the upgraded server finalizes
   it: an issued lease by its settlement deadline, and a provisioning lease at
   zero once its settlement is due. It then contests the escape too, even at
   zero charge; on a legacy vault that consumes the nullifier, and the owner
   exits from the signed successor state. Nullifiers with no record or only a
   `ClearanceReserved` record are honest exits and are not contested, and
   neither is a `Reserved` record without a lease row, which nothing finalizes.
   Schedule Phase 0 so that the new challenger runs well before the nearest
   deadline it must meet. A lease created before the upgrade gets its
   settlement deadline when the new server first sees it: the later of its
   expiry and that moment, plus `SETTLEMENT_GRACE_SECONDS` and
   `ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS`. If that would fall after an
   escape's deadline minus a quarter of `challengePeriod()`, lower
   `ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS` for the first start (to no
   less than `SETTLEMENT_GRACE_SECONDS` + 900), then restore it; each lease
   keeps the deadline it received.

3. **Signing seeds under the new policy.** Build the new images (Phase 0, step
   1) and run `dc run --rm --no-deps --entrypoint zkapi server signing-keys`. If
   it refuses the production seeds, this release cannot serve that vault: keep
   the earlier server binary for it, deploy a hardened vault with new seeds, and
   drain the legacy one (Phases 1 to 4). Keeping the earlier server also means
   keeping the earlier challenger, which runs from the same image: the new
   challenger refuses a database without the `deployment_binding` row that only
   the new server writes. That vault therefore keeps the earlier API server and
   challenger behaviours listed under [Rollback](#rollback), and Phase 4's
   "disable legacy clearance" does not apply to it, because the earlier server
   always signs proof-less clearance. Drain it promptly. In the Docker
   deployment the indexer, server and challenger share one image tag, and
   Phase 0, step 1 sets a new one. Run that stack from the previous release's
   checkout and `ZKAPI_IMAGE_TAG`: a `dc up` with the new tag starts this
   release's server, which refuses the seeds, and its challenger, which exits,
   leaving no API and no challenger. The stack thus also keeps the earlier
   indexer, gateway and signer, so skip Phase 0 for it except step 8 (owner
   policy), and do not ship this release's `zkapi-clientd` to it in Phase 2:
   without the upgraded indexer its deposits are not signed and its
   withdrawals wait (see [Compatibility](#compatibility)). If the seeds derive
   a development key, follow
   [the compromise procedure](#if-development-or-mismatched-keys-were-ever-served).

4. **Served keys against the vault.** Compare the attestation with the vault's
   getters as numbers; `cast call` without a return type prints the raw
   32-byte word, and the attestation omits leading zeros:

   ```sh
   for getter in stateSigningKeyX stateSigningKeyY clearanceSigningKeyX clearanceSigningKeyY; do
     cast to-dec "$(cast call "$VAULT" "$getter()" --rpc-url "$RPC_URL")"
   done
   curl -fsS "$API_URL/v1/attestation" \
     | jq -r '.state_signing_key.x, .state_signing_key.y, .clearance_signing_key.x, .clearance_signing_key.y' \
     | while read -r value; do cast to-dec "$value"; done
   ```

5. **Keys the server served in the past.** Every archived request must carry the
   vault's state key. Run on a copy of the database:

   ```sh
   sudo sqlite3 -readonly "$DATA_DIR/server.db" \
     "SELECT json_extract(request_inputs_json, '$.state_signing_key_x') AS k, count(*) FROM nullifiers WHERE request_inputs_json IS NOT NULL GROUP BY k;
      SELECT json_extract(api_request_json, '$.public_inputs.state_signing_key_x') AS k, count(*) FROM openrouter_leases GROUP BY k;"
   ```

   Any other value, in particular the development state key
   `0x2b8cfd91b905cae31d41e7dedf4a927ee3bc429aad7e344d59d2810d82876c32`, means
   [the deployment is compromised](#if-development-or-mismatched-keys-were-ever-served).

6. **Settlement and clearance snapshot.**

   ```sh
   sudo sqlite3 -readonly "$DATA_DIR/server.db" \
     "SELECT key_source, status, count(*) FROM openrouter_leases WHERE status <> 'finalized' GROUP BY 1, 2;
      SELECT status, reservation_kind, count(*) FROM nullifiers GROUP BY 1, 2;"
   ```

   If unsettled leases of a key source other than the one this release will
   run with remain, the upgraded server refuses to start until they drain; see
   [Changing the key source](native-eth-billing.md#changing-the-key-source).

   Proof-less clearance reservations made by the old endpoint stay reserved;
   after the upgrade they are the rows with
   `status = 'ClearanceReserved' AND clearance_auth IS NULL`. Never delete them:
   a clearance signature was returned for each, and deleting the reservation
   would let that state be both spent for service and closed at its earlier
   balance.

7. **RPC capabilities.** The indexer's RPC must answer an EIP-1898 call and
   `eth_getBlockByHash`; the native billing RPC must serve `CHAIN_ID` and the
   `finalized` tag:

   ```sh
   HASH=$(cast block latest --field hash --rpc-url "$INDEXER_RPC_URL")
   cast rpc eth_call "{\"to\":\"$VAULT\",\"data\":\"0xfdab463d\"}" "{\"blockHash\":\"$HASH\",\"requireCanonical\":true}" --rpc-url "$INDEXER_RPC_URL"
   cast rpc eth_getBlockByHash "$HASH" false --rpc-url "$INDEXER_RPC_URL" | jq -r .number
   cast chain-id --rpc-url "$NATIVE_BILLING_RPC_URL"
   cast block finalized --field number --rpc-url "$NATIVE_BILLING_RPC_URL"
   ```

   The indexer's RPC must also come from a provider other than the `rpc_url`
   that clients pin. `zkapi-clientd` activates a deposit, and accepts a
   withdrawal, only when the vault read through its pinned `rpc_url` and the
   indexer's tree agree; an indexer that reads the chain through the same
   provider lets that provider control both. Compare the hosts of these pinned
   values, and of the browser configs that hosts ship, with `INDEXER_RPC_URL`:

   ```sh
   jq -r .rpc_url zkapi-clientd/internal/zkapi/deployments/*.json
   jq -r .trusted_deployment.rpc_url sdk/assets/config/*.json
   ```

   If any of them uses the indexer's provider, move `RPC_URL` in `indexer.env`
   to another provider before Phase 0, step 4, and repeat the checks above
   with it.

   The `rpc_url` that `zkapi-clientd` pins must itself serve
   `eth_getBlockByHash` and `eth_call` of the vault's `currentRoot()` (see
   [Breaking changes](#breaking-changes)). Check each manifest's own provider:

   ```sh
   for m in zkapi-clientd/internal/zkapi/deployments/*.json; do
     R=$(jq -r .rpc_url "$m"); V=$(jq -r .contract_address "$m")
     H=$(cast block latest --field hash --rpc-url "$R")
     echo "$m: $(cast rpc eth_getBlockByHash "$H" false --rpc-url "$R" | jq -r .hash) (expect $H)"
     cast call "$V" 'currentRoot()(uint256)' --rpc-url "$R"
   done
   ```

   `cast` does not hash the header; the companion does, with the
   go-ethereum version in `zkapi-clientd/go.mod`, and signs no deposit when
   the hash does not match. After a hard fork that changes the block header,
   confirm one deposit on Sepolia with the release build before shipping it.

   Also find the `--rpc.txfeecap` of the node behind the signer (the upstream
   `ZKAPI_CHALLENGE_RPC_URL` of `signer.env`); the node does not report it.
   geth and reth refuse to relay a transaction whose gas limit x
   `maxFeePerGas` exceeds it, 1 ETH by default. A hosted provider's cap usually
   cannot be raised. Phase 0, step 2 sets the transaction fee cap to that value.

8. **Direct launches.** A server started outside the container must pass
   `--native-price-max-age-seconds` and `--native-price-feed-decimals` equal to
   its published manifest; the default changed from 3600 to 4500.

## Phase 0: upgrade the existing deployment in place

Upgrade the legacy deployment's own services: same vault, same data directory,
same sender. Do not point anything at a new vault. Plan a window with no
challenge deadline close (see Before you start, item 2); the API is down for a
few minutes during step 6.

1. **Build.** Check out the release, set a new `ZKAPI_IMAGE_TAG` in the
   operator's Compose environment file so the previous images stay available
   for rollback, and build:

   ```sh
   dc build server gateway signer
   ```

   Compose reads that file only if it is its default `.env` file or the `dc`
   alias passes it with `--env-file`. Otherwise the build replaces the images
   under the tag Compose already used (`note-bound-v1` when none is set), and
   the previous images stay reachable only by ID.

2. **Configuration.**
   - `deployment.env`: add `ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS=21600`,
     `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` (the node's `--rpc.txfeecap` in wei,
     `1000000000000000000` for the 1 ETH default), `INDEXER_CONFIRMATIONS=12`,
     `INDEXER_MAX_HEAD_AGE_SECS=180`, and `ZKAPI_ALLOW_LEGACY_CLEARANCE=true`.
     Legacy clearance must stay on while clients from earlier releases may
     withdraw: without it their mutual close fails, and `zkapi-clientd` 0.1.6
     and earlier have no other exit. Its proof-less budget
     (`ZKAPI_LEGACY_CLEARANCE_MAX_PER_MINUTE`, default 60 per minute per server
     process) is one pool that anyone can exhaust every minute with junk
     nullifiers, each of which stays reserved permanently. Keep the legacy
     window as short as Phase 4 allows, declare the capability in Phase 2, and
     alert on `legacy_clearance_rejected_total` (see Residual risks).
   - `server.env`: both seeds, which passed Before you start, item 3.
   - `signer.env`: delete `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI` and set
     `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` (required on Mainnet); see
     [the signer README](../docker/aws/signer/README.md). Set
     `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` to the upstream node's `--rpc.txfeecap`
     unless that is the default 1 ETH, and give `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`
     in `deployment.env` the same value. Until step 6 the earlier challenger
     bids this fee cap on every challenge, so keep it within the transaction fee
     cap / 7.6M gas (about 131.6 gwei at 1 ETH; see step 5).
   - `challenge.env`: add `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` and
     `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI`, no higher than the signer's
     caps (its tip cap defaults to 10 gwei), with the priority cap at least twice
     the daemon's priority fee (default 2 gwei).
   - Fund the sender with at least (pending escapes + reverted attempts + 1) x
     the lower of 7.6M gas x fee cap and `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`. A fee
     cap above about 131.6 gwei (7.6M gas x fee cap above 1 ETH) can be used
     only after the node's `--rpc.txfeecap` and `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`
     (in `signer.env` and `deployment.env`) are raised together. The signer
     warns `balance_below_required` below its own, larger figure (step 5).
   - Restrict the EC2 security group's inbound port to the
     `com.amazonaws.global.cloudfront.origin-facing` prefix list, so that the
     gateway's per-source limits see CloudFront's addresses only.

3. **Gateway.**

   ```sh
   dc up -d --no-deps --wait gateway
   ```

4. **Indexer.** The new indexer archives its version-1 checkpoint and replays
   from `DEPLOY_BLOCK`. Deposits and withdrawals that need Merkle paths, and the
   old challenger, wait until its view verifies.

   ```sh
   dc up -d --no-deps --wait indexer
   dc exec -T indexer curl -sS http://127.0.0.1:3001/health | jq '{status, served_block, root, next_note_id, missed_re_escape_count}'
   ```

   Compare its root and next note ID with the vault through `RPC_URL`, and
   check its pending escapes against the vault, as in
   [Indexer resync](../docker/aws/README.md#indexer-resync), step 1. A
   `missed_re_escape_count` above zero means that the indexer RPC's
   `eth_getLogs` dropped vault events, or a reorganization below the checkpoint
   replaced an escape (see Operations runbooks, Indexer divergence). The
   archived checkpoint, `indexer.cursor.v1-<unix_ms>.bak`, is the old mirror as
   it stood, never verified: it records its `last_processed_block` and the
   mirror's leaves but no root, and no tool in this release checks it against
   the vault. Keep it for forensics only, and never restore it (see
   [Rollback](#rollback)).

5. **Signer.** The new signer also serves the old challenger, which proposes no
   fees and therefore bids the fee cap. Until the challenger is upgraded in
   step 6, every challenge whose gas limit x fee cap exceeds
   `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` is refused with `tx_fee_above_cap` (one
   that exceeds only the node's `--rpc.txfeecap` with `upstream_tx_fee_cap`),
   and the old challenger retries it on the same nonce while holding back later
   challenges: at the default 1 ETH, keep the fee cap at most about 131.6 gwei.

   ```sh
   dc up -d --no-deps --wait signer
   dc exec -T challenger curl -sS -X POST http://signer:8547 -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"zkapi_signerStatus","params":[]}'
   ```

   Check that `tx_fee_cap_wei` (a hex quantity) is the node's `--rpc.txfeecap`.
   The signer cannot read the node's cap, so no warning covers a lower one; only
   `challenge_refused` audit lines with reason `upstream_tx_fee_cap` show it.
   Expect `warnings: []`, apart from two warnings that the default
   `ZKAPI_CHALLENGE_MAX_GAS` of 12M can raise while real challenges still sign:

   - `balance_below_required` while the balance is below `required_balance`,
     which is `ZKAPI_CHALLENGE_MAX_GAS` x fee cap (1.2 ETH at 100 gwei) and
     more than step 2's minimum for one challenge. Fund the sender up to it,
     or lower `ZKAPI_CHALLENGE_MAX_GAS` as below.
   - `tx_fee_cap_below_fee_cap` when the fee cap is above
     `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` / `ZKAPI_CHALLENGE_MAX_GAS` (about 83.3
     gwei at 12M gas) but within the limit above. Keep it in alerting, because
     it also covers a fee cap that real challenges cannot use; silence it only
     while `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` x 7.6M is at most
     `tx_fee_cap_wei`, and check that again after every fee-cap change.

   Lowering `ZKAPI_CHALLENGE_MAX_GAS` in `signer.env` toward the challenge's
   gas limit, then recreating the signer with
   `dc up -d --no-deps --wait signer`, clears both, but keep a margin above
   that limit. A challenge's gas limit is its gas estimate plus 20%, about
   7.53M as measured, and the signer refuses a larger one with
   `gas_limit_exceeds_cap`, which the upgraded challenger reports as
   `signer_refused`, critical at once, until the cap is raised. At 7.6M, a
   sender funded and capped as in step 2 raises neither warning, but a
   challenge 0.9% costlier than measured is refused. 8M leaves about 6%; it
   then needs a balance of at least 8M gas x fee cap, and a fee cap of at most
   125 gwei at 1 ETH, to raise neither.

6. **API server, then challenger.** Stop both, back up the data directory, then
   start the server first:

   ```sh
   dc stop challenger server
   sudo tar -C /var/lib -czf "/root/zkapi-before-hardening-$(date +%s).tgz" zkapi
   dc up -d --no-deps --wait server
   dc logs --tail=100 server
   ```

   Check for `server signing keys match the vault's immutable keys`, the
   `--allow-legacy-clearance` warning, `clearance_ownership_proof_required:
   false` and `legacy_clearance_window_limit: 60` in `/health`, and the
   attestation keys as in Before you start, item 4. The database migrates in
   place. Then start the challenger:

   ```sh
   dc up -d --no-deps --wait challenger
   dc exec -T challenger curl -sS http://127.0.0.1:3002/status \
     | jq '{status, alarms, config_warnings, indexer: .indexer.state, pending_escapes: .indexer.pending_escapes, tx_fee_ceiling: .sender.effective_tx_fee_cap_wei, detached_nonces, obligations: [.obligations[] | {note_id, state, severity, blocked_reason, detail, nonce, seconds_remaining}]}'
   ```

   `tx_fee_ceiling` must be the node's `--rpc.txfeecap` in decimal wei. Act on
   any `config_warnings` entry about the ceiling: a signer `tx_fee_cap_wei` that
   differs from the daemon's, or a fee cap above the ceiling, which bids never
   reach.

   The challenger keeps its checkpoint. A legacy-format pending transaction is
   replaced only by a bid that raises both fees by 10% over its gas price; until
   then `tip_cap_reached` may show. A nonce the old daemon reserved for
   lease-only evidence stays reserved until the server finalizes that request.
   A nonce it reserved with no known transaction, for example for a challenge
   that this release's signer refused after step 5, has no attempt record, so
   it is never released automatically. Once there is evidence, the challenge is
   sent on it within the transaction fee ceiling, provided a bid within the
   ceiling can be included before the deadline. If the deadline passes first,
   the missed obligation is blocked by `nonce_blocked` (`expired obligation
   retains unmined reserved nonce N, which an attempt may hold; resolve it at
   the signer`), and only once the escape is finalized does `/status` report
   `unmined nonce N of a completed or replaced note M requires signer
   intervention`; a nonce whose escape was finalized or replaced before the
   upgrade reports that at once. Look up the nonce's hashes (the obligation's,
   or `detached_nonces`) on a full node. If none is known and the nonce stays
   unmined, consume it with a zero-value transfer from the sender to itself at
   exactly that nonce, as in
   [Recovery and verification](challenge-service.md#recovery-and-verification);
   later notes wait until then.

   Before closing the window, set up alerting for the new signals, as in the
   Docker guide's [Monitoring](../docker/aws/README.md#monitoring) list. The
   earlier release had none of them:
   - the challenger's `/health` answering anything but 200, including no answer
     at all, and its container not running or unhealthy (`dc ps --all`). A
     stopped or crash-looping challenger reports nothing itself: the `exec`
     into it fails, and none of its own signals below can fire;
   - every `critical` alarm on the challenger's `/status`. A missed deadline,
     including an escape with evidence found paid out past its deadline, stays
     an alarm (`missed challenge deadline of note N`) for an hour.
     `evidence_invalid`, `evidence_db_error`, `indexer_invalid_response`,
     `indexer_diverged`, `signer_refused` and `upstream_tx_fee_cap` are
     critical at once, while every other blocked reason, `fee_reserve_held`,
     `tx_fee_cap_reached`, `tx_fee_above_cap` and `base_fee_above_max_fee`
     included, turns critical after `--critical-blocked-seconds`;
   - its warnings about the transaction fee ceiling, a fee the signer's node
     refused, and an indexer pending-escapes list that disagrees with the
     vault;
   - any increase of the indexer's `missed_re_escape_count`
     (`zkapi_indexer_missed_re_escapes_total`), paging on `event="finalized"`;
   - the signer's `challenge_refused` audit lines and its status warnings;
   - the server log lines `settlement required operator review` and
     `unreadable OpenRouter lease row cannot be settled` (see Settlement
     reviews under [Operations runbooks](#operations-runbooks)).

   Also schedule the online database backups described at the end of that
   section, if none run yet: the settlement runbooks below restore a corrupt
   saved request, and repair other fields by hand, from a backup.

7. **Settlement after the upgrade.** Every pre-upgrade lease receives its
   deadline. Provisioning leases finalize at zero once due, under the key
   issuance lock, so that no key is returned for a lease settled at zero; leases
   stuck on a configuration change settle from measured usage, and leases still
   failing at their deadline finalize at the solvency bound with a review.
   Within about TTL + grace + `ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS`,
   every row from Before you start, item 6 must reach `finalized`. A lease
   `cancelled` for a corrupt binding leaves its owner without an exit on the
   legacy vault: reopen it as under [Operations runbooks](#operations-runbooks),
   Settlement reviews. Check `/v1/dashboard/settlement` and handle each review;
   see [Monitoring](../docker/aws/README.md#monitoring).

8. **Owner policy for the legacy vault.** Its owner can still pause every new
   exit (escapes already started still finalize) while `claimExpired` and an
   instant `setTreasury` keep working. Every treasury payout must also
   succeed: while the treasury rejects ETH, every `mutualClose` and
   `finalizeEscapeWithdrawal` with an operator share and every `claimExpired`
   reverts (`NativeTransferFailed()`, `0xf4b3b1bc`), and only the owner's
   `setTreasury` can replace the treasury. Repeat the treasury check of Before
   you start, item 1, with the daily drain monitoring (Phase 3), and alert when
   it fails or users report that revert. Publish and follow a policy for the
   rest of its life:
   - never pause it; if `paused()` is true, unpause it now;
   - make no treasury change during the drain unless the treasury stops
     accepting ETH;
   - move ownership to a multisig or timelock with `transferOwnership(address)`
     (on a legacy vault this takes effect immediately and there is no
     `acceptOwnership()`, so verify the multisig address on that chain first);
   - never renounce ownership. After a renounce nothing can replace the
     treasury: if it stops accepting ETH and its own controller cannot fix it,
     the exit of every note with a spent balance is frozen for good. A renounce
     while paused also keeps the vault paused forever: no new exit can start,
     while `claimExpired`, which a legacy vault does not block while paused,
     sweeps every note that is not escaping to the treasury at its expiry.

## Phase 1: deploy the hardened vault

The hardened vault is a new deployment: new public manifest, new hostname, new
signer key and exclusive sender, and fresh data (database, indexer checkpoint,
challenge checkpoint). The legacy stack keeps running unchanged. Prefer a
separate VM. To share a VM, first move the legacy deployment into a second
Compose project as in
[Upgrades and running two deployments](../docker/aws/README.md#upgrades-and-running-two-deployments)
(stop all of its services for the move); the hardened deployment then uses the
default project and paths. From then on, run every command for the legacy
deployment with that project's settings: Phases 3 and 4, the checks they repeat
from Before you start, and the runbooks for its notes. In the shell you use for
it, set (with the data directory and HTTP port of that project's
`compose.env`):

```sh
dc() { sudo docker compose -p zkapi-legacy --env-file /etc/zkapi-legacy/compose.env -f docker/aws/compose.yml --profile challenge "$@"; }
DATA_DIR=/var/lib/zkapi-legacy API_URL=http://127.0.0.1:8081
```

Use the settings of Before you start for the hardened deployment. With them,
a legacy command reaches the hardened deployment instead: Phase 4's checks
would then read the hardened database and `/health`, and report legacy
clearance off while the legacy server still signs proof-less clearances.
Never repoint the legacy signer or challenger at the new vault.

1. **Parameters.** Decide them before deploying; the vault keeps them forever.
   - `OWNER`: a multisig, ideally behind a timelock. It can block every new
     exit without a time limit and schedule treasury changes. If you deploy
     with a temporary owner and then move ownership to the multisig, the
     multisig must call `acceptOwnership()`; until it does, `owner()` is still
     the temporary key.
   - `TREASURY`: receives spent shares and expired deposits.
   - `CHALLENGE_PERIOD_SECONDS`: the challenger's whole response time, which
     the settlement deadline must fit into twice over. Consider 48 to 72 hours
     instead of 24: it absorbs fee spikes, indexer rebuilds and outages, at the
     cost of a longer wait for escapes. It also sets `treasuryChangeDelay()`
     (at least two days) and `unpauseClaimGrace()` (at least one day).
   - `REQUEST_CHARGE_CAP=50000`, passed explicitly (the script default is
     1,000,000).
   - Seeds: generate new ones (recommended, so that an exposure of the legacy
     deployment's secrets cannot affect the new vault), or keep the existing
     seeds if they pass the policy.

2. **Keys and deployment.** Write the seeds into the new `server.env` and print
   the public keys, as in
   [Signing seeds](../docker/aws/README.md#signing-seeds). Deploy with
   `demo/contracts/script/Deploy.s.sol`, following its header and
   [the contract notes](deployment.md#contracts), passing the printed keys as
   `STATE_SIGNING_KEY_X/Y` and `CLEARANCE_SIGNING_KEY_X/Y`. Record the vault
   address (`NEW_VAULT` below), the proof adapter address and the vault's
   deployment block (its `DEPLOY_BLOCK`).

3. **Verify the vault.**

   ```sh
   for getter in 'owner()(address)' 'pendingOwner()(address)' 'treasury()(address)' 'paused()(bool)' \
       'challengePeriod()(uint64)' 'noteTtl()(uint64)' 'requestChargeCap()(uint128)' \
       'treasuryChangeDelay()(uint64)' 'unpauseClaimGrace()(uint64)' 'ROOT_HISTORY_WINDOW()(uint64)' \
       'ESCAPE_PAYOUT_GAS()(uint256)'; do
     printf '%s ' "$getter"; cast call "$NEW_VAULT" "$getter" --rpc-url "$RPC_URL"
   done
   ```

   `owner()` must be the multisig and `pendingOwner()` must be zero.
   `ESCAPE_PAYOUT_GAS()` must answer `100000`; a vault built from source
   without escape payout credits reverts there and would lock escapes to
   destinations that reject ETH. Compare the four key getters with the printed keys as
   numbers.

4. **Stack.** Configure the new deployment from the
   [Docker guide](../docker/aws/README.md): the new `VAULT_ADDRESS`,
   `DEPLOY_BLOCK` and keys, a signer with a new private key and
   `ZKAPI_CHALLENGE_VAULT` set to the new vault, a funded new sender in
   `challenge.env`, `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` set to the `--rpc.txfeecap`
   of the new signer's node in both `signer.env` and `deployment.env`, and
   `ZKAPI_ALLOW_LEGACY_CLEARANCE` unset: no client of a new vault predates
   ownership proofs. Check the settlement timing rule against the
   new `challengePeriod()`. Publish its `config.json` on a new hostname with its
   own CloudFront origin. Start it as described there, and set up its alerting
   from the Docker guide's [Monitoring](../docker/aws/README.md#monitoring)
   list, as in Phase 0, step 6. Also alert on the new vault's events: any
   `OwnershipTransferStarted` you did not send, `TreasuryChangeScheduled`,
   `Paused`, `Unpaused`, `TreasuryPaymentDeferred` and `EscapePayoutDeferred`
   (see [Operations runbooks](#operations-runbooks)). Monitoring that watched
   `OwnershipTransferred` for a `transferOwnership` call sees only the
   nomination's `OwnershipTransferStarted` until the new owner accepts.

5. **Acceptance.** Run the Docker guide's acceptance checks, `npm run
   test:e2e:v2` from the release checkout, and a funded lifecycle on the target
   network: deposit, a paid request, a mutual close (which sends an ownership
   proof), and on a test network a stale escape that the challenger contests.
   After that challenge, `cast call "$NEW_VAULT" 'usedNullifiers(uint256)(bool)'
   <nullifier>` is `false`, `challengedNullifiers(uint256)` is `true`, and the
   owner withdraws from the next state. Measure the real challenge gas for the
   sender's funding.

## Phase 2: publish clients

### Releases for the legacy deployment

Ship these right after Phase 0; they protect legacy users and are required
before Phase 4.

- **Browser SDK.** A release built from this source with the packaged legacy
  profiles unchanged runs in strict mode (no `vault_revision`), sends clearance
  without a proof first and with one after `400 clearance_ownership_required`
  or `503 legacy_clearance_capacity`, and keeps the transmitted-request archive.
  In strict mode the SDK never sends an ownership proof from a note state
  whose request proof left the device, whatever `clearance_ownership_proof`
  says. On this vault that proof is an escape that the request proof's holder
  could challenge, which burns the nullifier. A mutual close at such a state
  checks the request's status with the server, then sends only the proof-less
  clearance. If the server asks for a proof, the SDK refuses with
  `409 transmitted_anchor_ownership_unsafe` and leaves the note usable: a chat
  from it that settles moves it to a state that closes normally. Suppose a
  mutual close sent its ownership proof and the gateway answers
  `429 gateway_rate_limited` beyond the SDK's retries. The note then stays
  withdrawal-only (`error.data.withdrawal_only: true`), so no request proof
  follows at that nullifier. Retrying the close, or escaping, completes it. At
  the Phase 3 cutoff, also set `"deposits": "closed"` in this profile.
  Tell users that an escape's destination cannot change after initiation and
  must accept ETH: on this vault an escape to a destination that rejects ETH
  never finalizes. This release's SDK simulates the vault's payout before it
  proves an escape and refuses such a destination with
  `escape_destination_unpayable`; a host passes
  `overrideDestinationCheck: true` only after the user confirms that address
  anyway.
  Once the legacy deployment's server is upgraded, declaring
  `"clearance_ownership_proof": "optional"` in the legacy profile's
  `trusted_deployment` (in `sdk/assets/config/mainnet.json` and `sepolia.json`,
  or the host's own browser config; then sync, verify and build as for the
  hardened profile below) is a required step, not an option. Without it, mutual
  close first sends a proof-less request that competes for the shared legacy
  budget, then falls back to the proof on `503 legacy_clearance_capacity` or
  `400 clearance_ownership_required`, at the cost of one extra round trip. With
  it, every clearance request carries the ownership proof and never uses the
  budget, except at a state whose request proof left the device: there the SDK
  sends only the proof-less clearance (see above). Browser SDKs from earlier
  releases and `zkapi-clientd` 0.1.6 and earlier never send a proof, so their
  mutual close fails while anyone keeps that budget spent (see
  [residual risks](#residual-risks-and-items-not-fixed)). Hosts update and
  reload every tab; the IndexedDB version is unchanged and older tabs keep
  working, but they do not write archive records. Users must not reset or
  export wallets.
- **`zkapi-clientd`.** A release built from this source with the current pinned
  manifests, whose native companion is rebuilt by
  `zkapi-clientd/scripts/prepare-zkapi.sh` from the unchanged pins in
  `zkapi-clientd/packaging/zkapi-source.env` and the updated `companion.patch`
  and `protocol-transport.patch`. It needs the indexer from Phase 0, reading
  the chain through a provider other than the manifests' `rpc_url` (Before you
  start, item 7), and its pinned `rpc_url` must pass that item's
  `eth_getBlockByHash` and `currentRoot()` checks. Tell users that deposits
  need a device clock within one day of chain time; otherwise the companion
  refuses them (`this device's clock differs from Ethereum's block time by
  more than a day`). Users stop
  `serve`, install the release, and start it again. The companion keeps
  set-aside request journals in `request_archive/` in its state directory and
  never prunes them. Users who back up the wallet must include that directory
  and must not delete files in it; a damaged record there counts as an
  unsettled request. Once a withdrawal's clearance request carrying the
  ownership proof has left the companion, the note state stays reserved for
  that withdrawal: **repair** cannot release it (`ownership_proof_sent`), no
  chat request is made from it, and the user finishes the close by choosing
  **withdraw** again. A reservation saved by an earlier build is judged by
  the note's leaf in the indexer's tree (see
  [Breaking changes](#breaking-changes)). A deposit in
  `verification_conflict` is re-checked by `zkapi-clientd config` and repaired
  with `zkapi-clientd config --menu`, then **repair**; this includes a retry
  refused because an earlier deposit of the same note, reported as reverted,
  landed; see
  [chain verification and recovery](../zkapi-clientd/docs/CLI_ZKAPI.md#chain-verification-and-recovery).
  Tell users not to downgrade to 0.1.6 or earlier while a deposit is confirming
  or in `verification_conflict`: older releases activate the RPC's note ID
  without these checks. The code does not warn about this. Its companion checks
  a journaled request's quote only for internal consistency and its chain, so a
  later release that changes `native_price_feed_address`,
  `native_price_feed_decimals` or `native_price_max_age_seconds` keeps a wallet
  with a request in flight loadable. A request the server never admitted is
  retired once its quote expires, on the next lease at its original model
  budget (a lease at another budget reports `lease_pending`) or when a
  withdrawal settles. 0.1.6 and earlier cannot open such a wallet, so ship a
  pin change only in a release built with this `companion.patch`, and tell
  users not to downgrade below it while a request is in flight.

### Releases for the hardened deployment

- **Browser SDK.** Add a hardened profile to `sdk/assets/config/mainnet.json`
  and `sepolia.json` (or the host's own browser config): a new
  `trusted_deployment` with the new deployment ID, vault, keys, hostnames and
  RPC, plus `"vault_revision": 2` and `"clearance_ownership_proof": "required"`.
  `unsettled_request_escape_after_seconds` (default 43200) must stay above TTL +
  grace + the settlement deadline. Run `node scripts/sync-sdk-assets.mjs`, then
  `npm run verify:assets`, then build (`npm run build:browser`,
  `npm run build:mainnet`). Keep a legacy-exit build or profile pinned to the
  legacy vault, without `vault_revision` and with
  `"clearance_ownership_proof": "optional"` and, after the Phase 3 cutoff,
  `"deposits": "closed"`, so that owners can still withdraw legacy notes in
  strict mode. Hosts that offer the escape override show
  `escape_override_warning`, from the refusal or from
  `snapshot().config.escape_override`, and pass the
  `escape_override_acknowledgement` given with it as
  `overrideUnsettledRequest`, never one derived from the refusal code (see
  [Breaking changes](#breaking-changes)): a host that always passes `true`
  leaves its users no exit while a false receipt claim stands. Surface
  `request_archive_limit` as a prompt to withdraw that balance. An escape's
  destination cannot change after initiation, so tell users to choose one
  that accepts a plain ETH transfer within 100,000 gas, such as an ordinary
  account; `client.checkEscapeDestination(destination)` checks an address
  before the user confirms it, and an escape to a failing one proceeds with a
  warning. The SDK reports an escape whose payout the vault credited
  (`EscapePayoutDeferred`) as credited (`payoutCredited: true`, with
  `payoutVerified: false` until a claim is proven), lists it in
  `client.creditedEscapePayouts` and delivers it with
  `client.claimEscapePayout(recordId)`, sent from the connected account,
  which pays only gas. Show it as credited, never as returned, and offer the
  claim; while the destination still rejects ETH, the claim fails its gas
  estimate (`native_transfer_failed`) before the wallet is asked to sign, and
  the credit stays. The SDK detects only escapes this browser started, so
  keep relaying the operator's credit announcements to other owners (see
  [Escape payout credits](#operations-runbooks)).
- **Wallet ordering in browsers.** The SDK keeps one selected note per origin
  and refuses to open a wallet for another deployment while it holds durable
  state (`This browser contains a wallet for <id>. Switch back to that deployment
  before using or withdrawing it.`). Before configuring the SDK, hosts call
  `readBrowserWalletHoldings()` from `@openanonymity/zkapi-browser-sdk/store`.
  It lists each deployment this browser still holds state for: the runtime
  slot's deployment while that slot holds a note, journal, lease, pending
  deposit, deposit draft, prepared withdrawal or unfinished late attempt
  (`runtime: true`), and every deployment with an open withdrawal record (a
  set-aside mutual close, a pending or challenged escape, a close awaiting
  finality, or a finalization in flight). While the legacy deployment is
  listed, configure the legacy profile and offer its withdrawals. Configure the
  hardened profile only when it is not listed. If both are listed, the entry
  with `runtime: true` comes first and is the only one that can load. Setting
  a withdrawal aside is not an exit: the withdrawal stays bound to the legacy
  deployment. A loaded runtime also lists other deployments' open withdrawals
  in `snapshot().config.other_deployment_withdrawals`; do not offer a deposit
  while that list is non-empty. A finalized escape whose payout the hardened
  vault only credited is not listed, because it holds no note;
  `readBrowserWalletPayoutCredits()` and
  `snapshot().config.other_deployment_credits` report it, without blocking a
  deposit. Its claim needs that deployment's profile, which loads only while
  the runtime slot holds no other deployment's state; anyone can also call
  `claimEscapePayout(destination)` on that vault. Never clear site data to get
  past the check.
  Hosts that route protocol calls through a same-origin rewrite need a rewrite
  for the new hostname as well.
- **`zkapi-clientd`.** A release pinned to the hardened vault needs work that
  this release does not include: new pinned manifests (`rpc_url`,
  `indexer_url`, `protocol_server_url` and `note_ttl_seconds` are required, plus
  `"vault_revision": 2` and `"clearance_ownership_proof": "required"`), a guard
  for profiles of the retired deployments, and removal of the two pinned
  manifest-migration exceptions in `deployments.go`. A profile that saved the
  legacy manifest is refused by a client pinned to another one (`deployment
  manifest does not match this client's pinned configuration`), so users
  withdraw with the legacy release first. There is also no way yet to abandon an
  unmined deposit; a pending deposit blocks `/admin/return`.

## Phase 3: stop deposits to the legacy vault and drain it

Clients pin the legacy hostnames, which must keep serving the legacy stack until
the drain completes. On a shared VM, run this phase's commands and Phase 4's
with the legacy deployment's settings (see Phase 1). Once the hardened releases
are out:

1. **Deposit cutoff.** Announce a date. At the cutoff, stop serving the two
   routes that `zkapi-clientd` deposits need, `/v1/tree/next-note-id` and
   `/v1/tree/notes/{id}/zero-path`, on the legacy deployment's public gateway.
   Add to the `nginx.conf` of the checkout that the legacy deployment is built
   from, before `location /v1/tree/`:

   ```nginx
   # Deposit cutoff: the drained vault no longer offers new deposit paths.
   location = /v1/tree/next-note-id { return 410; }
   location ~ ^/v1/tree/notes/[0-9]+/zero-path$ { return 410; }
   ```

   Then set a new `ZKAPI_IMAGE_TAG` for the legacy deployment, so that its
   previous images stay available, and build and start the gateway. That tag
   names all three images, so build all of them under it:

   ```sh
   dc build server gateway signer
   dc up -d --no-deps --wait gateway
   ```

   On a shared VM, use a checkout of the release that only the legacy
   deployment builds from, and put its tag in `/etc/zkapi-legacy/compose.env`.
   The gateway image is built from the checkout's `nginx.conf`, and images are
   shared by tag across projects: a gateway that the hardened deployment builds
   or recreates from the same checkout or tag would also answer 410 to its own
   deposits.

   `zkapi-clientd` then fails before building a deposit transaction. The
   browser SDK does not use these routes: it takes the deposit slot from
   `/v1/tree/snapshot`, which withdrawals also need, so the cutoff does not
   stop its deposits. At the cutoff, ship browser builds whose legacy and
   legacy-exit profiles set `"deposits": "closed"` in `trusted_deployment`,
   then sync, verify and build as in Phase 2. The SDK then refuses a new
   deposit with `409 deposits_closed` before any chain read, note secret or
   wallet prompt, and reports `snapshot().config.deposits: "closed"` so the
   host can hide its deposit action. A deposit already started stays
   completable and recoverable for its original amount. Builds older than this
   release ignore the setting, so remove the deposit action from them. The
   drain monitoring below keeps tracking `nextNoteId()`. Keep
   the root, paths, snapshot, clearance, recovery and every other route, and
   keep the internal indexer unchanged: the challenger reads zero-paths from it
   directly. Never pause the legacy vault to stop deposits; anyone can still
   deposit by building a path from chain data, and such notes drain like any
   other.

2. **Drain monitoring.** Track the legacy notes daily (Before you start, items 1
   and 2): notes by status, pending escapes, `nextNoteId()` in case of late
   deposits, and whether the treasury still accepts ETH. A note's expiry is
   its `expiryTs`, the deposit time plus `noteTtl()` rounded up to a whole day.
   Plan the legacy stack's end from the latest `expiryTs` among open notes,
   plus one challenge period for escapes started near it.

   Anyone can finalize an escape after its deadline, and the call also pays
   the treasury, so finalize any that their owners leave pending. For each
   pending escape past its deadline (from the loop of Before you start, item
   2), simulate it first:

   ```sh
   cast call "$VAULT" 'finalizeEscapeWithdrawal(uint32)' <noteId> --rpc-url "$RPC_URL"
   ```

   It prints `0x` when the finalization would succeed. A revert with data
   `0xf4b3b1bc` (`NativeTransferFailed()`) while the treasury check of Before
   you start, item 1, still prints `0x` means the escape's destination rejects
   ETH: on a legacy vault that escape cannot finalize while it does, and
   nothing can challenge or change it any more. Record its note ID,
   destination and final balance (`.[4]` and `.[3]` of that loop's
   `pendingWithdrawals` output), and tell its owner through the hosts.

3. **Expired notes.** Exits remain possible after expiry until someone calls
   `claimExpired`, which anyone can do; on a legacy vault it pays the full
   deposit to the treasury. Publish what the operator does with such deposits
   (for example, when it claims them and how an owner can ask for a refund
   outside the protocol), and announce expiry dates early.

## Phase 4: disable legacy clearance and retire the legacy stack

1. **Disable legacy clearance** only after the `zkapi-clientd` and browser SDK
   releases for the legacy deployment are adopted and users of older releases
   were warned. Watch the warning `signing a legacy clearance without a note
   ownership proof` and `legacy_clearance_window_used` in `/health`, and count
   recent proof-less reservations:

   ```sh
   sudo sqlite3 -readonly "$DATA_DIR/server.db" \
     "SELECT count(*) FROM nullifiers WHERE status = 'ClearanceReserved' AND clearance_auth = 'legacy' AND created_at > strftime('%s', 'now', '-7 days');"
   ```

   Then remove `ZKAPI_ALLOW_LEGACY_CLEARANCE` from the legacy deployment's
   `deployment.env` (`/etc/zkapi-legacy/deployment.env` on a shared VM), or set
   it to `false`, and recreate the server:

   ```sh
   dc up -d --no-deps --wait server
   curl -fsS "$API_URL/health" | jq '{clearance_ownership_proof_required, legacy_clearance_window_limit}'
   ```

   It must report `true` and `0`. Older SDK builds can still
   escape; `zkapi-clientd` 0.1.6 and earlier cannot withdraw until they
   upgrade. With legacy clearance off, a browser SDK from this release in
   strict mode cannot mutual-close a note at a state whose request proof left
   the device and never settled. It refuses with
   `transmitted_anchor_ownership_unsafe`, and escape there is refused too.
   Such an owner exits after a chat from that state settles; a state whose row
   the operator changed under **Receipt journal missing** accepts no chat, so
   for such an owner the remedy works only while legacy clearance is on. Before
   disabling, check that no such users remain, or announce this.
   `zkapi-clientd` from this release asks for the same at a state with an
   unsettled request: one chat request first, or the owner's typed
   acknowledgement once the note expired or the server holds a clearance for
   the state.

2. **Retire the legacy stack** only when every legacy note is closed (status 3,
   by an exit or an expiry claim), no escape is pending, and the last challenge
   deadline has passed. The one exception is an escape stuck because its
   destination rejects ETH (Phase 3, step 2): once its deadline has passed it
   does not block retirement, since finalizing it needs only the chain should
   the destination ever accept ETH. Record it as described there first.
   Retiring earlier strands the remaining notes: without the API and indexer,
   clients can neither close nor build escape paths. Then, with the legacy
   deployment's `dc` (see Phase 1 for a shared VM):
   1. stop the challenger and signer, and move the sender's remaining balance;
   2. stop the server, indexer and gateway, and remove the legacy origin;
   3. archive the data directory as sensitive data (it holds request proofs and
      transcripts);
   4. keep the legacy client releases available for reference.

## Operations runbooks

**Treasury change on the hardened vault.** From the owner (the commands assume
an owner key in a Foundry keystore; a Safe owner submits the same calls as Safe
transactions):

```sh
cast send "$NEW_VAULT" 'setTreasury(address)' "$NEW_TREASURY" \
  --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"   # emits TreasuryChangeScheduled
cast call "$NEW_VAULT" 'pendingTreasury()(address)' --rpc-url "$RPC_URL"
cast call "$NEW_VAULT" 'pendingTreasuryReadyAt()(uint64)' --rpc-url "$RPC_URL"
cast call "$NEW_VAULT" 'totalPausedDuration()(uint64)' --rpc-url "$RPC_URL"
cast send "$NEW_VAULT" 'acceptTreasury()' \
  --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"   # emits TreasurySet
cast send "$NEW_VAULT" 'cancelTreasuryChange()' \
  --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"   # any time, also while paused
```

`pendingTreasuryReadyAt()` is on the active clock, wall time minus all paused
time: while unpaused, `acceptTreasury()` succeeds from
`pendingTreasuryReadyAt() + totalPausedDuration()`, and every later pause pushes
that further. `setTreasury` and `acceptTreasury` revert `Paused()` while paused,
and `acceptTreasury` reverts `TreasuryChangeNotReady()` before the time. Monitor
`TreasuryChangeScheduled`, `Paused` and `Unpaused` events; a scheduled change
gives users at least `treasuryChangeDelay()` of unpaused time to exit.

**Owner key rotation on the hardened vault.** Ownership moves in two steps, and
both work while paused: the current owner nominates the new one with
`transferOwnership(address)` (event `OwnershipTransferStarted`), and the new
owner completes the transfer with `acceptOwnership()` (event
`OwnershipTransferred`). Until the new owner accepts, the old key is still the
owner: it can pause, unpause, and replace or cancel the nomination
(`transferOwnership(address(0))`). Alert on any `OwnershipTransferStarted` you
did not send.

*If the current owner key may be compromised*, do not run the commands below:
whoever holds that key can replace a nomination before its acceptance, or
nominate and accept another address. Never send the nomination alone through
the public mempool. Sign both transactions in advance and submit them together,
nomination first, as one bundle to a block builder's private bundle endpoint
(`eth_sendBundle`), so that they are included atomically and consecutively in
one block or not at all. If the new owner is a Safe, its transaction in the
bundle is a pre-signed Safe `execTransaction` that calls `acceptOwnership()` on
the vault. Then run the checks at the end of this entry.

*Otherwise*, prepare the new owner's `acceptOwnership()` first (for a multisig,
collect its signatures), then nominate from the current owner. The commands
assume an owner key in a Foundry keystore (`--account`); a Safe owner submits
the same call as a Safe transaction:

```sh
cast send "$NEW_VAULT" 'transferOwnership(address)' "$NEW_OWNER" \
  --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"   # emits OwnershipTransferStarted
cast call "$NEW_VAULT" 'pendingOwner()(address)' --rpc-url "$RPC_URL"
```

As soon as that is mined, send `acceptOwnership()` from the new owner, for
example `cast send "$NEW_VAULT" 'acceptOwnership()' --rpc-url "$RPC_URL" --account "$NEW_OWNER_ACCOUNT"`
(it emits `OwnershipTransferred`). In either case, check:

```sh
cast call "$NEW_VAULT" 'owner()(address)' --rpc-url "$RPC_URL"          # the new owner
cast call "$NEW_VAULT" 'pendingOwner()(address)' --rpc-url "$RPC_URL"   # zero
```

**Treasury arrears.** A `TreasuryPaymentDeferred` event means a treasury payout
failed and was kept in `treasuryArrears()` (gwei). Fix the treasury (it must
accept ETH with 100,000 gas), then any funded account (`PAYER_ACCOUNT` below)
can pay it out, except while paused:

```sh
cast call "$NEW_VAULT" 'treasuryArrears()(uint128)' --rpc-url "$RPC_URL"
cast send "$NEW_VAULT" 'withdrawTreasuryArrears()' \
  --rpc-url "$RPC_URL" --account "$PAYER_ACCOUNT"   # emits TreasuryArrearsPaid
```

**Escape payout credits.** An `EscapePayoutDeferred(noteId, destination, amount)`
event means an escape closed but its push to `destination` failed: the
destination rejected ETH or needed more than 100,000 gas. The amount (gwei
units) waits in `escapePayoutCredits(destination)`. The browser SDK from this
release reports an escape it started as credited, and its users can claim it
from the app (`client.claimEscapePayout`). `zkapi-clientd` reports a credited
escape payout as `payout_credited`, with the vault and the claim's calldata,
and lists it under `escape_payout_credits` until the vault's credit for that
destination reads zero; its pinned manifests are still legacy vaults, which
never credit. Browser SDKs from earlier releases report such an escape as
returned. Clients detect a credit in only two cases: the browser SDK for an
escape that the same browser started, and `zkapi-clientd`, which has no
escape, for a relayed escape whose transaction hash the user enters as
withdrawal evidence. Any other escape, for example one started in another
browser or with an ownership proof that someone kept, reaches the owner only
through you, so still tell the owner. Anyone can deliver the credit, also
while paused, and the claim pays only `destination`, whoever sends it, so
claim it on the owner's behalf:

```sh
cast call "$NEW_VAULT" 'escapePayoutCredits(address)(uint128)' <destination> --rpc-url "$RPC_URL"
cast send "$NEW_VAULT" 'claimEscapePayout(address)' <destination> \
  --rpc-url "$RPC_URL" --account "$PAYER_ACCOUNT"   # emits EscapePayoutClaimed
```

The claim forwards all its gas, so a destination that needed more than
100,000 gas, such as some smart-contract wallets, is paid at once. The claim
reverts and keeps the credit while the destination still rejects ETH; the
credit then waits until that destination's owner makes it accept ETH. The
server cannot tell who owns a note, so announce such a credit with its note ID
(the event's first indexed topic) and destination through the hosts. An
`EscapePayoutClaimed(destination, amount)` event, whoever sent the claim,
shows that the credit was delivered, and `escapePayoutCredits(destination)`
then reads zero until another escape to that address is credited. A browser
SDK that started the escape marks it delivered at its next claim action, also
when someone else claimed it, and `zkapi-clientd` stops listing it once the
credit reads zero.

**Settlement reviews.** Alert on `settlement required operator review`, list
open reviews, and acknowledge each handled one, as in the
[Docker guide](../docker/aws/README.md#monitoring). The reasons are
`usage_clamped`, `deadline_worst_case`, `unsettleable_worst_case`,
`finalized_before_key_deletion`, `binding_corrupt` and `binding_reopened`
([operator review](native-eth-billing.md#operator-review)). The review table is
a log: one lease can have several rows, so acknowledge each handled row by its
`review_id`. A `deadline_worst_case` review charged the full solvency bound;
compare it with the provider's usage for that key.

A `binding_corrupt` review means that a lease's row and its nullifier
reservation disagree; the server signs nothing for that lease. Its nullifier
stays reserved, so its owner cannot exit:

- SDK builds on a vault without `vault_revision` 2 refuse to escape at that
  state. That covers every shipped profile, and the legacy vault throughout
  Phases 0 to 4.
- `zkapi-clientd` has no escape.
- The server never grants a mutual-close clearance for a reserved nullifier.

Only an SDK on a hardened vault can escape there, through the explicit override
once `unsettled_request_escape_after_seconds` has passed. Remediate each such
review before the note expires; otherwise its deposit goes to the treasury at
expiry:

1. Read the review's `detail`. It names the first field (`table.column`) in
   which the lease row disagrees with its reservation. Either side may be the
   corrupt one; edit nothing by hand unless a refusal asks for a hand repair
   (step 4). Set `ID` to the review's `client_request_id`.
2. Wait until the lease row's status is `cancelled`. Read the row itself: the
   dashboard's `pending` list holds at most `limit` leases, so a lease missing
   from it may still be pending.

   ```sh
   sudo sqlite3 -readonly "$DATA_DIR/server.db" \
     "SELECT client_request_id, status FROM openrouter_leases WHERE client_request_id = '$ID';"
   ```

   A direct lease that may have been delivered is reviewed as soon as its
   corruption is found, but cancelled only once its key's usage is captured (at
   its settlement deadline at the latest). Until then the reopen command
   refuses it.
3. Stop the API server with `dc stop server`. The challenger may keep running;
   it only reads the database.
4. Reopen the lease:

   ```sh
   dc run --rm --no-deps --entrypoint zkapi server \
     settlement reopen --db-path /data/server.db --client-request-id "$ID"
   ```

   The command first verifies the lease's saved request against its Groth16
   proof with the image's proof setup (`ZKAPI_PROOF_SETUP_DIR` when the
   deployment sets it; outside the container, the global `--proof-setup-dir`
   before `settlement`). It changes nothing while it refuses, and each refusal
   names the field and its repair:
   - `openrouter_leases.api_request_json`: the saved request is the corrupt
     side. Supply the authentic request on standard input: add `-T` after
     `run`, `--saved-request -` to the command, and `< request.json`. Take the
     copy from a database backup
     (`sudo sqlite3 -readonly <backup> "SELECT api_request_json FROM openrouter_leases WHERE client_request_id = '$ID'" > request.json`)
     or from its owner (`prepared_request` in zkapi-clientd's
     `pending_journal.json`, or in the browser SDK's request journal). The
     command accepts it only if it verifies and its binding is the
     reservation's `api_request_binding`. Never recompute the reservation from
     the saved request: the server would then sign a successor for a request
     its owner never authorized. If that `api_request_binding` is corrupt too,
     the copy is refused, and the column needs a hand repair from a backup.
   - Another `openrouter_leases` column, or a `nullifiers` field: the other
     side is corrupt. Run the command again with `--rebind`. It rewrites from
     the verified request either the lease row's `client_request_id` and
     `request_nullifier` (the lease's reviews move to the corrected id) or the
     reservation, and re-creates a missing reservation row. Re-creating assumes
     that no successor was ever signed for the request. It refuses a
     `Finalized` reservation, which needs its row restored from a backup, and
     a reservation kept under another nullifier, whose `nullifier` column
     needs a hand repair.
   - `ClearanceReserved`: the owner already exits by mutual close; nothing to
     do.

   The hand repairs are database surgery outside these runbooks; see
   [Reopening a cancelled lease](native-eth-billing.md#reopening-a-cancelled-lease).
   The output's `settles` reports how the lease will settle. A `warning` means
   that only the full solvency bound can be charged. To concede the request's
   charge instead, run the command again with `--zero-charge` before restarting
   the server (charge basis `operator_conceded`); the same checks apply. A
   lease reopened earlier whose binding is found corrupt again is repaired and
   conceded with `--zero-charge --rebind`.
5. Start the server with `dc start server`. It verifies the reopened lease's
   request and checks its binding, deployment and signing key again before
   signing. A lease that fails is cancelled again, with a new review.
6. When the query of step 2, with `ID` set to the `client_request_id` the
   command printed (`--rebind` may have corrected it), shows `finalized`,
   acknowledge each of the lease's `binding_reopened` reviews: a later
   `--zero-charge` concession adds one. Each reopening or concession itself
   acknowledges the lease's open `binding_corrupt` reviews. The owner's wallet
   installs the signed receipt through ordinary recovery. See
   [Reopening a cancelled lease](native-eth-billing.md#reopening-a-cancelled-lease).

An `unreadable OpenRouter lease row cannot be settled` line in the server log,
logged at every settlement tick with the row's `client_request_id`, names a
pending lease whose saved request cannot be decoded. No tick settles it, not
even at its settlement deadline, and its nullifier stays reserved, which
leaves its owner without an exit as above. Restore its saved request with the
reopen command of step 4 and `--saved-request` (from a backup or its owner),
without waiting for a cancellation: the lease keeps its status and the command
prints `"result": "restored"`. If its deadline has already passed, it is
charged its solvency bound on restart; add `--zero-charge` to concede
instead. Acknowledge the restoration's `binding_reopened` review once the
lease is `finalized`. See
[Restoring an unreadable pending lease](native-eth-billing.md#restoring-an-unreadable-pending-lease).

**Receipt journal missing.** A user reporting `receipt_journal_missing` was told
that the nullifier of their note's current state is finalized for a request
their client cannot apply, usually one an older SDK build, `zkapi-clientd`
0.1.6 or earlier, or a pre-release build of this release's companion
discarded. `zkapi-clientd` shows that nullifier with the code, in the chat
error and in **withdraw**. Look up that
nullifier's row and the request's charge in gwei. The server stores the
nullifier as lowercase `0x` hex without leading zeros, which
`cast to-hex "$(cast to-dec ...)"` prints from a decimal or hex value:

```sh
N=$(cast to-hex "$(cast to-dec REPLACE_WITH_NULLIFIER)")
sudo sqlite3 -readonly "$DATA_DIR/server.db" \
  "SELECT n.nullifier, n.status, n.reservation_kind, n.client_request_id, n.clearance_auth, n.created_at, n.finalized_at, COALESCE(l.charge_applied, n.charge_applied) AS charge FROM nullifiers n LEFT JOIN openrouter_leases l ON l.request_nullifier = n.nullifier WHERE n.nullifier = '$N';"
```

If its `status` is not `Finalized`, the answer was false (check the gateway); on
a hardened vault the user's exit is then the SDK's escape override after its
grace period, with the `receipt_journal_missing` acknowledgement
(`zkapi-clientd` has no escape). If it is
`Finalized`, an escape at that state will be challenged, and
`POST /v2/withdraw/clearance` answers `nullifier_used`. The only remedy is to
turn the row into a clearance reservation, and that rests on the owner's word:

- *What it can cost.* A `Finalized` row means that the server signed a
  successor state for the request, which it serves to anyone who asks by that
  nullifier. An owner whose browser lost the request's journal cannot install
  that successor; for that owner the remedy costs the operator the request's
  charge. An owner who kept the journal can install the successor, keep
  spending it and the states after it for service, and then close or escape
  at the reserved state at its earlier balance. The operator then loses up to
  the note's whole balance at that state, at most its deposit: the service
  spent since that state goes unpaid. The same holds for any state that was
  not the last one its owner reached. Nothing tells these cases apart. A
  request proof reveals neither its note nor the state it spends, so the
  server cannot link later requests to this one, and an ownership proof shows
  only that the claimant held the state, which a dishonest owner did too.
  On a legacy vault, grant it before Phase 4 disables legacy clearance (see
  *Ownership* below).
- *When to offer it.* Only where the operator accepts losing up to that
  balance: for example, for a small deposit, or for an owner it can identify
  and hold to account outside the protocol. A genuine claim normally concerns
  a request sent before the host shipped this release's SDK, which keeps a
  transmitted request's journal while its note state is current; question a
  claim about a request whose `created_at` is later.
- *Ownership.* Collect no withdrawal proof before you change the row. On a
  legacy vault an escape-form ownership proof is a valid escape while its root
  is the vault's current root. If one leaks while the row is still
  `Finalized`, the challenger contests the escape it starts, and on a legacy
  vault the challenge consumes the nullifier: the owner can then neither close
  nor escape at that state. (On a hardened vault the challenge leaves the
  mutual close possible.) The change needs no ownership proof of its own: a
  clearance at that state, and an escape there, are usable only with a
  withdrawal proof for it, which only the holder of the state can make, and
  the vault pays that state's balance to the destination in the proof. A
  claim filed by anyone else gains its filer nothing. The server verifies an
  ownership proof sent with the clearance request, and requires one where
  legacy clearance is off; once the row is changed, the challenger no longer
  contests an escape at that state, so sending that proof no longer risks the
  challenge above. To tie the claimant to the exit, ask them, before you
  change the row, for the note ID (`NOTE_ID`) and the destination address, and
  read the note:
  `cast call --json "$VAULT" 'notes(uint32)(bytes32,uint128,uint64,uint8)' "$NOTE_ID" --rpc-url "$RPC_URL"`
  must show status `1` (active) or `2` (escape pending), and a deposit, in
  gwei, within the loss you accept. A browser SDK from this release at such a
  state asks for the clearance without an ownership proof on a legacy vault,
  so the changed row is used only while legacy clearance is on.
- *Logging.* Record every use outside the database: the claimant and how to
  reach them, the note ID and destination they gave, the row and charge read
  above, the note's deposit, who approved it, the loss accepted, and the block
  number at the change (`FLIP_BLOCK`, from
  `cast block-number --rpc-url "$RPC_URL"`). Changed rows keep their marker;
  `SELECT nullifier, created_at, finalized_at FROM nullifiers WHERE clearance_auth = 'operator_receipt_missing';`
  lists them. After the owner's exit, `usedNullifiers(N)` is true: record the
  exit's note ID, final balance and destination, and compare them with the
  claim. A mutual close emits `MutualClose`, an escape
  `EscapeWithdrawalInitiated`:

  ```sh
  cast call "$VAULT" 'usedNullifiers(uint256)(bool)' "$N" --rpc-url "$RPC_URL"
  cast logs --from-block "$FLIP_BLOCK" --address "$VAULT" 'MutualClose(uint32 indexed,uint256,uint128,address)' "$NOTE_ID" --rpc-url "$RPC_URL"
  cast abi-decode --input 'f(uint256,uint128,address)' REPLACE_WITH_LOG_DATA   # nullifier, final balance, destination
  ```

To grant the remedy, turn the row into a clearance reservation. Apart from the
hand repairs that a refused reopen asks for (see Settlement reviews, above),
this is the only edit of the `nullifiers` table this guide prescribes, and the
only one with a tested statement. Run it as the container's user 10001, like
the review acknowledgements in the Docker guide:

```sh
sudo setpriv --reuid=10001 --regid=10001 --clear-groups sqlite3 "$DATA_DIR/server.db" \
  "UPDATE nullifiers SET status = 'ClearanceReserved', clearance_auth = 'operator_receipt_missing' WHERE nullifier = '$N' AND status = 'Finalized'; SELECT changes();"
```

It must print `1`; `0` means that no `Finalized` row has that key. Spell the
status exactly `ClearanceReserved`: the server reads any other value, including
the API's spelling `clearance_reserved`, as `Reserved`, which still refuses the
clearance and makes the challenger wait for a settlement. The server never acts
on `clearance_auth`; the marker keeps the row apart from the old endpoint's
reservations (`clearance_auth IS NULL`) and from proof-less ones (`legacy`).
The server then reports the nullifier `clearance_reserved` and signs the
owner's mutual-close clearance (while legacy clearance is on, also for a
request without an ownership proof, which spends no proof-less budget), and
the challenger no longer contests an escape at that state. Never undo the
change: a clearance may already have been signed. On a hardened vault this
also works after the owner's escape was challenged, because a challenge does
not burn the nullifier.

What the owner's client does after the change:

- *Browser SDK.* On a hardened vault it reads `clearance_reserved` and closes
  with an ownership proof as usual. On a legacy vault this release's SDK sends
  only the proof-less clearance from that state, which the server signs only
  while legacy clearance is on; afterwards it refuses with
  `transmitted_anchor_ownership_unsafe`, and no chat can move the state.
- *`zkapi-clientd`.* The owner's chats stop with `clearance_reserved_state`
  instead of `receipt_journal_missing`, and the owner chooses **withdraw**.
  The companion first sets aside its own retry that the server refused,
  whether or not the vault's root has changed since. On a server with legacy
  clearance off it then reports `unsettled_clearance_reserved`, and the
  guided withdrawal sends the ownership proof only after the owner types
  `send`. Tell the owner to expect that prompt.

**Indexer divergence.** Follow
[Indexer resync](../docker/aws/README.md#indexer-resync). The indexer verifies
only its root and next note ID, so the nullifier and deadline that
`/v1/escapes/pending` lists for an open escape are hints; the challenger tracks
the escape that `pendingWithdrawals(noteId)` holds. A challenge and a re-escape
of the same note leave the root unchanged: if the indexer RPC's `eth_getLogs`
dropped such a pair, `/health` stays `ok` and the challenged escape stays
listed until the note's next challenge or finalization, which the indexer
applies, counts in `missed_re_escape_count` and logs (a finalization at error
level). A dropped finalization, or a challenge and a later mutual close or
expiry claim of the note that were both dropped, leave the note listed with no
escape in the vault until a resync. The challenger reads such a dead entry on
every poll until reads 60 seconds apart find no escape, then every 16 polls,
and reports it in `indexer.pending_escapes_disagreement` (`N listed note(s)
with no pending escape in the vault: …`), with the resync warning, once reads
`--blocked-warning-seconds` apart find none and a list served after the first
such read still names it. A list that may only lag the vault is not reported,
so a stalled indexer's dead entry is caught by the indexer's own `/health` and
`head_age_seconds` alerts instead. Its per-poll vault reads resume
where the previous poll stopped, so dead entries cannot keep it from checking
the escapes listed after them. Also check for dead entries daily with
[Indexer resync](../docker/aws/README.md#indexer-resync), step 1. When the
count rises, a dead entry appears, or the challenger's `/status` keeps showing
`indexer.pending_escapes_disagreement`, fix or replace the indexer RPC's log
index, then resync.

**Fee spikes.** When the challenger reports `base_fee_above_fee_cap`,
`fee_cap_reached`, `tip_cap_reached`, `fee_reserve_held`, `tx_fee_cap_reached`
or `insufficient_balance`, raise the signer's caps in `signer.env` and recreate
the signer, then raise the daemon's caps in `challenge.env` (no higher) and
recreate the challenger, or fund the sender, with two exceptions. A container
reads its environment files only when it is created, so apply each edit with
`dc up -d --no-deps --wait signer`, then `dc up -d --no-deps --wait challenger`:
`docker compose restart` keeps the old values, and `--no-deps` leaves the
server and indexer, which also read `deployment.env`, running. For
`tx_fee_cap_reached`, or a signer refusal with `tx_fee_above_cap` or
`upstream_tx_fee_cap`, raising the fee caps changes nothing: raise the node's
`--rpc.txfeecap` first, then `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` in `signer.env`
(recreate the signer) and `deployment.env` (recreate the challenger, which also
clears a bound learned from `upstream_tx_fee_cap`); at 1 ETH a 7.53M-gas
challenge bids at most about 132.7 gwei. `fee_reserve_held` means that the pending challenge used the
replacements allowed before the critical threshold, until which bids stay
within 100/121 of the tip cap and of the lower of the fee cap and the ceiling /
gas limit. Raising both caps lets the next poll replace it once 100/121 of the
new caps is at least 10% above both of its fees: raising both caps by 10% is
enough for a bid at that limit, but one placed nearer the caps while the base
fee needed it takes just over 21% (a bid at 10/11 of the caps) to 33% (a bid at
the caps, which reports `fee_cap_reached`, `tip_cap_reached` or
`tx_fee_cap_reached` before the raise, and `fee_reserve_held` after a smaller
one). The fee cap counts only up to the ceiling / gas limit, which `/status`
shows as `sender.tx_fee_cap_max_fee_per_gas_wei`. When the raised fee cap
would exceed that, also raise the node's `--rpc.txfeecap` and
`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` as above; otherwise the challenge is replaced
at the critical threshold. See the
[fee-spike runbook](../docker/aws/signer/README.md#fee-spike-runbook) and
[challenge operation](challenge-service.md#when-no-valid-bid-remains).

## Rollback

Roll forward where possible: the earlier binaries bring back the defects.

- **Gateway:** the previous image tag.
- **Signer:** the previous image tag, with `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI`
  restored (otherwise its 10 gwei default and 100 gwei ceiling apply). It signs
  legacy transactions again and refuses the new challenger's fee fields, so roll
  the challenger back with it or stop it. It ignores
  `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` and reports a node's fee-cap refusal as a
  generic upstream failure; at its 100 gwei ceiling a 7.53M-gas challenge stays
  within a 1 ETH node cap.
- **Challenger:** the earlier binary reads the new checkpoint, but it writes to
  the server database and treats reserved leases as evidence, which burns
  nullifiers on a legacy vault. It also ignores `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`
  and proposes no fees, so behind this release's signer every challenge bids
  the signer's fee cap (see [Compatibility](#compatibility)). It drops the
  checkpoint's `missed_nullifiers` when it rewrites the checkpoint, so after a
  re-upgrade the misses the new daemon had counted are treated like an earlier
  release's (see Breaking changes). Prefer fixing forward.
- **API server:** the earlier binary ignores the new tables and columns; rows
  finalized at zero or at the worst case stay finalized, queued key cleanups
  pause, and its settlement can stall again. It also restores the seed fallback
  and proof-less clearance. It ignores a lease's committed `charge_basis`
  (`unissued` or `operator_conceded`) and does not verify a reopened lease's
  request again, so first let every such lease, and every reopened lease,
  settle. It ignores `next_attempt_at` and does not check the lease key
  source at startup. Never restore an older database over newer wallet
  activity.
- **Indexer:** the earlier binary refuses a version-2 checkpoint and answers 503.
  Stop the indexer, move `indexer.cursor` aside, and start the earlier image
  without a cursor: it replays from `DEPLOY_BLOCK`, which is the only rollback
  path. Never restore an `indexer.cursor.v1-<unix_ms>.bak` as `indexer.cursor`.
  The earlier binary resumes from a checkpoint without checking it against the
  vault, and that file may hold the diverged mirror this release replaced. It
  records the mirror's leaves but no root, and no tool here can check it
  against the vault, so keep it for forensics only.
- **Browser SDK:** earlier builds ignore the archive records, which stay inert;
  the archive's protections are lost, wallet data is not. They send clearance
  without an ownership proof, as in [Compatibility](#compatibility), and ignore
  `trusted_deployment.deposits`. They also ignore the payout-credit fields:
  they show a credited escape as returned and offer no claim, while the vault
  keeps the credit, and they start a legacy-vault escape to a destination that
  rejects ETH without the destination check.
- **`zkapi-clientd`:** the additive state fields are ignored by earlier
  releases, subject to the downgrade warning in Phase 2. An earlier release
  (0.1.6 or before) drops `slot`, `signed_slots` and each slot's
  `empty_before` from `pending-deposit.json` when it rewrites that file. After
  upgrading again, a revert of that deposit is retired, and a retry signed,
  without any indexer search for its earlier deposits, as for deposits signed
  before this release; this is one more reason for that warning. A companion
  from 0.1.6 or before cannot accept an escape payout as withdrawal evidence,
  has no release route, and cannot open a wallet whose journaled request was
  quoted under other native-price pins. Earlier companions ignore
  `request_archive/` and delete journals again instead of archiving them; a
  pre-release build of this companion also sends an ownership proof from a
  state with a set-aside request. Keep the directory, so that an upgrade sees
  those requests again. Every earlier companion, 0.1.6 included, ignores
  `oa-ownership-proof-sent.json`, so it makes chat requests again from a
  state whose ownership proof left through the generic `/wallet/withdraw`
  close. On a vault below `vault_revision` 2, whoever kept that proof can then
  escape with it and challenge the escape with such a request, which burns
  the nullifier, so finish such a close (repeat it until the note is closed)
  before rolling back. Earlier companions also ignore a reservation's
  `ownership_proof_sent`: a pre-release build of this companion, which has
  the release route, can again release through **repair** a reservation whose
  ownership proof left the device, and a reservation that any earlier
  companion rewrites loses that field and is judged by its note leaf after an
  upgrade. Earlier daemons ignore `payout_credited` and drop
  `credited_payouts` when they rewrite the funding record; the vault keeps the
  credit.
- **Contracts:** a deployed vault cannot be rolled back. The legacy vault is
  untouched by this release; an unannounced hardened deployment can simply be
  abandoned before anyone deposits.

## If development or mismatched keys were ever served

If a server ever ran with a development key (seed `0x1` or `0x2` in any
spelling), or with keys different from its vault's, treat the deployment as
compromised. Anyone could forge state signatures, obtain provider keys with
limits far above their deposit, and, if the clearance key was a development
key, forge clearances for their own notes.

1. Stop the server.
2. Rotate `ZKAPI_OPENROUTER_MANAGEMENT_KEY` or the OA org shared secret, and
   delete all outstanding runtime keys at the provider.
3. Audit `openrouter_leases` since the first start (`spending_limit_usd`,
   `usage_usd`, `charge_applied`) and the provider's usage, using the queries in
   Before you start, item 5, to find requests signed under other keys.
4. Generate new seeds and deploy a new vault with the new keys (Phase 1); vault
   keys are immutable.
5. Publish new client manifests and move users (Phases 2 to 4). If the vault
   itself pinned a development key, its notes remain forgeable until they are
   drained: retire it as quickly as its owners can exit.

## Residual risks and items not fixed

These need a new circuit, trusted setup, verifier and vault, or other work
outside this release:

- **Withholding operator.** The vault does not check settlement: an operator
  that never settles a request, or withholds the signed successor, can still
  submit its archived request proof as a challenge to the owner's escape at that
  state (once on a hardened vault, after which the nullifier can never escape
  again) and at each older spent state. Without a concession escape, an exit
  that concedes the solvency bound, such a note can leave only through an
  operator clearance; otherwise it is swept at expiry, after at least one
  challenge period of unpaused time on a hardened vault. The honest challenger
  never does this, and honest servers finalize by the settlement deadline.
- **Signed balances are not bounded by the deposit.** The request circuit's
  signed branch does not constrain the balance to at most the deposit, so a
  compromised state key is not bounded by real collateral.
- **Clearance signatures do not expire**, so clearance reservations are
  permanent, including those made through the old unauthenticated endpoint.
- **Legacy clearance budget.** While `ZKAPI_ALLOW_LEGACY_CLEARANCE` is on, the
  proof-less clearance budget (`--legacy-clearance-max-per-minute`, 60 per
  minute per server process) is one pool shared by every caller.
  - Anyone can exhaust it every minute with random nullifiers; the gateway
    admits a burst of 100 per source.
  - Each junk request leaves a permanent `ClearanceReserved` row, up to 86,400 a
    day at the default.
  - Clients that send an ownership proof are unaffected: this release's browser
    SDK (which falls back to its proof on `legacy_clearance_capacity`), the
    Rust wallet, and `zkapi-clientd` built from this release. The exception is
    a legacy-vault note state whose request left the device and never
    settled: there this release's SDK and `zkapi-clientd` send only the
    proof-less request, so while the budget is exhausted their mutual close
    fails (`409 transmitted_anchor_ownership_unsafe` in the SDK,
    `409 unsettled_request_state` in `zkapi-clientd`) until one chat request
    from that state settles or the attack stops.
  - Browser SDKs from earlier releases and `zkapi-clientd` 0.1.6 and earlier
    stay exposed to this denial of service for the whole legacy window: their
    mutual close fails with `503 legacy_clearance_capacity` while the attack
    lasts. Older browser SDKs can still escape; `zkapi-clientd` 0.1.6 and
    earlier have no escape.
  - Alert on a rising `legacy_clearance_rejected_total` in `/health`, or on the
    `legacy clearance budget exhausted` log line (written at most once a
    minute).
- **Pause has no time limit.** On a hardened vault the owner can block new
  exits and expiry claims indefinitely but cannot move deposits; escapes
  started before a pause still finalize, and credited escape payouts can still
  be claimed. Two-step transfers keep a mistyped or
  unusable nominee from leaving a paused vault without an owner, but if the key
  of an owner that has accepted is lost while the vault is paused, the freeze is
  permanent. Legacy vaults also allow the sweep described above, and a treasury
  that rejects ETH blocks the exits of their spent notes until the owner
  replaces it, so only the owner policy protects them.
- **Escape destinations that reject ETH.** On legacy vaults an escape to a
  destination that rejects ETH can never finalize, so the note, including the
  operator's share, stays locked. Hardened vaults credit the payout instead,
  and a credit to a destination that keeps rejecting ETH waits until it
  accepts.
- **Root races.** Merkle siblings must match the live root on every vault, so a
  challenge, deposit, expiry claim or withdrawal reverts `StaleRoot()` when an
  unrelated root change lands after its siblings were built. A challenge has
  already paid for proof verification by then. The challenger retries with
  fresh siblings, but anyone can force repeated reverts at their own gas cost;
  fund the sender for them. On a hardened vault the SDK retries a withdrawal
  with fresh siblings without proving again.
- **Ownership proofs.** An ownership proof is a valid escape while its root is
  accepted (for a day on a hardened vault, until the next root change on a
  legacy vault): whoever holds it, including the server, can start the owner's
  escape. Unless that escape is challenged, the payout still goes to the
  owner's destination at the owner's balance, one challenge period later. A
  challenge needs a request proof for the same state; the server holds the
  request proofs it receives, and a gateway sees each in transit. On a
  hardened vault the owner can still close by mutual close after a challenge.
  On a legacy vault the challenge consumes the nullifier, so the owner can no
  longer exit at that state; this is why the **Receipt journal missing**
  runbook collects no ownership proof before the row is changed. The proof
  shows the server the note ID, balance and destination before the close,
  which the close then publishes anyway. This release's browser SDK never
  sends an ownership proof from a legacy-vault state whose request proof left
  the device. After it has sent one, it never sends a request proof from that
  state, even when the clearance answer is a gateway 429 or is lost.
  `zkapi-clientd` from this release also sends no ownership proof from a
  legacy-vault state with an archived (set-aside) request, unless its owner
  types `send` at the guided withdrawal's risk warning, which it offers only
  once the note has expired or the server holds a clearance for the state.
  Once a clearance request carrying the proof has left it, it makes no
  request proof from that state and never releases that withdrawal's
  reservation, whatever the answer.
- **Client gaps.**
  - `zkapi-clientd` cannot yet abandon an unmined deposit, has no hardened
    manifests or retired-deployment guard, and does not warn against
    downgrades; 0.1.6 and earlier cannot open a wallet whose journaled request
    was quoted under other native-price pins.
  - On a legacy vault `zkapi-clientd` sends no ownership proof from a note
    state with an unsettled request. That includes a request it set aside on
    unsigned answers and a damaged record in `request_archive/`. With legacy
    clearance off, such a note withdraws only after one chat request settles
    the state, or, once the note has expired or the server holds a clearance
    for it, with the owner's typed acknowledgement of the challenge risk. After
    expiry `claimExpired` can take the note at any time, so owners must act
    before then. A note whose journal 0.1.6 or earlier discarded reports
    `receipt_journal_missing` with its nullifier; a lying server or gateway can
    produce the same code.
  - The browser SDK detects a credited escape payout only for an escape this
    browser started, and its claim action runs only in that deployment's
    runtime: a user who has since funded another deployment must withdraw
    there first, or claim on chain directly. Operators still alert on
    `EscapePayoutDeferred` and announce credits (see Escape payout credits
    under Operations runbooks). Its expiry display does not use
    `effectiveExpiry` yet.
  - A wallet whose older SDK already discarded a journal cannot rebuild it, so
    a finalized receipt it cannot install shows `receipt_journal_missing`; a
    lying server or gateway can produce the same code. On a hardened vault the
    SDK still offers its time-gated escape override for that code, behind that
    code's own warning and acknowledgement. If the claim is genuine, the escape
    will be challenged, its gas is lost and the note then needs operator help;
    if it is false, the escape is the only exit. Mutual close is refused at
    that state, so on a legacy vault, or after such a challenge, only operator
    remediation helps, and it rests on the owner's word: an owner who kept the
    request's journal can spend the successor state and still exit at the
    earlier balance (see **Receipt journal missing** under Operations
    runbooks). On a legacy vault this release's SDK can use that remediation
    only while legacy clearance is on.
  - A note state with 64 unsettled requests accepts no new chat. If none of
    them settles, its balance has to be withdrawn, and on a legacy vault only
    mutual close, which needs the server, can do that.
- **Fee spikes above the transaction fee ceiling.** A challenge bids at most
  the lower of the fee cap and the ceiling / gas limit, about 132.7 gwei for a
  7.53M-gas challenge at the default 1 ETH. While the base fee stays above
  that, nothing is sent (`base_fee_above_fee_cap` or `tx_fee_cap_reached`), and
  the vault's deadline does not move: a stale escape whose challenge cannot be
  included before its deadline finalizes. A higher ceiling needs a node whose
  `--rpc.txfeecap` you control; a hosted provider's cap usually cannot be
  raised. A longer `challengePeriod()` on the new vault rides out longer
  spikes. Page on both reasons (see Fee spikes under Operations runbooks).
- **Gateway limits are per source.** One browser host's users share one source,
  IPv6 clients can rotate addresses, and a client that reaches the origin
  without CloudFront can choose its key.
- **Operational dependencies.** A fresh server database, or one left with an
  unfinished SQLite transaction, cannot start while the native billing RPC is
  down. Private transaction relays may hide pending transactions from the
  challenger. The signer cannot read its node's `--rpc.txfeecap`: a node cap
  below `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` shows only as `upstream_tx_fee_cap`
  refusals, which the challenger treats as critical before it bids within
  10/11 of the refused fee. The signer recognizes that refusal only in geth's
  wording, `tx fee (...) exceeds the configured cap (...)`; any other wording
  stays `broadcast_ambiguous`. Same-nonce replacement rules were tested on
  anvil, not against geth or reth.
