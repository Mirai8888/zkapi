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
`legacy clearance budget exhausted` at most once a minute. The Rust wallet and
the `zkapi-clientd` companion always send ownership proofs; the browser SDK
sends one when its profile declares the capability, or after a proof-less
request is refused. The gateway now limits POST floods per source.
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
reopened with `zkapi settlement reopen`. The CLI default of
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
(strict mode). An archived request keeps its full journal while its note state
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
earlier releases write no archive records. The companion discards a lease
journal on `stale_root` only when the server reports the nullifier unknown.

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
revert was retired, cannot land beside the retry. The search misses such a
deposit in two cases only. Either challenges restored 64 or more escaped notes
between its slot (or the start of that run) and its landing slot after it
landed. Or it landed about 63 or more days before the retry. It needs the
upgraded indexer, whose snapshot carries block metadata.

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
- Withdrawals revert `InvalidDestination()` for the zero address and
  `UnknownRoot()` for a root neither current nor retired within
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
  wallet's previous withdrawal state, checks a transmitted state with the
  server, proves locally, and only then marks the note withdrawal-only again
  and sends the ownership proof. A proving failure or a refused check leaves
  the previous state in place, so a note that was usable stays usable. After
  any other failure of the proof-less request (a lost connection, or a 5xx
  without one of these codes), the note stays withdrawal-only, because the
  server may have reserved it; retrying the mutual close completes it.

`zkapi-clientd`:

- The companion must report the pinned `rpc_url`, `indexer_url` and
  `protocol_server_url`; funding stops otherwise.
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

## Compatibility

Clients against each server state (`legacy clearance` is
`ZKAPI_ALLOW_LEGACY_CLEARANCE`):

| Client | Legacy deployment, server not upgraded | Legacy deployment, upgraded, legacy clearance on | Legacy deployment, upgraded, legacy clearance off | Hardened deployment |
| --- | --- | --- | --- | --- |
| Browser SDK from earlier releases | All flows, with the old risks | All flows, but mutual close fails with `503 legacy_clearance_capacity` while anyone keeps the shared proof-less budget exhausted; escape still works | Mutual close fails with `400 clearance_ownership_required`; escape still works | Not usable: pinned to the legacy vault |
| Browser SDK from this release, legacy profile (no capability keys) | All flows; clearance without proof | All flows; when the proof-less budget is spent (`503 legacy_clearance_capacity`) the proof is sent instead | All flows: the proof is sent after the `400` | Not usable |
| Browser SDK from this release, legacy profile with `"clearance_ownership_proof": "optional"` (required once the server is upgraded, Phase 2) | All flows; the old server ignores the proof | All flows; the proof is always sent, so the shared proof-less budget is never used | All flows | Not usable |
| Browser SDK from this release, hardened profile (`vault_revision` 2) | Not usable | Not usable | Not usable | All flows |
| `zkapi-clientd` 0.1.6 and earlier | All flows | All flows, but withdrawals fail with `503 legacy_clearance_capacity` while anyone keeps the shared proof-less budget exhausted (clientd has no escape) | Withdrawals fail with `400 clearance_ownership_required`; the note stays reserved locally and recovers after an upgrade (clientd has no escape) | Not usable |
| `zkapi-clientd` built from this release, current manifests | Needs the upgraded indexer; ownership proof ignored by the old server | All flows | All flows | Not usable |
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
```

Use for `RPC_URL` a read RPC independent of the indexer's. Item 7 also uses
`INDEXER_RPC_URL` (the `RPC_URL` of `indexer.env`) and `NATIVE_BILLING_RPC_URL`
(`ZKAPI_NATIVE_BILLING_RPC_URL` of `deployment.env`).

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
   N=$(cast call "$VAULT" 'nextNoteId()(uint32)' --rpc-url "$RPC_URL")
   for i in $(seq 0 $((N - 1))); do
     status=$(cast call --json "$VAULT" 'notes(uint32)(bytes32,uint128,uint64,uint8)' "$i" --rpc-url "$RPC_URL" | jq -r '.[3]')
     [ "$status" = 2 ] || continue
     pending=$(cast call --json "$VAULT" 'pendingWithdrawals(uint32)(bool,uint256,uint256,uint128,address,uint64)' "$i" --rpc-url "$RPC_URL")
     nullifier=$(cast to-hex "$(echo "$pending" | jq -r '.[2]')")
     echo "note $i deadline $(echo "$pending" | jq -r '.[5]') nullifier $nullifier"
     sudo sqlite3 -readonly /var/lib/zkapi/server.db \
       "SELECT n.status, n.reservation_kind, l.status, l.key_source, l.key_hash IS NOT NULL FROM nullifiers n LEFT JOIN openrouter_leases l ON l.request_nullifier = n.nullifier WHERE n.nullifier = '$nullifier';"
   done
   ```

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
   curl -fsS http://127.0.0.1:8080/v1/attestation \
     | jq -r '.state_signing_key.x, .state_signing_key.y, .clearance_signing_key.x, .clearance_signing_key.y' \
     | while read -r value; do cast to-dec "$value"; done
   ```

5. **Keys the server served in the past.** Every archived request must carry the
   vault's state key. Run on a copy of the database:

   ```sh
   sudo sqlite3 -readonly /var/lib/zkapi/server.db \
     "SELECT json_extract(request_inputs_json, '$.state_signing_key_x') AS k, count(*) FROM nullifiers WHERE request_inputs_json IS NOT NULL GROUP BY k;
      SELECT json_extract(api_request_json, '$.public_inputs.state_signing_key_x') AS k, count(*) FROM openrouter_leases GROUP BY k;"
   ```

   Any other value, in particular the development state key
   `0x2b8cfd91b905cae31d41e7dedf4a927ee3bc429aad7e344d59d2810d82876c32`, means
   [the deployment is compromised](#if-development-or-mismatched-keys-were-ever-served).

6. **Settlement and clearance snapshot.**

   ```sh
   sudo sqlite3 -readonly /var/lib/zkapi/server.db \
     "SELECT key_source, status, count(*) FROM openrouter_leases WHERE status <> 'finalized' GROUP BY 1, 2;
      SELECT status, reservation_kind, count(*) FROM nullifiers GROUP BY 1, 2;"
   ```

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
   gas limit, then restarting the signer, clears both, but keep a margin above
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
   - the challenger's `/health` returning 503 and every `critical` alarm on its
     `/status`: `evidence_invalid`, `evidence_db_error`,
     `indexer_invalid_response`, `indexer_diverged`, `signer_refused` and
     `upstream_tx_fee_cap` are critical at once, while every other blocked
     reason, `fee_reserve_held`, `tx_fee_cap_reached`, `tx_fee_above_cap` and
     `base_fee_above_max_fee` included, turns critical after
     `--critical-blocked-seconds`;
   - its warnings about the transaction fee ceiling, a fee the signer's node
     refused, and an indexer pending-escapes list that disagrees with the
     vault;
   - any increase of the indexer's `missed_re_escape_count`
     (`zkapi_indexer_missed_re_escapes_total`), paging on `event="finalized"`;
   - the signer's `challenge_refused` audit lines and its status warnings.

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
default project and paths. Never repoint the legacy signer or challenger at the
new vault.

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
       'treasuryChangeDelay()(uint64)' 'unpauseClaimGrace()(uint64)' 'ROOT_HISTORY_WINDOW()(uint64)'; do
     printf '%s ' "$getter"; cast call "$NEW_VAULT" "$getter" --rpc-url "$RPC_URL"
   done
   ```

   `owner()` must be the multisig and `pendingOwner()` must be zero. Compare the
   four key getters with the printed keys as numbers.

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
   `Paused`, `Unpaused` and `TreasuryPaymentDeferred` (see
   [Operations runbooks](#operations-runbooks)). Monitoring that watched
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
  Once the legacy deployment's server is upgraded, declaring
  `"clearance_ownership_proof": "optional"` in the legacy profile's
  `trusted_deployment` (in `sdk/assets/config/mainnet.json` and `sepolia.json`,
  or the host's own browser config; then sync, verify and build as for the
  hardened profile below) is a required step, not an option. Without it, mutual
  close first sends a proof-less request that competes for the shared legacy
  budget, then falls back to the proof on `503 legacy_clearance_capacity` or
  `400 clearance_ownership_required`, at the cost of one extra round trip. With
  it, every clearance request carries the ownership proof and never uses the
  budget. Browser SDKs from earlier releases and `zkapi-clientd` 0.1.6 and
  earlier never send a proof, so their mutual close fails while anyone keeps
  that budget spent (see
  [residual risks](#residual-risks-and-items-not-fixed)). Hosts update and
  reload every tab; the IndexedDB version is unchanged and older tabs keep
  working, but they do not write archive records. Users must not reset or
  export wallets.
- **`zkapi-clientd`.** A release built from this source with the current pinned
  manifests, whose native companion is rebuilt by
  `zkapi-clientd/scripts/prepare-zkapi.sh` from the unchanged pins in
  `zkapi-clientd/packaging/zkapi-source.env` and the updated `companion.patch`
  and `protocol-transport.patch`. It needs the indexer from Phase 0. Users stop
  `serve`, install the release, and start it again. A deposit in
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
  `"clearance_ownership_proof": "optional"`, so that owners can still withdraw
  legacy notes in strict mode. Hosts that offer the escape override show
  `escape_override_warning`, from the refusal or from
  `snapshot().config.escape_override`, and pass the
  `escape_override_acknowledgement` given with it as
  `overrideUnsettledRequest`, never one derived from the refusal code (see
  [Breaking changes](#breaking-changes)): a host that always passes `true`
  leaves its users no exit while a false receipt claim stands. Surface
  `request_archive_limit` as a prompt to withdraw that balance.
- **Wallet ordering in browsers.** The SDK keeps one selected note per origin
  and refuses to open a wallet for another deployment while it holds durable
  state (`This browser contains a wallet for <id>. Switch back to that deployment
  before using or withdrawing it.`). Before configuring the SDK, hosts read
  `readBrowserWalletSnapshot()` from `@openanonymity/zkapi-browser-sdk/store`.
  If `runtime.deploymentId` is the legacy deployment and the runtime still holds
  a note, journal, lease, pending deposit, prepared withdrawal or unfinished
  late attempt, configure the legacy profile and offer a withdrawal; otherwise
  configure the hardened profile. Never clear site data to get past the check.
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
the drain completes. Once the hardened releases are out:

1. **Deposit cutoff.** Announce a date. At the cutoff, stop serving the two
   routes that deposits need, `/v1/tree/next-note-id` and
   `/v1/tree/notes/{id}/zero-path`, on the legacy deployment's public gateway,
   by adding to its `nginx.conf` before `location /v1/tree/` and rebuilding its
   gateway image under its own tag:

   ```nginx
   # Deposit cutoff: the drained vault no longer offers new deposit paths.
   location = /v1/tree/next-note-id { return 410; }
   location ~ ^/v1/tree/notes/[0-9]+/zero-path$ { return 410; }
   ```

   Clients then fail before building a deposit transaction. Keep the root,
   paths, snapshot, clearance, recovery and every other route, and keep the
   internal indexer unchanged: the challenger reads zero-paths from it
   directly. Never pause the legacy vault to stop deposits; anyone can still
   deposit by building a path from chain data, and such notes drain like any
   other.

2. **Drain monitoring.** Track the legacy notes daily (Before you start, items 1
   and 2): notes by status, pending escapes, `nextNoteId()` in case of late
   deposits, and whether the treasury still accepts ETH. A note's expiry is
   its `expiryTs`, the deposit time plus `noteTtl()` rounded up to a whole day.
   Plan the legacy stack's end from the latest `expiryTs` among open notes,
   plus one challenge period for escapes started near it.

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
   sudo sqlite3 -readonly /var/lib/zkapi/server.db \
     "SELECT count(*) FROM nullifiers WHERE status = 'ClearanceReserved' AND clearance_auth = 'legacy' AND created_at > strftime('%s', 'now', '-7 days');"
   ```

   Then remove `ZKAPI_ALLOW_LEGACY_CLEARANCE` from `deployment.env` (or set it to
   `false`), run `dc up -d --no-deps --wait server`, and confirm
   `clearance_ownership_proof_required: true` and
   `legacy_clearance_window_limit: 0` in `/health`. Older SDK builds can still
   escape; `zkapi-clientd` 0.1.6 and earlier cannot withdraw until they
   upgrade.

2. **Retire the legacy stack** only when every legacy note is closed (status 3,
   by an exit or an expiry claim), no escape is pending, and the last challenge
   deadline has passed.
   Retiring earlier strands the remaining notes: without the API and indexer,
   clients can neither close nor build escape paths. Then:
   1. stop the challenger and signer, and move the sender's remaining balance;
   2. stop the server, indexer and gateway, and remove the legacy origin;
   3. archive the data directory as sensitive data (it holds request proofs and
      transcripts);
   4. keep the legacy client releases available for reference.

## Operations runbooks

**Treasury change on the hardened vault.** From the owner:

```sh
cast send "$NEW_VAULT" 'setTreasury(address)' "$NEW_TREASURY"   # emits TreasuryChangeScheduled
cast call "$NEW_VAULT" 'pendingTreasury()(address)' --rpc-url "$RPC_URL"
cast call "$NEW_VAULT" 'pendingTreasuryReadyAt()(uint64)' --rpc-url "$RPC_URL"
cast call "$NEW_VAULT" 'totalPausedDuration()(uint64)' --rpc-url "$RPC_URL"
cast send "$NEW_VAULT" 'acceptTreasury()'                       # emits TreasurySet
cast send "$NEW_VAULT" 'cancelTreasuryChange()'                 # any time, also while paused
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
accept ETH with 100,000 gas), then anyone can pay it out, except while paused:

```sh
cast call "$NEW_VAULT" 'treasuryArrears()(uint128)' --rpc-url "$RPC_URL"
cast send "$NEW_VAULT" 'withdrawTreasuryArrears()'   # emits TreasuryArrearsPaid
```

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
   sudo sqlite3 -readonly /var/lib/zkapi/server.db \
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

**Receipt journal missing.** A user reporting `receipt_journal_missing` was told
that the nullifier of their note's current state is finalized for a request the
browser cannot apply, usually one an older SDK build discarded. Look up that
nullifier's row. The server stores the nullifier as lowercase `0x` hex without
leading zeros, which `cast to-hex "$(cast to-dec ...)"` prints from a decimal or
hex value:

```sh
N=$(cast to-hex "$(cast to-dec REPLACE_WITH_NULLIFIER)")
sudo sqlite3 -readonly /var/lib/zkapi/server.db \
  "SELECT nullifier, status, reservation_kind, client_request_id, clearance_auth FROM nullifiers WHERE nullifier = '$N';"
```

If its `status` is not `Finalized`, the answer was false (check the gateway); on
a hardened vault the user's exit is then the SDK's escape override after its
grace period, with the `receipt_journal_missing` acknowledgement. If it is
`Finalized`, an escape at that state will be challenged, and
`POST /v2/withdraw/clearance` answers `nullifier_used`. To let the owner exit,
verify ownership (for example, with an escape-form ownership proof for that
nullifier), then turn the row into a clearance reservation. Apart from the hand
repairs that a refused reopen asks for (see Settlement reviews, above), this is
the only edit of the `nullifiers` table this guide prescribes, and the only one
with a tested statement. Run it as the container's user 10001, like the review
acknowledgements in the Docker guide:

```sh
sudo setpriv --reuid=10001 --regid=10001 --clear-groups sqlite3 /var/lib/zkapi/server.db \
  "UPDATE nullifiers SET status = 'ClearanceReserved', clearance_auth = 'operator_receipt_missing' WHERE nullifier = '$N' AND status = 'Finalized'; SELECT changes();"
```

It must print `1`; `0` means that no `Finalized` row has that key. Spell the
status exactly `ClearanceReserved`: the server reads any other value, including
the API's spelling `clearance_reserved`, as `Reserved`, which still refuses the
clearance and makes the challenger wait for a settlement. The server never acts
on `clearance_auth`; the marker keeps the row apart from the old endpoint's
reservations (`clearance_auth IS NULL`) and from proof-less ones (`legacy`).
The server then reports the nullifier `clearance_reserved` and signs the
owner's mutual-close clearance, and the challenger no longer contests an escape
at that state. The owner withdraws the balance from before that request, and
the operator forgoes that request's charge. On a hardened vault this also works
after the owner's escape was challenged, because a challenge does not burn the
nullifier.

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
or `insufficient_balance`, raise the signer's caps and restart it, then raise
the daemon's caps (no higher) and restart it, or fund the sender, with two
exceptions. For `tx_fee_cap_reached`, or a signer refusal with
`tx_fee_above_cap` or `upstream_tx_fee_cap`, raising the fee caps changes
nothing: raise the node's `--rpc.txfeecap` first, then
`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` in `signer.env` (restart the signer) and
`deployment.env` (restart the challenger, which also clears a bound learned
from `upstream_tx_fee_cap`); at 1 ETH a 7.53M-gas challenge bids at most about
132.7 gwei. `fee_reserve_held` means that the pending challenge used the
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
  the signer's fee cap (see [Compatibility](#compatibility)). Prefer fixing
  forward.
- **API server:** the earlier binary ignores the new tables and columns; rows
  finalized at zero or at the worst case stay finalized, queued key cleanups
  pause, and its settlement can stall again. It also restores the seed fallback
  and proof-less clearance. It ignores a lease's committed `charge_basis`
  (`unissued` or `operator_conceded`) and does not verify a reopened lease's
  request again, so first let every such lease, and every reopened lease,
  settle. Never restore an older database over newer wallet activity.
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
  without an ownership proof, as in [Compatibility](#compatibility).
- **`zkapi-clientd`:** the additive state fields are ignored by earlier
  releases, subject to the downgrade warning in Phase 2. An earlier release
  (0.1.6 or before) drops `slot`, `signed_slots` and each slot's
  `empty_before` from `pending-deposit.json` when it rewrites that file. After
  upgrading again, a revert of that deposit is retired, and a retry signed,
  without any indexer search for its earlier deposits, as for deposits signed
  before this release; this is one more reason for that warning. An earlier
  companion cannot accept an escape payout as withdrawal evidence and has no
  release route, and 0.1.6 and earlier cannot open a wallet whose journaled
  request was quoted under other native-price pins.
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
    Rust wallet, and `zkapi-clientd` built from this release.
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
  started before a pause still finalize. Two-step transfers keep a mistyped or
  unusable nominee from leaving a paused vault without an owner, but if the key
  of an owner that has accepted is lost while the vault is paused, the freeze is
  permanent. Legacy vaults also allow the sweep described above, and a treasury
  that rejects ETH blocks the exits of their spent notes until the owner
  replaces it, so only the owner policy protects them.
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
  escape and delay the payout by one challenge period. The
  payout still goes to the owner's destination at the owner's balance. The
  proof shows the server the note ID, balance and destination before the close,
  which the close then publishes anyway.
- **Client gaps.** `zkapi-clientd` cannot yet abandon an unmined deposit, has no
  hardened manifests or retired-deployment guard, and does not warn against
  downgrades; 0.1.6 and earlier cannot open a wallet whose journaled request
  was quoted under other native-price pins. The browser SDK's expiry display
  does not use `effectiveExpiry` yet. A wallet whose older SDK already
  discarded a journal cannot rebuild it, so a finalized receipt it cannot
  install shows `receipt_journal_missing`; a lying server or gateway can
  produce the same code. On a hardened vault the SDK still offers its
  time-gated escape override for that code, behind that code's own warning and
  acknowledgement. If the claim is genuine, the escape will be challenged, its
  gas is lost and the note then needs operator help; if it is false, the escape
  is the only exit. Mutual close is refused at that state, so on a legacy
  vault, or after such a challenge, only operator remediation helps (see
  **Receipt journal missing** under Operations runbooks). A note state with 64
  unsettled requests accepts no new chat. If none of them settles, its balance
  has to be withdrawn, and on a legacy vault only mutual close, which needs the
  server, can do that.
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
