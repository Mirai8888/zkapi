# Native ETH browser billing

The protocol uses native ETH billing with the browser SDK and the
server, indexer, and challenger services.

Native ETH deployments hold ETH and use integer **gwei** in the proof
ledger: one unit is 1,000,000,000 wei. The browser displays an approximate USD reference value;
the USD value changes with ETH's price. This is not a stable-dollar deposit or a
swap into USDC. Fractional gwei are never credited to a private note.

The native vault exposes `billingToken() == address(0)` and
`nativeAssetWeiPerUnit() == 1000000000`. Its deposit selector accepts
integer gwei and requires exactly `amount * 1 gwei` in `msg.value`. Wrong values
revert atomically. Native deposits are capped at JavaScript's maximum exact
integer, 9,007,199,254,740,991 units. Withdrawal and expiry payouts convert ledger
units back to wei and enforce proof, nullifier, destination, timing
and reentrancy protections. A failed transfer to the withdrawal destination
reverts the complete close. On vaults deployed from this release a treasury
that rejects its share, or needs more than 100,000 gas to receive it, cannot
block a close: the share accrues to `treasuryArrears()` with a
`TreasuryPaymentDeferred` event, and anyone can pay it out later with
`withdrawTreasuryArrears()`.

The deployment manifest pins the vault address, native asset, and circuit
`zkapi-v2-note-bound-v1` with its exact setup/WASM/key hashes. The circuit binds
each signed balance to its deposit note. Challenges preserve the historical
request root and use a current restoration path. See
[Note-bound commitments](note-bound-commitments.md).

## Pinned configuration

The public deployment manifest and browser trust configuration must agree on:

```json
{
  "billing_asset": "native_eth",
  "billing_unit": "gwei",
  "billing_token_address": null,
  "native_asset_wei_per_unit": "1000000000",
  "native_price_feed_address": "0x694AA1769357215DE4FAC081bf1f309aDC325306",
  "native_price_feed_decimals": 8,
  "native_price_max_age_seconds": 4500
}
```

Pin the RPC URL, chain, vault and protocol/signing/proof-asset
fields too. Both manifest `proof_setup.circuit_id` and browser
`trusted_deployment.circuit_id` must equal `zkapi-v2-note-bound-v1`, and all
request/withdrawal proving and verifying key hashes must match that setup. The example feed is Sepolia; it does not select a production feed.
The server checks chain ID, feed decimals and the vault's native-unit getter
before answering or accepting a quote. There is no symbol-only fallback.

Chainlink's reference directory lists the ordinary ETH/USD proxies as
`0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419` on Mainnet and
`0x694AA1769357215DE4FAC081bf1f309aDC325306` on Sepolia, both eight decimals
with a 3,600-second heartbeat. The server and SDK read
oracle rounds at the RPC `finalized` block tag; the USD reference can therefore
lag the chain head, and `updated_at` identifies the actual feed observation.
The native deployment pins a 4,500-second maximum age: the heartbeat plus a
900-second finality allowance. Freshness remains configurable and fails closed
if finality or feed updates lag beyond the pinned allowance. The RPC must support
`finalized`; there is no fallback to head/latest pricing. Quotes with a future
timestamp, incomplete round, nonpositive price or expired timestamp fail.
Review feed provenance and freshness policy before each deployment.

Sources: [official documentation feed-directory configuration](https://github.com/smartcontractkit/documentation/blob/main/src/features/data/chains.ts#L294),
[Chainlink API](https://docs.chain.link/data-feeds/api-reference),
[Mainnet directory](https://reference-data-directory.vercel.app/feeds-mainnet.json),
[Sepolia directory](https://reference-data-directory.vercel.app/feeds-ethereum-testnet-sepolia.json).

## A quote belongs to one private lease

`GET /v2/billing/quote` is a read-only, `Cache-Control: no-store` endpoint:

```json
{
  "asset": "native_eth",
  "units_per_eth": 1000000000,
  "chain_id": 11155111,
  "feed_address": "0x694aa1769357215de4fac081bf1f309adc325306",
  "round_id": "123",
  "answer": "250000000000",
  "decimals": 8,
  "updated_at": 1700000000,
  "expires_at": 1700004500
}
```

This is a schema example, not a usable current quote. Round and price are
canonical decimal strings. `expires_at = updated_at + configured max age`.
The browser independently verifies the round through the pinned RPC and adds
this entire object as `billing_quote` to the existing prompt-free lease
authorization before generating a proof. The canonical payload hash and request
authorization tag bind the quote to that request and its proof. It carries no
prompt, account identity, funding address or wallet secret.

Before reserving a new nullifier, the server verifies the quoted round with
`getRoundData` and requires it to equal `latestRoundData` on the pinned feed,
both read at `finalized`, as well as checking freshness. A user cannot choose a
favorable historical round. Head-only updates do not invalidate a prepared
finalized quote. If a newer round finalizes while a proof is being prepared,
new issuance rejects it with `native_quote_superseded`; the exact old request
must be recovered before constructing a new proof. The exact accepted request,
including its quote, is persisted before upstream key provisioning. The rate is
never refreshed on a matching retry or during settlement. In particular, a
restart or an oracle outage cannot reprice an existing lease. Settlement checks
the saved quote only for internal consistency and never compares it with the
server's current `--native-price-*` settings, so changing the feed address,
decimals or maximum age affects only new admissions (and the acknowledgement of
an unaccepted quote that has not yet expired). Keep those settings equal to the
published manifest.

An accepted reservation does not authorize new access after its state has been
withdrawn. Before contacting either provider to create a key, including an exact
reserved/provisioning retry, the server checks the configured chain ID and the
vault's `usedNullifiers(request_nullifier)` at `latest`. Only an explicit ABI
`false` permits issuance. Consumed nullifiers return `nullifier_used`; unavailable,
wrong-chain or malformed RPC responses fail closed with a retriable server error.
This live authorization read does not refresh the frozen quote or require the
original Merkle root to remain current after unrelated deposits.

The lease row is created, with its frozen TTL and write-once settlement
deadline, right after the reservation and before that check. After provider
creation, the server durably activates the lease and repeats the same check
before returning its secret, and it records that the key was delivered only
immediately before returning it. If a withdrawal consumed the nullifier during
provider I/O, or the read fails, no key is returned; the active record stays for
status and settlement, which charges such an undelivered key nothing, and a
direct key is queued for deletion at once. RPC availability is therefore
required for new key delivery, including retries. Existing lease status and
settlement do not require this issuance check.

A key is only ever returned for a lease that settles from usage. Issuance holds
the issuance lock from its first check until it has returned or abandoned the
key. The background settler and a client's retirement settle a never-delivered
lease at zero only while holding that same lock (a retirement waits for it) and
read the lease again once they hold it: a key delivered meanwhile settles from
usage instead. Before signing the zero-charge successor, the settlement also
commits the lease row to it, after which the key can neither be activated nor
marked delivered, and an issuance whose delivery mark is refused never returns
its key. Such a direct key is deleted in the background. The OA org offers no
key revocation: an OA key that was never returned was seen only by the org, its
station and this server, and lapses at its TTL.

A withdrawal started after key delivery still requires timely operation of the
challenger. The challenger contests an escape at a lease's state only after
settlement finalizes it, which the settlement deadline below bounds. These
checks do not replace the configured challenge window, a trustworthy view of the
selected chain, or sufficient operational time to observe and challenge a stale
escape. The challenge window is fixed when the vault is deployed (24 hours in
the current deployments).

For ledger units `U`, oracle integer answer `P`, and decimals `D`, the upstream
budget in micro-USD is:

`floor(U * P * 1,000,000 / (1,000,000,000 * 10^D))`.

The OA org still receives and signs micro-USD limits and measured usage; it does
not need native-token pricing support. For measured usage `C` in micro-USD the
native charge is:

`ceil(C * 1,000,000,000 * 10^D / (P * 1,000,000))`.

Zero usage stays zero. Settlement clamps measured usage to the micro-USD limit
of the proof's solvency bound before converting it, so the conversion cannot
overflow and the signed charge never exceeds the solvency bound; a clamped
charge carries `charge_basis: "clamped"` with the reported and charged usage,
and records a `usage_clamped` review. OA receipts above the lease limit are
clamped the same way. Issuance and the settlement response payload echo the
exact quote so the browser can compare it with its persisted journal.

A `native_quote_expired` response is emitted only before any nullifier
reservation. Freshness is rechecked after all oracle awaits and after proof
verification immediately before reservation, with equality treated as expired.
Issuance attempts share one lock, so an exact POST that returns this rejection
has also waited for earlier in-flight attempts. A local clock or an unknown GET
alone does not authorize deleting a journal; startup remains read-only.
`POST /v2/openrouter/leases/{id}/expire` accepts the exact saved request. It
returns `expired_unaccepted` when the server clock says expired, or
`superseded_unaccepted` when a newer finalized round exists, with the exact
request ID, nullifier and payload hash. Both acknowledgments require that
neither its nullifier nor request ID has a reservation. That is checked under
the same issuance lock, which waits for earlier in-flight attempts, before and
again after the oracle reads; the lock is not held across them. An issuance
that reserved the request meanwhile is seen, and a later one reads the clock
and the oracle later, so it cannot accept an expired or superseded quote.
Superseded recovery relies on Ethereum finality: an ordinary head
reorganization cannot revive the old quote. A finalized-chain safety violation is outside this model,
as it is for the private note's confirmed chain state. This endpoint is
read-only: it never generates a key, signs, reserves or cancels anything. Every
other result preserves the journal. It allows interrupted startup/withdrawal recovery without
starting a chat solely to test whether an old proof is still issuable. Matching
reserved/provisioning requests retain their old quote and remain recoverable
after expiry. Other errors do not authorize discarding a
pending journal. `POST /v2/requests` has been removed; all new authorizations
require prompt-private leases with a proof-bound native quote.

## Deployment

The deploy script creates a native-only vault and accepts `REQUEST_CHARGE_CAP`
in gwei. It checks an optional `CHAIN_ID` against the connected chain and, off
local chains, requires an explicit `OWNER`; see
[deployment](deployment.md#contracts). Publish a manifest that pins the
resulting vault, circuit artifacts, signing keys, and native asset
configuration.

Start the native server with its vault/chain/request cap and
signer, indexer, proof and OA-source settings, plus:

```sh
zkapi ... serverd ... \
  --native-billing-rpc-url "$RPC_URL" \
  --native-price-feed-address "$ETH_USD_FEED" \
  --native-price-feed-decimals 8 \
  --native-price-max-age-seconds 4500
```

The server requires native oracle and prompt-private lease configuration.
`--openrouter-settlement-deadline-seconds` (default 21600) sets the settlement
deadline described below. Operate the compatible v2
[challenge daemon](challenge-service.md) alongside server and indexer, with a
dedicated funded signer restricted to the configured vault. Its only evidence is
the server's finalized transcript: the exact historical request root, inputs and
proof of a request whose settlement is signed. A reserved request, including an
issued lease whose usage is not settled yet, is not evidence; the daemon waits
for settlement, which the deadline bounds, and uses a current zero-slot
restoration path. Native usage settlement preserves the original proof/public
inputs required for that challenge. After a successful challenge on a vault
deployed from this release, `usedNullifiers(nullifier)` reads `false` and
`challengedNullifiers(nullifier)` reads `true`: no escape can use that
nullifier again, and the owner exits from the signed successor state. On vaults
deployed before this release the nullifier stays consumed.
Do not reuse a daemon, verifier or setup from another circuit. Configure the published manifest separately; these flags do
not rewrite static frontend manifests. The browser SDK handles funding and
withdrawals; the operator CLI runs setup, signing-key, server and indexer
commands, and `zkapi settlement reopen` (see
[Reopening a cancelled lease](#reopening-a-cancelled-lease)).

OA provisioning retries accept a shortened remaining lifetime only when the
relay explicitly marks the station response `replayed: true`. Its original
expiry stays unchanged and must remain in the future and within the requested
maximum TTL; absent flags and ordinary new issuance retain strict lifetime
bounds. A resumed OA issuance uses the lease's frozen TTL, and is refused with
`lease_pending` when the lease's settlement deadline no longer leaves room for
TTL + grace + 900 seconds; such a lease is later finalized at zero. A replay
never creates a second key for the same accepted request.

Native OA issuance uses a deployment-bound upstream request ID: a versioned
Keccak domain hash of the complete accepted request binding (chain, vault,
nullifier, browser request ID, payload/quote, and proof). This separate ID is
persisted atomically with the lease and reused for key issuance and usage
recovery. It prevents two deployments that share an org from redeeming the same
key by choosing the same browser request ID. The browser-visible ID stays
unchanged. OA lease recovery rejects a missing or mismatched native upstream ID.

## Recovering OA provisioning

The server records whether a new OA lease has ever attempted issuance. Before
provider I/O, it durably changes `not_started` to `may_have_issued`; a timeout,
lost reply, malformed success or restart therefore preserves uncertainty. The
only automatic rejection classification is HTTP 400 with an exact org
pre-provider validation detail: `credit_limit exceeds zkAPI policy`,
`credit_limit_credits exceeds zkAPI policy`, or
`duration_minutes exceeds zkAPI policy`. These are a contract with the org's
`request_key` validator, which runs before station/provider I/O. A generic
400, 429, missing key hash, or expired local lease is not nonissuance evidence.
Even a recognized rejection cannot clear uncertainty from an earlier attempt.

A definitive first-attempt rejection becomes `confirmed_unissued` and receives
a normal signed zero-charge successor state. The issuance request returns
`oa_key_policy_rejected` (HTTP 400, nonretriable); this error alone does not
authorize deleting a wallet journal. Clients retrieve and verify the signed
response using ordinary request recovery. The receipt keeps the original quote
and has type `oa_org_unissued_lease_cancellation`, `issued: false`, and zero usage.
The nullifier is finalized, never deleted or made reusable.

If finalization is interrupted, the next background scan or exact saved-proof
settlement request finishes it. A persisted signed successor is reused after a
crash; it is never replaced with a new signature. A provisioning row is
finalized at zero only while it still has no key and only while holding the
issuance lock, so never during an issuance attempt; see
[Settlement terminality](#settlement-terminality) for when.

Every other OA lease that never returned a key to the client is also finalized
at zero once its settlement is due, whatever its outcome: `not_started`,
`may_have_issued`, or a historical row whose outcome is unknown. Its receipt has
the same type with `reason` `issuance_not_started` or `issuance_not_completed`,
and no provider or chain call is needed. A key the org may have issued was never
delivered through this lease, so nothing can have used it. The read-only issuer
reconciliation of earlier releases (`POST /api/zkapi/reconcile_key`) is no
longer used. Rows that an earlier release reconciled are treated as possibly
delivered and settle from measured usage. Usage settlement uses the TTL frozen
in the lease row; only rows created by earlier releases, which have none, use
the server's current setting.

A crash after nullifier reservation but before the lease row is created still
requires exact issuance replay. Nothing can infer an outcome from that
incomplete state, nothing settles it automatically, and the challenger never
treats it as evidence.

## Settlement terminality

Every accepted lease reaches a signed transcript by a deadline, so a lease can
no longer hold its note state reserved indefinitely:

- The deadline (`settlement_deadline_at`) is written once, when the lease row is
  created: issuance + TTL + grace + `--openrouter-settlement-deadline-seconds`
  (`ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS`, default 21600). Retirement
  steps, timing updates and a provider that keeps reporting a key enabled never
  move it, and the first error time is never reset. A row created by an earlier
  release receives one at first sight: the later of its expiry and that moment,
  plus grace and the deadline setting.
- A lease that never delivered a key is finalized at zero, signed, without any
  provider or chain call: a provisioning row (direct, or OA in any outcome), or
  an activated lease whose key was never returned. The receipt keeps its
  source's type (`openrouter_ephemeral_lease_settlement`, or
  `oa_org_unissued_lease_cancellation` for OA) with `charge_basis: "unissued"`,
  `issued: false`, `delivered: false` and a `reason`
  (`issuance_not_started`, `issuer_policy_rejected`, `issuance_not_completed`
  or `key_never_delivered`).
- Such a lease is due once its `settle_after` passes (for a provisioning row,
  normally its creation plus TTL and grace; for an activated one, its key's
  expiry plus grace) or its settlement deadline passes, and at once after a
  confirmed OA rejection or once the lease is committed to its zero charge.
  Its zero settlement needs the issuance lock (see above). A settlement tick
  (every `--openrouter-settlement-poll-seconds`) finalizes a due lease when that
  lock is free and otherwise defers it to the next tick. Once the lease is past
  its settlement deadline, the tick instead queues for the lock, in arrival
  order, for up to 30 seconds after its other zero settlements, then finishes
  its other work. Lock holders that come and go, such as issuance attempts or
  `/expire` checks, can therefore no longer postpone it; only a lock held, or
  a queue of holders waiting, for longer than 30 seconds defers it to the next
  tick. Its owner can also finalize it at once by retiring it with the exact
  saved request, which waits for the lock within the 45-second retirement
  timeout.
- A lease that may have been delivered (active, retiring, disabled or revoking)
  is settled from measured usage, clamped to its solvency bound
  (`charge_basis` `measured` or `clamped`). Transient failures, such as an
  unavailable provider, org or RPC or an unconfirmed key deletion, are retried
  until the deadline. At the deadline it is finalized without further I/O: a
  revoking direct key whose usage was already captured is charged that usage
  (`key_deleted: false`, review `finalized_before_key_deletion`); any other is
  charged its solvency bound (`charge_basis: "worst_case"`,
  `settlement_reason: "settlement_deadline"`, review `deadline_worst_case`).
- A deterministic failure, such as a corrupt saved quote, missing revocation
  usage, or an invalid saved TTL, namespace or limit, is finalized at the
  solvency bound at once (`settlement_reason: "unsettleable"`, review
  `unsettleable_worst_case`).
- A charge is final once signed; there is no refund transaction. The solvency
  bound is the most the user's own proof authorized, and the provider key's
  spending limit was derived from it.
- `cancelled` is used only for a lease whose saved binding does not match its
  nullifier record. The server never signs it and records a `binding_corrupt`
  review naming the first mismatching field, and a retry of the request returns
  `nullifier_used`. A direct key that may have been delivered is first disabled
  and its usage captured, so that a reopening can charge that usage. The
  capture is retried like any settlement until the deadline; the corruption is
  reviewed as soon as it is found, and the lease is cancelled, with a second
  review, once its usage is read, or at its deadline without it. The
  cancellation queues the key's deletion. Its nullifier stays reserved without
  evidence, which blocks most owners: SDK builds on a vault without
  `vault_revision` 2 (strict mode, every shipped profile) refuse
  to escape at that state, zkapi-clientd has no escape, and a reserved nullifier
  never receives a mutual-close clearance. Only an SDK on a `vault_revision` 2
  vault can escape there, through the explicit override once
  `unsettled_request_escape_after_seconds` has passed; the challenger does not
  contest it. The operator's remedy is to
  [reopen the lease](#reopening-a-cancelled-lease) once its binding is
  repaired. Conceding its charge (`--zero-charge`) is a choice of charge within
  that remedy, not a way around the repair.
- Keys of terminal direct leases that may still exist at the provider (worst
  case, never delivered or cancelled) are disabled and then deleted in the
  background, outside the settlement lock; a 404 counts as done, and failures
  are retried with backoff up to one hour.

Lease status responses carry `charge_basis` and, until the lease is terminal,
`settlement_deadline`; nullifier and request recovery responses for a reserved
lease request carry `settlement_deadline` too. Every settlement payload carries
`charge_basis` and the original `billing_quote`, and fallback settlements add
`settlement_reason`. The payload `type` of each key source is unchanged.

The server refuses to start unless TTL + grace + deadline + twice the settlement
poll interval + 600 seconds is at most half the vault's `challengePeriod()`
(read with the startup key check), and unless the deadline leaves at least 900
seconds of retries after the grace. Finalized evidence therefore exists before
half of the challenge window has passed. With a 24-hour challenge period and
the defaults (300 + 5 + 21600 + 4 + 600 seconds) the check passes; a shorter
challenge period needs a smaller deadline.

## Operator review

Every clamped, deadline, deletion-pending, unsettleable or corrupt-binding
settlement writes a row to the `settlement_reviews` table with one of the
reasons `usage_clamped`, `deadline_worst_case`, `unsettleable_worst_case`,
`finalized_before_key_deletion` or `binding_corrupt`, and logs
`settlement required operator review` at error level. Alert on that line.
Reopening a cancelled lease adds a `binding_reopened` row, as does conceding the
charge of a reopened lease later. The table is a log: one lease can have
several rows, such as its cancellation, its reopening and its final settlement.
A `binding_corrupt` row's detail names the first disagreeing field; either side
of the disagreement may be the corrupt one, which the reopen command tells
apart. A direct lease that may have been delivered gets one such row when its
corruption is found and another when it is cancelled.
`GET /v1/dashboard/settlement?limit=N` (operator-only and never proxied by the
gateway; password-gated like the other dashboard routes on Sepolia) returns:

- `counts`: `pending`, `retrying`, `provisioning`, `cancelled`,
  `unknown_status`, `open_reviews`, `pending_key_cleanups` and
  `next_deadline_in_seconds`;
- `pending`: each unsettled lease with its status, delivery, charge basis
  already committed (`unissued` or `operator_conceded`, otherwise null),
  deadline, seconds remaining, attempts, first error time and last error;
- `reviews`: each review with its reason, charge basis, reported usage, applied
  charge, solvency bound and acknowledgement time.

`GET /v1/dashboard/summary` includes the same counts as `settlement`.
Acknowledge each handled review row by setting its `acknowledged_at`, selected
by its `review_id`; the [Docker guide](../docker/aws/README.md#monitoring) has
the commands.

Keep backups of the server database, for example with sqlite3's online backup
(`sudo sqlite3 -readonly /var/lib/zkapi/server.db ".backup /var/backups/zkapi/server.db"`
on the Docker host), without stopping the server. A backup is never restored
over the live database; it is a source of the authentic saved request when a
lease's own copy is corrupt (see
[Reopening a cancelled lease](#reopening-a-cancelled-lease)).

Every file-backed signing processor holds an exclusive database sidecar lock
for its lifetime. Challenger reads remain available. Stop all older server
writers before deployment: old binaries and manual database writes do not honor
this lock. Preserve the sidecar, database and backup together; never unlink the
lock to bypass an active writer. Do not downgrade a migrated live database to an
older writer. An older writer ignores the settlement deadline, delivery and
review columns, compares saved quotes with its live settings again, treats
`cancelled` and direct provisioning rows as not due, so its settlement can stall
again, and ignores both a lease's commitment to a zero charge and an operator
concession; rows already finalized stay finalized. Rollback requires a
compatible writer or stopped-service reconciliation of affected rows, not
restoring an old database over newer wallet activity.

## Reopening a cancelled lease

A `binding_corrupt` review names the first field in which the lease row
disagrees with its nullifier reservation. The server has not checked which side
is corrupt: the saved request (`openrouter_leases.api_request_json`), the lease
row's other columns, or the reservation (the `nullifiers` row). Wait until the
lease is `cancelled`: a direct lease that may have been delivered is reviewed
when its corruption is found but cancelled only once its key's usage is
captured (at its deadline at the latest), and the command refuses it until
then. Then stop the API server and run the command against its database, with
its proof setup. In the [Docker deployment](../docker/aws/README.md), with `dc`
defined as under its Monitoring section:

```sh
dc stop server
dc run --rm --no-deps --entrypoint zkapi server settlement reopen \
  --db-path /data/server.db --client-request-id "$ID"
dc start server
```

`$ID` is the `client_request_id` the review names. The container sees the
database as `/data/server.db`, and the default `--proof-setup-dir`
(`protocol/setup/v2` under the image's working directory, or
`ZKAPI_PROOF_SETUP_DIR` from the deployment) is the server's setup. On a host
install, run
`zkapi --proof-setup-dir <the server's setup> settlement reopen --db-path <the server's --db-path> --client-request-id "$ID"`;
the global `--proof-setup-dir` goes before `settlement`. The command takes the
server's database writer lock: it refuses while a server holds it, and no
server starts while it runs. It changes nothing unless the lease is `cancelled`
with a `binding_corrupt` review and passes these checks in order; a refusal
names the first field that fails and its repair:

1. The nullifier is not `ClearanceReserved`: that owner already holds a
   clearance and exits by mutual close.
2. The saved request verifies as admission verified it: its payload hashes to
   its `payload_hash`, its proof's authorization tag binds its
   `client_request_id` and payload, and its Groth16 proof verifies against its
   public inputs. Together these cover every field of the request. A request
   that fails, or cannot be read, is the corrupt side. Never recompute the
   reservation from it: the server would then sign a successor for a request
   that its owner never authorized. Instead run the command again with
   `--saved-request FILE` (`-` reads standard input), a JSON copy of the
   authentic request from either source:
   - a backup of the server database:
     `sqlite3 -readonly backup.db "SELECT api_request_json FROM openrouter_leases WHERE client_request_id = '$ID'" > request.json`;
   - its owner's copy, which the wallet keeps until the lease settles:
     `prepared_request` in zkapi-clientd's `pending_journal.json`, in its state
     directory (`jq .prepared_request pending_journal.json > request.json`), or
     in the browser SDK's request journal.

   The copy is accepted only if it verifies, its binding is the
   `api_request_binding` its reservation recorded at admission, and it shares
   the lease row's `client_request_id` or `request_nullifier`. A tampered copy,
   another request its owner authorized for the same note state, and another
   lease's request are refused. If the reservation's `api_request_binding` is
   corrupt too, restore that column from a backup first. In the Docker
   deployment, pass the copy on standard input:
   `dc run -T --rm --no-deps --entrypoint zkapi server settlement reopen --db-path /data/server.db --client-request-id "$ID" --saved-request - < request.json`.
3. The lease row agrees with the verified request: its `client_request_id` and
   `request_nullifier`. The request having verified, the lease row is the
   corrupt side: run the command again with `--rebind`, which sets both columns
   from the request and moves the lease's reviews to its corrected id. It
   refuses while another lease row holds the request's id or nullifier. Do not
   set these columns by hand: `client_request_id` also keys the lease's reviews
   and key cleanup. (A row renamed by hand is still found by its nullifier.)
4. The reservation agrees with it: its row exists, its kind is
   `openrouter_lease`, and its `client_request_id`, `payload_hash` and
   `api_request_binding` match. The request having verified, the reservation is
   the corrupt side. Its `api_request_binding` is a keccak digest of the
   request, which `sqlite3` cannot compute: run the command again with
   `--rebind`, which rewrites a `Reserved` row's fields from the verified
   request, or re-creates a missing row as `Reserved`. It refuses a `Finalized`
   row (a successor is already signed: restore that row from a backup) and a
   row of the request kept under another nullifier (mis-keyed, not missing:
   repair its `nullifier` column instead). Re-creating a missing row assumes
   that no successor was signed for it: a transcript lost with the row is
   signed again.

`--saved-request` and `--rebind` combine. Once every check passes, the command
returns the lease to settlement with its write-once deadline unchanged, and
prints the lease's new state as JSON:

- `client_request_id`: the lease's id, as corrected by `--rebind`.
- `status`: a lease without a key resumes `provisioning`, a direct lease whose
  usage was captured resumes `revoking`, and any other resumes `active`.
- `settles`, how the restarted server settles it:
  - `zero_never_delivered`: a lease never delivered is committed to its zero
    charge at once, so that a retry of the request cannot issue its key.
  - `captured_usage`: a direct key that may have been delivered was disabled
    and its usage captured before the cancellation. That usage, clamped to the
    solvency bound, is charged at the first tick.
  - `measured_until_deadline`: usage is measured until the deadline, then the
    lease falls back to captured usage or its solvency bound. The command
    withdraws a key deletion the cancellation queued and that has not run yet
    (`key_cleanup_withdrawn: true`), so that the key can still be read.
  - `deadline_fallback`: no usage can be measured, because the deadline has
    passed or because a direct key was deleted before its usage was captured.
    The lease is charged its full solvency bound at its deadline (at once if it
    has passed), and the output adds a `warning`.
  - `operator_conceded` or `signed_transcript`, below.
- `reservation`: `unchanged`, or, with `--rebind`, `rewritten` or `recreated`.
- `lease_row`: `unchanged`, or, with `--rebind`, `rewritten`.
- `saved_request`: `unchanged`, or `restored` from `--saved-request`.

With `--zero-charge` the lease is finalized at zero instead, with `charge_basis`
and `settlement_reason` `operator_conceded`: the operator concedes the request's
charge, as the owner's escape would have, and a direct key is deleted. The same
checks apply: a request that does not verify, or a binding still corrupt, is
not conceded either. `--zero-charge` also concedes a lease reopened earlier that
is not settled yet, for instance after a `deadline_fallback` warning; run it
before restarting the server. A request whose successor is already signed
settles from that transcript and cannot be conceded. The command acknowledges
the lease's `binding_corrupt` reviews and records a `binding_reopened` review,
and records another for a later concession.

The restarted server verifies a reopened lease's saved request again, and
checks its binding, deployment and signing key, before it signs anything; a
lease that fails is cancelled again with a new review. The owner's wallet
installs the signed receipt through its ordinary recovery, as for any finalized
lease. Once signed, the transcript is challenge evidence: an escape the owner
started at that state is contested, and the owner exits from the signed
successor state. Reopen before the note expires, or its deposit goes to the
treasury.
