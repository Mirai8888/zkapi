# zkAPI browser SDK

`@openanonymity/zkapi-browser-sdk` owns the browser wallet, local proof worker,
private-note journal, short-lived key issuance and settlement, deposit/withdrawal
recovery, and public payment-history reconciliation. It has no UI,
model-catalog, or chat-storage dependency. The host owns chat and payment UI.

Install a reviewed immutable Git revision, or install its `npm pack` tarball.
No Rust compiler, setup ceremony, or npm publish step is needed to
consume this package. The public proving keys and WASM are included and hashed
in `sdk/assets/manifest.json`; these are public artifacts, not wallet secrets.

```js
import { configureBrowserSdk } from '@openanonymity/zkapi-browser-sdk';
import client from '@openanonymity/zkapi-browser-sdk/client';

configureBrowserSdk({
  configUrl: '/zkapi/v2c/browser-config.json',
  workerUrl: '/zkapi/v2c/assets/zkapiWasmWorker.js',
  // Optional: the host may preserve its explicit opt-in privacy proxy policy.
  transport: (url, init, hints) => hostTransport.fetch(url, init, hints)
});

// Initialize only when private payments are enabled. Importing creates no
// proof worker, network request, wallet connection, or wallet popup.
await client.init();
const unsubscribe = client.subscribe(snapshot => renderBalance(snapshot));
```

Configuration must precede the first initialization. The SDK runs only the
native ETH browser wallet; `mode: 'auto'` and `mode: 'daemon'` are unsupported.
The host config URL supplies the pinned network, vault, server signing keys,
proof hashes, and approved deployment manifest URLs. Runtime URL overrides
remain restricted to that allowlist. Configure the same-origin
`/zkapi-deployment/` rewrite for the chosen trusted deployment, as declared by
the bundled browser config. Private protocol and public manifest/config requests omit account credentials,
including through the same-origin deployment rewrite. An injected transport
receives `credentials: 'omit'` and the existing `{ preferProxy: true }` hint and
must preserve that credential policy. Chat account cookies must never accompany
private proof or key issuance requests.
Never include note secrets, key values, proof bodies, or wallet transactions
in host logs.

## Sepolia shared password

A Sepolia server can require a shared testnet password. Pass
`requestTestnetPassword: async ({ authenticate, signal }) => { ... }` to
`configureBrowserSdk`. Show a password form and call
`await authenticate(value, { signal: dialogAbortSignal })` on explicit submit.
Keep the form open for a rejected password; resolve the callback only after
validation succeeds. Reject on dismissal, and abort its validation request.
Neither the callback nor the SDK should log or persist the password.

Call `client.ensureTestnetAccess({ interactive: true, signal })` before the
host's Send gate, including when reusing a live provider key. Deposit and
access acquisition also enforce this inside the SDK. Read-only funding quotes
fail with `testnet_password_required` until authenticated; they never open a
dialog in background polling. Offer an explicit password action that calls
`ensureTestnetAccess({ interactive: true, changePassword: true })`. The boolean
`client.testnetAuthenticated` contains no credential. Reload clears access.

Cooperative withdrawal authenticates before wallet work and refuses to continue
if the selected private note changes while its password dialog is open.
Unilateral escape requests the service password only when it must check a
private request this device already sent from the current note state.

Public `/health` must report the configured Sepolia `chain_id` and boolean
`testnet_password_required`; missing or invalid discovery fails closed. The
password is validated at `/v2/auth`, then attached only to the configured
Sepolia protocol server's `/v2/` paths as `X-ZKAPI-Testnet-Password`. The host's
trusted same-origin deployment rewrite and opt-in transport retain their
normal roles. Transports must honor `redirect: 'error'` for these requests.
Account cookies remain omitted. RPC, indexer, proof downloads, account
endpoints and provider inference never receive this password. A 401 clears
the rejected credential without replaying a protocol operation; recovery
journals remain authoritative. Mainnet does no password discovery or prompting.

This SDK requires `proof_setup.circuit_id: "zkapi-v2-concession-v1"` in the
deployment manifest and matching `trusted_deployment.circuit_id` in the host
config, a vault with the concession exit (`trusted_deployment.exit_concession:
1`, vault revision 3), and a `trusted_deployment.setup_id` equal to the setup
the bundled WebAssembly is built for (`browser_setup_id()`, also
`setupId` in `sdk/assets/manifest.json`). The vault's immutable verifier,
proving keys, and signing-key pins must match this circuit. Configuration
mismatches are rejected before funding; a profile with
`deployment_status: "not_deployed"` is a placeholder and is refused with
`deployment_not_deployed`. Notes in a `zkapi-v2-note-bound-v1` vault exit
through the legacy build of this SDK, served at its own path.

## External wallets and manual signing

`client.setWalletProvider(provider)` selects an instance-scoped EIP-1193
provider. The default is the browser's injected `globalThis.ethereum`;
`setWalletProvider(null)` restores that default. The SDK never replaces the
browser global. Install the host provider before `client.init()` when restoring
a saved external transaction. Changing providers during an asynchronous SDK
operation throws `wallet_provider_busy`; nested calls retain the same provider
through RPC reads, wallet prompts, journal commits, and receipt polling.
`client.walletProviderBusy` exposes this state. Providers may also expose
`hasPendingTransaction: true` to prevent switching away from an unresolved
durable request after its UI stops waiting. Re-selecting the same provider is
always a no-op.

A host can implement manual signing without a wallet extension: obtain the
user's public account address for `eth_requestAccounts`, use a fixed public RPC
for reads, and display the exact `eth_sendTransaction` payload for submission
with the user's own wallet. The connected address funds deposits and pays
withdrawal gas. By default it is also the destination of a newly prepared
withdrawal. To choose an independent payout address, call
`client.withdraw(mode, onStatus, { destination })`, where `mode` is `mutual` or
`escape`. The destination must be a nonzero Ethereum address, distinct from the
configured vault. An escape's destination cannot change after initiation. On a
vault with `vault_revision` 2, finalization pushes the payout with at most
100,000 gas; a destination that rejects it or needs more gas is only credited
in the vault (`escapePayoutCredits`, `EscapePayoutDeferred`) until someone calls
`claimEscapePayout(destination)`. The SDK then reports that escape as credited,
not returned, and offers the claim (see
[Credited escape payouts](#credited-escape-payouts)). On an older vault an
escape to a destination that rejects ETH cannot finalize, so the SDK refuses
to start one unless the caller overrides that check. Steer users to a
destination that accepts a plain ETH transfer within 100,000 gas, such as an
ordinary account; `client.checkEscapeDestination(destination)` simulates the
vault's push to it. The host must confirm the intended address
and network with the user. The SDK binds it into the durable proof; an explicit
different destination on a later call is rejected. Omitting the option when
resuming always retains the saved destination, even if the gas-paying account
changes. Concurrent withdrawals with different requested destinations cannot
share an action. Native deposits require the SDK's payable vault calldata
and its exact ETH value; a plain ETH transfer does not create a private note.

For durable manual signing, the provider implements
`acknowledgeTransaction(hash)`. The SDK then includes a `zkapiRecovery` field
alongside `method` and `params` in each send request. It contains only public
deployment and journal identities, never note secrets, private state, or proof
plans. Before displaying an executable payload, the provider must durably save
the transaction (including its exact nonce) and this context. It must preserve
them through UI dismissal and reload, verify a supplied hash matches the exact
chain, sender, target, value, nonce, and calldata, and retain that hash until
the SDK acknowledges it. Do not forward `zkapiRecovery` to a remote RPC service.

For a live request, return the verified hash to `request()`; the SDK acknowledges
after the existing deposit/withdrawal journal accepts it. After reload, call
`client.resumeExternalTransaction({ transaction, hash, context })`, where
`context` is the saved `zkapiRecovery`. This independently reads and checks the
transaction, validates the durable SDK claim and exact plan, and invokes the
same atomic journal methods. It does not confirm deposits or withdrawals by
itself. Continue using `recoverBrowserDeposit()`, `syncWithdrawal()`, and
`syncEscapeWithdrawals()` for the usual canonical-state and finality checks.
Resumption is idempotent when a previous journal write succeeded but host
acknowledgement was interrupted. The host owns the public pending-send record;
private wallet material and all settlement and payout decisions stay in the SDK.

To recover fee speed-ups while a transaction is still awaiting its receipt,
providers may implement `getVerifiedTransactionHashes(originalHash)`,
`beginTransactionReceiptWait(originalHash)`, and
`endTransactionReceiptWait(originalHash)`. Return only hashes independently
verified against the same original chain, sender, target, calldata, value and
nonce. The SDK checks each candidate's own receipt and acknowledges the hash
that actually mined; either the original or its replacement may win the nonce.
The host should add newly verified hashes to the active receipt consumer rather
than start a concurrent resume operation. Preserve that consumer's completed
hash through cross-tab acknowledgment, and make repeated acknowledgments of
completed transactions harmless to any newer pending transaction. These hooks
track receipt-only requests; browser deposit/withdrawal recovery remains journal-owned.

In the host build:

```js
import { build } from 'esbuild';
import { buildBrowserSdkAssets } from '@openanonymity/zkapi-browser-sdk/build';

await buildBrowserSdkAssets({
  outDir: 'dist/zkapi/v2c',
  publicPath: '/zkapi/v2c/', // the default
  network: 'sepolia', // or 'mainnet'
  build
});
```

The helper emits `browser-config.json`, `assets/zkapiWasmWorker.js`,
`wasm/zkapi_browser_bg.wasm`, `proofs/request.pk`, `proofs/withdrawal.pk`,
`proofs/request.vk`, and `sdk-assets.json` (schema 2: `circuitId`, `setupId`,
`sourceRevision`, `publicPath` and the emitted hashes). It verifies all source
artifact hashes, the WebAssembly's own circuit and setup, and the profile's
proving- and verifying-key pins before writing anything. It refuses a
placeholder profile (`deployment_not_deployed`), a profile of another circuit
(`incompatible_proof_circuit`) or setup (`setup_mismatch`), a profile without
`exit_concession: 1` (`exit_concession_required`), and a mainnet profile on
any setup but the ceremony's `mpc-1` (`development_setup_on_mainnet`). Both
shipped profiles are `not_deployed` placeholders until their vaults exist.
The default `publicPath` is `/zkapi/v2c/`: proving keys are fetched with
`cache: 'force-cache'`, so new keys need URLs the legacy build never used.
The host supplies its esbuild implementation, controls its CSP/rewrites, and
hashes these emitted assets in its deployment manifest. Proof downloads are
verified again inside the worker; every key download must carry its SHA-256
pin. No private credentials are required to build either network.

### Building and checking the WebAssembly

Maintainers build the bundle with `scripts/build-browser-client.sh --setup
dev|mpc-1`. `mpc-1` is the production bundle, which loads only the ceremony
keys pinned in `zkapi-proof`; `dev` loads only the development keys of
`protocol/setup/v2-concession-dev` (CI, tests and the drill vault). The script
copies the setup's `request.pk`, `withdrawal.pk` and `request.vk` into
`sdk/assets/proofs/` and rewrites `sdk/assets/manifest.json` with the hashes,
the setup's VK keccak256 values and `sourceRevision`, the commit the bundle
was built from (the WebAssembly sources must be committed first). The build is
reproducible: `rust-toolchain.toml` pins rustc 1.99.0, the script requires
wasm-bindgen-cli 0.2.117, uses `Cargo.lock` as is, and remaps every absolute
build path. `npm run verify:wasm` rebuilds into a temporary directory and
fails unless every `sdk/wasm/` file matches the manifest byte for byte;
`npm run verify:assets` checks the committed hashes without Rust.

The SDK uses IndexedDB, local/session storage, Web Locks, BroadcastChannel,
revision checks, and signed receipt validation to manage wallet state. Hosting
the same SDK on a different origin does not transfer browser wallet data. A model adapter must select one of
`CHAT_SPENDING_TIER_USD` (`1`, `2`, `3`, `4.5`, `6`) without disclosing the user's
exact balance. The SDK settles/rekeys when a selected cap changes; only actual
usage is charged. Requests stop at the note's original expiry. On a
`vault_revision` 2 vault the treasury can claim the note only after
`effectiveExpiry(noteId)`, which paused time and a challenge can extend; the
SDK reads that view only for the escape override below.

Run `npm run test:sdk` in this checkout. For an installed package, run
`node --test node_modules/@openanonymity/zkapi-browser-sdk/sdk/test/*.test.mjs`
from a host that provides esbuild as a development dependency. The tests use
local fixtures and do not connect a wallet or broadcast transactions.

## Transmitted requests and safe withdrawals

A proved request leaves the device when it is sent, and every request and
withdrawal at one note state shares that state's nullifier. The SDK therefore
keeps an append-only archive of transmitted requests in the existing IndexedDB
`archives` store (records `request_journal` and `request_evidence`; the database
version stays 3, so older builds keep opening it). The archive record and the
write-ahead journal are committed in one transaction before the request is
sent. A journal leaves the wallet only in the same write that installs a
verified next state or records its outcome in the archive. A server error string
alone never discards it. A `stale_root` reply is first checked against the
pinned vault RPC (the same request is retried while the vault still has the
proof's root). Only then is the server's own nullifier record consulted.
An archived request keeps its full journal, including the private
rerandomization, while its note state is current, so a receipt the server
finalizes later still installs. A record is resolved only when the next state
is installed or the note closes. Resolved records are compacted (no proof,
payload or rerandomization) and pruned to the newest 256 per deployment. No
host action is needed. In-flight journals from older builds migrate on the
first read.

Each note state is bounded. At most 16 of its unresolved requests count toward
a per-state cap. Past the cap, the oldest discarded requests whose nullifier
read `unknown` or `clearance_reserved` at least 20 minutes after their request
time are evicted. Eviction only takes a record out of the cap: an `evicted`
record keeps its journal, still marks its state as transmitted for the gates
below, and still installs a later receipt. A state keeps at most 64 unresolved
records, evicted ones included. Beyond that, a new chat fails with
`request_archive_limit` before proving, and nothing is evicted or discarded.
Chats at that state resume only if the server settles one of its requests: the
receipt still installs and resolves every record there. A request the server
never accepted (for example, a quote that expired before acceptance) never
settles, so waiting does not help and the balance has to be withdrawn: by
mutual close, which needs the server's clearance, or on a `vault_revision` 2
vault also by escape. A strict vault never escapes at a transmitted state, so
there mutual close is the only exit from that note, and it needs a clearance
the server grants without an ownership proof (below); otherwise only the
operator can help. Reaching the ceiling takes at least 64 failed chats at one
state, spread over at least an hour.

Each record keeps its newest eight server observations. Of its older ones it
keeps at most one: the newest that is a receipt claim or a reading that ends
one (both below). Trimming therefore never changes whether a claim stands.
"Newest" and "after" mean save order, never the device clock. The store stamps
every observation it saves with a sequence number (`seq`) inside its write
transaction, above every one already saved. A clock that ran fast or stepped
back therefore cannot make an older reading outrank one saved after it. Each
observation's `at` is the device time of its save; it only decides eviction
(above). Observations saved by an older build have no `seq`. They order before
every stamped one, by `at` among themselves. An older build open in another tab
drops the stamps of each record it writes.
`unknown`, `reserved`, `finalized` and `clearance_reserved` are readings of the
state's nullifier from
`GET /v2/nullifiers/{nullifier}`; `unavailable` is a failed read. A `finalized`
reading that carried a receipt is marked `receipt` and names the receipt's
`client_request_id` when it has one. A receipt that `GET /v2/requests/{id}`
returns and this browser cannot apply is saved as such a `finalized`
observation too. A receipt that installs resolves every record at its state,
so such an observation at the current state is a receipt claim: the server
says the nullifier was finalized with a receipt this browser could not apply.
The claim stands until a reading saved after it reports the nullifier `unknown`
or `clearance_reserved`, also when that reading was saved with another request
at the same state. A failed read, `reserved`, or `finalized` without a
receipt leaves it standing. `unaccepted` records that
`POST /v2/openrouter/leases/{id}/expire` answered `expired_unaccepted` or
`superseded_unaccepted` for that one request. That
answer only echoes identifiers the wallet sent, so it is never treated as a
nullifier reading: it never makes a record evictable and never corroborates a
discard. The escape and clearance gates decide on a fresh nullifier reading,
and a saved observation never allows a withdrawal. A standing receipt claim
only makes the escape override require that claim's own acknowledgement
(below).

Escape and clearance behavior depends on two optional keys in
`browser-config.json`'s `trusted_deployment`, read only from that build-pinned
trust anchor and never from the served manifest:

- `vault_revision` (integer; absent means `1`, the deployed vaults). With `2`
  (a vault whose challenge is non-destructive and that keeps recent roots), an
  escape at a transmitted state is allowed when the server reports the
  nullifier `unknown` or `clearance_reserved` and no challenge was observed.
  Exits carry no Merkle path and the vault accepts any root it ever held,
  so a withdrawal proof is reused until its `valid_until`. Without it (strict mode) an escape at a transmitted state is
  always refused (`transmitted_anchor_escape_unsafe`), and a moved root always
  re-proves. A declared `2` is checked on chain before it takes effect:
  initialization reads the vault's `ROOT_HISTORY_WINDOW()`, a view only that
  vault has, and refuses with `vault_revision_mismatch` if the read reverts,
  returns no word or is not 86400. Later, a hardened-only view that reverts
  (`challengedNullifiers` or `effectiveExpiry`) is the same configuration
  error, never read as "not challenged" or "not about to expire".
- `clearance_ownership_proof` (`"required"` or `"optional"`). Mutual close
  then sends an escape-form ownership proof (a second withdrawal proof, to the
  user's real destination and current balance) with
  `POST /v2/withdraw/clearance`. This also happens when `vault_revision` is 2 or
  more. Otherwise the request is sent without a proof first. A server with
  legacy clearance on may reserve on it, so the note is marked withdrawal-only
  before it is sent. If the server answers `400 clearance_ownership_required`,
  or `503 legacy_clearance_capacity` (an upgraded server whose shared
  proof-less budget is spent), nothing was reserved: the wallet restores its
  previous withdrawal state, generates the ownership proof, and only then marks
  the note withdrawal-only again and sends the request once more with the
  proof. A proving failure or a refused transmitted-state check (below) leaves
  that previous state, so a note that was usable for chat stays usable. After
  any other failure of the proof-less request the note stays withdrawal-only,
  because the server may have reserved it. The ownership proof is never
  persisted. The returned clearance is persisted with the plan and reused
  while the state's nullifier is unchanged.

Clearance retries: a gateway's `429 gateway_rate_limited` (the request never
reached the API) is retried with the same body after its `retry_after_seconds`,
and so are `409 stale_root` and `503 capacity_exhausted` for a request with a
proof (the server sends neither for a proof-less one). All waits share one
budget of 15 seconds, and a wait that does not fit ends the retries. A 429 that
outlasts them fails the close with `gateway_rate_limited`; trying again later
completes it. From an honest gateway it reserved nothing, but it is unsigned,
and whoever sent it may have read the body. So the wallet restores its previous
withdrawal state only when the request carried no ownership proof, or when
`vault_revision` is 2. After a request with an ownership proof on any other
vault, the note stays withdrawal-only and the error carries
`error.data.withdrawal_only: true`. That proof is an escape at the state's
nullifier, and a request proof from the same state could challenge it, which
on such a vault burns the nullifier, so the wallet never makes one from that
state. Closing again or escaping still works. The wallet does not re-prove on
its own: a `stale_root` that outlasts the budget fails the close, and the next
attempt proves at the then-current root.

An ownership proof is itself a valid escape at the state's nullifier. On a
`vault_revision` 2 vault it is generated for a transmitted state only when the
server reports that nullifier `unknown` or `clearance_reserved`. On any other
vault a challenge burns the nullifier, and whoever holds a request proof sent
from that state (for example a gateway that withheld it) could submit the
ownership proof as an escape and challenge it. There the wallet never generates
one for a transmitted state, whatever `clearance_ownership_proof` says: after
the same server reading, mutual close sends only the proof-less request. If the
server answers it with `400 clearance_ownership_required` or
`503 legacy_clearance_capacity`, the wallet restores its previous withdrawal
state and refuses with `409 transmitted_anchor_ownership_unsafe`
(`error.data.clearance_error_code` names the server's answer). The note stays
usable for chat: a request that settles moves it to a new state, which closes
normally with a proof. A state that never left the device is unaffected.

On a revision-2 vault, `client.withdraw('escape', onStatus, { destination,
overrideUnsettledRequest: true })` is an explicit, separately keyed escape
override for a request the server never settles. It is available once
`browser-config.json`'s `unsettled_request_escape_after_seconds` has elapsed
since this device sent the request (default 43200, clamped to 3600–604800;
keep it above the server's settlement deadline), or earlier when the note's
`effectiveExpiry` is within a challenge period plus a margin. A receipt the
server finalized installs instead, and only a receipt that verifies vetoes the
override. The override never abandons another tab's live key, and the archived
journal still installs a later receipt. Before the user overrides, show the
override's warning, then pass the acknowledgement that goes with it as
`overrideUnsettledRequest`. Both come from a refusal that offers the override
(`error.data.escape_override_warning` and
`error.data.escape_override_acknowledgement`) or from
`snapshot().config.escape_override` (`warning` and `acknowledgement`). The
acknowledgement is `true` for the general warning and
`'receipt_journal_missing'` for that code's own warning (see below), which also
covers the general case. While the server's claim of a finalized receipt this
browser cannot apply stands (the fresh reading, or a receipt claim saved
earlier that the fresh reading does not contradict), the override never
proceeds with `true`, also after the grace period. It is refused with
`receipt_journal_missing`, that code's warning and its acknowledgement. When
that refusal rests on a saved claim, its message says that the server earlier
reported it, and `error.data.nullifier_status` is the fresh reading (for
example `unavailable`). The other refusals that offer the override keep the
code of their fresh reading and carry the same warning and acknowledgement as
the snapshot. A claim first read during an override can still change the
warning to show. `snapshot().config.escape_override` is `null` on
strict vaults, where no override exists. Escape gates contact the server only
for a transmitted state; on Sepolia that read may prompt for the password.

New 409 codes: `request_settlement_pending`, `transmitted_anchor_unconfirmed`,
`transmitted_anchor_escape_unsafe`, `transmitted_anchor_ownership_unsafe`,
`anchor_challenged`, `nullifier_challenged`,
`receipt_journal_missing`, `receipt_response_missing`, `receipt_pending_install`,
`request_archive_limit` and `withdrawal_submission_pending`. Vault reverts map to
`unknown_root`, `challenged_nullifier`, `invalid_destination` and
`vault_paused`. A refusal that offers the override carries
`error.data.escape_override_after` (milliseconds; no later than now once the
override is ready and only its acknowledgement was missing),
`error.data.escape_override_warning` and
`error.data.escape_override_acknowledgement`: the escape gate's refusals, the
override's own refusals, and a plain escape's `receipt_journal_missing`.
`snapshot().config` adds `vault_revision`, `escape_override` (`grace_seconds`,
`warning`, `acknowledgement`), `unresolved_requests` (per request at the
selected state: `client_request_id`, `kind`, `disposition` (including
`evicted`), `created_at`, `server_status` (the newest observation),
`server_status_at`, `escape_override_after` (when the override opens absent an
imminent expiry: the grace after the live request's transmission while one
exists, else after the earliest archived one; `null` on strict vaults and at a
challenged state); no proofs) and `last_settlement`
(`charge_applied`, `charge_basis`, `settlement_reason`). Receipts are installed
against the proof-bound billing quote, never re-validated against changed
manifest price pins. A worst-case charge equal to the proven bound is valid.

Challenge evidence is recorded only from a finalized
`EscapeWithdrawalChallenged` log for the note and nullifier. A server reply such
as `nullifier_used` is advisory. A challenged state is never escaped again; the
wallet installs the server-signed successor (from the archived journal) and
withdraws from that next state.

`receipt_journal_missing` means the server reports a finalized request at the
current state with a receipt this browser cannot apply. Either the browser
holds no journal for its `client_request_id` (for example, one an older SDK
build discarded), or the receipt does not verify. A lying server or gateway
can send the same answer, for example `finalized` for an invented
`client_request_id` at a state whose nullifier the honest server never
reserved. Only a receipt that verifies vetoes the escape override, so on a
revision-2 vault the override is offered for this code on the same schedule as
for the others, with its own warning and its own acknowledgement,
`overrideUnsettledRequest: 'receipt_journal_missing'`. A plain escape refused
with this code offers both wherever the override applies (never at a challenged
state), also when the receipt surfaced while recovering a live request. If the
claim is genuine, the server holds the finalized transcript, so the escape will
be challenged, its gas is lost and the note then needs the operator's help. If
the claim is false, the escape is the only exit. Mutual close is refused at that
state on every vault, and strict
vaults have no override, so there only the operator can help. For a genuine
claim, the operator can, for example, mark that state's nullifier
`ClearanceReserved` and sign its mutual-close clearance (forgoing that
request's charge), after which `withdraw('mutual')` withdraws the current
balance. On a strict vault the wallet asks for that clearance without an
ownership proof (above), so the server must grant it proof-less, which needs
its legacy clearance on; ownership is then verified outside the protocol. On a
revision-2 vault this also works after a challenged escape, because a
challenge does not burn the nullifier.

## Credited escape payouts

On a `vault_revision` 2 vault, `finalizeEscapeWithdrawal` closes the note and
pays the treasury even when its push to the destination fails. The balance is
then added to `escapePayoutCredits(destination)`, and the receipt carries
`EscapePayoutDeferred(noteId, destination, amount)` before
`EscapeWithdrawalFinalized`. `EscapeWithdrawalFinalized` alone therefore does
not prove that the destination was paid.

The SDK reads that receipt wherever it finalizes an escape (`finalizeEscape`,
and the background check of a submitted finalization). When it carries the
vault's credit log for the note and destination, the withdrawal record gets
`payoutCredited: true`, `payoutVerified: false`, `creditedAmount` (vault units)
and `payoutCreditEvidence: "receipt"`. The status message says that the escape
closed but the destination did not accept the payout, which the vault holds for
it, and `finalizeEscape` also returns `payoutCredited: true`. Show such a
withdrawal as credited, never as returned. The fields survive finality, when
the record's recovery material is removed. An escape that another device or a
third party finalized has no receipt in this browser, and a receipt can also be
unreadable for a while. On a `vault_revision` 2 vault the SDK then reads
`escapePayoutCredits(destination)` at the block where the note reads Closed. A
nonzero credit marks the record credited, with
`payoutCreditEvidence: "vault_credit"` and `creditedAmount: null`, because that
credit can also hold other escapes' payouts to the same address. This is the
only reading that later evidence replaces: when this browser's own
finalization receipt is read and shows the push was paid, the record becomes
`payoutCredited: false`, `payoutVerified: true`. Receipt and claim evidence is
kept: a pass that cannot read the receipt again does not undo a proven push or
credit. If the note reads open again at or after the block where it was seen
Closed, a reorganization removed that close, and the SDK resets the record's
payout, credit and claim fields. `payoutVerified: true` means that a receipt
proved the push or, together with `payoutClaimed: true`, that the credit was
delivered (below). `client.creditedEscapePayouts` lists the credited records
not yet seen delivered.

Anyone can deliver a credit, also while the vault is paused.
`await client.claimEscapePayout(recordId, onStatus)` reads
`escapePayoutCredits(destination)` and sends `claimEscapePayout(destination)`
from the connected account. That account pays only gas; the vault pays the
destination all of its credits. Only an `EscapePayoutClaimed` log for that
destination proves the delivery. A claim pays the credits the vault holds when
it executes, so the SDK marks a credited record of that destination delivered
only when the record's `closeBlockNumber` (its finalization block, or a later
block where the note was first seen Closed) is lower than the claim's block. It
sets `payoutClaimed: true`, `payoutVerified: true`,
`payoutClaimEvidence: "claim_receipt"`, `payoutClaimTransactionHash`,
`payoutClaimBlockNumber` and `payoutClaimedAmount` on those records, and
returns `{ status: "claimed" }`. A record credited in the claim's block or later
keeps its credit, and a later claim delivers it. Credits leave the vault only
through such a claim. So a zero credit, read at a block where the note reads
Closed, means someone else already delivered it; the records whose note reads
Closed there are then marked the same way with
`payoutClaimEvidence: "credit_cleared"` and no transaction. While the
destination still rejects ETH, the claim fails its gas estimate with
`native_transfer_failed` before the wallet is asked to sign, and the credit
stays. Claims already sent from any credited record of that destination are
checked first. While one is still pending, the call returns
`{ status: "pending" }` instead of sending another, because the pending claim
also pays this record's credit. A manual signer's claim carries
`zkapiRecovery.kind: "escape-payout-claim"`; `resumeExternalTransaction`
accepts it, and the next `claimEscapePayout` checks it.
`client.readEscapePayoutCredit(destination)` reads the credit directly.

Before proving a new escape, the SDK simulates the vault's push: a plain
transfer of one vault unit from the vault to the destination. On a
`vault_revision` 2 vault the call gets the payout gas (21,000 intrinsic gas,
100,000, and the 2,300 call stipend); on older vaults it gets all gas. A
revert or another EVM halt (for example geth's `out of gas` or anvil's
`EVM error OutOfGas`) counts as a failed transfer. On a `vault_revision` 2
vault the escape then still proceeds, because the payout is credited, but
`onStatus` shows a warning first and the result carries `destinationWarning`.
On an older vault such an escape could never be finalized: the note would
stay pending, and expiry cannot claim it either. `withdraw("escape")` therefore
refuses before proving, with error code `escape_destination_unpayable` and
`error.data.override_option: "overrideDestinationCheck"`. Only after the user
has confirmed that address anyway, call `client.withdraw("escape", onStatus,
{ destination, overrideDestinationCheck: true })`; the warning is still shown.
A host can run the same check before the user confirms the address:
`client.checkEscapeDestination(destination, { finalBalance })` returns
`{ destination, accepts, warning }`, where `accepts` is `null` when the RPC
cannot tell. Such an unknown result never refuses an escape.

Withdrawal records written by earlier builds have no `payoutCredited` field and
keep their meaning. SDK builds before this one report a credited escape as
returned and offer no claim.

## Moving to a newly pinned deployment

The runtime holds one selected note per origin, and it lists and acts only on
its own deployment's withdrawal records. Exit an older deployment completely
before funding a note on a newly pinned one: withdraw its selected note and
finish or finalize every one of its withdrawals. Setting a withdrawal aside is
not an exit. A set-aside mutual close, a pending or challenged escape, a close
awaiting finality and a finalization in flight all stay bound to the older
deployment: only a runtime configured with that deployment's profile can
submit, finalize or restore them. Once a note on the new deployment is funded,
the older profile refuses to load in this browser (`This browser contains a
wallet for <id>`) until that note is withdrawn, while an older note that is
active again (a set-aside mutual close, or a challenged escape on a vault that
burns the nullifier) can be claimed at its expiry.

Hosts choose the profile before configuring the SDK, from
`readBrowserWalletHoldings()` in `@openanonymity/zkapi-browser-sdk/store`. It
reads the stored wallet once and returns
`[{ deploymentId, runtime, withdrawals: [{ recordId, noteId, mode, phase }] }]`:
the runtime slot's deployment while that slot holds durable state (`runtime:
true`; a note, journal, lease, pending deposit, deposit draft, prepared
withdrawal or unfinished late attempt), and every deployment with an open
withdrawal record (any record except a finalized close with no finalization in
flight). Configure an older deployment's profile while it is listed, and offer
its withdrawals; configure the newer profile only when it is not. When several
deployments are listed, the entry with `runtime: true` comes first and is the
only one that can load until its slot is empty. `browserWalletHoldings(snapshot)`,
`browserRuntimeHoldsState(runtime)` and `isOpenBrowserWithdrawal(record)` apply
the same rules to a `readBrowserWalletSnapshot()` the host already read. A
loaded runtime also reports what it cannot reach:
`snapshot().config.other_deployment_withdrawals` lists the open withdrawal
records of other deployments (`deployment_id`, `record_id`, `note_id`, `mode`,
`phase`; no note state). A host should not offer a deposit while it is
non-empty. The one exception is an escape on an older deployment that its
operator announced as stuck because its destination rejects ETH
([migration guide](../docs/migration-hardened-vault.md#phase-3-stop-deposits-to-the-legacy-vault-and-drain-it),
Phase 3, step 2): when that deployment's entry has `runtime: false` and each
of its withdrawals is such an announced escape (`mode: "escape"`, matched by
`noteId`), the host may configure the newer profile and offer deposits, and
shows the owner that note ID and how to finalize it on chain. Never clear site
data to get past these checks.

A finalized escape whose payout the vault only credited
([Credited escape payouts](#credited-escape-payouts)) holds no note. It does
not keep its deployment listed and does not block a deposit elsewhere, but the
user still has a payout to claim there. `readBrowserWalletPayoutCredits()`
lists the unclaimed credits of every deployment as
`[{ deploymentId, recordId, noteId, chainId, contractAddress, destination,
creditedAmount }]`. `browserWalletPayoutCredits(snapshot)` and
`isUnclaimedPayoutCredit(record)` apply the same rule to a snapshot the host
already read. A loaded runtime reports other deployments' credits in
`snapshot().config.other_deployment_credits` (`deployment_id`, `record_id`,
`note_id`, `chain_id`, `contract_address`, `destination`, `credited_amount`).
This SDK's claim action needs that deployment's profile, which loads while
the runtime slot holds no other deployment's state. Anyone can also call
`claimEscapePayout(destination)` on that vault directly; the SDK recognises
that delivery from the zero credit the next time that profile's claim action
runs.

## Native ETH deployments

Native ETH requires a trusted native vault and billing-server configuration.
Token manifests are unsupported and rejected before wallet mutation. Notes and
transaction journals are bound to the configured chain and vault.
Native manifests pin `billing_asset: "native_eth"`, `billing_unit: "gwei"`,
`native_asset_wei_per_unit: "1000000000"`, a null `billing_token_address`,
`rpc_url`, `native_price_feed_address`, `native_price_feed_decimals: 8`, and
`native_price_max_age_seconds`. The browser config must pin the same values.
Protocol amounts are whole gwei, bounded by JavaScript's safe-integer range.
For a payable deposit, `msg.value` must equal the exact ledger
amount multiplied by one billion wei. Token minting, approvals and transfers are unsupported.
Withdrawals and all other protected calls retain zero transaction value.

`client.isNativeEthFunding` identifies native deployments.
`await client.quoteDepositUsd("10")` makes credential-free reads of the pinned
Chainlink feed at a finalized block, without connecting a wallet, preparing a
note, or signing. The finalized reference price can lag the latest block; the
quote exposes the feed's actual update time. Native deployment freshness pins
include the feed heartbeat plus a finality allowance (4,500 seconds for the
reviewed one-hour ETH/USD feeds), and any longer delay fails closed.
It returns `{ amount, ethAmount, depositWei, usdAmount, priceUpdatedAt, price,
chainId, contractAddress }`. Amount and wei fields are exact decimal strings;
`priceUpdatedAt` is Unix seconds. Persist this quote with the host's deposit
intent. The ETH principal remains fixed while a user funds the address; a
fresh quote must never silently change it. Native deposits accept up to nine
ETH decimal places. Recovery validates the exact saved calldata and payable
value against the durable deposit journal.

For a browser-controlled funding address, prepare the actual native deposit
before quoting its fee:

```js
const prepared = await client.prepareDepositQuote(quote.ethAmount, { from: fundingAddress });
// Simulate prepared.transaction using the host's public RPC. When the address
// is unfunded, override only that sender's balance, never contract storage.
// Show estimated fee, additional buffer and principal + reserved fee separately.
// Refresh the preparation and fee quote before the explicit Next action.
await client.deposit(quote.ethAmount, onStatus, { preparedOperationId: prepared.operationId });
```

`prepareDepositQuote` is available only for native ETH browser wallets. It
returns `{ operationId, commitment, amount, depositWei, chainId,
contractAddress, transaction: { from, to, data, value } }`; it never returns
note secrets, connects a wallet, claims a submission, signs, or broadcasts.
It stores the note secret in a separate durable `depositQuote` draft, which is
not a pending deposit or payment-history entry. Read-only polling and reload
cannot promote it. Same-amount refreshes retain the commitment and operation
identity while updating the Merkle append path. Changing the amount replaces
only the unused draft. An active note or unresolved deposit must be recovered
before another quote is prepared. After a proven pre-broadcast rejection, an
existing pending deposit can be requoted only when
`config.pending_deposit.funding_quote_available === true`. Its principal,
commitment and operation remain fixed. Claimed, signed and ambiguous
transactions are excluded; hosts must use this authoritative flag rather than
infer safety from the visible transaction hash. SDK storage keeps drafts
deployment-bound.

For an ambiguous funding-address deposit, an explicit user action may call
`await client.prepareDepositRetry(onStatus)` to review retry fees. This checks
for a mined deposit first and returns `status: "confirmed"` if recovered.
Otherwise it authorizes only an exact retry fee review, including a saved
`retry_exact` operation. It does not sign or submit. The funding-quote flag
then permits simulation of the saved calldata without
refreshing its Merkle path. After the quote is shown, a separate explicit Next
uses the same `preparedOperationId`. A pre-broadcast fee rejection keeps that
exact path for the next quote. Only finalized consumed-slot recovery permits
rebasing an uncertain old operation, and it records which ambiguity was
resolved while retaining the original claims for late recovery. Ordinary
MetaMask retry behavior remains unchanged.

An explicit deposit with `preparedOperationId` atomically promotes that exact
draft under the wallet's cross-tab lock. A stale operation or changed principal
fails before any submission. An ordinary deposit without the option (including
MetaMask) discards an unused draft. Refreshing a Merkle path never changes the
principal or commitment. The host must bind its displayed fee authorization to
the returned operation and commitment and enforce that ceiling again on the
actual transaction; a quote is not permission to sign. The actual transaction
continues to simulate the current vault state and may need a new quote/top-up
if network fees increase. Unsupported balance overrides must fail with a clear
estimation error rather than silently substituting a fixed reserve.

After native deposit confirmation, `client.snapshot().deposits` may include
`feeWei`, `fundingAddress`, `gasUsed`, `effectiveGasPrice`,
`receiptBlockNumber`, and `receiptBlockHash`. These fields are stored with the
existing public deposit history, including across reload or note closure.
`feeWei` is mined `gasUsed * effectiveGasPrice`, not the maximum gas limit or
fee quote. The SDK verifies the receipt event, exact mined transaction and
canonical block before recording it. Deposit recovery checks saved transaction
hashes for that same evidence before clearing its journal. Missing or historical
fee evidence leaves these fields absent; hosts must show unavailable rather
than zero. The public funding-address balance is read separately: it may include
previous funds and is not necessarily only this deposit's unused fee buffer.

`client.formatBillingAmount(units)` returns decimal ETH on native deployments;
`client.formatMoney(units)` uses the current verified quote, returning `—`
when none is fresh. Normal wallet refreshes attempt a public price refresh at
most once per minute; `refreshEthUsdPrice({ signal })` explicitly refreshes it.
`creditsPerUsd` is only a display conversion on native deployments, may be
fractional, and is `NaN` without a fresh quote. It is not an integer billing
scale and must not be used to construct a payment or proof.

For inference, the server's public `/v2/billing/quote` is checked against the
pinned feed's exact round in finalized chain state. New issuance accepts only
the latest finalized round. The complete quote is bound into the
prompt-free authorization payload before generating its proof. Fixed USD
model tiers round upward to whole gwei; the provider's USD limit rounds down
to microdollars. The saved request, issued key, and settlement all retain that
same quote, even if ETH's price subsequently changes. A quote that expires or
is superseded before acceptance can be discarded only after the read-only
`POST /v2/openrouter/leases/{id}/expire` endpoint confirms that exact saved
request expired or was superseded without acceptance under the server’s
issuance lock. The response must match the saved request ID, nullifier, and
payload hash. Local wall-clock expiry, a changed market price, or a missing
nullifier alone never clears a proof. Wallet balances continue to display their
current USD value independently of a running key's frozen conversion.

## Default deployments

The packaged mainnet and Sepolia configurations use
`https://zkapi-mainnet.openanonymity.ai` and
`https://zkapi-sepolia.openanonymity.ai`. Each profile pins its native ETH vault,
signing keys, proof artifacts, and circuit hashes. Hosts may supply reviewed
explicit profiles as described above. The packaged profiles declare neither
`vault_revision` nor `clearance_ownership_proof`: they run in strict mode and
send clearance requests without a proof first, adding one when the server
answers `400 clearance_ownership_required` or `503 legacy_clearance_capacity`.
Once a deployment's server is upgraded, its profile must declare
`"clearance_ownership_proof": "optional"` in `trusted_deployment`, because
proof-less requests share a legacy budget that anyone can exhaust (see the
[migration guide](../docs/migration-hardened-vault.md#phase-2-publish-clients)).

The runtime checks that active notes, pending deposits, leases, and unfinished
recovery state match the selected deployment. Preserve wallet state and recovery
journals with their matching configuration.

## Closing a deployment to deposits

`trusted_deployment.deposits` (`"open"`, the default when absent, or
`"closed"`) is the browser half of a deposit cutoff for a deployment being
drained. Like the keys above it is read only from the build-pinned profile and
validated with it; any other value fails initialization. With `"closed"`:

- `quoteDepositUsd`, `prepareDepositQuote` and `deposit` refuse to start a new
  deposit with `409 deposits_closed`, before any chain read, note secret or
  wallet prompt. `snapshot().config.deposits` is `"closed"` (otherwise
  `"open"`), so the host can hide its deposit action.
- An unused `depositQuote` draft is discarded at initialization and on a
  refused attempt. It was never signed, and it would otherwise count as this
  deployment's wallet state.
- A deposit already started is never stranded. A pending deposit, signed or
  not, stays tracked, completable and recoverable for its original amount
  (`deposit`, `prepareDepositRetry`, `retryUnknownDeposit`,
  `retryDroppedDeposit`, `recoverBrowserDeposit`); only replacing it with a
  different amount is refused. Withdrawals, chats and recovery are unaffected.

The SDK builds a deposit's Merkle path from `/v1/tree/snapshot`, which
withdrawals also need, so a gateway that stops serving the deposit-only tree
routes does not stop browser deposits. Set this flag in every browser profile
of the drained deployment, legacy-exit builds included. Builds older than this
release ignore it and keep offering deposits.
