# Client privacy and recovery boundaries

`zkapi-clientd` runs on the user's computer. An OpenAI-compatible UI sends its
prompt to the loopback API; the daemon acquires a short-lived OpenRouter key
through the zkAPI proof protocol and sends inference directly to the provider.
The wallet/prover helper receives neither prompts nor responses nor model IDs.
The provider sees the inference content. Client applications may store their
own transcripts; the daemon cannot hide content already given to that UI.

Direct HTTPS is the default. It exposes the source IP to destination services
and uses local DNS, so network timing/IP can correlate activity even though
credential issuance is unlinkable. Optional Wisp carries destination TLS with
certificate verification and hides the source IP from destination services;
the relay still sees connection metadata. A configured relay failure never
falls back to direct HTTPS. A loopback SOCKS5 route can send destination DNS
and HTTPS traffic through Tor when Tor is running locally. It also fails closed
if the proxy is unavailable. Environment proxy variables are ignored.

The client keeps the deployed manifest/contract pins and normal station/key
verification binding. Unverified continuation requires the compiled `oa-station`
Ed25519 public key, scoped to `https://verifier2.openanonymity.ai`, and local
verification of the station signature over the exact station ID, provider key
and integer expiry. This fallback pin remains scoped to the Sepolia verifier;
Mainnet's production verifier requires ordinary matching verifier approval.
The web client has the same pin scope. A station name,
`station_recently_attested` flag or live broadcast cannot add a trusted station. Unknown stations still need a matching
successful verifier approval, including during rate limiting and outages.

For that pinned station, the client may continue through a verifier outage or
refusal such as HTTP 401 `Invalid org signature`. Invalid station signatures block
fallback. Known bans at verification, expired keys and mismatched verifier
bindings block access. TLS,
redirect, cancellation, response-size and lease/cap/origin checks remain in
force. The same compiled pin is used by the web app. Its initial provenance is
the HTTPS verifier broadcast observed on October 1, 2026; operator identity was
not independently confirmed through another channel. This release accepts that
one-time trust bootstrap. A pin rotation requires a reviewed client release.

This exception trusts the station identity; it does not establish org-signature
validity, provider-account ownership or provider logging/training settings.
Fallback remains `verified: false`, with `verifier-unavailable` status and the
fixed `trusted_station_fallback` detail. A fixed warning explains the reduced
assurance without exposing keys, station signatures or verifier response bodies.
One verification result remains with its acquired key for the configured fixed
reuse window; there is no background re-verification or ban polling. The gateway
accepts fallback only with the `trusted_station_fallback` detail that identifies
this station-pin check.

The default key-reuse window is a fixed 60 seconds from acquisition, capped by
the provider's expiry; reusing a key does not extend it. Compatible requests can
share access, including different chats, local clients, and automatic title and
follow-up requests.
The provider can link all requests using the same key, and its original
aggregate spending cap is shared. Expiry, errors and cancellation discard
cached access. The cache is memory-only and does not survive a restart.

An explicitly saved window is preserved across updates. Profiles without a
saved window use the default. Stop `serve`, run
`zkapi-clientd config --key-reuse-window-seconds 0`, then restart `serve` to
disable reuse; keep the same `--config-dir` if set.

With reuse disabled, every inference request gets fresh access without needing
a conversation identifier from the UI. A value from 1 to 300 sets the fixed
reuse window in seconds. The daemon starts settlement when the window ends,
without waiting for another request. Any active provider response finishes
first. With reuse disabled, settlement starts after each response. When an
earlier lease blocks the next fresh key, the daemon also requests settlement
instead of waiting for the key's full expiry. The helper recovers pending or
ambiguous outcomes without repeated retirement requests. Signed settlement
can still take several minutes.

For interrupted provisioning, settlement first sends the exact saved proof to
the server's authenticated retirement endpoint. A server that still reports
`lease_pending` can be retried using that original issuance request, including
its frozen quote and spending bound. The helper validates the returned lease
and OA key before retiring it; that recovered credential never enters the
inference cache or bridge response. A confirmed unissued cancellation advances
the wallet only through the normal matching signed response. Missing keys,
expiry, HTTP errors and ambiguous issuance never authorize clearing a journal.
A journal that was sent is never deleted without installing its signed
response. When an unsigned answer sets one aside, it moves, whole, into an
append-only archive (`request_archive/` in the companion's state directory,
owner-only like the journal, never pruned, and holding the same
prompt-free lease authorization and proof as the journal). Each record is
written and synced under a temporary name before it gets its
`<milliseconds>-<sequence>.json` name; other files there are ignored, and a
record that cannot be read is skipped by recovery and treated as an
unsettled request by withdrawal. A journal is set aside after a
`stale_root` reply, or when withdrawal settlement finds a request the
server reports unknown, but in both cases only once the pinned vault's
`currentRoot()` (read over the packaged RPC) no longer equals the request's
root and the server reports the request's nullifier unknown too; while the
vault still has that root, or the root cannot be read, the request stays
pending and the next lease attempt resends it unchanged. Withdrawal
settlement also sets aside a request whose nullifier the server reports
reserved for a clearance (an earlier withdrawal, or the operator's release
of a stuck state), without reading the root: the server refuses every
request at such a nullifier whatever the root, so it could never settle.
Chats at such a state stop with `clearance_reserved_state` and keep the
request, so they send no new request proof from that state. A journal is
also set aside after the server's
`/expire` acknowledgement of a never-admitted native request, when a wallet
reset replaces an unspent note, and, as superseded, when the note has
already moved past the state it was proved at. Explicit recovery
(`/wallet/recover`), a chat request that opens a new lease, withdrawal settlement and
withdrawal preparation also ask the server's nullifier record about
requests archived at the note's current state, and install a finalized
response for one of them only when it verifies. The daemon's background
recovery, every 5 seconds, asks only about a pending request, so it sends
nothing while the note is idle. Stopping or failing recovery keeps the
original note and request for retry.

Inference is loopback-only and key-free by default. Other local processes can
use it. Optional local API-key authentication affects only the UI-to-daemon hop.
Browser Origins, unexpected Host values and nonloopback peers are rejected.
Wallet routes always require both the local API credential and a separate
owner-only management credential. Incoming cookies, identity headers and
account/storage metadata are stripped before inference.

A local Ethereum signing key and private recovery journals are stored in
owner-only files. Public funding addresses, amounts, withdrawal destinations
and chain transactions are visible to RPC providers and chain observers. The
client sends chain reads and transactions only to the RPC packaged with the
release, and refuses a wallet companion that reports another RPC, indexer or
protocol server.
Deposit/withdrawal QR codes are generated locally and contain only public
payment address, chain and amount. No external QR service receives them.
A withdrawal fee QR funds the local signing address, never the private payout.

Waiting for ETH and refreshing quotes do not authorize transactions. For a
guided deposit, Enter approves the fixed principal with fees that adjust
automatically while the receiving balance covers the deposit and required
fees. The signer caps fees to the fresh quote and available balance. A renewed
shortage requires another Enter once funded. Withdrawal fee increases still
require renewed approval. Fresh quotes preserve network/deployment/address/
note/payout/nonce bindings. A lost reply is recovered from durable state, not
a blind second approval. Signed pending operations resume their exact bytes;
reverts never automatically sign a replacement. Wallet state is preserved
across updates.

Successful native ETH deposits activate after the saved transaction's successful
mined receipt, canonical block and deposit event are validated, and two further
sources agree: the vault's `notes(noteId)` at the receipt's block hash, and the
zkAPI indexer's whole-tree snapshot, which must hold this deposit's leaf at that
note. The note secret reaches the wallet companion only after they agree. The
vault read goes to the packaged RPC, which already serves the deposit and sees
its note ID in the public deposit event. The snapshot is the same response for
every client, so the indexer does not learn which note is yours. Disagreement
leaves the deposit in `verification_conflict`; nothing is activated, retired or
replaced until a later check agrees. Success does not wait for Ethereum
finality. Failed receipts retain the finality gate before explicit retry; a
deposit signed by this release is also retired only after the indexer shows
its note did not land. Because the RPC can withhold a deposit and relay it
after that check, a retry is signed only when a bounded search of the
indexer tree it is built from finds none of the note's earlier deposits
(CLI_ZKAPI.md describes the bound). That search uses the same whole-tree
snapshot. A quote repeated while the tree is unchanged reads only the tree's
root, which is also the same response for every client. So the indexer
still cannot tell which note is yours. Missing or ambiguous receipts preserve
the exact signed transaction without authorizing a replacement. Withdrawals
and public ETH returns require their own finality checks, and a withdrawal
completes locally only after the vault and the indexer both show the note
closed.

Pre-finality activation exposes the same reorganization risk as the web wallet:
a block can be replaced after a private note or inference credit becomes usable.
The wallet does not provide complete rollback and reconciliation for that
event. Local reset cannot undo credit already issued, and later inference
or withdrawal may require recovery. Canonical receipt validation establishes the
observed chain state, not a guarantee against a later reorganization.

A withdrawal builds two withdrawal proofs. The first, an ownership proof, goes
to the protocol server with the clearance request; its public statement shows
the server the note ID, the payout amount and the destination before the close
transaction publishes them. It is also a valid escape input, so a server that
kept it could start an escape to the same destination and amount, delaying the
payout by the vault's challenge period without changing it. The ownership proof
is never written to disk. On the packaged deployments' vaults (no
`vault_revision` 2) a challenged escape also consumes the note's nullifier for
good, and a request proof sent from the same note state, if it never settled,
is challenge evidence for whoever kept it. So at a note state with such an
archived request the companion sends no ownership proof and builds no
escape: it asks for a clearance without one, which only a server that still
allows legacy clearance grants, and otherwise refuses the withdrawal with
`unsettled_request_state` until a chat request or the earlier request's
settlement moves the note to a new state. After the note expires no chat
request can do that, and the vault's owner can claim the note at any time;
nor can one once the server holds a clearance for the state (refused with
`unsettled_clearance_reserved`). Then, and only after the owner types `send`
at the guided withdrawal's warning, the companion sends the ownership proof
anyway, accepting that a challenge with the unsettled request would consume
the nullifier. A request discarded by an earlier release left no archive
record, so this rule cannot apply to its state. When the server reports the
note's current nullifier settled by a request the wallet holds no record of,
chats and withdrawal stop with `receipt_journal_missing` and show that
nullifier locally, for the owner to give the operator; giving it links the
owner to that request.

The daemon creates no request-history log files. Foreground output includes
HTTP route/method/status/timing, local sequential `request=` numbers and local
key serials (`key_ref=`). Selection reports `source=fresh` or `source=reused`;
release reports `response_complete=true` or `false` and whether the key is
retired locally or available for reuse. Local retirement describes the daemon's
reuse policy, not proof of provider revocation or wallet settlement. Wallet
session numbers are independent of these key serials, especially after restart.
Background settlement logs include the local key serial, start, result and
duration.
Session ends, costs and remaining ETH balances are logged only after signed
settlement. Terminal redirection or service managers can retain that activity
and financial metadata. Prompts, responses, secrets, raw session identifiers,
proofs and provider credentials are not printed. Session events are a bounded
in-memory feed, not a ledger.

Only coarse reviewed model spending buckets reach the helper. The client
continues reading the existing public `/chat/model-tickets` pricing-policy
endpoint, which is also used by the web client; that does not add ticket
wallet, issuance or redemption support. Exact balances and prompt sizes do
not choose the bucket.

The protocol is experimental and uses a single-party Groth16 setup. See the
repository's [note-bound commitments](../../docs/note-bound-commitments.md)
and [native ETH architecture](../../docs/architecture.md).
