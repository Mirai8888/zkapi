# Client configuration and use

The public commands are `zkapi-clientd config` and `zkapi-clientd serve`.
The client only supports zkAPI private ETH balances. Ticket issuance, import,
redemption and ticket-based inference are not included.

## Configuration

A new `config` creates the private configuration directory and defaults to
Ethereum Mainnet, direct HTTPS and a loopback listener at `127.0.0.1:8787`.
It asks for the deposit amount in USD, defaulting to $20 on Enter, and shows the
ETH amount, receiving address and locally generated QR. It waits automatically
for ETH and updates the receiving balance. Once funded, Enter approves the
fixed deposit with network fees that adjust automatically while the receiving
balance covers the principal and required fees. It checks a fresh quote before
signing, deposits and activates the private balance once its successful mined
receipt is validated against the canonical block and saved deposit, and the
vault state and the zkAPI indexer confirm the same note (see
[chain verification](#chain-verification-and-recovery)). There is
no additional 15-minute finality gate for successful native ETH deposits, matching
the web wallet. No model is selected or priced during funding.

If the last fee or balance check leaves the deposit unsigned, configuration
refreshes the same fixed deposit and continues watching instead of exiting.
Interrupted approval responses are checked against saved progress before any
retry. Higher fees do not require another Enter while the deposit remains
funded, even if the recommended buffer is no longer fully covered. A renewed
funding shortage requires Enter again once funded. The recommended fee buffer
remains optional; the signer caps fees to the fresh quote and available balance.

After signing, progress distinguishes waiting to be mined, waiting for network
fees to fall below the signed cap, and private balance activation. In an
interactive terminal, payment details and progress update in place, with a
spinner and elapsed time while waiting. Enlarge a short terminal to show the
payment QR; the receiving address and amounts remain available as text. Prompts
pause the display while you answer. Redirected output and `TERM=dumb` use plain
status messages without animation. The same signed transaction is retried; the
client never silently raises its fee cap or sends a second deposit.

A failed receipt still waits for Ethereum finality before an explicit retry is
allowed. An unavailable or ambiguous receipt does not establish success or
permit a replacement transaction; recovery retains the exact saved transaction.
Withdrawals and public ETH returns require their own finality checks.

As on the web, activation before finality accepts the possibility of a chain
reorganization after the note becomes active. The wallet and indexer do not
provide complete rollback/reconciliation for that case, and already issued
inference credit cannot be undone by resetting the local wallet. See
[recovery boundaries](PRIVACY.md).

```sh
zkapi-clientd config --status           # show saved settings
zkapi-clientd config --edit             # change settings
zkapi-clientd config --usd 50           # amount for a new deposit
zkapi-clientd config --menu             # withdrawal and wallet actions
zkapi-clientd config --require-api-key  # require a local inference key
zkapi-clientd config --api-key          # show that key when requested
zkapi-clientd config --key-reuse-window-seconds 0  # fresh key per inference request
zkapi-clientd config --exit-rpc-url https://rpc.example  # your own RPC for exits ('none' clears it)
```

Use the arrow keys (or `j`/`k`) and Enter to select wallet actions and networks.
Esc or `q` cancels a selection. Text prompts remain available when output is
redirected. Ctrl+C stops safely and preserves saved progress; run
`zkapi-clientd config` again to continue.

`serve` does not prompt or authorize funding. Missing prerequisites point back
to `config`. Configuration stops temporary services it starts; an existing
compatible service it reused remains running. Stop a running service before
editing its configuration.

## Sepolia

```sh
zkapi-clientd config --network sepolia
zkapi-clientd serve
```

Sepolia requires the deployment's shared access password; configuration asks
with input hidden. Fund with Sepolia ETH, never mainnet ETH. Mainnet and
Sepolia have separate signing keys and wallet state. Switching networks keeps
the other network's recovery data.

## Tor

Start Tor with a local SOCKS listener, then select its numeric loopback address:

```sh
zkapi-clientd config --relay-url socks5://127.0.0.1:9050
zkapi-clientd serve
```

The client passes destination names to SOCKS5 for remote DNS and keeps HTTPS
certificate verification. The Go frontend and the wallet companion use the
same route. If Tor is unavailable, requests fail instead of connecting directly.
Keep the local OpenAI-compatible API at its loopback URL. Stop a running
`serve` before changing its saved transport. `HTTP_PROXY`, `HTTPS_PROXY`, and
`ALL_PROXY` do not change this client's route.
On macOS, `torify zkapi-clientd serve` alone does not route the Go client; set
the SOCKS5 relay URL above even when launching it through `torify`.

## Deployment origins

This release serves only the concession-exit vault (circuit
`zkapi-v2-concession-v1`, vault revision 3). Its embedded profiles are
`zkapi-native-eth-mainnet-concession-v1` and
`zkapi-native-eth-sepolia-concession-v1`. Until that vault is deployed on a
network, its profile ships as a placeholder (`"deployment_status":
"not_deployed"`, no contract, adapter, endpoints or signing keys) and the
client refuses to fund, use or withdraw a note there with
`deployment_not_deployed`. A release that pins the deployed vault replaces
the placeholder.

The embedded profiles pin the deployment IDs, contracts, the proof adapter
and Poseidon library, their runtime-code hashes, signing keys, oracle,
challenge period, note term, maximum pause, the settlement window `W`, the
deploy block and the proof setup (circuit, setup ID and key hashes). Wallet
funding and recovery records are bound to the configured network and
deployment. Unknown origins or unapproved manifest differences fail closed.
Do not delete recovery data to bypass a configuration mismatch.

A note of the earlier vault (circuit `zkapi-v2-note-bound-v1`) lives in its
own wallet directory, which this release never opens. When one is still open,
startup prints a warning naming its directory: withdraw it with the earlier
zkapi-clientd release line, which keeps that vault's exit routes, then fund
this release.

### Deployment checks and the exit RPC

At startup and before every deposit, the client checks through the pinned
RPC, and through your exit RPC when one is configured, that the deployment it
trusts is the one on chain: the runtime code of the vault, its proof adapter
and the Poseidon library hash to the pins, the vault's `proofAdapter()` is
the pinned adapter, and the vault's and adapter's getters
(`stateSigningKeyX/Y`, `clearanceSigningKeyX/Y`, `challengePeriod`,
`noteTtl`, `maxPauseDuration`, `CONCESSION_ESCAPE_VERSION`,
`ROOT_HISTORY_WINDOW`, `CIRCUIT_ID_HASH`, `REQUEST_VK_HASH`,
`WITHDRAWAL_VK_HASH`) and `eth_chainId` return the pinned values. A mismatch
refuses deposits with `deployment_mismatch`; exits stay available.

`config --exit-rpc-url URL` saves your own Ethereum RPC (HTTPS, or plain HTTP
to a node on this machine; no credentials, query or fragment). Deployment
checks use it as well, escape transactions are sent through it, and the
wallet companion reads exit state (note status, known roots, logs for a tree
rebuild) through it. `config --exit-rpc-url none` clears it. The companion
takes the same setting from `--exit-rpc-url` or `ZKAPI_EXIT_RPC_URL`.

Stop `serve` before installing an update. The installer preserves private files;
updating the repository alone does not update an installed binary.

## Chain verification and recovery

The embedded manifest also pins the payment RPC (`rpc_url`), the zkAPI indexer
(`indexer_url`) and the protocol server (`protocol_server_url`). The wallet
companion must report the same three endpoints; scheme and host case, an
explicit `:443` and one trailing slash are ignored, and any other difference
stops funding before any network read with "reinstall the zkAPI bundle". The
client always sends its chain and indexer requests to the packaged strings.
Transactions are signed for the network's pinned chain ID; the RPC's
`eth_chainId` is only a consistency check.

The RPC is a third party, so its answers are corroborated before they change
private state:

- **Deposit activation.** After a successful receipt, the vault's
  `notes(noteId)` is read at the receipt's own block hash (EIP-1898, canonical
  only), and the indexer's whole-tree snapshot (the same response for every
  client, so it does not reveal which note is yours) must have applied that
  block and hold this deposit's leaf at the receipt's note ID. The client
  recomputes the leaf with zkAPI Poseidon. The note secret is handed to the
  wallet only after both agree. While the indexer is behind, unavailable or an
  older version without snapshot block metadata, the deposit stays in phase
  `confirming` with stage `verifying` and polling continues. Disagreement sets
  phase `verification_conflict`. The conflict is not final: running
  `zkapi-clientd config` again checks the saved transaction against the vault
  and the indexer once more, and activates the deposit if they now agree.
  Otherwise it stops and points to the repair below.
- **Reverted deposits.** Before a finalized failed deposit is retired or
  requoted, the indexer must show that this note did not land at the empty
  slot the signed transaction was built for. The slot is checked against the
  indexer's tree and saved with the note just before signing, together with
  the run of empty slots right below it in that tree. A reported revert can
  also be a deposit the RPC withheld and relays later, so the slot of every
  deposit signed for the note is kept. Another deposit of the same note is
  signed only when a search of the indexer tree it is built from, starting
  at each of those slots, does not find the note. An earlier deposit missing
  from that tree cannot land beside the new one. Quotes run the same search
  to refuse early. While the indexer is unavailable, a quote is still given,
  but approval signs nothing. A saved `verification_conflict` without a
  pending transaction is the exception: there the quote's search decides
  whether the conflict clears, so it must complete, and while the indexer is
  unavailable the quote is refused and the conflict stays. The search is
  bounded: it compares the first 64 occupied slots from each kept slot on,
  and the first 64 in the empty run below it, for expiry days back to about
  63 days before the search. A deposit lands after its slot only when every
  slot in between is empty, and before it only inside that run, when the
  indexer's view it was built from was a short fork that was then orphaned.
  The expiry days come from chain time, not from this device's clock. The
  vault derives a deposit's expiry from its block's time, so the search runs
  from the block time of the indexer view each slot was built from to the
  block time of the view it searches, with one day of tolerance on each side.
  Each of those times comes from the payment RPC's header for the indexer
  view's block, and is accepted only when that header hashes to the block
  hash the indexer names. While the RPC does not serve that header
  (`eth_getBlockByHash`), or serves one this release cannot hash (a header
  format introduced by a later network upgrade), nothing is signed and a
  reported revert waits. A slot saved before this release, or rewritten by
  one, has only the device clock's preparation time, and its search starts
  7 days before it. Nothing is signed, and no reported revert is retired,
  while this device's clock is more than a day from that chain time: correct
  the system clock and retry.
  So a landed deposit is missed only in two cases. After it lands, challenges
  restore 64 or more escaped notes between the slot it was built for (or the
  start of the run) and the slot it landed in. Or it landed about 63 or more
  days earlier, past its note's 30-day term on the packaged deployments unless
  vault pauses extended it by more than 33 days. (A slot saved by a
  pre-release build of this version records no run and is never searched
  below, so a deposit signed for such a slot from a view that was then
  orphaned is also missed when it landed below the slot. A slot saved by an
  earlier release on a device clock more than 6 days fast is also missed
  when its deposit landed within that much of its preparation.) If the note is
  found, the deposit is reported as a `verification_conflict` and no
  replacement is signed. Running
  `zkapi-clientd config` again checks once more; **repair** (below) binds
  the note that landed. Deposits that reuse your public commitment with a
  different amount are ignored, so they cannot block a genuine retry. A
  deposit signed by 0.1.6 or earlier, or whose `pending-deposit.json` such
  a release rewrote (dropping `slot`, `signed_slots` and each slot's
  `empty_before`), has no recorded slot: its reported revert is retired, and
  a retry signed, without this search.
- **Withdrawals.** Before the wallet companion deletes its note state, the
  vault (at the payout receipt's block) must show the note closed and the
  indexer must no longer list its leaf; until then the withdrawal keeps
  waiting. A finalized escape of the same reservation (same note, nullifier,
  payout and destination) is accepted as an independently relayed payout:
  after a reverted withdrawal, choose `confirm` in the `withdraw` menu action
  and enter that transaction's hash. An escape pays `B − c_final`: the
  balance less the largest of the concession at initiation and every
  `EscapeConcessionRaised` for the note before finalization. A payout is
  accepted only when it equals that amount and is at most `B − c_init`; one
  below `B − b` (more than the state's bound `b` was conceded) still closes
  the withdrawal and is reported as `concession_exceeded_bound`. An escape
  can also close the note without paying the destination: when the
  destination rejects ETH or needs more than 100,000 gas to receive it, the
  vault credits the balance to `escapePayoutCredits(destination)` and logs
  `EscapePayoutDeferred` in the same receipt. The withdrawal then completes
  as **payout credited, not delivered**: nothing has arrived yet. Once the
  destination accepts a plain ETH transfer, anyone can deliver the credit,
  also while the vault is paused, by calling `claimEscapePayout(destination)`
  (selector `0x88c10aee`) on the vault. The withdrawal status names the vault
  (`vault_address`) and the transaction data (`claim_calldata`) with
  `payout_credited: true`. The guided setup repeats this before it asks for
  a new deposit. A new deposit replaces the withdrawal record but keeps the
  credit: the funding and withdrawal statuses then list it under
  `escape_payout_credits`, one entry per destination with its
  `credited_amount` (the vault's `escapePayoutCredits(destination)` now),
  `note_ids`, `transaction_hashes`, `vault_address`, `claim_calldata` and
  `message`, and **fund**, **withdraw** and the guided withdrawal print it as
  an unclaimed escape payout. An entry disappears once the vault's credit
  for its destination reads zero.

If a deposit stays in `verification_conflict`, compare its transaction on a
block explorer, then run `zkapi-clientd config --menu` (with the same
`--config-dir`, if set) and choose **repair**. It asks for the vault note ID
that holds the deposit (leave it blank to derive it from the saved
transaction) and for a wrongly bound wallet note to replace (blank if none),
and asks for confirmation before anything changes. The repair calls the
daemon's wallet-management route `POST /admin/funding/rebind` (optional JSON
fields `note_id` and `replace_note_id`), which verifies the deposit against
finalized vault state and the indexer itself. It succeeds when the private
balance is active again.

Rebind never changes the note secret, commitment or amount; it accepts a note
only when the finalized vault state and the indexer both hold exactly this
deposit there. Left blank, the note ID comes from a saved deposit's receipt
or, failing that, from this deposit's leaf in the indexer's tree, searched
with the bound above from every slot any of its deposits was signed for,
earliest first. It refuses while a withdrawal, public return or unconfirmed
deposit transaction is saved (including an earlier deposit of the note
retired after a reported revert), or while the wallet has an unsettled
request, and it replaces an existing wallet note only when you name it and it
is an unspent genesis note of the same amount. A withdrawal reservation of
that note is released first through the companion's `POST /oa/v1/withdraw/release`,
which refuses when the withdrawal has a prepared plan, when its clearance
request carried, or may have carried, an ownership proof
(`ownership_proof_sent`, described below), or when the
protocol server knows its nullifier; any other reservation blocks the rebind. The replacement
is saved before the wallet is reset, so an interrupted rebind resumes when
**repair** is chosen again with both fields left blank.

Every withdrawal sends the protocol server an ownership proof, a kind-2
withdrawal proof that shows the server the note ID and payout before the
close is on chain (see [privacy boundaries](PRIVACY.md)). It names no
destination and the vault accepts it neither as an escape nor as a close.
The wallet
companion must report bridge version 5 with `exit_concession: 1` and the
deployment's setup ID in its `/oa/v1/status`; an older companion is refused
before any note is reserved.

Once a clearance request carrying the proof has left the companion, whatever
came back (a gateway's 429, a server error, or no answer at all), the
companion makes no chat request from that note state: the server may hold
that state's clearance. The companion records this before the request leaves
and never releases that reservation: **repair** stops, explaining that the
withdrawal sent or may have sent its ownership proof, and the management
API's error body carries `"code": "ownership_proof_sent"`. The chat API
answers 409 `exit_locked` or `ownership_proof_sent`. Choose **withdraw**
again to finish the close; the companion resends the same proof while it is
valid rather than making a new one.

### Exit decisions

A withdrawal first takes the note's exit lock (`exit_lock.json` in the
companion's state directory): from then on the companion makes no request
proof from that note state, only the withdrawal's own proofs, and the chat
API answers 409 `exit_locked`. The lock is released when the note closes,
when you cancel a withdrawal that released no escape or close proof, or once
every released proof is dead (its `valid_until` plus 15 minutes is before the
finalized block and the note is still active).

Every request from one note state carries the same solvency bound `b`, the
largest charge the state can be asked to pay; a request needing a larger one
is refused with `bound_fixed_at_state` until the state settles. Near the
note's expiry, new requests are refused with `note_near_expiry`, leaving time
for a settlement window and an exit.

Before it asks for a clearance, the companion recovers every chat request
sent from the current state that has not settled: it asks the server for
each one's signed response (20 seconds per call, 120 seconds in all) and
installs any that passes its checks. Then:

- **Every sent request settled** (or the server can no longer admit it):
  the mutual close proceeds, an ownership proof then a close.
- **A sent request is still unsettled:** the companion asks for no clearance.
  The withdrawal waits (409 `pending_settlement`) until the request's
  settlement deadline plus 15 minutes, at most
  `unsettled_request_escape_after_seconds` (default 12 hours) after it was
  sent, and no later than 12 hours before the note's expiry. After that it
  needs an escape conceding the state's bound `b`: an honest operator would
  have settled the request by then.
- **The server refuses the clearance or cannot be reached**, or the note is
  less than an hour from that latest start: the withdrawal needs an escape
  conceding nothing.

A withdrawal that needs an escape stops with `escape_required` and the
decision; continue with `withdraw --escape` (below).

A request that an earlier release discarded left no archive record, so
its state is not recognized. If an earlier release discarded a request that
the server had in fact admitted, the note is stuck at that state: the server
refuses chat requests from it as replays, and chats and **withdraw** stop with
`receipt_journal_missing` and the state's nullifier. (A dishonest server
could claim the same.) Contact the zkAPI operator before the note expires
and give them that nullifier, the note ID and the withdrawal destination,
which tells them which of their requests was yours. Once the operator has
released it, the server holds a withdrawal
clearance for that state and refuses every chat request from it, so chats
stop with `clearance_reserved_state` ("reserved for withdrawal"); choose
**withdraw**.

## Withdrawals

Choose `withdraw` in `config --menu`. A new withdrawal asks for the destination
once and shows its full private payout. The vault's own contract address is
refused as a destination, before anything is reserved: the vault cannot
receive its own payout, so every close to it would revert. If gas is insufficient, it shows the
same address/QR and live balance UI as a deposit, but requests only public ETH
for fees. The QR pays the local signing address, not the withdrawal destination.
Partial incoming payments update the remaining top-up. Normal gas fluctuations
within the displayed buffer do not repeat the QR.

When funded, Enter approves the displayed operation and maximum fee. A fresh
quote checks the same chain, deployment, address, private note, payout, nonce
and recovery binding before signing. Higher fees or a new balance shortage
require another Enter. The optional fee buffer does not block an otherwise
funded transaction.

Ctrl+C preserves saved progress. A signed pending withdrawal resumes its exact
transaction without another approval. A reverted transaction is never retried
automatically. Explicit recovery offers a reviewed retry or confirmation of a
matching payout submitted independently. Public ETH return remains a separate
wallet menu action with its own approval. Return quotes expire after 30 seconds;
if one expires before signing, run the same wallet menu again and review a
fresh quote. A saved signed return resumes its original transaction instead.

Returning `all` requires an ordinary Ethereum account with no deployed code.
For a delegated or contract recipient, choose an exact ETH amount and leave
room for the displayed maximum fee. The exact-amount path still simulates the
transfer and requires destination, amount and fee approval.

### Escape withdrawals

An escape exits without the operator: the vault pays after its challenge
period, during which the operator can raise the concession up to the state's
bound with the signed charge of a request you sent, or defeat an escape made
from a state that was already spent (a stale device or backup).

```sh
zkapi-clientd withdraw --escape --to 0xDESTINATION                    # show the decision
zkapi-clientd withdraw --escape --to 0xDESTINATION --conceded 1500    # quote it
zkapi-clientd withdraw --approve QUOTE_ID                             # sign and send
zkapi-clientd withdraw --escape --to 0xDESTINATION                    # later: quote finalization
zkapi-clientd withdraw --claim --to 0xDESTINATION                     # deliver a credited payout
```

The first run shows what the escape concedes (in gwei), why, and what it
pays; nothing is signed. `--conceded` repeats the concession you reviewed
and quotes `initiateEscapeWithdrawal`; a different amount than the exit
rules allow now is refused with `conceded_mismatch`. While a sent request
can still settle, the decision is to wait; `--early-exit nothing` escapes
now conceding nothing (the operator can raise it to the request's actual
charge), and `--early-exit bound` concedes the state's bound so the request
never appears on chain. The guided **withdraw** menu shows the same
decision and command when a mutual close needs an escape.

Before it proves, the companion finds the note's Merkle path at a root the
vault holds: the path it saved at deposit, then the indexer's (checked with
the vault's `isKnownRoot`), then a rebuild from the vault's logs since its
deploy block. It asks the server whether another device already spent the
note's state, and refuses with `device_not_newest` when the server shows a
valid request proof of the next state. The escape proof is valid for 3 hours;
the transaction is checked word by word against the decision you confirmed
(kind 0, destination, concession, `B − c` and `valid_until`) before it is
signed, and is sent through your exit RPC when one is configured. After the
challenge period the same `withdraw --escape --to` quotes
`finalizeEscapeWithdrawal`. The payout is matched as described under
**Withdrawals** above; a credited payout is delivered with `--claim`.

The management API serves the same steps: `GET`/`POST /admin/escape`,
`POST /admin/escape/quote`, `POST /admin/escape/claim/quote` and
`POST /admin/escape/approve`. The companion's routes are
`POST /oa/v1/withdraw/escape/prepare`, `POST /oa/v1/withdraw/escape/submit`,
`GET /oa/v1/withdraw/escape/status` and `POST /oa/v1/withdraw/escape/finalize`.

### Exit kit

`zkapi-walletd exit-kit export --state-dir DIR --deployment MANIFEST --out
FILE` writes an encrypted copy of the note (format `zkapi-exit-kit-v1`: PBKDF2-SHA256 with 600,000 iterations and
AES-256-GCM) with the deployment profile, the note's secret and current
state, and the state's bound. Export it again after each chat request: an
older kit escapes from a state that was already spent, and that escape is
defeated. `zkapi-walletd exit-kit escape --kit FILE --destination ADDRESS
[--rpc URL] [--conceded UNITS]` checks the deployment's code hashes through
`--rpc`, builds the escape with the companion's bundled keys, and prints the
vault, the calldata and the payout, or signs and sends it with a key you
supply (`--private-key-file`, with `--rpc`). `--offline` skips the
stale-device question to the server; `--work-dir` keeps the kit's exit lock
and released proofs between runs. The passphrase comes from
`ZKAPI_EXIT_KIT_PASSPHRASE`, `--passphrase-file` or standard input.

## Inference and activity

Use base URL `http://127.0.0.1:8787/v1`. No inference API key is required by
default; a placeholder is accepted if a client UI insists on a value. Admin
and wallet routes remain authenticated with separate local credentials.
Browser Origins are rejected. The listener must be loopback.

Open WebUI running directly on the same machine can use that URL. A Docker
container has its own loopback: use host networking where supported and enabled,
or run the client in the same network namespace. `host.docker.internal` alone
does not make a loopback-only listener reachable. Remote/container access is not
a reason to expose an unauthenticated listener on all interfaces.

Requests are serialized, including concurrent chat/title requests. By default,
compatible requests reuse an OpenRouter key for a fixed window of up to 60
seconds from acquisition, capped by the provider's expiry. Reuse does not extend
the window. Requests from **different chats and local clients**, including Open
WebUI's automatic title and follow-up requests, can share a key and its aggregate
spending cap; the provider can link all those requests. Each request checks
current model policy.
The daemon starts settlement automatically when the window ends, even if no
further request arrives. If a provider response is still active, it finishes
before settlement starts. A required spending-cap change can also retire the
previous key before its window ends. When an earlier lease blocks a fresh key,
the daemon requests settlement instead of waiting for the key's full expiry.
The helper recovers pending or ambiguous settlement outcomes without repeated
retirement requests. Signed settlement can still take several minutes.
Inference is never retried automatically after a provider/transport error.

The allowance follows the OA web client's public model-tier policy: $1, $2,
$3, $4.50 or $6 depending on the model. This is an aggregate spending ceiling,
not a fixed charge. Both clients strip only `:online` for tier lookup, keep
other variants distinct, and reject an explicit tier without a reviewed budget.
The production org's $20 per-key ceiling does not raise these client allowances.

If issuance was interrupted before a key reached the client, settlement first
asks the server to reconcile the saved authorization. For an older pending
server, it replays that exact request, verifies any returned key and retires it
without using it for inference. A finalized cancellation needs no key: the
helper verifies and installs the signed wallet response. Unknown outcomes stay
pending with the original recovery journal intact. Retrying uses the existing
wallet; deleting or resetting its files cannot safely release a server reservation.

The default `key_reuse_window_seconds` is 60 seconds. An explicitly saved
window is preserved across updates. Stop `serve`, run
`zkapi-clientd config --key-reuse-window-seconds 0`, then restart `serve` to
require a fresh key per inference request. Use the same `--config-dir` if set.
A value from 1 to 300 sets the fixed reuse window in seconds. Use 60 to restore
the default. Setting 0 gives every inference request a fresh key without
depending on a chat ID supplied by the UI, and starts settlement after the
response ends.

Normal output assigns each HTTP request a local sequential `request=` number.
Key selection includes `key_ref=`, a local key serial, and `source=fresh` or
`source=reused`. Different `key_ref` values show that requests used different
OpenRouter keys; no key material is printed. The release line reports
`response_complete=true` or `false` and whether the key is retired locally or
available for reuse within the configured window. Local retirement means the
daemon will not reuse the key; it is not proof of provider revocation or signed
wallet settlement. Background settlement logs identify the local `key_ref`
and report its start and result; the duration excludes queueing, key issuance
and inference. A waiting line identifies earlier-key settlement as the reason
an inference request is waiting.

Wallet key-session starts and ends use independent session numbers. These are
not the `key_ref` numbers, especially after a daemon restart. Session ends,
actual cost and remaining private balance in ETH appear only after signed
settlement, which can arrive after the response ends. Routine helper
readiness/retry messages are hidden. The foreground daemon stops if its helper
exits; only an external service manager can restart it.

### Mainnet production issuer and verifier

Version `0.1.4` switches Mainnet to issuer
`https://org-live.openanonymity.ai` and verifier
`https://verifier-production-20260917.openanonymity.ai`. Sepolia continues using
the staging org and `verifier2`. The Mainnet vault, signing keys, proof hashes,
protocol endpoints and wallet directory are unchanged.

Stop the running daemon, install the update and restart with the same profile.
Existing Mainnet profiles using the historical default `verifier2` origin use
the production verifier when loaded; custom verifier origins are preserved.
Loading alone does not rewrite the configuration file. New profiles and network
selection use the matching network default. The saved Mainnet manifest migrates
only when both complete old and new manifests match their reviewed SHA-256 pins;
any other manifest change is rejected. Wallet notes and recovery journals are
preserved, and Sepolia's existing migration behavior is unchanged.

This update does not add station trust exceptions, fund a wallet or clear an
unfinished lease. Existing lease recovery still uses the saved request and
server-signed settlement response.

### Trusted-station verification fallback

Version `0.1.3` adds the same pinned-station exception as the web app.
A new provider key normally needs matching OA verifier approval. If verification
is unavailable or refused, the client can continue only for the compiled
`oa-station` signing-key pin, after checking the station signature locally.
This permits a valid trusted-station key when the verifier reports
`Invalid org signature`; unknown stations cannot use the exception. Bans,
expired keys, invalid station signatures and mismatched approvals still block.

Fallback responses include `X-OA-Verification-Status: verifier-unavailable` and
`X-OA-Verification-Detail: trusted_station_fallback`. The terminal warns that
provider ownership and privacy settings were not confirmed. The key is never
reported as verified. See [privacy boundaries](PRIVACY.md) for the trust pin's
provenance and limits. Install the matching client/helper bundle together. The
gateway accepts fallback only with the `trusted_station_fallback` detail.

## Private files and recovery

The default private configuration directory is
`~/.config/zkapi-clientd` on Linux or
`~/Library/Application Support/zkapi-clientd` on macOS.
`ZKAPI_CLIENTD_CONFIG_DIR` or global `--config-dir` selects another directory.
Keep the same directory when updating or resuming the wallet; it contains the
signing keys and recovery journals. See [wallet storage and updates](CLI_PACKAGING.md#wallet-storage-and-updates).
Never initialize a new profile over orphaned recovery state or delete saved
transactions to bypass a recovery error.
