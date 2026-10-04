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

The client defaults use these deployment manifests and vaults:

| Network | Manifest | Vault |
| --- | --- | --- |
| Mainnet | `https://zkapi-mainnet.openanonymity.ai/config.json` | `0x4386FDbdA35D995beB3BF8625118Ec5982ec81fe` |
| Sepolia | `https://zkapi-sepolia.openanonymity.ai/config.json` | `0x49fA19f9bdECe7A48Ebc7749fD69aD40F577590F` |

The embedded manifests pin the deployment IDs, contracts, signing keys, oracle
and proof setup. Wallet funding and recovery records are bound to the configured
network and deployment. Unknown origins or unapproved manifest differences fail
closed. Do not delete recovery data to bypass a configuration mismatch.

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
  indexer's tree and saved with the note just before signing. A reported
  revert can also be a deposit the RPC withheld and relays later, so the
  slot of every deposit signed for the note is kept. Another deposit of the
  same note is signed only when a search of the indexer tree it is built
  from, starting at each of those slots, does not find the note. An earlier
  deposit missing from that tree cannot land beside the new one. Quotes run
  the same search only to refuse early. While the indexer is unavailable, a
  quote is still given, but approval signs nothing. The search is bounded:
  it compares the first 64 occupied slots after each kept slot, for expiry
  days back to about 63 days before the search. A deposit lands after its
  slot only when every slot in between is empty. So a landed deposit is
  missed only in two cases. After it lands, challenges restore 64 or more
  escaped notes between the slot it was built for and the slot it landed
  in. Or it landed about 63 or more days earlier, past its note's 30-day
  term on the packaged deployments unless vault pauses extended it by more
  than 33 days. If the note is found, the deposit is reported as a
  `verification_conflict` and no replacement is signed. Running
  `zkapi-clientd config` again checks once more; **repair** (below) binds
  the note that landed. Deposits that reuse your public commitment with a
  different amount are ignored, so they cannot block a genuine retry.
- **Withdrawals.** Before the wallet companion deletes its note state, the
  vault (at the payout receipt's block) must show the note closed and the
  indexer must no longer list its leaf; until then the withdrawal keeps
  waiting. A finalized escape of the same reservation (same note, nullifier,
  payout and destination) is accepted as an independently relayed payout:
  after a reverted withdrawal, choose `confirm` in the `withdraw` menu action
  and enter that transaction's hash.

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
which refuses when the withdrawal has a prepared plan or the protocol server
knows its nullifier; any other reservation blocks the rebind. The replacement
is saved before the wallet is reset, so an interrupted rebind resumes when
**repair** is chosen again with both fields left blank.

Every withdrawal sends the protocol server an ownership proof, a second
withdrawal proof that shows the server the note ID, payout and destination
before the close is on chain (see [privacy boundaries](PRIVACY.md)). A
manifest that declares `clearance_ownership_proof` or `vault_revision` 2 or
later requires a wallet companion whose `/oa/v1/status` reports
`clearance_ownership_proof_version`; an older companion is refused before any
note is reserved.

## Withdrawals

Choose `withdraw` in `config --menu`. A new withdrawal asks for the destination
once and shows its full private payout. If gas is insufficient, it shows the
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
