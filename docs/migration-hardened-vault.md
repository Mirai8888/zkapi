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
`clearance_ownership_proof_required`. The browser SDK, the Rust wallet and the
`zkapi-clientd` companion send ownership proofs, and the gateway now limits
POST floods per source. Reservations stay permanent, because a clearance
signature has no expiry.

**Unsettleable leases.** A lease could fail settlement forever, on an
over-reported usage figure that overflowed the gwei conversion or after a change
to the `--native-price-*` settings, leaving its note state reserved and every
SDK withdrawal refused. Settlement now clamps usage to the proof's solvency
bound before converting it, checks the saved quote only for internal
consistency, finalizes never-delivered leases at zero, and finalizes every other
lease by a write-once deadline (`ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS`),
at worst at the solvency bound, with an operator review record. The server
refuses to start unless that deadline fits in half the vault's
`challengePeriod()`. The CLI default of `--native-price-max-age-seconds` is now
4500, matching the container launcher. The SDK installs clamped and worst-case
receipts and validates journal quotes without the live manifest. This applies to
legacy deployments too. See
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
(strict mode). The companion discards a lease journal on `stale_root` only when
the server reports the nullifier unknown.

**Indexer divergence.** The indexer applied unconfirmed logs with no block
continuity, only warned when its root diverged from the vault, kept reporting
healthy, and persisted the bad state, which silently disabled challenges and
exits. It now commits a checkpoint only at `--confirmations` depth after
verifying the vault's `currentRoot()` and `nextNoteId()` by block hash
(EIP-1898), serves a head view verified the same way, answers 503 otherwise,
rebuilds automatically after a divergence or deep reorganization, supports
`--resync`, and reports a frozen RPC head as stale. The challenger detects
divergence and alerts, and fills gaps in its own event scan from the indexer's
`/v1/escapes/pending`. On the hardened vault withdrawals accept a proof against
any root from the last day (`UnknownRoot()` for older roots, `StaleRoot()` only
for siblings that do not match the live root), and the SDK refreshes siblings
without proving again.

**Default gas-price cap.** The challenge signer signed legacy transactions only
while `eth_gasPrice` was under its cap (10 gwei by default, even on Mainnet),
with no escalation and only a log line as the deadline passed. It now signs
EIP-1559 transactions within explicit fee and tip caps (an explicit cap is
required on Mainnet), refuses with structured reasons before broadcasting, and
reports `zkapi_signerStatus`. The daemon proposes fees, replaces its pending
challenge on the same nonce with rising fees, bids its caps near the deadline,
and reports every obligation with its severity on `/health` and `/status`.

**Pause blocks exits while the expiry claim stays open.** On a legacy vault the
owner's `pause()` blocks every exit while `claimExpired` and an instant
`setTreasury` keep working, so the owner can force every note to expiry and
sweep it to a treasury chosen at that moment. On the hardened vault
`claimExpired` is blocked while paused, paused time extends each note's claim
time, and after an unpause claims wait `unpauseClaimGrace()`. Treasury changes
are two-step (`setTreasury`, then `acceptTreasury` after `treasuryChangeDelay()`
of unpaused time, blocked while paused), pause and unpause emit events, and
`Deploy.s.sol` requires an explicit `OWNER` off local chains. A pause still has
no time limit: the owner can freeze but not seize. Legacy vaults keep the
defect; only the owner policy in Phase 0 mitigates it.

**Unpinned funding RPC.** `zkapi-clientd` trusted one third-party RPC for
receipts and note IDs, and did not compare the companion's RPC with its pinned
manifest. It now requires the companion's RPC, indexer and protocol server
endpoints to equal the pinned ones, activates a deposit only when the vault's
`notes(noteId)` at the receipt block and the indexer's tree agree, refuses to
retry a reverted deposit that landed, corroborates withdrawals the same way, and
offers a **repair** action (`zkapi-clientd config --menu`, then repair) to fix a
wrong binding. It needs the
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
  `--allow-legacy-clearance` is set. New error `clearance_ownership_required`
  (400); `capacity_exhausted` (503) is now retriable; `stale_root` (409) reports
  the vault's root.
- Lease status `cancelled` (corrupt binding, never signed); lease status
  responses add `charge_basis` and `settlement_deadline`, and recovery responses
  add `settlement_deadline`; settlement payloads add `charge_basis` and, for
  fallbacks, `settlement_reason`. Payload `type` strings are unchanged.
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

Signer (`docker/aws/signer`):

- `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI` is refused, even when empty. The cap is
  `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI`, required when
  `ZKAPI_CHALLENGE_CHAIN_ID=1`.
- Transactions are type 2. The sender must hold gas limit x `maxFeePerGas` for
  each pending transaction: about 0.075 ETH per challenge at the Sepolia
  default cap of 10 gwei, ten times what legacy pricing at 1 gwei needed.
- An empty `ZKAPI_CHALLENGE_LISTEN_HOST` now means `127.0.0.1`.

Indexer (`zkapi-indexerd`, `zkapi indexer`):

- The first start archives a version-1 checkpoint as
  `<cursor>.v1-<unix_ms>.bak` and replays from `--from-block`; tree routes
  answer 503 until the replay verifies. A checkpoint is bound to its chain and
  vault.
- The RPC must support `eth_call` by block hash (EIP-1898) and
  `eth_getBlockByHash`, and the host clock must be accurate.
- Not-ready tree routes return a JSON 503 body with `Retry-After: 5`; `/health`
  returns 200 only when the status is `ok`. Tree responses add `root`,
  `block_number` and `block_hash`.

Docker deployment (`docker/aws`):

- `deployment.env` gains `ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS`,
  `INDEXER_CONFIRMATIONS` and `INDEXER_MAX_HEAD_AGE_SECS`; `challenge.env` needs
  the two fee caps; `signer.env` changes as above.
- The server and challenger no longer wait for a healthy indexer; the
  challenger's healthcheck reads `/livez`.
- The gateway limits POST requests per source and answers
  `429 gateway_rate_limited`.

Hardened vault (contract additions only; existing signatures and events are
unchanged):

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
  redundant; `renounceOwnership()` reverts while paused.
- `Deploy.s.sol` requires `OWNER` except on chains 31337 and 1337.

Browser SDK:

- New 409 codes `request_settlement_pending`, `transmitted_anchor_unconfirmed`,
  `transmitted_anchor_escape_unsafe`, `anchor_challenged`,
  `nullifier_challenged`, `receipt_journal_missing`, `receipt_response_missing`,
  `receipt_pending_install`, `request_archive_limit` and
  `withdrawal_submission_pending`; vault reverts map to `unknown_root`,
  `challenged_nullifier`, `invalid_destination` and `vault_paused`.
- Behaviour depends on `trusted_deployment.vault_revision` and
  `trusted_deployment.clearance_ownership_proof` in `browser-config.json`; see
  the [SDK README](../sdk/README.md).
- A mutual close generates two withdrawal proofs.

`zkapi-clientd`:

- The companion must report the pinned `rpc_url`, `indexer_url` and
  `protocol_server_url`; funding stops otherwise.
- Deposits and withdrawals wait (`confirming`, stage `verifying`) until the
  vault and the indexer agree; a disagreement is phase
  `verification_conflict`. The indexer must serve snapshot block metadata.
- Each withdrawal generates two withdrawal proofs. A manifest declaring
  `clearance_ownership_proof` or `vault_revision` 2 requires a companion that
  reports `clearance_ownership_proof_version`.

## Compatibility

Clients against each server state (`legacy clearance` is
`ZKAPI_ALLOW_LEGACY_CLEARANCE`):

| Client | Legacy deployment, server not upgraded | Legacy deployment, upgraded, legacy clearance on | Legacy deployment, upgraded, legacy clearance off | Hardened deployment |
| --- | --- | --- | --- | --- |
| Browser SDK from earlier releases | All flows, with the old risks | All flows | Mutual close fails with `400 clearance_ownership_required`; escape still works | Not usable: pinned to the legacy vault |
| Browser SDK from this release, legacy profile (no capability keys) | All flows; clearance without proof | All flows | All flows: the proof is sent after the `400` | Not usable |
| Browser SDK from this release, hardened profile (`vault_revision` 2) | Not usable | Not usable | Not usable | All flows |
| `zkapi-clientd` 0.1.6 and earlier | All flows | All flows | Withdrawals fail with `400 clearance_ownership_required`; the note stays reserved locally and recovers after an upgrade (clientd has no escape) | Not usable |
| `zkapi-clientd` built from this release, current manifests | Needs the upgraded indexer; ownership proof ignored by the old server | All flows | All flows | Not usable |
| `zkapi-clientd` pinned to the hardened vault | Not usable | Not usable | Not usable | Needs the manifest work listed under Phase 2 |

Services:

| Pair | Compatible |
| --- | --- |
| Signer from this release + earlier challenger | Yes: no fee proposals means the fee cap and the default tip. |
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
   ```

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
   Schedule
   Phase 0 so that the new challenger runs well before the nearest deadline it
   must meet. A lease created before the upgrade gets its settlement deadline
   when the new server first sees it: the later of its expiry and that moment,
   plus `SETTLEMENT_GRACE_SECONDS` and
   `ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS`. If that would fall after an
   escape's deadline minus a quarter of `challengePeriod()`, lower
   `ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS` for the first start (to no
   less than `SETTLEMENT_GRACE_SECONDS` + 900), then restore it; each lease
   keeps the deadline it received.

3. **Signing seeds under the new policy.** Build the new images (Phase 0, step
   1) and run `dc run --rm --no-deps --entrypoint zkapi server signing-keys`. If
   it refuses the production seeds, this release cannot serve that vault: keep
   the earlier server binary for it, deploy a hardened vault with new seeds, and
   drain the legacy one (Phases 1 to 4). If the seeds derive a development key,
   follow [the compromise procedure](#if-development-or-mismatched-keys-were-ever-served).

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
     `INDEXER_CONFIRMATIONS=12`, `INDEXER_MAX_HEAD_AGE_SECS=180`, and
     `ZKAPI_ALLOW_LEGACY_CLEARANCE=true`. Legacy clearance must stay on while
     clients from earlier releases may withdraw: without it their mutual close
     fails, and `zkapi-clientd` 0.1.6 and earlier have no other exit.
   - `server.env`: both seeds, which passed Before you start, item 3.
   - `signer.env`: delete `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI` and set
     `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` (required on Mainnet); see
     [the signer README](../docker/aws/signer/README.md).
   - `challenge.env`: add `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` and
     `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI`, no higher than the signer's
     caps (its tip cap defaults to 10 gwei), with the priority cap at least twice
     the daemon's priority fee (default 2 gwei).
   - Fund the sender with at least (pending escapes + reverted attempts + 1) x
     7.6M gas x fee cap.
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
   dc exec -T indexer curl -sS http://127.0.0.1:3001/health | jq '{status, served_block, root, next_note_id}'
   ```

   Compare its root and next note ID with the vault through `RPC_URL`, as in
   [Indexer resync](../docker/aws/README.md#indexer-resync), step 1. Comparing
   the archived version-1 checkpoint's root with the vault shows whether the old
   mirror had diverged.

5. **Signer.** The new signer also serves the old challenger, which proposes no
   fees and therefore bids the fee cap.

   ```sh
   dc up -d --no-deps --wait signer
   dc exec -T challenger curl -sS -X POST http://signer:8547 -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"zkapi_signerStatus","params":[]}'
   ```

   Expect `warnings: []`.

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
   false` in `/health`, and the attestation keys as in Before you start, item 4.
   The database migrates in place. Then start the challenger:

   ```sh
   dc up -d --no-deps --wait challenger
   dc exec -T challenger curl -sS http://127.0.0.1:3002/status \
     | jq '{status, alarms, indexer: .indexer.state, pending_escapes: .indexer.pending_escapes, obligations: [.obligations[] | {note_id, state, severity, blocked_reason, seconds_remaining}]}'
   ```

   The challenger keeps its checkpoint. A legacy-format pending transaction is
   replaced only by a bid that raises both fees by 10% over its gas price; until
   then `tip_cap_reached` may show. A nonce the old daemon reserved for
   lease-only evidence stays reserved until the server finalizes that request.

7. **Settlement after the upgrade.** Every pre-upgrade lease receives its
   deadline. Provisioning leases finalize at zero once due, leases stuck on a
   configuration change settle from measured usage, and leases still failing at
   their deadline finalize at the solvency bound with a review. Within about
   TTL + grace + `ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS`, every row from
   Before you start, item 6 must reach `finalized` (or, for a corrupt binding,
   `cancelled`). Check `/v1/dashboard/settlement` and handle each review; see
   [Monitoring](../docker/aws/README.md#monitoring).

8. **Owner policy for the legacy vault.** Its owner can still pause every exit
   while `claimExpired` and an instant `setTreasury` keep working. Publish and
   follow a policy for the rest of its life:
   - never pause it; if `paused()` is true, unpause it now;
   - make no treasury change during the drain;
   - move ownership to a multisig with `transferOwnership(address)`, or, with
     the vault unpaused, renounce it (`renounceOwnership()` removes pause and
     treasury changes for good; on a legacy vault it also succeeds while paused,
     which would freeze exits permanently, so check `paused()` first).

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
   - `OWNER`: a multisig, ideally behind a timelock. It can pause every exit
     without a time limit and schedule treasury changes.
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
   for getter in 'owner()(address)' 'treasury()(address)' 'paused()(bool)' \
       'challengePeriod()(uint64)' 'noteTtl()(uint64)' 'requestChargeCap()(uint128)' \
       'treasuryChangeDelay()(uint64)' 'unpauseClaimGrace()(uint64)' 'ROOT_HISTORY_WINDOW()(uint64)'; do
     printf '%s ' "$getter"; cast call "$NEW_VAULT" "$getter" --rpc-url "$RPC_URL"
   done
   ```

   Compare the four key getters with the printed keys as numbers.

4. **Stack.** Configure the new deployment from the
   [Docker guide](../docker/aws/README.md): the new `VAULT_ADDRESS`,
   `DEPLOY_BLOCK` and keys, a signer with a new private key and
   `ZKAPI_CHALLENGE_VAULT` set to the new vault, a funded new sender in
   `challenge.env`, and `ZKAPI_ALLOW_LEGACY_CLEARANCE` unset: no client of a new
   vault predates ownership proofs. Check the settlement timing rule against the
   new `challengePeriod()`. Publish its `config.json` on a new hostname with its
   own CloudFront origin. Start it as described there.

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
  without a proof first and with one after a `400 clearance_ownership_required`,
  and keeps the transmitted-request archive. Optionally declare
  `"clearance_ownership_proof": "optional"` in the legacy profile's
  `trusted_deployment` once its server is upgraded, so that the proof goes with
  the first request. Hosts update and reload every tab; the IndexedDB version is
  unchanged and older tabs keep working, but they do not write archive records.
  Users must not reset or export wallets.
- **`zkapi-clientd`.** A release built from this source with the current pinned
  manifests, whose native companion is rebuilt by
  `zkapi-clientd/scripts/prepare-zkapi.sh` from the unchanged pins in
  `zkapi-clientd/packaging/zkapi-source.env` and the updated `companion.patch`
  and `protocol-transport.patch`. It needs the indexer from Phase 0. Users stop
  `serve`, install the release, and start it again. A deposit in
  `verification_conflict` is re-checked by `zkapi-clientd config` and repaired
  with `zkapi-clientd config --menu`, then **repair**; see
  [chain verification and recovery](../zkapi-clientd/docs/CLI_ZKAPI.md#chain-verification-and-recovery).
  Tell users not to downgrade to 0.1.6 or earlier while a deposit is confirming
  or in `verification_conflict`: older releases activate the RPC's note ID
  without these checks. The code does not warn about this.

### Releases for the hardened deployment

- **Browser SDK.** Add a hardened profile to `sdk/assets/config/mainnet.json`
  and `sepolia.json` (or the host's own browser config): a new
  `trusted_deployment` with the new deployment ID, vault, keys, hostnames and
  RPC, plus `"vault_revision": 2` and `"clearance_ownership_proof": "required"`.
  `unsettled_request_escape_after_seconds` (default 43200) must stay above TTL +
  grace + the settlement deadline. Run `node scripts/sync-sdk-assets.mjs`, then
  `npm run verify:assets`, then build (`npm run build:browser`,
  `npm run build:mainnet`). Keep a legacy-exit build or profile pinned to the
  legacy vault, without `vault_revision`, so that owners can still withdraw
  legacy notes in strict mode.
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
   and 2): notes by status, pending escapes, and `nextNoteId()` in case of
   late deposits. A note's expiry is its `expiryTs`, the deposit time plus
   `noteTtl()` rounded up to a whole day. Plan the legacy stack's end from the
   latest `expiryTs` among open notes, plus one challenge period for escapes
   started near it.

3. **Expired notes.** Exits remain possible after expiry until someone calls
   `claimExpired`, which anyone can do; on a legacy vault it pays the full
   deposit to the treasury. Publish what the operator does with such deposits
   (for example, when it claims them and how an owner can ask for a refund
   outside the protocol), and announce expiry dates early.

## Phase 4: disable legacy clearance and retire the legacy stack

1. **Disable legacy clearance** only after the `zkapi-clientd` and browser SDK
   releases for the legacy deployment are adopted and users of older releases
   were warned. Watch the warning `signing a legacy clearance without a note
   ownership proof` and count recent proof-less reservations:

   ```sh
   sudo sqlite3 -readonly /var/lib/zkapi/server.db \
     "SELECT count(*) FROM nullifiers WHERE status = 'ClearanceReserved' AND clearance_auth = 'legacy' AND created_at > strftime('%s', 'now', '-7 days');"
   ```

   Then remove `ZKAPI_ALLOW_LEGACY_CLEARANCE` from `deployment.env` (or set it to
   `false`), run `dc up -d --no-deps --wait server`, and confirm
   `clearance_ownership_proof_required: true` in `/health`. Older SDK builds can
   still escape; `zkapi-clientd` 0.1.6 and earlier cannot withdraw until they
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

**Treasury arrears.** A `TreasuryPaymentDeferred` event means a treasury payout
failed and was kept in `treasuryArrears()` (gwei). Fix the treasury (it must
accept ETH with 100,000 gas), then anyone can pay it out, except while paused:

```sh
cast call "$NEW_VAULT" 'treasuryArrears()(uint128)' --rpc-url "$RPC_URL"
cast send "$NEW_VAULT" 'withdrawTreasuryArrears()'   # emits TreasuryArrearsPaid
```

**Settlement reviews.** Alert on `settlement required operator review`, list
open reviews, and acknowledge each handled one, as in the
[Docker guide](../docker/aws/README.md#monitoring). A `deadline_worst_case`
review charged the full solvency bound; compare it with the provider's usage
for that key. A `binding_corrupt` review means the server cannot sign that
request; its owner exits by escape.

**Indexer divergence.** Follow
[Indexer resync](../docker/aws/README.md#indexer-resync).

**Fee spikes.** When the challenger reports `base_fee_above_fee_cap`,
`fee_cap_reached`, `tip_cap_reached` or `insufficient_balance`, raise the
signer's caps and restart it, then raise the daemon's caps (no higher) and
restart it, or fund the sender. See the
[fee-spike runbook](../docker/aws/signer/README.md#fee-spike-runbook) and
[challenge operation](challenge-service.md).

## Rollback

Roll forward where possible: the earlier binaries bring back the defects.

- **Gateway:** the previous image tag.
- **Signer:** the previous image tag, with `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI`
  restored (otherwise its 10 gwei default and 100 gwei ceiling apply). It signs
  legacy transactions again and refuses the new challenger's fee fields, so roll
  the challenger back with it or stop it.
- **Challenger:** the earlier binary reads the new checkpoint, but it writes to
  the server database and treats reserved leases as evidence, which burns
  nullifiers on a legacy vault. Prefer fixing forward.
- **API server:** the earlier binary ignores the new tables and columns; rows
  finalized at zero or at the worst case stay finalized, queued key cleanups
  pause, and its settlement can stall again. It also restores the seed fallback
  and proof-less clearance. Never restore an older database over newer wallet
  activity.
- **Indexer:** the earlier binary refuses a version-2 checkpoint and answers 503.
  Stop the indexer, move `indexer.cursor` aside, restore the newest
  `indexer.cursor.v1-<unix_ms>.bak` as `indexer.cursor`, and start the earlier
  image.
- **Browser SDK:** earlier builds ignore the archive records, which stay inert;
  the archive's protections are lost, wallet data is not.
- **`zkapi-clientd`:** the additive state fields are ignored by earlier
  releases, subject to the downgrade warning in Phase 2. An earlier companion
  cannot accept an escape payout as withdrawal evidence and has no release route.
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
- **Pause has no time limit.** On a hardened vault the owner can freeze every
  exit indefinitely but cannot move deposits; legacy vaults also allow the
  sweep described above, so only the owner policy protects them.
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
  downgrades. The browser SDK's expiry display does not use `effectiveExpiry`
  yet. A wallet whose older SDK already discarded a journal cannot rebuild it;
  a finalized receipt it cannot install shows `receipt_journal_missing` and
  needs operator help.
- **Gateway limits are per source.** One browser host's users share one source,
  IPv6 clients can rotate addresses, and a client that reaches the origin
  without CloudFront can choose its key.
- **Operational dependencies.** A fresh server database, or one left with an
  unfinished SQLite transaction, cannot start while the native billing RPC is
  down. Private transaction relays may hide pending transactions from the
  challenger. The legacy clearance cap is per server process. Same-nonce
  replacement rules were tested on anvil, not against geth or reth.
