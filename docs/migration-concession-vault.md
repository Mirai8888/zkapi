# Migrating to the concession-exit vault

This is the operator runbook for moving a zkAPI deployment from the legacy
vault (circuit `zkapi-v2-note-bound-v1`) to the concession-exit vault (circuit
`zkapi-v2-concession-v1`, vault revision 3, capability `exit_concession: 1`).
The design and its security argument are in
[the concession-exit design](design/concession-exit.md); its §10 is the plan
this runbook carries out, with Amendment A1 (exits accept any root the vault
ever held).

On a legacy vault, an operator that finalizes a request but withholds its
signed successor state can defeat every escape the owner can build, and then
take the deposit at expiry. On the concession vault an escape names the state
it leaves and that state's successor, concedes an amount `c` of at most the
state's request budget, and pays `B − c`. Only a request proof at the
successor defeats it, and a request proof at the escaped state can only raise
`c`, within that budget. The owner's exit therefore needs no operator
cooperation. The vault is immutable, so this needs a new vault, adapter and
trusted setup.

Vaults deployed before this change are called **legacy vaults** here. They
include the published Mainnet vault
`0x4386FDbdA35D995beB3BF8625118Ec5982ec81fe` and Sepolia vault
`0x49fA19f9bdECe7A48Ebc7749fD69aD40F577590F`. The revision-2 "hardened" vault
that an earlier version of this guide described was built but never deployed.
It is superseded: the concession vault replaces it, so users migrate once.
[The earlier guide](migration-hardened-vault.md) now points here.

Notes cannot move between vaults. Each owner withdraws from the legacy vault
and deposits into the new one. The migration runs in these phases:

| Phase | What happens | Gate before it starts |
| --- | --- | --- |
| [0](#phase-0-harden-the-legacy-stack-in-place) | Upgrade the legacy stack's services in place, from `release/v2-note-bound` | None; do it now |
| [A](#phase-a-freeze-review-and-trusted-setup) | Freeze the circuits, external review, multi-party setup (G-SETUP), regenerate and publish every pin | All suites green on the revision-3 source |
| [B](#phase-b-sepolia) | Sepolia drill vault, then production Sepolia, then a 14-day soak | Phase A complete |
| [C](#phase-c-mainnet) | Mainnet deployment, smoke tests, canary, legacy re-cut, cutoff `X` announced | Phase B soak and drills green; the mainnet gates below |
| [D](#phase-d-clientd-releases) | The legacy clientd point release 0.1.7, then the new clientd release | 0.1.7 before the new release; the new release after a Sepolia drill |
| [E](#phase-e-drain-and-retire-the-legacy-vault) | Drain the legacy vault and retire its stack | The retirement condition |

Phases B to D overlap: the legacy stack keeps running, unchanged except for
configuration, until the end of Phase E.

**Mainnet gates.** Phase C starts only when all of these hold (design §11):

- G-SETUP is complete: a multi-party phase 2 with at least two contributors
  the operator did not select, a public random beacon, over a listed public
  powers of tau, with both fidelity gates passed;
- an external review covered the circuit diff, the `CircomReduction`
  prover, the R1CS export and zkey import, the vault, the adapter template,
  the codehash derivation, the challenger policy and the clients' exit logic;
- the WebAssembly is rebuilt reproducibly and the expected codehashes are
  published;
- every drill passed on Sepolia, followed by 14 days of soak with weekly
  drills;
- the daemons start in order, with the challenger healthy before the first
  deposit;
- the canary is configured (the SDK caps and the server's lease ceiling);
- the legacy re-cut is published and the cutoff `X` announced.

## Compatibility

| Component | Legacy vault (`zkapi-v2-note-bound-v1`) | Concession vault (revision 3, `zkapi-v2-concession-v1`) |
| --- | --- | --- |
| Legacy browser SDK re-cut (existing `publicPath`, `/zkapi/`) | Requests and exits; deposits closed | Refused (`incompatible_proof_circuit`) |
| Browser SDK from `main` (`/zkapi/v2c/`) | Refused (circuit mismatch) | Supported |
| zkapi-clientd 0.1.7 (`release/v2-note-bound`) | Supported; deposits closed; mutual close and a fresh-state escape | Refused (pins) |
| zkapi-clientd from `main` (`bridge_version` 5) | Warns and names the 0.1.7 release; never opens that wallet | Supported |
| zkapi-clientd 0.1.6 and earlier | Supported, with the earlier releases' risks; no escape | Refused |
| Legacy stack (serverd, indexer, challenger from `release/v2-note-bound`) | Supported | Refused (`deployment_binding`, circuit) |
| New stack (from `main`) | Refused | Supported |
| Request JSON (`ApiRequestV2`) | Same schema; legacy keys | Same schema; new keys |
| Withdrawal and clearance wire | `WithdrawalPublicInputsV2` (14 fields) | `WithdrawalPublicInputsV2C` (16 fields), `deny_unknown_fields` |
| Challenge calldata | `0x8a43467c`, evidence at `N`, with siblings | Defeat `0xda0ce43d`, evidence at `N⁺`, no siblings; raise `0xdd0064ba` |
| Proving keys and WebAssembly | `protocol/setup/v2` | `protocol/setup/v2-concession` (`mpc-1`), new key URLs |

The two stacks never share a database, indexer checkpoint, challenge
checkpoint, signer key, sender, hostname or gateway image tag. Each vault has
its own stack until the legacy one retires.

## Before you start

The examples assume the Docker deployment in [docker/aws](../docker/aws/README.md).
For the legacy deployment, set:

```sh
export VAULT=0xREPLACE_WITH_LEGACY_VAULT RPC_URL=https://REPLACE_WITH_READ_RPC DEPLOY_BLOCK=REPLACE
dc() { sudo docker compose -f docker/aws/compose.yml --profile challenge "$@"; }
DATA_DIR=/var/lib/zkapi API_URL=http://127.0.0.1:8080
```

Use for `RPC_URL` a read RPC independent of the indexer's. `DATA_DIR` is the
deployment's data directory (`ZKAPI_DATA_DIR`) and `API_URL` its gateway on
the VM (`ZKAPI_HTTP_PORT`). Once the new deployment shares the VM (Phase B),
`dc`, `DATA_DIR` and `API_URL` change for the legacy deployment; see
[Two stacks on one VM](#two-stacks-on-one-vm). Take numbers for shell
arithmetic from `cast call --json`: plain `cast call` annotates numbers of
10,000 or more (`10000 [1e4]`).

1. **Vault state.**

   ```sh
   for getter in 'owner()(address)' 'paused()(bool)' 'treasury()(address)' \
       'challengePeriod()(uint64)' 'noteTtl()(uint64)' 'nextNoteId()(uint32)'; do
     printf '%s ' "$getter"; cast call "$VAULT" "$getter" --rpc-url "$RPC_URL"
   done
   TREASURY=$(cast call "$VAULT" 'treasury()(address)' --rpc-url "$RPC_URL")
   cast call "$TREASURY" --value 1gwei --from "$VAULT" --rpc-url "$RPC_URL"
   ```

   The last call simulates a payment from the vault to its treasury and prints
   `0x` while the treasury accepts ETH. `execution reverted` means that every
   legacy exit with an operator share, and every expiry claim, reverts; see
   Phase 0, step 8.

2. **Pending escapes and their evidence.**

   ```sh
   N=$(cast call --json "$VAULT" 'nextNoteId()(uint32)' --rpc-url "$RPC_URL" | jq -r '.[0]')
   for i in $(seq 0 $((N - 1))); do
     status=$(cast call --json "$VAULT" 'notes(uint32)(bytes32,uint128,uint64,uint8)' "$i" --rpc-url "$RPC_URL" | jq -r '.[3]')
     [ "$status" = 2 ] || continue
     pending=$(cast call --json "$VAULT" 'pendingWithdrawals(uint32)(bool,uint256,uint256,uint128,address,uint64)' "$i" --rpc-url "$RPC_URL")
     nullifier=$(cast to-hex "$(echo "$pending" | jq -r '.[2]')")
     echo "note $i deadline $(echo "$pending" | jq -r '.[5]') nullifier $nullifier" \
       "destination $(echo "$pending" | jq -r '.[4]') final_balance $(echo "$pending" | jq -r '.[3]')"
     sudo sqlite3 -readonly "$DATA_DIR/server.db" \
       "SELECT n.status, n.reservation_kind, l.status, l.key_source, l.key_hash IS NOT NULL FROM nullifiers n LEFT JOIN openrouter_leases l ON l.request_nullifier = n.nullifier WHERE n.nullifier = '$nullifier';"
   done
   ```

   Schedule Phase 0 so that its challenger runs well before the nearest
   deadline. The Phase 0 challenger contests a legacy escape whose nullifier
   has a `Finalized` record, and waits on a `Reserved` one until the server
   finalizes it; on a legacy vault that challenge consumes the nullifier, and
   the owner exits from the signed successor state.

3. **Signing seeds.** Run `dc run --rm --no-deps --entrypoint zkapi server
   signing-keys` with the images of Phase 0, step 1. If it refuses the
   production seeds, the Phase 0 server cannot serve that vault: keep the
   earlier stack for it (server, challenger, indexer, gateway and signer from
   the previous checkout and image tag), apply only Phase 0, step 8, and drain
   it promptly. If the seeds derive a development key, follow
   [the compromise procedure](#if-development-or-mismatched-keys-were-ever-served).

4. **Served keys.** Compare `/v1/attestation` with the vault's getters as
   numbers:

   ```sh
   for getter in stateSigningKeyX stateSigningKeyY clearanceSigningKeyX clearanceSigningKeyY; do
     cast to-dec "$(cast call "$VAULT" "$getter()" --rpc-url "$RPC_URL")"
   done
   curl -fsS "$API_URL/v1/attestation" \
     | jq -r '.state_signing_key.x, .state_signing_key.y, .clearance_signing_key.x, .clearance_signing_key.y' \
     | while read -r value; do cast to-dec "$value"; done
   ```

5. **Keys served in the past.** Every archived request must carry the vault's
   state key. On a copy of the database:

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

   Unsettled leases of another key source make the Phase 0 server refuse to
   start until they drain; see
   [Changing the key source](native-eth-billing.md#changing-the-key-source).
   Never delete a `ClearanceReserved` row: a clearance signature was returned
   for it.

7. **RPC capabilities.** The indexer's RPC must answer an EIP-1898 call and
   `eth_getBlockByHash`; the native billing RPC must serve the chain and the
   `finalized` tag:

   ```sh
   HASH=$(cast block latest --field hash --rpc-url "$INDEXER_RPC_URL")
   cast rpc eth_call "{\"to\":\"$VAULT\",\"data\":\"0xfdab463d\"}" "{\"blockHash\":\"$HASH\",\"requireCanonical\":true}" --rpc-url "$INDEXER_RPC_URL"
   cast rpc eth_getBlockByHash "$HASH" false --rpc-url "$INDEXER_RPC_URL" | jq -r .number
   cast chain-id --rpc-url "$NATIVE_BILLING_RPC_URL"
   cast block finalized --field number --rpc-url "$NATIVE_BILLING_RPC_URL"
   ```

   The indexer's RPC must come from a provider other than the `rpc_url` that
   clients pin: `zkapi-clientd` corroborates deposits and withdrawals against
   the indexer's tree. Also find the `--rpc.txfeecap` of the node behind the
   challenge signer (1 ETH by default in geth and reth).

## Phase 0: harden the legacy stack in place

The legacy stack runs from the release line `release/v2-note-bound`, cut at
`ac9be63`. That line carries the hardening of the legacy services (required
signing seeds checked against the vault, authenticated clearance, terminal
settlement, the verifying indexer, the EIP-1559 challenger and signer), its
security fixes, and the config-only re-cuts of Phase E. `main` carries only
the new circuit, so never build the legacy stack from `main`. The maintainers
must publish the release line (push the branch and tag the release) before
operators build from it.

If the legacy deployment already runs images built from `ac9be63` or later on
that line, Phase 0 is done except for step 8; check the owner policy and
continue with Phase A. Otherwise upgrade the legacy deployment's own
services: same vault, data directory and sender. Plan a window with no
challenge deadline close (Before you start, item 2); the API is down for a few
minutes in step 6. The full list of the behaviour changes this upgrade brings
to the legacy services and clients is in that branch's own copy of the
earlier guide (`docs/migration-hardened-vault.md` on `release/v2-note-bound`,
sections "What changed and why", "Breaking changes" and "Compatibility");
ignore its Phases 1 to 4, which this runbook replaces.

1. **Build.** Check out `release/v2-note-bound`, set a new `ZKAPI_IMAGE_TAG`
   in the operator's Compose environment file (so the previous images stay
   available for rollback), and build: `dc build server gateway signer`.
2. **Configuration.**
   - `deployment.env`: add `ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS=21600`,
     `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` (the node's `--rpc.txfeecap` in wei),
     `INDEXER_CONFIRMATIONS=12`, `INDEXER_MAX_HEAD_AGE_SECS=180` and
     `ZKAPI_ALLOW_LEGACY_CLEARANCE=true`. Legacy clearance must stay on while
     clients from before this line may withdraw: `zkapi-clientd` 0.1.6 and
     earlier have no other exit. Its proof-less budget (60 per minute per
     server process) is one pool that anyone can exhaust; alert on
     `legacy_clearance_rejected_total`.
   - `server.env`: both seeds, which passed Before you start, item 3.
   - `signer.env`: delete `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI`, set
     `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` (required on Mainnet), and the same
     `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` as `deployment.env`. A legacy challenge
     needs about 7.53M gas, so at a 1 ETH ceiling keep the fee cap at most
     about 131.6 gwei.
   - `challenge.env`: `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` and
     `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI`, no higher than the
     signer's caps, the tip cap at least twice the daemon's priority fee.
   - Fund the sender with at least (pending escapes + reverted attempts + 1) x
     the lower of 7.6M gas x fee cap and the transaction fee cap.
   - Restrict the EC2 security group's inbound port to the
     `com.amazonaws.global.cloudfront.origin-facing` prefix list.
3. **Gateway:** `dc up -d --no-deps --wait gateway`.
4. **Indexer:** `dc up -d --no-deps --wait indexer`. It archives its
   version-1 checkpoint as `indexer.cursor.v1-<unix_ms>.bak` (keep it for
   forensics only; never restore it) and replays from `DEPLOY_BLOCK`. Compare
   its root and next note ID with the vault as in
   [Indexer resync](../docker/aws/README.md#indexer-resync), step 1.
5. **Signer:** `dc up -d --no-deps --wait signer`, then check
   `zkapi_signerStatus`: `tx_fee_cap_wei` must be the node's cap, and the
   warnings empty apart from `balance_below_required` and
   `tx_fee_cap_below_fee_cap`, which its default 12M `ZKAPI_CHALLENGE_MAX_GAS`
   can raise (lower it toward 8M to clear them).
6. **API server, then challenger.** Stop both, back up the data directory,
   start the server first, check the log line
   `server signing keys match the vault's immutable keys` and the attestation
   keys (Before you start, item 4), then start the challenger and read its
   `/status`:

   ```sh
   dc stop challenger server
   sudo tar -C /var/lib -czf "/root/zkapi-legacy-before-phase0-$(date +%s).tgz" zkapi
   dc up -d --no-deps --wait server
   dc up -d --no-deps --wait challenger
   dc exec -T challenger curl -sS http://127.0.0.1:3002/status | jq '{status, alarms, config_warnings}'
   ```

   Set up the alerting of that line's Docker guide (its Monitoring section)
   before closing the window, and schedule online database backups.
7. **Settlement.** Every pre-upgrade lease receives a settlement deadline and
   finalizes by it, at worst at its solvency bound with an operator review.
   Within about TTL + grace + the deadline, every row of Before you start,
   item 6, must be `finalized`. Handle each review
   ([Settlement reviews](#settlement-reviews)).
8. **Owner policy for the legacy vault.** Its owner can still pause every new
   exit without a time limit while `claimExpired` and an instant `setTreasury`
   keep working, and a treasury that rejects ETH blocks every exit with an
   operator share. Publish and follow this policy for the rest of its life:
   never pause it (unpause it now if `paused()` is true); make no treasury
   change unless the treasury stops accepting ETH; move ownership to a
   multisig with `transferOwnership(address)`, which takes effect at once on
   a legacy vault (verify the multisig address on that chain first); never
   renounce ownership. Repeat the treasury check of Before you start, item 1,
   daily during the drain.

## Phase A: freeze, review and trusted setup

1. **Freeze** the circuits at a tagged revision (`circuit-freeze-v2c`) and
   record the constraint counts (request 31,670, withdrawal 36,452 at the
   current revision).
2. **External review** of the scope listed under the mainnet gates above.
   Fix forward on `main`; any circuit change returns to step 1.
3. **G-SETUP**, as written step by step in
   [the ceremony setup README](../protocol/setup/v2-concession/README.md):
   - export the R1CS (`export_r1cs`) and pass the fidelity gate
     (`r1cs_export_roundtrip`, `r1cs_negative_assignments`);
   - use a public powers of tau of at least 2^16 that is on
     `ceremony::PUBLIC_PTAU`, checked against its published Blake2b-512, and
     pin its SHA-256 before the ceremony starts;
   - at least three phase-2 contributions, at least two of them by parties
     the operator did not select, then a public random beacon fixed in
     advance. Short of contributors, mainnet slips: no single-party setup
     reaches mainnet or production Sepolia, and `Deploy.s.sol` refuses one
     there;
   - publish the transcript, `r1cs-manifest.json` and every hash; each
     external reviewer downloads the powers of tau from its public source,
     exports the R1CS themselves and runs `snarkjs zkey verify` on both
     circuits;
   - import with `import_zkey --setup-id mpc-1` into
     `protocol/setup/v2-concession`, which runs every gate before writing
     anything;
   - run the proving gate against the imported keys (`ZKAPI_SETUP_DIR=../setup/v2-concession`
     with the `proofs` and `reduction_cross_check` tests and both fixture
     generators) before publishing the keys.
4. **Pins, in the same change that commits the keys.** Set
   `CEREMONY_VK_KECCAK256` in `zkapi-proof/src/compact.rs` and run
   `cargo run --release -p zkapi-proof --bin release_policy_check` from
   `protocol/rust`; regenerate the adapter (`forge fmt` into
   `protocol/contracts/src/adapters`), the fixtures and the gas snapshot; and
   rebuild the WebAssembly with `bash scripts/build-browser-client.sh --setup mpc-1`,
   which also copies the keys into `sdk/assets/proofs/` and rewrites
   `sdk/assets/manifest.json`. Commit
   `protocol/setup/v2-concession/manifest.json`: `Deploy.s.sol` checks an
   `mpc-1` deployment against it. Then `npm run verify:wasm` must reproduce
   the WebAssembly byte for byte.
5. **Expected codehashes.** Publish the expected runtime code hashes of the
   vault, adapter and library for each deployment's constructor arguments,
   computed from source by `node scripts/expected-codehashes.mjs` (it takes
   the arguments as flags, or reads a deployment manifest with
   `--deployment`). Anyone can rebuild the Forge artifacts with the pinned
   compiler settings and audit a profile against them.

## Phase B: Sepolia

### B1. Drill vault

The drill vault tests the adversarial cases with short timings. It uses the
`dev` setup, so it is a drill only: its toxic waste is public.

1. Deploy with the drill parameters (table below), `SETUP_MANIFEST` pointing
   at `protocol/setup/v2-concession-dev/manifest.json` and `ALLOW_DEV_SETUP=1`
   (recorded as `allowDevSetup: true`; a profile built from it is a drill
   profile only). Finalize the manifest as in
   [B2, step 3](#b2-production-sepolia).
2. Build drill binaries that load the `dev` keys, the server with the
   adversary modes:

   ```sh
   cargo build --release -p zkapi-cli --features adversary,zkapi-proof/dev-setup
   cargo build --release -p zkapi-serverd --bin zkapi-challenged --features zkapi-proof/dev-setup
   cargo build --release -p zkapi-companion --bin zkapi-walletd --features zkapi-proof/dev-setup
   bash scripts/build-browser-client.sh --setup dev
   ```

   Point their proof setup at `protocol/setup/v2-concession-dev`. Never ship
   these builds: release binaries and the Docker image load only the ceremony
   keys and reject `--adversary`. The server's mode is chosen at start,
   `zkapi --adversary <mode> serverd ...`: `withhold` (settles every request
   but never signs its successor), `born-spent` (signs successors at anchor 1),
   `reuse-anchor`, `random-anchor`, `overcharge` (one unit above the bound),
   `lie-expired` (answers every expiry check `expired_unaccepted`) and `hang`
   (holds every connection, drips a byte every 5 seconds for up to 600
   seconds, then answers 429 or 503 with `Retry-After: 86400`). Clients give
   up on each call after 20 seconds, so under `hang` an escape must still land
   before `must_initiate_by`.
3. Run the drills of design §10.7 B on it, each asserting the client's final
   state as well as balances: the honest flow; a withholding server
   (`--adversary withhold`) and the concession at `T`; `hang`, with the
   escape landing before `must_initiate_by`; `born-spent`, `reuse-anchor`,
   `random-anchor` and `overcharge`; `lie-expired`; a forced early exit with
   `c = 0`, a raise to the charge, and the client state `closed`; an
   under-concession, its raise, a finalization to a destination that refuses
   ETH and the credit's claim; a stale escape defeated, `SupersededState`,
   and a re-escape from an older state defeated again; the stale-device
   pre-check; a replay after `valid_until`; a late successor and the switch;
   an ownership proof sent on chain (`WrongWithdrawalKind`); the indexer down
   and the rebuild from logs; a pause with an escape pending, a pause past
   `maxPauseDuration`, and the re-pause cooldown; a codehash-mismatch profile
   refusing deposits; and a missed defeat (challenger stopped) followed by
   `retireClosedLeaf`. There is no scripted drill harness yet: run them with
   the drill binaries and record each result. A drill that retires leaves
   more than twice a day needs `ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY`
   raised in `signer.env`.

| Parameter | Mainnet | Sepolia production | Sepolia drill |
| --- | --- | --- | --- |
| `CHALLENGE_PERIOD_SECONDS` | 172,800 | 43,200 | 7,200 |
| `NOTE_TTL_SECONDS` | 2,592,000 (30 d) | 2,592,000 | 86,400 (1 d) |
| `MAX_PAUSE_DURATION_SECONDS` | 3,888,000 (45 d) | 604,800 (7 d) | 14,400 |
| `REQUEST_CHARGE_CAP` | 50,000 | 50,000 | 50,000 |
| Lease TTL / grace / settlement deadline / poll | 300 / 5 / 21,600 / 2 | 300 / 5 / 14,400 / 2 | 300 / 5 / 1,800 / 2 |
| `settlement_window_seconds` (`W`) | 21,905 | 14,705 | 2,105 |
| `ZKAPI_CHALLENGE_RAISE_LEAD_SECONDS` | 21,600 | 21,600 | 1,800 |
| Settlement check (`≤ challengePeriod / 2`) | 22,509 ≤ 86,400 | 15,309 ≤ 21,600 | 2,709 ≤ 3,600 |
| Raise check (`≤ challengePeriod`) | 44,713 ≤ 172,800 | 37,513 ≤ 43,200 | 5,113 ≤ 7,200 |
| Setup | `mpc-1` | `mpc-1` | `dev` (`ALLOW_DEV_SETUP=1`) |

The settlement check is lease TTL + grace + deadline + 2 x poll + 600; the
raise check is `W` + raise lead + 4 x poll + 1,200. serverd refuses to
start when the settlement check fails and `zkapi-challenged` when either
fails; the vault's constructor requires `maxPauseDuration` of at least twice
the challenge period.

### B2. Production Sepolia

The new deployment is a separate stack: new public manifest, hostname,
signer key, exclusive sender and data directory. Prefer a separate VM; to
share one, see [Two stacks on one VM](#two-stacks-on-one-vm).

1. **Keys.** Generate fresh state and clearance seeds into the new
   `server.env` and print the public keys
   ([Signing seeds](../docker/aws/README.md#signing-seeds)). Never reuse the
   legacy deployment's seeds.
2. **Deploy.** From `demo/contracts`, run `Deploy.s.sol` with `OWNER` (a
   multisig, ideally behind a timelock), `TREASURY`, the four key
   coordinates, the Sepolia production parameters,
   `SETUP_MANIFEST=../../protocol/setup/v2-concession/manifest.json`,
   optionally `POSEIDON_ADDRESS` (an existing library with the compiled
   codehash) and `CHAIN_ID=11155111`; see [the contract notes](deployment.md#contracts).
   The script checks the keys, links the library, deploys the adapter and
   the vault with 11 constructor arguments, checks the adapter's
   `CIRCUIT_ID_HASH()` and verifying-key hashes against the setup manifest,
   and writes only the provisional manifest `$OUTPUT_PATH.pending`.
3. **Finalize the manifest** once the vault's creation is final:

   ```sh
   node scripts/expected-codehashes.mjs --deployment "$OUTPUT_PATH.pending" \
     --rpc "$RPC_URL" --finalize "$OUTPUT_PATH" --confirmations 64
   ```

   It reads the creation receipts from forge's broadcast log
   (`demo/contracts/broadcast/Deploy.s.sol/<chainId>/run-latest.json`, or
   `--broadcast-log`), checks every creation, the three runtime codehashes,
   the owner and the treasury on chain, and only then writes `$OUTPUT_PATH`
   with `deploymentStatus: "deployed"`, `deployBlock` (the vault's creation
   block) and `deployTransactions`. Keep the broadcast log until then: there
   is no fallback without it. Re-audit later with
   `node scripts/expected-codehashes.mjs --deployment "$OUTPUT_PATH" --check --rpc "$RPC_URL"`.
4. **Post-deploy checks** (`NEW_VAULT` is the manifest's `vault`):

   ```sh
   for getter in 'owner()(address)' 'pendingOwner()(address)' 'treasury()(address)' 'paused()(bool)' \
       'challengePeriod()(uint64)' 'noteTtl()(uint64)' 'maxPauseDuration()(uint64)' \
       'requestChargeCap()(uint128)' 'PROTOCOL_VERSION()(uint16)' 'CONCESSION_ESCAPE_VERSION()(uint16)' \
       'ROOT_HISTORY_WINDOW()(uint64)' 'PAUSE_COOLDOWN()(uint64)' 'ESCAPE_PAYOUT_GAS()(uint256)' \
       'proofAdapter()(address)'; do
     printf '%s ' "$getter"; cast call "$NEW_VAULT" "$getter" --rpc-url "$RPC_URL"
   done
   ADAPTER=$(cast call "$NEW_VAULT" 'proofAdapter()(address)' --rpc-url "$RPC_URL")
   for getter in 'CIRCUIT_ID_HASH()(bytes32)' 'REQUEST_VK_HASH()(bytes32)' 'WITHDRAWAL_VK_HASH()(bytes32)'; do
     printf '%s ' "$getter"; cast call "$ADAPTER" "$getter" --rpc-url "$RPC_URL"
   done
   ```

   Expect `owner()` the multisig and `pendingOwner()` zero,
   `PROTOCOL_VERSION` 2, `CONCESSION_ESCAPE_VERSION` 1,
   `ROOT_HISTORY_WINDOW` 86400, `PAUSE_COOLDOWN` 86400,
   `ESCAPE_PAYOUT_GAS` 100000, `CIRCUIT_ID_HASH`
   `0xf464f910d858a070b2f88db1049aab19d8fabeed1e527920be90dc0c950b0687`
   (keccak256 of `zkapi-v2-concession-v1`), and the VK hashes of
   `protocol/setup/v2-concession/manifest.json`. Compare the four key getters
   with the printed keys as numbers, and the codehashes with the published
   expected values.
5. **Profiles.** Every consumer takes its pins and `deploy_block` from the
   finalized manifest only, never from `.pending` or `deployBlockLowerBound`.
   Write the `trusted_deployment` profile from it: `chain_id` (`chainId`),
   `contract_address` (`vault`), `deploy_block` (`deployBlock`), `circuit_id`,
   `setup_id`, `request_vk_keccak256`, `withdrawal_vk_keccak256`,
   `vault_runtime_codehash`, `proof_adapter_address` (`proofAdapter`),
   `adapter_runtime_codehash`, `poseidon_library_address` (`poseidonLibrary`),
   `poseidon_runtime_codehash`, `challenge_period`, `note_ttl`,
   `max_pause_duration`, `state_signing_key` and `clearance_signing_key`
   (`{x, y}`, from the decimal key coordinates), `request_charge_cap`,
   `vault_revision: 3`, `exit_concession: 1`,
   `clearance_ownership_proof: "required"`, `settlement_window_seconds`
   (lease TTL + grace + settlement deadline), the proving- and verifying-key
   SHA-256 pins of the setup, the endpoints, and
   `deployment_status: "deployed"`. The same profile is the server stack's
   `/etc/zkapi/deployment.json`; the SDK profile
   (`sdk/assets/config/sepolia.json`) adds the browser fields, and clientd's
   `deployments/sepolia.json` carries the same pins under its own names
   (`challenge_period_seconds`, `deployment_evidence.*_runtime_keccak256`,
   `proof_setup`).
6. **Stack.** Configure it from [the Docker guide](../docker/aws/README.md)
   with the Sepolia values of
   [`deployment.env.example`](../docker/aws/deployment.env.example): the new
   `VAULT_ADDRESS` and `DEPLOY_BLOCK`, a signer with a new private key and
   `ZKAPI_CHALLENGE_VAULT` set to the new vault, a new funded sender, the
   transaction fee cap in `signer.env` and `deployment.env`,
   `ZKAPI_CHALLENGE_RETIRE_ON_MISS` equal in both files, and no
   `ZKAPI_ALLOW_LEGACY_CLEARANCE` (serverd refuses it). Fund the sender for
   `⌈m/2⌉` defeats per note (a user holding `m` archived states can force that
   many), at most 64 concurrent escapes and a 20% margin, plus leaf
   retirements: at 100 gwei, about 0.06 ETH per defeat and 0.72 ETH per
   retirement.
7. **Start in this order:** the indexer from `DEPLOY_BLOCK`, `zkapi db init`
   (the `db-init` service), the challenger, then the API server.

   ```sh
   dc up -d --wait indexer
   dc run --rm db-init
   dc up -d --wait challenger
   dc up -d --wait server
   ```

   `zkapi db init` creates the schema, the append-only `request_evidence`
   table and the `deployment_binding` row, and refuses a database bound to
   anything else; the challenger refuses a database without it ("run
   `zkapi db init` first"). Each daemon refuses a placeholder or provisional
   manifest, and checks the vault, the adapter and the library against it.
   **The challenger must be healthy, with its alerting armed, before the
   first deposit.**
8. **Acceptance.** Run the Docker guide's acceptance checks: `/health` and
   `/v1/attestation` report `circuit_id` `zkapi-v2-concession-v1`,
   `setup_id` `mpc-1`, `exit_concession` 1 and the deployment's
   `settlement_window_seconds`; the server log shows
   `the vault, adapter and Poseidon library match the deployment manifest`.
   Then a funded lifecycle on Sepolia: deposit, a paid request, a mutual
   close (which sends a kind-2 ownership proof), an escape with `c = 0` from a
   fresh state, and an escape from a served state that the challenger raises.

### B3. Publish clients for Sepolia

- **New browser build.** Pin the deployed profile in
  `sdk/assets/config/sepolia.json`, run
  `node scripts/sync-sdk-assets.mjs --setup mpc-1 --network sepolia`, then
  `npm run verify:assets` and `npm run build:browser`. Hosts serve it at
  `/zkapi/v2c/` on the same origin as the legacy build
  ([Side-by-side browser builds](#side-by-side-browser-builds)).
- **Legacy Sepolia re-cut** with `"deposits": "closed"`
  ([Phase E, step 1](#phase-e-drain-and-retire-the-legacy-vault)).

### B4. Soak

Run production Sepolia for at least 14 days with weekly drills on the drill
vault. Watch every alert of the Docker guide's Monitoring section, the raise
and defeat counters, and the settlement dashboard's `exit_deferred` and
`exited_unsigned` counts.

## Phase C: mainnet

1. **Deploy** with the mainnet parameters, as in B2, steps 1 to 4
   (`CHAIN_ID=1`; `Deploy.s.sol` refuses a `dev` setup there). Finalize with
   `--confirmations 64` and publish the manifest and the expected codehashes.
2. **Start the daemons** in the order of B2, step 7.
3. **Smoke tests with small notes:** deposit, request, settle, mutual close;
   an escape with `c = 0` from a fresh state, then finalize; a served
   request, then a deliberate escape with `c = 0`, which the challenger
   raises to the charge, then finalize, and check that the client state is
   `closed`.
4. **Publish the new mainnet build with the canary for 30 days.** The
   profile's `canary` caps a note at 0.25 ETH (`per_note_max_wei`) and the
   vault's balance at 25 ETH (`aggregate_max_wei`) until `until`; the server
   runs with `ZKAPI_REQUEST_LIMIT_MAX_USD_MICROS=6000000` (recommended
   permanently). The SDK caps protect honest SDK users; direct depositors
   bypass them. Build with `node scripts/sync-sdk-assets.mjs --setup mpc-1 --network mainnet`,
   `npm run verify:assets` and `npm run build:mainnet`, which refuses
   anything but an `mpc-1` bundle. In the same host release, publish the
   legacy mainnet re-cut with `"deposits": "closed"`.
5. **Announce the legacy cutoff `X`** (Phase C + 30 days), and the treasury
   sweep of legacy stragglers that Phase E describes.
6. **Users.** New users deposit into the new vault. Browser users with a
   legacy note are routed to the legacy build to close it, then deposit.
   A legacy note with a request in flight waits for its settlement: publicly
   commit to finalizing every legacy lease and to running the legacy
   challenger until retirement.

## Phase D: clientd releases

1. **Legacy point release 0.1.7 first.** It is on `release/v2-note-bound`:
   deposits closed (`deposits_closed`; a deposit signed earlier still
   activates), `withdraw --escape` for a fresh, settled state with its
   finalization and payout match, and the runbook
   `zkapi-clientd/docs/LEGACY_ESCAPE.md`. Push the branch, tag
   `clientd-v0.1.7`, package it, and run its Sepolia drill (a fresh-state
   escape, its finalization, and a refused deposit). Then check its record,
   `zkapi-clientd/packaging/releases/clientd-0.1.7.json`, into `main`:
   `scripts/assemble-release.py` refuses to assemble any other release until
   that file exists, because the new release's warnings name 0.1.7.
2. **New release.** Pin the deployed profiles in
   `internal/zkapi/deployments/*.json` (replacing the `not_deployed`
   placeholders), move `ZKAPI_SOURCE_COMMIT` in `packaging/zkapi-source.env`
   to a commit pushed to the public repository that holds every companion,
   protocol and `Cargo.lock` change, run `scripts/test-companion.sh` on a tree
   from `scripts/prepare-zkapi.sh` (with Foundry on `PATH`, so the companion's
   Anvil test runs) and the Go suite, run a Sepolia drill of its escape
   route, then release it. It reports `bridge_version` 5 and
   `exit_concession` 1, warns about an open legacy wallet without refusing to
   start, and keeps its payment state per deployment.
3. **Users** close their legacy note with 0.1.7 (mutual close, or
   `withdraw --escape` from a settled state), upgrade, and deposit. Tell them
   that 0.1.7 refuses deposits, and that the new release never opens the
   legacy wallet directory.

## Phase E: drain and retire the legacy vault

1. **Legacy re-cut** for each network, from `release/v2-note-bound`: the same
   WebAssembly, worker and key bytes, with only the profiles changed to
   `"deposits": "closed"` in `trusted_deployment` (and
   `"clearance_ownership_proof": "optional"` if not set yet). On that branch,
   regenerate the config hashes (`node scripts/sync-sdk-assets.mjs`), check
   them (`npm run verify:assets`), build (`npm run build:browser`,
   `npm run build:mainnet`), and tag it `legacy-recut-<n>`. It keeps the
   existing `publicPath`. The runtime fetches `browser-config.json` with
   `cache: 'no-store'`, so a host that serves the new file reaches every
   loaded tab; confirm that every host serves this revision. The SDK then
   refuses a new deposit with `409 deposits_closed` before any chain read or
   wallet prompt, and a deposit already started stays completable. Builds
   older than the legacy line ignore the flag: hosts remove their deposit
   action. `zkapi-clientd` deposits stop with 0.1.7; to stop older clientd
   releases too, have the legacy gateway answer 410 on the two deposit-only
   routes, `/v1/tree/next-note-id` and `/v1/tree/notes/{id}/zero-path`
   (the legacy challenger reads zero-paths from the internal indexer, not
   through the gateway):

   ```nginx
   # Deposit cutoff: the drained vault no longer offers new deposit paths.
   location = /v1/tree/next-note-id { return 410; }
   location ~ ^/v1/tree/notes/[0-9]+/zero-path$ { return 410; }
   ```

   Put it before `location /v1/tree/` in the `nginx.conf` of the legacy
   checkout, build the legacy gateway under a new legacy `ZKAPI_IMAGE_TAG`,
   and recreate it. Never pause the legacy vault to stop deposits; anyone can
   still deposit directly, and such notes drain like any other.
2. **From `X`.** The design closes legacy admission at `X`
   (`--admission closed`, refusing new requests with `deployment_retiring`),
   but the legacy line has no such switch yet: it needs a legacy point
   release of serverd. Until one ships, the legacy stack keeps admitting
   requests from legacy notes; the retirement bound below holds either way,
   because requests end at each note's expiry. In-flight leases still settle,
   clearances for fresh nullifiers stay available, and the legacy challenger
   keeps running.
3. **Drain monitoring.** Track the legacy notes daily (Before you start, items
   1 and 2): notes by status, pending escapes, `nextNoteId()` for late direct
   deposits, and whether the treasury still accepts ETH. Anyone can finalize
   an escape after its deadline, which also pays the treasury, so finalize
   those their owners leave pending, simulating first:

   ```sh
   cast call "$VAULT" 'finalizeEscapeWithdrawal(uint32)' <noteId> --rpc-url "$RPC_URL"
   cast send "$VAULT" 'finalizeEscapeWithdrawal(uint32)' <noteId> \
     --rpc-url "$RPC_URL" --account "$PAYER_ACCOUNT"
   ```

   On a legacy vault, a simulation that reverts `0xf4b3b1bc`
   (`NativeTransferFailed()`) while the treasury check still passes means the
   escape's destination rejects ETH: that escape cannot finalize until the
   destination accepts ETH. Record its note ID, destination and final
   balance, announce it through the hosts, and keep simulating it, also after
   retirement. Anyone, the owner included, can finalize it without a zkAPI
   client once the destination accepts ETH, as long as the treasury does too.
4. **Expired notes.** A legacy note can still exit after its expiry until
   someone calls `claimExpired`, which pays the full deposit to the
   treasury. Announce the expiry dates early, and publish in advance what the
   operator does with deposits it claims (for example, a refund on request
   outside the protocol).
5. **Disable legacy clearance** once the legacy re-cut and 0.1.7 are adopted
   and owners of older releases were warned: remove
   `ZKAPI_ALLOW_LEGACY_CLEARANCE` from the legacy `deployment.env`, recreate
   the legacy server, and check that `/health` reports
   `clearance_ownership_proof_required: true` and
   `legacy_clearance_window_limit: 0`. Before that, count recent proof-less
   reservations:

   ```sh
   sudo sqlite3 -readonly "$DATA_DIR/server.db" \
     "SELECT count(*) FROM nullifiers WHERE status = 'ClearanceReserved' AND clearance_auth = 'legacy' AND created_at > strftime('%s', 'now', '-7 days');"
   ```

   `zkapi-clientd` 0.1.6 and earlier cannot withdraw afterwards. A legacy
   browser build cannot mutual-close a state whose request proof left the
   device and never settled; such an owner exits after a chat from that state
   settles.
6. **Retire the legacy stack** when every legacy note deposited before `X` is
   `Closed` or past its `effectiveExpiry`, and the last challenge deadline
   has passed: at most `X` + `noteTtl` + pauses + post-challenge grace +
   `challengePeriod`. Notes deposited after `X` hold only their genesis state,
   so they need no challenger; they exit at their deposit by escape (the
   legacy build or 0.1.7) or are swept at expiry, as announced. An escape
   stuck on a destination that rejects ETH (step 3) does not block retirement
   once its deadline has passed. Then, with the legacy deployment's `dc`:
   stop the challenger and signer and move the sender's balance; stop the
   server, indexer and gateway and remove the legacy origin; archive the data
   directory as sensitive data (it holds request proofs and transcripts);
   keep the legacy SDK bytes, keys and client releases available.

## Side-by-side browser builds

There is no multi-circuit loader. A host serves the legacy build at its
existing `publicPath` (`/zkapi/`) and the new build at `/zkapi/v2c/` on the
same origin. Both share IndexedDB `zkapi-browser-wallet-v1` (version 3) and its
Web Lock; each runtime refuses a runtime slot holding the other deployment's
note, and neither rewrites the other's records.

- The host lists two package entries, `zkapi-sdk-legacy` (`#legacy-recut-<n>`)
  and `zkapi-sdk` (`#v2c-<tag>`); each resolves its own WebAssembly, keys and
  worker.
- A small loader calls `readBrowserWalletHoldings()` from the store export and
  `import()`s the legacy entry while a legacy runtime holds an open note, and
  the new entry otherwise. A legacy withdrawal still open while the runtime
  slot is empty (a set-aside close or a pending escape) needs the legacy
  build; it cannot load while the new runtime holds a note. One SDK runs per
  page: switching builds reloads the page.
- [`examples/sample-host`](../examples/sample-host/README.md) builds both and
  holds that loader; `sdk/test/sample-host.test.mjs` and
  `sdk/test/browser-wallet-coexistence.test.mjs` test it.
- Do not offer a deposit while `snapshot().config.other_deployment_withdrawals`
  is non-empty. The exception is a legacy escape announced as stuck on a
  destination that rejects ETH (Phase E, step 3): show the owner its note ID
  and how to finalize it on chain. Never clear site data to get past these
  checks.
- Hosts that route protocol calls through a same-origin rewrite need one for
  the new hostname too.

See [Moving to a newly pinned deployment](../sdk/README.md#moving-to-a-newly-pinned-deployment)
and [Two builds on one origin](../sdk/README.md#two-builds-on-one-origin).

## Two stacks on one VM

Prefer a separate VM per deployment. On one VM, run the legacy deployment as a
second Compose project with its own configuration directory, data directory,
HTTP port and image tag, as in
[Upgrades and running two deployments](../docker/aws/README.md#upgrades-and-running-two-deployments).
Stop all of its services to move it, then use, for every legacy command:

```sh
dc() { sudo docker compose -p zkapi-legacy --env-file /etc/zkapi-legacy/compose.env -f docker/aws/compose.yml --profile challenge "$@"; }
DATA_DIR=/var/lib/zkapi-legacy API_URL=http://127.0.0.1:8081
```

Run that project from a checkout of `release/v2-note-bound` and the new one
from `main`: the images differ, and the gateway image contains its checkout's
`nginx.conf`. Never repoint the legacy signer or challenger at the new vault.

## Operations runbooks

These apply to the concession vault (`NEW_VAULT`) unless they say otherwise.
The commands assume a key in a Foundry keystore (`--account`); a Safe submits
the same calls as Safe transactions.

### Pause

`pause()` blocks `deposit`, `claimExpired`, `setTreasury`, `acceptTreasury`,
`withdrawTreasuryArrears` and `renounceOwnership` until `unpause()`. It blocks
`initiateEscapeWithdrawal` and `mutualClose` for at most `maxPauseDuration()`:
from `pausedAt() + maxPauseDuration()` they reopen while still paused.
Defeats, raises, `finalizeEscapeWithdrawal`, `claimEscapePayout`,
`retireClosedLeaf`, `cancelTreasuryChange`, `transferOwnership` and
`acceptOwnership` stay open. A new pause needs `PAUSE_COOLDOWN()` (one day)
since the latest unpause (`PauseCooldown()` otherwise). Paused time extends
every note's claim time, and after any unpause `claimExpired` waits at least
`unpauseClaimGrace()`. A pause does not move pending escapes' deadlines: the
challenger must still act in each window, which it can while paused. Alert on
`Paused` and `Unpaused`.

### Treasury change

```sh
cast send "$NEW_VAULT" 'setTreasury(address)' "$NEW_TREASURY" --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"
cast call "$NEW_VAULT" 'pendingTreasuryReadyAt()(uint64)' --rpc-url "$RPC_URL"
cast call "$NEW_VAULT" 'totalPausedDuration()(uint64)' --rpc-url "$RPC_URL"
cast send "$NEW_VAULT" 'acceptTreasury()' --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"
cast send "$NEW_VAULT" 'cancelTreasuryChange()' --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"
```

`pendingTreasuryReadyAt()` is on the active clock (wall time minus paused
time): while unpaused, `acceptTreasury()` succeeds from
`pendingTreasuryReadyAt() + totalPausedDuration()`, and every later pause
pushes that further. A scheduled change gives users at least
`treasuryChangeDelay()` of unpaused time to exit. On a legacy vault
`setTreasury` takes effect at once; follow the Phase 0 owner policy.

### Owner key rotation

Ownership moves in two steps on the concession vault, both open while paused:
`transferOwnership(address)` nominates (`OwnershipTransferStarted`) and the
nominee calls `acceptOwnership()` (`OwnershipTransferred`). Until then the old
key keeps every power and can replace or cancel the nomination
(`transferOwnership(address(0))`). Alert on any `OwnershipTransferStarted` you
did not send.

If the current owner key may be compromised, never send the nomination alone
through the public mempool. Sign both transactions in advance and submit them
together, nomination first, as one bundle to a block builder's private bundle
endpoint (`eth_sendBundle`), so that they land consecutively in one block or
not at all; a Safe nominee's transaction is a pre-signed `execTransaction`
calling `acceptOwnership()`. Otherwise prepare the acceptance, then:

```sh
cast send "$NEW_VAULT" 'transferOwnership(address)' "$NEW_OWNER" --rpc-url "$RPC_URL" --account "$OWNER_ACCOUNT"
cast send "$NEW_VAULT" 'acceptOwnership()' --rpc-url "$RPC_URL" --account "$NEW_OWNER_ACCOUNT"
cast call "$NEW_VAULT" 'owner()(address)' --rpc-url "$RPC_URL"          # the new owner
cast call "$NEW_VAULT" 'pendingOwner()(address)' --rpc-url "$RPC_URL"   # zero
```

### Treasury arrears

`TreasuryPaymentDeferred` means a treasury payout failed and was kept in
`treasuryArrears()` (gwei). Fix the treasury (it must accept ETH within
100,000 gas), then anyone can pay it out while unpaused:
`cast send "$NEW_VAULT" 'withdrawTreasuryArrears()' --rpc-url "$RPC_URL" --account "$PAYER_ACCOUNT"`.

### Escape payout credits

`EscapePayoutDeferred(noteId, destination, amount)` means an escape closed but
its push to `destination` failed (it rejected ETH or needed more than 100,000
gas). The amount waits in `escapePayoutCredits(destination)`. The browser SDK
reports an escape it started as credited and offers the claim, and
`zkapi-clientd` shows the claim (`withdraw --claim`); other owners learn of it
only from you, so announce each credit with its note ID and destination
through the hosts. Anyone can deliver it, also while paused, and only
`destination` is paid:

```sh
cast call "$NEW_VAULT" 'escapePayoutCredits(address)(uint128)' <destination> --rpc-url "$RPC_URL"
cast send "$NEW_VAULT" 'claimEscapePayout(address)' <destination> --rpc-url "$RPC_URL" --account "$PAYER_ACCOUNT"
```

The claim forwards all gas; it reverts and keeps the credit while the
destination still rejects ETH. Legacy vaults have no credits (Phase E, step 3).

### Missed defeat or raise

The challenger records a **missed defeat** when an escape finalized although
verified request evidence at its successor nullifier existed before its
deadline, and a **missed raise** when an escape finalized with a concession
below what the server was owed. Each logs `MISSED escape deadline`
(`missed="defeat"` or `missed="raise"`), stays a critical alarm for an hour,
and counts in `escapes_finalized_with_successor_evidence_total` or
`missed_raises_total`. After a missed defeat, with `--retire-on-miss` (the
default, and `ZKAPI_CHALLENGE_RETIRE_ON_MISS` in both `deployment.env` and
`signer.env`), the challenger retires the closed note's leaf with
`retireClosedLeaf`, so the server, which admits only requests at the current
root, refuses every later proof built on that note. The obligation shows
`retiring_leaf` until the retirement mines; it needs the indexer's path at
the live root, about 7.2M gas, and the signer's retirement budget
(`ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY`, default 2 per rolling day, counted
per nonce). A refusal shows as `signer_refused`; raise the budget in
`signer.env` and recreate the signer if repeated root races spent it. A miss
means the challenger was down, blocked or out of funds through a whole
window: find the cause before the next deadline (see
[challenge operation](challenge-service.md)).

### Settlement reviews

Alert on `settlement required operator review`, list open reviews, handle
each and acknowledge it by its `review_id`, as in the
[Docker guide](../docker/aws/README.md#monitoring). A `binding_corrupt` review
means a lease row and its reservation disagree, and the server signs nothing
for it until the operator repairs and reopens it with
`zkapi settlement reopen`, as in
[Reopening a cancelled lease](native-eth-billing.md#reopening-a-cancelled-lease).
On the concession vault its owner is not stranded meanwhile: the request stays
unresolved, so the owner's client escapes at its time `T` conceding the
state's bound, which already covers the most the challenger could raise to.
Reopening lets the owner install the real successor instead.
On a legacy vault a reserved nullifier leaves most owners without an exit
(legacy browser builds refuse to escape there, and the server grants no
clearance), so reopen such a lease before its note expires.

### Receipt journal missing (legacy vault)

A legacy client that reports `receipt_journal_missing` holds a note whose
current nullifier the server finalized for a request the client cannot apply,
usually one an older client discarded. The remedy, turning that `Finalized`
row into a clearance reservation, rests on the owner's word and can cost up
to the note's whole balance at that state. It is documented, with its
conditions and the one tested statement, in the copy of the earlier guide on
`release/v2-note-bound` (Operations runbooks, "Receipt journal missing").
Grant it only before legacy clearance is disabled (Phase E, step 5). The
concession vault needs no such remedy: an owner who lost a response escapes
conceding `min(charge, bound)`.

### Indexer divergence

Follow [Indexer resync](../docker/aws/README.md#indexer-resync). On the
concession vault, escapes, defeats, raises, closes and expiry claims change no
leaf, so the indexer's `/v1/escapes/pending` is not covered by its root check
at all: it is a hint. The challenger tracks escapes from its own event scan
and reads `pendingWithdrawals` and `pendingConcessions` from the vault, and a
defeat or a raise needs no indexer. A diverged indexer still blocks deposits,
leaf retirements, the server's admission (`root_unavailable`) and clients
without a saved deposit-time path or an exit RPC for a log rebuild.

### Fee spikes

When the challenger reports `base_fee_above_fee_cap`, `fee_cap_reached`,
`tip_cap_reached`, `fee_reserve_held`, `tx_fee_cap_reached` or
`insufficient_balance`, raise the signer's caps in `signer.env` and recreate
the signer, then the daemon's (no higher) in `challenge.env` and recreate the
challenger, or fund the sender. A container reads its environment files only
when created: use `dc up -d --no-deps --wait signer`, then `challenger`. For
`tx_fee_cap_reached`, `tx_fee_above_cap` or `upstream_tx_fee_cap`, raise the
node's `--rpc.txfeecap` first, then `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` in both
files. At the default 1 ETH ceiling a 600,000-gas defeat can bid about 1,666
gwei and a 450,000-gas raise about 2,222 gwei, so fee spikes threaten mostly
leaf retirements and legacy challenges (about 7.53M gas, about 132 gwei). See
the [fee-spike runbook](../docker/aws/signer/README.md#fee-spike-runbook) and
[challenge operation](challenge-service.md#when-no-valid-bid-remains).

## Rollback

| Stage | Action |
| --- | --- |
| Phase 0 | Roll forward where possible. The previous image tags bring back the defects the hardening fixed: the previous signer needs `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI` and refuses the new challenger's fee fields; the previous challenger treats reserved leases as evidence, which burns nullifiers on a legacy vault; the previous server restores the seed fallback and proof-less clearance; the previous indexer needs `indexer.cursor` moved aside and replays from `DEPLOY_BLOCK` (never restore a `.v1-*.bak`). Never restore an older database over newer wallet activity. |
| Before Phase C, step 4 | Do not publish; the contracts stay unused. An unannounced deployment can be abandoned before anyone deposits. |
| After new deposits; a client or server bug | Fix forward. Exits never depend on server or client cooperation. Optionally set the new profiles to `"deposits": "closed"`. |
| After new deposits; a vault or circuit bug that leaves exits sound | Close deposits on the new profiles. Reopen the legacy profiles only while the legacy stack runs, before `X`. Keep the new stack running until the new vault drains. Deploy a corrected vault with a new circuit ID if needed. |
| An exit-soundness bug (forgery) | Pausing stops only new escapes and closes, and only for up to `maxPauseDuration`. Pending escapes finalize at their deadlines unless defeated or raised, and the challenger must act in each window; a forged escape with no successor evidence cannot be defeated. Decide in advance: pause, publish, keep the challengers running, and let honest users exit when exits reopen. The vault has no upgrade path. The canary caps bound honest SDK users' exposure, and the server's lease ceiling bounds per-request service. |
| The server signs non-derived anchors (a bug) | Clients reject such successors (S4), and the request circuit makes them unspendable. Fix the server; nothing on chain changes. |
| A clientd release | The new line never reads or changes the legacy wallet and payment files, so reinstalling 0.1.7 finds them as it left them. Each line withdraws only its own vault's notes. |

## If development or mismatched keys were ever served

If a server ever ran with a development key (seed `0x1` or `0x2` in any
spelling) or with keys other than its vault's, treat the deployment as
compromised: anyone could forge state signatures and obtain provider keys
beyond their deposit, and with the development clearance key forge
clearances for their own notes.

1. Stop the server.
2. Rotate `ZKAPI_OPENROUTER_MANAGEMENT_KEY` or the OA org shared secret, and
   delete all outstanding runtime keys at the provider.
3. Audit `openrouter_leases` since the first start (`spending_limit_usd`,
   `usage_usd`, `charge_applied`) and the provider's usage, with the queries
   of Before you start, item 5.
4. Generate new seeds and deploy a new vault with their keys (Phase B or C);
   vault keys are immutable.
5. Publish new client profiles and move users (Phases C to E). If the vault
   itself pinned a development key, its notes stay forgeable until drained:
   retire it as fast as its owners can exit.

`Deploy.s.sol` refuses the development keys off local chains, and serverd
refuses them everywhere.

## Residual risks

**Concession vault** (design §9.2, plus the implementation):

- **Chain censorship** and **operator liveness**: the challenger must land one
  cheap transaction for each escape that needs a defeat or a raise. If it
  misses a defeat, the operator loses at most the stale payout plus service
  from the owner's newest state until `retireClosedLeaf` lands.
- **The retirement budget.** The signer bounds leaf retirements per rolling
  day, counted per nonce. Anyone who forces root races by front-running
  deposits can spend it and delay a retirement after a missed defeat; the
  miss itself is already critical.
- **Strategic under-conceding.** A raise costs about 335,000 gas, more than
  small request tiers; a modified client may bet that the operator does not
  raise. `ZKAPI_CHALLENGE_RAISE_MIN_UNITS` sets the smallest raise worth it.
- **Forced early exits conceding the bound** forfeit the bound minus the
  actual charge; clients ask the user.
- **Exit-time linkage.** An escape from a served state links the note's last
  request to the note and destination for the server and gateway; a raise
  publishes that request's public inputs on chain (design §8).
- **Leaked keys.** A leaked state key forges states, each capped at the
  deposit; a leaked clearance key lets a dishonest owner close at a spent
  state.
- **Permanent clearance reservations** (harmless while clients never request
  from a state after sending its ownership proof).
- **Setup trust.** An honest public phase 1 that the ceremony used and one
  honest phase-2 contributor (A2).
- **Stale backups.** Restoring a stale wallet or exit kit is caught by the
  stale-device pre-check only when the operator serves evidence; otherwise
  the escape is defeated and costs gas.
- **Owner pause** blocks new exits for up to `maxPauseDuration` (45 days on
  mainnet) per cycle.
- **Browser host dependence** without a current exit kit; the companion's
  `exit-kit escape` works without the host.
- **An exit RPC that is down.** With `--exit-rpc-url` set, clientd and the
  companion stop an escape with an error rather than fall back to the pinned
  RPC; the owner retries or changes the setting. Without an exit RPC, the
  pinned RPC is trusted for escape liveness. The SDK's chat path still
  releases a dead exit lock on the pinned RPC's reading when no exit RPC is
  set.
- **Deployment manifests.** Finalizing needs forge's broadcast log, and owner
  and treasury are checked only when it runs.

**Legacy vault, until it retires:**

- **Withholding operator.** An operator that withholds a signed successor can
  still defeat the owner's legacy escapes and take the deposit at expiry. Only
  the operator's public commitment to finalize every legacy lease, and the
  legacy challenger's finalized-only evidence rule, protect owners there.
- **Nullifier burn.** A legacy challenge consumes the escaped nullifier.
- **Unbounded pause** and an instant treasury change; only the Phase 0 owner
  policy protects owners.
- **Destinations that reject ETH** lock a legacy escape until they accept.
- **Root races.** Legacy exits and challenges need siblings at the live root,
  so an unrelated deposit can revert them; the challenger retries with fresh
  siblings.
- **The legacy clearance budget** is one shared pool while legacy clearance
  is on.
- **No admission switch.** The legacy line cannot stop new requests at `X`
  until a legacy serverd point release adds one (Phase E, step 2).
