# Native ETH deployment

The source supports native ETH vaults of circuit `zkapi-v2-concession-v1`
(vault revision 3). The committed keys are the single-party development setup
`dev`, which release builds refuse; production keys come from the multi-party
ceremony in [the ceremony setup](../protocol/setup/v2-concession/README.md),
which has not run yet. Publishing code does not establish an independent
audit or setup ceremony.

Configure the exact circuit artifacts, contract, code-hash and signing-key
pins, oracle feed, and denomination for the vault. Preserve persistent
operator state and keep wallet journals bound to their configuration. A
deployment of the legacy circuit `zkapi-v2-note-bound-v1` keeps running from
the release line `release/v2-note-bound`; moving its users to a revision-3
vault is described in
[the concession-vault migration runbook](migration-concession-vault.md).

## Build services

```sh
cargo build --release --workspace
```

`zkapi serverd` requires `--native-billing-rpc-url` and
`--native-price-feed-address` (or corresponding `ZKAPI_NATIVE_*` variables), plus
an OA org/service credential or direct OpenRouter management credential.
Supply chain ID, vault, gwei request cap, both signing seeds (required; see
below), the deployment manifest (`--deployment`), database path, indexer URL
and the exact proof directory. Run
`zkapi serverd --help` for flags. `--native-price-feed-decimals` (default 8) and
`--native-price-max-age-seconds` (default 4500) must equal the published
manifest. Native prices come from the pinned finalized oracle round; a generic
RPC/chain or USD token configuration is not interchangeable with these pins.

For a private Sepolia test, configure `ZKAPI_TESTNET_PASSWORD` only in the
Sepolia server's secret environment. The built-in gate requires that password
for every service API call while leaving health and protocol metadata public.
See [Sepolia shared password](testnet-auth.md) for client behavior, proxy header
forwarding, validation and rotation. Never put this value in the public SDK
manifest or configure it on Mainnet.

## Signing keys

The state and clearance signing seeds are required, with no default:
`ZKAPI_STATE_SEED` and `ZKAPI_CLEAR_SEED` (or `--state-seed` and
`--clear-seed`, which are visible in the process list; prefer the environment).
An empty value counts as missing, and an explicitly empty flag does not fall
back to the environment. A seed is a hex field element. Generate each with:

```sh
printf '0x%s\n' "$(openssl rand -hex 31)"
```

`zkapi signing-keys` and `zkapi serverd` refuse:

- zero and any multiple of the Baby-JubJub subgroup order;
- any seed whose public key is a published development key, in either role and
  any spelling (`0x1`, `1`, `0X1`, `0x0001`, `1` plus a multiple of the subgroup
  order, and the swapped pair);
- a secret within 2^128 of zero or of the subgroup order, which includes every
  seed of 16 bytes or fewer;
- one key for both roles.

The development keys, derived from seeds `0x1` (state) and `0x2` (clearance),
are public and must never be pinned in a vault:

| Role | x | y |
| --- | --- | --- |
| state | `0x2b8cfd91b905cae31d41e7dedf4a927ee3bc429aad7e344d59d2810d82876c32` | `0x2aaa6c24a758209e90aced1f10277b762a7c1115dbc0e16ac276fc2c671a861f` |
| clearance | `0x1812b84c2101217b0939a2f542535075eeaa81d07dab701a899a55db26e85be4` | `0x0be80d0f61a801533a94a03b12683474f86ca012941db1c568c53dc877b16fd6` |

Compare keys as numbers (for example with `cast to-dec`): `/v1/attestation` and
`zkapi signing-keys` omit leading zeros, while `cast call` prints 32 bytes.

With the seeds in the environment, `zkapi signing-keys` prints only the public
keys, `{"clearance_signing_key":{"x","y"},"state_signing_key":{"x","y"}}`, for
the vault constructor. The vault's keys are immutable: new keys need a new
vault.

Before `zkapi serverd` opens its database for writes, it checks that
`--native-billing-rpc-url` serves `--chain-id` (the CLI default is 1, so Sepolia
must pass 11155111), reads the vault's `stateSigningKeyX/Y()`,
`clearanceSigningKeyX/Y()` and `challengePeriod()` at `latest`, and refuses to
start unless both derived keys equal the vault's. There is no override. An
unreachable RPC is retried for about 15 seconds of backoff, each call waiting up
to 15 seconds, before the process exits. The verified result is recorded in the
database's `deployment_binding` row. Later restarts with the same database,
chain, vault and seeds start without the RPC and re-verify in the background,
stopping only when the vault definitively contradicts the record. A database
bound to another chain or vault is refused, so each deployment needs its own
database, indexer checkpoint and challenge checkpoint. `zkapi-challenged`
requires the row and refuses a database bound elsewhere. The RPC must allow
`eth_chainId` and the `eth_call` selectors listed in
[the Docker guide](../docker/aws/README.md#signing-seeds). After startup, compare
`GET /v1/attestation` with the vault's getters; the log line
`server signing keys match the vault's immutable keys` confirms the check.

If a deployment ever ran with the development keys, or with keys different from
its vault's, treat it as compromised and follow
[the compromise procedure](migration-concession-vault.md#if-development-or-mismatched-keys-were-ever-served).

## Contracts

`demo/contracts/script/Deploy.s.sol` links (or deploys) the `Bn254Poseidon`
library, deploys the circuit's Groth16 adapter and the native-only vault with
its 11 constructor arguments, and checks the adapter's circuit and
verifying-key hashes against the setup manifest and the vault's getters
against the inputs. Its header lists the environment it reads, and
`demo/contracts/foundry.toml` notes how to run it with `forge script`. The
script links the library itself; no `FOUNDRY_REMAPPINGS` override is needed.

| Variable | Meaning |
| --- | --- |
| `PRIVATE_KEY` | Pays for the deployment |
| `OWNER` | Vault owner; required except on local chains (31337, 1337), where it defaults to the deployer. Use a multisig or timelock; the script warns on Mainnet when it has no code |
| `TREASURY` | Payout address of spent balances and expired deposits; required off local chains |
| `OUTPUT_PATH` | Absolute path of the final deployment manifest; the script writes `$OUTPUT_PATH.pending` |
| `STATE_SIGNING_KEY_X/Y`, `CLEARANCE_SIGNING_KEY_X/Y` | The public keys `zkapi signing-keys` prints; points of Baby-JubJub's prime-order subgroup, distinct, and off local chains not the published development keys |
| `CHALLENGE_PERIOD_SECONDS` | Escape window; default 24 hours. Immutable; it bounds the challenger's whole response time. Plan 172,800 on Mainnet and 43,200 on Sepolia |
| `NOTE_TTL_SECONDS` | Note lifetime; default 30 days |
| `MAX_PAUSE_DURATION_SECONDS` | Longest a pause blocks escapes and closes; at least twice the challenge period. Required except on local chains (default 7 days). Plan 3,888,000 (45 days) on Mainnet |
| `REQUEST_CHARGE_CAP` | Per-request gwei limit; the script default is 1,000,000, the published deployments use 50,000, so pass it explicitly |
| `SETUP_MANIFEST` | The setup's `manifest.json`; the adapter's hashes must match it. Required except on local chains (default `protocol/setup/v2-concession-dev`) |
| `ALLOW_DEV_SETUP` | `1` deploys a `dev` or `rehearsal` setup off local chains: the Sepolia drill vault only, never Mainnet, which refuses it. Recorded as `allowDevSetup`; default 0 |
| `POSEIDON_ADDRESS` | An already deployed `Bn254Poseidon` to link; its runtime code hash must equal the compiled library's. Unset deploys a fresh library |
| `CHAIN_ID` | Optional expected chain ID; a mismatch aborts |

The setup policy is enforced by the script: off local chains a single-party
setup needs `ALLOW_DEV_SETUP=1` and Mainnet refuses it, and an `mpc-1` setup
must have the verifying keys of the committed
`protocol/setup/v2-concession/manifest.json`, which the ceremony commits with
its keys. Local chains accept any setup id.

```sh
cd demo/contracts
mkdir -p ../../.demo
OUTPUT_PATH="$PWD/../../.demo/deployment.json" \
  forge script script/Deploy.s.sol --rpc-url "$RPC_URL" --broadcast   # plus the variables above
cd ../..
node scripts/expected-codehashes.mjs --deployment .demo/deployment.json.pending \
  --rpc "$RPC_URL" --finalize .demo/deployment.json --confirmations 64
```

The script runs locally before it sends anything, so `$OUTPUT_PATH.pending`
describes the simulated deployment: `deploymentStatus` `"pending"` (or
`"simulated"` without `--broadcast`), the linked addresses, the three runtime
code hashes and `deployBlockLowerBound`, the chain head the simulation ran on,
which is not the vault's creation block. The deployment is final only after
`expected-codehashes.mjs --finalize`, run from the repository root after
`--broadcast`: it reads the creation receipts from forge's broadcast log
(`demo/contracts/broadcast/Deploy.s.sol/<chain>/run-latest.json`, or
`--broadcast-log FILE`), requires each creation to have succeeded at the
manifest's address, the runtime code hashes on chain to be the expected ones,
and the vault's owner and treasury to be the manifest's, and only then writes
`$OUTPUT_PATH` with `deploymentStatus: "deployed"`, `deployBlock` (the block
that created the vault) and `deployTransactions`. A mismatch exits 1 and any
other failure 2, and neither writes the output. Finalize after finality, for
example `--confirmations 64` on Sepolia and Mainnet (the default is 1), and
keep the broadcast log until then. Re-audit a deployment later with
`node scripts/expected-codehashes.mjs --deployment .demo/deployment.json --check --rpc "$RPC_URL"`,
which compares the code hashes only.

Every profile, the server stack's `deployment.json`, the SDK and clientd
profiles, takes its pins and `deploy_block` from the finalized manifest only,
never from `.pending` or `deployBlockLowerBound`; serverd, `zkapi db init`, the
companion, the SDK build and clientd refuse a `pending` or `simulated` status.
The profile is the snake_case `trusted_deployment` form of those fields; the
[migration runbook](migration-concession-vault.md#b2-production-sepolia), step
5, maps them.

The owner controls an emergency pause and the treasury address. Use a multisig,
ideally behind a timelock, never a single deployer key:

- `pause()` stops `deposit`, `claimExpired`, `setTreasury`, `acceptTreasury`,
  `withdrawTreasuryArrears` and `renounceOwnership` until `unpause()`, and
  `mutualClose` and `initiateEscapeWithdrawal` for at most
  `maxPauseDuration()`: from `pausedAt() + maxPauseDuration()` they reopen
  while the vault is still paused. `challengeEscapeWithdrawal`,
  `raiseEscapeConcession`, `finalizeEscapeWithdrawal`, `claimEscapePayout`
  and `retireClosedLeaf` stay open, so escapes in flight still resolve and
  credited escape payouts can be delivered, and `cancelTreasuryChange`,
  `transferOwnership` and `acceptOwnership` stay open. A new pause needs
  `PAUSE_COOLDOWN()` (one day) since the latest unpause (`PauseCooldown()`).
  The NatSpec of `pause()` in `ZkApiVault.sol` lists these sets. `pause()` and
  `unpause()` emit `Paused(address)` and `Unpaused(address)` and revert when
  redundant.
- Ownership transfers are two-step. `transferOwnership(address)` only sets
  `pendingOwner()` (event `OwnershipTransferStarted(previousOwner, newOwner)`).
  The new owner, for example the multisig, must then call `acceptOwnership()`
  from that address (event `OwnershipTransferred`). Until it does, `owner()` is
  unchanged and the old key keeps every power: it can re-nominate, or cancel
  with `transferOwnership(address(0))`. When rotating away from a key that may
  be compromised, never send the nomination alone through the public mempool:
  whoever holds the old key can re-nominate before the acceptance and then
  accept from its own address. Submit the nomination and the new owner's
  `acceptOwnership()` together as one private bundle, so that they land
  consecutively in the same block; for a Safe, pre-sign its `execTransaction`
  calling `acceptOwnership()` so that the bundle can carry it. After any
  transfer, check that `owner()` is the new owner and `pendingOwner()` is zero,
  and alert on any `OwnershipTransferStarted` you did not send. The `OWNER`
  passed to `Deploy.s.sol` takes effect at deployment without an acceptance
  step, so verify it before deploying. See
  [the owner key rotation runbook](migration-concession-vault.md#owner-key-rotation).
- Paused time extends every note's claim time, and after any unpause
  `claimExpired` waits at least `unpauseClaimGrace()`, the larger of
  `challengePeriod()` and one day. `effectiveExpiry(noteId)` returns the
  earliest claim time assuming no further pause; `notes(noteId)` keeps the
  nominal expiry. Inference ends at the nominal expiry regardless.
- `setTreasury(address)` only schedules a change (`TreasuryChangeScheduled`).
  `acceptTreasury()` applies it (`TreasurySet`) after `treasuryChangeDelay()`,
  the larger of `challengePeriod()` and two days, counted in unpaused time;
  `pendingTreasuryReadyAt()` is on that same clock. `cancelTreasuryChange()`
  works at any time. A treasury that rejects a payout cannot block exits: its
  share accrues to `treasuryArrears()`. Likewise an escape destination that
  rejects its payout, or needs more than 100,000 gas to receive it, cannot
  block the escape: the amount is credited to `escapePayoutCredits(destination)`
  with an `EscapePayoutDeferred` event, and anyone can deliver it with
  `claimEscapePayout(destination)`, also while paused. Alert on
  `EscapePayoutDeferred` and follow the
  [escape payout credit runbook](migration-concession-vault.md#escape-payout-credits).
  A mutual close to a destination that rejects ETH reverts, and withdrawals to
  the zero address or the vault itself revert `InvalidDestination()`.

Withdrawal proofs may use any root the vault ever held (`knownRoots`); no
withdrawal needs Merkle siblings, and an unknown root reverts `UnknownRoot()`.
An escape consumes its nullifier and its successor's; a request proof at the
successor defeats it and marks the escaped nullifier in
`challengedNullifiers`, and a request proof at the escaped nullifier raises
its concession. The legacy vaults have none of these rules; see
[owner and operator powers](../docs-site/content/docs/protocol.mdx#owner-and-operator-powers)
and the migration runbook.

Use a fresh directory when intentionally generating a new Groth16 setup.
Keep challenger coverage and persistent server/indexer state available whenever
the vault holds funds.

## Runtime

The [Docker guide](../docker/aws/README.md) configures API, indexer, gateway,
challenger and a restricted private signer. Start them in this order: the
indexer, `zkapi db init` (which creates the database with its append-only
request evidence and binds it to the deployment manifest), the challenger,
then the API server; the challenger must be healthy before the first deposit.
The challenger needs a funded exclusive account, EIP-1559 fee caps whose bids
fit the transaction fee cap of the node behind its signer
(`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`, default 1 ETH, which allows about 1,666 gwei
for a 600,000-gas defeat and about 138.9 gwei for a leaf retirement), and the
API server's database: it defeats and raises with the request evidence the
server records. Keep the API running for every challenge window; see
[challenge operation](challenge-service.md).

Every lease settles by a write-once deadline: issuance + TTL + grace +
`--openrouter-settlement-deadline-seconds` (default 21600), at worst at the
proof's solvency bound. The server refuses to start unless TTL + grace +
deadline + twice the settlement poll + 600 seconds is at most half the vault's
`challengePeriod()`, and unless TTL + grace + deadline is at most the
manifest's `settlement_window_seconds`; the challenger also checks that its
raise lead fits the challenge period. See
[settlement terminality](native-eth-billing.md#settlement-terminality).

The indexer (`zkapi-indexerd` or `zkapi indexer`) needs an RPC with EIP-1898
`eth_call` by block hash, `eth_getBlockByHash`, and state for its confirmation
depth (`--confirmations`, default 12), plus an NTP-synchronized clock
(`--max-head-age-secs`, default 180; 0 disables it for chains that mine on
demand). Use a provider other than the `rpc_url` that client manifests pin:
`zkapi-clientd` corroborates deposits and withdrawals against this indexer's
tree, and that check is only as independent as the indexer's RPC. That pinned
`rpc_url` must itself serve `eth_getBlockByHash` for recent blocks, which
`zkapi-clientd` uses to date its deposit search on chain time, and `eth_call`
for the vault's `currentRoot()`, which it reads before setting a request
aside. Pass
`--chain-id`. It serves only a view verified against the vault and
answers 503 otherwise; `--resync`, or a `<cursor>.resync` file before a restart,
rebuilds it from `--from-block`. The reference gateway limits POST requests per
source; see [request limits](../docker/aws/README.md#request-limits).

For a local chain, `npm run test:e2e:v2` runs the complete stack and the
drill scenarios on Anvil ([acceptance](v2-acceptance.md)). It runs Anvil with
Sepolia's chain ID, the only chain besides mainnet the signer sidecar signs
for. It then:

1. generates random seeds and derives the keys with `zkapi signing-keys`;
2. deploys with `Deploy.s.sol` (`ALLOW_DEV_SETUP=1`, as for the drill vault);
3. finalizes the manifest with `expected-codehashes.mjs --finalize`, and builds
   the `trusted_deployment` profile from it;
4. starts the daemons in order: the indexer
   (`--from-block deployBlock --max-head-age-secs 0`), `zkapi db init`, the
   signer sidecar, `zkapi-challenged` (`--deployment`,
   `--settlement-window-seconds`), then serverd (`--deployment`).

Its native billing RPC is a loopback mock price feed that forwards every other
read to Anvil. Use [`scripts/v2-acceptance.mjs`](../scripts/v2-acceptance.mjs)
as the reference for a local deployment. CI's contracts job also broadcasts the
demo deployment to Anvil and finalizes its manifest.

The host application packages the SDK assets for the selected network. Review
its trusted config against the finalized deployment manifest, on-chain state,
the published expected code hashes and the selected proof hashes before
enabling funding. Until a revision-3 vault exists on a network, its packaged
profile is a `not_deployed` placeholder that the SDK build refuses.
