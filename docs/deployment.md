# Native ETH deployment

The source supports native ETH vaults and the note-bound Groth16 circuit
`zkapi-v2-note-bound-v1`. The current selected setup remains a single-party
experimental setup; publishing code does not establish an independent audit or
setup ceremony. See [setup provenance](../protocol/setup/v2/README.md).

Configure the exact circuit artifacts, contract and signing-key pins, oracle
feed, and denomination for the vault. Preserve persistent operator state and
keep wallet journals bound to their configuration. An existing deployment
upgrades to this release, and moves to a newly deployed vault, as described in
[the hardened-vault migration guide](migration-hardened-vault.md).

## Build services

```sh
cargo build --release --workspace
```

`zkapi serverd` requires `--native-billing-rpc-url` and
`--native-price-feed-address` (or corresponding `ZKAPI_NATIVE_*` variables), plus
an OA org/service credential or direct OpenRouter management credential.
Supply chain ID, vault, gwei request cap, both signing seeds (required; see
below), database path, indexer URL and the exact proof directory. Run
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
[the compromise procedure](migration-hardened-vault.md#if-development-or-mismatched-keys-were-ever-served).

## Contracts

`demo/contracts/script/Deploy.s.sol` deploys the real Groth16 adapter and a
native-only vault; its header lists the environment it reads, and
`demo/contracts/foundry.toml` notes how to run it with `forge script`. `PRIVATE_KEY`
pays for the deployment. `OWNER` is required except on local chains (31337 and
1337, where it defaults to the deployer), and the script prints a warning on
Mainnet when `OWNER` has no code. `TREASURY` is required off local chains. It
also reads `OUTPUT_PATH`, the state and clearance public-key coordinates
(`STATE_SIGNING_KEY_X/Y`, `CLEARANCE_SIGNING_KEY_X/Y`), optional `CHAIN_ID`
(checked against the connected chain), `REQUEST_CHARGE_CAP` and
`CHALLENGE_PERIOD_SECONDS`. Pass `REQUEST_CHARGE_CAP` explicitly: the script
default is 1,000,000 gwei, while the published deployments use 50,000.
`CHALLENGE_PERIOD_SECONDS` defaults to 24 hours and is immutable; it bounds the
challenger's whole response time, so consider a longer window. The deployment
output is constructor metadata, including `owner`, `treasuryChangeDelay` and
`rootHistoryWindow`; prepare the public SDK manifest with circuit/key hashes and
oracle/deployment pins separately. The vault accepts native ETH.

forge cannot link `Bn254Poseidon` through the relative remappings in the
committed `foundry.toml`, so pass a canonical absolute remapping when running
the script (CI simulates exactly this):

```sh
cd demo/contracts
mkdir -p ../../.demo
FOUNDRY_REMAPPINGS="zkapi-contracts/=$(cd ../../protocol/contracts/src && pwd -P)/" \
  OUTPUT_PATH="$PWD/../../.demo/deployment.json" \
  forge script script/Deploy.s.sol --rpc-url "$RPC_URL" --broadcast   # plus the variables above
```

The owner controls an emergency pause and the treasury address. Use a multisig,
ideally behind a timelock, never a single deployer key:

- `pause()` stops `deposit`, `mutualClose`, `initiateEscapeWithdrawal`,
  `claimExpired`, `setTreasury`, `acceptTreasury`, `withdrawTreasuryArrears`
  and `renounceOwnership`. `challengeEscapeWithdrawal`,
  `finalizeEscapeWithdrawal` and `claimEscapePayout` stay open, so disputes in
  flight still resolve and credited escape payouts can be delivered, and
  `cancelTreasuryChange`, `transferOwnership` and `acceptOwnership` stay open.
  The NatSpec of `pause()` in `ZkApiVault.sol` lists both sets, and
  `test_pauseGuardCoverage` checks that list against the vault's pause guards.
  `pause()` and `unpause()` emit `Paused(address)` and `Unpaused(address)` and
  revert when redundant.
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
  [the owner key rotation runbook](migration-hardened-vault.md#operations-runbooks).
- A pause has no time limit: the owner, or whoever controls its key, can stop
  every new exit indefinitely. It cannot move deposits. Paused time extends
  every note's claim time, and after any unpause `claimExpired` waits at least
  `unpauseClaimGrace()`, the larger of `challengePeriod()` and one day.
  `effectiveExpiry(noteId)` returns the earliest claim time assuming no further
  pause; `notes(noteId)` keeps the nominal expiry. Inference ends at the nominal
  expiry regardless.
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
  [escape payout credit runbook](migration-hardened-vault.md#operations-runbooks).
  A mutual close to a destination that rejects ETH reverts, and withdrawals to
  the zero address or the vault itself revert `InvalidDestination()`.

Withdrawal proofs may use the current root or one replaced within
`ROOT_HISTORY_WINDOW()` (one day), while their Merkle siblings must match the
current root; an older root reverts `UnknownRoot()`. A successful challenge
releases the escape's nullifier but marks it in `challengedNullifiers`, so no
escape can use it again. Vaults deployed before this release have none of these
protections; see
[owner and operator powers](../docs-site/content/docs/protocol.mdx#owner-and-operator-powers)
and the migration guide.

Use a fresh directory when intentionally generating a new Groth16 setup.
Keep challenger coverage and persistent server/indexer state available whenever
the vault holds funds.

## Runtime

The [Docker guide](../docker/aws/README.md) configures API, indexer, gateway,
challenger and a restricted private signer. The challenger needs a funded
exclusive account, EIP-1559 fee caps whose bids fit the transaction fee cap of
the node behind its signer (`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`, default 1 ETH,
which allows about 132 gwei for a challenge), and the API server: it challenges
only with finalized settlements, and owners recover their signed state from the
API after a challenge. Keep the API running for every challenge window; see
[challenge operation](challenge-service.md).

Every lease settles by a write-once deadline: issuance + TTL + grace +
`--openrouter-settlement-deadline-seconds` (default 21600), at worst at the
proof's solvency bound. The server refuses to start unless TTL + grace +
deadline + twice the settlement poll + 600 seconds is at most half the vault's
`challengePeriod()`. See
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

For a local chain, `npm run test:e2e:v2` runs the complete lifecycle on anvil
(chain 31337): it generates random seeds, derives the keys with
`zkapi signing-keys`, deploys the vault with them, and starts the indexer with
`--chain-id 31337 --max-head-age-secs 0`, the server with `--chain-id 31337`,
and the challenger. Its native billing RPC is a loopback mock price feed that
forwards chain ID and vault reads to anvil. Use
[`scripts/v2-acceptance.mjs`](../scripts/v2-acceptance.mjs) as the reference for
a local deployment.

The host application packages the SDK assets for the selected network. Review
its trusted config against finalized on-chain deployment state, the public
manifest and the selected proof hashes before enabling funding.
