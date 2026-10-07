# Local concession-exit acceptance

This process tests circuit `zkapi-v2-concession-v1` (vault revision 3) end to
end on a disposable Anvil chain, runs every scenario of the Sepolia drill
(design §10.7 Phase B) and the mainnet smoke tests of Phase C, and measures
gas.

Real components:

- the contracts, deployed by `demo/contracts/script/Deploy.s.sol` and
  finalized on chain by `scripts/expected-codehashes.mjs --finalize`;
- Groth16 proofs with the dev setup (`protocol/setup/v2-concession-dev`);
- `zkapi serverd`, as the drill build with `--adversary`;
- `zkapi db init`, `zkapi-indexerd` and `zkapi-challenged`;
- the challenge signer sidecar (`docker/aws/signer`);
- three clients:
  - the browser SDK (`sdk/`: `zkapiClient` and `browserWalletRuntime`, with
    the shipped WebAssembly running in Node);
  - the clientd companion (`zkapi-walletd`);
  - the browser wallet core run natively behind a small driver
    (`crates/zkapi-serverd/examples/v2_acceptance_wallet.rs`).

Mocked, all on loopback: the inference provider and its key management API,
the OA org that issues station keys with its verifier, and the ETH/USD price
feed. No hosted service, provider credential, public RPC or testnet funds are
needed.

## Run

Install Node 24+, Rust and Foundry (`forge` and `anvil` on PATH), then run from
the repository root:

```sh
npm run test:e2e:v2
```

The wrapper (`scripts/run-v2-acceptance.sh`) does the following:

1. Runs the harness's own unit tests (`scripts/v2-acceptance.test.mjs`).
2. Installs the signer sidecar's locked dependencies.
3. Builds the drill binaries into `target/acceptance/`, so they never replace a
   release build. These are `zkapi` with `--features zkapi-cli/adversary`, and
   `zkapi-challenged`, `zkapi-indexerd`, `zkapi-walletd` and the wallet driver
   with `zkapi-proof/dev-setup` (release builds refuse the dev setup).
4. Builds both Forge projects.
5. Runs `scripts/v2-acceptance.mjs`.

It takes about fifteen minutes after the builds. CI runs the same wrapper in the
`lifecycle-acceptance` job. Dependency installation and the builds may
contact package registries; the scenarios use only loopback endpoints.

Each run saves a private, timestamped directory under `.zkapi/acceptance/`. It
holds:

- `result.json`: the outcome, the source commit, whether the tree is dirty, a
  hash of the tracked diff, and the hashes of the tested binaries, keys and
  WebAssembly;
- `scenarios.json`: each scenario's PASS or FAIL with its evidence;
- `gas.json`;
- the deployment manifests, every service log and the server database.

Override the parent directory with
`npm run test:e2e:v2 -- --output-dir /path/to/results`. After a build, iterate
with:

```sh
node scripts/v2-acceptance.mjs --bin-dir target/acceptance/release [--stop-after STEP]
```

`--help` lists the steps. A successful exit and the run's JSON are the
acceptance evidence.

Each run generates fresh operator signing seeds. They reach only the
environment of `zkapi signing-keys` and `zkapi serverd`, and the run fails if
any saved file contains one.

## Chain and time

Anvil runs with Sepolia's chain ID, 11155111, because the signer sidecar signs
only for mainnet or Sepolia. `Deploy.s.sol` therefore treats it as a public
chain. It requires `OWNER`, `TREASURY`, `SETUP_MANIFEST`,
`MAX_PAUSE_DURATION_SECONDS` and `ALLOW_DEV_SETUP=1`, and it records
`allowDevSetup: true`, exactly as for the Sepolia drill vault.

`--slots-in-an-epoch 1` makes the `finalized` tag two blocks deep, and a
block is mined every second.

The drill parameters are scaled down so that a challenge period can be skipped
with `evm_increaseTime`. Both daemons' startup checks hold for them
(`drillTiming`):

| Parameter | Value |
| --- | --- |
| `challengePeriod` | 3,600 s |
| `maxPauseDuration` | 7,200 s |
| `noteTtl` | 30 days |
| Lease TTL + grace + settlement deadline (`W`) | 60 + 1 + 901 = 962 s |
| `--raise-lead-seconds` | 1,200 s |
| Request bound (`request_charge_cap`) | 50,000 gwei |
| Deposit | 1,000,000 gwei |
| One inference | 400 gwei |

A time skip moves only block time. The daemons and clients keep the wall
clock, and clients bound exit proofs by it (valid for 3 hours). The chain
therefore starts two challenge periods behind the wall clock, so that block
time meets it when the bounded pause ends. That is just before the
missed-defeat drill: the challenger counts a miss only for evidence written
(wall clock) before the escape's deadline (block time).

From then on block time runs at most one period ahead, and two at the end. An
SDK that must judge a chain deadline (to finalize) gets its device clock moved
to block time. The SDK whose operator withholds gets its clock moved to the
settlement time `T` it reports. In the late-successor drill, the last before
the expiry sweep, the SDK's device clock is set so that its released escape
proof lives 600 s of block time; then block time and the device clock both
move past that proof's `valid_until + 900`. The run records every skip.

## Scenarios

The daemons start in the production order: indexer, `zkapi db init`, signer,
challenger, serverd. The challenger and its signer are healthy before the
first deposit.

Before the scenarios, serverd must refuse to start with:

- the published development seeds;
- seeds whose keys the vault does not pin;
- no seeds;
- a profile that pins another vault codehash.

| # | Scenario (design §10.7 Phase B) | Client | What is asserted |
| --- | --- | --- | --- |
| 1 | Honest flow | wallet core | Two requests settle at the measured charge and install (S1–S6). A kind-2 ownership proof reverts `WrongWithdrawalKind` as an escape or a close. The clearance reserves the nullifier. The close proves at the deposit-time root (A1). Payout `D − 800`, treasury 800, the wallet's balance equals the payout. |
| 2 | Stale exit after spending, defeat, `SupersededState`, re-escape from an older state, defeat | wallet core | The operator serves the evidence at `S2⁺` and it verifies. The escape from `S2` is defeated through the signer with the request at `N3`. `S1` reverts `SupersededState`. `S0` is recorded and defeated with the request at `N1`. `S2` again reverts `ChallengedNullifier`. Defeats move no funds, and the newest state closes. |
| 3 | Codehash-mismatch profile refuses deposits | SDK | `deposit` fails `deployment_mismatch` on `vault_runtime_codehash`, read through the wallet and the pinned RPC. Nothing is signed. |
| 4 | Indexer down, exit with the deposit-time path | SDK | Deposit (deployment checks pass), request, settle. Another deposit moves the root, the indexer stops, and the SDK escapes (`E2.escape`, `c = 0`, path source `deposit`) at the note's deposit root, not the current one. The indexer restarts from its checkpoint. |
| 5 | Honest close (the Phase C smoke test) | SDK | Deposit, request, settle, then `withdraw('mutual')`: the SDK's own exit lock, ownership proof, clearance and close proof. `MutualClose` pays `D − 400` to the destination and 400 to the treasury, the clearance nullifier reads `usedNullifiers` and `clearance_reserved`, the record is `closed`, and the SDK holds no note and no exit lock. |
| 6 | Under-concession, raise, finalize, deferred credit, claim | wallet core | The escape concedes 100 while a request is in flight. The server settles 400, signs nothing (`exit_deferred`), and the challenger raises to 400. Finalization to a destination that needs more than 100,000 gas credits the payout (`EscapePayoutDeferred`); `claimEscapePayout`, sent by a third party, pays it. |
| 7 | Forced early exit with `c = 0`, raise to the real charge, client state closed | companion | Serverd switches to the OA org key source; the companion's OA bridge lease is verified. The operator is unreachable: `early_exit: concede_nothing` prepares `c = 0` from the deposit path (`path_source` `deposit`). The key lapses, the server settles 400, the challenger raises to 400. After finalization (9) the companion records `complete` (payout `D − 400`, `conceded_final` 400) and `has_note` is false. |
| 8 | Stale-device pre-check; honest close | companion | A copy of the companion's wallet taken at the genesis state is the stale device; the newest device spends the genesis state and its successor. A second `zkapi-walletd` on the copy refuses the escape with `device_not_newest` and holds no exit lock and no escape record: nothing left it. The newest device then closes through its mutual route (kind 2, clearance, kind 1); the close pays `D − 800`, and `/oa/v1/withdraw/confirm` records it. |
| 9 | Pause with an escape pending, then finalize | all three | Escapes 4, 6 and 7 are pending when the owner pauses. A new escape reverts `Paused`. Finalization, the deferred credit and the claim all run while paused. The SDK record is `closed` with `concededFinal` 0, the companion holds no note, and the wallet core holds the state it escaped. |
| 10 | Pause past `maxPauseDuration`, then escape; re-pause cooldown; replay of an abandoned proof after `valid_until` | wallet core | Past `pausedAt + maxPauseDuration` a fresh escape lands while still paused. A proof prepared earlier and abandoned now reverts `ProofExpired` for anyone. After `unpause`, `pause` reverts `PauseCooldown`. |
| 11–13 | Born-spent anchor 1, reused anchor, random anchor | wallet core | The drill server signs the bad successor. The wallet refuses it (S4, archived `invalid_successor`, state unchanged). In a scratch copy installed without the checks, the wallet core refuses to prove from it, and the request circuit synthesized for it is unsatisfied (Q6a; anchor 1 names the genesis nullifier). A successor refused for S4 is handled like a withheld one (E3): the owner exits before `T` conceding 0, and the challenger raises to the settled 400. The wallet core has no exit rules of its own, so the harness applies them; 15 has the SDK decide. |
| 14 | Overcharge | wallet core | The successor charges `bound + 1`; the wallet refuses it (S3). The response passes S1, S2, S4 and S6, so the escape concedes `min(charge, bound)`, the bound, at once (E3, lost ε), and no raise exceeds it. |
| 15 | Random anchor, through the SDK | SDK | The SDK archives the successor `invalid_successor`; its balance is unchanged. A mutual withdrawal waits (`request_settlement_pending`). The SDK's early escape decides `E3.forced` conceding 0, to a destination that needs more than 100,000 gas to receive; the challenger raises to 400. At finalization (21) the payout is credited and the SDK's own `claimEscapePayout` delivers it. |
| 16 | Lying `expired_unaccepted` | SDK | The operator reserves the lease, keeps and spends the key, and answers `native_quote_expired`; `/expire` lies. The SDK archives `discarded_expired_unaccepted`. The mutual close's clearance reveals the reservation, so the SDK waits (`request_settlement_pending`). The forced escape concedes 0, the server settles 400 (`exit_deferred`), and the challenger raises to 400. |
| 17 | Withholding, then concession at `T` | SDK | The server settles and never signs. The state's bound is the SDK request's, 400,000 gwei (its $1 limit at the mock price). Before `T` a withdrawal waits. At `T` (device clock) it decides `E3.T` and concedes exactly that bound. The challenger finds the concession covers the settled 400 and sends nothing; there is no defeat. Payout `B − b`. |
| 18 | Indexer down, then rebuild from logs | SDK | The SDK loses its deposit-time path, a later deposit moves the root, and the indexer stops. The escape (`E2.escape`, path source `rebuild`) proves at the current root, rebuilt from the vault's logs through the wallet provider. |
| 19 | `hang` | SDK | After a served request, serverd restarts with `--adversary hang`, behind a gateway that relays without timeouts. The SDK's escape (`E3.forced`, `c = 0`) lands within its exit budget (each operator call 20 s, each recovery pass 120 s) and before `must_initiate_by`. The operator comes back, settles 400, and the challenger raises to it. |
| 20 | Missed defeat (challenger stopped), then `retireClosedLeaf` | wallet core | With the challenger stopped, an escape from the genesis state, whose successor's request is in the evidence, finalizes. The restarted challenger counts the miss for that note (`last_missed.note_id`, `kind` defeat), logs `MISSED escape deadline` for it, and retires the leaf through the signer (`ClosedLeafRetired`, new root, retirement budget 1). The note's leaf is gone from the current root. |
| 21 | Finalize every pending escape | all | Each payout is `B − c_final`, each treasury share `D − payout`. Escapes 17–20 were never defeated. Each SDK record is `closed` with `concededFinal = B − payout` and no payout alert; the SDK claims its credited payout (15). Each wallet core escape is the one it proved: the finalized nullifier is the wallet's, from the state it holds (from its `S0` snapshot for 20). |
| 22 | Late successor, then switch | SDK | The operator's successor reaches the SDK only after it released an escape proof (`E3.forced`, `c = 0`), which the owner rejects in the wallet: nothing is broadcast. The successor is archived `late_successor` and does not install, and a cancel keeps the lock while the proof can land. Once block time and the device clock pass `valid_until + 900`, E6 releases the lock and installs the successor (bound reset), and the owner closes from that newer state: `MutualClose` pays `D − 400`, and no escape of the note ever lands. |
| 23 | Expiry sweep; pause after the cooldown | — | `claimExpired` after `effectiveExpiry` pays the treasury `D`. `pause` succeeds after `PAUSE_COOLDOWN`. At the end the vault holds nothing and owes no treasury arrears. |

Each client escaped at least once: the SDK (4, 15–19), the companion (7) and
the wallet core (2, 6, 10–14, 20). The SDK (5, 22), the companion (8) and the
wallet core (1, 2) each closed cooperatively.

`gas.json` holds every transaction's `gasUsed` by operation:

- deposit, escape, defeat and raise;
- mutual close, finalize (paid or deferred) and `claimEscapePayout`;
- `retireClosedLeaf`, `claimExpired`, pause and unpause;
- the reverted `SupersededState`, `ProofExpired` and ownership-proof calls.

It also carries the committed Forge snapshot (`protocol/contracts/snapshots/concession-exit-gas.json`) for comparison.

## Coverage boundary

| Component | Execution |
| --- | --- |
| Vault, adapter, Poseidon library | Actual contracts from `Deploy.s.sol` on Anvil, finalized and codehash-checked |
| Proofs | Actual Groth16 proofs of the single-party dev setup (drill vault only; not the ceremony keys) |
| Server | Actual `zkapi serverd` drill build: honest, `withhold`, `born-spent`, `reuse-anchor`, `random-anchor`, `overcharge` and `lie-expired`, restarted between modes behind one loopback endpoint |
| Indexer | Actual `zkapi-indexerd`, stopped and restarted from its checkpoint |
| Challenger and signer | Actual `zkapi-challenged` and signer sidecar: defeats, raises and retire-on-miss, EIP-1559 fees within the caps |
| SDK | Actual `sdk/` code and WebAssembly in Node. A browser's IndexedDB, Web Worker, window and wallet extension are substituted (in-memory store, in-thread worker, an EIP-1193 wallet over an Anvil account) |
| Companion | Actual `zkapi-walletd` routes as `zkapi-clientd` calls them; the harness plays clientd and signs its transactions |
| Provider, OA org, price feed | Loopback mocks |

The run does not establish:

- the ceremony setup;
- the Go clientd's signing path and UI (its own test suite covers them);
- a real browser's storage, locks and tabs;
- reorganizations (the indexer's `poller::reorg_tests`);
- a pending bid replaced in a node's pool;
- public-network finality and real operator and RPC latency;
- live Sepolia.

The wallet core has no exit rules (E0–E7): where it escapes, the harness
applies them, and the SDK or companion scenario of the same drill shows the
client deciding. The companion's endpoints are on loopback; the run shows that
every one of its connections passed its authenticated proxy (the operator,
indexer and RPC entrances answer only relayed requests), not that a remote
endpoint is reached only that way.

Those need their own runs, and the result keeps the mocked-provider label.
