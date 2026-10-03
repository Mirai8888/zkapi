# Local v2 lifecycle acceptance

This process tests the current native ETH protocol from a real deposit through
provider usage, signed settlement, a challenged stale escape, and a successful
real-proof withdrawal. It also checks the server's signing-key binding to the
vault, an indexer rebuild after a reorganization, and ownership-proof
clearance. A separate regression verifies that a failed issuance cannot create
access from the saved request after its note begins or completes an escape
withdrawal. The provider and price oracle are local mocks. Everything runs on
loopback with disposable Anvil accounts; no hosted server, provider credential,
public RPC, or testnet funds are required.

## Run

Install Node 24+, Rust, and Foundry (`forge` and `anvil` in PATH), then run from
the repository root:

```sh
npm run test:e2e:v2
```

The wrapper first runs the harness's own unit tests (provider mock accounting,
loopback-only transport, challenge transaction shape and JSON-RPC error relay),
installs the locked ethers dependency, rebuilds the actual server, indexer, challenger and wallet helper,
builds the Solidity contracts, and runs the scenario.
Dependency installation/builds may contact package registries;
the acceptance scenario itself uses only loopback endpoints. It uses the
checked-in proving keys and does not generate or replace a setup.
CI runs the same wrapper in the `lifecycle-acceptance` job.

Each run saves a private timestamped directory under `.zkapi/acceptance/` with
its JSON result, transaction receipts, service logs and server database. The
result records the source commit, whether the working tree has changes, a hash
of the tracked diff against that commit, and the tested binary/artifact hashes.
Override the parent directory with
`npm run test:e2e:v2 -- --output-dir /path/to/results`.
The runner shuts down its own child processes and listeners on success or
failure. Wallet data and service state are confined to the run's private directory.

Each run generates fresh 31-byte operator signing seeds. They exist only in the
runner's memory and in the environment of `zkapi signing-keys` and
`zkapi serverd`; the run fails if any file in its directory contains one.

On macOS the wrapper respects explicit `DEVELOPER_DIR` and `SDKROOT` values.
Otherwise, it uses installed standalone Command Line Tools and the macOS 15.4
SDK when available. It does not accept an Xcode license or change system settings.

For iteration after building, run the harness directly:

```sh
node scripts/v2-acceptance.mjs --bin-dir target/release
```

Use the wrapper for a review or release check so the binaries and contracts are
rebuilt from the current source. A successful exit and the run's JSON result are
the acceptance evidence; simply having this script does not establish a pass.

## Scenario

1. Derive the run's state and clearance keys with `zkapi signing-keys` (which
   also refuses the published development seeds), and deploy the actual
   Poseidon library, Groth16 verifier and native vault with those keys on a
   fresh local chain. Start the actual indexer with 2 confirmations and the
   head-age check disabled, because Anvil mines only on demand.
2. Deposit native ETH and initialize a genesis wallet state from the contract's
   note ID, amount and expiry. No earlier signed balance is manufactured.
3. Start the actual HTTP API server three times with seeds it must refuse: the
   published development seeds, fresh seeds the vault does not pin, and no
   seeds. Each start exits non-zero and creates no database. Then start it with
   the run's seeds. It reads the vault's four key getters and
   `challengePeriod()` over its native-billing RPC, logs the key match, and
   serves `/v1/attestation` keys equal to the vault getters.
4. Generate a real request proof, obtain a lease through the HTTP API, and send
   an inference request directly to the local provider mock using its issued key.
5. Retire the lease through HTTP. The server reads the mock's measured usage,
   settles the charge (`charge_basis` `measured`) and signs the new state. The
   wallet verifies and applies that response using the production
   browser-wallet implementation.
6. Repeat the request/usage/settlement flow, retaining the genuine earlier signed
   state. An unrelated deposit changes the tree root.
7. Submit a real escape proof using that earlier, consumed state. Start the
   actual challenger while its indexer requests receive the indexer's own
   `503 indexer_unavailable` response from a loopback gate. The challenger finds
   the escape and the server's finalized evidence, and its `/status` reports the
   obligation blocked with `indexer_unavailable`; nothing is sent.
8. Deposit a throwaway note, let the indexer commit it at its confirmation
   depth, and remove it with `anvil_reorg` three blocks deep, below the indexer
   checkpoint. The escape survives. The indexer detects the reorganized
   checkpoint, rebuilds from the deployment block, returns to `ok` and converges
   on the vault root.
9. Pause Anvil's automatic mining and open the gate. The challenger reads the
   current path from the rebuilt indexer and sends its own challenge. Every
   send carries exactly `from`, `to`, `data`, `gas`, `nonce`, `maxFeePerGas`
   and `maxPriorityFeePerGas`, with the tip at most the max fee and the max fee
   at most the 100 gwei cap; the RPC proxy relays upstream JSON-RPC errors with
   their original code, message and data. A 20 gwei base-fee block then prices
   out the pending first bid, which Anvil drops from its pool. The challenger
   bids again on the same nonce with the same calldata, a tip no lower and a
   max fee covering the new base fee; that bid mines before the deadline and
   the first never does. After the challenge, `usedNullifiers` is false,
   `challengedNullifiers` is true, and replaying the stale escape with fresh
   siblings reverts `ChallengedNullifier()`. Once the challenge is two blocks
   deep, the challenger's `/livez` and `/health` answer 200 and `/status` lists
   no obligations and no critical status.
10. Request clearance for the current state without an ownership proof and
    require `400 clearance_ownership_required` with nothing reserved. Request it
    again with an escape-form ownership proof of the same state to the real
    destination and require `clearance_reserved`. Submit the real
    mutual-withdrawal proof and check the remaining-balance payout and treasury
    charge.
11. Deposit a separate fresh note and prepare a real genesis escape proof and
    request proof. Make the provider fail one key creation after the request has
    been reserved. Confirm the reservation remains and no key was created.
12. Start that note's escape, then retry the exact saved issuance request. Require
    `nullifier_used` and no new provider creation attempt. Advance only the local
    chain clock past the challenge deadline and finalize the full refund. Retry
    the same saved request again and require the same rejection, with no key.
13. Stop the server. Refuse a start of its database for another contract
    address. Restart it while its native-billing RPC answers every call with an
    error: it starts from the recorded deployment binding, serves the vault
    keys, and re-verifies the binding in the background once the RPC returns.

The vault keeps its 86,400-second challenge period. The challenged stale
withdrawal in steps 7-9 runs before its deadline without a time jump. The
separate failed-issuance regression advances the disposable Anvil clock by
86,401 seconds to test the state after a completed refund. Neither scenario
requires a real one-day wait or changes the configured challenge period. The
result records these timing conditions separately.

The server settles a never-delivered lease at zero once its TTL and settlement
grace pass on the wall clock (301 seconds here). The failed-issuance checks run
within seconds of the failed key creation, so they observe the reserved lease
before that settlement; the result records the elapsed wall time.

## Coverage boundary

| Component | Execution |
| --- | --- |
| Deposit, escape, challenge and mutual withdrawal | Actual native vault and Groth16 verifier on Anvil |
| Wallet state, proofs and settlement verification | Actual `zkapi-browser` Rust operations behind a small in-memory JSONL driver |
| Signing-key binding | Actual `zkapi signing-keys` and server startup checks against the deployed vault |
| Lease issuance, retirement, recovery and clearance | Actual HTTP API server and SQLite database; failed issuance remains reserved but cannot retry against an on-chain spent nullifier |
| Tree paths and reorganization recovery | Actual indexer at 2 confirmations; one reorganization below its checkpoint on Anvil |
| Challenge submission | Actual challenger process; its indexer access passes through a loopback gate that withholds the indexer first |
| Inference and key management | Local provider mock; usage accrues when an inference call is accepted |
| ETH/USD quote | Local oracle mock; chain, vault key, challenge-period, root and nullifier reads are forwarded to the actual local chain |
| Transaction signing and chain confirmation | Local Anvil accounts and blocks; the challenger sends through Anvil's unlocked account, not the AWS signer sidecar |

The harness does not establish real provider behavior, browser/CLI host
persistence or UI correctness, the AWS signer configuration, replacement of a
bid that stays in a node's pool (nodes such as geth and reth keep a transaction
priced out by the base fee and accept a replacement only when both fees rise by
at least 10%; Anvil drops it), public-network finality/reorg behavior, or live
Sepolia acceptance. Those require their own integration runs. The indexer's
unit suite (`poller::reorg_tests`) covers further reorganization and
lagging-replica cases. The generated result must retain the mocked-provider
label.
