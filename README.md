# zkAPI

zkAPI lets you pay for AI and other APIs with ETH and make unlinkable requests.
It keeps API usage separate from your on-chain deposit: the service can verify
that you can pay without learning which deposit is yours.

Built by Open Anonymity in collaboration with the Ethereum Foundation, zkAPI
uses zero-knowledge proofs to make this possible. Deposit ETH, pay only for what
you use, and withdraw your remaining balance on-chain.

Live web app: [**chat.openanonymity.ai**](https://chat.openanonymity.ai/) —
try zkAPI in OA Chat by choosing the Ethereum wallet option.

Documentation: [**zkapi.openanonymity.ai**](https://zkapi.openanonymity.ai/).

The protocol is experimental; see
[the note-binding review](docs/note-bound-commitments.md) and
[the concession exit design](docs/design/concession-exit.md), which lets a
user withdraw without any cooperation from the operator.

## Local OpenAI-compatible API

Use [zkapi-clientd](zkapi-clientd/README.md) to configure an ETH wallet and serve
inference to Open WebUI or another local OpenAI-compatible client.

## Build and test

```sh
npm ci
npm test
npm run verify:assets
npm run verify:builds   # the placeholder profiles must refuse to build
cargo build --release --workspace
cargo test --release --workspace
cargo test --release --manifest-path protocol/rust/Cargo.toml --workspace
(cd protocol/contracts && forge test)
```

The protocol and required Solidity libraries are ordinary files in this repository.
No submodule initialization, Cairo compiler or STARK prover is needed. See
[source provenance](protocol/VENDORED.md).

## Browser SDK

`@openanonymity/zkapi-browser-sdk` owns native ETH funding, wallet persistence,
proof generation, lease recovery, settlement and withdrawals. Mainnet and Sepolia
have independent deployment pins, signing keys and wallet state. Applications
configure the SDK before initializing a wallet; see [SDK integration](sdk/README.md)
and [native billing](docs/native-eth-billing.md).

The packaged WASM and proving keys support the current circuit
`zkapi-v2-concession-v1` (vault revision 3), with the development setup until
the multi-party ceremony has run. Until a revision-3 vault is deployed, the
packaged network profiles are placeholders and `npm run build:browser` and
`npm run build:mainnet` refuse them by design (`deployment_not_deployed`);
`npm run verify:builds` checks exactly that. Notes of the earlier circuit
`zkapi-v2-note-bound-v1` are served by the release line
`release/v2-note-bound`. Ordinary SDK consumers do not need Rust. To rebuild
WASM deliberately, use `scripts/build-browser-client.sh` and review the changed
artifact hashes; `npm run verify:wasm` rebuilds it reproducibly and compares.

## Full local lifecycle acceptance

Run `npm run test:e2e:v2` to build and run the lifecycle acceptance on a fresh
local chain: real protocol services, wallet proofs and contracts, with a
mocked provider and oracle. See the
[acceptance process and coverage limits](docs/v2-acceptance.md).
`node scripts/check-withdrawal-golden.mjs` submits the Rust, JS and Go
withdrawal encoders' calldata to an Anvil vault.

## Operator services

- `zkapi serverd`: native ETH lease authorization, settlement and Schnorr signing.
- `zkapi-indexerd` / `zkapi indexer`: vault event indexing and Merkle paths
  from a view verified against the vault.
- `zkapi db init`: create the server database with its append-only request
  evidence and bind it to the deployment manifest, before any daemon starts.
- `zkapi-challenged`: durable escape monitoring; defeats escapes from spent
  states, raises under-conceded escapes, and retires a closed note's leaf
  after a missed defeat; private status endpoints.
- `zkapi signing-keys`: derive deployment public keys from operator seeds
  (the published development keys are rejected).
- `zkapi settlement reopen`: with the API server stopped, verify, repair and
  reopen a lease cancelled for a corrupt binding.
- `zkapi setup --output-dir NEW_DIRECTORY`: generate a fresh single-party
  development setup, which release builds refuse.

Native server startup requires a pinned oracle RPC/feed, a lease issuer, the
deployment manifest, and both `ZKAPI_STATE_SEED` and `ZKAPI_CLEAR_SEED`; there
are no default seeds. The server refuses to start unless their keys equal the
vault's immutable keys and the vault, adapter and Poseidon library match the
manifest. Use [deployment instructions](docs/deployment.md),
[Docker operation](docker/aws/README.md),
[challenge service operation](docs/challenge-service.md) and the
[concession-vault migration runbook](docs/migration-concession-vault.md). The
browser sends prompts directly to the inference provider; the server handles
authorization and settlement.

The keys in `protocol/setup/v2-concession` (the ceremony's, once G-SETUP has
run) must match the vault's immutable verifier and the client's pinned proof
artifacts; `protocol/setup/v2-concession-dev` holds the development keys for
tests and the drill vault. The `setup` command generates new development keys;
it is not part of connecting a client to the configured vault.

## Protocol details

The active protocol uses Groth16 over BN254, Poseidon, note-bound Baby-JubJub
commitments and Schnorr signatures, a nullifier chain whose successor anchors
are derived from the spent nullifier, and a 32-level append-only Merkle tree.
The ledger uses integer gwei. An escape concedes at most the request budget of
the state it leaves and needs no operator cooperation. Production keys need
the multi-party setup described in
[the ceremony setup](protocol/setup/v2-concession/README.md); the committed
keys are a single-party development setup.

## Source layout

| Directory | Purpose |
| --- | --- |
| `zkapi-clientd/` | Local ETH-funded OpenAI-compatible client and installer |
| `sdk/` | Browser native ETH wallet, public artifacts and SDK tests |
| `protocol/rust/` | Shared v2 types, BN254 helpers, circuits and Rust/WASM wallets |
| `protocol/contracts/` | Native ETH vault, Groth16 verifier and contract tests |
| `protocol/setup/v2-concession/`, `v2-concession-dev/` | Ceremony and development setups of the current circuit |
| `protocol/setup/v2/` | Setup of the legacy circuit, for `release/v2-note-bound` |
| `crates/` | Operator CLI, server, indexer, challenger and the clientd wallet companion |
| `demo/contracts/` | Native ETH verifier/vault deployment script |
| `docker/aws/` | API/indexer/challenger image configuration and restricted signer |
