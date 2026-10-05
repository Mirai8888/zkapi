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
[the note-binding review](docs/note-bound-commitments.md).

## Local OpenAI-compatible API

Use [zkapi-clientd](zkapi-clientd/README.md) to configure an ETH wallet and serve
inference to Open WebUI or another local OpenAI-compatible client.

## Build and test

```sh
npm ci
npm test
npm run build:browser
npm run build:mainnet
npm run verify:assets
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
`zkapi-v2-note-bound-v1`. Ordinary SDK consumers do not need Rust. To rebuild
WASM deliberately, use `scripts/build-browser-client.sh` and review the changed
artifact hashes.

## Full local lifecycle acceptance

Run `npm run test:e2e:v2` to build and test deposit, HTTP lease issuance, mocked
provider usage, signed settlement, real-proof stale withdrawal/challenge and
honest withdrawal on a fresh local chain. The provider and oracle are mocked;
protocol services, wallet proofs and contracts are real. See the
[acceptance process and coverage limits](docs/v2-acceptance.md).

## Operator services

- `zkapi serverd`: native ETH lease authorization, settlement and Schnorr signing.
- `zkapi-indexerd` / `zkapi indexer`: vault event indexing and Merkle paths
  from a view verified against the vault.
- `zkapi-challenged`: durable escape monitoring, challenge submission and
  private status endpoints.
- `zkapi signing-keys`: derive deployment public keys from operator seeds
  (the published development keys are rejected).
- `zkapi settlement reopen`: with the API server stopped, verify, repair and
  reopen a lease cancelled for a corrupt binding.
- `zkapi setup --output-dir NEW_DIRECTORY`: generate a fresh single-party Groth16 setup.

Native server startup requires a pinned oracle RPC/feed, a lease issuer, and
both `ZKAPI_STATE_SEED` and `ZKAPI_CLEAR_SEED`; there are no default seeds. The
server refuses to start unless their keys equal the vault's immutable keys.
Use [deployment instructions](docs/deployment.md), [Docker operation](docker/aws/README.md),
[challenge service operation](docs/challenge-service.md) and the
[hardened vault migration](docs/migration-hardened-vault.md). The browser sends
prompts directly to the inference provider; the server handles authorization
and settlement.

The keys in `protocol/setup/v2` must match the vault's immutable verifier and
the client's pinned proof artifacts. The `setup` command generates new keys; it
is not part of connecting a client to the configured vault.

## Protocol details

The active protocol uses Groth16 over BN254, Poseidon, note-bound Baby-JubJub
commitments and Schnorr signatures, and a 32-level Merkle tree. The ledger uses
integer gwei, and the protocol relies on a single-party setup.

## Source layout

| Directory | Purpose |
| --- | --- |
| `zkapi-clientd/` | Local ETH-funded OpenAI-compatible client and installer |
| `sdk/` | Browser native ETH wallet, public artifacts and SDK tests |
| `protocol/rust/` | Shared v2 types, BN254 helpers, circuits and Rust/WASM wallets |
| `protocol/contracts/` | Native ETH vault, Groth16 verifier and contract tests |
| `protocol/setup/v2/` | Selected circuit setup and verifier artifacts |
| `crates/` | Operator CLI, server, indexer and challenger |
| `demo/contracts/` | Native ETH verifier/vault deployment script |
| `docker/aws/` | API/indexer/challenger image configuration and restricted signer |
