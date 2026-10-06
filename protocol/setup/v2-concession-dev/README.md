# Development setup for `zkapi-v2-concession-v1` (setup id `dev`)

These keys are for tests, CI, fixtures and the Sepolia drill vault only.
They are single-party Groth16 keys generated with OS randomness, so whoever
ran the generator could have kept the toxic waste. **Release builds refuse
them**: every key file starts with the header
`zkapi-v2-concession-v1/dev/<request|withdrawal>\0`, and only builds of
`zkapi-proof` with the `dev-setup` feature accept the `dev` setup id. The
production setup is the multi-party ceremony in
[`../v2-concession`](../v2-concession/README.md) (setup id `mpc-1`).

## Contents

| File | What it is |
| --- | --- |
| `request.pk`, `request.vk` | Request circuit keys (12 public inputs, 13 IC points) |
| `withdrawal.pk`, `withdrawal.vk` | Withdrawal circuit keys (16 public inputs, 17 IC points) |
| `manifest.json` | `setup_id`, `reduction: "circom"`, SHA-256 of the four key files, `vk_keccak256` per kind, circuit shapes, the verifying keys and the Poseidon parameters. `ptau_sha256` and `transcript_sha256` are `null`: there was no ceremony. |
| `Groth16ProofAdapter.sol` | The generated Solidity verifier, with `CIRCUIT_ID_HASH`, `REQUEST_VK_HASH` and `WITHDRAWAL_VK_HASH` |
| `Bn254Poseidon.sol` | The generated Poseidon library (unchanged from `setup/v2`) |

The VK hashes are keccak256 of each `.vk` file without its header. They are
also the adapter constants, so a deployment's adapter identifies its setup.

## How it was made

```text
cd protocol/rust
cargo run --release -p zkapi-proof --example setup -- ../setup/v2-concession-dev
```

The generator is `Groth16::<Bn254, CircomReduction>::circuit_specific_setup`
(`zkapi_proof::compact::setup`). `ark-groth16` 0.5's generator calls the
reduction's `h_query_scalars`, so these keys have the snarkjs-style H query
and are used by the same `CircomReduction` prover as the ceremony keys
(checked by `tests/reduction_cross_check.rs` and `tests/proofs.rs`).

Re-importing these keys through the ceremony path (`.zkey` export, then
`examples/import_zkey.rs --setup-id dev`) reproduces this directory byte for
byte (`tests/zkey_import.rs`).

## Regenerating

Regenerate only when the circuits change. The new keys replace every pin:
the fixtures (`examples/solidity_fixture.rs`,
`examples/vault_challenge_fixture.rs`), the contracts' adapter and its tests,
the SDK proving keys and hashes, and the deployment profiles of the drill
vault. The setup example refuses to overwrite an existing directory.
