# Ceremony setup for `zkapi-v2-concession-v1` (setup id `mpc-1`)

This directory will hold the production Groth16 keys of circuit
`zkapi-v2-concession-v1`, produced by a snarkjs multi-party phase-2 ceremony
(gate **G-SETUP**). **It holds no keys yet.** Until the ceremony is complete,
CI, tests and the drill vault use the development setup in
[`../v2-concession-dev`](../v2-concession-dev/README.md), which release builds
refuse.

One setup serves Sepolia and mainnet (`chain_id` is a public input). Never
regenerate it after a public deployment: the adapter's `REQUEST_VK_HASH` and
`WITHDRAWAL_VK_HASH`, every client profile and every deployment manifest pin
these keys.

## Trust assumption

Groth16 is sound only if nobody knows the setup's toxic waste. A trapdoor
holder can forge any proof, including defeat evidence against an honest
user's escape. The ceremony makes this assumption hold if **at least one**
phase-2 contributor (or the public phase-1 transcript) is honest and outside
the attacker's control. Users can audit it through the published transcript,
the VK hashes in the adapter and the codehash pins in the client profiles.

## Steps

All commands run from `protocol/rust` at the frozen circuit revision
(`circuit-freeze-v2c`).

1. **Export.** Write the circom R1CS of both circuits:

   ```text
   cargo run --release -p zkapi-proof --example export_r1cs -- ceremony/
   ```

   The files come from the finalized arkworks matrices
   (`OptimizationGoal::Constraints`, then `finalize()`), exactly as the
   generator and the prover see them. Wire order is
   `[one, public inputs in statement order, witnesses]`; all public inputs
   are declared public inputs (`nPubOut = 0`). `r1cs-manifest.json` records
   the SHA-256 of both files and the circuit shapes. At the WP-A revision:

   | Circuit | Constraints | Public inputs | Witnesses | QAP domain |
   | --- | --- | --- | --- | --- |
   | request | 31,670 | 12 | 31,378 | 2^15 |
   | withdrawal | 36,452 | 16 | 36,001 | 2^16 |

2. **Fidelity gate** (in CI, and again on the frozen circuit):
   - (a) `r1cs_export_roundtrip`: the files parse back with `ark-circom`'s
     R1CS reader to the in-memory A, B, C matrices, instance count, witness
     count and wire order;
   - (b) `r1cs_negative_assignments`: for every negative case of the WP-A
     test plan, the full unsatisfying assignment is rejected by an
     independent evaluator over the exported file;
   - (c) after the ceremony, `import_zkey` (step 6) requires the A and B
     matrices read from each final `.zkey` by `ark_circom::read_zkey` to
     equal the synthesized matrices (snarkjs stores no C matrix; C is covered
     by (a)).

   ```text
   cargo test --release -p zkapi-proof --test r1cs_fidelity --test zkey_import
   ```

3. **Powers of tau.** A public BN254 phase-1 transcript of at least 2^16
   (the withdrawal circuit's domain), for example Hermez
   `powersOfTau28_hez_final_16.ptau`. Pin its SHA-256 before the ceremony
   starts and record it as `ptau_sha256`.

4. **Contributions.** For each circuit:

   ```text
   snarkjs groth16 setup <circuit>.r1cs pot.ptau <circuit>_0000.zkey
   snarkjs zkey contribute <circuit>_000i.zkey <circuit>_000(i+1).zkey   # each contributor
   snarkjs zkey beacon <circuit>_000n.zkey <circuit>_final.zkey <beacon> 10
   ```

   At least three contributions, **at least two of them by parties the
   operator did not select** (nominated by the external reviewers or by a
   public call), then a public random beacon fixed in advance (for example a
   future block hash). If fewer contributors are available, the ceremony
   still requires two externally nominated contributions plus the beacon;
   otherwise mainnet slips. No single-party setup ever reaches mainnet or
   production Sepolia.

5. **Publication.** Publish the transcript (every intermediate `.zkey`, the
   contribution hashes and attestations), the output of
   `snarkjs zkey verify <circuit>.r1cs pot.ptau <circuit>_final.zkey` for
   both circuits, and every hash. Record the transcript's SHA-256 as
   `transcript_sha256`.

6. **Import.** Convert the final zkeys into this directory:

   ```text
   cargo run --release -p zkapi-proof --example import_zkey -- \
     --request ceremony/request_final.zkey --withdrawal ceremony/withdrawal_final.zkey \
     --setup-id mpc-1 --ptau-sha256 <hex> --transcript-sha256 <hex> \
     ../setup/v2-concession
   ```

   The import refuses to overwrite existing key, manifest or Solidity files.
   `import_zkey` runs fidelity gate (c), checks the key
   shapes (13 and 17 IC points, an H query of the domain size) and proves
   and verifies a canonical statement of each circuit with the shipping
   `CircomReduction` prover before writing anything. It then writes:

   | File | Content |
   | --- | --- |
   | `request.pk`, `request.vk`, `withdrawal.pk`, `withdrawal.vk` | arkworks keys with headers `zkapi-v2-concession-v1/mpc-1/<kind>\0` |
   | `manifest.json` | `setup_id: "mpc-1"`, `reduction: "circom"`, SHA-256 of the four keys, `vk_keccak256` per kind, `ptau_sha256`, `transcript_sha256`, circuit shapes, verifying keys, Poseidon parameters |
   | `Groth16ProofAdapter.sol` | the regenerated adapter with `CIRCUIT_ID_HASH`, `REQUEST_VK_HASH`, `WITHDRAWAL_VK_HASH` (then `forge fmt` into `protocol/contracts/src/adapters`) |
   | `Bn254Poseidon.sol` | the Poseidon library |

7. **Proving gate, before the keys are published.** With the imported keys,
   the `CircomReduction` prover and the adapter deployed on Anvil, run the
   mutate-each-public-input tests (12 request and 16 withdrawal inputs), the
   negative proving tests, and positive proofs of every kind: genesis and
   signed requests; escapes with `c = 0` and `c > 0`; a mutual close
   (kind 1); an ownership proof (kind 2); a full 160-bit destination. Then
   replace the pins (adapter, fixtures, SDK assets and hashes, deployment
   profiles) and rebuild the WebAssembly reproducibly.

## Acceptance by builds

Release builds of `zkapi-proof` accept only the setup ids in
`RELEASE_SETUP_IDS = ["mpc-1"]`; test builds (`--features dev-setup`) also
accept `dev`. Every key file names its circuit, setup and kind, so a request
key cannot be loaded as a withdrawal key and a key of another circuit
(including `zkapi-v2-note-bound-v1`) is refused before decoding.
