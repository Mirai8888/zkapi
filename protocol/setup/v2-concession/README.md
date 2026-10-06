# Ceremony setup for `zkapi-v2-concession-v1` (setup id `mpc-1`)

This directory will hold the production Groth16 keys of circuit
`zkapi-v2-concession-v1`, produced by a snarkjs multi-party phase-2 ceremony
(gate **G-SETUP**). **It holds no keys yet.** Until the ceremony is complete,
CI, tests and the drill vault use the development setup in
[`../v2-concession-dev`](../v2-concession-dev/README.md), which release builds
refuse.

One setup serves Sepolia and mainnet (`chain_id` is a public input). Never
regenerate it after a public deployment: the adapter's `REQUEST_VK_HASH` and
`WITHDRAWAL_VK_HASH`, `CEREMONY_VK_KECCAK256` in `compact.rs`, every client
profile and every deployment manifest pin these keys.

## Trust assumption

Groth16 is sound only if nobody knows the setup's toxic waste. A trapdoor
holder can forge any proof, including defeat evidence against an honest
user's escape. The ceremony makes this assumption hold if **at least one**
phase-2 contributor (or the public phase-1 transcript) is honest and outside
the attacker's control, **and** the keys are keys of this circuit. Users can
audit both through the published transcript, the VK hashes in the adapter
and the codehash pins in the client profiles.

The second condition is not implied by the first. Contributions only
re-randomize `δ`; they cannot repair a ceremony that the coordinator set up
from another R1CS. For example, the R1CS could keep the A and B matrices but
change C so that `enforce_equal` rows become vacuous. Steps 2(c), 5 and 6 check
this binding independently of the coordinator.

## Steps

All commands run from `protocol/rust` at the frozen circuit revision
(`circuit-freeze-v2c`).

1. **Export.** Write the circom R1CS of both circuits:

   ```text
   cargo run --release -p zkapi-proof --example export_r1cs -- ceremony/
   ```

   The files come from the finalized arkworks matrices
   (`OptimizationGoal::Constraints`, then `finalize()`), exactly as the
   generator and the prover see them.
   - Wire order is `[one, public inputs in statement order, witnesses]`.
   - All public inputs are declared public inputs (`nPubOut = 0`).
   - `r1cs-manifest.json` records the SHA-256 of both files and the circuit
     shapes. Publish it: everyone who checks the ceremony compares their own
     export with it.

   At the WP-A revision the shapes and SHA-256 are:

   | Circuit | Constraints | Public inputs | Witnesses | QAP domain | `.r1cs` SHA-256 |
   | --- | --- | --- | --- | --- | --- |
   | request | 31,670 | 12 | 31,378 | 2^15 | `08af67fa…e9ae4f9d` |
   | withdrawal | 36,452 | 16 | 36,001 | 2^16 | `c3713cf8…e2f72bfb` |

2. **Fidelity gate** (in CI, and again on the frozen circuit):
   - (a) `r1cs_export_roundtrip`: the files parse back with `ark-circom`'s
     R1CS reader to the in-memory A, B, C matrices, instance count, witness
     count and wire order. This shows that the export is faithful. It says
     nothing about which file a ceremony used.
   - (b) `r1cs_negative_assignments`: for every negative case of the WP-A
     test plan, an independent evaluator over the exported file rejects the
     full unsatisfying assignment.
   - (c) After the ceremony, `import_zkey` (step 6) binds the keys to the
     circuit. A snarkjs zkey stores no C matrix: C reaches the keys only
     through the IC and L points.
     - Coefficient check: the zkey's section-4 A and B coefficients must
       equal the synthesized matrices. snarkjs's prover reads them and ours
       does not, so this check is for consistency only.
     - Binding check (`zkapi_proof::ceremony::check_key_binding`): every
       circuit-dependent point must be what `snarkjs groth16 setup` derives
       from this build's A, B **and C** over the pinned powers of tau, up to
       `δ`. That covers the A and B queries, IC, L and H. This is the circuit
       half of `snarkjs zkey verify`, computed from our own matrices.
     - A key set up from an R1CS with the same A and B but another C passes
       the coefficient check and the proving gate. Only the binding check
       refuses it (`keys_set_up_from_another_c_matrix_are_refused`).

   ```text
   cargo test --release -p zkapi-proof --test r1cs_fidelity --test zkey_import
   ```

   On the real ceremony files, before importing:

   ```text
   ZKAPI_PTAU=pot.ptau ZKAPI_REQUEST_ZKEY=ceremony/request_final.zkey \
   ZKAPI_WITHDRAWAL_ZKEY=ceremony/withdrawal_final.zkey \
   cargo test --release -p zkapi-proof --test zkey_import ceremony_zkeys_pass_the_import_gates -- --ignored
   ```

3. **Powers of tau.** Use a public BN254 phase-1 transcript prepared for
   phase 2 (`snarkjs powersoftau prepare phase2`), of at least 2^16 (the
   withdrawal circuit's domain). An example is Hermez
   `powersOfTau28_hez_final_16.ptau`.
   - Pin its SHA-256 before the ceremony starts and record it as
     `ptau_sha256`.
   - Anyone can check the file itself with `snarkjs powersoftau verify`.
   - The binding check is only as good as this file, so import with
     `--ptau-sha256 <pin>`.

4. **Contributions.** For each circuit:

   ```text
   snarkjs groth16 setup <circuit>.r1cs pot.ptau <circuit>_0000.zkey      # the step-1 export
   snarkjs zkey contribute <circuit>_000i.zkey <circuit>_000(i+1).zkey   # each contributor
   snarkjs zkey beacon <circuit>_000n.zkey <circuit>_final.zkey <beacon> 10
   ```

   - At least three contributions, **at least two of them by parties the
     operator did not select** (nominated by the external reviewers or by a
     public call), then a public random beacon fixed in advance (for example
     a future block hash).
   - Before contributing, each contributor should run
     `snarkjs zkey verify <own export> pot.ptau <received zkey>` on their own
     export.
   - If fewer contributors are available, the ceremony still requires two
     externally nominated contributions plus the beacon; otherwise mainnet
     slips. No single-party setup ever reaches mainnet or production
     Sepolia.
   - The import refuses an `mpc-1` zkey that records fewer than three
     contributions before its beacon.

5. **Publication and independent verification.** Publish the transcript
   (every intermediate `.zkey`, the contribution hashes and attestations),
   `r1cs-manifest.json`, and every hash. Record the transcript's SHA-256 as
   `transcript_sha256`.
   - The coordinator's own `snarkjs zkey verify` output is evidence only for
     the `.r1cs` it was run on.
   - So **each external reviewer** must, at the frozen revision:
     1. export the R1CS themselves (step 1);
     2. check its SHA-256 against `r1cs-manifest.json`;
     3. run `snarkjs zkey verify <own export> <pinned ptau> <circuit>_final.zkey`
        for both circuits.
   - That run checks the contribution chain (each `δ` update and its proof
     of knowledge), which `import_zkey` does not check. It also checks the
     circuit binding a second time.

6. **Import.** Convert the final zkeys into this directory:

   ```text
   cargo run --release -p zkapi-proof --example import_zkey -- \
     --setup-id mpc-1 \
     --ptau pot.ptau --ptau-sha256 <pinned hex> \
     --request-r1cs ceremony/request.r1cs --withdrawal-r1cs ceremony/withdrawal.r1cs \
     --request ceremony/request_final.zkey --withdrawal ceremony/withdrawal_final.zkey \
     --transcript-sha256 <hex> \
     ../setup/v2-concession
   ```

   The import runs every gate before it writes anything:
   - the `.r1cs` files the ceremony used must be byte for byte this build's
     export;
   - the powers of tau must hash to the pin;
   - each zkey must record at least three contributions followed by a beacon
     (`mpc-1` only);
   - each zkey must pass the coefficient and binding checks of 2(c);
   - each zkey must have the key shapes: 13 and 17 IC points, and an H query
     of the domain size;
   - the proving gate: a canonical statement of each circuit, proved with
     the shipping `CircomReduction` prover, must verify, and must stop
     verifying when any single public input changes.

   The import refuses to overwrite existing key, manifest or Solidity files.
   It then writes:

   | File | Content |
   | --- | --- |
   | `request.pk`, `request.vk`, `withdrawal.pk`, `withdrawal.vk` | arkworks keys with headers `zkapi-v2-concession-v1/mpc-1/<kind>\0` |
   | `manifest.json` | See below |
   | `Groth16ProofAdapter.sol` | the regenerated adapter with `CIRCUIT_ID_HASH`, `REQUEST_VK_HASH`, `WITHDRAWAL_VK_HASH` (then `forge fmt` into `protocol/contracts/src/adapters`) |
   | `Bn254Poseidon.sol` | the Poseidon library |

   `manifest.json` records:
   - `setup_id: "mpc-1"` and `reduction: "circom"`;
   - the SHA-256 of the four keys, and `vk_keccak256` per kind;
   - `r1cs_sha256` (this build's exports), `ptau_sha256` (computed by the
     import), `transcript_sha256` and `zkey_sha256` (the final zkeys);
   - the circuit shapes, the verifying keys and the Poseidon parameters.

7. **Proving gate, before the keys are published.** With the imported keys
   (`ZKAPI_SETUP_DIR` points the proof tests at them):

   ```text
   ZKAPI_SETUP_DIR=../setup/v2-concession \
     cargo test --release -p zkapi-proof --test proofs --test reduction_cross_check
   cargo run --release -p zkapi-proof --example solidity_fixture -- ../setup/v2-concession
   cargo run --release -p zkapi-proof --example vault_challenge_fixture -- ../setup/v2-concession
   ```

   The first command runs, against the `CircomReduction` prover and the
   native verifier:
   - the mutate-each-public-input tests (12 request and 16 withdrawal
     inputs) and the non-canonical-input tests;
   - the negative proving tests;
   - positive proofs of every kind: genesis and signed requests; escapes
     with `c = 0` and `c > 0`; a mutual close (kind 1); an ownership proof
     (kind 2); a full 160-bit destination;
   - the manifest and adapter checks.

   The fixtures feed the same statements to the adapter deployed on Anvil
   (the contract tests).

   Then replace the pins:
   - set `CEREMONY_VK_KECCAK256` in `zkapi-proof/src/compact.rs` to the two
     VK hashes and run
     `cargo run --release -p zkapi-proof --bin release_policy_check`;
   - update the adapter, the fixtures, the SDK assets and hashes, and the
     deployment profiles;
   - rebuild the WebAssembly reproducibly.

## Rehearsals

Dry runs of this pipeline must use `--setup-id rehearsal`. Examples are a
throwaway powers of tau, or a single contribution. Rehearsal keys load only
in `dev-setup` builds. Never label a dry run `mpc-1`. Its toxic waste is
known to whoever ran it.

## Acceptance by builds

Release builds of `zkapi-proof` (no `dev-setup` feature) accept only the
setup ids in `RELEASE_SETUP_IDS = ["mpc-1"]`. An `mpc-1` key also needs a
verifying key whose keccak256 equals the pin of its kind in
`CEREMONY_VK_KECCAK256`, so a key that merely carries the label is refused.
That pin is `None` until step 7, so release builds load no key until then.

Test builds (`--features dev-setup`) also accept `dev`, `rehearsal` and
unpinned `mpc-1` keys, so the step-7 tests can run before the pins exist.

Only accepting keys needs the feature. Generating development keys
(`compact::setup`) and the fixtures (feature `dev-fixtures`) do not. Never
enable `dev-setup` on a dependency of a production binary: Cargo unifies
features across the packages of one build.

`cargo run --release -p zkapi-proof --bin release_policy_check` (run in CI)
builds the library as production binaries see it. It fails unless the build
refuses the committed development setup and development keys relabelled
`rehearsal` or `mpc-1`.

Every key file names its circuit, setup and kind. So a request key cannot be
loaded as a withdrawal key, and a key of another circuit (including
`zkapi-v2-note-bound-v1`) is refused before decoding.
