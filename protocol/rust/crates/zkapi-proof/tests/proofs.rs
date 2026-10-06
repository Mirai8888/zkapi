//! Proof-level tests with the committed development setup and the shipping
//! `CircomReduction` prover: positive proofs of every kind, the
//! mutate-each-public-input test, refusal of invalid statements, the
//! end-to-end Rust chain, key kinds and setup ids.

mod common;

use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, UniformRand};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::{Groth16, ProvingKey};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use common::*;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    circuit_shape, decode_compressed, decode_compressed_accepting, keccak256, proof_from_wire,
    proof_to_wire, request_circuit, sha256, verifying_key_keccak256, withdrawal_circuit, KeyKind,
    RequestProver, RequestVerifier, SetupManifest, WithdrawalProver, WithdrawalVerifier,
    DEV_SETUP_ID, RELEASE_SETUP_IDS,
};
use zkapi_proof::dev::DevState;
use zkapi_proof::groth16::verify_field_elements;
use zkapi_types::wire::Groth16ProofWire;
use zkapi_types::{Felt252, WithdrawalKind};

struct Keys {
    request_prover: RequestProver,
    request_verifier: RequestVerifier,
    withdrawal_prover: WithdrawalProver,
    withdrawal_verifier: WithdrawalVerifier,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| {
        let dir = setup_dir();
        Keys {
            request_prover: RequestProver::load(&dir).unwrap(),
            request_verifier: RequestVerifier::load(&dir).unwrap(),
            withdrawal_prover: WithdrawalProver::load(&dir).unwrap(),
            withdrawal_verifier: WithdrawalVerifier::load(&dir).unwrap(),
        }
    })
}

fn read(file: &str) -> Vec<u8> {
    std::fs::read(setup_dir().join(file)).unwrap()
}

fn mutated(inputs: &[Felt252], index: usize) -> Vec<Felt252> {
    let mut inputs = inputs.to_vec();
    let value = core::felt_to_field(&inputs[index]) + Fr::ONE;
    inputs[index] = core::field_to_felt(&value);
    inputs
}

#[test]
fn development_setup_matches_its_manifest_and_adapter() {
    let manifest: SetupManifest = serde_json::from_slice(&read("manifest.json")).expect("manifest");
    assert_eq!(manifest.circuit_id, "zkapi-v2-concession-v1");
    assert_eq!(manifest.setup_id, DEV_SETUP_ID);
    assert_eq!(manifest.reduction, "circom");
    assert_eq!(manifest.ptau_sha256, None);
    for (file, digest) in &manifest.files {
        assert_eq!(&hex::encode(sha256(&read(file))), digest, "{file}");
    }
    assert_eq!(manifest.files.len(), 4);
    let request_vk = verifying_key_keccak256(&read("request.vk"), KeyKind::Request).unwrap();
    let withdrawal_vk =
        verifying_key_keccak256(&read("withdrawal.vk"), KeyKind::Withdrawal).unwrap();
    let hex = |bytes: [u8; 32]| format!("0x{}", hex::encode(bytes));
    assert_eq!(manifest.vk_keccak256.request, hex(request_vk));
    assert_eq!(manifest.vk_keccak256.withdrawal, hex(withdrawal_vk));
    let keys = keys();
    assert_eq!(keys.request_verifier.verifying_key_keccak256(), request_vk);
    assert_eq!(keys.request_prover.verifying_key_keccak256(), request_vk);
    assert_eq!(
        keys.withdrawal_verifier.verifying_key_keccak256(),
        withdrawal_vk
    );
    assert_eq!(
        keys.withdrawal_prover.verifying_key_keccak256(),
        withdrawal_vk
    );
    for setup_id in [
        keys.request_prover.setup_id(),
        keys.request_verifier.setup_id(),
        keys.withdrawal_prover.setup_id(),
        keys.withdrawal_verifier.setup_id(),
    ] {
        assert_eq!(setup_id, DEV_SETUP_ID);
    }
    let adapter = String::from_utf8(read("Groth16ProofAdapter.sol")).unwrap();
    assert!(adapter.contains(&format!(
        "CIRCUIT_ID_HASH = {}",
        hex(keccak256(b"zkapi-v2-concession-v1"))
    )));
    assert!(adapter.contains(&format!("REQUEST_VK_HASH = {}", hex(request_vk))));
    assert!(adapter.contains(&format!("WITHDRAWAL_VK_HASH = {}", hex(withdrawal_vk))));
    assert!(adapter.contains("uint256[16] memory values"));
    assert!(adapter.contains("if (index == 16) return"));
    assert!(!adapter.contains("if (index == 17) return"));
    assert_eq!(manifest.request.ic.len(), 13);
    assert_eq!(manifest.withdrawal.ic.len(), 17);
    assert_eq!(
        manifest.circuits.request,
        circuit_shape(KeyKind::Request).unwrap()
    );
    assert_eq!(
        manifest.circuits.withdrawal,
        circuit_shape(KeyKind::Withdrawal).unwrap()
    );
}

#[test]
fn key_kinds_and_setup_ids() {
    // A request key loaded as a withdrawal key (and the reverse) fails.
    assert!(WithdrawalProver::from_bytes(&read("request.pk")).is_err());
    assert!(WithdrawalVerifier::from_bytes(&read("request.vk")).is_err());
    assert!(RequestProver::from_bytes(&read("withdrawal.pk")).is_err());
    assert!(RequestVerifier::from_bytes(&read("withdrawal.vk")).is_err());
    let error = decode_compressed::<ark_groth16::VerifyingKey<Bn254>>(
        &read("request.vk"),
        KeyKind::Withdrawal,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("wrong key kind"), "{error}");
    // Release builds refuse the development setup.
    for (file, kind) in [
        ("request.pk", KeyKind::Request),
        ("withdrawal.vk", KeyKind::Withdrawal),
    ] {
        let error = decode_compressed_accepting::<ark_groth16::VerifyingKey<Bn254>>(
            &read(file),
            kind,
            RELEASE_SETUP_IDS,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not accepted"), "{file}: {error}");
    }
    // The legacy note-bound keys are refused outright.
    let legacy = setup_dir().join("../v2/request.pk");
    if let Ok(bytes) = std::fs::read(legacy) {
        let error = RequestProver::from_bytes(&bytes).err().unwrap();
        assert!(
            format!("{error:#}").contains("incompatible setup"),
            "{error:#}"
        );
    }
}

fn prove_request_case(
    state: &DevState,
    request: &zkapi_proof::dev::DevRequest,
) -> (zkapi_types::RequestPublicInputsV2, Groth16ProofWire) {
    let c = chain();
    let (public, witness) = c.request_of(state, request);
    let proof = keys().request_prover.prove(&public, witness).unwrap();
    assert!(keys().request_verifier.verify(&public, &proof).unwrap());
    (public, proof)
}

#[test]
fn positive_proofs_of_every_kind_verify() {
    let c = chain();
    prove_request_case(&c.s0, &c.r0);
    prove_request_case(&c.s1, &c.r1);
    prove_request_case(&c.s2, &c.r2);
    for (state, kind, destination, conceded) in [
        (&c.s1, WithdrawalKind::Escape, DESTINATION, 0),
        (
            &c.s1,
            WithdrawalKind::Escape,
            DESTINATION,
            c.r1.solvency_bound,
        ),
        (&c.s0, WithdrawalKind::Escape, DESTINATION, 100_000),
        (&c.s1, WithdrawalKind::MutualClose, DESTINATION, 0),
        (&c.s1, WithdrawalKind::Ownership, [0; 20], 0),
        (&c.s1, WithdrawalKind::Escape, [0xff; 20], 0),
    ] {
        let (public, witness) = c.withdrawal_of(state, &withdrawal(kind, destination, conceded));
        let proof = keys().withdrawal_prover.prove(&public, witness).unwrap();
        assert!(
            keys().withdrawal_verifier.verify(&public, &proof).unwrap(),
            "{kind:?} c={conceded}"
        );
    }
}

#[test]
fn mutating_any_public_input_fails_verification() {
    let c = chain();
    let (public, proof) = prove_request_case(&c.s1, &c.r1);
    let inputs = public.to_field_elements();
    assert!(keys()
        .request_verifier
        .verify_field_elements(&inputs, &proof)
        .unwrap());
    for index in 0..inputs.len() {
        assert!(
            !keys()
                .request_verifier
                .verify_field_elements(&mutated(&inputs, index), &proof)
                .unwrap(),
            "request input {index} is not bound"
        );
    }
    for (kind, destination, conceded) in [
        (WithdrawalKind::Escape, DESTINATION, 30_000),
        (WithdrawalKind::Ownership, [0; 20], 0),
    ] {
        let (public, witness) = c.withdrawal_of(&c.s1, &withdrawal(kind, destination, conceded));
        let proof = keys().withdrawal_prover.prove(&public, witness).unwrap();
        let inputs = public.to_field_elements();
        assert_eq!(inputs.len(), 16);
        assert!(keys()
            .withdrawal_verifier
            .verify_field_elements(&inputs, &proof)
            .unwrap());
        for index in 0..inputs.len() {
            assert!(
                !keys()
                    .withdrawal_verifier
                    .verify_field_elements(&mutated(&inputs, index), &proof)
                    .unwrap(),
                "{kind:?} withdrawal input {index} is not bound"
            );
        }
        // Typed mutations of the fields the vault and server read.
        for mutate in [
            |p: &mut zkapi_types::WithdrawalPublicInputsV2C| p.kind ^= 1,
            |p: &mut zkapi_types::WithdrawalPublicInputsV2C| p.conceded += 1,
            |p: &mut zkapi_types::WithdrawalPublicInputsV2C| p.valid_until += 1,
            |p: &mut zkapi_types::WithdrawalPublicInputsV2C| p.destination[0] ^= 1,
            |p: &mut zkapi_types::WithdrawalPublicInputsV2C| {
                p.next_nullifier = Felt252::from_u64(1)
            },
        ] {
            let mut wrong = public.clone();
            mutate(&mut wrong);
            assert!(!keys().withdrawal_verifier.verify(&wrong, &proof).unwrap());
        }
    }
}

#[test]
fn provers_refuse_invalid_statements() {
    let c = chain();
    let b1 = c.s1.balance;
    let next = c.s1.successor_nullifier();
    for (kind, destination, conceded, final_balance, next_nullifier, clearance) in [
        (0u8, DESTINATION, 10, b1 - 9, next, false),
        (3, [0; 20], 0, b1, Felt252::ZERO, true),
        (1, DESTINATION, 0, b1, next, true),
        (2, [0; 20], 1, b1 - 1, Felt252::ZERO, false),
        (0, DESTINATION, 0, b1, Felt252::ZERO, false),
        (2, DESTINATION, 0, b1, Felt252::ZERO, false),
        (1, DESTINATION, 0, b1, Felt252::ZERO, false),
    ] {
        let (public, witness) = c.raw_withdrawal(
            &c.s1,
            kind,
            destination,
            conceded,
            final_balance,
            next_nullifier,
            clearance,
        );
        assert!(keys().withdrawal_prover.prove(&public, witness).is_err());
    }
    // A signed state at a non-derived anchor cannot make a request.
    let stray = DevState::signed(
        &c.note,
        &c.deployment,
        800_000,
        Felt252::from_u64(23),
        Felt252::from_u64(0xabcdef),
        Some(c.s0.anchor),
    );
    let (public, witness) = c.request_of(&stray, &c.r1);
    assert!(keys().request_prover.prove(&public, witness).is_err());
    // A born-spent state (signed at anchor 1, B < D) cannot request or exit.
    let born_spent = DevState::signed(
        &c.note,
        &c.deployment,
        DEPOSIT - 1,
        Felt252::from_u64(29),
        core::GENESIS_ANCHOR,
        None,
    );
    let (public, witness) = c.request_of(&born_spent, &c.r1);
    assert!(keys().request_prover.prove(&public, witness).is_err());
    let (public, witness) = c.withdrawal_unchecked(
        &born_spent,
        &withdrawal(WithdrawalKind::Escape, DESTINATION, 0),
    );
    assert!(keys().withdrawal_prover.prove(&public, witness).is_err());
}

/// The escape from S_k names N_{k+1}, which is exactly the nullifier of a
/// request from the installed successor S_{k+1}: that request proof is the
/// defeat evidence, while a request at N_k is only raise evidence.
#[test]
fn end_to_end_chain() {
    let c = chain();
    // Genesis request R0 at N0.
    let (r0_public, _) = prove_request_case(&c.s0, &c.r0);
    assert_eq!(r0_public.request_nullifier, c.s0.nullifier());
    // The operator signs S1 at the derived anchor; the client's install checks.
    assert_eq!(c.s1.anchor, core::next_anchor(&r0_public.request_nullifier));
    assert!(c.s1.anchor != Felt252::ZERO && c.s1.anchor != core::GENESIS_ANCHOR);
    let message = core::state_message(
        2,
        CHAIN_ID,
        &c.deployment.contract_address,
        &c.s1.commitment().x,
        &c.s1.commitment().y,
        &c.s1.anchor,
    );
    assert!(zkapi_proof::compact::verify_signature(
        &c.deployment.state_key(),
        &message,
        c.s1.signature.as_ref().unwrap()
    )
    .unwrap());
    // An escape from S0 publishes N1 = N(succ(N0)).
    let (escape0, witness) =
        c.withdrawal_of(&c.s0, &withdrawal(WithdrawalKind::Escape, DESTINATION, 0));
    let escape0_proof = keys().withdrawal_prover.prove(&escape0, witness).unwrap();
    assert!(keys()
        .withdrawal_verifier
        .verify(&escape0, &escape0_proof)
        .unwrap());
    // A request from the installed successor S1 is at exactly that nullifier.
    let (r1_public, r1_proof) = prove_request_case(&c.s1, &c.r1);
    assert_eq!(escape0.next_nullifier, r1_public.request_nullifier);
    assert_eq!(escape0.withdrawal_nullifier, r0_public.request_nullifier);
    assert!(keys()
        .request_verifier
        .verify(&r1_public, &r1_proof)
        .unwrap());
    // One step further: an escape from S1 is defeated by a request from S2.
    let (escape1, witness) = c.withdrawal_of(
        &c.s1,
        &withdrawal(WithdrawalKind::Escape, DESTINATION, c.r1.solvency_bound),
    );
    let escape1_proof = keys().withdrawal_prover.prove(&escape1, witness).unwrap();
    assert!(keys()
        .withdrawal_verifier
        .verify(&escape1, &escape1_proof)
        .unwrap());
    let (r2_public, _) = prove_request_case(&c.s2, &c.r2);
    assert_eq!(escape1.next_nullifier, r2_public.request_nullifier);
    assert_eq!(escape1.withdrawal_nullifier, r1_public.request_nullifier);
    assert_eq!(escape1.final_balance + escape1.conceded, c.s1.balance);
    // Notes sharing the secret never collide.
    let other = c.same_secret_note.genesis(Felt252::from_u64(5));
    let (other_request, _) = prove_request_case(&other, &c.r0);
    assert_ne!(other_request.request_nullifier, r0_public.request_nullifier);
    assert_ne!(other_request.request_nullifier, escape0.next_nullifier);
}

/// The development keys were generated for the circom reduction: a proof
/// made with `ark-groth16`'s default reduction from the same keys does not
/// verify, while the shipping prover's does.
#[test]
fn development_keys_are_circom_reduction_keys() {
    let c = chain();
    let (public, witness) = c.request_of(&c.s1, &c.r1);
    let circuit = request_circuit(&public, &witness).unwrap();
    let (pk, _): (ProvingKey<Bn254>, _) =
        decode_compressed(&read("request.pk"), KeyKind::Request).unwrap();
    let inputs: Vec<Fr> = public
        .to_field_elements()
        .iter()
        .map(core::felt_to_field)
        .collect();
    let mut rng = StdRng::seed_from_u64(7);
    let (r, s) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let libsnark = Groth16::<Bn254, LibsnarkReduction>::create_proof_with_reduction(
        circuit.clone(),
        &pk,
        r,
        s,
    )
    .unwrap();
    assert!(!verify_field_elements(&pk.vk, &inputs, &libsnark).unwrap());
    let circom =
        zkapi_proof::compact::Prover::create_proof_with_reduction(circuit, &pk, r, s).unwrap();
    assert!(verify_field_elements(&pk.vk, &inputs, &circom).unwrap());
    let wire = proof_to_wire(&circom).unwrap();
    assert_eq!(proof_from_wire(&wire).unwrap(), circom);

    let (public, witness) = c.withdrawal_of(
        &c.s1,
        &withdrawal(WithdrawalKind::MutualClose, DESTINATION, 0),
    );
    let circuit = withdrawal_circuit(&public, &witness).unwrap();
    let (pk, _): (ProvingKey<Bn254>, _) =
        decode_compressed(&read("withdrawal.pk"), KeyKind::Withdrawal).unwrap();
    let inputs: Vec<Fr> = public
        .to_field_elements()
        .iter()
        .map(core::felt_to_field)
        .collect();
    let libsnark = Groth16::<Bn254, LibsnarkReduction>::create_proof_with_reduction(
        circuit.clone(),
        &pk,
        r,
        s,
    )
    .unwrap();
    assert!(!verify_field_elements(&pk.vk, &inputs, &libsnark).unwrap());
    let circom =
        zkapi_proof::compact::Prover::create_proof_with_reduction(circuit, &pk, r, s).unwrap();
    assert!(verify_field_elements(&pk.vk, &inputs, &circom).unwrap());
}
