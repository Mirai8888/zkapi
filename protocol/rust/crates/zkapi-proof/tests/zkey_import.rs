//! Round trip of the ceremony import on the development setup: the dev
//! proving keys are written as snarkjs `.zkey` files, imported by
//! `examples/import_zkey.rs` (which reads them with `ark_circom::read_zkey`
//! and runs the fidelity, shape and proving gates), and the resulting setup
//! directory must equal the committed one byte for byte.
#![cfg(not(target_arch = "wasm32"))]

mod common;

#[allow(dead_code)]
#[path = "../examples/import_zkey.rs"]
mod import_zkey;

use std::path::{Path, PathBuf};

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine};
use ark_ff::{Field, PrimeField};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalSerialize;
use common::setup_dir;
use import_zkey::{import, ImportArgs};
use zkapi_proof::compact::{decode_compressed, KeyKind, SetupProvenance, DEV_SETUP_ID};
use zkapi_proof::r1cs::circuit_matrices;

/// snarkjs stores base-field coordinates in Montgomery form, little-endian.
fn put_fq(out: &mut Vec<u8>, value: &Fq) {
    value.0.serialize_uncompressed(&mut *out).unwrap();
}

fn put_g1(out: &mut Vec<u8>, point: &G1Affine) {
    put_fq(out, &point.x);
    put_fq(out, &point.y);
}

fn put_g2(out: &mut Vec<u8>, point: &G2Affine) {
    put_fq(out, &point.x.c0);
    put_fq(out, &point.x.c1);
    put_fq(out, &point.y.c0);
    put_fq(out, &point.y.c1);
}

/// snarkjs stores coefficients as `value · R²` (Montgomery form of `value · R`).
fn put_coefficient(out: &mut Vec<u8>, value: &Fr) {
    let r = Fr::from(2u64).pow([256]);
    (*value * r).0.serialize_uncompressed(&mut *out).unwrap();
}

fn section(out: &mut Vec<u8>, id: u32, body: Vec<u8>) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(&body);
}

/// A snarkjs Groth16 zkey (sections 1–9) for `pk` over `matrices`.
fn write_zkey(pk: &ProvingKey<Bn254>, matrices: &ConstraintMatrices<Fr>) -> Vec<u8> {
    let n_public = matrices.num_instance_variables - 1;
    let n_vars = matrices.num_instance_variables + matrices.num_witness_variables;
    let mut out = b"zkey".to_vec();
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&9u32.to_le_bytes());
    section(&mut out, 1, 1u32.to_le_bytes().to_vec());

    let mut header = Vec::new();
    header.extend_from_slice(&32u32.to_le_bytes());
    Fq::MODULUS.serialize_uncompressed(&mut header).unwrap();
    header.extend_from_slice(&32u32.to_le_bytes());
    Fr::MODULUS.serialize_uncompressed(&mut header).unwrap();
    header.extend_from_slice(&(n_vars as u32).to_le_bytes());
    header.extend_from_slice(&(n_public as u32).to_le_bytes());
    header.extend_from_slice(&(pk.h_query.len() as u32).to_le_bytes());
    put_g1(&mut header, &pk.vk.alpha_g1);
    put_g1(&mut header, &pk.beta_g1);
    put_g2(&mut header, &pk.vk.beta_g2);
    put_g2(&mut header, &pk.vk.gamma_g2);
    put_g1(&mut header, &pk.delta_g1);
    put_g2(&mut header, &pk.vk.delta_g2);
    section(&mut out, 2, header);

    let mut ic = Vec::new();
    pk.vk
        .gamma_abc_g1
        .iter()
        .for_each(|point| put_g1(&mut ic, point));
    section(&mut out, 3, ic);

    let mut entries = Vec::new();
    let mut count = 0u32;
    for (matrix_id, matrix) in [(0u32, &matrices.a), (1u32, &matrices.b)] {
        for (row, terms) in matrix.iter().enumerate() {
            for (value, wire) in terms {
                entries.extend_from_slice(&matrix_id.to_le_bytes());
                entries.extend_from_slice(&(row as u32).to_le_bytes());
                entries.extend_from_slice(&(*wire as u32).to_le_bytes());
                put_coefficient(&mut entries, value);
                count += 1;
            }
        }
    }
    // The rows binding each instance variable, as snarkjs adds them.
    for input in 0..=n_public {
        entries.extend_from_slice(&0u32.to_le_bytes());
        entries.extend_from_slice(&((matrices.num_constraints + input) as u32).to_le_bytes());
        entries.extend_from_slice(&(input as u32).to_le_bytes());
        put_coefficient(&mut entries, &Fr::ONE);
        count += 1;
    }
    let mut coefficients = count.to_le_bytes().to_vec();
    coefficients.extend_from_slice(&entries);
    section(&mut out, 4, coefficients);

    let g1_section = |points: &[G1Affine]| {
        let mut body = Vec::new();
        points.iter().for_each(|point| put_g1(&mut body, point));
        body
    };
    section(&mut out, 5, g1_section(&pk.a_query));
    section(&mut out, 6, g1_section(&pk.b_g1_query));
    let mut b2 = Vec::new();
    pk.b_g2_query
        .iter()
        .for_each(|point| put_g2(&mut b2, point));
    section(&mut out, 7, b2);
    section(&mut out, 8, g1_section(&pk.l_query));
    section(&mut out, 9, g1_section(&pk.h_query));
    assert_eq!(pk.a_query.len(), n_vars);
    out
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("zkey-import-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn dev_zkeys(dir: &Path) -> (PathBuf, PathBuf) {
    let mut paths = Vec::new();
    for kind in [KeyKind::Request, KeyKind::Withdrawal] {
        let bytes = std::fs::read(setup_dir().join(kind.proving_key_file())).unwrap();
        let (pk, _): (ProvingKey<Bn254>, _) = decode_compressed(&bytes, kind).unwrap();
        let zkey = write_zkey(&pk, &circuit_matrices(kind).unwrap());
        // ark-circom reads back exactly the development key.
        let (read, _) = ark_circom::read_zkey(&mut std::io::Cursor::new(&zkey)).unwrap();
        assert_eq!(read, pk, "{kind}");
        let path = dir.join(format!("{kind}.zkey"));
        std::fs::write(&path, zkey).unwrap();
        paths.push(path);
    }
    (paths[0].clone(), paths[1].clone())
}

#[test]
fn import_zkey_round_trips_the_development_setup() {
    let dir = scratch("roundtrip");
    let (request_zkey, withdrawal_zkey) = dev_zkeys(&dir);
    let output = dir.join("setup");
    import(&ImportArgs {
        request_zkey,
        withdrawal_zkey,
        setup_id: DEV_SETUP_ID.to_string(),
        provenance: SetupProvenance::default(),
        output: output.clone(),
    })
    .unwrap();
    for file in [
        "request.pk",
        "request.vk",
        "withdrawal.pk",
        "withdrawal.vk",
        "manifest.json",
        "Groth16ProofAdapter.sol",
        "Bn254Poseidon.sol",
    ] {
        assert!(
            std::fs::read(output.join(file)).unwrap()
                == std::fs::read(setup_dir().join(file)).unwrap(),
            "{file} differs after the zkey round trip"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn import_zkey_refuses_foreign_constraints() {
    let dir = scratch("foreign");
    let (request_zkey, withdrawal_zkey) = dev_zkeys(&dir);
    // Swapped circuits fail the fidelity gate.
    let error = import(&ImportArgs {
        request_zkey: withdrawal_zkey.clone(),
        withdrawal_zkey: request_zkey.clone(),
        setup_id: "mpc-1".to_string(),
        provenance: SetupProvenance::default(),
        output: dir.join("swapped"),
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("request zkey"), "{error}");
    // One changed A coefficient fails it too.
    let bytes = std::fs::read(setup_dir().join("request.pk")).unwrap();
    let (pk, _): (ProvingKey<Bn254>, _) = decode_compressed(&bytes, KeyKind::Request).unwrap();
    let mut matrices = circuit_matrices(KeyKind::Request).unwrap();
    let row = matrices.a.iter().position(|row| !row.is_empty()).unwrap();
    matrices.a[row][0].0 += Fr::ONE;
    let tampered = dir.join("tampered.zkey");
    std::fs::write(&tampered, write_zkey(&pk, &matrices)).unwrap();
    let error = import(&ImportArgs {
        request_zkey: tampered,
        withdrawal_zkey,
        setup_id: "mpc-1".to_string(),
        provenance: SetupProvenance::default(),
        output: dir.join("tampered-setup"),
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("A matrix differs"), "{error}");
    assert!(!dir.join("tampered-setup").exists());
    let _ = std::fs::remove_dir_all(dir);
}

/// Fidelity gate (c) on real ceremony output: the A and B matrices of the
/// final zkeys (read by `ark_circom::read_zkey`) equal the synthesized ones,
/// and the shipping prover's proofs verify under them. Run after the
/// ceremony with
/// `ZKAPI_REQUEST_ZKEY=... ZKAPI_WITHDRAWAL_ZKEY=... cargo test --release
/// -p zkapi-proof --test zkey_import zkey_matrices_match -- --ignored`.
#[test]
#[ignore = "needs ceremony zkeys in ZKAPI_REQUEST_ZKEY and ZKAPI_WITHDRAWAL_ZKEY"]
fn zkey_matrices_match() {
    for (variable, kind) in [
        ("ZKAPI_REQUEST_ZKEY", KeyKind::Request),
        ("ZKAPI_WITHDRAWAL_ZKEY", KeyKind::Withdrawal),
    ] {
        let path = std::env::var(variable).unwrap_or_else(|_| panic!("set {variable}"));
        import_zkey::read_checked_zkey(Path::new(&path), kind).unwrap();
    }
}
