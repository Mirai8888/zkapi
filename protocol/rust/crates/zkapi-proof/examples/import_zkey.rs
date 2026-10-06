//! Import the snarkjs phase-2 keys of the ceremony (G-SETUP step 6):
//!
//! ```text
//! cargo run --release -p zkapi-proof --example import_zkey -- \
//!   --request request_final.zkey --withdrawal withdrawal_final.zkey \
//!   [--setup-id mpc-1] [--ptau-sha256 HEX] [--transcript-sha256 HEX] \
//!   OUTPUT_DIRECTORY
//! ```
//!
//! For each zkey (read with `ark_circom::read_zkey`):
//! 1. fidelity gate (c): the zkey's A and B matrices, constraint count and
//!    variable counts equal the circuit synthesized by this build (snarkjs
//!    stores no C matrix; C is checked by the R1CS export round trip);
//! 2. shape: 13 / 17 IC points and an H query of the QAP domain size;
//! 3. proving gate: a canonical statement is proved with the shipping
//!    `CircomReduction` prover and verified with the imported key, and a
//!    mutated input is rejected.
//!
//! Then it writes the setup directory (keys with
//! `zkapi-v2-concession-v1/<setup_id>/<kind>` headers, `manifest.json` with the
//! ptau and transcript hashes, `Bn254Poseidon.sol` and the regenerated
//! `Groth16ProofAdapter.sol` with the VK hashes). It refuses to overwrite any
//! of those files.
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::{Bn254, Fr};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use zkapi_proof::compact::{
    circuit_shape, request_circuit, withdrawal_circuit, write_setup_directory, KeyKind, Prover,
    SetupManifest, SetupProvenance, CEREMONY_SETUP_ID, REQUEST_PROVING_KEY_FILE,
    REQUEST_VERIFYING_KEY_FILE, SETUP_MANIFEST_FILE, SOLIDITY_POSEIDON_FILE,
    SOLIDITY_VERIFIER_FILE, WITHDRAWAL_PROVING_KEY_FILE, WITHDRAWAL_VERIFYING_KEY_FILE,
};
use zkapi_proof::dev::{tree_with, DevDeployment, DevNote, DevRequest, DevWithdrawal};
use zkapi_proof::groth16::verify_field_elements;
use zkapi_proof::r1cs::circuit_matrices;
use zkapi_types::{Felt252, WithdrawalKind};

/// Arguments of one import.
#[derive(Clone, Debug)]
pub struct ImportArgs {
    pub request_zkey: PathBuf,
    pub withdrawal_zkey: PathBuf,
    pub setup_id: String,
    pub provenance: SetupProvenance,
    pub output: PathBuf,
}

/// Read a zkey and run the fidelity, shape and proving gates for `kind`.
pub fn read_checked_zkey(path: &Path, kind: KeyKind) -> Result<ProvingKey<Bn254>> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let (pk, matrices) = ark_circom::read_zkey(&mut reader)
        .map_err(|error| anyhow!("read {}: {error}", path.display()))?;
    check_matrices(&matrices, &pk, kind)?;
    check_shape(&pk, kind)?;
    check_proving(&pk, kind)?;
    Ok(pk)
}

fn sorted_rows(rows: &[Vec<(Fr, usize)>]) -> Vec<Vec<(usize, Fr)>> {
    rows.iter()
        .map(|row| {
            let mut row: Vec<(usize, Fr)> =
                row.iter().map(|(value, wire)| (*wire, *value)).collect();
            row.sort_by_key(|(wire, _)| *wire);
            row
        })
        .collect()
}

/// Fidelity gate (c): the ceremony's constraints are this build's.
pub fn check_matrices(
    zkey: &ConstraintMatrices<Fr>,
    pk: &ProvingKey<Bn254>,
    kind: KeyKind,
) -> Result<()> {
    let ours = circuit_matrices(kind)?;
    ensure!(
        zkey.num_instance_variables == ours.num_instance_variables,
        "{kind} zkey has {} instance variables, the circuit {}",
        zkey.num_instance_variables,
        ours.num_instance_variables
    );
    ensure!(
        zkey.num_constraints == ours.num_constraints,
        "{kind} zkey has {} constraints, the circuit {}",
        zkey.num_constraints,
        ours.num_constraints
    );
    let variables = ours.num_instance_variables + ours.num_witness_variables;
    ensure!(
        pk.a_query.len() == variables && pk.b_g2_query.len() == variables,
        "{kind} zkey has {} variables, the circuit {variables}",
        pk.a_query.len()
    );
    ensure!(
        pk.l_query.len() == ours.num_witness_variables,
        "{kind} zkey has {} private variables, the circuit {}",
        pk.l_query.len(),
        ours.num_witness_variables
    );
    ensure!(
        sorted_rows(&zkey.a) == sorted_rows(&ours.a),
        "{kind} zkey A matrix differs from the circuit"
    );
    ensure!(
        sorted_rows(&zkey.b) == sorted_rows(&ours.b),
        "{kind} zkey B matrix differs from the circuit"
    );
    Ok(())
}

fn check_shape(pk: &ProvingKey<Bn254>, kind: KeyKind) -> Result<()> {
    let shape = circuit_shape(kind)?;
    ensure!(
        pk.vk.gamma_abc_g1.len() == kind.public_inputs() + 1,
        "{kind} zkey has {} IC points",
        pk.vk.gamma_abc_g1.len()
    );
    ensure!(
        pk.h_query.len() == shape.domain_size,
        "{kind} zkey H query has {} points, expected the domain size {}",
        pk.h_query.len(),
        shape.domain_size
    );
    Ok(())
}

/// Proving gate: the shipping prover's proof of a canonical statement
/// verifies under the imported key, and a mutated input does not.
fn check_proving(pk: &ProvingKey<Bn254>, kind: KeyKind) -> Result<()> {
    let deployment = DevDeployment::new(31_337, Felt252::from_u64(0x1234));
    let note = DevNote {
        secret: Felt252::from_u64(42),
        note_id: 0,
        deposit_amount: 1_000_000,
        expiry: 4_000_000_000,
    };
    let tree = tree_with(&[&note]);
    let request = DevRequest {
        request_time: 2_000_000_000,
        solvency_bound: 100_000,
        request_context: Felt252::from_u64(99),
        rerandomization: Felt252::from_u64(9),
    };
    let state = note.genesis(Felt252::from_u64(7)).successor(
        &deployment,
        &request,
        60_000,
        &Felt252::from_u64(17),
    )?;
    let mut rng = rand::rngs::OsRng;
    let (inputs, proof) = match kind {
        KeyKind::Request => {
            let (public, witness) = state.request(&deployment, &tree, &request)?;
            let circuit = request_circuit(&public, &witness)?;
            let proof = <Prover as ark_snark::SNARK<Fr>>::prove(pk, circuit, &mut rng)?;
            (public.to_field_elements().to_vec(), proof)
        }
        KeyKind::Withdrawal => {
            let (public, witness) = state.withdrawal(
                &deployment,
                &tree,
                &DevWithdrawal {
                    kind: WithdrawalKind::Escape,
                    destination: [0xff; 20],
                    conceded: 50_000,
                    valid_until: 2_000_010_800,
                },
            )?;
            let circuit = withdrawal_circuit(&public, &witness)?;
            let proof = <Prover as ark_snark::SNARK<Fr>>::prove(pk, circuit, &mut rng)?;
            (public.to_field_elements().to_vec(), proof)
        }
    };
    let mut fields: Vec<Fr> = inputs.iter().map(zkapi_core::v2::felt_to_field).collect();
    ensure!(
        verify_field_elements(&pk.vk, &fields, &proof)?,
        "{kind} proving gate: the CircomReduction proof does not verify under the imported key"
    );
    fields[kind.public_inputs() - 1] += Fr::from(1u64);
    ensure!(
        !verify_field_elements(&pk.vk, &fields, &proof)?,
        "{kind} proving gate: a mutated statement verifies"
    );
    Ok(())
}

/// Import both zkeys and write the setup directory. The directory may exist
/// (for example holding only its README) but must hold none of the files the
/// import writes.
pub fn import(args: &ImportArgs) -> Result<SetupManifest> {
    for file in [
        REQUEST_PROVING_KEY_FILE,
        REQUEST_VERIFYING_KEY_FILE,
        WITHDRAWAL_PROVING_KEY_FILE,
        WITHDRAWAL_VERIFYING_KEY_FILE,
        SETUP_MANIFEST_FILE,
        SOLIDITY_POSEIDON_FILE,
        SOLIDITY_VERIFIER_FILE,
    ] {
        ensure!(
            !args.output.join(file).exists(),
            "refusing to overwrite {} in {}",
            file,
            args.output.display()
        );
    }
    let request = read_checked_zkey(&args.request_zkey, KeyKind::Request)?;
    let withdrawal = read_checked_zkey(&args.withdrawal_zkey, KeyKind::Withdrawal)?;
    write_setup_directory(
        &args.output,
        &args.setup_id,
        &request,
        &withdrawal,
        &args.provenance,
    )
}

fn parse_args() -> Result<ImportArgs> {
    let mut request = None;
    let mut withdrawal = None;
    let mut setup_id = CEREMONY_SETUP_ID.to_string();
    let mut provenance = SetupProvenance::default();
    let mut output = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| anyhow!("{arg} needs a value"));
        match arg.as_str() {
            "--request" => request = Some(PathBuf::from(value()?)),
            "--withdrawal" => withdrawal = Some(PathBuf::from(value()?)),
            "--setup-id" => setup_id = value()?,
            "--ptau-sha256" => provenance.ptau_sha256 = Some(hex_digest(&value()?)?),
            "--transcript-sha256" => provenance.transcript_sha256 = Some(hex_digest(&value()?)?),
            flag if flag.starts_with("--") => bail!("unknown option {flag}"),
            path => {
                ensure!(output.is_none(), "one output directory");
                output = Some(PathBuf::from(path));
            }
        }
    }
    Ok(ImportArgs {
        request_zkey: request.context("--request ZKEY is required")?,
        withdrawal_zkey: withdrawal.context("--withdrawal ZKEY is required")?,
        setup_id,
        provenance,
        output: output.context("OUTPUT_DIRECTORY is required")?,
    })
}

fn hex_digest(value: &str) -> Result<String> {
    let value = value.trim_start_matches("0x").to_ascii_lowercase();
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "a SHA-256 digest is 64 hex characters"
    );
    Ok(value)
}

#[allow(dead_code)]
fn main() -> Result<()> {
    let args = parse_args()?;
    if args.setup_id == CEREMONY_SETUP_ID {
        ensure!(
            args.provenance.ptau_sha256.is_some() && args.provenance.transcript_sha256.is_some(),
            "the ceremony setup records --ptau-sha256 and --transcript-sha256"
        );
    }
    let manifest = import(&args)?;
    println!(
        "imported {} setup {} into {}\nrequest VK keccak256 {}\nwithdrawal VK keccak256 {}",
        manifest.circuit_id,
        manifest.setup_id,
        args.output.display(),
        manifest.vk_keccak256.request,
        manifest.vk_keccak256.withdrawal
    );
    Ok(())
}
