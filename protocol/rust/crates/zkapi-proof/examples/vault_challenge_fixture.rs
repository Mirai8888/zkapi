//! Regenerate the real-proof vault regression fixture with the selected setup:
//! cargo run --release -p zkapi-proof --example vault_challenge_fixture -- ../setup/v2 \
//!   > ../contracts/test/fixtures/vault-challenge.json
use anyhow::{Context, Result};
use base64::Engine;
use serde::Serialize;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    balance_commitment, rerandomize, CompactSigner, RequestProver, RequestVerifier,
    RequestWitnessData, WithdrawalProver, WithdrawalVerifier, WithdrawalWitnessData, CIRCUIT_ID,
};
use zkapi_types::{
    wire::Groth16ProofWire, Felt252, RequestPublicInputsV2, SchnorrSignature,
    WithdrawalPublicInputsV2, MERKLE_DEPTH,
};

const TIMESTAMP: u64 = 2_000_000_000;
const NOTE_TTL: u64 = 30 * 86_400;
const DEPOSIT: u128 = 1_000_000;
// CREATE from address(0xf00d), nonce 0. The Forge test deploys normally there.
const VAULT: &str = "0xFb1b848e938aE6474F890bfb28f6a793a515BAcb";

#[derive(Serialize)]
struct Fixture {
    inputs_abi: String,
    proof_hex: String,
}

#[derive(Serialize)]
struct Fixtures {
    circuit_id: &'static str,
    note_a_registration: String,
    note_b_registration: String,
    request_before_deposit: Fixture,
    request_before_close: Fixture,
    escape_after_deposit: Fixture,
    escape_after_close: Fixture,
    close_b: Fixture,
    close_a_after_deposit: Fixture,
    escape_after_deposit_other_destination: Fixture,
    escape_next_after_deposit: Fixture,
}

struct Generator {
    requests: RequestProver,
    request_verifier: RequestVerifier,
    withdrawals: WithdrawalProver,
    withdrawal_verifier: WithdrawalVerifier,
    state_signer: CompactSigner,
    clearance_signer: CompactSigner,
    expiry: u64,
    vault: Felt252,
}

#[derive(Clone)]
struct Note {
    id: u32,
    secret: Felt252,
    balance: u128,
    blinding: Felt252,
    anchor: Felt252,
    signature: Option<SchnorrSignature>,
}

impl Generator {
    fn leaf(&self, note: &Note) -> Felt252 {
        core::note_leaf(
            note.id,
            &core::registration_commitment(&note.secret),
            DEPOSIT,
            self.expiry,
        )
    }

    /// The operator's state signature over the note's balance commitment and anchor.
    fn sign_state(&self, note: &Note) -> SchnorrSignature {
        let commitment = balance_commitment(note.balance, &note.blinding, &self.leaf(note));
        self.state_signer.sign(&core::state_message(
            2,
            31_337,
            &self.vault,
            &commitment.x,
            &commitment.y,
            &note.anchor,
        ))
    }

    fn request(&self, note: &Note, siblings: [Felt252; MERKLE_DEPTH]) -> Result<Fixture> {
        let key = self.state_signer.public_key();
        let leaf = self.leaf(note);
        let context = Felt252::from_u64(99);
        let rerandomization = Felt252::from_u64(9);
        let anonymous = rerandomize(
            &balance_commitment(note.balance, &note.blinding, &leaf),
            &rerandomization,
        )?;
        let nullifier = core::nullifier(&note.secret, &note.anchor);
        let public = RequestPublicInputsV2 {
            protocol_version: 2,
            chain_id: 31_337,
            contract_address: self.vault,
            active_root: core::merkle_root(note.id, &leaf, &siblings),
            state_signing_key_x: key.x,
            state_signing_key_y: key.y,
            request_time: TIMESTAMP,
            solvency_bound: 100_000,
            request_nullifier: nullifier,
            authorization_tag: core::authorization_tag(&nullifier, &context),
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        };
        let proof = self.requests.prove(
            &public,
            RequestWitnessData {
                secret: note.secret,
                request_context: context,
                note_id: note.id,
                deposit_amount: DEPOSIT,
                expiry: self.expiry,
                merkle_siblings: siblings,
                current_balance: note.balance,
                current_blinding: note.blinding,
                rerandomization,
                current_anchor: note.anchor,
                is_genesis: note.signature.is_none(),
                state_signature: note.signature,
            },
        )?;
        anyhow::ensure!(
            self.request_verifier.verify(&public, &proof)?,
            "request proof failed"
        );
        fixture(&public.to_field_elements(), &proof)
    }

    fn withdrawal(
        &self,
        note: &Note,
        siblings: [Felt252; MERKLE_DEPTH],
        clearance: bool,
    ) -> Result<Fixture> {
        self.withdrawal_to(note, siblings, clearance, [0x11; 20])
    }

    fn withdrawal_to(
        &self,
        note: &Note,
        siblings: [Felt252; MERKLE_DEPTH],
        clearance: bool,
        destination: [u8; 20],
    ) -> Result<Fixture> {
        let key = self.state_signer.public_key();
        let clear_key = self.clearance_signer.public_key();
        let nullifier = core::nullifier(&note.secret, &note.anchor);
        let mut public = WithdrawalPublicInputsV2 {
            protocol_version: 2,
            chain_id: 31_337,
            contract_address: self.vault,
            active_root: core::merkle_root(note.id, &self.leaf(note), &siblings),
            state_signing_key_x: key.x,
            state_signing_key_y: key.y,
            clearance_signing_key_x: clear_key.x,
            clearance_signing_key_y: clear_key.y,
            note_id: note.id,
            final_balance: note.balance,
            destination,
            withdrawal_nullifier: nullifier,
            has_clearance: clearance,
            withdrawal_tag: Felt252::ZERO,
        };
        public.withdrawal_tag = core::withdrawal_tag(
            &nullifier,
            &public.destination_field(),
            note.balance,
            clearance,
        );
        let proof = self.withdrawals.prove(
            &public,
            WithdrawalWitnessData {
                secret: note.secret,
                deposit_amount: DEPOSIT,
                expiry: self.expiry,
                merkle_siblings: siblings,
                final_blinding: note.blinding,
                current_anchor: note.anchor,
                is_genesis: note.signature.is_none(),
                state_signature: note.signature,
                clearance_signature: clearance.then(|| {
                    self.clearance_signer.sign(&core::clearance_message(
                        2,
                        31_337,
                        &self.vault,
                        &nullifier,
                    ))
                }),
            },
        )?;
        anyhow::ensure!(
            self.withdrawal_verifier.verify(&public, &proof)?,
            "withdrawal proof failed"
        );
        fixture(&public.to_field_elements(), &proof)
    }
}

fn fixture(inputs: &[Felt252], proof: &Groth16ProofWire) -> Result<Fixture> {
    // Both Solidity public-input structs are static ABI tuples in this order.
    let inputs = inputs
        .iter()
        .flat_map(|field| field.as_bytes().iter().copied())
        .collect::<Vec<_>>();
    let proof = base64::engine::general_purpose::STANDARD.decode(&proof.proof)?;
    Ok(Fixture {
        inputs_abi: format!("0x{}", hex::encode(inputs)),
        proof_hex: format!("0x{}", hex::encode(proof)),
    })
}

fn main() -> Result<()> {
    let setup = std::env::args()
        .nth(1)
        .context("usage: vault_challenge_fixture SETUP_DIRECTORY")?;
    let generator = Generator {
        requests: RequestProver::load(&setup)?,
        request_verifier: RequestVerifier::load(&setup)?,
        withdrawals: WithdrawalProver::load(&setup)?,
        withdrawal_verifier: WithdrawalVerifier::load(&setup)?,
        state_signer: CompactSigner::from_seed(&Felt252::from_u64(1)),
        clearance_signer: CompactSigner::from_seed(&Felt252::from_u64(2)),
        expiry: (TIMESTAMP + NOTE_TTL).div_ceil(86_400) * 86_400,
        vault: Felt252::from_hex(VAULT).map_err(anyhow::Error::msg)?,
    };
    // A has genuine signed non-genesis state. Its historical request and stale
    // escape use that identical state under different active Merkle roots.
    let mut a = Note {
        id: 0,
        secret: Felt252::from_u64(42),
        balance: 900_000,
        blinding: Felt252::from_u64(7),
        anchor: Felt252::from_u64(12_345),
        signature: None,
    };
    a.signature = Some(generator.sign_state(&a));
    // The successor state the operator signs when it settles A's request: a lower
    // balance under a fresh anchor, so its nullifier is one no request has spent.
    let mut a_next = Note {
        balance: 850_000,
        blinding: Felt252::from_u64(17),
        anchor: Felt252::from_u64(67_890),
        signature: None,
        ..a.clone()
    };
    a_next.signature = Some(generator.sign_state(&a_next));
    let b = Note {
        id: 1,
        secret: Felt252::from_u64(43),
        balance: DEPOSIT,
        blinding: Felt252::from_u64(8),
        anchor: Felt252::ONE,
        signature: None,
    };
    let empty: [Felt252; MERKLE_DEPTH] = core::zero_hashes()[..MERKLE_DEPTH].try_into().unwrap();
    let mut a_with_b = empty;
    a_with_b[0] = generator.leaf(&b);
    let mut b_with_a = empty;
    b_with_a[0] = generator.leaf(&a);
    let fixtures = Fixtures {
        circuit_id: CIRCUIT_ID,
        note_a_registration: format!(
            "0x{}",
            hex::encode(core::registration_commitment(&a.secret).as_bytes())
        ),
        note_b_registration: format!(
            "0x{}",
            hex::encode(core::registration_commitment(&b.secret).as_bytes())
        ),
        request_before_deposit: generator.request(&a, empty)?,
        request_before_close: generator.request(&a, a_with_b)?,
        escape_after_deposit: generator.withdrawal(&a, a_with_b, false)?,
        escape_after_close: generator.withdrawal(&a, empty, false)?,
        close_b: generator.withdrawal(&b, b_with_a, true)?,
        // Clearance-backed close of A's challenged anchor at the two-note root.
        close_a_after_deposit: generator.withdrawal(&a, a_with_b, true)?,
        // A's challenged anchor escaping to another destination.
        escape_after_deposit_other_destination: generator
            .withdrawal_to(&a, a_with_b, false, [0x22; 20])?,
        // The honest exit after a challenge: escape from the signed successor state.
        escape_next_after_deposit: generator.withdrawal(&a_next, a_with_b, false)?,
    };
    println!("{}", serde_json::to_string_pretty(&fixtures)?);
    Ok(())
}
