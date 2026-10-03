//! Compact zkAPI v2 request proof over BN254.
//!
//! The circuit uses Poseidon over the BN254 scalar field, a note-bound
//! Baby-JubJub Pedersen balance commitment, and a Poseidon-
//! challenged Schnorr state signature. Exact balance, note identity, expiry,
//! state anchor, and server signature stay private. The request context is
//! bound through a public authorization tag while the state nullifier remains
//! independent of the payload, so one state cannot authorize two requests.

use std::ops::Not;
use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr as CircuitField};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::{AdditiveGroup, AffineRepr, CurveConfig, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{
    constraints::EdwardsVar, EdwardsAffine, EdwardsConfig, EdwardsProjective,
    Fq as EdwardsBaseField, Fr as EdwardsScalarField,
};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::cmp::CmpGadget;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::{UInt128, UInt32, UInt64};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{CryptoRng, RngCore};
use sha3::{Digest, Keccak256};

pub const REQUEST_PUBLIC_INPUTS: usize = 12;
pub const WITHDRAWAL_PUBLIC_INPUTS: usize = 14;
pub const REQUEST_MERKLE_DEPTH: usize = 32;

const DOMAIN_REG: &[u8] = b"zkapi.v2.reg";
const DOMAIN_LEAF: &[u8] = b"zkapi.v2.leaf";
const DOMAIN_NODE: &[u8] = b"zkapi.v2.node";
const DOMAIN_NULLIFIER: &[u8] = b"zkapi.v2.null";
const DOMAIN_AUTHORIZATION: &[u8] = b"zkapi.v2.auth";
const DOMAIN_STATE: &[u8] = b"zkapi.v2.state";
const DOMAIN_CLEARANCE: &[u8] = b"zkapi.v2.clear";
const DOMAIN_WITHDRAWAL: &[u8] = b"zkapi.v2.withdraw";
const DOMAIN_SIGNATURE: &[u8] = b"zkapi.v2.sig";

pub(crate) fn poseidon_config() -> &'static PoseidonConfig<CircuitField> {
    static CONFIG: OnceLock<PoseidonConfig<CircuitField>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let full_rounds = 8;
        let partial_rounds = 57;
        let rate = 2;
        let (ark, mds) = find_poseidon_ark_and_mds::<CircuitField>(
            CircuitField::MODULUS_BIT_SIZE as u64,
            rate,
            full_rounds,
            partial_rounds,
            0,
        );
        PoseidonConfig::new(
            full_rounds as usize,
            partial_rounds as usize,
            5,
            mds,
            ark,
            rate,
            1,
        )
    })
}

pub fn poseidon_hash(inputs: &[CircuitField]) -> CircuitField {
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.absorb(&inputs);
    sponge.squeeze_native_field_elements(1)[0]
}

fn poseidon_hash_var(
    cs: ConstraintSystemRef<CircuitField>,
    inputs: &[FpVar<CircuitField>],
) -> Result<FpVar<CircuitField>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    sponge.absorb(&inputs)?;
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

fn domain(label: &[u8]) -> CircuitField {
    CircuitField::from_be_bytes_mod_order(label)
}

fn domain_var(label: &[u8]) -> FpVar<CircuitField> {
    FpVar::Constant(domain(label))
}

/// Independently derived blinding generator. Its discrete logarithm relative
/// to the standard Baby-JubJub generator is not known.
pub fn balance_blinding_generator() -> EdwardsProjective {
    static GENERATOR: OnceLock<EdwardsProjective> = OnceLock::new();
    *GENERATOR.get_or_init(|| derive_generator(b"zkapi.v2.balance.blinding.generator"))
}

/// Independent third Pedersen generator for the private active-note leaf.
/// Do not derive this as a known scalar multiple of G or H: that would let
/// a client absorb a different note binding into the balance or blinding.
pub fn note_binding_generator() -> EdwardsProjective {
    static GENERATOR: OnceLock<EdwardsProjective> = OnceLock::new();
    *GENERATOR.get_or_init(|| derive_generator(b"zkapi.v2.note-binding.generator.v1"))
}

fn derive_generator(label: &[u8]) -> EdwardsProjective {
    for counter in 0u32..u32::MAX {
        let mut digest = Keccak256::new();
        digest.update(label);
        digest.update(counter.to_be_bytes());
        let x = EdwardsBaseField::from_be_bytes_mod_order(&digest.finalize());
        let x_squared = x.square();
        let numerator = EdwardsBaseField::ONE - x_squared;
        let denominator = EdwardsBaseField::ONE - (EdwardsConfig::COEFF_D * x_squared);
        let Some(denominator_inverse) = denominator.inverse() else {
            continue;
        };
        let Some(mut y) = (numerator * denominator_inverse).sqrt() else {
            continue;
        };
        if y.into_bigint().is_odd() {
            y = -y;
        }
        let point = EdwardsAffine::new_unchecked(x, y)
            .mul_bigint(EdwardsConfig::COFACTOR)
            .into_affine();
        if !point.is_zero() && point.is_in_correct_subgroup_assuming_on_curve() {
            return point.into_group();
        }
    }
    unreachable!("hash-to-curve counter exhausted")
}

/// C = balance*G + blinding*H + note_leaf*J. The full canonical field
/// representation of the leaf is multiplied by J (implicitly modulo its
/// prime subgroup order), identically to the circuit's bit decomposition.
pub fn balance_commitment(
    balance: u128,
    blinding: EdwardsScalarField,
    note_leaf: CircuitField,
) -> EdwardsProjective {
    EdwardsProjective::generator().mul_bigint(EdwardsScalarField::from(balance).into_bigint())
        + balance_blinding_generator().mul_bigint(blinding.into_bigint())
        + note_binding_generator().mul_bigint(note_leaf.into_bigint())
}

pub fn rerandomize_commitment(
    commitment: EdwardsProjective,
    rerandomization: EdwardsScalarField,
) -> EdwardsProjective {
    commitment + balance_blinding_generator().mul_bigint(rerandomization.into_bigint())
}

#[derive(Clone, Debug)]
pub struct StateSigningKey {
    secret: EdwardsScalarField,
    pub public: EdwardsAffine,
}

impl StateSigningKey {
    /// A zero secret is never remapped: it would silently become a public key.
    pub fn from_secret(secret: EdwardsScalarField) -> Self {
        assert!(
            secret != EdwardsScalarField::ZERO,
            "Schnorr signing secret must be nonzero"
        );
        let public = EdwardsProjective::generator()
            .mul_bigint(secret.into_bigint())
            .into_affine();
        Self { secret, public }
    }

    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        loop {
            let secret = EdwardsScalarField::rand(rng);
            if secret != EdwardsScalarField::ZERO {
                return Self::from_secret(secret);
            }
        }
    }

    pub fn sign(
        &self,
        message: CircuitField,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> StateSignature {
        let nonce = EdwardsScalarField::rand(rng);
        let r = EdwardsProjective::generator()
            .mul_bigint(nonce.into_bigint())
            .into_affine();
        let challenge = signature_challenge(r, message);
        let s = nonce + (challenge * self.secret);
        StateSignature { r, s }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StateSignature {
    pub r: EdwardsAffine,
    pub s: EdwardsScalarField,
}

pub fn state_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: CircuitField,
    commitment: EdwardsAffine,
    anchor: CircuitField,
) -> CircuitField {
    poseidon_hash(&[
        domain(DOMAIN_STATE),
        CircuitField::from(protocol_version as u64),
        CircuitField::from(chain_id),
        contract_address,
        commitment.x,
        commitment.y,
        anchor,
    ])
}

pub fn clearance_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: CircuitField,
    withdrawal_nullifier: CircuitField,
) -> CircuitField {
    poseidon_hash(&[
        domain(DOMAIN_CLEARANCE),
        CircuitField::from(protocol_version as u64),
        CircuitField::from(chain_id),
        contract_address,
        withdrawal_nullifier,
    ])
}

fn signature_challenge(r: EdwardsAffine, message: CircuitField) -> EdwardsScalarField {
    let hash = poseidon_hash(&[domain(DOMAIN_SIGNATURE), r.x, r.y, message]);
    EdwardsScalarField::from_le_bytes_mod_order(&hash.into_bigint().to_bytes_le())
}

pub fn verify_state_signature(
    public: EdwardsAffine,
    message: CircuitField,
    signature: StateSignature,
) -> bool {
    let challenge = signature_challenge(signature.r, message);
    let lhs = EdwardsProjective::generator().mul_bigint(signature.s.into_bigint());
    let rhs = signature.r.into_group() + public.mul_bigint(challenge.into_bigint());
    lhs == rhs
}

fn scalar_bits_witness(
    cs: ConstraintSystemRef<CircuitField>,
    value: EdwardsScalarField,
) -> Result<Vec<Boolean<CircuitField>>, SynthesisError> {
    let native_bits = value.into_bigint().to_bits_le();
    (0..EdwardsScalarField::MODULUS_BIT_SIZE as usize)
        .map(|index| {
            Boolean::new_witness(cs.clone(), || {
                Ok(native_bits.get(index).copied().unwrap_or(false))
            })
        })
        .collect()
}

fn commitment_var(
    cs: ConstraintSystemRef<CircuitField>,
    balance: &UInt128<CircuitField>,
    blinding: EdwardsScalarField,
    note_leaf: &FpVar<CircuitField>,
) -> Result<EdwardsVar, SynthesisError> {
    let g = EdwardsVar::new_constant(cs.clone(), EdwardsProjective::generator())?;
    let h = EdwardsVar::new_constant(cs.clone(), balance_blinding_generator())?;
    let j = EdwardsVar::new_constant(cs.clone(), note_binding_generator())?;
    let blinding_bits = scalar_bits_witness(cs, blinding)?;
    let note_bits = note_leaf.to_bits_le()?;
    Ok(g.scalar_mul_le(balance.bits.iter())?
        + h.scalar_mul_le(blinding_bits.iter())?
        + j.scalar_mul_le(note_bits.iter())?)
}

fn enforce_signature(
    cs: ConstraintSystemRef<CircuitField>,
    public_key: &EdwardsVar,
    message: &FpVar<CircuitField>,
    signature: StateSignature,
    condition: &Boolean<CircuitField>,
) -> Result<(), SynthesisError> {
    let r = EdwardsVar::new_witness(cs.clone(), || Ok(signature.r))?;
    let s_bits = scalar_bits_witness(cs.clone(), signature.s)?;
    let challenge_hash = poseidon_hash_var(
        cs.clone(),
        &[
            domain_var(DOMAIN_SIGNATURE),
            r.x.clone(),
            r.y.clone(),
            message.clone(),
        ],
    )?;
    let challenge_bits = challenge_hash.to_bits_le()?;
    let g = EdwardsVar::new_constant(cs, EdwardsProjective::generator())?;
    let lhs = g.scalar_mul_le(s_bits.iter())?;
    let rhs = r + public_key.scalar_mul_le(challenge_bits.iter())?;
    lhs.conditional_enforce_equal(&rhs, condition)
}

#[derive(Clone, Debug)]
pub struct RequestPublic {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: CircuitField,
    pub active_root: CircuitField,
    pub state_signing_key: EdwardsAffine,
    pub request_time: u64,
    pub solvency_bound: u128,
    pub request_nullifier: CircuitField,
    pub authorization_tag: CircuitField,
    pub anonymous_commitment: EdwardsAffine,
}

impl RequestPublic {
    pub fn to_field_elements(&self) -> Vec<CircuitField> {
        vec![
            CircuitField::from(self.protocol_version as u64),
            CircuitField::from(self.chain_id),
            self.contract_address,
            self.active_root,
            self.state_signing_key.x,
            self.state_signing_key.y,
            CircuitField::from(self.request_time),
            CircuitField::from(self.solvency_bound),
            self.request_nullifier,
            self.authorization_tag,
            self.anonymous_commitment.x,
            self.anonymous_commitment.y,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct RequestWitness {
    pub secret: CircuitField,
    pub request_context: CircuitField,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub merkle_siblings: [CircuitField; REQUEST_MERKLE_DEPTH],
    pub current_balance: u128,
    pub current_blinding: EdwardsScalarField,
    pub rerandomization: EdwardsScalarField,
    pub current_anchor: CircuitField,
    pub is_genesis: bool,
    pub state_signature: StateSignature,
}

#[derive(Clone, Debug)]
pub struct RequestCircuit {
    pub public: RequestPublic,
    pub witness: RequestWitness,
}

impl ConstraintSynthesizer<CircuitField> for RequestCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.protocol_version as u64))
        })?;
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.chain_id)))?;
        let contract_address = FpVar::new_input(cs.clone(), || Ok(self.public.contract_address))?;
        let active_root = FpVar::new_input(cs.clone(), || Ok(self.public.active_root))?;
        let state_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.state_signing_key))?;
        let request_time_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.request_time))
        })?;
        let solvency_bound_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.solvency_bound))
        })?;
        let request_nullifier = FpVar::new_input(cs.clone(), || Ok(self.public.request_nullifier))?;
        let authorization_tag = FpVar::new_input(cs.clone(), || Ok(self.public.authorization_tag))?;
        let anonymous_commitment =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.anonymous_commitment))?;

        let secret = FpVar::new_witness(cs.clone(), || Ok(self.witness.secret))?;
        secret.enforce_not_equal(&FpVar::zero())?;
        let request_context = FpVar::new_witness(cs.clone(), || Ok(self.witness.request_context))?;
        let note_id = UInt32::new_witness(cs.clone(), || Ok(self.witness.note_id))?;
        let deposit_amount = UInt128::new_witness(cs.clone(), || Ok(self.witness.deposit_amount))?;
        let expiry = UInt64::new_witness(cs.clone(), || Ok(self.witness.expiry))?;
        let balance = UInt128::new_witness(cs.clone(), || Ok(self.witness.current_balance))?;
        let request_time = UInt64::new_witness(cs.clone(), || Ok(self.public.request_time))?;
        request_time.to_fp()?.enforce_equal(&request_time_field)?;
        expiry.is_ge(&request_time)?.enforce_equal(&Boolean::TRUE)?;
        let solvency_bound = UInt128::new_witness(cs.clone(), || Ok(self.public.solvency_bound))?;
        solvency_bound
            .to_fp()?
            .enforce_equal(&solvency_bound_field)?;
        balance
            .is_ge(&solvency_bound)?
            .enforce_equal(&Boolean::TRUE)?;

        let registration = poseidon_hash_var(
            cs.clone(),
            &[domain_var(DOMAIN_REG), secret.clone(), FpVar::zero()],
        )?;
        let leaf = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_LEAF),
                note_id.to_fp()?,
                registration,
                deposit_amount.to_fp()?,
                expiry.to_fp()?,
            ],
        )?;
        let mut current = leaf.clone();
        for (level, sibling_value) in self.witness.merkle_siblings.iter().enumerate() {
            let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling_value))?;
            let bit = &note_id.bits[level];
            let left = bit.select(&sibling, &current)?;
            let right = bit.select(&current, &sibling)?;
            current = poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NODE), left, right])?;
        }
        current.enforce_equal(&active_root)?;

        let is_genesis = Boolean::new_witness(cs.clone(), || Ok(self.witness.is_genesis))?;
        let anchor = FpVar::new_witness(cs.clone(), || Ok(self.witness.current_anchor))?;
        anchor.conditional_enforce_equal(&FpVar::one(), &is_genesis)?;
        balance
            .to_fp()?
            .conditional_enforce_equal(&deposit_amount.to_fp()?, &is_genesis)?;

        let current_commitment =
            commitment_var(cs.clone(), &balance, self.witness.current_blinding, &leaf)?;
        let state_message = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_STATE),
                protocol_version,
                chain_id,
                contract_address,
                current_commitment.x.clone(),
                current_commitment.y.clone(),
                anchor.clone(),
            ],
        )?;
        enforce_signature(
            cs.clone(),
            &state_signing_key,
            &state_message,
            self.witness.state_signature,
            &is_genesis.not(),
        )?;

        let h = EdwardsVar::new_constant(cs.clone(), balance_blinding_generator())?;
        let rerandomization_bits = scalar_bits_witness(cs.clone(), self.witness.rerandomization)?;
        let computed_anonymous =
            current_commitment + h.scalar_mul_le(rerandomization_bits.iter())?;
        computed_anonymous.enforce_equal(&anonymous_commitment)?;

        let computed_nullifier =
            poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NULLIFIER), secret, anchor])?;
        computed_nullifier.enforce_equal(&request_nullifier)?;
        let computed_authorization = poseidon_hash_var(
            cs,
            &[
                domain_var(DOMAIN_AUTHORIZATION),
                request_nullifier,
                request_context,
            ],
        )?;
        computed_authorization.enforce_equal(&authorization_tag)?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct WithdrawalPublic {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: CircuitField,
    pub active_root: CircuitField,
    pub state_signing_key: EdwardsAffine,
    pub clearance_signing_key: EdwardsAffine,
    pub note_id: u32,
    pub final_balance: u128,
    pub destination: CircuitField,
    pub withdrawal_nullifier: CircuitField,
    pub has_clearance: bool,
    pub withdrawal_tag: CircuitField,
}

impl WithdrawalPublic {
    pub fn to_field_elements(&self) -> Vec<CircuitField> {
        vec![
            CircuitField::from(self.protocol_version as u64),
            CircuitField::from(self.chain_id),
            self.contract_address,
            self.active_root,
            self.state_signing_key.x,
            self.state_signing_key.y,
            self.clearance_signing_key.x,
            self.clearance_signing_key.y,
            CircuitField::from(self.note_id),
            CircuitField::from(self.final_balance),
            self.destination,
            self.withdrawal_nullifier,
            CircuitField::from(self.has_clearance as u64),
            self.withdrawal_tag,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct WithdrawalWitness {
    pub secret: CircuitField,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub merkle_siblings: [CircuitField; REQUEST_MERKLE_DEPTH],
    pub final_blinding: EdwardsScalarField,
    pub current_anchor: CircuitField,
    pub is_genesis: bool,
    pub state_signature: StateSignature,
    pub clearance_signature: StateSignature,
}

#[derive(Clone, Debug)]
pub struct WithdrawalCircuit {
    pub public: WithdrawalPublic,
    pub witness: WithdrawalWitness,
}

impl ConstraintSynthesizer<CircuitField> for WithdrawalCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.protocol_version as u64))
        })?;
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.chain_id)))?;
        let contract_address = FpVar::new_input(cs.clone(), || Ok(self.public.contract_address))?;
        let active_root = FpVar::new_input(cs.clone(), || Ok(self.public.active_root))?;
        let state_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.state_signing_key))?;
        let clearance_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.clearance_signing_key))?;
        let note_id_field =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.note_id)))?;
        let final_balance_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.final_balance))
        })?;
        let destination = FpVar::new_input(cs.clone(), || Ok(self.public.destination))?;
        let withdrawal_nullifier =
            FpVar::new_input(cs.clone(), || Ok(self.public.withdrawal_nullifier))?;
        let has_clearance = Boolean::new_input(cs.clone(), || Ok(self.public.has_clearance))?;
        let withdrawal_tag = FpVar::new_input(cs.clone(), || Ok(self.public.withdrawal_tag))?;

        let secret = FpVar::new_witness(cs.clone(), || Ok(self.witness.secret))?;
        secret.enforce_not_equal(&FpVar::zero())?;
        let note_id = UInt32::new_witness(cs.clone(), || Ok(self.public.note_id))?;
        note_id.to_fp()?.enforce_equal(&note_id_field)?;
        let deposit_amount = UInt128::new_witness(cs.clone(), || Ok(self.witness.deposit_amount))?;
        let final_balance = UInt128::new_witness(cs.clone(), || Ok(self.public.final_balance))?;
        final_balance.to_fp()?.enforce_equal(&final_balance_field)?;
        deposit_amount
            .is_ge(&final_balance)?
            .enforce_equal(&Boolean::TRUE)?;
        let expiry = UInt64::new_witness(cs.clone(), || Ok(self.witness.expiry))?;

        let registration = poseidon_hash_var(
            cs.clone(),
            &[domain_var(DOMAIN_REG), secret.clone(), FpVar::zero()],
        )?;
        let leaf = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_LEAF),
                note_id.to_fp()?,
                registration,
                deposit_amount.to_fp()?,
                expiry.to_fp()?,
            ],
        )?;
        let mut current = leaf.clone();
        for (level, sibling_value) in self.witness.merkle_siblings.iter().enumerate() {
            let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling_value))?;
            let bit = &note_id.bits[level];
            let left = bit.select(&sibling, &current)?;
            let right = bit.select(&current, &sibling)?;
            current = poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NODE), left, right])?;
        }
        current.enforce_equal(&active_root)?;

        let is_genesis = Boolean::new_witness(cs.clone(), || Ok(self.witness.is_genesis))?;
        let anchor = FpVar::new_witness(cs.clone(), || Ok(self.witness.current_anchor))?;
        anchor.conditional_enforce_equal(&FpVar::one(), &is_genesis)?;
        final_balance
            .to_fp()?
            .conditional_enforce_equal(&deposit_amount.to_fp()?, &is_genesis)?;

        let current_commitment = commitment_var(
            cs.clone(),
            &final_balance,
            self.witness.final_blinding,
            &leaf,
        )?;
        let state_message = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_STATE),
                protocol_version.clone(),
                chain_id.clone(),
                contract_address.clone(),
                current_commitment.x.clone(),
                current_commitment.y.clone(),
                anchor.clone(),
            ],
        )?;
        enforce_signature(
            cs.clone(),
            &state_signing_key,
            &state_message,
            self.witness.state_signature,
            &is_genesis.not(),
        )?;

        let computed_nullifier =
            poseidon_hash_var(cs.clone(), &[domain_var(DOMAIN_NULLIFIER), secret, anchor])?;
        computed_nullifier.enforce_equal(&withdrawal_nullifier)?;

        let computed_withdrawal_tag = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_WITHDRAWAL),
                withdrawal_nullifier.clone(),
                destination,
                final_balance_field,
                has_clearance.select(&FpVar::one(), &FpVar::zero())?,
            ],
        )?;
        computed_withdrawal_tag.enforce_equal(&withdrawal_tag)?;

        let clear_message = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_CLEARANCE),
                protocol_version,
                chain_id,
                contract_address,
                withdrawal_nullifier,
            ],
        )?;
        enforce_signature(
            cs,
            &clearance_signing_key,
            &clear_message,
            self.witness.clearance_signature,
            &has_clearance,
        )?;
        Ok(())
    }
}

pub fn request_nullifier(secret: CircuitField, anchor: CircuitField) -> CircuitField {
    poseidon_hash(&[domain(DOMAIN_NULLIFIER), secret, anchor])
}

pub fn withdrawal_tag(
    nullifier: CircuitField,
    destination: CircuitField,
    final_balance: u128,
    has_clearance: bool,
) -> CircuitField {
    poseidon_hash(&[
        domain(DOMAIN_WITHDRAWAL),
        nullifier,
        destination,
        CircuitField::from(final_balance),
        CircuitField::from(has_clearance as u64),
    ])
}

pub fn authorization_tag(nullifier: CircuitField, request_context: CircuitField) -> CircuitField {
    poseidon_hash(&[domain(DOMAIN_AUTHORIZATION), nullifier, request_context])
}

pub fn registration_commitment(secret: CircuitField) -> CircuitField {
    poseidon_hash(&[domain(DOMAIN_REG), secret, CircuitField::ZERO])
}

pub fn note_leaf(
    note_id: u32,
    registration: CircuitField,
    deposit_amount: u128,
    expiry: u64,
) -> CircuitField {
    poseidon_hash(&[
        domain(DOMAIN_LEAF),
        CircuitField::from(note_id),
        registration,
        CircuitField::from(deposit_amount),
        CircuitField::from(expiry),
    ])
}

pub fn merkle_root(
    note_id: u32,
    leaf: CircuitField,
    siblings: &[CircuitField; REQUEST_MERKLE_DEPTH],
) -> CircuitField {
    let mut current = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if ((note_id >> level) & 1) == 0 {
            poseidon_hash(&[domain(DOMAIN_NODE), current, *sibling])
        } else {
            poseidon_hash(&[domain(DOMAIN_NODE), *sibling, current])
        };
    }
    current
}

pub fn request_setup(
    circuit: RequestCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::setup(circuit, rng)
}

pub fn withdrawal_setup(
    circuit: WithdrawalCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::setup(circuit, rng)
}

pub fn prove_withdrawal(
    proving_key: &ProvingKey<Bn254>,
    circuit: WithdrawalCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Proof<Bn254>, SynthesisError> {
    Groth16::<Bn254>::prove(proving_key, circuit, rng)
}

pub fn verify_withdrawal(
    verifying_key: &VerifyingKey<Bn254>,
    public: &WithdrawalPublic,
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let prepared = prepare_verifying_key(verifying_key);
    Groth16::<Bn254>::verify_with_processed_vk(&prepared, &public.to_field_elements(), proof)
}

pub fn prove_request(
    proving_key: &ProvingKey<Bn254>,
    circuit: RequestCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Proof<Bn254>, SynthesisError> {
    Groth16::<Bn254>::prove(proving_key, circuit, rng)
}

pub fn verify_request(
    verifying_key: &VerifyingKey<Bn254>,
    public: &RequestPublic,
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let prepared = prepare_verifying_key(verifying_key);
    Groth16::<Bn254>::verify_with_processed_vk(&prepared, &public.to_field_elements(), proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(0x7a6b_6170_6932)
    }

    fn fixture() -> RequestCircuit {
        let mut rng = test_rng();
        let protocol_version = 2;
        let chain_id = 11_155_111;
        let contract_address = CircuitField::from(0xdead_u64);
        let secret = CircuitField::from(42u64);
        let note_id = 0;
        let deposit_amount = 5_000_000;
        let expiry = 4_000_000_000;
        let siblings = [CircuitField::ZERO; REQUEST_MERKLE_DEPTH];
        let registration = registration_commitment(secret);
        let leaf = note_leaf(note_id, registration, deposit_amount, expiry);
        let active_root = merkle_root(note_id, leaf, &siblings);
        let current_balance = 4_900_000;
        let current_blinding = EdwardsScalarField::rand(&mut rng);
        let rerandomization = EdwardsScalarField::rand(&mut rng);
        let current_commitment =
            balance_commitment(current_balance, current_blinding, leaf).into_affine();
        let anonymous_commitment =
            rerandomize_commitment(current_commitment.into_group(), rerandomization).into_affine();
        let current_anchor = CircuitField::from(12345u64);
        let signer = StateSigningKey::generate(&mut rng);
        let message = state_message(
            protocol_version,
            chain_id,
            contract_address,
            current_commitment,
            current_anchor,
        );
        let signature = signer.sign(message, &mut rng);
        assert!(verify_state_signature(signer.public, message, signature));
        let request_context = CircuitField::from(777u64);
        let nullifier = request_nullifier(secret, current_anchor);

        RequestCircuit {
            public: RequestPublic {
                protocol_version,
                chain_id,
                contract_address,
                active_root,
                state_signing_key: signer.public,
                request_time: 3_000_000_000,
                solvency_bound: 1_000_000,
                request_nullifier: nullifier,
                authorization_tag: authorization_tag(nullifier, request_context),
                anonymous_commitment,
            },
            witness: RequestWitness {
                secret,
                request_context,
                note_id,
                deposit_amount,
                expiry,
                merkle_siblings: siblings,
                current_balance,
                current_blinding,
                rerandomization,
                current_anchor,
                is_genesis: false,
                state_signature: signature,
            },
        }
    }

    fn withdrawal_fixture() -> WithdrawalCircuit {
        let mut rng = test_rng();
        let protocol_version = 2;
        let chain_id = 11_155_111;
        let contract_address = CircuitField::from(0xdead_u64);
        let secret = CircuitField::from(42u64);
        let note_id = 0;
        let deposit_amount = 5_000_000;
        let expiry = 4_000_000_000;
        let siblings = [CircuitField::ZERO; REQUEST_MERKLE_DEPTH];
        let registration = registration_commitment(secret);
        let leaf = note_leaf(note_id, registration, deposit_amount, expiry);
        let active_root = merkle_root(note_id, leaf, &siblings);
        let final_balance = 4_900_000;
        let final_blinding = EdwardsScalarField::rand(&mut rng);
        let current_commitment =
            balance_commitment(final_balance, final_blinding, leaf).into_affine();
        let current_anchor = CircuitField::from(12345u64);
        let state_signer = StateSigningKey::generate(&mut rng);
        let state_signature = state_signer.sign(
            state_message(
                protocol_version,
                chain_id,
                contract_address,
                current_commitment,
                current_anchor,
            ),
            &mut rng,
        );
        let clearance_signer = StateSigningKey::generate(&mut rng);
        let nullifier = request_nullifier(secret, current_anchor);
        let clearance_signature = clearance_signer.sign(
            clearance_message(protocol_version, chain_id, contract_address, nullifier),
            &mut rng,
        );
        let destination = CircuitField::from(0xbeef_u64);
        let has_clearance = true;

        WithdrawalCircuit {
            public: WithdrawalPublic {
                protocol_version,
                chain_id,
                contract_address,
                active_root,
                state_signing_key: state_signer.public,
                clearance_signing_key: clearance_signer.public,
                note_id,
                final_balance,
                destination,
                withdrawal_nullifier: nullifier,
                has_clearance,
                withdrawal_tag: withdrawal_tag(
                    nullifier,
                    destination,
                    final_balance,
                    has_clearance,
                ),
            },
            witness: WithdrawalWitness {
                secret,
                deposit_amount,
                expiry,
                merkle_siblings: siblings,
                final_blinding,
                current_anchor,
                is_genesis: false,
                state_signature,
                clearance_signature,
            },
        }
    }

    #[test]
    fn generators_are_distinct_nonzero_subgroup_points() {
        let g = EdwardsProjective::generator();
        let h = balance_blinding_generator();
        let j = note_binding_generator();
        assert_ne!(g, h);
        assert_ne!(g, j);
        assert_ne!(h, j);
        for point in [h, j] {
            assert_ne!(point, EdwardsProjective::default());
            assert!(point.into_affine().is_on_curve());
            assert!(point
                .into_affine()
                .is_in_correct_subgroup_assuming_on_curve());
        }
    }

    #[test]
    #[should_panic(expected = "Schnorr signing secret must be nonzero")]
    fn zero_signing_secret_is_rejected() {
        StateSigningKey::from_secret(EdwardsScalarField::ZERO);
    }

    #[test]
    fn signed_state_cannot_move_to_another_note() {
        for (secret, amount) in [(42, 5_000_000), (43, 5_000_000), (43, 6_000_000)] {
            let mut circuit = fixture();
            circuit.witness.secret = CircuitField::from(secret as u64);
            circuit.witness.note_id = 1;
            circuit.witness.deposit_amount = amount;
            let leaf = note_leaf(
                1,
                registration_commitment(circuit.witness.secret),
                amount,
                circuit.witness.expiry,
            );
            circuit.public.active_root = merkle_root(1, leaf, &circuit.witness.merkle_siblings);
            circuit.public.request_nullifier =
                request_nullifier(circuit.witness.secret, circuit.witness.current_anchor);
            circuit.public.authorization_tag = authorization_tag(
                circuit.public.request_nullifier,
                circuit.witness.request_context,
            );
            // Recompute everything the attacker controls for B; only A's genuine
            // signature is retained. Both amounts exceed the current balance.
            circuit.public.anonymous_commitment = rerandomize_commitment(
                balance_commitment(
                    circuit.witness.current_balance,
                    circuit.witness.current_blinding,
                    leaf,
                ),
                circuit.witness.rerandomization,
            )
            .into_affine();
            let cs = ConstraintSystem::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn signed_withdrawal_cannot_move_to_another_note() {
        for (secret, amount) in [(42, 5_000_000), (43, 5_000_000), (43, 6_000_000)] {
            let mut circuit = withdrawal_fixture();
            circuit.witness.secret = CircuitField::from(secret as u64);
            circuit.public.note_id = 1;
            circuit.witness.deposit_amount = amount;
            let leaf = note_leaf(
                1,
                registration_commitment(circuit.witness.secret),
                amount,
                circuit.witness.expiry,
            );
            circuit.public.active_root = merkle_root(1, leaf, &circuit.witness.merkle_siblings);
            circuit.public.withdrawal_nullifier =
                request_nullifier(circuit.witness.secret, circuit.witness.current_anchor);
            circuit.public.has_clearance = false;
            circuit.public.withdrawal_tag = withdrawal_tag(
                circuit.public.withdrawal_nullifier,
                circuit.public.destination,
                circuit.public.final_balance,
                false,
            );
            let cs = ConstraintSystem::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn request_circuit_is_satisfied() {
        let circuit = fixture();
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_instance_variables() - 1, REQUEST_PUBLIC_INPUTS);
        eprintln!("request constraints: {}", cs.num_constraints());
    }

    #[test]
    fn request_proof_round_trip() {
        use std::time::Instant;

        let mut rng = test_rng();
        let circuit = fixture();
        let public = circuit.public.clone();
        let setup_started = Instant::now();
        let (pk, vk) = request_setup(circuit.clone(), &mut rng).unwrap();
        let setup_elapsed = setup_started.elapsed();
        let prove_started = Instant::now();
        let proof = prove_request(&pk, circuit, &mut rng).unwrap();
        let prove_elapsed = prove_started.elapsed();
        let verify_started = Instant::now();
        assert!(verify_request(&vk, &public, &proof).unwrap());
        let verify_elapsed = verify_started.elapsed();

        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        eprintln!("request proof bytes: {}", proof_bytes.len());
        eprintln!("setup: {setup_elapsed:?}");
        eprintln!("prove: {prove_elapsed:?}");
        eprintln!("verify: {verify_elapsed:?}");
    }

    #[test]
    fn request_context_is_cryptographically_bound() {
        let mut rng = test_rng();
        let circuit = fixture();
        let (pk, vk) = request_setup(circuit.clone(), &mut rng).unwrap();
        let proof = prove_request(&pk, circuit.clone(), &mut rng).unwrap();
        let mut wrong = circuit.public;
        wrong.authorization_tag += CircuitField::ONE;
        assert!(!verify_request(&vk, &wrong, &proof).unwrap());
    }

    #[test]
    fn withdrawal_proof_round_trip() {
        use std::time::Instant;

        let mut rng = test_rng();
        let circuit = withdrawal_fixture();
        let public = circuit.public.clone();
        let cs = ConstraintSystem::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_instance_variables() - 1, WITHDRAWAL_PUBLIC_INPUTS);

        let setup_started = Instant::now();
        let (pk, vk) = withdrawal_setup(circuit.clone(), &mut rng).unwrap();
        let setup_elapsed = setup_started.elapsed();
        let prove_started = Instant::now();
        let proof = prove_withdrawal(&pk, circuit, &mut rng).unwrap();
        let prove_elapsed = prove_started.elapsed();
        let verify_started = Instant::now();
        assert!(verify_withdrawal(&vk, &public, &proof).unwrap());
        let verify_elapsed = verify_started.elapsed();

        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        eprintln!("withdrawal constraints: {}", cs.num_constraints());
        eprintln!("withdrawal proof bytes: {}", proof_bytes.len());
        eprintln!("setup: {setup_elapsed:?}");
        eprintln!("prove: {prove_elapsed:?}");
        eprintln!("verify: {verify_elapsed:?}");
    }
}
