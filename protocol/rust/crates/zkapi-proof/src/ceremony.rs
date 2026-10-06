//! Binding of imported phase-2 keys to this build's circuits (G-SETUP step 6).
//!
//! `snarkjs groth16 setup <r1cs> <ptau>` derives every circuit-dependent point
//! of a key from the R1CS matrices A, B, C and the Lagrange bases of a
//! powers-of-tau file. Phase-2 contributions and the beacon only change `δ`:
//! they rescale the L and H queries by `1/δ` and touch nothing else.
//! [`check_key_binding`] recomputes that relation for the matrices this build
//! synthesizes, so a key set up from any other R1CS (for example one with the
//! same A and B but a different C, which a prover never reads) is refused.
//! It is the circuit half of `snarkjs zkey verify`; the contribution chain
//! (who changed `δ`, with proofs of knowledge) is not checked here.
//!
//! The binding is only as good as the powers of tau: [`Ptau::open`] hashes the
//! file so that the importer compares it with the pinned public transcript.
//!
//! Formats (iden3 binary files, snarkjs 0.7): every point is little-endian
//! Montgomery `x ‖ y` (G2: `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`), `(0, 0)` for
//! infinity. A prepared powers of tau of power `p` holds, in sections 12-15,
//! the Lagrange bases `L_j(τ)·G1`, `L_j(τ)·G2`, `α·L_j(τ)·G1` and
//! `β·L_j(τ)·G1` for every domain size `2^k`, `k = 0..=p` (section 12 also
//! `k = p + 1`), the block of size `d` starting at point `d - 1`.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{BigInt, PrimeField, UniformRand, Zero};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const G1_BYTES: u64 = 64;
const G2_BYTES: u64 = 128;
/// Two-adicity of the BN254 scalar field: the largest radix-2 domain.
const MAX_POWER: u32 = 28;

const PTAU_HEADER: u32 = 1;
const PTAU_ALPHA_TAU_G1: u32 = 4;
const PTAU_BETA_TAU_G1: u32 = 5;
const PTAU_BETA_G2: u32 = 6;
const PTAU_LAGRANGE_TAU_G1: u32 = 12;
const PTAU_LAGRANGE_TAU_G2: u32 = 13;
const PTAU_LAGRANGE_ALPHA_TAU_G1: u32 = 14;
const PTAU_LAGRANGE_BETA_TAU_G1: u32 = 15;

/// Section 10 of a snarkjs zkey: the phase-2 contributions.
const ZKEY_CONTRIBUTIONS: u32 = 10;

/// Position and length of one section of an iden3 binary file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section {
    pub offset: u64,
    pub size: u64,
}

/// Read the section table of an iden3 binary file (`ptau`, `zkey`, `r1cs`):
/// a 4-byte magic, version 1, the section count, then `(type: u32, size:
/// u64, body)` records. Refuses duplicated sections and sections that run
/// past the end of the file.
pub fn binfile_sections<R: Read + Seek>(
    reader: &mut R,
    magic: &[u8; 4],
) -> Result<BTreeMap<u32, Section>> {
    let length = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    let mut head = [0u8; 12];
    reader
        .read_exact(&mut head)
        .with_context(|| format!("read the {} header", magic_name(magic)))?;
    ensure!(
        &head[..4] == magic,
        "not a {} file (magic {:?})",
        magic_name(magic),
        String::from_utf8_lossy(&head[..4])
    );
    let version = u32::from_le_bytes(head[4..8].try_into().expect("4 bytes"));
    ensure!(
        version == 1,
        "unsupported {} version {version}",
        magic_name(magic)
    );
    let count = u32::from_le_bytes(head[8..12].try_into().expect("4 bytes"));
    let mut sections = BTreeMap::new();
    let mut position = 12u64;
    for _ in 0..count {
        let mut record = [0u8; 12];
        reader
            .read_exact(&mut record)
            .context("read a section header")?;
        let id = u32::from_le_bytes(record[..4].try_into().expect("4 bytes"));
        let size = u64::from_le_bytes(record[4..].try_into().expect("8 bytes"));
        let offset = position + 12;
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= length)
            .ok_or_else(|| anyhow!("section {id} runs past the end of the file"))?;
        ensure!(
            sections.insert(id, Section { offset, size }).is_none(),
            "section {id} appears twice"
        );
        reader.seek(SeekFrom::Start(end))?;
        position = end;
    }
    Ok(sections)
}

fn magic_name(magic: &[u8; 4]) -> String {
    String::from_utf8_lossy(magic).into_owned()
}

/// A prepared (phase-2 ready) BN254 powers-of-tau file.
#[derive(Debug)]
pub struct Ptau {
    path: PathBuf,
    sha256: [u8; 32],
    power: u32,
    sections: BTreeMap<u32, Section>,
}

impl Ptau {
    /// Hash the whole file and read its section table and header. Requires
    /// the BN254 base field, a power of at most 28 and the four Lagrange
    /// sections of `snarkjs powersoftau prepare phase2`, each of the exact
    /// size its power implies.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            let read = file
                .read(&mut buffer)
                .with_context(|| format!("read {}", path.display()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let sha256 = hasher.finalize().into();
        let mut reader = BufReader::new(file);
        let sections = binfile_sections(&mut reader, b"ptau")
            .with_context(|| format!("read {}", path.display()))?;
        let header = sections
            .get(&PTAU_HEADER)
            .ok_or_else(|| anyhow!("{}: no header section", path.display()))?;
        ensure!(header.size == 44, "{}: malformed header", path.display());
        reader.seek(SeekFrom::Start(header.offset))?;
        let mut bytes = [0u8; 44];
        reader.read_exact(&mut bytes)?;
        ensure!(
            u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes")) == 32
                && bytes[4..36] == le_bytes(&Fq::MODULUS),
            "{}: not a BN254 powers of tau",
            path.display()
        );
        let power = u32::from_le_bytes(bytes[36..40].try_into().expect("4 bytes"));
        ensure!(
            (1..=MAX_POWER).contains(&power),
            "{}: unsupported power {power}",
            path.display()
        );
        let ptau = Self {
            path,
            sha256,
            power,
            sections,
        };
        let block_points = |top: u32| (1u64 << (top + 1)) - 1;
        for (id, size) in [
            (PTAU_LAGRANGE_TAU_G1, block_points(power + 1) * G1_BYTES),
            (PTAU_LAGRANGE_TAU_G2, block_points(power) * G2_BYTES),
            (PTAU_LAGRANGE_ALPHA_TAU_G1, block_points(power) * G1_BYTES),
            (PTAU_LAGRANGE_BETA_TAU_G1, block_points(power) * G1_BYTES),
        ] {
            let section = ptau.section(id)?;
            ensure!(
                section.size == size,
                "{}: section {id} has {} bytes, expected {size} for power {power} \
                 (run `snarkjs powersoftau prepare phase2`)",
                ptau.path.display(),
                section.size
            );
        }
        for (id, size) in [
            (PTAU_ALPHA_TAU_G1, G1_BYTES),
            (PTAU_BETA_TAU_G1, G1_BYTES),
            (PTAU_BETA_G2, G2_BYTES),
        ] {
            ensure!(
                ptau.section(id)?.size >= size,
                "{}: section {id} is empty",
                ptau.path.display()
            );
        }
        Ok(ptau)
    }

    /// SHA-256 of the file.
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// `log2` of the largest domain the file supports.
    pub fn power(&self) -> u32 {
        self.power
    }

    fn section(&self, id: u32) -> Result<Section> {
        self.sections.get(&id).copied().ok_or_else(|| {
            anyhow!(
                "{}: no section {id} (the powers of tau is not prepared for phase 2)",
                self.path.display()
            )
        })
    }

    fn read(&self, id: u32, offset: u64, length: u64) -> Result<Vec<u8>> {
        let section = self.section(id)?;
        ensure!(
            offset + length <= section.size,
            "{}: read past section {id}",
            self.path.display()
        );
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(section.offset + offset))?;
        let mut bytes = vec![0u8; length as usize];
        file.read_exact(&mut bytes)
            .with_context(|| format!("read {}", self.path.display()))?;
        Ok(bytes)
    }

    fn g1_block(&self, id: u32, size: usize) -> Result<Vec<G1Affine>> {
        let bytes = self.read(id, (size as u64 - 1) * G1_BYTES, size as u64 * G1_BYTES)?;
        bytes.as_chunks::<64>().0.iter().map(g1_from_lem).collect()
    }

    /// The bases snarkjs uses for a circuit whose QAP domain has
    /// `domain_size` points: the size-`n` blocks of sections 12-15, the odd
    /// points of section 12's size-`2n` block (the H query), and `α·G1`,
    /// `β·G1`, `β·G2`.
    pub fn lagrange_bases(&self, domain_size: usize) -> Result<LagrangeBases> {
        ensure!(
            domain_size.is_power_of_two() && domain_size as u64 <= 1u64 << self.power,
            "{}: a powers of tau of power {} has no domain of {domain_size} points",
            self.path.display(),
            self.power
        );
        let n = domain_size as u64;
        let tau_g2 = self
            .read(PTAU_LAGRANGE_TAU_G2, (n - 1) * G2_BYTES, n * G2_BYTES)?
            .as_chunks::<128>()
            .0
            .iter()
            .map(g2_from_lem)
            .collect::<Result<Vec<_>>>()?;
        let double = self.read(
            PTAU_LAGRANGE_TAU_G1,
            (2 * n - 1) * G1_BYTES,
            2 * n * G1_BYTES,
        )?;
        let h_g1 = double
            .as_chunks::<64>()
            .0
            .iter()
            .skip(1)
            .step_by(2)
            .map(g1_from_lem)
            .collect::<Result<Vec<_>>>()?;
        let first_g1 =
            |id| -> Result<G1Affine> { g1_from_lem(&self.read(id, 0, G1_BYTES)?.as_chunks().0[0]) };
        Ok(LagrangeBases {
            tau_g1: self.g1_block(PTAU_LAGRANGE_TAU_G1, domain_size)?,
            tau_g2,
            alpha_tau_g1: self.g1_block(PTAU_LAGRANGE_ALPHA_TAU_G1, domain_size)?,
            beta_tau_g1: self.g1_block(PTAU_LAGRANGE_BETA_TAU_G1, domain_size)?,
            h_g1,
            alpha_g1: first_g1(PTAU_ALPHA_TAU_G1)?,
            beta_g1: first_g1(PTAU_BETA_TAU_G1)?,
            beta_g2: g2_from_lem(&self.read(PTAU_BETA_G2, 0, G2_BYTES)?.as_chunks().0[0])?,
        })
    }
}

/// The powers-of-tau points a key for one QAP domain of `n` points is built
/// from (`L_j` is the Lagrange basis of that domain).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LagrangeBases {
    /// `L_j(τ)·G1`, `j < n`.
    pub tau_g1: Vec<G1Affine>,
    /// `L_j(τ)·G2`.
    pub tau_g2: Vec<G2Affine>,
    /// `α·L_j(τ)·G1`.
    pub alpha_tau_g1: Vec<G1Affine>,
    /// `β·L_j(τ)·G1`.
    pub beta_tau_g1: Vec<G1Affine>,
    /// The odd points `2i + 1` of the size-`2n` block of `L(τ)·G1`: the H
    /// query before division by `δ`.
    pub h_g1: Vec<G1Affine>,
    pub alpha_g1: G1Affine,
    pub beta_g1: G1Affine,
    pub beta_g2: G2Affine,
}

impl LagrangeBases {
    /// `n`, the QAP domain size.
    pub fn domain_size(&self) -> usize {
        self.tau_g1.len()
    }
}

/// Check that `pk` is the phase-2 key `snarkjs groth16 setup` derives from
/// `matrices` and `bases`, with only `δ` changed since:
/// * `α·G1`, `β·G1`, `β·G2` are the powers of tau's; `γ·G2` is the generator
///   (snarkjs sets `γ = 1`); `δ·G1` and `δ·G2` encode the same `δ ≠ 0`;
/// * for every wire `i`: `A_i = Σ_j A_ji·L_j(τ)·G1`, `B_i` likewise in G1 and
///   G2, and with `K_i = Σ_j (β·A_ji + α·B_ji + C_ji)·L_j(τ)·G1`,
///   `IC_i = K_i` for "one" and the public inputs and `L_i = K_i / δ` for the
///   witnesses;
/// * `H_i = h_g1[i] / δ`.
///
/// Like snarkjs, rows `m + s` (`m` constraints, `s` = 0 for "one" and then
/// each public input) carry `A = 1` on wire `s`. Each vector equation is
/// checked as one random linear combination with fresh `OsRng` weights, the
/// `δ`-scaled ones by a pairing, so a key that differs anywhere passes with
/// probability at most about `2^-253` per equation.
pub fn check_key_binding(
    pk: &ProvingKey<Bn254>,
    matrices: &ConstraintMatrices<Fr>,
    bases: &LagrangeBases,
) -> Result<()> {
    let n = bases.domain_size();
    let constraints = matrices.num_constraints;
    let instance = matrices.num_instance_variables;
    let wires = instance + matrices.num_witness_variables;
    ensure!(
        matrices.a.len() == constraints
            && matrices.b.len() == constraints
            && matrices.c.len() == constraints,
        "matrix row counts differ from the constraint count"
    );
    ensure!(
        constraints + instance <= n
            && bases.tau_g2.len() == n
            && bases.alpha_tau_g1.len() == n
            && bases.beta_tau_g1.len() == n
            && bases.h_g1.len() == n,
        "the bases do not describe a domain for {constraints} constraints and {instance} instance variables"
    );
    ensure!(
        pk.a_query.len() == wires
            && pk.b_g1_query.len() == wires
            && pk.b_g2_query.len() == wires
            && pk.vk.gamma_abc_g1.len() == instance
            && pk.l_query.len() == wires - instance
            && pk.h_query.len() == n,
        "the key's query sizes do not match the circuit"
    );

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    ensure!(
        pk.vk.alpha_g1 == bases.alpha_g1
            && pk.beta_g1 == bases.beta_g1
            && pk.vk.beta_g2 == bases.beta_g2,
        "alpha or beta is not the powers of tau's"
    );
    ensure!(
        pk.vk.gamma_g2 == g2,
        "gamma is not the G2 generator (snarkjs keys have gamma = 1)"
    );
    ensure!(
        !pk.delta_g1.is_zero()
            && !pk.vk.delta_g2.is_zero()
            && Bn254::pairing(pk.delta_g1, g2) == Bn254::pairing(g1, pk.vk.delta_g2),
        "delta in G1 and G2 differ"
    );

    // Row sums Σ_i M_ji·r_i, for public (0) and private (1) wires apart.
    let mut rng = OsRng;
    let weights: Vec<Fr> = (0..wires).map(|_| Fr::rand(&mut rng)).collect();
    let class = |wire: usize| usize::from(wire >= instance);
    let row_sums = |matrix: &[Vec<(Fr, usize)>]| -> Result<[Vec<Fr>; 2]> {
        let mut sums = [vec![Fr::zero(); n], vec![Fr::zero(); n]];
        for (row, terms) in matrix.iter().enumerate() {
            for (coefficient, wire) in terms {
                ensure!(
                    *wire < wires,
                    "constraint {row} names wire {wire} of {wires}"
                );
                sums[class(*wire)][row] += *coefficient * weights[*wire];
            }
        }
        Ok(sums)
    };
    let mut a = row_sums(&matrices.a)?;
    for (wire, weight) in weights.iter().enumerate().take(instance) {
        a[0][constraints + wire] += weight;
    }
    let b = row_sums(&matrices.b)?;
    let c = row_sums(&matrices.c)?;
    let add = |x: &[Fr], y: &[Fr]| x.iter().zip(y).map(|(x, y)| *x + y).collect::<Vec<_>>();
    let a_all = add(&a[0], &a[1]);
    let b_all = add(&b[0], &b[1]);
    let msm_g1 = |points: &[G1Affine], scalars: &[Fr]| G1Projective::msm_unchecked(points, scalars);
    let msm_g2 = |points: &[G2Affine], scalars: &[Fr]| G2Projective::msm_unchecked(points, scalars);

    ensure!(
        msm_g1(&pk.a_query, &weights) == msm_g1(&bases.tau_g1, &a_all),
        "A query does not match the circuit"
    );
    ensure!(
        msm_g1(&pk.b_g1_query, &weights) == msm_g1(&bases.tau_g1, &b_all),
        "B query (G1) does not match the circuit"
    );
    ensure!(
        msm_g2(&pk.b_g2_query, &weights) == msm_g2(&bases.tau_g2, &b_all),
        "B query (G2) does not match the circuit"
    );
    let k = |class: usize| {
        msm_g1(&bases.beta_tau_g1, &a[class])
            + msm_g1(&bases.alpha_tau_g1, &b[class])
            + msm_g1(&bases.tau_g1, &c[class])
    };
    ensure!(
        msm_g1(&pk.vk.gamma_abc_g1, &weights[..instance]) == k(0),
        "IC (the public-input part of the verifying key) does not match the circuit"
    );
    ensure!(
        Bn254::pairing(msm_g1(&pk.l_query, &weights[instance..]), pk.vk.delta_g2)
            == Bn254::pairing(k(1), g2),
        "L query does not match the circuit"
    );
    let h_weights: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    ensure!(
        Bn254::pairing(msm_g1(&pk.h_query, &h_weights), pk.vk.delta_g2)
            == Bn254::pairing(msm_g1(&bases.h_g1, &h_weights), g2),
        "H query does not match the powers of tau"
    );
    Ok(())
}

/// The kind of one snarkjs phase-2 contribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Contribution {
    /// `snarkjs zkey contribute` (type 0).
    Contribution,
    /// `snarkjs zkey beacon` (type 1).
    Beacon,
}

/// The contributions a snarkjs zkey records in section 10, in order. This is
/// what the zkey claims; `snarkjs zkey verify` checks the chain.
pub fn zkey_contributions(zkey: &[u8]) -> Result<Vec<Contribution>> {
    let mut reader = std::io::Cursor::new(zkey);
    let sections = binfile_sections(&mut reader, b"zkey")?;
    let section = sections
        .get(&ZKEY_CONTRIBUTIONS)
        .ok_or_else(|| anyhow!("the zkey has no contributions section"))?;
    let body = &zkey[section.offset as usize..(section.offset + section.size) as usize];
    let mut at = 64usize; // circuit hash
    let take = |at: &mut usize, length: usize| -> Result<&[u8]> {
        let bytes = body
            .get(*at..*at + length)
            .ok_or_else(|| anyhow!("truncated contributions section"))?;
        *at += length;
        Ok(bytes)
    };
    let count = u32::from_le_bytes(take(&mut at, 4)?.try_into().expect("4 bytes"));
    let mut contributions = Vec::new();
    for _ in 0..count {
        // deltaAfter, g1_s, g1_sx (G1), g2_spx (G2), transcript (64 bytes).
        take(&mut at, 3 * G1_BYTES as usize + G2_BYTES as usize + 64)?;
        let kind = u32::from_le_bytes(take(&mut at, 4)?.try_into().expect("4 bytes"));
        let parameters = u32::from_le_bytes(take(&mut at, 4)?.try_into().expect("4 bytes"));
        take(&mut at, parameters as usize)?;
        contributions.push(match kind {
            0 => Contribution::Contribution,
            1 => Contribution::Beacon,
            other => bail!("unknown contribution type {other}"),
        });
    }
    ensure!(
        at == body.len(),
        "trailing bytes in the contributions section"
    );
    Ok(contributions)
}

fn le_bytes(value: &BigInt<4>) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (chunk, limb) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(value.0) {
        *chunk = limb.to_le_bytes();
    }
    bytes
}

/// A base-field element in snarkjs's little-endian Montgomery form, which is
/// arkworks' internal representation.
fn fq_from_lem(bytes: &[u8; 32]) -> Result<Fq> {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*chunk);
    }
    let value = BigInt::new(limbs);
    ensure!(
        value < Fq::MODULUS,
        "non-canonical base-field element in the powers of tau"
    );
    Ok(Fq::new_unchecked(value))
}

fn g1_from_lem(bytes: &[u8; 64]) -> Result<G1Affine> {
    let [x, y] = bytes.as_chunks::<32>().0 else {
        unreachable!("64 bytes are two coordinates")
    };
    let (x, y) = (fq_from_lem(x)?, fq_from_lem(y)?);
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::zero());
    }
    let point = G1Affine::new_unchecked(x, y);
    ensure!(
        point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve(),
        "invalid G1 point in the powers of tau"
    );
    Ok(point)
}

fn g2_from_lem(bytes: &[u8; 128]) -> Result<G2Affine> {
    let [x0, x1, y0, y1] = bytes.as_chunks::<32>().0 else {
        unreachable!("128 bytes are four coordinates")
    };
    let x = Fq2::new(fq_from_lem(x0)?, fq_from_lem(x1)?);
    let y = Fq2::new(fq_from_lem(y0)?, fq_from_lem(y1)?);
    if x.is_zero() && y.is_zero() {
        return Ok(G2Affine::zero());
    }
    let point = G2Affine::new_unchecked(x, y);
    ensure!(
        point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve(),
        "invalid G2 point in the powers of tau"
    );
    Ok(point)
}

/// Encode a point as snarkjs does (for tests and fixtures that write files).
pub fn g1_to_lem(point: &G1Affine) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    if let Some((x, y)) = point.xy() {
        bytes[..32].copy_from_slice(&le_bytes(&x.0));
        bytes[32..].copy_from_slice(&le_bytes(&y.0));
    }
    bytes
}

/// See [`g1_to_lem`].
pub fn g2_to_lem(point: &G2Affine) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    if let Some((x, y)) = point.xy() {
        for (chunk, value) in bytes
            .as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip([x.c0, x.c1, y.c0, y.c1])
        {
            *chunk = le_bytes(&value.0);
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{CurveGroup, PrimeGroup};

    #[test]
    fn points_round_trip_through_the_snarkjs_encoding() {
        let mut rng = OsRng;
        for point in [
            G1Affine::zero(),
            G1Affine::generator(),
            (G1Projective::generator() * Fr::rand(&mut rng)).into_affine(),
        ] {
            assert_eq!(g1_from_lem(&g1_to_lem(&point)).unwrap(), point);
        }
        for point in [
            G2Affine::zero(),
            G2Affine::generator(),
            (G2Projective::generator() * Fr::rand(&mut rng)).into_affine(),
        ] {
            assert_eq!(g2_from_lem(&g2_to_lem(&point)).unwrap(), point);
        }
        // Off-curve and non-canonical encodings are refused.
        let mut off = g1_to_lem(&G1Affine::generator());
        off[0] ^= 1;
        assert!(g1_from_lem(&off).is_err());
        let mut big = [0xffu8; 64];
        big[32..].copy_from_slice(&g1_to_lem(&G1Affine::generator())[32..]);
        assert!(g1_from_lem(&big).is_err());
    }

    #[test]
    fn binfile_section_tables_are_checked() {
        let file = |magic: &[u8; 4], sections: &[(u32, u64, usize)]| {
            let mut bytes = magic.to_vec();
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&(sections.len() as u32).to_le_bytes());
            for (id, declared, actual) in sections {
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.extend_from_slice(&declared.to_le_bytes());
                bytes.extend(std::iter::repeat_n(7u8, *actual));
            }
            bytes
        };
        let read = |bytes: Vec<u8>, magic: &[u8; 4]| {
            binfile_sections(&mut std::io::Cursor::new(bytes), magic)
        };
        let sections = read(file(b"ptau", &[(1, 3, 3), (12, 5, 5)]), b"ptau").unwrap();
        assert_eq!(
            sections[&1],
            Section {
                offset: 24,
                size: 3
            }
        );
        assert_eq!(
            sections[&12],
            Section {
                offset: 39,
                size: 5
            }
        );
        assert!(read(file(b"zkey", &[(1, 3, 3)]), b"ptau").is_err());
        assert!(read(file(b"ptau", &[(1, 3, 3), (1, 3, 3)]), b"ptau").is_err());
        assert!(read(file(b"ptau", &[(1, 9, 3)]), b"ptau").is_err());
    }
}
