//! zkAPI Groth16 circuits (`zkapi-v2-concession-v1`) and native proof interface.
//!
//! * [`groth16`]: the request and withdrawal circuits and native mirrors of
//!   their hashes.
//! * [`compact`]: wire-level provers and verifiers, key headers and setup
//!   policy, setup directories and the generated Solidity adapter.
//! * [`reduction`]: the snarkjs-compatible R1CS-to-QAP reduction every prover
//!   uses.
//! * [`r1cs`]: export of the circuits as circom `.r1cs` files for the
//!   multi-party setup.
//! * [`dev`] (feature `dev-setup`): deterministic development fixtures.

pub mod compact;
#[cfg(feature = "dev-setup")]
pub mod dev;
pub mod groth16;
pub mod r1cs;
pub mod reduction;
