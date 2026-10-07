//! Client error types.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Sepolia password is missing or incorrect")]
    TestnetPasswordRequired,
    #[error("no active note")]
    NoActiveNote,
    #[error("note already exists")]
    NoteAlreadyExists,
    #[error("insufficient balance: need {needed}, have {available}")]
    InsufficientBalance { needed: u128, available: u128 },
    #[error("stale root")]
    StaleRoot,
    #[error("server error: {0}")]
    ServerError(String),
    #[error("invalid server response: {0}")]
    InvalidResponse(String),
    #[error("pending request exists, must recover first")]
    PendingRequest,
    /// A signed note state without the anchor of its predecessor cannot
    /// prove a request (the request circuit checks that its anchor is derived
    /// from the predecessor's nullifier). Exits never need it.
    #[error("prev_anchor_missing: this note state has no predecessor anchor; requests are refused, exits remain available")]
    PrevAnchorMissing,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("proof generation failed: {0}")]
    ProofGeneration(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    /// The server refused a clearance with a code that reserves nothing:
    /// `clearance_ownership_required`, `legacy_clearance_capacity`, or
    /// `nullifier_used` (a request already owns the nullifier).
    #[error("clearance refused: {0}")]
    ClearanceRefused(String),
}
