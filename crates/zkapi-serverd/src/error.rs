//! Server error types.

use thiserror::Error;

/// Errors that can occur during server-side request processing.
#[derive(Error, Debug)]
pub enum ServerError {
    /// Emitted before a native request nullifier is reserved. Existing bound
    /// requests retain their quote and never return this during recovery.
    #[error("native billing quote expired before request acceptance")]
    NativeQuoteExpired,

    /// A newer finalized oracle round exists before request acceptance.
    /// Recover this exact request before preparing another proof.
    #[error("native billing quote superseded before request acceptance")]
    NativeQuoteSuperseded,

    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("stale root: latest is {latest_root}")]
    StaleRoot { latest_root: String },

    #[error("replayed nullifier")]
    Replay,

    #[error("note expired")]
    NoteExpired,

    #[error("internal error: {0}")]
    Internal(String),

    /// A deterministic settlement failure, such as a corrupt persisted quote.
    /// Settlement absorbs it by finalizing at the proof-bound worst case.
    #[error("lease cannot be settled from measured usage: {0}")]
    Unsettleable(String),

    /// POST /v2/withdraw/clearance without an escape-form withdrawal proof.
    #[error("clearance requires an escape-form withdrawal proof of note ownership")]
    ClearanceOwnershipRequired,

    #[error("capacity exhausted")]
    CapacityExhausted,

    /// A proof-less clearance found this minute's transitional legacy budget
    /// spent. Nothing was reserved; a request with an ownership proof never
    /// consults the budget.
    #[error(
        "legacy clearance capacity exhausted; send an ownership proof or retry after {retry_after_seconds} seconds"
    )]
    LegacyClearanceCapacity { retry_after_seconds: u64 },

    #[error("nullifier already used")]
    NullifierUsed,

    #[error("database error: {0}")]
    Database(String),

    /// The store holds a lease row for this ID that it cannot decode. It
    /// never heals by itself (an operator restores its saved request with
    /// `zkapi settlement reopen --saved-request`, also for a pending lease,
    /// which the settlement sweep skips until then, or repairs another
    /// undecodable column by hand, which that command names); the request's
    /// nullifier record stays readable and authoritative. The decoding error
    /// is logged, not returned.
    #[error(
        "lease record cannot be decoded until an operator repairs it; GET /v2/nullifiers/{{request_nullifier}} is authoritative"
    )]
    LeaseRecordUnreadable,

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("protocol mismatch: {0}")]
    ProtocolMismatch(String),

    #[error("OpenRouter lease is already active or awaiting settlement")]
    LeasePending,

    #[error(
        "OpenRouter lease settlement is still pending; retry after {retry_after_seconds} seconds"
    )]
    LeaseSettlementPending { retry_after_seconds: u64 },

    #[error("OA org rejected the key allowance or duration; recover the saved request")]
    OaKeyPolicyRejected,

    #[error(
        "OA org key issuance was rate limited ({reason}); retry after {retry_after_seconds} seconds"
    )]
    OaRateLimited {
        reason: String,
        retry_after_seconds: u64,
    },
}

impl ServerError {
    /// Return a machine-readable error code string for the error.
    pub fn error_code(&self) -> &str {
        match self {
            ServerError::NativeQuoteExpired => "native_quote_expired",
            ServerError::NativeQuoteSuperseded => "native_quote_superseded",
            ServerError::InvalidProof(_) => "invalid_proof",
            ServerError::StaleRoot { .. } => "stale_root",
            ServerError::Replay => "replay",
            ServerError::NoteExpired => "note_expired",
            ServerError::Internal(_) => "internal_error",
            ServerError::Unsettleable(_) => "lease_unsettleable",
            ServerError::ClearanceOwnershipRequired => "clearance_ownership_required",
            ServerError::CapacityExhausted => "capacity_exhausted",
            ServerError::LegacyClearanceCapacity { .. } => "legacy_clearance_capacity",
            ServerError::NullifierUsed => "nullifier_used",
            ServerError::Database(_) => "database_error",
            ServerError::LeaseRecordUnreadable => "lease_record_unreadable",
            ServerError::InvalidRequest(_) => "invalid_request",
            ServerError::ProtocolMismatch(_) => "protocol_mismatch",
            ServerError::LeasePending => "lease_pending",
            ServerError::LeaseSettlementPending { .. } => "lease_settlement_pending",
            ServerError::OaKeyPolicyRejected => "oa_key_policy_rejected",
            ServerError::OaRateLimited { reason, .. } => reason,
        }
    }

    /// Whether the client should retry the request.
    pub fn is_retriable(&self) -> bool {
        match self {
            ServerError::NativeQuoteExpired => true,
            ServerError::NativeQuoteSuperseded => false,
            ServerError::StaleRoot { .. } => true,
            ServerError::Internal(_) => true,
            ServerError::Database(_) => true,
            // Only an operator's repair of the row changes the answer.
            ServerError::LeaseRecordUnreadable => false,
            ServerError::Unsettleable(_) => false,
            ServerError::ClearanceOwnershipRequired => false,
            ServerError::InvalidProof(_) => false,
            ServerError::Replay => false,
            ServerError::NoteExpired => false,
            // Clearance proof verification is bounded; retry after backoff.
            ServerError::CapacityExhausted => true,
            // Retry after the window, or at once with an ownership proof.
            ServerError::LegacyClearanceCapacity { .. } => true,
            ServerError::NullifierUsed => false,
            ServerError::InvalidRequest(_) => false,
            ServerError::ProtocolMismatch(_) => false,
            ServerError::LeasePending => true,
            ServerError::LeaseSettlementPending { .. } => true,
            ServerError::OaKeyPolicyRejected => false,
            ServerError::OaRateLimited { .. } => true,
        }
    }
}
