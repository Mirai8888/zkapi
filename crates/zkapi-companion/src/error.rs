use axum::http::StatusCode;
use thiserror::Error;
use zkapi_client::error::ClientError;
use zkapi_types::Felt252;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Sepolia password is missing or incorrect; stop the daemon and run zkapi-clientd config to enter the current shared password")]
    TestnetPasswordRequired,
    #[error("inference is awaiting settlement; retry withdrawal after settlement")]
    PendingSettlement,
    #[error("withdrawal transaction is awaiting finalized confirmation")]
    OaWithdrawalPending,
    #[error("a withdrawal is reserved for a different destination or note state; resume the saved withdrawal")]
    WithdrawalConflict,
    #[error("wallet is busy in another process")]
    WalletBusy,
    #[error("wallet has no active note; fund it first")]
    NoActiveNote,
    #[error("wallet balance is too low for this request")]
    InsufficientBalance,
    #[error("wallet has a pending request; recover it before spending again")]
    PendingRequest,
    #[error("OpenRouter lease pending: {0}")]
    LeasePending(String),
    #[error("withdrawal pending: {0}")]
    WithdrawalPending(String),
    #[error(
        "another chat ({active_session_id}) owns the current ephemeral key until {expires_at}"
    )]
    LeaseSessionConflict {
        active_session_id: String,
        expires_at: u64,
    },
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("upstream returned {status}: {message}")]
    UpstreamResponse { status: StatusCode, message: String },
    #[error("OA key verification failed: {0}")]
    KeyVerification(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("wallet error: {0}")]
    Wallet(String),
    #[error("indexer error: {0}")]
    Indexer(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("receipt journal missing: the server reports this note state's nullifier {0} settled by a request this wallet holds no journal or archive record of, so its receipt cannot be installed and neither chat requests nor a withdrawal can continue from this state; an earlier release deleted that request's journal (a lying server could claim the same). Contact the zkAPI operator with this nullifier")]
    ReceiptJournalMissing(Felt252),
    #[error("this note state is withdrawal-only: a withdrawal clearance request carrying its ownership proof was sent, or may have been sent, and whoever saw that request may hold the proof, which is a valid escape at this state; on this vault a chat request from this state would let them escape and challenge it, which burns the note's nullifier, so no chat request is made from it and its withdrawal reservation is not released. Retry the withdrawal (in zkapi-clientd: config --menu, then withdraw) to close the note")]
    OwnershipProofSent,
    #[error("this note state is reserved for a withdrawal: the server holds a clearance for its nullifier (an earlier withdrawal reserved it, or the operator released a stuck state) and refuses every request at it as a replay, so no chat request can settle this state; withdraw the balance by mutual close (in zkapi-clientd: config --menu, then withdraw), which sets the refused request aside first")]
    ClearanceReservedState,
}

impl AuthError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::TestnetPasswordRequired => StatusCode::UNAUTHORIZED,
            Self::WalletBusy
            | Self::PendingSettlement
            | Self::OaWithdrawalPending
            | Self::WithdrawalConflict
            | Self::ReceiptJournalMissing(_)
            | Self::OwnershipProofSent
            | Self::ClearanceReservedState => StatusCode::CONFLICT,
            Self::NoActiveNote | Self::InsufficientBalance => StatusCode::PAYMENT_REQUIRED,
            Self::PendingRequest
            | Self::LeasePending(_)
            | Self::WithdrawalPending(_)
            | Self::LeaseSessionConflict { .. } => StatusCode::CONFLICT,
            Self::InvalidInput(_) | Self::Serialization(_) => StatusCode::BAD_REQUEST,
            Self::UpstreamResponse { status, .. } => *status,
            Self::Wallet(_) | Self::Indexer(_) | Self::Upstream(_) | Self::KeyVerification(_) => {
                StatusCode::BAD_GATEWAY
            }
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::TestnetPasswordRequired => "testnet_password_required",
            Self::WalletBusy => "wallet_busy",
            Self::PendingSettlement => "pending_settlement",
            Self::OaWithdrawalPending => "withdrawal_pending",
            Self::WithdrawalConflict => "withdrawal_conflict",
            Self::NoActiveNote => "no_active_note",
            Self::InsufficientBalance => "insufficient_balance",
            Self::PendingRequest => "pending_request",
            Self::LeasePending(_) => "lease_pending",
            Self::WithdrawalPending(_) => "withdrawal_pending",
            Self::LeaseSessionConflict { .. } => "lease_session_conflict",
            Self::Upstream(_) | Self::UpstreamResponse { .. } => "upstream_error",
            Self::KeyVerification(_) => "key_verification_failed",
            Self::InvalidInput(_) => "invalid_input",
            Self::Wallet(_) => "wallet_error",
            Self::Indexer(_) => "indexer_error",
            Self::Serialization(_) => "serialization_error",
            Self::ReceiptJournalMissing(_) => "receipt_journal_missing",
            Self::ClearanceReservedState => "clearance_reserved_state",
            Self::OwnershipProofSent => "ownership_proof_sent",
        }
    }

    /// The note state's nullifier the owner gives the operator, for
    /// `receipt_journal_missing` only.
    pub fn nullifier(&self) -> Option<String> {
        match self {
            Self::ReceiptJournalMissing(nullifier) => Some(nullifier.to_string()),
            _ => None,
        }
    }

    pub fn funding_url(&self) -> Option<&'static str> {
        matches!(self, Self::NoActiveNote | Self::InsufficientBalance).then_some("/funding")
    }
}

impl From<ClientError> for AuthError {
    fn from(value: ClientError) -> Self {
        match value {
            ClientError::TestnetPasswordRequired => Self::TestnetPasswordRequired,
            ClientError::NoActiveNote => Self::NoActiveNote,
            ClientError::InsufficientBalance { .. } => Self::InsufficientBalance,
            ClientError::PendingRequest => Self::PendingRequest,
            other => Self::Wallet(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_failure_retains_safe_status_and_code() {
        let error = AuthError::from(ClientError::TestnetPasswordRequired);
        assert_eq!(error.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(error.code(), "testnet_password_required");
        assert_eq!(error.funding_url(), None);
    }

    #[test]
    fn upstream_http_status_is_not_disguised_as_bad_gateway() {
        let error = AuthError::UpstreamResponse {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "rate limited".to_string(),
        };
        assert_eq!(error.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.funding_url(), None);
    }
}
