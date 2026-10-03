//! Wire format types for HTTP APIs.
//!
//! Field elements use 0x-prefixed lowercase hex strings; curve points have
//! x and y fields. Proofs contain base64-encoded canonical Groth16 bytes.
//! Integer fields retain the existing v2 serde representation.

use serde::{Deserialize, Serialize};

use crate::Felt252;

/// Supported proof backend on the wire.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofBackendWire {
    Groth16Bn254,
}

/// Compact Groth16 proof artifact. Public inputs are carried in the enclosing
/// request and are verified directly; there is no separately trusted output
/// hash or witness envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Groth16ProofWire {
    pub backend: ProofBackendWire,
    /// Arkworks canonical compressed proof bytes, base64 encoded.
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRequestV2 {
    pub client_request_id: String,
    pub payload: String,
    pub payload_hash: Felt252,
    pub public_inputs: crate::RequestPublicInputsV2,
    pub proof: Groth16ProofWire,
}

/// Prompt-free payload authorized by a client when opening a short-lived
/// OpenRouter lease. The server rejects extra fields so this protocol message
/// cannot accidentally carry an LLM prompt or response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenRouterLeaseAuthorization {
    pub mode: String,
    pub version: u16,
}

impl Default for OpenRouterLeaseAuthorization {
    fn default() -> Self {
        Self {
            mode: "openrouter_ephemeral_lease".to_string(),
            version: 1,
        }
    }
}

/// A freshly-issued, short-lived OpenRouter key. The plaintext key is only
/// present in this live response; server recovery responses never contain it.
#[derive(Clone, Serialize, Deserialize)]
pub struct OpenRouterLeaseResponse {
    pub status: String,
    pub client_request_id: String,
    pub api_key: String,
    /// OpenRouter inference base, normally `https://openrouter.ai/api/v1`.
    pub openrouter_api_base: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub valid_for_seconds: u64,
    /// The server will not finalize usage before this UNIX timestamp.
    pub settle_after: u64,
    pub spending_limit_usd: f64,
}

/// Non-secret lease metadata, safe to return during crash recovery. It never
/// contains the plaintext OpenRouter runtime key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRouterLeaseStatusResponse {
    /// provisioning, active, retiring, disabled, revoking, finalized, or
    /// cancelled (a corrupt server record that was never signed).
    pub status: String,
    pub client_request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub settle_after: u64,
    pub spending_limit_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charge_applied: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// How a finalized charge was determined: "measured", "clamped",
    /// "worst_case" or "unissued".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charge_basis: Option<String>,
    /// UNIX time by which a pending lease is finalized, at worst at the
    /// request's solvency bound. Absent once the lease is terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_deadline: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponseV2 {
    pub status: String,
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub response_code: u16,
    pub response_payload: String,
    pub response_hash: Felt252,
    pub charge_applied: u128,
    pub next_commitment: CurvePointWire,
    pub next_anchor: Felt252,
    pub blind_delta_srv: Felt252,
    pub next_state_signature: crate::SchnorrSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_reason_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_evidence_hash: Option<Felt252>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearanceResponseV2 {
    pub status: String,
    pub withdrawal_nullifier: Felt252,
    pub signature: crate::SchnorrSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResponseV2 {
    pub status: String,
    pub nullifier_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_response: Option<RequestResponseV2>,
    /// For a reserved lease request: the UNIX time by which the server
    /// finalizes it. Wait for that response rather than escaping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_deadline: Option<u64>,
}

/// A curve point serialized as {x, y} hex fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurvePointWire {
    pub x: Felt252,
    pub y: Felt252,
}

/// Error response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub client_request_id: String,
    pub error_code: String,
    pub error_message: String,
    pub retriable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_root: Option<Felt252>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_time_ms: Option<u64>,
    /// Present for retriable throttling errors and mirrored in the HTTP
    /// `Retry-After` header when the transport supports response headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

/// Clearance request for mutual close. Servers that require note ownership
/// reject a request without `ownership_proof` (`clearance_ownership_required`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearanceRequest {
    pub withdrawal_nullifier: Felt252,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership_proof: Option<ClearanceOwnershipProof>,
}

/// An escape-form (`has_clearance = false`) withdrawal proof for the same
/// nullifier, proving knowledge of the note secret. Build it with the real
/// destination and current balance of the intended mutual close: it is also
/// a valid escape input for whoever holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClearanceOwnershipProof {
    pub public_inputs: crate::WithdrawalPublicInputsV2,
    pub proof: Groth16ProofWire,
}

#[cfg(test)]
mod tests {
    use super::{ClearanceRequest, ErrorResponse};
    use crate::Felt252;

    #[test]
    fn clearance_request_ownership_proof_is_optional_and_exact() {
        let legacy: ClearanceRequest =
            serde_json::from_str(r#"{"withdrawal_nullifier":"0x7"}"#).unwrap();
        assert!(legacy.ownership_proof.is_none());
        assert_eq!(
            serde_json::to_value(&legacy).unwrap(),
            serde_json::json!({"withdrawal_nullifier": Felt252::from_u64(7)})
        );
        let destination = [17u8; 20];
        let inputs = serde_json::json!({
            "protocol_version":2, "chain_id":11155111, "contract_address":"0x1", "active_root":"0x2",
            "state_signing_key_x":"0x3", "state_signing_key_y":"0x4",
            "clearance_signing_key_x":"0x5", "clearance_signing_key_y":"0x6",
            "note_id":7, "final_balance":1950000, "destination":destination,
            "withdrawal_nullifier":"0x7", "has_clearance":false, "withdrawal_tag":"0x8"
        });
        let proof = serde_json::json!({"backend":"groth16_bn254","proof":"AA=="});
        let body = serde_json::json!({"withdrawal_nullifier":"0x7",
            "ownership_proof":{"public_inputs":inputs, "proof":proof}});
        let parsed: ClearanceRequest = serde_json::from_value(body.clone()).unwrap();
        let ownership = parsed.ownership_proof.as_ref().unwrap();
        assert_eq!(ownership.public_inputs.final_balance, 1_950_000);
        assert!(!ownership.public_inputs.has_clearance);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), body);
        // Unknown ownership fields, and a request proof's statement, are rejected.
        let mut extra = body.clone();
        extra["ownership_proof"]["prompt"] = "not allowed".into();
        assert!(serde_json::from_value::<ClearanceRequest>(extra).is_err());
        let request_statement = serde_json::json!({
            "protocol_version":2, "chain_id":1, "contract_address":"0x1", "active_root":"0x2",
            "state_signing_key_x":"0x3", "state_signing_key_y":"0x4", "request_time":5,
            "solvency_bound":6, "request_nullifier":"0x7", "authorization_tag":"0x8",
            "anonymous_commitment_x":"0x9", "anonymous_commitment_y":"0xa"
        });
        let mut request_proof = body;
        request_proof["ownership_proof"]["public_inputs"] = request_statement;
        assert!(serde_json::from_value::<ClearanceRequest>(request_proof).is_err());
    }

    #[test]
    fn legacy_error_response_without_retry_delay_remains_compatible() {
        let response: ErrorResponse = serde_json::from_str(
            r#"{
                "status":"error",
                "client_request_id":"request-1",
                "error_code":"internal_error",
                "error_message":"temporary failure",
                "retriable":true
            }"#,
        )
        .unwrap();

        assert_eq!(response.retry_after_seconds, None);
        let serialized = serde_json::to_value(response).unwrap();
        assert!(serialized.get("retry_after_seconds").is_none());
    }
}
