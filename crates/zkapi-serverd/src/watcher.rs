//! Reconstruct v2 escape challenges from finalized request transcripts only.
//!
//! A reservation, including an issued, retiring or revoking lease, is never
//! challenge evidence. The API server's bounded settlement writes the
//! Finalized transcript, and only that archived proof and request inputs ever
//! build challenge calldata; lease rows are read solely for operator status.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use zkapi_types::{Felt252, NullifierStatus, RequestPublicInputsV2, MERKLE_DEPTH};

use crate::error::ServerError;
use crate::nullifier_store::{DeploymentBinding, NullifierStore, TranscriptRecord};

pub const CHALLENGE_SIGNATURE: &str = "challengeEscapeWithdrawal(uint32,(uint16,uint64,address,uint256,uint256,uint256,uint64,uint128,uint256,uint256,uint256,uint256),bytes,uint256[32])";

/// Server-written lease errors shown on the operator status are bounded.
const MAX_LAST_ERROR_CHARS: usize = 256;

/// What the server database holds for an escaped nullifier.
#[derive(Debug, Clone)]
pub enum EvidenceStatus {
    /// Finalized transcript with a well-formed archived proof and inputs.
    Ready(Box<TranscriptRecord>),
    /// Reserved: the request is settling, or its issuance never completed.
    AwaitingSettlement(SettlementProgress),
    /// Reserved for a withdrawal clearance, which is never request evidence.
    ClearanceOnly,
    /// No nullifier row.
    Unknown,
    /// Finalized, but the archived proof or inputs are missing or malformed.
    Corrupt(String),
}

impl EvidenceStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ready(_) => "finalized",
            Self::AwaitingSettlement(progress)
                if progress.lease_status.is_none() && progress.lease_read_error.is_none() =>
            {
                "reserved_without_lease"
            }
            Self::AwaitingSettlement(_) => "reserved",
            Self::ClearanceOnly => "clearance",
            Self::Unknown => "unknown",
            Self::Corrupt(_) => "corrupt",
        }
    }
}

/// Settlement progress of a Reserved request, for operator status only. It
/// deliberately carries no client request ID: the nullifier already
/// correlates with the server, and status must not link note and request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementProgress {
    pub reservation_kind: String,
    pub reserved_at: u64,
    /// None: there is no lease row, so issuance never completed.
    pub lease_status: Option<String>,
    pub key_issued: bool,
    pub key_source: Option<String>,
    pub expires_at: Option<u64>,
    /// Server time at which settlement is next due.
    pub settle_after: Option<u64>,
    pub last_error: Option<String>,
    /// The lease row exists but could not be read; the server's settlement
    /// scan cannot read it either, so evidence may never be produced.
    pub lease_read_error: Option<String>,
}

/// Fully reconstructed challenge action for the v2 vault.
#[derive(Debug, Clone)]
pub struct ChallengeAction {
    pub note_id: u32,
    pub request_inputs: RequestPublicInputsV2,
    /// Eight big-endian BN254 coordinates, in the archived Groth16 wire order.
    pub proof_artifact: Vec<u8>,
    /// Current zero-slot path, independent of the historical request root.
    pub siblings: [Felt252; MERKLE_DEPTH],
}

impl ChallengeAction {
    /// ABI-encode the exact v2 tuple and archived proof for the vault.
    pub fn calldata(&self) -> Result<Vec<u8>, String> {
        let p = &self.request_inputs;
        if p.protocol_version != 2 {
            return Err("unsupported archived request protocol version".into());
        }
        if p.contract_address.as_bytes()[..12]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err("archived contract address exceeds 20 bytes".into());
        }
        if self.proof_artifact.len() != 256 {
            return Err("archived Groth16 proof must contain eight 32-byte coordinates".into());
        }
        // noteId + static 12-word tuple + bytes offset + static 32-word array.
        let head_words = 1 + 12 + 1 + MERKLE_DEPTH;
        let mut data = Keccak256::digest(CHALLENGE_SIGNATURE.as_bytes())[..4].to_vec();
        for value in [
            Felt252::from_u64(self.note_id as u64),
            Felt252::from_u64(p.protocol_version as u64),
            Felt252::from_u64(p.chain_id),
            p.contract_address,
            p.active_root,
            p.state_signing_key_x,
            p.state_signing_key_y,
            Felt252::from_u64(p.request_time),
            Felt252::from_u128(p.solvency_bound),
            p.request_nullifier,
            p.authorization_tag,
            p.anonymous_commitment_x,
            p.anonymous_commitment_y,
            Felt252::from_u64((head_words * 32) as u64),
        ] {
            data.extend_from_slice(value.as_bytes());
        }
        for sibling in self.siblings {
            data.extend_from_slice(sibling.as_bytes());
        }
        data.extend_from_slice(Felt252::from_u64(256).as_bytes());
        data.extend_from_slice(&self.proof_artifact);
        Ok(data)
    }

    /// Digest of everything a same-nonce replacement must keep: the note, the
    /// archived request tuple and the proof. Only siblings, gas and fees may
    /// differ between attempts on one nonce.
    pub fn evidence_digest(&self) -> String {
        let mut digest = Keccak256::new();
        digest.update(b"zkapi:v2:challenge-evidence\0");
        digest.update(self.note_id.to_be_bytes());
        for value in self.request_inputs.to_field_elements() {
            digest.update(value.as_bytes());
        }
        digest.update(&self.proof_artifact);
        format!("0x{}", hex::encode(digest.finalize()))
    }
}

pub struct ChallengeWatcher {
    store: Arc<NullifierStore>,
}

impl ChallengeWatcher {
    pub fn new(store: Arc<NullifierStore>) -> Self {
        Self { store }
    }

    /// The deployment the server recorded after verifying its keys on-chain.
    pub fn deployment_binding(&self) -> Result<Option<DeploymentBinding>, ServerError> {
        self.store.read_deployment_binding()
    }

    /// Classify the database state of an escaped nullifier. A database or
    /// lock failure is an error, never `Unknown`: reporting a fraudulent escape
    /// as unknown would silently disable its challenge.
    pub fn evidence_status(&self, nullifier: &Felt252) -> Result<EvidenceStatus, ServerError> {
        let Some(record) = self.store.try_lookup_by_nullifier(nullifier)? else {
            return Ok(EvidenceStatus::Unknown);
        };
        Ok(match record.status {
            NullifierStatus::ClearanceReserved => EvidenceStatus::ClearanceOnly,
            NullifierStatus::Reserved => {
                EvidenceStatus::AwaitingSettlement(self.settlement_progress(&record))
            }
            // Zero-charge transcripts are evidence too: an older zero-charge
            // anchor can precede charged states.
            NullifierStatus::Finalized => match finalized_inputs(&record, nullifier) {
                Ok(_) => EvidenceStatus::Ready(Box::new(record)),
                Err(reason) => EvidenceStatus::Corrupt(reason),
            },
        })
    }

    fn settlement_progress(&self, record: &TranscriptRecord) -> SettlementProgress {
        let mut progress = SettlementProgress {
            reservation_kind: record.reservation_kind.clone(),
            reserved_at: record.created_at,
            ..Default::default()
        };
        let Some(id) = record
            .client_request_id
            .as_deref()
            .filter(|_| record.reservation_kind == "openrouter_lease")
        else {
            return progress;
        };
        match self.store.try_lookup_openrouter_lease(id) {
            Ok(Some(lease)) if lease.request_nullifier != record.nullifier => {
                progress.lease_read_error =
                    Some("lease row belongs to another nullifier".to_string());
            }
            Ok(Some(lease)) => {
                progress.lease_status = Some(lease.status);
                progress.key_issued = lease.key_hash.is_some();
                progress.key_source = Some(lease.key_source);
                progress.expires_at = Some(lease.expires_at);
                progress.settle_after = Some(lease.settle_after);
                // Upstream errors may echo the key name, which embeds the ID.
                progress.last_error = lease.last_error.as_deref().map(|error| {
                    let mut error = error.replace(id, "[request]");
                    if let Some(oa_id) = lease.oa_client_request_id.as_deref() {
                        error = error.replace(oa_id, "[request]");
                    }
                    bounded(&error)
                });
            }
            Ok(None) => {}
            Err(error) => progress.lease_read_error = Some(bounded(&error.to_string())),
        }
        progress
    }

    /// The Finalized transcript for a nullifier, if it is valid evidence.
    pub fn challenge_transcript(&self, nullifier: &Felt252) -> Option<TranscriptRecord> {
        match self.evidence_status(nullifier) {
            Ok(EvidenceStatus::Ready(record)) => Some(*record),
            _ => None,
        }
    }

    pub fn build_challenge_action(
        &self,
        note_id: u32,
        nullifier: &Felt252,
        siblings: [Felt252; MERKLE_DEPTH],
    ) -> Result<ChallengeAction, String> {
        let record = match self.evidence_status(nullifier) {
            Ok(EvidenceStatus::Ready(record)) => record,
            Ok(EvidenceStatus::Corrupt(reason)) => {
                return Err(format!("corrupt finalized evidence: {reason}"))
            }
            Ok(other) => {
                return Err(format!(
                    "no finalized evidence for nullifier ({})",
                    other.label()
                ))
            }
            Err(error) => return Err(format!("evidence database read failed: {error}")),
        };
        let request_inputs = finalized_inputs(&record, nullifier)
            .map_err(|reason| format!("corrupt finalized evidence: {reason}"))?;
        let action = ChallengeAction {
            note_id,
            request_inputs,
            proof_artifact: record.proof_blob.ok_or("missing archived proof blob")?,
            siblings,
        };
        // Fail at the compatibility boundary, before submitting malformed calldata.
        action.calldata()?;
        Ok(action)
    }
}

/// The archived request inputs of a Finalized record, if its proof and inputs
/// are well formed and bound to the escaped nullifier.
fn finalized_inputs(
    record: &TranscriptRecord,
    nullifier: &Felt252,
) -> Result<RequestPublicInputsV2, String> {
    match record.proof_blob.as_deref() {
        Some(proof) if proof.len() == 256 => {}
        Some(_) => return Err("archived proof blob is not 256 bytes".to_string()),
        None => return Err("missing archived proof blob".to_string()),
    }
    let inputs: RequestPublicInputsV2 = serde_json::from_str(
        record
            .request_inputs_json
            .as_deref()
            .ok_or("missing archived request inputs")?,
    )
    .map_err(|error| format!("invalid archived v2 request inputs: {error}"))?;
    if inputs.request_nullifier != *nullifier {
        return Err("archived request nullifier mismatch".to_string());
    }
    Ok(inputs)
}

fn bounded(text: &str) -> String {
    text.chars().take(MAX_LAST_ERROR_CHARS).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{config::ServerConfig, processor::RequestProcessor, signer::ServerSigner};
    use base64::Engine;
    use zkapi_core::v2 as core;
    use zkapi_proof::compact::{balance_commitment, RequestProver, RequestWitnessData};
    use zkapi_types::wire::ApiRequestV2;
    use zkapi_types::{canonical_payload_hash, canonical_request_context};

    /// Prove a genesis request for note 0 and have the active processor accept
    /// and archive it, rather than hand-constructing a transcript that could
    /// drift from its writer. Each secret yields a distinct nullifier.
    async fn archive_v2_request(
        store: &Arc<NullifierStore>,
        secret: u64,
        client_request_id: &str,
    ) -> ApiRequestV2 {
        let setup_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/setup/v2");
        let signer = Arc::new(ServerSigner::new(
            &Felt252::from_u64(11),
            &Felt252::from_u64(12),
        ));
        let key = signer.state_public_key();
        let secret = Felt252::from_u64(secret);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry = now + 86_400;
        let siblings = core::zero_hashes()[..MERKLE_DEPTH].try_into().unwrap();
        let registration = core::registration_commitment(&secret);
        let leaf = core::note_leaf(0, &registration, 100, expiry);
        let root = core::merkle_root(0, &leaf, &siblings);
        let nullifier = core::nullifier(&secret, &Felt252::ONE);
        let test_config = ServerConfig {
            native_billing: Some(crate::test_support::native_config()),
            openrouter_leases: Some(crate::test_support::lease_config()),
            ..Default::default()
        };
        let payload = crate::test_support::lease_payload(&test_config, now);
        let payload_hash = canonical_payload_hash(payload.as_bytes());
        let request_context = canonical_request_context(client_request_id, &payload_hash);
        let blind = Felt252::from_u64(17);
        let anonymous = balance_commitment(100, &blind, &leaf);
        let public = RequestPublicInputsV2 {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Felt252::from_u64(0xdead),
            active_root: root,
            state_signing_key_x: key.x,
            state_signing_key_y: key.y,
            request_time: now,
            solvency_bound: 1,
            request_nullifier: nullifier,
            authorization_tag: core::authorization_tag(&nullifier, &request_context),
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        };
        let proof = RequestProver::load(&setup_dir)
            .unwrap()
            .prove(
                &public,
                RequestWitnessData {
                    secret,
                    request_context,
                    note_id: 0,
                    deposit_amount: 100,
                    expiry,
                    merkle_siblings: siblings,
                    current_balance: 100,
                    current_blinding: Felt252::ZERO,
                    rerandomization: blind,
                    current_anchor: Felt252::ONE,
                    is_genesis: true,
                    state_signature: None,
                },
            )
            .unwrap();
        let request = ApiRequestV2 {
            client_request_id: client_request_id.into(),
            payload_hash,
            payload,
            public_inputs: public.clone(),
            proof,
        };
        let processor = RequestProcessor::try_new(
            ServerConfig {
                contract_address: public.contract_address,
                request_charge_cap: 1,
                proof_setup_dir: setup_dir.to_string_lossy().into_owned(),
                ..test_config
            },
            store.clone(),
            signer,
            root,
        )
        .unwrap();
        processor.finalize_test_lease(&request, 1).unwrap();
        request
    }

    /// A real v2 proof accepted and archived by the active processor.
    pub(crate) async fn finalized_v2_request() -> (Arc<NullifierStore>, ApiRequestV2) {
        static FIXTURE: tokio::sync::OnceCell<(Arc<NullifierStore>, ApiRequestV2)> =
            tokio::sync::OnceCell::const_new();
        FIXTURE
            .get_or_init(|| async {
                let store = Arc::new(NullifierStore::in_memory().unwrap());
                let request = archive_v2_request(&store, 42, "challenge-v2").await;
                (store, request)
            })
            .await
            .clone()
    }

    /// Two finalized requests with distinct nullifiers in one archive, for an
    /// escape at one anchor followed by a re-escape at another.
    pub(crate) async fn two_finalized_v2_requests(
    ) -> (Arc<NullifierStore>, ApiRequestV2, ApiRequestV2) {
        static FIXTURE: tokio::sync::OnceCell<(Arc<NullifierStore>, ApiRequestV2, ApiRequestV2)> =
            tokio::sync::OnceCell::const_new();
        FIXTURE
            .get_or_init(|| async {
                let store = Arc::new(NullifierStore::in_memory().unwrap());
                let first = archive_v2_request(&store, 42, "challenge-v2").await;
                let second = archive_v2_request(&store, 43, "challenge-v2-second").await;
                assert_ne!(
                    first.public_inputs.request_nullifier,
                    second.public_inputs.request_nullifier
                );
                (store, first, second)
            })
            .await
            .clone()
    }

    /// The Finalized transcript bounded settlement writes for this request.
    pub(crate) fn finalized_transcript(request: &ApiRequestV2, charge: u128) -> TranscriptRecord {
        TranscriptRecord {
            nullifier: request.public_inputs.request_nullifier,
            status: NullifierStatus::Finalized,
            reservation_kind: "openrouter_lease".into(),
            client_request_id: Some(request.client_request_id.clone()),
            payload_hash: Some(request.payload_hash),
            charge_applied: Some(charge),
            response_code: Some(200),
            response_payload: Some("{}".into()),
            response_hash: Some(Felt252::from_u64(7)),
            next_commitment_x: None,
            next_commitment_y: None,
            next_anchor: Some(Felt252::from_u64(8)),
            blind_delta_srv: None,
            next_state_sig: None,
            policy_reason_code: None,
            policy_evidence_hash: None,
            proof_blob: Some(
                base64::engine::general_purpose::STANDARD
                    .decode(&request.proof.proof)
                    .unwrap(),
            ),
            request_inputs_json: Some(serde_json::to_string(&request.public_inputs).unwrap()),
            api_request_binding: None,
            created_at: 0,
            finalized_at: None,
        }
    }

    fn assert_exact_evidence(action: &ChallengeAction, request: &ApiRequestV2) {
        assert_eq!(action.request_inputs, request.public_inputs);
        assert_eq!(
            action.proof_artifact,
            base64::engine::general_purpose::STANDARD
                .decode(&request.proof.proof)
                .unwrap()
        );
    }

    #[tokio::test]
    async fn issued_lease_awaits_settlement_and_is_not_challenge_evidence() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease(&request, "oa_org", 1, 2, 3, 1.0)
            .unwrap();
        // Status never links a note to its request: the ID is redacted.
        store
            .record_openrouter_lease_error(
                &request.client_request_id,
                &format!("upstream rejected key zkapi-{}", request.client_request_id),
            )
            .unwrap();
        let watcher = ChallengeWatcher::new(store.clone());
        let nullifier = request.public_inputs.request_nullifier;
        match watcher.evidence_status(&nullifier).unwrap() {
            EvidenceStatus::AwaitingSettlement(progress) => assert_eq!(
                progress.last_error.as_deref(),
                Some("upstream rejected key zkapi-[request]")
            ),
            other => panic!("expected awaiting settlement, got {other:?}"),
        }
        for (status, issued) in [("provisioning", false), ("active", true)] {
            if issued {
                store
                    .activate_openrouter_lease(&request.client_request_id, "issued-key-hash")
                    .unwrap();
            }
            match watcher.evidence_status(&nullifier).unwrap() {
                EvidenceStatus::AwaitingSettlement(progress) => {
                    assert_eq!(progress.lease_status.as_deref(), Some(status));
                    assert_eq!(progress.key_issued, issued);
                    assert_eq!(progress.key_source.as_deref(), Some("oa_org"));
                    assert_eq!(progress.expires_at, Some(2));
                    assert_eq!(progress.settle_after, Some(3));
                    assert_eq!(progress.reservation_kind, "openrouter_lease");
                }
                other => panic!("{status} lease must await settlement, got {other:?}"),
            }
            assert!(watcher.challenge_transcript(&nullifier).is_none());
            let error = watcher
                .build_challenge_action(0, &nullifier, [Felt252::ZERO; MERKLE_DEPTH])
                .unwrap_err();
            assert!(error.contains("no finalized evidence"), "{error}");
        }
        let reservation = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(reservation.status, NullifierStatus::Reserved);
        assert!(reservation.response_hash.is_none());
        assert!(
            reservation.proof_blob.is_none(),
            "evidence classification must not finalize usage"
        );

        // Bounded settlement finalizes the exact archived request.
        store
            .finalize(&nullifier, &finalized_transcript(&request, 1))
            .unwrap();
        assert!(matches!(
            watcher.evidence_status(&nullifier).unwrap(),
            EvidenceStatus::Ready(_)
        ));
        let action = watcher
            .build_challenge_action(0, &nullifier, [Felt252::ZERO; MERKLE_DEPTH])
            .unwrap();
        assert_exact_evidence(&action, &request);
    }

    #[tokio::test]
    async fn direct_key_retirement_awaits_settlement_until_finalized() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease(&request, "openrouter", 1, 2, 3, 1.0)
            .unwrap();
        store
            .activate_openrouter_lease(&request.client_request_id, "issued-key-hash")
            .unwrap();
        let watcher = ChallengeWatcher::new(store.clone());
        let nullifier = request.public_inputs.request_nullifier;
        for (from, to) in [
            ("active", "retiring"),
            ("retiring", "disabled"),
            ("disabled", "revoking"),
        ] {
            store
                .advance_openrouter_retirement(&request.client_request_id, from, to, 50, None)
                .unwrap();
            match watcher.evidence_status(&nullifier).unwrap() {
                EvidenceStatus::AwaitingSettlement(progress) => {
                    assert_eq!(progress.lease_status.as_deref(), Some(to));
                    assert!(progress.key_issued);
                    assert_eq!(progress.settle_after, Some(50));
                }
                other => panic!("{to} must await settlement, got {other:?}"),
            }
            assert!(watcher.challenge_transcript(&nullifier).is_none());
        }
        store
            .finalize(&nullifier, &finalized_transcript(&request, 1))
            .unwrap();
        let action = watcher
            .build_challenge_action(0, &nullifier, [Felt252::ZERO; MERKLE_DEPTH])
            .unwrap();
        assert_exact_evidence(&action, &request);
    }

    #[tokio::test]
    async fn zero_charge_finalized_transcript_is_challenge_evidence() {
        // A zero-charge anchor can precede charged states; skipping it would
        // let an escape at that older anchor avoid every later charge.
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let nullifier = request.public_inputs.request_nullifier;
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .finalize(&nullifier, &finalized_transcript(&request, 0))
            .unwrap();
        let action = ChallengeWatcher::new(store)
            .build_challenge_action(0, &nullifier, [Felt252::ZERO; MERKLE_DEPTH])
            .unwrap();
        assert_exact_evidence(&action, &request);
    }

    #[tokio::test]
    async fn finalized_record_missing_archived_proof_is_corrupt() {
        let (_, request) = finalized_v2_request().await;
        let nullifier = request.public_inputs.request_nullifier;
        for (label, mutate) in [
            (
                "missing archived proof blob",
                (|record: &mut TranscriptRecord| record.proof_blob = None)
                    as fn(&mut TranscriptRecord),
            ),
            ("not 256 bytes", |record| {
                record.proof_blob.as_mut().unwrap().pop();
            }),
            ("missing archived request inputs", |record| {
                record.request_inputs_json = None
            }),
            ("invalid archived v2 request inputs", |record| {
                record.request_inputs_json = Some("{}".into())
            }),
        ] {
            let store = Arc::new(NullifierStore::in_memory().unwrap());
            store.reserve_openrouter_lease(&request).unwrap();
            let mut record = finalized_transcript(&request, 1);
            mutate(&mut record);
            store.finalize(&nullifier, &record).unwrap();
            let watcher = ChallengeWatcher::new(store);
            match watcher.evidence_status(&nullifier).unwrap() {
                EvidenceStatus::Corrupt(reason) => assert!(reason.contains(label), "{reason}"),
                other => panic!("{label}: expected corrupt evidence, got {other:?}"),
            }
            assert!(watcher.challenge_transcript(&nullifier).is_none());
            let error = watcher
                .build_challenge_action(0, &nullifier, [Felt252::ZERO; MERKLE_DEPTH])
                .unwrap_err();
            assert!(error.starts_with("corrupt finalized evidence"), "{error}");
        }
    }

    #[tokio::test]
    async fn finalized_record_with_mismatched_archived_nullifier_is_corrupt() {
        let (_, request) = finalized_v2_request().await;
        let nullifier = request.public_inputs.request_nullifier;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        store.reserve_openrouter_lease(&request).unwrap();
        let mut record = finalized_transcript(&request, 1);
        let mut inputs = request.public_inputs.clone();
        inputs.request_nullifier = Felt252::from_u64(999);
        record.request_inputs_json = Some(serde_json::to_string(&inputs).unwrap());
        store.finalize(&nullifier, &record).unwrap();
        match ChallengeWatcher::new(store)
            .evidence_status(&nullifier)
            .unwrap()
        {
            EvidenceStatus::Corrupt(reason) => {
                assert_eq!(reason, "archived request nullifier mismatch")
            }
            other => panic!("expected corrupt evidence, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn clearance_and_unknown_nullifiers_are_not_evidence() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let clearance = Felt252::from_u64(5);
        store.reserve_clearance(&clearance).unwrap();
        let watcher = ChallengeWatcher::new(store);
        assert!(matches!(
            watcher.evidence_status(&clearance).unwrap(),
            EvidenceStatus::ClearanceOnly
        ));
        assert!(matches!(
            watcher.evidence_status(&Felt252::from_u64(6)).unwrap(),
            EvidenceStatus::Unknown
        ));
        for nullifier in [clearance, Felt252::from_u64(6)] {
            assert!(watcher.challenge_transcript(&nullifier).is_none());
            assert!(watcher
                .build_challenge_action(0, &nullifier, [Felt252::ZERO; MERKLE_DEPTH])
                .unwrap_err()
                .contains("no finalized evidence"));
        }
    }

    #[tokio::test]
    async fn reservation_without_lease_row_reports_incomplete_issuance() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        store.reserve_openrouter_lease(&request).unwrap();
        let watcher = ChallengeWatcher::new(store);
        let status = watcher
            .evidence_status(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(status.label(), "reserved_without_lease");
        match status {
            EvidenceStatus::AwaitingSettlement(progress) => {
                assert_eq!(progress.lease_status, None);
                assert!(!progress.key_issued);
                assert_eq!(progress.lease_read_error, None);
            }
            other => panic!("expected awaiting settlement, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn evidence_database_errors_are_errors_not_unknown() {
        let (_, request) = finalized_v2_request().await;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let server = NullifierStore::new(&path).unwrap();
        server.reserve_openrouter_lease(&request).unwrap();
        server
            .create_openrouter_lease(&request, "oa_org", 1, 2, 3, 1.0)
            .unwrap();
        let watcher =
            ChallengeWatcher::new(Arc::new(NullifierStore::open_read_only(&path).unwrap()));
        let nullifier = request.public_inputs.request_nullifier;
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("UPDATE openrouter_leases SET api_request_json = 'not json';")
            .unwrap();
        match watcher.evidence_status(&nullifier).unwrap() {
            EvidenceStatus::AwaitingSettlement(progress) => {
                assert!(progress.lease_read_error.is_some());
                assert_eq!(progress.lease_status, None);
            }
            other => panic!("expected awaiting settlement, got {other:?}"),
        }
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TABLE nullifiers;")
            .unwrap();
        assert!(watcher.evidence_status(&nullifier).is_err());
        assert!(watcher
            .build_challenge_action(0, &nullifier, [Felt252::ZERO; MERKLE_DEPTH])
            .unwrap_err()
            .starts_with("evidence database read failed"));
    }

    #[tokio::test]
    async fn active_v2_processor_transcript_builds_challenge_calldata() {
        let (store, request) = finalized_v2_request().await;
        let nullifier = request.public_inputs.request_nullifier;
        let watcher = ChallengeWatcher::new(store);
        let action = watcher
            .build_challenge_action(0, &nullifier, [Felt252::ZERO; MERKLE_DEPTH])
            .unwrap();
        assert_eq!(
            serde_json::to_value(&action.request_inputs).unwrap(),
            serde_json::to_value(&request.public_inputs).unwrap()
        );
        assert_eq!(
            action.proof_artifact,
            base64::engine::general_purpose::STANDARD
                .decode(&request.proof.proof)
                .unwrap()
        );
        let calldata = action.calldata().unwrap();
        assert_eq!(&calldata[..4], &[0x8a, 0x43, 0x46, 0x7c]);
        assert_eq!(calldata.len(), 4 + (46 + 1 + 8) * 32);
        assert_eq!(
            &calldata[4 + 4 * 32..4 + 5 * 32],
            request.public_inputs.active_root.as_bytes()
        );
        assert_eq!(&calldata[4 + 9 * 32..4 + 10 * 32], nullifier.as_bytes());
        assert_eq!(
            &calldata[4 + 13 * 32..4 + 14 * 32],
            Felt252::from_u64(46 * 32).as_bytes()
        );
        assert_eq!(&calldata[4 + 47 * 32..], action.proof_artifact);
        // Siblings change neither the evidence digest nor anything else.
        let mut refreshed = action.clone();
        refreshed.siblings[0] = Felt252::from_u64(1);
        assert_eq!(refreshed.evidence_digest(), action.evidence_digest());
        assert_ne!(refreshed.calldata().unwrap(), calldata);
        refreshed.note_id = 1;
        assert_ne!(refreshed.evidence_digest(), action.evidence_digest());
        let mut malformed = action.clone();
        malformed.proof_artifact.pop();
        assert!(malformed.calldata().is_err());
        malformed = action;
        malformed.request_inputs.protocol_version = 1;
        assert!(malformed.calldata().is_err());
    }
}
