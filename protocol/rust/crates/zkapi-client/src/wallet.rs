//! zkAPI v2 wallet: compact Groth16 proofs and proof-friendly state signatures.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    add_blindings, balance_commitment, random_field, random_scalar, rerandomize, server_update,
    verify_signature, RequestProver, RequestWitnessData, WithdrawalProver, WithdrawalWitnessData,
};
use zkapi_types::wire::{
    ApiRequestV2, ClearanceOwnershipProof, ClearanceRequest, ClearanceResponseV2, CurvePointWire,
    ErrorResponse, Groth16ProofWire, RecoveryResponseV2, RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash, Felt252,
    RequestPublicInputsV2, WithdrawalPublicInputsV2, MERKLE_DEPTH,
};

use crate::config::{ClientConfig, ClientProofMode};
use crate::error::ClientError;
use crate::journal::PendingRequestJournal;
use crate::note_state::NoteState;

/// Clearance attempts with the same body on a retriable stale_root (the
/// server's view of the vault root lags) or capacity_exhausted, before the
/// caller must refresh its path and prove again.
const CLEARANCE_ATTEMPTS: u32 = 3;
const CLEARANCE_RETRY_DELAY: Duration = Duration::from_millis(500);

pub struct Wallet {
    config: ClientConfig,
    state: Option<NoteState>,
    state_path: PathBuf,
    journal_path: PathBuf,
    http: reqwest::Client,
}

impl Wallet {
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let state_dir = PathBuf::from(&config.state_dir);
        std::fs::create_dir_all(&state_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let state_path = state_dir.join("note_state.json");
        let journal_path = state_dir.join("pending_journal.json");
        let state = state_path
            .exists()
            .then(|| NoteState::load(&state_path))
            .transpose()?;
        Ok(Self {
            config,
            state,
            state_path,
            journal_path,
            http: reqwest::Client::new(),
        })
    }

    pub fn state(&self) -> Option<&NoteState> {
        self.state.as_ref()
    }

    pub fn has_pending_request(&self) -> bool {
        PendingRequestJournal::read(&self.journal_path)
            .ok()
            .flatten()
            .is_some()
    }

    pub fn get_pending_journal(&self) -> Result<Option<PendingRequestJournal>, ClientError> {
        PendingRequestJournal::read(&self.journal_path)
    }

    /// Return the durable, already-proved request for an idempotent transport
    /// retry. Older journals may not contain the full request.
    pub fn pending_api_request(&self) -> Result<Option<ApiRequestV2>, ClientError> {
        Ok(PendingRequestJournal::read(&self.journal_path)?
            .and_then(|journal| journal.prepared_request))
    }

    pub fn generate_deposit_params(&self) -> (Felt252, Felt252) {
        loop {
            let secret = random_field();
            if !secret.is_zero() {
                return (secret, core::registration_commitment(&secret));
            }
        }
    }

    pub fn confirm_deposit(
        &mut self,
        secret: Felt252,
        note_id: u32,
        deposit_amount: u128,
        expiry: u64,
    ) -> Result<(), ClientError> {
        if self.state.is_some() {
            return Err(ClientError::NoteAlreadyExists);
        }
        let blinding = random_scalar();
        let commitment = balance_commitment(
            deposit_amount,
            &blinding,
            &core::note_leaf(
                note_id,
                &core::registration_commitment(&secret),
                deposit_amount,
                expiry,
            ),
        );
        let state = NoteState::new_from_deposit(
            self.config.protocol_version,
            self.config.chain_id,
            self.config.contract_address,
            note_id,
            secret,
            deposit_amount,
            expiry,
            blinding.to_hex(),
            commitment.x,
            commitment.y,
        );
        state.save(&self.state_path)?;
        self.state = Some(state);
        Ok(())
    }

    pub async fn request_flow(
        &mut self,
        payload: &str,
        payload_hash: Felt252,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<RequestResponseV2, ClientError> {
        let request = self.prepare_request(payload, payload_hash, active_root, merkle_siblings)?;
        let response = self
            .http
            .post(format!(
                "{}/v2/requests",
                self.config.server_url.trim_end_matches('/')
            ))
            .json(&request)
            .send()
            .await
            .map_err(|error| ClientError::ServerError(error.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| ClientError::ServerError(error.to_string()))?;
        if !status.is_success() {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&body) {
                if error.error_code == "stale_root" {
                    self.clear_pending_request()?;
                    return Err(ClientError::StaleRoot);
                }
                return Err(ClientError::ServerError(format!(
                    "{}: {}",
                    error.error_code, error.error_message
                )));
            }
            return Err(ClientError::ServerError(format!("HTTP {status}: {body}")));
        }
        let response: RequestResponseV2 = serde_json::from_str(&body)
            .map_err(|error| ClientError::InvalidResponse(error.to_string()))?;
        self.complete_pending_response(&response)?;
        Ok(response)
    }

    /// Generate and durably journal one zkAPI request without submitting it.
    /// This is used by multi-network-request flows such as an OpenRouter lease,
    /// whose zkAPI state transition completes only after later settlement.
    pub fn prepare_request(
        &mut self,
        payload: &str,
        payload_hash: Felt252,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<ApiRequestV2, ClientError> {
        if self.has_pending_request() {
            return Err(ClientError::PendingRequest);
        }
        if canonical_payload_hash(payload.as_bytes()) != payload_hash {
            return Err(ClientError::InvalidResponse(
                "payload_hash does not match payload bytes".to_string(),
            ));
        }
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let solvency_bound = state.solvency_bound(
            self.config.policy_enabled,
            self.config.request_charge_cap,
            self.config.policy_charge_cap,
        );
        if state.current_balance < solvency_bound {
            return Err(ClientError::InsufficientBalance {
                needed: solvency_bound,
                available: state.current_balance,
            });
        }

        let siblings = siblings_array(merkle_siblings)?;
        let current_blinding = parse_scalar(&state.balance_blinding)?;
        let expected_current = balance_commitment(
            state.current_balance,
            &current_blinding,
            &state_note_leaf(state),
        );
        ensure_stored_commitment(state, &expected_current)?;
        let rerandomization = random_scalar();
        let anonymous = rerandomize(&expected_current, &rerandomization)
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let nullifier = core::nullifier(&state.secret_s, &state.current_anchor);
        let client_request_id = uuid::Uuid::new_v4().to_string();
        let request_context = canonical_request_context(&client_request_id, &payload_hash);
        let public_inputs = RequestPublicInputsV2 {
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            state_signing_key_x: self.config.state_signing_key.x,
            state_signing_key_y: self.config.state_signing_key.y,
            request_time: now_seconds(),
            solvency_bound,
            request_nullifier: nullifier,
            authorization_tag: core::authorization_tag(&nullifier, &request_context),
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        };
        let prover = RequestProver::load(self.setup_dir())
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let proof = prover
            .prove(
                &public_inputs,
                RequestWitnessData {
                    secret: state.secret_s,
                    request_context,
                    note_id: state.note_id,
                    deposit_amount: state.deposit_amount,
                    expiry: state.expiry_ts,
                    merkle_siblings: siblings,
                    current_balance: state.current_balance,
                    current_blinding,
                    rerandomization,
                    current_anchor: state.current_anchor,
                    is_genesis: state.is_genesis,
                    state_signature: state.state_signature,
                },
            )
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;

        let request = ApiRequestV2 {
            client_request_id: client_request_id.clone(),
            payload: payload.to_string(),
            payload_hash,
            public_inputs,
            proof,
        };
        PendingRequestJournal::write(
            &self.journal_path,
            &PendingRequestJournal {
                exists: true,
                client_request_id,
                nullifier,
                payload_hash,
                user_rerandomization: rerandomization,
                created_at_ms: now_ms(),
                prepared_request: Some(request.clone()),
            },
        )?;
        Ok(request)
    }

    /// Verify a finalized response for the currently journaled request, persist
    /// the next note state, and clear the journal atomically after the state is
    /// safe on disk.
    pub fn complete_pending_response(
        &mut self,
        response: &RequestResponseV2,
    ) -> Result<(), ClientError> {
        let journal =
            PendingRequestJournal::read(&self.journal_path)?.ok_or(ClientError::PendingRequest)?;
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let current = balance_commitment(
            state.current_balance,
            &parse_scalar(&state.balance_blinding)?,
            &state_note_leaf(state),
        );
        ensure_stored_commitment(state, &current)?;
        let anonymous = rerandomize(&current, &journal.user_rerandomization)
            .map_err(|error| ClientError::VerificationFailed(error.to_string()))?;
        self.apply_response(
            response,
            &journal.client_request_id,
            journal.nullifier,
            &anonymous,
            journal.user_rerandomization,
        )?;
        PendingRequestJournal::clear(&self.journal_path)?;
        Ok(())
    }

    /// Clear a request that the server explicitly rejected before reserving its
    /// nullifier (for example because the indexer root was stale).
    pub fn clear_pending_request(&self) -> Result<(), ClientError> {
        PendingRequestJournal::clear(&self.journal_path)
    }

    pub async fn recover(&mut self) -> Result<Option<RequestResponseV2>, ClientError> {
        let Some(journal) = PendingRequestJournal::read(&self.journal_path)? else {
            return Ok(None);
        };
        let response = self
            .http
            .get(format!(
                "{}/v2/requests/{}",
                self.config.server_url.trim_end_matches('/'),
                journal.client_request_id
            ))
            .send()
            .await
            .map_err(|error| ClientError::ServerError(error.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let recovery: RecoveryResponseV2 = response
            .error_for_status()
            .map_err(|error| ClientError::ServerError(error.to_string()))?
            .json()
            .await
            .map_err(|error| ClientError::InvalidResponse(error.to_string()))?;
        let Some(response) = recovery.request_response else {
            return Ok(None);
        };
        self.complete_pending_response(&response)?;
        Ok(Some(response))
    }

    /// Obtain the server's clearance and prove a mutual close. The server
    /// requires an escape-form withdrawal proof of note ownership. That proof
    /// is also a valid escape input, so it is built for the same destination
    /// and current balance as this close, never a placeholder. Returns
    /// `ClientError::StaleRoot` if the server still rejects `active_root`
    /// after retries: refresh the Merkle path and call again.
    pub async fn withdrawal_mutual_close(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<(WithdrawalPublicInputsV2, Groth16ProofWire), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let nullifier = core::nullifier(&state.secret_s, &state.current_anchor);
        let (public_inputs, proof) = self.build_withdrawal(
            destination,
            active_root,
            merkle_siblings.clone(),
            false,
            None,
        )?;
        let clearance = self
            .request_clearance(
                &nullifier,
                ClearanceOwnershipProof {
                    public_inputs,
                    proof,
                },
            )
            .await?;
        let message = core::clearance_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &nullifier,
        );
        if !verify_signature(
            &self.config.clearance_signing_key,
            &message,
            &clearance.signature,
        )
        .map_err(|error| ClientError::VerificationFailed(error.to_string()))?
        {
            return Err(ClientError::VerificationFailed(
                "invalid clearance signature".to_string(),
            ));
        }
        self.build_withdrawal(
            destination,
            active_root,
            merkle_siblings,
            true,
            Some(clearance.signature),
        )
    }

    pub fn withdrawal_escape_hatch(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<(WithdrawalPublicInputsV2, Groth16ProofWire), ClientError> {
        self.build_withdrawal(destination, active_root, merkle_siblings, false, None)
    }

    pub fn archive_note(&mut self) -> Result<(), ClientError> {
        if let Some(state) = &self.state {
            state.archive(&self.state_path)?;
        }
        self.state = None;
        PendingRequestJournal::clear(&self.journal_path)?;
        Ok(())
    }

    fn build_withdrawal(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
        has_clearance: bool,
        clearance_signature: Option<zkapi_types::SchnorrSignature>,
    ) -> Result<(WithdrawalPublicInputsV2, Groth16ProofWire), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let nullifier = core::nullifier(&state.secret_s, &state.current_anchor);
        let mut destination_bytes = [0u8; 32];
        destination_bytes[12..].copy_from_slice(&destination);
        let destination_field = Felt252(destination_bytes);
        let public = WithdrawalPublicInputsV2 {
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            state_signing_key_x: self.config.state_signing_key.x,
            state_signing_key_y: self.config.state_signing_key.y,
            clearance_signing_key_x: self.config.clearance_signing_key.x,
            clearance_signing_key_y: self.config.clearance_signing_key.y,
            note_id: state.note_id,
            final_balance: state.current_balance,
            destination,
            withdrawal_nullifier: nullifier,
            has_clearance,
            withdrawal_tag: core::withdrawal_tag(
                &nullifier,
                &destination_field,
                state.current_balance,
                has_clearance,
            ),
        };
        let prover = WithdrawalProver::load(self.setup_dir())
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let proof = prover
            .prove(
                &public,
                WithdrawalWitnessData {
                    secret: state.secret_s,
                    deposit_amount: state.deposit_amount,
                    expiry: state.expiry_ts,
                    merkle_siblings: siblings_array(merkle_siblings)?,
                    final_blinding: parse_scalar(&state.balance_blinding)?,
                    current_anchor: state.current_anchor,
                    is_genesis: state.is_genesis,
                    state_signature: state.state_signature,
                    clearance_signature,
                },
            )
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        Ok((public, proof))
    }

    async fn request_clearance(
        &self,
        nullifier: &Felt252,
        ownership_proof: ClearanceOwnershipProof,
    ) -> Result<ClearanceResponseV2, ClientError> {
        let request = ClearanceRequest {
            withdrawal_nullifier: *nullifier,
            ownership_proof: Some(ownership_proof),
        };
        let mut delay = CLEARANCE_RETRY_DELAY;
        for attempt in 1..=CLEARANCE_ATTEMPTS {
            let response = self
                .http
                .post(format!(
                    "{}/v2/withdraw/clearance",
                    self.config.server_url.trim_end_matches('/')
                ))
                .json(&request)
                .send()
                .await
                .map_err(|error| ClientError::ServerError(error.to_string()))?;
            let status = response.status();
            let body = response
                .text()
                .await
                .map_err(|error| ClientError::ServerError(error.to_string()))?;
            if status.is_success() {
                return serde_json::from_str(&body)
                    .map_err(|error| ClientError::InvalidResponse(error.to_string()));
            }
            let Ok(error) = serde_json::from_str::<ErrorResponse>(&body) else {
                return Err(ClientError::ServerError(format!("HTTP {status}: {body}")));
            };
            let retriable = matches!(
                error.error_code.as_str(),
                "stale_root" | "capacity_exhausted"
            );
            if retriable && attempt < CLEARANCE_ATTEMPTS {
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2);
                continue;
            }
            if error.error_code == "stale_root" {
                return Err(ClientError::StaleRoot);
            }
            return Err(ClientError::ServerError(format!(
                "{}: {}",
                error.error_code, error.error_message
            )));
        }
        Err(ClientError::StaleRoot)
    }

    fn apply_response(
        &mut self,
        response: &RequestResponseV2,
        request_id: &str,
        nullifier: Felt252,
        anonymous: &CurvePointWire,
        rerandomization: Felt252,
    ) -> Result<(), ClientError> {
        if response.client_request_id != request_id || response.request_nullifier != nullifier {
            return Err(ClientError::VerificationFailed(
                "response request identity mismatch".to_string(),
            ));
        }
        if canonical_response_hash(response.response_payload.as_bytes()) != response.response_hash {
            return Err(ClientError::VerificationFailed(
                "response payload hash mismatch".to_string(),
            ));
        }
        let cap = if self.config.policy_enabled {
            self.config.policy_charge_cap
        } else {
            self.config.request_charge_cap
        };
        if response.charge_applied > cap || response.next_anchor.is_zero() {
            return Err(ClientError::VerificationFailed(
                "invalid charge or next anchor".to_string(),
            ));
        }
        let expected = server_update(
            anonymous,
            response.charge_applied,
            &response.blind_delta_srv,
        )
        .map_err(|error| ClientError::VerificationFailed(error.to_string()))?;
        if expected != response.next_commitment {
            return Err(ClientError::VerificationFailed(
                "next commitment algebra mismatch".to_string(),
            ));
        }
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let message = core::state_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &response.next_commitment.x,
            &response.next_commitment.y,
            &response.next_anchor,
        );
        if !verify_signature(
            &self.config.state_signing_key,
            &message,
            &response.next_state_signature,
        )
        .map_err(|error| ClientError::VerificationFailed(error.to_string()))?
        {
            return Err(ClientError::VerificationFailed(
                "invalid next-state signature".to_string(),
            ));
        }

        let current_blinding = parse_scalar(&state.balance_blinding)?;
        let next_blinding = add_blindings(
            &add_blindings(&current_blinding, &rerandomization),
            &response.blind_delta_srv,
        );
        let mut next = state.clone();
        next.current_balance = next
            .current_balance
            .checked_sub(response.charge_applied)
            .ok_or_else(|| ClientError::VerificationFailed("charge exceeds balance".to_string()))?;
        next.balance_blinding = next_blinding.to_hex();
        next.current_commitment_x = response.next_commitment.x;
        next.current_commitment_y = response.next_commitment.y;
        next.current_anchor = response.next_anchor;
        next.is_genesis = false;
        next.state_signature = Some(response.next_state_signature);
        next.save(&self.state_path)?;
        self.state = Some(next);
        Ok(())
    }

    fn setup_dir(&self) -> &str {
        match &self.config.proof_mode {
            ClientProofMode::Groth16 { setup_dir } => setup_dir,
        }
    }
}

fn ensure_stored_commitment(
    state: &NoteState,
    commitment: &CurvePointWire,
) -> Result<(), ClientError> {
    if commitment.x != state.current_commitment_x || commitment.y != state.current_commitment_y {
        return Err(ClientError::VerificationFailed(
            "persisted balance commitment is inconsistent".to_string(),
        ));
    }
    Ok(())
}

fn parse_scalar(value: &str) -> Result<Felt252, ClientError> {
    Felt252::from_hex(value).map_err(ClientError::Serialization)
}

fn siblings_array(values: Vec<Felt252>) -> Result<[Felt252; MERKLE_DEPTH], ClientError> {
    values.try_into().map_err(|values: Vec<Felt252>| {
        ClientError::ProofGeneration(format!(
            "expected {MERKLE_DEPTH} Merkle siblings, got {}",
            values.len()
        ))
    })
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_ms() -> u64 {
    now_seconds().saturating_mul(1_000)
}

fn state_note_leaf(state: &NoteState) -> Felt252 {
    core::note_leaf(
        state.note_id,
        &core::registration_commitment(&state.secret_s),
        state.deposit_amount,
        state.expiry_ts,
    )
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::{Arc, Mutex};

    use zkapi_proof::compact::{CompactSigner, WithdrawalVerifier};

    use super::*;

    const DEPOSIT: u128 = 1_950_000;
    const EXPIRY: u64 = 4_000_000_000;

    fn setup_dir() -> String {
        format!("{}/../../../setup/v2", env!("CARGO_MANIFEST_DIR"))
    }

    struct Fixture {
        wallet: Wallet,
        clearance_signer: CompactSigner,
        active_root: Felt252,
        siblings: Vec<Felt252>,
        state_dir: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.state_dir);
        }
    }

    fn fixture(server_url: String) -> Fixture {
        let state_signer = CompactSigner::from_seed(&Felt252::from_u64(7));
        let clearance_signer = CompactSigner::from_seed(&Felt252::from_u64(8));
        let state_dir = std::env::temp_dir().join(format!("zkapi-wallet-{}", uuid::Uuid::new_v4()));
        let mut wallet = Wallet::new(ClientConfig {
            protocol_version: 2,
            chain_id: 11_155_111,
            contract_address: Felt252::from_u64(0x1234),
            request_charge_cap: 50_000,
            policy_charge_cap: 0,
            policy_enabled: false,
            server_url,
            state_dir: state_dir.to_string_lossy().into_owned(),
            proof_mode: ClientProofMode::Groth16 {
                setup_dir: setup_dir(),
            },
            state_signing_key: state_signer.public_key(),
            clearance_signing_key: clearance_signer.public_key(),
        })
        .unwrap();
        let (secret, registration) = wallet.generate_deposit_params();
        wallet.confirm_deposit(secret, 0, DEPOSIT, EXPIRY).unwrap();
        let siblings: [Felt252; MERKLE_DEPTH] =
            core::zero_hashes()[..MERKLE_DEPTH].try_into().unwrap();
        let leaf = core::note_leaf(0, &registration, DEPOSIT, EXPIRY);
        Fixture {
            active_root: core::merkle_root(0, &leaf, &siblings),
            siblings: siblings.to_vec(),
            wallet,
            clearance_signer,
            state_dir,
        }
    }

    fn clearance_body(fixture: &Fixture) -> String {
        let state = fixture.wallet.state().unwrap();
        let nullifier = core::nullifier(&state.secret_s, &state.current_anchor);
        let message = core::clearance_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &nullifier,
        );
        serde_json::to_string(&ClearanceResponseV2 {
            status: "ok".into(),
            withdrawal_nullifier: nullifier,
            signature: fixture.clearance_signer.sign(&message),
        })
        .unwrap()
    }

    fn stale_root_body() -> String {
        serde_json::json!({"status":"error", "client_request_id":"0x1", "error_code":"stale_root",
            "error_message":"stale root", "retriable":true, "latest_root":"0x7"})
        .to_string()
    }

    type Recorded = Arc<Mutex<Vec<serde_json::Value>>>;

    /// A minimal HTTP/1.1 server: one scripted response per connection.
    fn serve(responses: Arc<Mutex<Vec<(u16, String)>>>) -> (String, Recorded) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let recorded: Recorded = Arc::default();
        let bodies = recorded.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                assert!(request_line.starts_with("POST /v2/withdraw/clearance "));
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                bodies
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(&body).unwrap());
                let (status, response) = {
                    let mut responses = responses.lock().unwrap();
                    if responses.len() > 1 {
                        responses.remove(0)
                    } else {
                        responses[0].clone()
                    }
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} Scripted\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response}",
                    response.len()
                )
                .unwrap();
            }
        });
        (url, recorded)
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn mutual_close_proves_ownership_for_the_real_destination_and_balance() {
        let responses = Arc::new(Mutex::new(Vec::new()));
        let (url, recorded) = serve(responses.clone());
        let fixture = fixture(url);
        responses
            .lock()
            .unwrap()
            .push((200, clearance_body(&fixture)));
        let destination = [0x42u8; 20];
        let (close, _) = runtime()
            .block_on(fixture.wallet.withdrawal_mutual_close(
                destination,
                fixture.active_root,
                fixture.siblings.clone(),
            ))
            .unwrap();
        assert!(close.has_clearance);
        let bodies = recorded.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        let request: ClearanceRequest = serde_json::from_value(bodies[0].clone()).unwrap();
        assert_eq!(request.withdrawal_nullifier, close.withdrawal_nullifier);
        let ownership = request.ownership_proof.unwrap();
        let proven = &ownership.public_inputs;
        assert!(!proven.has_clearance);
        assert_eq!(proven.destination, destination);
        assert_eq!(proven.final_balance, close.final_balance);
        assert_eq!(proven.final_balance, DEPOSIT);
        assert_eq!(proven.withdrawal_nullifier, close.withdrawal_nullifier);
        assert_eq!(proven.active_root, fixture.active_root);
        assert_eq!(
            proven.clearance_signing_key_x,
            fixture.clearance_signer.public_key().x
        );
        // A genuine escape-form proof the server can verify.
        assert!(WithdrawalVerifier::load(setup_dir())
            .unwrap()
            .verify(proven, &ownership.proof)
            .unwrap());
    }

    #[test]
    fn mutual_close_retries_a_stale_root_then_asks_for_a_fresh_path() {
        let responses = Arc::new(Mutex::new(Vec::new()));
        let (url, recorded) = serve(responses.clone());
        let fixture = fixture(url);
        // The server's view of the vault root lags once, then catches up.
        responses
            .lock()
            .unwrap()
            .extend([(409, stale_root_body()), (200, clearance_body(&fixture))]);
        let runtime = runtime();
        runtime
            .block_on(fixture.wallet.withdrawal_mutual_close(
                [0x11; 20],
                fixture.active_root,
                fixture.siblings.clone(),
            ))
            .unwrap();
        {
            let mut bodies = recorded.lock().unwrap();
            assert_eq!(bodies.len(), 2);
            assert_eq!(bodies[0], bodies[1], "a retry resends the same proof");
            bodies.clear();
        }
        // A root the server keeps rejecting needs a fresh path and proof.
        *responses.lock().unwrap() = vec![(409, stale_root_body())];
        let error = runtime
            .block_on(fixture.wallet.withdrawal_mutual_close(
                [0x11; 20],
                fixture.active_root,
                fixture.siblings.clone(),
            ))
            .unwrap_err();
        assert!(matches!(error, ClientError::StaleRoot), "{error}");
        assert_eq!(recorded.lock().unwrap().len(), CLEARANCE_ATTEMPTS as usize);
        // Other refusals are reported, not retried.
        *responses.lock().unwrap() = vec![(
            400,
            serde_json::json!({"status":"error", "client_request_id":"0x1",
                "error_code":"invalid_proof", "error_message":"bad", "retriable":false})
            .to_string(),
        )];
        recorded.lock().unwrap().clear();
        let error = runtime
            .block_on(fixture.wallet.withdrawal_mutual_close(
                [0x11; 20],
                fixture.active_root,
                fixture.siblings.clone(),
            ))
            .unwrap_err();
        assert!(error.to_string().contains("invalid_proof"), "{error}");
        assert_eq!(recorded.lock().unwrap().len(), 1);
    }
}
