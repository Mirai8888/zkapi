//! zkAPI v2 wallet for circuit `zkapi-v2-concession-v1`: compact Groth16
//! proofs, note-bound nullifiers, derived successor anchors and the three
//! withdrawal kinds (escape, mutual close, ownership proof).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    add_blindings, balance_commitment, random_field, random_scalar, rerandomize, server_update,
    verify_signature, withdrawal_public_inputs, RequestProver, RequestWitnessData,
    WithdrawalProver, WithdrawalStatementParams, WithdrawalWitnessData,
};
use zkapi_types::wire::{
    ApiRequestV2, ClearanceOwnershipProofV2C, ClearanceRequestV2C, ClearanceResponseV2,
    CurvePointWire, ErrorResponse, Groth16ProofWire, RecoveryResponseV2, RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash, Felt252,
    RequestPublicInputsV2, WithdrawalKind, WithdrawalPublicInputsV2C, MERKLE_DEPTH,
};

use crate::config::{ClientConfig, ClientProofMode};
use crate::error::ClientError;
use crate::journal::{read_archive, ArchiveListing, ArchivedRequest, PendingRequestJournal};
use crate::note_state::NoteState;

/// Delays before resending the identical clearance body after a retriable
/// `stale_root` (the server has not yet observed the indexer's root) or
/// `capacity_exhausted` answer. A caller re-proves at a fresh root afterwards.
#[cfg(not(test))]
const CLEARANCE_RETRY_DELAYS_MS: [u64; 4] = [1_000, 2_000, 4_000, 8_000];
#[cfg(test)]
const CLEARANCE_RETRY_DELAYS_MS: [u64; 4] = [1, 2, 4, 8];

/// Lifetime of an escape (kind 0) or mutual-close (kind 1) proof: the vault
/// refuses it after `valid_until = now + 10,800`.
pub const EXIT_PROOF_VALIDITY_SECONDS: u64 = 10_800;
/// Lifetime of an ownership proof (kind 2). The server accepts one with
/// `now <= valid_until <= now + 3,600` by its own clock.
pub const OWNERSHIP_PROOF_VALIDITY_SECONDS: u64 = 3_600;
/// How far ahead of the server's clock this device's clock may run before an
/// ownership proof's `valid_until` exceeds the server's 3,600-second window.
pub const OWNERSHIP_CLOCK_SKEW_MARGIN_SECONDS: u64 = 300;

pub struct Wallet {
    config: ClientConfig,
    state: Option<NoteState>,
    state_path: PathBuf,
    journal_path: PathBuf,
    archive_dir: PathBuf,
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
        let archive_dir = state_dir.join("request_archive");
        let state = state_path
            .exists()
            .then(|| NoteState::load(&state_path))
            .transpose()?;
        Ok(Self {
            config,
            state,
            state_path,
            journal_path,
            archive_dir,
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
        let response = crate::testnet_auth::request(
            self.config.chain_id,
            &self.config.server_url,
            reqwest::Method::POST,
            format!(
                "{}/v2/requests",
                self.config.server_url.trim_end_matches('/')
            ),
        )?
        .json(&request)
        .send()
        .await
        .map_err(|error| ClientError::ServerError(error.to_string()))?;
        let response = crate::testnet_auth::check_response(response)?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| ClientError::ServerError(error.to_string()))?;
        if !status.is_success() {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&body) {
                if error.error_code == "stale_root" {
                    // Unsigned: kept in the archive, where a later receipt
                    // can still be installed from it.
                    self.archive_pending_request("discarded_stale_root")?;
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
        // The request circuit checks a signed state's anchor against its
        // predecessor's nullifier. Without the predecessor anchor no request
        // can be proved from this state (exits do not need it).
        let prev_anchor = if state.current_anchor == core::GENESIS_ANCHOR {
            None
        } else {
            Some(state.prev_anchor.ok_or(ClientError::PrevAnchorMissing)?)
        };
        let rerandomization = random_scalar();
        let anonymous = rerandomize(&expected_current, &rerandomization)
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let nullifier = state_nullifier(state);
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
                    prev_anchor,
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
        let cap = if self.config.policy_enabled {
            self.config.policy_charge_cap
        } else {
            self.config.request_charge_cap
        };
        let next = self.verified_successor(&journal, response, cap)?;
        self.persist_state(next)?;
        PendingRequestJournal::clear(&self.journal_path)?;
        Ok(())
    }

    /// Verify `response` for `journal`'s request at the current state and
    /// return the next note state, without persisting anything.
    fn verified_successor(
        &self,
        journal: &PendingRequestJournal,
        response: &RequestResponseV2,
        cap: u128,
    ) -> Result<NoteState, ClientError> {
        if let Some(prepared) = &journal.prepared_request {
            let request_payload = serde_json::from_str::<serde_json::Value>(&prepared.payload).ok();
            if let Some(quote) = request_payload
                .as_ref()
                .and_then(|payload| payload.get("billing_quote"))
            {
                let settled: serde_json::Value = serde_json::from_str(&response.response_payload)
                    .map_err(|_| {
                    ClientError::VerificationFailed("invalid native settlement payload".into())
                })?;
                if settled.get("billing_quote") != Some(quote) {
                    return Err(ClientError::VerificationFailed(
                        "native settlement changed the authorized quote".into(),
                    ));
                }
            }
        }
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let current = balance_commitment(
            state.current_balance,
            &parse_scalar(&state.balance_blinding)?,
            &state_note_leaf(state),
        );
        ensure_stored_commitment(state, &current)?;
        let anonymous = rerandomize(&current, &journal.user_rerandomization)
            .map_err(|error| ClientError::VerificationFailed(error.to_string()))?;
        self.successor_state(
            response,
            &journal.client_request_id,
            journal.nullifier,
            &anonymous,
            journal.user_rerandomization,
            cap,
        )
    }

    fn persist_state(&mut self, next: NoteState) -> Result<(), ClientError> {
        next.save(&self.state_path)?;
        self.state = Some(next);
        Ok(())
    }

    /// Set aside the pending request without installing a response. Its
    /// journal moves into the append-only request archive, where `recover`
    /// can still install a later finalized receipt for it.
    pub fn clear_pending_request(&self) -> Result<(), ClientError> {
        self.archive_pending_request("discarded")
    }

    /// Like `clear_pending_request`, recording why the journal was set aside.
    pub fn archive_pending_request(&self, disposition: &str) -> Result<(), ClientError> {
        PendingRequestJournal::archive(&self.journal_path, &self.archive_dir, disposition)
    }

    /// The archive of the current note state: requests transmitted from it
    /// share its nullifier. None of them has installed a response, since that
    /// would have advanced the state. A record that cannot be read is listed
    /// as unreadable, so callers can still tell that something was archived.
    pub fn archive_at_current_state(&self) -> Result<ArchiveListing, ClientError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(ArchiveListing::default());
        };
        read_archive(&self.archive_dir, &state_nullifier(state))
    }

    /// The readable archived requests of the current note state.
    pub fn archived_requests_at_current_state(&self) -> Result<Vec<ArchivedRequest>, ClientError> {
        Ok(self.archive_at_current_state()?.records)
    }

    /// Install a finalized response for the pending request, or else for a
    /// request archived at the current state.
    pub async fn recover(&mut self) -> Result<Option<RequestResponseV2>, ClientError> {
        if let Some(response) = self.recover_pending().await? {
            return Ok(Some(response));
        }
        self.recover_archived().await
    }

    /// Install a finalized response for the pending request only. Unlike
    /// `recover`, this sends nothing when no request is pending, so it suits
    /// background polling.
    pub async fn recover_pending(&mut self) -> Result<Option<RequestResponseV2>, ClientError> {
        self.archive_stale_pending_request()?;
        if let Some(journal) = PendingRequestJournal::read(&self.journal_path)? {
            let response = crate::testnet_auth::request(
                self.config.chain_id,
                &self.config.server_url,
                reqwest::Method::GET,
                format!(
                    "{}/v2/requests/{}",
                    self.config.server_url.trim_end_matches('/'),
                    journal.client_request_id
                ),
            )?
            .send()
            .await
            .map_err(|error| ClientError::ServerError(error.to_string()))?;
            let response = crate::testnet_auth::check_response(response)?;
            if response.status() != reqwest::StatusCode::NOT_FOUND {
                let recovery: RecoveryResponseV2 = response
                    .error_for_status()
                    .map_err(|error| ClientError::ServerError(error.to_string()))?
                    .json()
                    .await
                    .map_err(|error| ClientError::InvalidResponse(error.to_string()))?;
                if let Some(response) = recovery.request_response {
                    self.complete_pending_response(&response)?;
                    return Ok(Some(response));
                }
            }
        }
        Ok(None)
    }

    /// A pending journal whose nullifier is not the current state's was
    /// proved at an earlier state, which has since been settled: its own
    /// response was installed (a crash before the journal was cleared), or
    /// another request's was. It can never be installed or admitted at this
    /// state, so it moves into the archive as superseded.
    fn archive_stale_pending_request(&self) -> Result<(), ClientError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(());
        };
        let current = state_nullifier(state);
        if PendingRequestJournal::read(&self.journal_path)?
            .is_some_and(|pending| pending.nullifier != current)
        {
            self.archive_pending_request("superseded")?;
        }
        Ok(())
    }

    /// One read of the server's record for the current state's nullifier,
    /// made only when requests were archived at this state. A finalized
    /// response for one of them is installed when it verifies; the pending
    /// request at this state, if any, can then never be admitted and is
    /// archived as superseded. Failures and unverifiable claims change
    /// nothing.
    async fn recover_archived(&mut self) -> Result<Option<RequestResponseV2>, ClientError> {
        let archived = match self.archive_at_current_state() {
            Ok(listing) => {
                // A damaged record cannot be installed, but it must not stop
                // the readable ones from being installed.
                for path in &listing.unreadable {
                    tracing::warn!(path = %path.display(), "skipping an unreadable request archive record");
                }
                listing.records
            }
            Err(error) => {
                tracing::warn!(%error, "the request archive could not be read");
                return Ok(None);
            }
        };
        if archived.is_empty() {
            return Ok(None);
        }
        let nullifier = archived[0].journal.nullifier;
        let Ok(response) = crate::testnet_auth::request(
            self.config.chain_id,
            &self.config.server_url,
            reqwest::Method::GET,
            format!(
                "{}/v2/nullifiers/{}",
                self.config.server_url.trim_end_matches('/'),
                nullifier
            ),
        ) else {
            return Ok(None);
        };
        let Ok(response) = response.send().await else {
            return Ok(None);
        };
        let response = crate::testnet_auth::check_response(response)?;
        if !response.status().is_success() {
            return Ok(None);
        }
        let Ok(recovery) = response.json::<RecoveryResponseV2>().await else {
            return Ok(None);
        };
        let Some(response) = recovery.request_response else {
            return Ok(None);
        };
        let Some(record) = archived
            .iter()
            .rev()
            .find(|record| record.journal.client_request_id == response.client_request_id)
        else {
            return Ok(None);
        };
        // The request's own proved bound limits its charge, whatever cap
        // the wallet was opened with.
        let cap = record
            .journal
            .prepared_request
            .as_ref()
            .map(|request| request.public_inputs.solvency_bound)
            .unwrap_or(if self.config.policy_enabled {
                self.config.policy_charge_cap
            } else {
                self.config.request_charge_cap
            });
        let Ok(next) = self.verified_successor(&record.journal, &response, cap) else {
            return Ok(None);
        };
        // The pending retry at this state can never be admitted once the
        // archived request owns its nullifier. Archive it before the next
        // state is saved: a crash in between leaves both requests archived
        // at this state, where the next recovery installs the same receipt,
        // never a saved successor beside a journal of the old state.
        if PendingRequestJournal::read(&self.journal_path)?
            .is_some_and(|pending| pending.nullifier == nullifier)
        {
            self.archive_pending_request("superseded")?;
        }
        self.persist_state(next)?;
        Ok(Some(response))
    }

    /// Obtain the server's clearance and build the mutual-close (kind 1)
    /// proof. The clearance request carries an ownership proof (kind 2) for
    /// the same state and nullifier: it has no destination, concedes nothing,
    /// publishes no successor nullifier and is refused by every vault entry
    /// point. A witness that cannot prove membership fails before anything
    /// is sent.
    pub async fn withdrawal_mutual_close(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<(WithdrawalPublicInputsV2C, Groth16ProofWire), ClientError> {
        self.withdrawal_mutual_close_recorded(destination, active_root, merkle_siblings, || Ok(()))
            .await
    }

    /// Like `withdrawal_mutual_close`, but calls `before_send` once the
    /// ownership proof is built and before the clearance request carrying it
    /// is sent. An error from it sends nothing. Callers record there, durably,
    /// that the proof may have left: any answer, or none, can follow the
    /// request, and the proof publishes this state's nullifier to whoever
    /// sees it.
    pub async fn withdrawal_mutual_close_recorded(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
        before_send: impl FnOnce() -> Result<(), ClientError>,
    ) -> Result<(WithdrawalPublicInputsV2C, Groth16ProofWire), ClientError> {
        check_payout_destination(&destination)?;
        let ownership = self.ownership_proof(active_root, merkle_siblings.clone())?;
        before_send()?;
        self.mutual_close_with_clearance(destination, active_root, merkle_siblings, ownership)
            .await
    }

    /// The ownership proof (kind 2) a clearance request carries for the
    /// current state, valid for `OWNERSHIP_PROOF_VALIDITY_SECONDS` less a
    /// clock-skew margin.
    pub fn ownership_proof(
        &self,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<ClearanceOwnershipProofV2C, ClientError> {
        let valid_until = now_seconds()
            + OWNERSHIP_PROOF_VALIDITY_SECONDS.saturating_sub(OWNERSHIP_CLOCK_SKEW_MARGIN_SECONDS);
        let (public_inputs, proof) = self.build_withdrawal(
            WithdrawalKind::Ownership,
            [0; 20],
            0,
            valid_until,
            active_root,
            merkle_siblings,
            None,
        )?;
        Ok(ClearanceOwnershipProofV2C {
            public_inputs,
            proof,
        })
    }

    async fn mutual_close_with_clearance(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
        ownership: ClearanceOwnershipProofV2C,
    ) -> Result<(WithdrawalPublicInputsV2C, Groth16ProofWire), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let nullifier = state_nullifier(state);
        let clearance = self.request_clearance(&nullifier, ownership).await?;
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
            WithdrawalKind::MutualClose,
            destination,
            0,
            now_seconds() + EXIT_PROOF_VALIDITY_SECONDS,
            active_root,
            merkle_siblings,
            Some(clearance.signature),
        )
    }

    /// An escape (kind 0) from the current state that pays
    /// `current_balance - conceded` to `destination` and publishes the
    /// successor nullifier. The vault accepts it until
    /// `now + EXIT_PROOF_VALIDITY_SECONDS`.
    pub fn withdrawal_escape_hatch(
        &self,
        destination: [u8; 20],
        conceded: u128,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<(WithdrawalPublicInputsV2C, Groth16ProofWire), ClientError> {
        check_payout_destination(&destination)?;
        self.build_withdrawal(
            WithdrawalKind::Escape,
            destination,
            conceded,
            now_seconds() + EXIT_PROOF_VALIDITY_SECONDS,
            active_root,
            merkle_siblings,
            None,
        )
    }

    pub fn archive_note(&mut self) -> Result<(), ClientError> {
        if let Some(state) = &self.state {
            state.archive(&self.state_path)?;
        }
        self.state = None;
        self.archive_pending_request("note_archived")?;
        Ok(())
    }

    /// The nullifier of the current state, `N(s, note_id, τ)`.
    pub fn current_nullifier(&self) -> Option<Felt252> {
        self.state.as_ref().map(state_nullifier)
    }

    /// The nullifier an escape from the current state publishes as
    /// `next_nullifier`: that of the state's only valid successor.
    pub fn current_successor_nullifier(&self) -> Option<Felt252> {
        self.state.as_ref().map(|state| {
            core::successor_nullifier(&state.secret_s, state.note_id, &state.current_anchor)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_withdrawal(
        &self,
        kind: WithdrawalKind,
        destination: [u8; 20],
        conceded: u128,
        valid_until: u64,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
        clearance_signature: Option<zkapi_types::SchnorrSignature>,
    ) -> Result<(WithdrawalPublicInputsV2C, Groth16ProofWire), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let params = WithdrawalStatementParams {
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            state_signing_key: self.config.state_signing_key.clone(),
            clearance_signing_key: self.config.clearance_signing_key.clone(),
            note_id: state.note_id,
            destination,
        };
        let witness = WithdrawalWitnessData {
            secret: state.secret_s,
            deposit_amount: state.deposit_amount,
            expiry: state.expiry_ts,
            merkle_siblings: siblings_array(merkle_siblings)?,
            state_balance: state.current_balance,
            state_blinding: parse_scalar(&state.balance_blinding)?,
            current_anchor: state.current_anchor,
            kind,
            conceded,
            valid_until,
            state_signature: state.state_signature,
            clearance_signature,
        };
        let public = withdrawal_public_inputs(&params, &witness)
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let prover = WithdrawalProver::load(self.setup_dir())
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let proof = prover
            .prove(&public, witness)
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        Ok((public, proof))
    }

    async fn request_clearance(
        &self,
        nullifier: &Felt252,
        ownership: ClearanceOwnershipProofV2C,
    ) -> Result<ClearanceResponseV2, ClientError> {
        let request = ClearanceRequestV2C {
            withdrawal_nullifier: *nullifier,
            ownership_proof: ownership,
        };
        let url = format!(
            "{}/v2/withdraw/clearance",
            self.config.server_url.trim_end_matches('/')
        );
        let mut delays = CLEARANCE_RETRY_DELAYS_MS.iter();
        loop {
            let response = crate::testnet_auth::request(
                self.config.chain_id,
                &self.config.server_url,
                reqwest::Method::POST,
                url.clone(),
            )?
            .json(&request)
            .send()
            .await
            .map_err(|error| ClientError::ServerError(error.to_string()))?;
            let response = crate::testnet_auth::check_response(response)?;
            let status = response.status();
            let body = response
                .text()
                .await
                .map_err(|error| ClientError::ServerError(error.to_string()))?;
            if status.is_success() {
                return serde_json::from_str(&body)
                    .map_err(|error| ClientError::InvalidResponse(error.to_string()));
            }
            let code = serde_json::from_str::<ErrorResponse>(&body)
                .map(|error| error.error_code)
                .unwrap_or_default();
            let stale_root = status == reqwest::StatusCode::CONFLICT && code == "stale_root";
            let saturated =
                status == reqwest::StatusCode::SERVICE_UNAVAILABLE && code == "capacity_exhausted";
            if stale_root || saturated {
                if let Some(delay) = delays.next() {
                    tokio::time::sleep(std::time::Duration::from_millis(*delay)).await;
                    continue;
                }
                if stale_root {
                    return Err(ClientError::StaleRoot);
                }
            }
            if (status == reqwest::StatusCode::BAD_REQUEST
                && code == "clearance_ownership_required")
                || (status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                    && code == "legacy_clearance_capacity")
                || (status == reqwest::StatusCode::CONFLICT && code == "nullifier_used")
            {
                return Err(ClientError::ClearanceRefused(code));
            }
            return Err(ClientError::ServerError(format!("HTTP {status}: {body}")));
        }
    }

    fn successor_state(
        &self,
        response: &RequestResponseV2,
        request_id: &str,
        nullifier: Felt252,
        anonymous: &CurvePointWire,
        rerandomization: Felt252,
        cap: u128,
    ) -> Result<NoteState, ClientError> {
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
        if response.charge_applied > cap {
            return Err(ClientError::VerificationFailed(
                "the charge exceeds the request's bound".to_string(),
            ));
        }
        // The only successor the request circuit can spend, and the only one
        // whose nullifier an escape from this state publishes, sits at
        // `next_anchor(N)`. Any other anchor (0, 1, reused, random) is
        // treated like a withheld successor.
        if response.next_anchor != core::next_anchor(&nullifier) {
            return Err(ClientError::VerificationFailed(
                "the successor anchor is not derived from the request nullifier".to_string(),
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
        next.prev_anchor = Some(state.current_anchor);
        next.current_anchor = response.next_anchor;
        next.is_genesis = false;
        next.state_signature = Some(response.next_state_signature);
        Ok(next)
    }

    fn setup_dir(&self) -> &str {
        match &self.config.proof_mode {
            ClientProofMode::Groth16 { setup_dir } => setup_dir,
        }
    }
}

/// Refuse a payout to the zero address for escapes and mutual closes. Only
/// an ownership proof has no destination.
fn check_payout_destination(destination: &[u8; 20]) -> Result<(), ClientError> {
    if *destination == [0; 20] {
        return Err(ClientError::ProofGeneration(
            "withdrawal destination cannot be the zero address".to_string(),
        ));
    }
    Ok(())
}

fn state_nullifier(state: &NoteState) -> Felt252 {
    core::nullifier(&state.secret_s, state.note_id, &state.current_anchor)
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
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zkapi_proof::compact::{CompactSigner, RequestVerifier, WithdrawalVerifier};

    use super::*;

    /// The committed development setup (loaded with the `dev-setup` feature).
    const SETUP_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../setup/v2-concession-dev"
    );
    const DESTINATION: [u8; 20] = [0x11; 20];
    const NOTE_ID: u32 = 5;

    type Replies = Arc<Mutex<VecDeque<(u16, String)>>>;
    type Calls = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// Minimal HTTP/1.1 server: records each request path and body and answers
    /// with the next scripted (status, body) reply.
    struct MockServer {
        url: String,
        replies: Replies,
        calls: Calls,
    }

    impl MockServer {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let replies = Replies::default();
            let calls = Calls::default();
            let (queued, recorded) = (replies.clone(), calls.clone());
            tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 8192];
                    let header_end = loop {
                        let read = socket.read(&mut buffer).await.unwrap();
                        assert!(read > 0, "truncated request");
                        request.extend_from_slice(&buffer[..read]);
                        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            break end + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&request[..header_end]).to_string();
                    let length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    while request.len() < header_end + length {
                        let read = socket.read(&mut buffer).await.unwrap();
                        assert!(read > 0, "truncated body");
                        request.extend_from_slice(&buffer[..read]);
                    }
                    let path = head.split_whitespace().nth(1).unwrap_or_default();
                    recorded
                        .lock()
                        .unwrap()
                        .push((path.to_string(), request[header_end..].to_vec()));
                    let (status, body) = queued
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or((500, "{}".to_string()));
                    let response = format!(
                        "HTTP/1.1 {status} Mock\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                    let _ = socket.shutdown().await;
                }
            });
            Self {
                url,
                replies,
                calls,
            }
        }

        fn reply(&self, status: u16, body: String) {
            self.replies.lock().unwrap().push_back((status, body));
        }

        fn calls(&self) -> Vec<(String, Vec<u8>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    struct Fixture {
        wallet: Wallet,
        state_signer: CompactSigner,
        clearance_signer: CompactSigner,
        root: Felt252,
        siblings: Vec<Felt252>,
        state_dir: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.state_dir);
        }
    }

    fn config(server_url: &str, state_dir: &std::path::Path) -> ClientConfig {
        ClientConfig {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Felt252::from_u64(0x1234),
            request_charge_cap: 1_000,
            policy_charge_cap: 1_000,
            policy_enabled: false,
            server_url: server_url.to_string(),
            state_dir: state_dir.to_string_lossy().into_owned(),
            proof_mode: ClientProofMode::Groth16 {
                setup_dir: SETUP_DIR.to_string(),
            },
            state_signing_key: CompactSigner::from_seed(&Felt252::from_u64(11)).public_key(),
            clearance_signing_key: CompactSigner::from_seed(&Felt252::from_u64(12)).public_key(),
        }
    }

    /// A genesis note alone in an otherwise empty tree.
    fn fixture(server_url: &str) -> Fixture {
        let state_dir =
            std::env::temp_dir().join(format!("zkapi-client-wallet-{}", uuid::Uuid::new_v4()));
        let mut wallet = Wallet::new(config(server_url, &state_dir)).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), NOTE_ID, 2_000_000, 4_000_000_000)
            .unwrap();
        let siblings = core::zero_hashes()[..MERKLE_DEPTH].to_vec();
        let state = wallet.state().unwrap();
        let root = core::merkle_root(
            state.note_id,
            &state_note_leaf(state),
            &siblings_array(siblings.clone()).unwrap(),
        );
        Fixture {
            wallet,
            state_signer: CompactSigner::from_seed(&Felt252::from_u64(11)),
            clearance_signer: CompactSigner::from_seed(&Felt252::from_u64(12)),
            root,
            siblings,
            state_dir,
        }
    }

    fn nullifier(fixture: &Fixture) -> Felt252 {
        let state = fixture.wallet.state().unwrap();
        core::nullifier(&state.secret_s, state.note_id, &state.current_anchor)
    }

    fn clearance(fixture: &Fixture) -> String {
        let state = fixture.wallet.state().unwrap();
        let nullifier = nullifier(fixture);
        let message = core::clearance_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &nullifier,
        );
        serde_json::to_string(&ClearanceResponseV2 {
            status: "ok".to_string(),
            withdrawal_nullifier: nullifier,
            signature: fixture.clearance_signer.sign(&message),
        })
        .unwrap()
    }

    fn error(code: &str, retriable: bool) -> String {
        serde_json::json!({"status": "error", "client_request_id": "", "error_code": code,
            "error_message": "mock", "retriable": retriable, "latest_root": "0x7"})
        .to_string()
    }

    /// The server's finalized response to the pending request, signed by the
    /// state key at `anchor` (the derived anchor unless a test overrides it).
    fn signed_response(
        fixture: &Fixture,
        request: &ApiRequestV2,
        charge: u128,
        anchor: Option<Felt252>,
    ) -> RequestResponseV2 {
        let state = fixture.wallet.state().unwrap();
        let anonymous = CurvePointWire {
            x: request.public_inputs.anonymous_commitment_x,
            y: request.public_inputs.anonymous_commitment_y,
        };
        let delta = random_scalar();
        let next = server_update(&anonymous, charge, &delta).unwrap();
        let next_anchor =
            anchor.unwrap_or_else(|| core::next_anchor(&request.public_inputs.request_nullifier));
        let message = core::state_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &next.x,
            &next.y,
            &next_anchor,
        );
        let payload = "{\"ok\":true}".to_string();
        RequestResponseV2 {
            status: "ok".into(),
            client_request_id: request.client_request_id.clone(),
            request_nullifier: request.public_inputs.request_nullifier,
            response_code: 200,
            response_hash: canonical_response_hash(payload.as_bytes()),
            response_payload: payload,
            charge_applied: charge,
            next_commitment: next,
            next_anchor,
            blind_delta_srv: delta,
            next_state_signature: fixture.state_signer.sign(&message),
            policy_reason_code: None,
            policy_evidence_hash: None,
        }
    }

    fn prepare(fixture: &mut Fixture) -> ApiRequestV2 {
        let payload = "{\"model\":\"m\"}";
        fixture
            .wallet
            .prepare_request(
                payload,
                canonical_payload_hash(payload.as_bytes()),
                fixture.root,
                fixture.siblings.clone(),
            )
            .unwrap()
    }

    #[tokio::test]
    async fn mutual_close_sends_a_verifiable_ownership_proof_without_a_destination() {
        let server = MockServer::start().await;
        let fixture = fixture(&server.url);
        server.reply(409, error("stale_root", true));
        server.reply(503, error("capacity_exhausted", true));
        server.reply(200, clearance(&fixture));

        let before = now_seconds();
        let (public, proof) = fixture
            .wallet
            .withdrawal_mutual_close(DESTINATION, fixture.root, fixture.siblings.clone())
            .await
            .unwrap();

        // Retriable answers resend the byte-identical body without re-proving.
        let calls = server.calls();
        assert_eq!(calls.len(), 3);
        assert!(calls
            .iter()
            .all(|(path, _)| path == "/v2/withdraw/clearance"));
        assert!(calls.iter().all(|(_, body)| *body == calls[0].1));
        let body: serde_json::Value = serde_json::from_slice(&calls[0].1).unwrap();
        assert_eq!(body.as_object().unwrap().len(), 2);
        for request_field in ["request_nullifier", "authorization_tag", "solvency_bound"] {
            assert!(body["ownership_proof"]["public_inputs"]
                .get(request_field)
                .is_none());
        }
        let request: ClearanceRequestV2C = serde_json::from_slice(&calls[0].1).unwrap();
        let ownership = request.ownership_proof;
        assert_eq!(request.withdrawal_nullifier, nullifier(&fixture));

        // The ownership proof (kind 2): same state, nullifier, root, keys and
        // balance, but no destination, no successor nullifier, no concession
        // and a valid_until inside the server's one-hour window.
        let owned = &ownership.public_inputs;
        assert_eq!(owned.withdrawal_kind(), Some(WithdrawalKind::Ownership));
        assert_eq!(owned.destination, [0; 20]);
        assert_eq!(owned.next_nullifier, Felt252::ZERO);
        assert_eq!(owned.conceded, 0);
        assert_eq!(owned.withdrawal_nullifier, request.withdrawal_nullifier);
        assert_eq!(owned.final_balance, 2_000_000);
        assert_eq!(owned.active_root, fixture.root);
        assert!(owned.valid_until > before);
        assert!(owned.valid_until <= now_seconds() + OWNERSHIP_PROOF_VALIDITY_SECONDS);

        // The close (kind 1) pays the real destination the whole balance.
        assert_eq!(public.withdrawal_kind(), Some(WithdrawalKind::MutualClose));
        assert_eq!(public.destination, DESTINATION);
        assert_eq!(public.withdrawal_nullifier, request.withdrawal_nullifier);
        assert_eq!(public.final_balance, 2_000_000);
        assert_eq!(public.next_nullifier, Felt252::ZERO);
        assert_eq!(public.conceded, 0);
        assert!(public.valid_until >= before + EXIT_PROOF_VALIDITY_SECONDS);
        assert!(public.valid_until <= now_seconds() + EXIT_PROOF_VALIDITY_SECONDS);
        assert_eq!(
            ownership.proof.backend,
            zkapi_types::wire::ProofBackendWire::Groth16Bn254
        );
        assert_ne!(ownership.proof, proof);

        // Both proofs verify under the deployment's withdrawal verifying key.
        let verifier = WithdrawalVerifier::load(SETUP_DIR).unwrap();
        assert!(verifier.verify(owned, &ownership.proof).unwrap());
        assert!(verifier.verify(&public, &proof).unwrap());
    }

    #[tokio::test]
    async fn persistent_stale_root_is_bounded_then_reported_for_reproving() {
        let server = MockServer::start().await;
        let fixture = fixture(&server.url);
        for _ in 0..=CLEARANCE_RETRY_DELAYS_MS.len() {
            server.reply(409, error("stale_root", true));
        }
        let result = fixture
            .wallet
            .withdrawal_mutual_close(DESTINATION, fixture.root, fixture.siblings.clone())
            .await;
        assert!(matches!(result, Err(ClientError::StaleRoot)), "{result:?}");
        let calls = server.calls();
        assert_eq!(calls.len(), CLEARANCE_RETRY_DELAYS_MS.len() + 1);
        assert!(calls.iter().all(|(_, body)| *body == calls[0].1));
    }

    #[tokio::test]
    async fn rejected_clearance_is_not_retried() {
        for (status, code) in [(400, "invalid_proof"), (409, "nullifier_used")] {
            let server = MockServer::start().await;
            let fixture = fixture(&server.url);
            server.reply(status, error(code, false));
            let result = fixture
                .wallet
                .withdrawal_mutual_close(DESTINATION, fixture.root, fixture.siblings.clone())
                .await;
            // nullifier_used reserves nothing for this clearance, so the caller
            // may release its reservation (see ClientError::ClearanceRefused).
            let refused =
                matches!(&result, Err(ClientError::ClearanceRefused(refused)) if refused == code);
            let failed =
                matches!(&result, Err(ClientError::ServerError(message)) if message.contains(code));
            assert!(
                if code == "nullifier_used" {
                    refused
                } else {
                    failed
                },
                "{result:?}"
            );
            assert_eq!(server.calls().len(), 1, "{code}");
        }
    }

    #[tokio::test]
    async fn invalid_ownership_witness_or_destination_sends_no_clearance_request() {
        let server = MockServer::start().await;
        let fixture = fixture(&server.url);
        let mut wrong_path = fixture.siblings.clone();
        wrong_path[3] = Felt252::from_u64(9);
        for (destination, root, siblings) in [
            (DESTINATION, Felt252::from_u64(7), fixture.siblings.clone()),
            (DESTINATION, fixture.root, wrong_path),
            (DESTINATION, fixture.root, fixture.siblings[1..].to_vec()),
            ([0; 20], fixture.root, fixture.siblings.clone()),
        ] {
            let result = fixture
                .wallet
                .withdrawal_mutual_close(destination, root, siblings)
                .await;
            assert!(
                matches!(result, Err(ClientError::ProofGeneration(_))),
                "{result:?}"
            );
        }
        assert!(server.calls().is_empty());
        assert!(fixture
            .wallet
            .withdrawal_escape_hatch([0; 20], 0, fixture.root, fixture.siblings.clone())
            .is_err());
    }

    /// The caller's record that an ownership proof may have left is made
    /// after the proof is built and before the request carrying it is sent,
    /// so it covers every answer, including none: a gateway's 429 here. A
    /// proof that cannot be built records nothing, and a failed record sends
    /// nothing.
    #[tokio::test]
    async fn the_ownership_proof_is_recorded_before_its_clearance_request_leaves() {
        let server = MockServer::start().await;
        let fixture = fixture(&server.url);
        server.reply(
            429,
            serde_json::json!({"error": {"code": "gateway_rate_limited"}}).to_string(),
        );
        let mut recorded = Vec::new();
        let result = fixture
            .wallet
            .withdrawal_mutual_close_recorded(
                DESTINATION,
                fixture.root,
                fixture.siblings.clone(),
                || {
                    recorded.push(server.calls().len());
                    Ok(())
                },
            )
            .await;
        assert!(
            matches!(result, Err(ClientError::ServerError(_))),
            "{result:?}"
        );
        assert_eq!(recorded, [0], "recorded once, before any request");
        assert_eq!(server.calls().len(), 1);

        let mut wrong_path = fixture.siblings.clone();
        wrong_path[3] = Felt252::from_u64(9);
        let result = fixture
            .wallet
            .withdrawal_mutual_close_recorded(DESTINATION, fixture.root, wrong_path, || {
                panic!("recorded a proof that was never built")
            })
            .await;
        assert!(
            matches!(result, Err(ClientError::ProofGeneration(_))),
            "{result:?}"
        );

        let result = fixture
            .wallet
            .withdrawal_mutual_close_recorded(
                DESTINATION,
                fixture.root,
                fixture.siblings.clone(),
                || Err(ClientError::Serialization("storage unavailable".into())),
            )
            .await;
        assert!(
            matches!(result, Err(ClientError::Serialization(_))),
            "{result:?}"
        );
        assert_eq!(server.calls().len(), 1, "a failed record sends nothing");
    }

    /// An escape (kind 0) publishes the state's nullifier and that of its
    /// derived successor, and pays the balance less the concession.
    #[test]
    fn escape_publishes_the_successor_nullifier_and_pays_balance_less_concession() {
        let fixture = fixture("http://127.0.0.1:1");
        let before = now_seconds();
        let (public, proof) = fixture
            .wallet
            .withdrawal_escape_hatch(DESTINATION, 1_234, fixture.root, fixture.siblings.clone())
            .unwrap();
        let state = fixture.wallet.state().unwrap();
        assert_eq!(public.withdrawal_kind(), Some(WithdrawalKind::Escape));
        assert_eq!(public.withdrawal_nullifier, nullifier(&fixture));
        assert_eq!(
            Some(public.withdrawal_nullifier),
            fixture.wallet.current_nullifier()
        );
        let successor = core::nullifier(
            &state.secret_s,
            state.note_id,
            &core::next_anchor(&public.withdrawal_nullifier),
        );
        assert_eq!(public.next_nullifier, successor);
        assert_eq!(
            Some(public.next_nullifier),
            fixture.wallet.current_successor_nullifier()
        );
        assert_eq!(public.conceded, 1_234);
        assert_eq!(public.final_balance, 2_000_000 - 1_234);
        assert_eq!(public.destination, DESTINATION);
        assert!(public.valid_until >= before + EXIT_PROOF_VALIDITY_SECONDS);
        let verifier = WithdrawalVerifier::load(SETUP_DIR).unwrap();
        assert!(verifier.verify(&public, &proof).unwrap());
        // More than the balance cannot be conceded.
        assert!(matches!(
            fixture.wallet.withdrawal_escape_hatch(
                DESTINATION,
                2_000_001,
                fixture.root,
                fixture.siblings.clone()
            ),
            Err(ClientError::ProofGeneration(_))
        ));
    }

    /// A request from the installed successor proves the anchor chain with
    /// the predecessor's anchor, and its nullifier is exactly the
    /// `next_nullifier` an escape from the predecessor publishes.
    #[test]
    fn the_successor_records_its_predecessor_anchor_and_proves_the_next_request() {
        let mut fixture = fixture("http://127.0.0.1:1");
        let genesis = fixture.wallet.state().unwrap().clone();
        let (escape, _) = fixture
            .wallet
            .withdrawal_escape_hatch(DESTINATION, 0, fixture.root, fixture.siblings.clone())
            .unwrap();
        let request = prepare(&mut fixture);
        let verifier = RequestVerifier::load(SETUP_DIR).unwrap();
        assert!(verifier
            .verify(&request.public_inputs, &request.proof)
            .unwrap());
        let response = signed_response(&fixture, &request, 400, None);
        fixture.wallet.complete_pending_response(&response).unwrap();

        let next = fixture.wallet.state().unwrap().clone();
        assert_eq!(next.prev_anchor, Some(genesis.current_anchor));
        assert_eq!(
            next.current_anchor,
            core::next_anchor(&request.public_inputs.request_nullifier)
        );
        assert!(!next.is_genesis);
        assert_eq!(next.current_balance, 2_000_000 - 400);
        // Persisted with the predecessor anchor.
        let reloaded = NoteState::load(&fixture.state_dir.join("note_state.json")).unwrap();
        assert_eq!(reloaded.prev_anchor, Some(genesis.current_anchor));

        let second = prepare(&mut fixture);
        assert!(verifier
            .verify(&second.public_inputs, &second.proof)
            .unwrap());
        assert_eq!(
            second.public_inputs.request_nullifier,
            escape.next_nullifier
        );
    }

    /// S4: a correctly signed successor at any anchor but `next_anchor(N)` is
    /// refused and nothing is installed.
    #[test]
    fn a_successor_at_a_non_derived_anchor_is_refused() {
        let mut fixture = fixture("http://127.0.0.1:1");
        let request = prepare(&mut fixture);
        let genesis = fixture.wallet.state().unwrap().clone();
        let nullifier = request.public_inputs.request_nullifier;
        for anchor in [
            Felt252::ZERO,
            Felt252::ONE,
            genesis.current_anchor,
            Felt252::from_u64(0xdead_beef),
            // The derived anchor of another note's nullifier at this anchor.
            core::next_anchor(&core::nullifier(
                &genesis.secret_s,
                genesis.note_id + 1,
                &genesis.current_anchor,
            )),
            // The old (pre-concession) style: any server-chosen anchor.
            nullifier,
        ] {
            let response = signed_response(&fixture, &request, 400, Some(anchor));
            let result = fixture.wallet.complete_pending_response(&response);
            assert!(
                matches!(&result, Err(ClientError::VerificationFailed(message))
                    if message.contains("not derived")),
                "{anchor:?}: {result:?}"
            );
            assert_eq!(
                fixture.wallet.state().unwrap().current_anchor,
                genesis.current_anchor
            );
            assert!(fixture.wallet.has_pending_request());
        }
        let response = signed_response(&fixture, &request, 400, None);
        fixture.wallet.complete_pending_response(&response).unwrap();
        assert!(!fixture.wallet.has_pending_request());
    }

    /// A signed state saved before `prev_anchor` existed proves no request,
    /// but still exits.
    #[test]
    fn a_signed_state_without_its_predecessor_anchor_refuses_requests_but_exits() {
        let mut fixture = fixture("http://127.0.0.1:1");
        let request = prepare(&mut fixture);
        let response = signed_response(&fixture, &request, 400, None);
        fixture.wallet.complete_pending_response(&response).unwrap();
        let path = fixture.state_dir.join("note_state.json");
        let mut legacy = NoteState::load(&path).unwrap();
        legacy.prev_anchor = None;
        legacy.save(&path).unwrap();
        let mut wallet = Wallet::new(config("http://127.0.0.1:1", &fixture.state_dir)).unwrap();
        let payload = "{}";
        let refused = wallet.prepare_request(
            payload,
            canonical_payload_hash(payload.as_bytes()),
            fixture.root,
            fixture.siblings.clone(),
        );
        assert!(
            matches!(refused, Err(ClientError::PrevAnchorMissing)),
            "{refused:?}"
        );
        assert!(!wallet.has_pending_request());
        let (escape, proof) = wallet
            .withdrawal_escape_hatch(DESTINATION, 0, fixture.root, fixture.siblings.clone())
            .unwrap();
        assert_eq!(escape.final_balance, 2_000_000 - 400);
        assert!(WithdrawalVerifier::load(SETUP_DIR)
            .unwrap()
            .verify(&escape, &proof)
            .unwrap());
    }

    /// The nullifier is bound to the note: the same secret at the same
    /// anchor in another note has another nullifier.
    #[test]
    fn requests_from_notes_sharing_a_secret_have_distinct_nullifiers() {
        let mut first = fixture("http://127.0.0.1:1");
        let state_dir =
            std::env::temp_dir().join(format!("zkapi-client-wallet-{}", uuid::Uuid::new_v4()));
        let mut other = Wallet::new(config("http://127.0.0.1:1", &state_dir)).unwrap();
        other
            .confirm_deposit(Felt252::from_u64(42), NOTE_ID + 1, 2_000_000, 4_000_000_000)
            .unwrap();
        let request = prepare(&mut first);
        assert_ne!(
            Some(request.public_inputs.request_nullifier),
            other.current_nullifier()
        );
        let _ = std::fs::remove_dir_all(state_dir);
    }
}
