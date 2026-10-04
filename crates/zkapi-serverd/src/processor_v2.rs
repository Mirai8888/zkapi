//! zkAPI v2 request processor.
//!
//! Lease settlement always terminates. A lease whose runtime key was never
//! returned to the client finalizes at zero. A lease that may have been
//! delivered finalizes at its measured usage, clamped to the proof-bound
//! budget before conversion; transient failures retry until the lease's
//! write-once settlement deadline, after which it finalizes without provider
//! I/O at the solvency bound (or at captured usage when only key deletion
//! failed), with an operator-visible review. Settlement never re-validates the
//! frozen quote against live configuration. A corrupt binding is cancelled
//! and never signed.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use sha3::{Digest, Keccak256};
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    random_field, random_scalar, server_update, RequestVerifier, WithdrawalVerifier,
};
use zkapi_types::wire::{
    ApiRequestV2, ClearanceOwnershipProof, ClearanceRequest, ClearanceResponseV2, CurvePointWire,
    OpenRouterLeaseAuthorization, OpenRouterLeaseResponse, OpenRouterLeaseStatusResponse,
    RecoveryResponseV2, RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash, Felt252,
    NullifierStatus,
};

use crate::config::{
    OpenRouterLeaseConfig, OpenRouterLeaseSourceConfig, ServerConfig,
    MIN_SETTLEMENT_RETRY_WINDOW_SECONDS,
};
use crate::dashboard::{
    redact_secrets, DashboardEvent, DashboardHub, PendingLeaseView, SettlementCounts,
    SettlementOverview, SettlementReviewView,
};
use crate::error::ServerError;
use crate::native_billing::{NativeBillingOracle, NativeBillingQuote};
use crate::nullifier_store::{
    api_request_binding, KeyCleanup, LeaseFinalization, NewOpenRouterLease, NullifierStore,
    OaProvisioningOutcome, OpenRouterLeaseRecord, SettlementReview, TranscriptRecord,
};
use crate::oa_org::{IssuedOpenRouterLease, OaOrgProvisioner, OaOrgUsage, OaOrgUsageExpectation};
use crate::openrouter::OpenRouterProvisioner;
use crate::pricing;
use crate::settlement::{SettlementResult, UsageInfo};
use crate::signer::ServerSigner;

const MAX_REQUEST_AGE_SECONDS: u64 = 300;
const MAX_FUTURE_SKEW_SECONDS: u64 = 30;
// OA's signed validity is an upstream upper bound, not a guarantee that the
// child key remains usable until the final second. Stop advertising it as the
// usable lease end and leave room for clock skew and in-flight requests.
const OA_LEASE_EXPIRY_SAFETY_SECONDS: u64 = 30;
/// Concurrent clearance ownership-proof verifications.
const CLEARANCE_VERIFY_PERMITS: usize = 4;
const CLEARANCE_PERMIT_TIMEOUT: Duration = Duration::from_secs(2);
const RECENT_ROOTS_CAPACITY: usize = 1024;
const REJECTED_CLEARANCE_CAPACITY: usize = 4096;
const KEY_CLEANUP_BATCH: usize = 50;
const KEY_CLEANUP_MAX_BACKOFF_SECONDS: u64 = 3_600;

/// Latency bounds of the settler. Every settlement step persists its phase
/// before its external side effect, so cancelling an attempt is safe.
#[derive(Debug, Clone, Copy)]
struct SettlementTiming {
    /// Stop starting provider-I/O attempts after this much of a tick.
    tick_budget: Duration,
    /// One provider-I/O settlement attempt.
    attempt_timeout: Duration,
    /// Client retirement waits this long for the settlement lock...
    retire_lock_timeout: Duration,
    /// ...and this long for its settlement attempt.
    retire_timeout: Duration,
    /// Background provider-key cleanup per tick and per key.
    cleanup_budget: Duration,
    cleanup_attempt_timeout: Duration,
    /// Single-flight cache of the vault's currentRoot() for clearance.
    vault_root_ttl: Duration,
}

impl Default for SettlementTiming {
    fn default() -> Self {
        // tick budget + attempt timeout + cleanup stays well inside
        // config::SETTLEMENT_SWEEP_SLACK_SECONDS (600).
        Self {
            tick_budget: Duration::from_secs(120),
            attempt_timeout: Duration::from_secs(150),
            retire_lock_timeout: Duration::from_secs(10),
            retire_timeout: Duration::from_secs(45),
            cleanup_budget: Duration::from_secs(30),
            cleanup_attempt_timeout: Duration::from_secs(30),
            vault_root_ttl: Duration::from_secs(3),
        }
    }
}

/// Roots the server observed (indexer polls and vault reads), each with the
/// time it was last seen.
#[derive(Default)]
struct RecentRoots {
    entries: VecDeque<(Felt252, u64)>,
}

impl RecentRoots {
    fn observe(&mut self, root: Felt252, now: u64, window: u64) {
        match self.entries.iter_mut().find(|(seen, _)| *seen == root) {
            Some(entry) => entry.1 = entry.1.max(now),
            None => {
                self.entries.push_back((root, now));
                if self.entries.len() > RECENT_ROOTS_CAPACITY {
                    self.entries.pop_front();
                }
            }
        }
        self.entries
            .retain(|(_, seen)| seen.saturating_add(window) >= now);
    }

    fn contains(&self, root: &Felt252, now: u64, window: u64) -> bool {
        self.entries
            .iter()
            .any(|(seen, at)| seen == root && at.saturating_add(window) >= now)
    }
}

/// The transitional budget of new proof-less clearance reservations: one
/// window per UNIX minute, shared by every caller, so anyone can spend it. A
/// request with an ownership proof never consults it.
#[derive(Default)]
struct LegacyClearanceWindow {
    minute: u64,
    admitted: u32,
    /// This window's exhaustion was logged.
    warned: bool,
    /// Proof-less requests refused since the process started.
    rejected_total: u64,
}

/// A proof-less clearance refused until the next window.
struct LegacyClearanceRefusal {
    retry_after_seconds: u64,
    /// The window's first refusal: the only one that is logged.
    first_in_window: bool,
    rejected_total: u64,
}

impl LegacyClearanceWindow {
    fn admit(&mut self, now: u64, limit: u32) -> Result<(), LegacyClearanceRefusal> {
        let minute = now / 60;
        if self.minute != minute {
            *self = Self {
                minute,
                rejected_total: self.rejected_total,
                ..Self::default()
            };
        }
        if self.admitted < limit {
            self.admitted += 1;
            return Ok(());
        }
        self.rejected_total = self.rejected_total.saturating_add(1);
        Err(LegacyClearanceRefusal {
            retry_after_seconds: 60 - now % 60,
            first_in_window: !std::mem::replace(&mut self.warned, true),
            rejected_total: self.rejected_total,
        })
    }

    fn usage(&self, now: u64, limit: u32) -> LegacyClearanceUsage {
        LegacyClearanceUsage {
            window_used: if self.minute == now / 60 {
                self.admitted
            } else {
                0
            },
            window_limit: limit,
            rejected_total: self.rejected_total,
        }
    }
}

/// The legacy clearance budget as `/health` reports it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegacyClearanceUsage {
    /// New proof-less reservations admitted in the current minute.
    pub window_used: u32,
    /// The per-minute budget; 0 while legacy clearance is off.
    pub window_limit: u32,
    /// Proof-less requests refused by the budget since the process started.
    pub rejected_total: u64,
}

/// (root, nullifier) pairs whose verified ownership proof used a root the
/// vault did not have, with the vault root read and an expiry. While the
/// (cached, single-flight) vault root is unchanged, replays are answered from
/// here without a pairing check.
#[derive(Default)]
struct RejectedClearances {
    entries: VecDeque<(Felt252, Felt252, Felt252, u64)>,
}

impl RejectedClearances {
    fn lookup(&self, root: &Felt252, nullifier: &Felt252, now: u64) -> Option<Felt252> {
        self.entries
            .iter()
            .find(|(r, n, _, expires)| r == root && n == nullifier && *expires > now)
            .map(|(_, _, vault_root, _)| *vault_root)
    }

    fn insert(&mut self, root: Felt252, nullifier: Felt252, vault_root: Felt252, expires: u64) {
        self.entries
            .retain(|(r, n, _, _)| !(*r == root && *n == nullifier));
        self.entries
            .push_back((root, nullifier, vault_root, expires));
        if self.entries.len() > REJECTED_CLEARANCE_CAPACITY {
            self.entries.pop_front();
        }
    }
}

/// Why a possibly delivered lease is finalized without measured usage.
#[derive(Debug, Clone)]
enum FallbackCause {
    Deadline,
    Unsettleable(String),
}

/// The integrity of a lease row against its nullifier reservation.
enum LeaseBinding {
    Valid(Box<TranscriptRecord>),
    /// Never signed: the lease is cancelled with a binding_corrupt review.
    Corrupt(String),
}

pub struct RequestProcessor {
    config: ServerConfig,
    store: Arc<NullifierStore>,
    signer: Arc<ServerSigner>,
    verifier: RequestVerifier,
    withdrawal_verifier: WithdrawalVerifier,
    current_root: Arc<RwLock<Felt252>>,
    recent_roots: Mutex<RecentRoots>,
    rejected_clearances: Mutex<RejectedClearances>,
    clearance_permits: tokio::sync::Semaphore,
    /// The last vault currentRoot() read (or its failure) and when.
    vault_root_cache: tokio::sync::Mutex<Option<(Result<Felt252, String>, Instant)>>,
    /// The current minute's proof-less clearance budget.
    legacy_clearances: Mutex<LegacyClearanceWindow>,
    timing: SettlementTiming,
    dashboard: Option<Arc<DashboardHub>>,
    openrouter: Option<Arc<OpenRouterProvisioner>>,
    oa_org: Option<Arc<OaOrgProvisioner>>,
    native_oracle: NativeBillingOracle,
    lease_issue_lock: tokio::sync::Mutex<()>,
    lease_settlement_lock: tokio::sync::Mutex<()>,
    // Keep the database exclusive for this processor's full lifetime, including
    // background tasks that may outlive an HTTP listener.
    _writer_lock: Option<crate::writer_lock::ServerWriterLock>,
}

impl RequestProcessor {
    pub fn try_new(
        config: ServerConfig,
        store: Arc<NullifierStore>,
        signer: Arc<ServerSigner>,
        current_root: Felt252,
    ) -> anyhow::Result<Self> {
        config.validate_native_mode()?;
        // Library embeddings can bypass run_server's full seed policy; never
        // serve the published development keys or one key for both roles.
        signer.ensure_serving_keys()?;
        let writer_lock = store.acquire_writer_lock()?;
        if let Some(lease) = config.openrouter_leases.as_ref() {
            anyhow::ensure!(
                lease.ttl_seconds > 0,
                "OpenRouter lease TTL must be positive"
            );
            // Sanity only: run_server enforces the full bound against the
            // vault's challengePeriod().
            anyhow::ensure!(
                lease.settlement_deadline_seconds > lease.settlement_grace_seconds,
                "OpenRouter settlement deadline must exceed the settlement grace"
            );
            match &lease.source {
                OpenRouterLeaseSourceConfig::OpenRouter { management_key, .. } => {
                    anyhow::ensure!(
                        !management_key.is_empty(),
                        "OpenRouter management key cannot be empty"
                    );
                }
                OpenRouterLeaseSourceConfig::OaOrg {
                    org_base_url,
                    shared_secret,
                } => {
                    anyhow::ensure!(!org_base_url.is_empty(), "OA org URL cannot be empty");
                    anyhow::ensure!(
                        !shared_secret.is_empty(),
                        "OA org shared secret cannot be empty"
                    );
                    anyhow::ensure!(
                        lease.ttl_seconds.is_multiple_of(60),
                        "OA org lease TTL must be a whole number of minutes"
                    );
                }
            }
        }
        let native_oracle = NativeBillingOracle::for_server(&config)?;
        let verifier = RequestVerifier::load(&config.proof_setup_dir)?;
        let withdrawal_verifier = WithdrawalVerifier::load(&config.proof_setup_dir)?;
        let openrouter = config
            .openrouter_leases
            .as_ref()
            .and_then(|lease| match &lease.source {
                OpenRouterLeaseSourceConfig::OpenRouter {
                    management_key,
                    api_base,
                } => Some(
                    OpenRouterProvisioner::new(management_key.clone(), api_base.clone())
                        .map(Arc::new),
                ),
                OpenRouterLeaseSourceConfig::OaOrg { .. } => None,
            })
            .transpose()?;
        let oa_org = config
            .openrouter_leases
            .as_ref()
            .and_then(|lease| match &lease.source {
                OpenRouterLeaseSourceConfig::OaOrg {
                    org_base_url,
                    shared_secret,
                } => Some(
                    OaOrgProvisioner::new(org_base_url.clone(), shared_secret.clone())
                        .map(Arc::new),
                ),
                OpenRouterLeaseSourceConfig::OpenRouter { .. } => None,
            })
            .transpose()?;
        let mut recent_roots = RecentRoots::default();
        recent_roots.observe(
            current_root,
            current_timestamp(),
            config.clearance_root_window_seconds,
        );
        Ok(Self {
            native_oracle,
            config,
            store,
            signer,
            verifier,
            withdrawal_verifier,
            current_root: Arc::new(RwLock::new(current_root)),
            recent_roots: Mutex::new(recent_roots),
            rejected_clearances: Mutex::new(RejectedClearances::default()),
            clearance_permits: tokio::sync::Semaphore::new(CLEARANCE_VERIFY_PERMITS),
            vault_root_cache: tokio::sync::Mutex::new(None),
            legacy_clearances: Mutex::new(LegacyClearanceWindow::default()),
            timing: SettlementTiming::default(),
            dashboard: None,
            openrouter,
            oa_org,
            lease_issue_lock: tokio::sync::Mutex::new(()),
            lease_settlement_lock: tokio::sync::Mutex::new(()),
            _writer_lock: writer_lock,
        })
    }

    #[cfg(test)]
    pub(crate) fn finalize_test_lease(
        &self,
        request: &ApiRequestV2,
        charge_gwei: u128,
    ) -> Result<RequestResponseV2, ServerError> {
        if let Some(response) = self.validate_and_reserve(request)? {
            return Ok(response);
        }
        self.finalize_request(
            request,
            SettlementResult {
                status_code: 200,
                payload: self
                    .settlement_payload(request, serde_json::json!({"status":"finalized"}))?,
                charge_applied: charge_gwei,
                usage: None,
                billing_label: "native-test".into(),
            },
            0,
            0,
        )
    }

    pub fn with_dashboard(mut self, dashboard: Arc<DashboardHub>) -> Self {
        self.dashboard = Some(dashboard);
        self
    }

    pub fn dashboard(&self) -> Option<&Arc<DashboardHub>> {
        self.dashboard.as_ref()
    }

    pub fn update_root(&self, new_root: Felt252) {
        if let Ok(mut root) = self.current_root.write() {
            *root = new_root;
        }
        self.observe_root(new_root, current_timestamp());
    }

    fn observe_root(&self, root: Felt252, now: u64) {
        if let Ok(mut roots) = self.recent_roots.lock() {
            roots.observe(root, now, self.config.clearance_root_window_seconds);
        }
    }

    pub fn current_root(&self) -> Felt252 {
        self.current_root
            .read()
            .map(|value| *value)
            .unwrap_or(Felt252::ZERO)
    }

    pub fn state_signing_key(&self) -> CurvePointWire {
        self.signer.state_public_key()
    }

    pub fn clearance_signing_key(&self) -> CurvePointWire {
        self.signer.clearance_public_key()
    }

    pub async fn native_billing_quote(&self) -> Result<NativeBillingQuote, ServerError> {
        self.native_oracle.quote(current_timestamp()).await
    }

    /// The proof-bound lease terms exactly as persisted: the prompt-free
    /// authorization and the frozen quote, checked only intrinsically.
    /// Settlement uses these and never reads mutable configuration.
    fn lease_terms(
        request: &ApiRequestV2,
    ) -> Result<(OpenRouterLeaseAuthorization, NativeBillingQuote), ServerError> {
        let mut payload: serde_json::Value = serde_json::from_str(&request.payload)
            .map_err(|_| ServerError::InvalidRequest("invalid lease authorization".into()))?;
        let object = payload.as_object_mut().ok_or_else(|| {
            ServerError::InvalidRequest("invalid lease authorization object".into())
        })?;
        let quote = object.remove("billing_quote").ok_or_else(|| {
            ServerError::InvalidRequest("native ETH lease requires a bound billing quote".into())
        })?;
        let quote: NativeBillingQuote = serde_json::from_value(quote)
            .map_err(|_| ServerError::InvalidRequest("invalid native billing quote".into()))?;
        quote.validate_intrinsic(request.public_inputs.chain_id)?;
        let authorization = serde_json::from_value(payload).map_err(|_| {
            ServerError::InvalidRequest("invalid prompt-free lease authorization".into())
        })?;
        Ok((authorization, quote))
    }

    /// Admission only: the frozen terms must also match the live deployment.
    fn lease_authorization(
        &self,
        request: &ApiRequestV2,
    ) -> Result<(OpenRouterLeaseAuthorization, NativeBillingQuote), ServerError> {
        let (authorization, quote) = Self::lease_terms(request)?;
        let config = self.config.native_billing.as_ref().ok_or_else(|| {
            ServerError::InvalidRequest("native ETH billing configuration is required".into())
        })?;
        quote.validate_identity(config, self.config.chain_id)?;
        Ok((authorization, quote))
    }

    fn lease_limit_micro_usd(&self, request: &ApiRequestV2) -> Result<u128, ServerError> {
        Self::lease_terms(request)?
            .1
            .limit_micro_usd(request.public_inputs.solvency_bound)
    }

    fn settlement_payload(
        &self,
        request: &ApiRequestV2,
        mut payload: serde_json::Value,
    ) -> Result<String, ServerError> {
        let quote = Self::lease_terms(request)?.1;
        payload
            .as_object_mut()
            .ok_or_else(|| ServerError::Internal("settlement payload is not an object".into()))?
            .insert(
                "billing_quote".into(),
                serde_json::to_value(quote).map_err(|_| {
                    ServerError::Internal("could not encode native billing quote".into())
                })?,
            );
        Ok(payload.to_string())
    }

    /// A settlement payload that cannot fail: the frozen quote when it parses,
    /// otherwise the request's untouched billing_quote value. Clients require
    /// the quote they signed to be echoed.
    fn fallback_settlement_payload(
        &self,
        request: &ApiRequestV2,
        payload: serde_json::Value,
    ) -> String {
        self.settlement_payload(request, payload.clone())
            .unwrap_or_else(|_| {
                let mut payload = payload;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("billing_quote".into(), Self::raw_billing_quote(request));
                }
                payload.to_string()
            })
    }

    fn raw_billing_quote(request: &ApiRequestV2) -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(&request.payload)
            .ok()
            .and_then(|payload| payload.get("billing_quote").cloned())
            .unwrap_or(serde_json::Value::Null)
    }

    #[cfg(test)]
    fn lease_charge_units(
        &self,
        request: &ApiRequestV2,
        micro_usd: u128,
    ) -> Result<u128, ServerError> {
        Self::lease_terms(request)?.1.charge_units(micro_usd)
    }

    fn lease_config(&self) -> Result<&OpenRouterLeaseConfig, ServerError> {
        self.config
            .openrouter_leases
            .as_ref()
            .ok_or_else(|| ServerError::Internal("lease configuration is unavailable".into()))
    }

    /// The write-once deadline of a lease created now.
    fn new_lease_deadline(&self, lease_config: &OpenRouterLeaseConfig, created_at: u64) -> u64 {
        created_at
            .saturating_add(lease_config.ttl_seconds)
            .saturating_add(lease_config.settlement_grace_seconds)
            .saturating_add(lease_config.settlement_deadline_seconds)
    }

    /// The deadline a lease recorded without one receives at first sight:
    /// a full settlement window from its expiry or from now, whichever is later.
    fn first_sight_deadline(
        &self,
        lease_config: &OpenRouterLeaseConfig,
        expires_at: u64,
        now: u64,
    ) -> u64 {
        expires_at
            .max(now)
            .saturating_add(lease_config.settlement_grace_seconds)
            .saturating_add(lease_config.settlement_deadline_seconds)
    }

    /// A lease's write-once settlement deadline, assigned (once) at first
    /// sight for a row recorded without one.
    fn settlement_deadline(
        &self,
        lease: &OpenRouterLeaseRecord,
        now: u64,
    ) -> Result<u64, ServerError> {
        if let Some(deadline) = lease.settlement_deadline_at {
            return Ok(deadline);
        }
        let deadline = self.first_sight_deadline(self.lease_config()?, lease.expires_at, now);
        self.store
            .assign_settlement_deadline(&lease.client_request_id, deadline)
    }

    fn assign_missing_settlement_deadlines(&self, now: u64) {
        let Ok(lease_config) = self.lease_config() else {
            return;
        };
        let rows = match self.store.leases_without_settlement_deadline() {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(error = %error, "cannot assign lease settlement deadlines");
                return;
            }
        };
        for (client_request_id, expires_at) in rows {
            let deadline = self.first_sight_deadline(lease_config, expires_at, now);
            if let Err(error) = self
                .store
                .assign_settlement_deadline(&client_request_id, deadline)
            {
                tracing::error!(%client_request_id, error = %error, "cannot assign a lease settlement deadline");
            }
        }
    }

    /// A runtime key was, or may have been, returned to the client. Only
    /// such a lease can be charged more than zero.
    fn may_have_delivered(lease: &OpenRouterLeaseRecord) -> bool {
        matches!(
            lease.status.as_str(),
            "active" | "retiring" | "disabled" | "revoking"
        ) && lease.delivered != Some(false)
    }

    fn native_oa_request_id(request: &ApiRequestV2) -> Result<String, ServerError> {
        let binding = api_request_binding(request)?;
        let mut hash = Keccak256::new();
        hash.update(b"zkapi:oa-org-request:v1\0");
        hash.update(binding.as_bytes());
        Ok(format!("zkapi-v2-{}", hex::encode(hash.finalize())))
    }

    fn persisted_oa_request_id(
        &self,
        lease: &crate::nullifier_store::OpenRouterLeaseRecord,
    ) -> Result<String, ServerError> {
        let expected = Self::native_oa_request_id(&lease.api_request)?;
        if lease.oa_client_request_id.as_deref() != Some(expected.as_str()) {
            return Err(ServerError::Internal(
                "native OA lease is missing its bound upstream request ID".into(),
            ));
        }
        Ok(expected)
    }

    /// The upstream request ID of an issued OA lease for usage settlement.
    /// Leases issued before the bound namespace existed used the plain
    /// client request ID upstream; settle them under it first.
    fn oa_usage_request_id(&self, lease: &OpenRouterLeaseRecord) -> Result<String, ServerError> {
        let expected = Self::native_oa_request_id(&lease.api_request)?;
        match lease.oa_client_request_id.as_deref() {
            Some(id) if id == expected => Ok(expected),
            None => Ok(lease.client_request_id.clone()),
            Some(_) => Err(ServerError::Unsettleable(
                "OA lease upstream request ID does not match its bound request".into(),
            )),
        }
    }

    /// The lease TTL frozen at creation; legacy rows use the configured TTL.
    fn lease_ttl_seconds(&self, lease: &OpenRouterLeaseRecord) -> Result<u64, ServerError> {
        let valid = |ttl: u64| ttl > 0 && (lease.key_source != "oa_org" || ttl.is_multiple_of(60));
        match lease.ttl_seconds {
            Some(ttl) if valid(ttl) => Ok(ttl),
            Some(_) => Err(ServerError::Unsettleable(
                "persisted lease TTL is not a positive whole number of minutes".into(),
            )),
            None => {
                let ttl = self.lease_config()?.ttl_seconds;
                if !valid(ttl) {
                    return Err(ServerError::Internal(
                        "OA org lease duration is not a positive whole number of minutes".into(),
                    ));
                }
                Ok(ttl)
            }
        }
    }

    /// Reserve one prompt-free zkAPI request and mint its bounded OpenRouter
    /// runtime key using its frozen native ETH price quote.
    pub async fn issue_openrouter_lease(
        &self,
        request: &ApiRequestV2,
    ) -> Result<IssuedOpenRouterLease, ServerError> {
        let public = &request.public_inputs;
        if public.protocol_version != self.config.protocol_version
            || public.chain_id != self.config.chain_id
            || public.contract_address != self.config.contract_address
        {
            return Err(ServerError::ProtocolMismatch(
                "version, chain, or contract mismatch".to_string(),
            ));
        }
        // A new reservation's quote is checked against the live deployment by
        // the oracle below; an exact retry keeps its frozen quote.
        let (authorization, billing_quote) = Self::lease_terms(request)?;
        if authorization != OpenRouterLeaseAuthorization::default() {
            return Err(ServerError::InvalidRequest(
                "unsupported OpenRouter lease authorization".to_string(),
            ));
        }
        let lease_config = self.config.openrouter_leases.as_ref().ok_or_else(|| {
            ServerError::InvalidRequest(
                "prompt-private OpenRouter leases are not enabled on this server".to_string(),
            )
        })?;
        // Validate native integer bounds before reserving a nullifier. An
        // unrepresentable budget must never strand otherwise unused state.
        let limit_micro_usd =
            billing_quote.limit_micro_usd(request.public_inputs.solvency_bound)?;
        let _issue_guard = self.lease_issue_lock.lock().await;
        let oa_request_id = if matches!(
            lease_config.source,
            OpenRouterLeaseSourceConfig::OaOrg { .. }
        ) {
            Some(Self::native_oa_request_id(request)?)
        } else {
            None
        };

        // A persisted request already froze its quote before external issuance.
        // Matching retries remain valid after the oracle round ages out.
        let existing_lease = self
            .store
            .lookup_openrouter_lease(&request.client_request_id);
        let existing_reservation = self
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier);
        if let Some(existing) = existing_lease.as_ref() {
            if api_request_binding(&existing.api_request)? != api_request_binding(request)? {
                return Err(ServerError::Replay);
            }
        }
        if existing_reservation.is_none() {
            self.native_oracle
                .validate(&billing_quote, current_timestamp())
                .await?;
            // Oracle reads may span expiry; no await may separate this check
            // from the synchronous proof validation and reservation below.
            self.native_oracle
                .assert_fresh(&billing_quote, current_timestamp())?;
        }
        if self.validate_and_reserve(request)?.is_some() {
            return Err(ServerError::Replay);
        }
        let key_name = format!("zkapi-{}", request.client_request_id);
        // The verified proof may expose a coarse solvency tier above the
        // deployment's minimum request cap. Bind that exact tier to the child
        // key's cumulative USD budget for this chat.
        let mut spending_limit_usd = pricing::micro_usd_to_usd(limit_micro_usd);
        if !spending_limit_usd.is_finite() || spending_limit_usd <= 0.0 {
            return Err(ServerError::InvalidRequest(
                "lease spending limit must be positive".to_string(),
            ));
        }
        let mut issued_at = current_timestamp();
        let mut ttl_seconds = lease_config.ttl_seconds;
        let existing = self
            .store
            .lookup_openrouter_lease(&request.client_request_id);
        if let Some(existing) = existing.as_ref() {
            let persisted_binding = api_request_binding(&existing.api_request)?;
            if existing.request_nullifier != request.public_inputs.request_nullifier
                || persisted_binding != api_request_binding(request)?
            {
                return Err(ServerError::Internal(
                    "pending lease request does not match its nullifier reservation".to_string(),
                ));
            }
            if existing.key_source != lease_config.source.label() {
                return Err(ServerError::Internal(format!(
                    "pending lease source {} does not match configured source {}",
                    existing.key_source,
                    lease_config.source.label()
                )));
            }
            if existing.status == "cancelled" {
                return Err(ServerError::NullifierUsed);
            }
            if existing.status != "provisioning" || existing.key_hash.is_some() {
                return Err(ServerError::LeasePending);
            }
            if existing.key_source == "oa_org"
                && existing.oa_provisioning_outcome == OaProvisioningOutcome::ConfirmedUnissued
            {
                // A definitive rejection is terminal. Never mint another key
                // while recovering a crash between its evidence and signature.
                self.finalize_never_delivered_lease(&existing.client_request_id)?;
                return Err(ServerError::OaKeyPolicyRejected);
            }
        } else {
            // Persist a settleable lease before any further I/O. A chain or
            // provider failure from here on leaves a provisioning row, which
            // settles at zero, rather than a bare nullifier reservation.
            self.create_issuance_lease(
                request,
                lease_config,
                spending_limit_usd,
                oa_request_id.as_deref(),
            )?;
        }
        // A reservation preserves the accepted request, not permission to mint
        // new access after its collateral has entered an escape or been paid
        // out. Check immediately before provider I/O, including OA retries
        // that might be the first successful upstream issuance.
        self.native_oracle
            .assert_request_unspent(&request.public_inputs.request_nullifier)
            .await?;
        if let Some(existing) = existing.as_ref() {
            match &lease_config.source {
                OpenRouterLeaseSourceConfig::OpenRouter { .. } => {
                    let provisioner = self.openrouter.as_ref().ok_or_else(|| {
                        ServerError::Internal(
                            "OpenRouter lease provider is unavailable".to_string(),
                        )
                    })?;
                    provisioner.delete_keys_named(&key_name).await?;
                    self.store
                        .remove_failed_openrouter_lease(&request.client_request_id)?;
                    self.create_issuance_lease(
                        request,
                        lease_config,
                        spending_limit_usd,
                        oa_request_id.as_deref(),
                    )?;
                }
                OpenRouterLeaseSourceConfig::OaOrg { .. } => {
                    // OA station issuance is replay-safe. Retain the durable
                    // reservation and ask for the same one-show key again. The
                    // persisted limit, not any retry input, is authoritative.
                    let persisted_limit = pricing::micro_usd_to_usd(
                        self.lease_limit_micro_usd(&existing.api_request)?,
                    );
                    if existing.spending_limit_usd.to_bits() != persisted_limit.to_bits()
                        || !persisted_limit.is_finite()
                        || persisted_limit <= 0.0
                    {
                        return Err(ServerError::Internal(
                            "pending lease spending limit does not match its bound request"
                                .to_string(),
                        ));
                    }
                    self.persisted_oa_request_id(existing)?;
                    // The persisted TTL, not the live configuration, defines
                    // the lease the station issues and settles.
                    ttl_seconds = self.lease_ttl_seconds(existing)?;
                    // Never deliver a key whose settlement could not finish
                    // before this lease's deadline; it then settles at zero.
                    if let Some(deadline) = existing.settlement_deadline_at {
                        let latest_start = current_timestamp()
                            .saturating_add(ttl_seconds)
                            .saturating_add(lease_config.settlement_grace_seconds)
                            .saturating_add(MIN_SETTLEMENT_RETRY_WINDOW_SECONDS);
                        if latest_start > deadline {
                            return Err(ServerError::LeasePending);
                        }
                    }
                    spending_limit_usd = existing.spending_limit_usd;
                    issued_at = existing.issued_at;
                }
            }
        }
        let requested_expires_at = current_timestamp().saturating_add(ttl_seconds);
        let (api_key, key_hash, openrouter_api_base, expires_at, verification) = match &lease_config
            .source
        {
            OpenRouterLeaseSourceConfig::OpenRouter { .. } => {
                let provisioner = self.openrouter.as_ref().ok_or_else(|| {
                    ServerError::Internal("OpenRouter lease provider is unavailable".to_string())
                })?;
                match provisioner
                    .create_key(&key_name, spending_limit_usd, requested_expires_at)
                    .await
                {
                    Ok(created) => (
                        created.key,
                        created.hash,
                        provisioner.inference_base(),
                        requested_expires_at,
                        None,
                    ),
                    Err(error) => {
                        // Keep the provisioning row: it was never delivered and
                        // settles at zero unless an exact retry reissues it
                        // (which first removes any key created ambiguously).
                        let _ = self.store.record_openrouter_lease_error(
                            &request.client_request_id,
                            &error.to_string(),
                        );
                        return Err(error);
                    }
                }
            }
            OpenRouterLeaseSourceConfig::OaOrg { .. } => {
                let provisioner = self.oa_org.as_ref().ok_or_else(|| {
                    ServerError::Internal("OA org lease provider is unavailable".to_string())
                })?;
                // Commit uncertainty before any external side effect. A crash
                // or timeout can never later be mistaken for nonissuance.
                let first_attempt = self.store.begin_oa_issuance(&request.client_request_id)?;
                let created = provisioner
                    .create_key(
                        oa_request_id
                            .as_deref()
                            .unwrap_or(&request.client_request_id),
                        spending_limit_usd,
                        limit_micro_usd,
                        ttl_seconds,
                    )
                    .await;
                let created = match created {
                    Ok(created) => created,
                    Err(ServerError::OaKeyPolicyRejected) if first_attempt => {
                        self.store.confirm_oa_unissued(&request.client_request_id)?;
                        self.finalize_never_delivered_lease(&request.client_request_id)?;
                        return Err(ServerError::OaKeyPolicyRejected);
                    }
                    Err(error) => {
                        let _ = self.store.record_openrouter_lease_error(
                            &request.client_request_id,
                            &error.to_string(),
                        );
                        return Err(error);
                    }
                };
                let usable_expires_at = created
                    .expires_at
                    .saturating_sub(OA_LEASE_EXPIRY_SAFETY_SECONDS);
                if usable_expires_at <= current_timestamp() {
                    return Err(ServerError::Internal(
                        "OA org key has no safe usable lifetime".to_string(),
                    ));
                }
                (
                    created.key,
                    created.hash,
                    created.openrouter_api_base,
                    usable_expires_at,
                    Some(created.verification),
                )
            }
        };
        let settle_after = expires_at.saturating_add(lease_config.settlement_grace_seconds);
        self.store.update_openrouter_lease_timing(
            &request.client_request_id,
            expires_at,
            settle_after,
        )?;
        if let Err(error) = self
            .store
            .activate_openrouter_lease(&request.client_request_id, &key_hash)
        {
            if let (Some(provisioner), OpenRouterLeaseSourceConfig::OpenRouter { .. }) =
                (&self.openrouter, &lease_config.source)
            {
                let _ = provisioner.delete_key(&key_hash).await;
            }
            return Err(error);
        }
        // The chain may have consumed this nullifier during provider I/O.
        // Persist activation first so challenge evidence and settlement survive
        // either a consumed nullifier or an unavailable RPC, but never expose
        // the runtime key unless its authorization is still unspent.
        self.native_oracle
            .assert_request_unspent(&request.public_inputs.request_nullifier)
            .await?;
        // Durably mark the key delivered before returning it. A key that is
        // never returned can only ever be charged zero.
        self.store
            .mark_openrouter_lease_delivered(&request.client_request_id)?;
        Ok(IssuedOpenRouterLease {
            lease: OpenRouterLeaseResponse {
                status: "active".to_string(),
                client_request_id: request.client_request_id.clone(),
                api_key,
                openrouter_api_base,
                issued_at,
                expires_at,
                valid_for_seconds: expires_at.saturating_sub(issued_at),
                settle_after,
                spending_limit_usd,
            },
            key_source: lease_config.source.label().to_string(),
            verification,
            billing_quote,
        })
    }

    /// A provisioning lease row for issuance, with its TTL and write-once
    /// settlement deadline frozen now. Its key is undelivered until marked.
    fn create_issuance_lease(
        &self,
        request: &ApiRequestV2,
        lease_config: &OpenRouterLeaseConfig,
        spending_limit_usd: f64,
        oa_request_id: Option<&str>,
    ) -> Result<(), ServerError> {
        let now = current_timestamp();
        let expires_at = now.saturating_add(lease_config.ttl_seconds);
        self.store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request,
                key_source: lease_config.source.label(),
                issued_at: now,
                expires_at,
                settle_after: expires_at.saturating_add(lease_config.settlement_grace_seconds),
                spending_limit_usd,
                oa_client_request_id: oa_request_id,
                ttl_seconds: Some(lease_config.ttl_seconds),
                settlement_deadline_at: Some(self.new_lease_deadline(lease_config, now)),
                delivered: Some(false),
            })
    }

    /// Read-only expiration handshake. It serializes behind in-flight issuance
    /// without provisioning a key or mutating the wallet/nullifier database.
    pub async fn expire_unaccepted_native_lease(
        &self,
        client_request_id: &str,
        request: &ApiRequestV2,
    ) -> Result<serde_json::Value, ServerError> {
        let (authorization, quote) = Self::lease_terms(request)?;
        if authorization != OpenRouterLeaseAuthorization::default()
            || request.client_request_id != client_request_id
            || canonical_payload_hash(request.payload.as_bytes()) != request.payload_hash
        {
            return Err(ServerError::InvalidRequest(
                "native expiry check does not match the exact request".into(),
            ));
        }
        if request.public_inputs.protocol_version != self.config.protocol_version
            || request.public_inputs.chain_id != self.config.chain_id
            || request.public_inputs.contract_address != self.config.contract_address
        {
            return Err(ServerError::ProtocolMismatch(
                "native expiry check deployment mismatch".into(),
            ));
        }
        let _guard = self.lease_issue_lock.lock().await;
        if self
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_some()
            || self
                .store
                .lookup_openrouter_lease(client_request_id)
                .is_some()
            || self.store.lookup_by_client_id(client_request_id).is_some()
        {
            return Err(ServerError::LeasePending);
        }
        // Admission rejects an expired quote whatever the configuration, so a
        // configuration change can never strand an expired unaccepted journal.
        let status = if quote.expires_at <= current_timestamp() {
            "expired_unaccepted"
        } else {
            let config = self.config.native_billing.as_ref().ok_or_else(|| {
                ServerError::InvalidRequest("native ETH billing configuration is required".into())
            })?;
            quote.validate_identity(config, self.config.chain_id)?;
            let oracle = &self.native_oracle;
            match oracle.validate(&quote, current_timestamp()).await {
                Err(ServerError::NativeQuoteSuperseded) => "superseded_unaccepted",
                Err(ServerError::NativeQuoteExpired) if quote.expires_at <= current_timestamp() => {
                    "expired_unaccepted"
                }
                Err(error) => return Err(error),
                Ok(()) if quote.expires_at <= current_timestamp() => "expired_unaccepted",
                Ok(()) => return Err(ServerError::LeasePending),
            }
        };
        Ok(serde_json::json!({
            "status":status, "client_request_id":client_request_id,
            "request_nullifier":request.public_inputs.request_nullifier,
            "payload_hash":request.payload_hash, "server_time_ms":current_timestamp().saturating_mul(1000),
        }))
    }

    /// Settle every due lease. Pass 1 finalizes without provider or chain I/O:
    /// never-delivered leases at zero (provisioning rows only when issuance is
    /// idle) and possibly delivered leases past their write-once deadline.
    /// Pass 2 settles from provider usage, bounded per attempt and per tick.
    /// Pass 3 deletes provider keys of terminal leases, outside the lock.
    pub async fn settle_due_openrouter_leases(&self) {
        {
            let _settlement_guard = self.lease_settlement_lock.lock().await;
            let started = Instant::now();
            let now = current_timestamp();
            self.assign_missing_settlement_deadlines(now);
            let mut provider_io = Vec::new();
            for lease in self.store.due_openrouter_leases(now) {
                let result = if lease.status == "provisioning" {
                    // Issuance holds this lock across provider I/O; a busy
                    // lock defers this zero finalization to the next tick.
                    let Ok(_issue_guard) = self.lease_issue_lock.try_lock() else {
                        continue;
                    };
                    self.finalize_never_delivered_lease(&lease.client_request_id)
                } else if !Self::may_have_delivered(&lease) {
                    self.finalize_never_delivered_lease(&lease.client_request_id)
                } else {
                    match self.settlement_deadline(&lease, now) {
                        Ok(deadline)
                            if now >= deadline
                                && matches!(lease.key_source.as_str(), "openrouter" | "oa_org") =>
                        {
                            self.finalize_lease_fallback(
                                &lease.client_request_id,
                                FallbackCause::Deadline,
                            )
                        }
                        Ok(_) => {
                            provider_io.push(lease);
                            continue;
                        }
                        Err(error) => Err(error),
                    }
                };
                if let Err(error) = result {
                    self.note_settlement_failure(&lease, &error);
                }
            }
            for lease in provider_io {
                if started.elapsed() >= self.timing.tick_budget {
                    break;
                }
                let attempt = tokio::time::timeout(
                    self.timing.attempt_timeout,
                    self.settle_with_provider(&lease),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(ServerError::Internal(
                        "settlement attempt timed out".to_string(),
                    ))
                });
                if let Err(error) = attempt {
                    self.note_settlement_failure(&lease, &error);
                }
            }
        }
        self.cleanup_provider_keys().await;
    }

    fn note_settlement_failure(&self, lease: &OpenRouterLeaseRecord, error: &ServerError) {
        // Waiting for a drain interval or an OA receipt is not a failure.
        if matches!(error, ServerError::LeaseSettlementPending { .. }) {
            return;
        }
        tracing::warn!(
            client_request_id = %lease.client_request_id,
            error = %error,
            "OpenRouter lease settlement will be retried"
        );
        let _ = self
            .store
            .record_openrouter_lease_error(&lease.client_request_id, &error.to_string());
    }

    /// One provider-I/O settlement attempt for a possibly delivered lease. A
    /// deterministic failure finalizes at once without provider I/O.
    async fn settle_with_provider(&self, lease: &OpenRouterLeaseRecord) -> Result<(), ServerError> {
        let result = match lease.key_source.as_str() {
            "openrouter" => match &self.openrouter {
                Some(provisioner) => self.settle_openrouter_lease(lease, provisioner).await,
                None => Err(ServerError::Internal(
                    "direct OpenRouter settlement credential is unavailable".to_string(),
                )),
            },
            "oa_org" => self.settle_oa_org_lease(lease).await,
            // Never force-finalized, so that a rollback stays safe.
            source => Err(ServerError::Internal(format!(
                "unsupported lease key source {source}"
            ))),
        };
        match result {
            Err(ServerError::Unsettleable(message)) => {
                self.note_settlement_failure(lease, &ServerError::Unsettleable(message.clone()));
                self.finalize_lease_fallback(
                    &lease.client_request_id,
                    FallbackCause::Unsettleable(message),
                )
            }
            other => other,
        }
    }

    /// Retire a key that the upstream rejected before its advertised lease
    /// end. Requiring the original prompt-free proof prevents lease IDs alone
    /// from acting as unauthenticated denial-of-service capabilities.
    pub async fn retire_openrouter_lease(
        &self,
        client_request_id: &str,
        request: &ApiRequestV2,
    ) -> Result<OpenRouterLeaseStatusResponse, ServerError> {
        let pending = || ServerError::LeaseSettlementPending {
            retry_after_seconds: self
                .config
                .openrouter_leases
                .as_ref()
                .map_or(1, |lease| lease.settlement_poll_seconds.max(1)),
        };
        let Ok(_settlement_guard) = tokio::time::timeout(
            self.timing.retire_lock_timeout,
            self.lease_settlement_lock.lock(),
        )
        .await
        else {
            return Err(pending());
        };
        let lease = self
            .store
            .lookup_openrouter_lease(client_request_id)
            .ok_or_else(|| ServerError::InvalidRequest("unknown OpenRouter lease".to_string()))?;
        let request_matches = serde_json::to_value(request)
            .and_then(|request| {
                serde_json::to_value(&lease.api_request).map(|issued| request == issued)
            })
            .map_err(|error| {
                ServerError::Internal(format!("failed to compare lease retirement proof: {error}"))
            })?;
        if request.client_request_id != client_request_id || !request_matches {
            return Err(ServerError::InvalidRequest(
                "lease retirement proof does not match the issued lease".to_string(),
            ));
        }
        tokio::time::timeout(self.timing.retire_timeout, self.retire_locked(&lease))
            .await
            .map_err(|_| pending())??;
        self.openrouter_lease_status(client_request_id)
            .ok_or_else(|| ServerError::Internal("retired lease disappeared".to_string()))
    }

    /// Callers hold the settlement lock.
    async fn retire_locked(&self, lease: &OpenRouterLeaseRecord) -> Result<(), ServerError> {
        let now = current_timestamp();
        let result = match lease.status.as_str() {
            "finalized" | "cancelled" => return Ok(()),
            // Never delivered: settle at zero, serialized with issuance.
            "provisioning" => {
                let _issue_guard = self.lease_issue_lock.lock().await;
                self.finalize_never_delivered_lease(&lease.client_request_id)
            }
            "active" | "retiring" | "disabled" | "revoking" if !Self::may_have_delivered(lease) => {
                self.finalize_never_delivered_lease(&lease.client_request_id)
            }
            "active" | "retiring" | "disabled" | "revoking" => {
                match self.settlement_deadline(lease, now)? {
                    deadline
                        if now >= deadline
                            && matches!(lease.key_source.as_str(), "openrouter" | "oa_org") =>
                    {
                        self.finalize_lease_fallback(
                            &lease.client_request_id,
                            FallbackCause::Deadline,
                        )
                    }
                    _ => self.settle_with_provider(lease).await,
                }
            }
            _ => return Err(ServerError::LeasePending),
        };
        if let Err(error) = &result {
            self.note_settlement_failure(lease, error);
        }
        result
    }

    /// Check a lease row against its nullifier reservation. A mismatch is a
    /// corrupt binding (never signed); a different deployment or signing key
    /// is an operator configuration error and stays pending.
    fn check_lease_binding(
        &self,
        lease: &OpenRouterLeaseRecord,
    ) -> Result<LeaseBinding, ServerError> {
        let request = &lease.api_request;
        let public = &request.public_inputs;
        let Some(record) = self
            .store
            .try_lookup_by_nullifier(&lease.request_nullifier)?
        else {
            return Ok(LeaseBinding::Corrupt(
                "lease has no nullifier reservation".into(),
            ));
        };
        let binding = api_request_binding(request)?;
        if lease.client_request_id != request.client_request_id
            || lease.request_nullifier != public.request_nullifier
            || record.status == NullifierStatus::ClearanceReserved
            || record.reservation_kind != "openrouter_lease"
            || record.client_request_id.as_deref() != Some(request.client_request_id.as_str())
            || record.payload_hash != Some(request.payload_hash)
            || record.api_request_binding.as_deref() != Some(binding.as_str())
            || canonical_payload_hash(request.payload.as_bytes()) != request.payload_hash
        {
            return Ok(LeaseBinding::Corrupt(
                "lease row does not match its nullifier reservation".into(),
            ));
        }
        let signing_key = self.state_signing_key();
        if public.protocol_version != self.config.protocol_version
            || public.chain_id != self.config.chain_id
            || public.contract_address != self.config.contract_address
            || public.state_signing_key_x != signing_key.x
            || public.state_signing_key_y != signing_key.y
        {
            return Err(ServerError::Internal(
                "lease belongs to a different deployment or state signing key; refusing to sign"
                    .into(),
            ));
        }
        Ok(LeaseBinding::Valid(Box::new(record)))
    }

    fn review(
        lease: &OpenRouterLeaseRecord,
        reason: &str,
        charge_basis: Option<&str>,
        detail: String,
        reported_usage_micro_usd: Option<u128>,
        charge_applied: Option<u128>,
    ) -> SettlementReview {
        SettlementReview {
            client_request_id: lease.client_request_id.clone(),
            request_nullifier: lease.request_nullifier,
            key_source: lease.key_source.clone(),
            reason: reason.to_string(),
            charge_basis: charge_basis.map(str::to_string),
            detail,
            reported_usage_micro_usd,
            charge_applied,
            solvency_bound: lease.api_request.public_inputs.solvency_bound,
        }
    }

    fn direct_key_cleanup<'a>(
        lease: &'a OpenRouterLeaseRecord,
        key_name: &'a str,
    ) -> Option<KeyCleanup<'a>> {
        (lease.key_source == "openrouter").then_some(KeyCleanup {
            key_source: "openrouter",
            key_hash: lease.key_hash.as_deref(),
            key_name,
        })
    }

    /// Cancel a lease whose binding is corrupt. Nothing is ever signed for
    /// it; a direct key it may hold is still disabled and deleted.
    fn cancel_corrupt_lease(
        &self,
        lease: &OpenRouterLeaseRecord,
        detail: &str,
    ) -> Result<(), ServerError> {
        let review = Self::review(
            lease,
            "binding_corrupt",
            None,
            detail.to_string(),
            None,
            None,
        );
        tracing::error!(
            client_request_id = %lease.client_request_id,
            reason = "binding_corrupt",
            "settlement required operator review"
        );
        self.store
            .cancel_openrouter_lease(&lease.client_request_id, &review)?;
        let key_name = format!("zkapi-{}", lease.client_request_id);
        if let Some(cleanup) = Self::direct_key_cleanup(lease, &key_name) {
            self.store
                .enqueue_key_cleanup(&lease.client_request_id, &cleanup)?;
        }
        Ok(())
    }

    /// The transcript committed before the lease row (a crash window, or a
    /// legacy row): record the lease from the signed transcript, never
    /// signing another balance.
    fn reconcile_finalized_lease(
        &self,
        lease: &OpenRouterLeaseRecord,
        record: &TranscriptRecord,
    ) -> Result<(), ServerError> {
        let payload = record
            .response_payload
            .as_deref()
            .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
            .unwrap_or_default();
        let usage_usd = payload["usage_usd"].as_f64().unwrap_or_else(|| {
            payload["usage_credits"]
                .as_u64()
                .map(|credits| pricing::micro_usd_to_usd(u128::from(credits)))
                .unwrap_or_default()
        });
        let basis = payload["charge_basis"].as_str().unwrap_or("measured");
        let key_name = format!("zkapi-{}", lease.client_request_id);
        self.store.finalize_openrouter_lease_with(
            &lease.client_request_id,
            &LeaseFinalization {
                usage_usd,
                charge_applied: record.charge_applied.unwrap_or_default(),
                charge_basis: basis,
                review: None,
                // Deletion is idempotent: a crash may have preceded it.
                key_cleanup: Self::direct_key_cleanup(lease, &key_name),
                only_if_unissued: false,
            },
        )?;
        Ok(())
    }

    /// Finalize a lease whose runtime key was never returned to the client
    /// at zero: provisioning rows (callers hold lease_issue_lock), and
    /// activations whose key was never delivered. Zero-charge successors are
    /// always signed. A direct key that may exist is deleted in the background.
    fn finalize_never_delivered_lease(&self, client_request_id: &str) -> Result<(), ServerError> {
        let lease = self
            .store
            .try_lookup_openrouter_lease(client_request_id)?
            .ok_or_else(|| ServerError::Internal("pending lease disappeared".into()))?;
        if matches!(lease.status.as_str(), "finalized" | "cancelled") {
            return Ok(());
        }
        if Self::may_have_delivered(&lease)
            || !matches!(
                lease.status.as_str(),
                "provisioning" | "active" | "retiring" | "disabled" | "revoking"
            )
        {
            return Err(ServerError::Internal(
                "lease may have been delivered; it cannot settle at zero".into(),
            ));
        }
        let record = match self.check_lease_binding(&lease)? {
            LeaseBinding::Valid(record) => record,
            LeaseBinding::Corrupt(detail) => return self.cancel_corrupt_lease(&lease, &detail),
        };
        if record.status == NullifierStatus::Finalized {
            return self.reconcile_finalized_lease(&lease, &record);
        }
        if record.status != NullifierStatus::Reserved {
            return Err(ServerError::LeasePending);
        }
        let request = &lease.api_request;
        let reason = match (lease.status.as_str(), lease.key_source.as_str()) {
            ("provisioning", "oa_org") => match lease.oa_provisioning_outcome {
                OaProvisioningOutcome::NotStarted => "issuance_not_started",
                OaProvisioningOutcome::ConfirmedUnissued => "issuer_policy_rejected",
                OaProvisioningOutcome::MayHaveIssued => "issuance_not_completed",
            },
            ("provisioning", _) => "issuance_not_completed",
            _ => "key_never_delivered",
        };
        let (body, billing_label) = if lease.key_source == "oa_org" {
            (
                serde_json::json!({
                    "type": "oa_org_unissued_lease_cancellation",
                    "issued": false,
                    "delivered": false,
                    "usage_credits": 0,
                    "usage_usd": 0,
                    "charge_basis": "unissued",
                    "reason": reason,
                }),
                "direct:oa-org-unissued",
            )
        } else {
            (
                serde_json::json!({
                    "type": "openrouter_ephemeral_lease_settlement",
                    "issued": false,
                    "delivered": false,
                    "issued_at": lease.issued_at,
                    "expires_at": lease.expires_at,
                    "usage_usd": 0,
                    "charge_basis": "unissued",
                    "reason": reason,
                }),
                "direct:openrouter-unissued",
            )
        };
        let payload = self.fallback_settlement_payload(request, body);
        match self.finalize_request(
            request,
            SettlementResult {
                status_code: 200,
                payload,
                charge_applied: 0,
                usage: None,
                billing_label: billing_label.into(),
            },
            0,
            0,
        ) {
            Ok(_) => {}
            Err(ServerError::InvalidProof(detail) | ServerError::InvalidRequest(detail)) => {
                return self.cancel_corrupt_lease(&lease, &detail)
            }
            Err(error) => return Err(error),
        }
        let key_name = format!("zkapi-{}", lease.client_request_id);
        let finalized = self.store.finalize_openrouter_lease_with(
            &lease.client_request_id,
            &LeaseFinalization {
                usage_usd: 0.0,
                charge_applied: 0,
                charge_basis: "unissued",
                review: None,
                // Best effort and outside every lock: retries now return the
                // finalized response before any key creation.
                key_cleanup: Self::direct_key_cleanup(&lease, &key_name),
                only_if_unissued: lease.status == "provisioning",
            },
        )?;
        if !finalized {
            // The next scan records the lease from the signed transcript.
            return Err(ServerError::Internal(
                "lease changed during zero settlement".into(),
            ));
        }
        tracing::info!(
            client_request_id = %lease.client_request_id,
            reason,
            "finalized a never-delivered lease at zero"
        );
        Ok(())
    }

    /// Finalize a possibly delivered lease without provider I/O: at its
    /// captured usage when a direct key was already disabled and only its
    /// deletion failed, otherwise at the request's solvency bound. Records an
    /// operator review. A corrupt binding is cancelled, never signed.
    fn finalize_lease_fallback(
        &self,
        client_request_id: &str,
        cause: FallbackCause,
    ) -> Result<(), ServerError> {
        let lease = self
            .store
            .try_lookup_openrouter_lease(client_request_id)?
            .ok_or_else(|| ServerError::Internal("pending lease disappeared".into()))?;
        if matches!(lease.status.as_str(), "finalized" | "cancelled") {
            return Ok(());
        }
        if !Self::may_have_delivered(&lease) {
            return Err(ServerError::Internal(
                "a never-delivered lease settles at zero".into(),
            ));
        }
        let record = match self.check_lease_binding(&lease)? {
            LeaseBinding::Valid(record) => record,
            LeaseBinding::Corrupt(detail) => return self.cancel_corrupt_lease(&lease, &detail),
        };
        if record.status == NullifierStatus::Finalized {
            return self.reconcile_finalized_lease(&lease, &record);
        }
        if record.status != NullifierStatus::Reserved {
            return Err(ServerError::LeasePending);
        }
        let request = &lease.api_request;
        let bound = request.public_inputs.solvency_bound;
        let deadline = lease.settlement_deadline_at;
        let (settlement_reason, detail) = match &cause {
            FallbackCause::Deadline => (
                "settlement_deadline",
                format!(
                    "not settled by its deadline; last error: {}",
                    lease.last_error.as_deref().unwrap_or("none")
                ),
            ),
            FallbackCause::Unsettleable(message) => ("unsettleable", message.clone()),
        };
        let source_type = if lease.key_source == "oa_org" {
            "oa_org_ephemeral_lease_settlement"
        } else {
            "openrouter_ephemeral_lease_settlement"
        };
        // A revoking direct key was confirmed disabled and its usage captured;
        // only deletion failed. Charge that usage, not the worst case.
        let captured = match (
            lease.key_source.as_str(),
            lease.status.as_str(),
            lease.usage_usd,
        ) {
            ("openrouter", "revoking", Some(usage_usd)) => Self::lease_terms(request)
                .ok()
                .map(|(_, quote)| (usage_usd, quote)),
            _ => None,
        };
        let (charge, basis, usage_usd, review, body) = match captured {
            Some((usage_usd, quote)) => {
                let reported = pricing::usd_to_micro_usd(usage_usd);
                let capped = quote.capped_charge_units(reported, bound);
                let basis = if capped.clamped {
                    "clamped"
                } else {
                    "measured"
                };
                let mut body = serde_json::json!({
                    "type": source_type,
                    "issued_at": lease.issued_at,
                    "expires_at": lease.expires_at,
                    "usage_usd": usage_usd,
                    "charge_basis": basis,
                    "settlement_reason": settlement_reason,
                    "key_deleted": false,
                });
                if capped.clamped {
                    body["reported_usage_micro_usd"] = reported.to_string().into();
                    body["charged_usage_micro_usd"] = capped.charged_micro_usd.to_string().into();
                }
                let review = Self::review(
                    &lease,
                    "finalized_before_key_deletion",
                    Some(basis),
                    detail,
                    Some(reported),
                    Some(capped.charge),
                );
                (capped.charge, basis, usage_usd, review, body)
            }
            None => {
                let body = serde_json::json!({
                    "type": source_type,
                    "issued_at": lease.issued_at,
                    "expires_at": lease.expires_at,
                    "charge_basis": "worst_case",
                    "settlement_reason": settlement_reason,
                    "settlement_deadline": deadline,
                });
                let reason = match cause {
                    FallbackCause::Deadline => "deadline_worst_case",
                    FallbackCause::Unsettleable(_) => "unsettleable_worst_case",
                };
                let review = Self::review(
                    &lease,
                    reason,
                    Some("worst_case"),
                    detail,
                    None,
                    Some(bound),
                );
                (bound, "worst_case", 0.0, review, body)
            }
        };
        let payload = self.fallback_settlement_payload(request, body);
        let response = match self.finalize_request(
            request,
            SettlementResult {
                status_code: 200,
                payload,
                charge_applied: charge,
                usage: None,
                billing_label: format!("direct:{}-{basis}", lease.key_source),
            },
            0,
            0,
        ) {
            Ok(response) => response,
            Err(ServerError::InvalidProof(detail) | ServerError::InvalidRequest(detail)) => {
                return self.cancel_corrupt_lease(&lease, &detail)
            }
            Err(error) => return Err(error),
        };
        tracing::error!(
            client_request_id = %lease.client_request_id,
            reason = %review.reason,
            charge = response.charge_applied,
            "settlement required operator review"
        );
        let key_name = format!("zkapi-{}", lease.client_request_id);
        self.store.finalize_openrouter_lease_with(
            &lease.client_request_id,
            &LeaseFinalization {
                usage_usd,
                charge_applied: response.charge_applied,
                charge_basis: basis,
                review: Some(&review),
                key_cleanup: Self::direct_key_cleanup(&lease, &key_name),
                only_if_unissued: false,
            },
        )?;
        Ok(())
    }

    /// Ask the OA org for the station-signed final child-key usage. Pending or
    /// unavailable receipts are retried until the lease's deadline.
    async fn settle_oa_org_lease(
        &self,
        lease: &crate::nullifier_store::OpenRouterLeaseRecord,
    ) -> Result<(), ServerError> {
        let record = match self.check_lease_binding(lease)? {
            LeaseBinding::Valid(record) => record,
            LeaseBinding::Corrupt(detail) => return self.cancel_corrupt_lease(lease, &detail),
        };
        if record.status == NullifierStatus::Finalized {
            return self.reconcile_finalized_lease(lease, &record);
        }
        let key_hash = lease.key_hash.as_deref().ok_or_else(|| {
            ServerError::Internal("active OA org lease has no key hash".to_string())
        })?;
        let provisioner = self.oa_org.as_ref().ok_or_else(|| {
            ServerError::Internal("OA org lease provider is unavailable".to_string())
        })?;
        let duration_minutes = self.lease_ttl_seconds(lease)? / 60;
        let (_, quote) = Self::lease_terms(&lease.api_request)
            .map_err(|error| ServerError::Unsettleable(error.to_string()))?;
        let bound = lease.api_request.public_inputs.solvency_bound;
        let expected_limit_credits = quote
            .limit_micro_usd(bound)
            .map_err(|error| ServerError::Unsettleable(error.to_string()))?;
        if lease.spending_limit_usd.to_bits()
            != pricing::micro_usd_to_usd(expected_limit_credits).to_bits()
        {
            return Err(ServerError::Unsettleable(
                "OA lease spending limit does not match its bound request".into(),
            ));
        }
        let oa_request_id = self.oa_usage_request_id(lease)?;
        let receipt = provisioner
            .get_key_usage(
                &oa_request_id,
                key_hash,
                OaOrgUsageExpectation {
                    credit_limit_usd: lease.spending_limit_usd,
                    duration_minutes,
                    limit_credits: expected_limit_credits,
                    minimum_expires_at: lease.expires_at,
                    maximum_expires_at: lease
                        .expires_at
                        .saturating_add(OA_LEASE_EXPIRY_SAFETY_SECONDS),
                },
            )
            .await?;
        let receipt = match receipt {
            OaOrgUsage::Finalized(receipt) => receipt,
            OaOrgUsage::Pending {
                retry_after_seconds,
            } => {
                return Err(ServerError::LeaseSettlementPending {
                    retry_after_seconds,
                })
            }
        };
        if receipt.closed_at < lease.issued_at {
            return Err(ServerError::Internal(
                "OA org usage receipt predates the issued lease".to_string(),
            ));
        }
        // Clamp before conversion: a receipt above the issued limit still
        // settles, at no more than the proof-bound budget.
        let capped = quote.capped_charge_units(receipt.usage_credits, bound);
        let basis = if capped.clamped {
            "clamped"
        } else {
            "measured"
        };
        let usage_usd = pricing::micro_usd_to_usd(receipt.usage_credits);
        let payload = self
            .settlement_payload(
                &lease.api_request,
                serde_json::json!({
                    "type": "oa_org_ephemeral_lease_settlement",
                    "issued_at": lease.issued_at,
                    "expires_at": lease.expires_at,
                    "usage_credits": receipt.usage_credits,
                    "charged_usage_credits": capped.charged_micro_usd,
                    "usage_usd": usage_usd,
                    "charge_basis": basis,
                    "usage_receipt_expires_at": receipt.expires_at,
                    "usage_receipt_closed_at": receipt.closed_at,
                    "usage_finalized_at": receipt.finalized_at,
                    "station_id": receipt.station_id,
                    "station_signature": receipt.station_signature,
                    "org_signature": receipt.org_signature,
                }),
            )
            .map_err(|error| ServerError::Unsettleable(error.to_string()))?;
        let provider_response = SettlementResult {
            status_code: 200,
            payload,
            charge_applied: capped.charge,
            usage: Some(UsageInfo {
                cost_usd: usage_usd,
                cost_source: "oa_org_signed_usage_receipt".to_string(),
            }),
            billing_label: "direct:oa-org-ephemeral".to_string(),
        };
        let response = self
            .finalize_request(&lease.api_request, provider_response, 0, 0)
            .map_err(Self::deterministic_as_unsettleable)?;
        let review = capped.clamped.then(|| {
            Self::review(
                lease,
                "usage_clamped",
                Some(basis),
                "station-signed usage exceeded the proof-bound lease budget".into(),
                Some(receipt.usage_credits),
                Some(response.charge_applied),
            )
        });
        self.finish_measured_settlement(lease, usage_usd, response.charge_applied, basis, review)
    }

    async fn settle_openrouter_lease(
        &self,
        lease: &crate::nullifier_store::OpenRouterLeaseRecord,
        provisioner: &OpenRouterProvisioner,
    ) -> Result<(), ServerError> {
        let record = match self.check_lease_binding(lease)? {
            LeaseBinding::Valid(record) => record,
            LeaseBinding::Corrupt(detail) => return self.cancel_corrupt_lease(lease, &detail),
        };
        if record.status == NullifierStatus::Finalized {
            // Also reconcile a legacy/crash-window finalized transcript; its
            // key deletion is queued and retried in the background.
            return self.reconcile_finalized_lease(lease, &record);
        }
        let key_hash = lease.key_hash.as_deref().ok_or_else(|| {
            ServerError::Internal("active OpenRouter lease has no key hash".to_string())
        })?;
        let mut phase = lease.status.as_str();
        let mut settle_after = lease.settle_after;
        if phase == "active" {
            self.store.advance_openrouter_retirement(
                &lease.client_request_id,
                "active",
                "retiring",
                current_timestamp(),
                None,
            )?;
            phase = "retiring";
        }
        if phase == "retiring" {
            provisioner.disable_key(key_hash).await?;
            // OpenRouter does not issue a finalized receipt. Its aggregate
            // accounting requires the configured drain/reconciliation interval
            // after disabling, including when retiring a key before expiry.
            let grace = self.lease_config()?.settlement_grace_seconds;
            settle_after = current_timestamp().saturating_add(grace);
            self.store.advance_openrouter_retirement(
                &lease.client_request_id,
                "retiring",
                "disabled",
                settle_after,
                None,
            )?;
            phase = "disabled";
        }
        let usage_usd = if phase == "disabled" {
            let now = current_timestamp();
            if now < settle_after {
                return Err(ServerError::LeaseSettlementPending {
                    retry_after_seconds: settle_after - now,
                });
            }
            let usage = provisioner.get_key_usage(key_hash).await?;
            if !usage.disabled {
                // The write-once deadline still applies across this cycle.
                self.store.advance_openrouter_retirement(
                    &lease.client_request_id,
                    "disabled",
                    "retiring",
                    now,
                    None,
                )?;
                return Err(ServerError::Internal(
                    "OpenRouter settlement key is still enabled".to_string(),
                ));
            }
            // Capture usage durably before deletion makes it unavailable.
            self.store.advance_openrouter_retirement(
                &lease.client_request_id,
                "disabled",
                "revoking",
                now,
                Some(usage.usage_usd),
            )?;
            usage.usage_usd
        } else if phase == "revoking" {
            lease.usage_usd.ok_or_else(|| {
                ServerError::Unsettleable(
                    "OpenRouter revocation has no persisted usage".to_string(),
                )
            })?
        } else {
            return Err(ServerError::LeasePending);
        };
        // Fail closed until the deadline. A 503 or ambiguous DELETE leaves the
        // nullifier reserved and the revoking lease visible to the scanner.
        provisioner.delete_key(key_hash).await?;
        let (_, quote) = Self::lease_terms(&lease.api_request)
            .map_err(|error| ServerError::Unsettleable(error.to_string()))?;
        // Clamp to the proof-bound budget before converting, so that no
        // reported usage can make the conversion fail.
        let reported = pricing::usd_to_micro_usd(usage_usd);
        let capped =
            quote.capped_charge_units(reported, lease.api_request.public_inputs.solvency_bound);
        let basis = if capped.clamped {
            "clamped"
        } else {
            "measured"
        };
        let mut body = serde_json::json!({
            "type": "openrouter_ephemeral_lease_settlement",
            "issued_at": lease.issued_at,
            "expires_at": lease.expires_at,
            "usage_usd": usage_usd,
            "charge_basis": basis,
        });
        if capped.clamped {
            tracing::warn!(
                client_request_id = %lease.client_request_id,
                reported_micro_usd = reported,
                charge = capped.charge,
                "OpenRouter usage exceeded the proof-bound lease limit; clamped charge"
            );
            body["reported_usage_micro_usd"] = reported.to_string().into();
            body["charged_usage_micro_usd"] = capped.charged_micro_usd.to_string().into();
        }
        let payload = self
            .settlement_payload(&lease.api_request, body)
            .map_err(|error| ServerError::Unsettleable(error.to_string()))?;
        let provider_response = SettlementResult {
            status_code: 200,
            payload,
            charge_applied: capped.charge,
            usage: Some(UsageInfo {
                cost_usd: usage_usd,
                cost_source: "openrouter_key_aggregate".to_string(),
            }),
            billing_label: "direct:openrouter-ephemeral".to_string(),
        };
        let response = self
            .finalize_request(&lease.api_request, provider_response, 0, 0)
            .map_err(Self::deterministic_as_unsettleable)?;
        let review = capped.clamped.then(|| {
            Self::review(
                lease,
                "usage_clamped",
                Some(basis),
                "OpenRouter usage exceeded the proof-bound lease budget".into(),
                Some(reported),
                Some(response.charge_applied),
            )
        });
        self.finish_measured_settlement(lease, usage_usd, response.charge_applied, basis, review)
    }

    /// A signing failure caused by the persisted request itself cannot heal.
    fn deterministic_as_unsettleable(error: ServerError) -> ServerError {
        match error {
            ServerError::InvalidProof(detail) | ServerError::InvalidRequest(detail) => {
                ServerError::Unsettleable(detail)
            }
            other => other,
        }
    }

    fn finish_measured_settlement(
        &self,
        lease: &OpenRouterLeaseRecord,
        usage_usd: f64,
        charge: u128,
        basis: &str,
        review: Option<SettlementReview>,
    ) -> Result<(), ServerError> {
        if let Some(review) = &review {
            tracing::error!(
                client_request_id = %lease.client_request_id,
                reason = %review.reason,
                charge,
                "settlement required operator review"
            );
        }
        self.store.finalize_openrouter_lease_with(
            &lease.client_request_id,
            &LeaseFinalization {
                usage_usd,
                charge_applied: charge,
                charge_basis: basis,
                review: review.as_ref(),
                key_cleanup: None,
                only_if_unissued: false,
            },
        )?;
        Ok(())
    }

    /// Disable and delete the provider keys of terminal direct leases, retried
    /// with backoff until the provider confirms removal (404 included). Runs
    /// outside every lock: a terminal lease's retries never create a key.
    async fn cleanup_provider_keys(&self) {
        let Some(provisioner) = self.openrouter.as_ref() else {
            return;
        };
        let started = Instant::now();
        let now = current_timestamp();
        let pending = match self.store.due_key_cleanups(now, KEY_CLEANUP_BATCH) {
            Ok(pending) => pending,
            Err(error) => {
                tracing::warn!(error = %error, "provider key cleanup scan failed");
                return;
            }
        };
        for cleanup in pending {
            if started.elapsed() >= self.timing.cleanup_budget {
                break;
            }
            if cleanup.key_source != "openrouter" {
                let _ = self.store.complete_key_cleanup(&cleanup.client_request_id);
                continue;
            }
            let attempt = async {
                match cleanup.key_hash.as_deref() {
                    Some(hash) => provisioner.retire_key(hash).await,
                    None => provisioner.retire_keys_named(&cleanup.key_name).await,
                }
            };
            let result = tokio::time::timeout(self.timing.cleanup_attempt_timeout, attempt)
                .await
                .unwrap_or_else(|_| Err(ServerError::Internal("key cleanup timed out".into())));
            match result {
                Ok(()) => {
                    let _ = self.store.complete_key_cleanup(&cleanup.client_request_id);
                }
                Err(error) => {
                    let backoff = 2u64
                        .saturating_pow(cleanup.attempts.min(16) as u32)
                        .min(KEY_CLEANUP_MAX_BACKOFF_SECONDS);
                    tracing::warn!(
                        client_request_id = %cleanup.client_request_id,
                        error = %error,
                        "provider key cleanup will be retried"
                    );
                    let _ = self.store.defer_key_cleanup(
                        &cleanup.client_request_id,
                        &error.to_string(),
                        now.saturating_add(backoff),
                    );
                }
            }
        }
    }

    /// Validate proof/deployment bindings and reserve the request nullifier.
    /// Returns a prior finalized response for an idempotent replay.
    fn validate_and_reserve(
        &self,
        request: &ApiRequestV2,
    ) -> Result<Option<RequestResponseV2>, ServerError> {
        let public = &request.public_inputs;
        let payload_hash = canonical_payload_hash(request.payload.as_bytes());
        if payload_hash != request.payload_hash {
            return Err(ServerError::InvalidRequest(
                "payload_hash does not match payload bytes".to_string(),
            ));
        }
        if public.protocol_version != self.config.protocol_version
            || public.chain_id != self.config.chain_id
            || public.contract_address != self.config.contract_address
        {
            return Err(ServerError::ProtocolMismatch(
                "version, chain, or contract mismatch".to_string(),
            ));
        }
        let request_binding = api_request_binding(request)?;
        // A byte-identical request already reserved by this endpoint passed
        // all checks on its first attempt. Resume it before root/freshness
        // checks so a transport retry remains possible after those values move.
        // A different endpoint kind can never claim the reservation.
        if let Some(existing) = self.store.lookup_by_nullifier(&public.request_nullifier) {
            let same_request = existing.client_request_id.as_deref()
                == Some(&request.client_request_id)
                && existing.payload_hash == Some(request.payload_hash)
                && existing.reservation_kind == "openrouter_lease"
                && existing.api_request_binding.as_deref() == Some(request_binding.as_str());
            if !same_request {
                return Err(ServerError::Replay);
            }
            return match existing.status {
                NullifierStatus::Finalized => {
                    response_from_record(&existing, &request.client_request_id).map(Some)
                }
                NullifierStatus::Reserved => Ok(None),
                NullifierStatus::ClearanceReserved => Err(ServerError::Replay),
            };
        }
        let root = self.current_root();
        if public.active_root != root {
            return Err(ServerError::StaleRoot {
                latest_root: root.to_hex(),
            });
        }
        let state_key = self.state_signing_key();
        if public.state_signing_key_x != state_key.x || public.state_signing_key_y != state_key.y {
            return Err(ServerError::InvalidRequest(
                "state signing key does not match this deployment".to_string(),
            ));
        }
        let now = current_timestamp();
        if public.request_time.saturating_add(MAX_REQUEST_AGE_SECONDS) < now
            || public.request_time > now.saturating_add(MAX_FUTURE_SKEW_SECONDS)
        {
            return Err(ServerError::InvalidRequest(
                "request_time is outside the accepted freshness window".to_string(),
            ));
        }
        let required_solvency = self.config.request_charge_cap;
        if public.solvency_bound < required_solvency {
            return Err(ServerError::InvalidRequest(format!(
                "solvency_bound {} is below required {}",
                public.solvency_bound, required_solvency
            )));
        }
        let context = canonical_request_context(&request.client_request_id, &payload_hash);
        if core::authorization_tag(&public.request_nullifier, &context) != public.authorization_tag
        {
            return Err(ServerError::InvalidProof(
                "proof authorization tag does not bind this request id and payload".to_string(),
            ));
        }
        if !self
            .verifier
            .verify(public, &request.proof)
            .map_err(|error| ServerError::InvalidProof(error.to_string()))?
        {
            return Err(ServerError::InvalidProof(
                "Groth16 verification returned false".to_string(),
            ));
        }

        // Proof verification is synchronous but can be slow. Recheck at the
        // actual reservation boundary, while issue_openrouter_lease retains
        // its serialization lock. A matching existing reservation returned
        // above and keeps its original quote even after expiration.
        self.native_oracle
            .assert_fresh(&self.lease_authorization(request)?.1, current_timestamp())?;
        self.store.reserve_openrouter_lease(request)?;
        Ok(None)
    }

    fn finalize_request(
        &self,
        request: &ApiRequestV2,
        provider_response: SettlementResult,
        upstream_ms: u64,
        total_ms: u64,
    ) -> Result<RequestResponseV2, ServerError> {
        let public = &request.public_inputs;
        if public.protocol_version != self.config.protocol_version
            || public.chain_id != self.config.chain_id
            || public.contract_address != self.config.contract_address
        {
            return Err(ServerError::Internal(
                "refusing to sign a successor for a different deployment".into(),
            ));
        }
        let reservation_kind = self
            .store
            .lookup_by_nullifier(&public.request_nullifier)
            .ok_or_else(|| {
                ServerError::Internal("request nullifier is no longer reserved".to_string())
            })?
            .reservation_kind;
        if reservation_kind != "openrouter_lease" {
            return Err(ServerError::InvalidRequest(
                "only native lease reservations can settle".into(),
            ));
        }
        // The request proved balance >= solvency_bound; never sign more.
        let charge_applied = provider_response.charge_applied.min(public.solvency_bound);
        if charge_applied != provider_response.charge_applied {
            tracing::error!(
                client_request_id = %request.client_request_id,
                charge = provider_response.charge_applied,
                solvency_bound = public.solvency_bound,
                "settlement charge exceeded the solvency bound; clamped"
            );
        }

        let anonymous = CurvePointWire {
            x: public.anonymous_commitment_x,
            y: public.anonymous_commitment_y,
        };
        let blind_delta = random_scalar();
        let next_commitment = server_update(&anonymous, charge_applied, &blind_delta)
            .map_err(|error| ServerError::InvalidProof(error.to_string()))?;
        let next_anchor = core::next_anchor(
            &random_field(),
            &public.request_nullifier,
            &next_commitment.x,
            &next_commitment.y,
        );
        let state_message = core::state_message(
            self.config.protocol_version,
            self.config.chain_id,
            &self.config.contract_address,
            &next_commitment.x,
            &next_commitment.y,
            &next_anchor,
        );
        let state_signature = self.signer.sign_state(&state_message);
        let response_hash = canonical_response_hash(provider_response.payload.as_bytes());
        let proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(&request.proof.proof)
            .map_err(|error| ServerError::InvalidProof(error.to_string()))?;
        let transcript = TranscriptRecord {
            nullifier: public.request_nullifier,
            status: NullifierStatus::Finalized,
            reservation_kind,
            client_request_id: Some(request.client_request_id.clone()),
            payload_hash: Some(request.payload_hash),
            charge_applied: Some(charge_applied),
            response_code: Some(provider_response.status_code),
            response_payload: Some(provider_response.payload.clone()),
            response_hash: Some(response_hash),
            next_commitment_x: Some(next_commitment.x),
            next_commitment_y: Some(next_commitment.y),
            next_anchor: Some(next_anchor),
            blind_delta_srv: Some(blind_delta),
            next_state_sig: Some(state_signature),
            policy_reason_code: None,
            policy_evidence_hash: None,
            proof_blob: Some(proof_bytes.clone()),
            request_inputs_json: serde_json::to_string(public).ok(),
            api_request_binding: Some(api_request_binding(request)?),
            created_at: current_timestamp(),
            finalized_at: Some(current_timestamp()),
        };
        self.store
            .finalize(&public.request_nullifier, &transcript)?;

        // Nothing below may fail: the signed transcript is committed.
        if let Some(hub) = &self.dashboard {
            hub.record(DashboardEvent {
                seq: hub.next_seq(),
                ts_ms: current_timestamp_ms(),
                client_request_id: request.client_request_id.clone(),
                billing_label: provider_response.billing_label.clone(),
                request_nullifier: public.request_nullifier,
                active_root: public.active_root,
                anon_commitment: anonymous,
                solvency_bound: public.solvency_bound,
                solvency_bound_usd: Self::lease_terms(request)
                    .ok()
                    .and_then(|(_, quote)| quote.limit_micro_usd(public.solvency_bound).ok())
                    .map(pricing::micro_usd_to_usd)
                    .unwrap_or(0.0),
                proof_backend: "groth16_bn254".to_string(),
                proof_public_output_hash: public.authorization_tag,
                proof_size_bytes: proof_bytes.len(),
                request_raw: redact_secrets(&request.payload),
                response_code: provider_response.status_code,
                response_text: redact_secrets(&provider_response.payload),
                response_hash,
                usage: provider_response.usage.clone(),
                charge_applied,
                charge_usd: provider_response
                    .usage
                    .as_ref()
                    .map(|usage| usage.cost_usd)
                    .unwrap_or(0.0),
                next_commitment: next_commitment.clone(),
                next_anchor,
                blind_delta_srv: blind_delta,
                upstream_ms,
                total_ms,
            });
        }

        Ok(RequestResponseV2 {
            status: "ok".to_string(),
            client_request_id: request.client_request_id.clone(),
            request_nullifier: public.request_nullifier,
            response_code: provider_response.status_code,
            response_payload: provider_response.payload,
            response_hash,
            charge_applied,
            next_commitment,
            next_anchor,
            blind_delta_srv: blind_delta,
            next_state_signature: state_signature,
            policy_reason_code: None,
            policy_evidence_hash: None,
        })
    }

    pub fn openrouter_leases_enabled(&self) -> bool {
        self.config.openrouter_leases.is_some()
    }

    /// The deadline a pending lease will be finalized by, without assigning
    /// one (reads must not write).
    fn pending_settlement_deadline(&self, lease: &OpenRouterLeaseRecord, now: u64) -> Option<u64> {
        if matches!(lease.status.as_str(), "finalized" | "cancelled") {
            return None;
        }
        lease.settlement_deadline_at.or_else(|| {
            self.lease_config()
                .ok()
                .map(|config| self.first_sight_deadline(config, lease.expires_at, now))
        })
    }

    pub fn openrouter_lease_status(
        &self,
        client_request_id: &str,
    ) -> Option<OpenRouterLeaseStatusResponse> {
        let now = current_timestamp();
        self.store
            .lookup_openrouter_lease(client_request_id)
            .map(|lease| OpenRouterLeaseStatusResponse {
                settlement_deadline: self.pending_settlement_deadline(&lease, now),
                status: lease.status,
                client_request_id: lease.client_request_id,
                issued_at: lease.issued_at,
                expires_at: lease.expires_at,
                settle_after: lease.settle_after,
                spending_limit_usd: lease.spending_limit_usd,
                usage_usd: lease.usage_usd,
                charge_applied: lease.charge_applied,
                last_error: lease.last_error,
                charge_basis: lease.charge_basis,
            })
    }

    /// Sign a mutual-close clearance for a nullifier and reserve it for good.
    /// The caller must prove note ownership with an escape-form withdrawal
    /// proof for that nullifier, unless the transitional legacy flag is set.
    /// The ownership proof is never stored or logged.
    pub async fn process_clearance(
        &self,
        request: &ClearanceRequest,
    ) -> Result<ClearanceResponseV2, ServerError> {
        let nullifier = request.withdrawal_nullifier;
        let already_reserved = match self.store.try_lookup_by_nullifier(&nullifier)? {
            Some(record) if record.status == NullifierStatus::ClearanceReserved => true,
            Some(_) => return Err(ServerError::NullifierUsed),
            None => false,
        };
        let auth = match &request.ownership_proof {
            Some(ownership) => {
                self.verify_clearance_ownership(&nullifier, ownership)
                    .await?;
                "ownership_proof"
            }
            None if self.config.allow_legacy_clearance => {
                if !already_reserved {
                    self.admit_legacy_clearance()?;
                }
                // No nullifier in logs: it links the note to this request.
                tracing::warn!("signing a legacy clearance without a note ownership proof");
                "legacy"
            }
            None => return Err(ServerError::ClearanceOwnershipRequired),
        };
        let message = core::clearance_message(
            self.config.protocol_version,
            self.config.chain_id,
            &self.config.contract_address,
            &nullifier,
        );
        let signature = self.signer.sign_clearance(&message);
        if !already_reserved {
            // A concurrent lease reservation wins the primary key: NullifierUsed.
            self.store.reserve_clearance(&nullifier, auth)?;
        }
        Ok(ClearanceResponseV2 {
            status: "ok".to_string(),
            withdrawal_nullifier: nullifier,
            signature,
        })
    }

    /// Spend one slot of the shared per-minute budget on a new proof-less
    /// reservation. Exhaustion has its own error code, so a client can tell
    /// it from verification saturation and send its ownership proof instead.
    fn admit_legacy_clearance(&self) -> Result<(), ServerError> {
        let admitted = self
            .legacy_clearances
            .lock()
            .map_err(|_| ServerError::Internal("legacy clearance limiter poisoned".into()))?
            .admit(
                current_timestamp(),
                self.config.legacy_clearance_max_per_minute,
            );
        let Err(refusal) = admitted else {
            return Ok(());
        };
        // Junk requests can exhaust the budget every minute: log once per window.
        if refusal.first_in_window {
            tracing::warn!(
                max_per_minute = self.config.legacy_clearance_max_per_minute,
                rejected_total = refusal.rejected_total,
                "legacy clearance budget exhausted: proof-less clearances are refused until the next minute"
            );
        }
        Err(ServerError::LegacyClearanceCapacity {
            retry_after_seconds: refusal.retry_after_seconds,
        })
    }

    /// The legacy clearance budget for `/health`.
    pub fn legacy_clearance_usage(&self) -> LegacyClearanceUsage {
        let limit = if self.config.allow_legacy_clearance {
            self.config.legacy_clearance_max_per_minute
        } else {
            0
        };
        self.legacy_clearances
            .lock()
            .map(|window| window.usage(current_timestamp(), limit))
            .unwrap_or_default()
    }

    /// Verify an escape-form withdrawal proof for exactly this nullifier and
    /// deployment at a root the server or the vault knows. Cheap checks come
    /// first; the verification permit is released before any I/O; the vault
    /// root read is single-flight and cached; rejected (root, nullifier)
    /// pairs are answered from a negative cache.
    async fn verify_clearance_ownership(
        &self,
        nullifier: &Felt252,
        ownership: &ClearanceOwnershipProof,
    ) -> Result<(), ServerError> {
        let inputs = &ownership.public_inputs;
        if inputs.withdrawal_nullifier != *nullifier {
            return Err(ServerError::InvalidRequest(
                "ownership proof is for a different nullifier".into(),
            ));
        }
        if inputs.has_clearance {
            return Err(ServerError::InvalidRequest(
                "ownership proof must be an escape-form withdrawal proof".into(),
            ));
        }
        if inputs.protocol_version != self.config.protocol_version
            || inputs.chain_id != self.config.chain_id
            || inputs.contract_address != self.config.contract_address
        {
            return Err(ServerError::ProtocolMismatch(
                "ownership proof is for a different deployment".into(),
            ));
        }
        let state_key = self.signer.state_public_key();
        let clearance_key = self.signer.clearance_public_key();
        if inputs.state_signing_key_x != state_key.x
            || inputs.state_signing_key_y != state_key.y
            || inputs.clearance_signing_key_x != clearance_key.x
            || inputs.clearance_signing_key_y != clearance_key.y
        {
            return Err(ServerError::InvalidRequest(
                "ownership proof signing keys do not match this deployment".into(),
            ));
        }
        let now = current_timestamp();
        let root = inputs.active_root;
        let window = self.config.clearance_root_window_seconds;
        let known_root = root == self.current_root()
            || self
                .recent_roots
                .lock()
                .map(|roots| roots.contains(&root, now, window))
                .unwrap_or(false);
        let mut vault_root_read = None;
        if !known_root {
            let rejected = self
                .rejected_clearances
                .lock()
                .ok()
                .and_then(|rejected| rejected.lookup(&root, nullifier, now));
            // A replay is answered without a pairing check while the vault
            // root it was rejected against is still current (a cached read).
            if let Some(rejected_against) = rejected {
                let vault_root = self.cached_vault_root().await?;
                if vault_root == rejected_against {
                    return Err(ServerError::StaleRoot {
                        latest_root: vault_root.to_hex(),
                    });
                }
                vault_root_read = Some(vault_root);
            }
        }
        {
            let _permit =
                tokio::time::timeout(CLEARANCE_PERMIT_TIMEOUT, self.clearance_permits.acquire())
                    .await
                    .map_err(|_| ServerError::CapacityExhausted)?
                    .map_err(|_| ServerError::CapacityExhausted)?;
            // Generic errors: verifier details could echo request bytes.
            if !self
                .withdrawal_verifier
                .verify(inputs, &ownership.proof)
                .map_err(|_| ServerError::InvalidProof("ownership proof is malformed".into()))?
            {
                return Err(ServerError::InvalidProof(
                    "ownership proof failed verification".into(),
                ));
            }
        }
        if known_root {
            return Ok(());
        }
        // Only a verified proof reaches the vault, and the read is cached.
        let vault_root = match vault_root_read {
            Some(vault_root) => vault_root,
            None => self.cached_vault_root().await?,
        };
        if vault_root == root {
            self.observe_root(root, now);
            return Ok(());
        }
        if let Ok(mut rejected) = self.rejected_clearances.lock() {
            rejected.insert(root, *nullifier, vault_root, now.saturating_add(window));
        }
        Err(ServerError::StaleRoot {
            latest_root: vault_root.to_hex(),
        })
    }

    /// The vault's currentRoot(), read at most once per TTL; concurrent
    /// callers wait for the one in-flight read.
    async fn cached_vault_root(&self) -> Result<Felt252, ServerError> {
        let mut cached = self.vault_root_cache.lock().await;
        if let Some((read, read_at)) = cached.as_ref() {
            if read_at.elapsed() < self.timing.vault_root_ttl {
                // A failed read is cached too: an RPC outage costs at most one
                // read per TTL instead of a queue of slow reads.
                return read.clone().map_err(ServerError::Internal);
            }
        }
        let read = self
            .native_oracle
            .vault_current_root()
            .await
            .map_err(|error| match error {
                ServerError::Internal(message) => message,
                other => other.to_string(),
            });
        *cached = Some((read.clone(), Instant::now()));
        read.map_err(ServerError::Internal)
    }

    pub fn recover_by_client_id(
        &self,
        client_request_id: &str,
    ) -> Result<RecoveryResponseV2, ServerError> {
        Ok(self
            .store
            .lookup_by_client_id(client_request_id)
            .map(|record| self.recovery_from_record(&record))
            .unwrap_or_else(not_found_recovery))
    }

    pub fn recover_by_nullifier(
        &self,
        nullifier: &Felt252,
    ) -> Result<RecoveryResponseV2, ServerError> {
        Ok(self
            .store
            .lookup_by_nullifier(nullifier)
            .map(|record| self.recovery_from_record(&record))
            .unwrap_or_else(not_found_recovery))
    }

    fn recovery_from_record(&self, record: &TranscriptRecord) -> RecoveryResponseV2 {
        let mut recovery = recovery_from_record(record);
        if record.status == NullifierStatus::Reserved
            && record.reservation_kind == "openrouter_lease"
        {
            recovery.settlement_deadline = record
                .client_request_id
                .as_deref()
                .and_then(|id| self.store.lookup_openrouter_lease(id))
                .filter(|lease| lease.request_nullifier == record.nullifier)
                .and_then(|lease| self.pending_settlement_deadline(&lease, current_timestamp()));
        }
        recovery
    }

    /// Settlement health for the operator dashboard; never public.
    pub fn settlement_counts(&self) -> Result<SettlementCounts, ServerError> {
        self.store.settlement_counts(current_timestamp())
    }

    /// Pending leases and settlement reviews for the operator dashboard.
    pub fn settlement_overview(&self, limit: usize) -> Result<SettlementOverview, ServerError> {
        let now = current_timestamp();
        let pending = self
            .store
            .pending_openrouter_leases(limit)?
            .into_iter()
            .map(|lease| {
                let deadline = self.pending_settlement_deadline(&lease, now);
                PendingLeaseView {
                    client_request_id: lease.client_request_id,
                    request_nullifier: lease.request_nullifier,
                    key_source: lease.key_source,
                    status: lease.status,
                    delivered: lease.delivered,
                    expires_at: lease.expires_at,
                    settle_after: lease.settle_after,
                    settlement_deadline: deadline,
                    seconds_until_deadline: deadline.map(|deadline| deadline.saturating_sub(now)),
                    attempts: lease.settlement_attempts,
                    first_error_at: lease.first_error_at,
                    last_error: lease.last_error,
                }
            })
            .collect();
        let reviews = self
            .store
            .settlement_reviews(limit)?
            .into_iter()
            .map(|stored| SettlementReviewView {
                client_request_id: stored.review.client_request_id,
                request_nullifier: stored.review.request_nullifier,
                key_source: stored.review.key_source,
                reason: stored.review.reason,
                charge_basis: stored.review.charge_basis,
                detail: stored.review.detail,
                reported_usage_micro_usd: stored
                    .review
                    .reported_usage_micro_usd
                    .map(|value| value.to_string()),
                charge_applied: stored.review.charge_applied.map(|value| value.to_string()),
                solvency_bound: stored.review.solvency_bound.to_string(),
                created_at: stored.created_at,
                acknowledged_at: stored.acknowledged_at,
            })
            .collect();
        Ok(SettlementOverview {
            generated_at: now,
            settlement_deadline_seconds: self
                .config
                .openrouter_leases
                .as_ref()
                .map(|lease| lease.settlement_deadline_seconds),
            counts: self.store.settlement_counts(now)?,
            pending,
            reviews,
        })
    }

    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    pub fn store(&self) -> &Arc<NullifierStore> {
        &self.store
    }
}

fn response_from_record(
    record: &TranscriptRecord,
    client_request_id: &str,
) -> Result<RequestResponseV2, ServerError> {
    Ok(RequestResponseV2 {
        status: "ok".to_string(),
        client_request_id: client_request_id.to_string(),
        request_nullifier: record.nullifier,
        response_code: record.response_code.unwrap_or(200),
        response_payload: record.response_payload.clone().unwrap_or_default(),
        response_hash: record.response_hash.unwrap_or(Felt252::ZERO),
        charge_applied: record.charge_applied.unwrap_or(0),
        next_commitment: CurvePointWire {
            x: record.next_commitment_x.unwrap_or(Felt252::ZERO),
            y: record.next_commitment_y.unwrap_or(Felt252::ZERO),
        },
        next_anchor: record.next_anchor.unwrap_or(Felt252::ZERO),
        blind_delta_srv: record.blind_delta_srv.unwrap_or(Felt252::ZERO),
        next_state_signature: record
            .next_state_sig
            .ok_or_else(|| ServerError::Internal("stored response lacks signature".to_string()))?,
        policy_reason_code: record.policy_reason_code,
        policy_evidence_hash: record.policy_evidence_hash,
    })
}

fn recovery_from_record(record: &TranscriptRecord) -> RecoveryResponseV2 {
    let status = match record.status {
        NullifierStatus::Reserved => "reserved",
        NullifierStatus::Finalized => "finalized",
        NullifierStatus::ClearanceReserved => "clearance_reserved",
    };
    RecoveryResponseV2 {
        status: "ok".to_string(),
        nullifier_status: status.to_string(),
        request_response: (record.status == NullifierStatus::Finalized)
            .then(|| {
                response_from_record(record, record.client_request_id.as_deref().unwrap_or(""))
            })
            .transpose()
            .ok()
            .flatten(),
        settlement_deadline: None,
    }
}

fn not_found_recovery() -> RecoveryResponseV2 {
    RecoveryResponseV2 {
        status: "not_found".to_string(),
        nullifier_status: "unknown".to_string(),
        request_response: None,
        settlement_deadline: None,
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use zkapi_types::wire::{Groth16ProofWire, ProofBackendWire};
    use zkapi_types::RequestPublicInputsV2;

    use crate::config::OpenRouterLeaseConfig;

    fn setup_directory() -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../protocol/setup/v2")
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .to_string()
    }

    fn oa_lease_processor(store: Arc<NullifierStore>) -> RequestProcessor {
        let state_seed = Felt252::from_u64(11);
        let clear_seed = Felt252::from_u64(12);
        let signer = Arc::new(ServerSigner::new(&state_seed, &clear_seed));
        RequestProcessor::try_new(
            ServerConfig {
                request_charge_cap: 1,
                contract_address: Felt252::from_u64(1),
                native_billing: Some(crate::test_support::native_config()),
                proof_setup_dir: setup_directory(),
                openrouter_leases: Some(OpenRouterLeaseConfig {
                    source: OpenRouterLeaseSourceConfig::OaOrg {
                        // No request should reach this address in the mutation
                        // tests: the bound-retry check must reject first.
                        org_base_url: "http://127.0.0.1:9".to_string(),
                        shared_secret: "test-secret".to_string(),
                    },
                    ttl_seconds: 300,
                    settlement_grace_seconds: 0,
                    settlement_poll_seconds: 1,
                    // Lifecycle fixtures use 1970 timestamps; tests of the
                    // deadline set realistic times and their own deadline.
                    settlement_deadline_seconds: crate::test_support::TEST_DEADLINE_DISABLED,
                }),
                ..Default::default()
            },
            store,
            signer,
            Felt252::ZERO,
        )
        .unwrap()
    }

    fn unverified_lease_request(processor: &RequestProcessor) -> ApiRequestV2 {
        let payload = crate::test_support::lease_payload(&processor.config, current_timestamp());
        let state_key = processor.state_signing_key();
        ApiRequestV2 {
            client_request_id: "pre-oa-failure-request".to_string(),
            payload_hash: canonical_payload_hash(payload.as_bytes()),
            payload,
            public_inputs: RequestPublicInputsV2 {
                protocol_version: processor.config.protocol_version,
                chain_id: processor.config.chain_id,
                contract_address: processor.config.contract_address,
                active_root: Felt252::ZERO,
                state_signing_key_x: state_key.x,
                state_signing_key_y: state_key.y,
                request_time: current_timestamp(),
                solvency_bound: 3_000_000,
                request_nullifier: Felt252::from_u64(77),
                authorization_tag: Felt252::from_u64(78),
                anonymous_commitment_x: Felt252::from_u64(79),
                anonymous_commitment_y: Felt252::from_u64(80),
            },
            proof: Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: "original-proof-that-was-verified-before-reservation".to_string(),
            },
        }
    }

    fn mutated_request(
        request: &ApiRequestV2,
        mutate: impl FnOnce(&mut ApiRequestV2),
    ) -> ApiRequestV2 {
        let mut mutation = request.clone();
        mutate(&mut mutation);
        mutation
    }

    // These lifecycle tests start at the durable boundary immediately after
    // proof verification. Proof/circuit tests separately cover admission.
    fn reserved_request(processor: &RequestProcessor) -> ApiRequestV2 {
        let mut request = unverified_lease_request(processor);
        let commitment = zkapi_proof::compact::balance_commitment(
            3_000_000,
            &Felt252::from_u64(13),
            &Felt252::from_u64(14),
        );
        request.public_inputs.anonymous_commitment_x = commitment.x;
        request.public_inputs.anonymous_commitment_y = commitment.y;
        request.proof.proof = base64::engine::general_purpose::STANDARD.encode(b"verified-proof");
        processor.store.reserve_openrouter_lease(&request).unwrap();
        request
    }

    #[derive(Default)]
    struct IssuanceMock {
        spent: bool,
        consume_on_create: bool,
        fail_create: bool,
        policy_reject: bool,
        fail_rpc_after_create: bool,
        /// Fail every vault read (including the pre-provider spend check).
        fail_rpc: bool,
        creates: usize,
        provider_calls: usize,
        nullifier_reads: usize,
        /// A key an ambiguous create left behind under this request name.
        orphan_name: Option<String>,
        /// Key cleanup calls: "disable:<hash>" / "delete:<hash>".
        cleanup: Vec<String>,
    }

    type IssuanceMockState = Arc<std::sync::Mutex<IssuanceMock>>;

    async fn issuance_rpc(
        axum::extract::State(state): axum::extract::State<IssuanceMockState>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
        let mut state = state.lock().unwrap();
        if state.fail_rpc || (state.fail_rpc_after_create && state.creates > 0) {
            return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
        }
        let result = if body["method"] == "eth_chainId" {
            "0x1".to_string()
        } else {
            assert_eq!(body["method"], "eth_call");
            assert_eq!(body["params"][1], "latest");
            assert_eq!(
                body["params"][0]["to"],
                "0x0000000000000000000000000000000000000001"
            );
            let selector = Keccak256::digest(b"usedNullifiers(uint256)");
            let data = body["params"][0]["data"].as_str().unwrap_or_default();
            assert!(data.starts_with(&format!("0x{}", hex::encode(&selector[..4]))));
            assert_eq!(data.len(), 2 + 8 + 64);
            state.nullifier_reads += 1;
            format!("0x{:064x}", u8::from(state.spent))
        };
        Ok(axum::Json(
            serde_json::json!({"jsonrpc":"2.0","id":1,"result":result}),
        ))
    }

    fn configure_issuance_rpc(processor: &mut RequestProcessor, url: String) {
        let config = processor.config.native_billing.as_mut().unwrap();
        config.rpc_url = url;
        processor.native_oracle = NativeBillingOracle::new(
            config.clone(),
            processor.config.chain_id,
            "0x0000000000000000000000000000000000000001".into(),
        )
        .unwrap();
    }

    async fn unspent_rpc(processor: &mut RequestProcessor) -> tokio::task::JoinHandle<()> {
        let app = axum::Router::new()
            .route("/", axum::routing::post(issuance_rpc))
            .with_state(Arc::new(std::sync::Mutex::new(IssuanceMock::default())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        configure_issuance_rpc(
            processor,
            format!("http://{}", listener.local_addr().unwrap()),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() })
    }

    async fn issuance_processor(
        oa: bool,
        state: IssuanceMockState,
    ) -> (RequestProcessor, ApiRequestV2, tokio::task::JoinHandle<()>) {
        use axum::{
            extract::State,
            http::StatusCode,
            routing::{get, post},
            Json, Router,
        };
        use serde_json::{json, Value};
        async fn create(
            State(state): State<IssuanceMockState>,
            Json(body): Json<Value>,
        ) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
            let mut state = state.lock().unwrap();
            state.provider_calls += 1;
            state.creates += 1;
            if state.fail_create {
                state.fail_create = false;
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"detail":"unavailable"})),
                ));
            }
            if state.policy_reject {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"detail":"credit_limit exceeds zkAPI policy"})),
                ));
            }
            state.spent |= state.consume_on_create;
            let response = if body.get("credit_limit").is_some() {
                json!({"source":"oa_org", "key":"runtime-key", "key_hash":"test-hash",
                    "credit_limit":body["credit_limit"], "duration_minutes":body["duration_minutes"],
                    "expires_at_unix":current_timestamp()+300,
                    "station_id":"station", "station_recently_attested":true,
                    "station_signature":"ab".repeat(64), "org_signature":"cd".repeat(64),
                    "verifier_url":"https://verifier.example", "openrouter_api_base":"https://openrouter.ai/api/v1"})
            } else {
                json!({"key":"runtime-key", "data":{"hash":"test-hash", "name":body["name"],
                    "limit":body["limit"], "expires_at":body["expires_at"], "include_byok_in_limit":true}})
            };
            Ok(Json(response))
        }
        async fn list(
            State(state): State<IssuanceMockState>,
            axum::extract::Query(query): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >,
        ) -> Json<Value> {
            let mut state = state.lock().unwrap();
            state.provider_calls += 1;
            let first_page = query.get("offset").map(String::as_str) == Some("0");
            match state.orphan_name.clone() {
                Some(name) if first_page => Json(json!({"data":[
                    {"hash":"orphan-hash", "name":name},
                    {"hash":"unrelated-hash", "name":"zkapi-unrelated"}
                ]})),
                _ => Json(json!({"data":[]})),
            }
        }
        async fn cleanup(
            State(state): State<IssuanceMockState>,
            method: axum::http::Method,
            axum::extract::Path(hash): axum::extract::Path<String>,
        ) -> (StatusCode, Json<Value>) {
            let mut state = state.lock().unwrap();
            state.provider_calls += 1;
            let verb = if method == axum::http::Method::PATCH {
                "disable"
            } else {
                "delete"
            };
            state.cleanup.push(format!("{verb}:{hash}"));
            if verb == "disable" {
                (StatusCode::OK, Json(json!({"data":{"disabled":true}})))
            } else {
                (StatusCode::OK, Json(json!({"deleted":true})))
            }
        }
        let app = Router::new()
            .route("/rpc", post(issuance_rpc))
            .route("/v1/keys", get(list).post(create))
            .route(
                "/v1/keys/{hash}",
                axum::routing::patch(cleanup).delete(cleanup),
            )
            .route("/api/zkapi/request_key", post(create))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        configure_issuance_rpc(&mut processor, format!("{url}/rpc"));
        if oa {
            processor.oa_org = Some(Arc::new(
                OaOrgProvisioner::new(url, "test-secret".into()).unwrap(),
            ));
        } else {
            processor.config.openrouter_leases.as_mut().unwrap().source =
                OpenRouterLeaseSourceConfig::OpenRouter {
                    management_key: "test-secret".into(),
                    api_base: url.clone(),
                };
            processor.openrouter = Some(Arc::new(
                OpenRouterProvisioner::new("test-secret".into(), url).unwrap(),
            ));
            processor.oa_org = None;
        }
        // Resume at the durable verified boundary, with a frozen quote and
        // request that have aged out. The admission proof tests are separate.
        let mut request = unverified_lease_request(&processor);
        let commitment = zkapi_proof::compact::balance_commitment(
            3_000_000,
            &Felt252::from_u64(13),
            &Felt252::from_u64(14),
        );
        request.public_inputs.anonymous_commitment_x = commitment.x;
        request.public_inputs.anonymous_commitment_y = commitment.y;
        request.payload = crate::test_support::lease_payload(&processor.config, 100);
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.request_time = 100;
        request.proof.proof = base64::engine::general_purpose::STANDARD.encode(b"verified-proof");
        store.reserve_openrouter_lease(&request).unwrap();
        let id = oa.then(|| RequestProcessor::native_oa_request_id(&request).unwrap());
        store
            .create_openrouter_lease_with_oa_id(
                &request,
                if oa { "oa_org" } else { "openrouter" },
                100,
                400,
                400,
                3.0,
                id.as_deref(),
            )
            .unwrap();
        (processor, request, server)
    }

    /// A lease whose upstream issuance outcome is unknown was never returned
    /// to the client: activation precedes delivery. It settles at zero with no
    /// provider reads, instead of waiting forever for issuer evidence.
    #[tokio::test]
    async fn expired_unconfirmed_provisioning_finalizes_at_zero_without_provider_calls() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        processor
            .store
            .begin_oa_issuance(&request.client_request_id)
            .unwrap();
        let before = state.lock().unwrap().provider_calls;
        processor.settle_due_openrouter_leases().await;
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "finalized");
        assert_eq!(lease.charge_applied, Some(0));
        assert_eq!(lease.charge_basis.as_deref(), Some("unissued"));
        assert!(lease.key_hash.is_none());
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        let payload: serde_json::Value =
            serde_json::from_str(record.response_payload.as_deref().unwrap()).unwrap();
        assert_eq!(payload["type"], "oa_org_unissued_lease_cancellation");
        assert_eq!(payload["charge_basis"], "unissued");
        assert_eq!(payload["reason"], "issuance_not_completed");
        assert_eq!(payload["issued"], false);
        assert_eq!(
            payload["billing_quote"],
            serde_json::from_str::<serde_json::Value>(&request.payload).unwrap()["billing_quote"]
        );
        {
            let state = state.lock().unwrap();
            assert_eq!(
                state.provider_calls, before,
                "no reconciliation or usage read"
            );
            assert_eq!(state.creates, 0);
        }
        // An exact retry recovers the signed zero-charge response, never a key.
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Replay)
        ));
        assert_eq!(
            processor
                .retire_openrouter_lease(&request.client_request_id, &request)
                .await
                .unwrap()
                .status,
            "finalized"
        );
        assert_eq!(state.lock().unwrap().creates, 0);
        server.abort();
    }

    #[tokio::test]
    async fn ambiguous_unissued_lease_retires_at_zero_without_reissuing() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        processor
            .store
            .begin_oa_issuance(&request.client_request_id)
            .unwrap();
        let status = processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(status.status, "finalized");
        assert_eq!(status.charge_basis.as_deref(), Some("unissued"));
        assert_eq!(status.settlement_deadline, None);
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .next_state_sig,
            record.next_state_sig
        );
        assert_eq!(state.lock().unwrap().creates, 0);
        server.abort();
    }

    #[tokio::test]
    async fn definitive_first_rejection_finalizes_zero_charge_and_never_reissues() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            policy_reject: true,
            ..Default::default()
        }));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::OaKeyPolicyRejected)
        ));
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        let payload: serde_json::Value =
            serde_json::from_str(record.response_payload.as_ref().unwrap()).unwrap();
        assert_eq!(payload["type"], "oa_org_unissued_lease_cancellation");
        assert_eq!(payload["issued"], false);
        assert_eq!(
            payload["billing_quote"],
            serde_json::from_str::<serde_json::Value>(&request.payload).unwrap()["billing_quote"]
        );
        assert_eq!(
            processor
                .openrouter_lease_status(&request.client_request_id)
                .unwrap()
                .status,
            "finalized"
        );
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Replay)
        ));
        processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        processor.settle_due_openrouter_leases().await;
        let again = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(again.next_state_sig, record.next_state_sig);
        assert_eq!(state.lock().unwrap().creates, 1);
        server.abort();
    }

    #[tokio::test]
    async fn later_policy_rejection_cannot_erase_earlier_issuance_uncertainty() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            fail_create: true,
            policy_reject: true,
            ..Default::default()
        }));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Internal(_))
        ));
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::OaKeyPolicyRejected)
        ));
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        assert_eq!(lease.status, "provisioning");
        assert!(lease.last_error.is_some());
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .status,
            NullifierStatus::Reserved
        );
        // The key was never returned, whatever the issuer did: zero, and the
        // record keeps the earlier uncertainty rather than a confirmed rejection.
        processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        let payload: serde_json::Value =
            serde_json::from_str(record.response_payload.as_deref().unwrap()).unwrap();
        assert_eq!(payload["reason"], "issuance_not_completed");
        assert_eq!(state.lock().unwrap().creates, 2);
        server.abort();
    }

    #[tokio::test]
    async fn confirmed_rejection_finalizes_at_zero_without_chain_reads_and_recovers_after_crash() {
        // Zero-charge successors need no chain read: an unavailable RPC after
        // the rejection does not block finalization.
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            policy_reject: true,
            fail_rpc_after_create: true,
            ..Default::default()
        }));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::OaKeyPolicyRejected)
        ));
        let reads = state.lock().unwrap().nullifier_reads;
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
        assert_eq!(lease.status, "finalized");
        assert_eq!(lease.charge_basis.as_deref(), Some("unissued"));
        assert_eq!(state.lock().unwrap().creates, 1);
        server.abort();

        // A crash between the confirmed rejection and its finalization is
        // recovered by the background settler.
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        assert!(processor
            .store
            .begin_oa_issuance(&request.client_request_id)
            .unwrap());
        processor
            .store
            .confirm_oa_unissued(&request.client_request_id)
            .unwrap();
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .openrouter_lease_status(&request.client_request_id)
                .unwrap()
                .status,
            "finalized"
        );
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.charge_applied, Some(0));
        let payload: serde_json::Value =
            serde_json::from_str(record.response_payload.as_deref().unwrap()).unwrap();
        assert_eq!(payload["reason"], "issuer_policy_rejected");
        let state = state.lock().unwrap();
        assert_eq!(state.creates, 0);
        assert_eq!(state.nullifier_reads, 0);
        assert!(reads >= 1);
        server.abort();
    }

    #[tokio::test]
    async fn unstarted_retirement_preserves_exact_binding_and_waits_for_issuance_lock() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        let mut changed = request.clone();
        changed.proof.proof.push('x');
        assert!(matches!(
            processor
                .retire_openrouter_lease(&request.client_request_id, &changed)
                .await,
            Err(ServerError::InvalidRequest(_))
        ));
        let guard = processor.lease_issue_lock.lock().await;
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            processor.retire_openrouter_lease(&request.client_request_id, &request)
        )
        .await
        .is_err());
        drop(guard);
        processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(
            processor
                .openrouter_lease_status(&request.client_request_id)
                .unwrap()
                .status,
            "finalized"
        );
        assert_eq!(state.lock().unwrap().creates, 0);
        server.abort();
    }

    #[tokio::test]
    async fn cancellation_reconciles_existing_signed_transcript_after_crash() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        assert!(processor
            .store
            .begin_oa_issuance(&request.client_request_id)
            .unwrap());
        processor
            .store
            .confirm_oa_unissued(&request.client_request_id)
            .unwrap();
        let signed = processor.finalize_request(&request, SettlementResult {
            status_code: 200,
            payload: processor.settlement_payload(&request, serde_json::json!({
                "type":"oa_org_unissued_lease_cancellation", "issued":false, "usage_credits":0
            })).unwrap(),
            charge_applied: 0, usage: None, billing_label: "test".into(),
        }, 0, 0).unwrap();
        processor.settle_due_openrouter_leases().await;
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.next_state_sig, Some(signed.next_state_signature));
        assert_eq!(
            processor
                .openrouter_lease_status(&request.client_request_id)
                .unwrap()
                .status,
            "finalized"
        );
        assert_eq!(state.lock().unwrap().creates, 0);
        server.abort();
    }

    #[tokio::test]
    async fn stalled_active_usage_does_not_block_new_issuance() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (mut processor, request, rpc_server) = issuance_processor(true, state).await;
        processor
            .store
            .activate_openrouter_lease(&request.client_request_id, "issued-hash")
            .unwrap();
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let started_handler = started.clone();
        let release_handler = release.clone();
        let app = axum::Router::new().route(
            "/api/zkapi/key_usage",
            axum::routing::post(move || {
                let started = started_handler.clone();
                let release = release_handler.clone();
                async move {
                    started.notify_one();
                    release.notified().await;
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(
                format!("http://{}", listener.local_addr().unwrap()),
                "test-secret".into(),
            )
            .unwrap(),
        ));
        let usage_server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let processor = Arc::new(processor);
        let scanning = processor.clone();
        let scan = tokio::spawn(async move {
            scanning.settle_due_openrouter_leases().await;
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        let guard = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            processor.lease_issue_lock.lock(),
        )
        .await
        .expect("active usage blocked issuance");
        drop(guard);
        release.notify_one();
        scan.await.unwrap();
        rpc_server.abort();
        usage_server.abort();
    }

    #[tokio::test]
    async fn failed_issuance_cannot_retry_after_withdrawal_consumes_its_nullifier() {
        for oa in [false, true] {
            let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
                fail_create: true,
                ..Default::default()
            }));
            let (processor, request, server) = issuance_processor(oa, state.clone()).await;
            assert!(matches!(
                processor.issue_openrouter_lease(&request).await,
                Err(ServerError::Internal(_))
            ));
            // The failed attempt leaves a settleable provisioning row (it is
            // never delivered and settles at zero), not a bare reservation.
            let lease = processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap();
            assert_eq!(lease.status, "provisioning");
            assert!(lease.last_error.is_some());
            let provider_calls = {
                let mut state = state.lock().unwrap();
                assert_eq!(state.creates, 1);
                state.spent = true;
                state.provider_calls
            };
            assert!(matches!(
                processor.issue_openrouter_lease(&request).await,
                Err(ServerError::NullifierUsed)
            ));
            assert_eq!(state.lock().unwrap().provider_calls, provider_calls);
            let reserved = processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap();
            assert_eq!(reserved.status, NullifierStatus::Reserved);
            assert_eq!(
                reserved.api_request_binding.as_deref(),
                Some(api_request_binding(&request).unwrap().as_str())
            );
            assert!(
                crate::watcher::ChallengeWatcher::new(processor.store.clone())
                    .challenge_transcript(&request.public_inputs.request_nullifier)
                    .is_none()
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn collateral_change_during_issuance_never_exposes_key_and_awaits_settlement_evidence() {
        for oa in [false, true] {
            for rpc_failure in [false, true] {
                let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
                    consume_on_create: !rpc_failure,
                    fail_rpc_after_create: rpc_failure,
                    ..Default::default()
                }));
                let (processor, request, server) = issuance_processor(oa, state.clone()).await;
                let result = processor.issue_openrouter_lease(&request).await;
                if rpc_failure {
                    assert!(matches!(result, Err(ServerError::Internal(_))));
                } else {
                    assert!(matches!(result, Err(ServerError::NullifierUsed)));
                }
                assert_eq!(state.lock().unwrap().creates, 1);
                let lease = processor
                    .store
                    .lookup_openrouter_lease(&request.client_request_id)
                    .unwrap();
                assert_eq!(lease.status, "active");
                assert_eq!(lease.key_hash.as_deref(), Some("test-hash"));
                assert_eq!(
                    api_request_binding(&lease.api_request).unwrap(),
                    api_request_binding(&request).unwrap()
                );
                // An issued but unsettled lease is not challenge evidence; the
                // retained active row lets bounded settlement finalize it.
                let watcher = crate::watcher::ChallengeWatcher::new(processor.store.clone());
                let nullifier = request.public_inputs.request_nullifier;
                assert!(watcher.challenge_transcript(&nullifier).is_none());
                assert!(matches!(
                    watcher.evidence_status(&nullifier),
                    Ok(crate::watcher::EvidenceStatus::AwaitingSettlement(progress))
                        if progress.lease_status.as_deref() == Some("active") && progress.key_issued
                ));
                // Recovery of already activated access needs no fresh chain
                // read and cannot repeat provider issuance after either error.
                assert!(matches!(
                    processor.issue_openrouter_lease(&request).await,
                    Err(ServerError::LeasePending)
                ));
                assert_eq!(state.lock().unwrap().creates, 1);
                server.abort();
            }
        }
    }

    #[tokio::test]
    async fn unspent_reserved_retry_keeps_frozen_quote_after_unrelated_root_change() {
        for oa in [false, true] {
            let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
            let (processor, request, server) = issuance_processor(oa, state.clone()).await;
            processor.update_root(Felt252::from_u64(999));
            let quote = processor.lease_authorization(&request).unwrap().1;
            assert!(quote.expires_at < current_timestamp());
            let issued = processor.issue_openrouter_lease(&request).await.unwrap();
            assert_eq!(issued.lease.api_key, "runtime-key");
            assert_eq!(issued.billing_quote, quote);
            assert_eq!(issued.lease.spending_limit_usd, 3.0);
            let state = state.lock().unwrap();
            assert_eq!(state.creates, 1);
            assert_eq!(state.nullifier_reads, 2);
            server.abort();
        }
    }

    #[derive(Default)]
    struct RetirementMock {
        disabled: bool,
        deleted: bool,
        fail_disable: bool,
        fail_delete: bool,
        lose_delete_response: bool,
        fail_usage: bool,
        /// Every usage read fails (a provider outage).
        usage_unavailable: bool,
        /// Every deletion fails.
        delete_unavailable: bool,
        /// The provider keeps reporting the key as enabled.
        report_enabled: bool,
        usage: f64,
        events: Vec<&'static str>,
    }

    async fn retirement_processor(
        state: Arc<std::sync::Mutex<RetirementMock>>,
        grace: u64,
        database_path: Option<&std::path::Path>,
    ) -> (RequestProcessor, ApiRequestV2, tokio::task::JoinHandle<()>) {
        use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
        type MockState = Arc<std::sync::Mutex<RetirementMock>>;
        async fn disable(
            State(state): State<MockState>,
            Json(body): Json<serde_json::Value>,
        ) -> Result<Json<serde_json::Value>, StatusCode> {
            assert_eq!(body["disabled"], true);
            let mut state = state.lock().unwrap();
            state.events.push("disable");
            if state.fail_disable {
                state.fail_disable = false;
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            state.disabled = true;
            Ok(Json(serde_json::json!({"data": {"disabled": true}})))
        }
        async fn usage(
            State(state): State<MockState>,
        ) -> Result<Json<serde_json::Value>, StatusCode> {
            let mut state = state.lock().unwrap();
            state.events.push("usage");
            assert!(state.disabled, "usage must be read after spending stops");
            assert!(!state.deleted, "usage is unavailable after deletion");
            if state.fail_usage || state.usage_unavailable {
                state.fail_usage = false;
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            let disabled = state.disabled && !state.report_enabled;
            Ok(Json(
                serde_json::json!({"data": {"disabled": disabled, "usage": state.usage, "byok_usage": 0.0}}),
            ))
        }
        async fn delete(State(state): State<MockState>) -> StatusCode {
            let mut state = state.lock().unwrap();
            state.events.push("delete");
            assert!(state.disabled);
            if state.delete_unavailable {
                return StatusCode::SERVICE_UNAVAILABLE;
            }
            if state.fail_delete {
                state.fail_delete = false;
                state.deleted = state.lose_delete_response;
                return StatusCode::SERVICE_UNAVAILABLE;
            }
            if state.deleted {
                return StatusCode::NOT_FOUND;
            }
            state.deleted = true;
            StatusCode::NO_CONTENT
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route("/v1/keys/{hash}", get(usage).patch(disable).delete(delete))
            .with_state(state);
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let store = Arc::new(match database_path {
            Some(path) => NullifierStore::new(path).unwrap(),
            None => NullifierStore::in_memory().unwrap(),
        });
        let mut processor = oa_lease_processor(store.clone());
        let config = processor.config.openrouter_leases.as_mut().unwrap();
        config.source = OpenRouterLeaseSourceConfig::OpenRouter {
            management_key: "test".to_string(),
            api_base: url.clone(),
        };
        config.settlement_grace_seconds = grace;
        processor.openrouter = Some(Arc::new(
            OpenRouterProvisioner::new("test".to_string(), url).unwrap(),
        ));
        processor.oa_org = None;
        let request = reserved_request(&processor);
        let now = current_timestamp();
        store
            .create_openrouter_lease(
                &request,
                "openrouter",
                now,
                now + 300,
                now + 300 + grace,
                3.0,
            )
            .unwrap();
        store
            .activate_openrouter_lease(&request.client_request_id, "test-hash")
            .unwrap();
        (processor, request, server)
    }

    #[tokio::test]
    async fn failed_key_deletion_never_signs_and_background_retry_recovers() {
        for lose_delete_response in [false, true] {
            let state = Arc::new(std::sync::Mutex::new(RetirementMock {
                usage: 0.000002,
                fail_delete: true,
                lose_delete_response,
                ..Default::default()
            }));
            let db_path =
                std::env::temp_dir().join(format!("zkapi-retirement-{}.db", uuid::Uuid::new_v4()));
            let (processor, request, server) =
                retirement_processor(state.clone(), 0, Some(&db_path)).await;
            assert!(processor
                .retire_openrouter_lease(&request.client_request_id, &request)
                .await
                .is_err());
            let store = &processor.store;
            assert_eq!(
                store
                    .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                    .unwrap()
                    .status,
                NullifierStatus::Reserved
            );
            let lease = store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap();
            assert_eq!(lease.status, "revoking");
            assert_eq!(lease.usage_usd, Some(0.000002));
            assert!(lease.last_error.is_some());
            assert_eq!(store.due_openrouter_leases(current_timestamp()).len(), 1);
            assert!(state.lock().unwrap().disabled);
            assert_eq!(state.lock().unwrap().deleted, lose_delete_response);
            // Reopen SQLite with a fresh processor: both a still-existing key
            // and a lost successful DELETE must resume from durable usage.
            let config = processor.config.clone();
            let signer = processor.signer.clone();
            drop(processor);
            let store = Arc::new(NullifierStore::new(&db_path).unwrap());
            let processor =
                RequestProcessor::try_new(config, store.clone(), signer, Felt252::ZERO).unwrap();
            processor.settle_due_openrouter_leases().await;
            let response = processor
                .retire_openrouter_lease(&request.client_request_id, &request)
                .await
                .unwrap();
            assert_eq!(response.status, "finalized");
            assert_eq!(
                store
                    .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                    .unwrap()
                    .charge_applied,
                Some(2)
            );
            assert_eq!(
                state.lock().unwrap().events,
                ["disable", "usage", "delete", "delete"]
            );
            server.abort();
            drop(processor);
            drop(store);
            std::fs::remove_file(db_path).unwrap();
        }
    }

    #[tokio::test]
    async fn retirement_disable_and_usage_failures_remain_retryable() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage: 0.000003,
            fail_disable: true,
            fail_usage: true,
            ..Default::default()
        }));
        let (processor, request, server) = retirement_processor(state.clone(), 0, None).await;
        assert!(processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .is_err());
        assert_eq!(
            processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap()
                .status,
            "retiring"
        );
        assert!(!state.lock().unwrap().disabled);
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap()
                .status,
            "disabled"
        );
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .status,
            NullifierStatus::Reserved
        );
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap()
                .status,
            "finalized"
        );
        assert_eq!(
            state.lock().unwrap().events,
            ["disable", "disable", "usage", "usage", "delete"]
        );
        server.abort();
    }

    #[tokio::test]
    async fn early_retirement_waits_for_usage_reconciliation_after_disabling() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock::default()));
        let (processor, request, server) = retirement_processor(state.clone(), 60, None).await;
        assert!(matches!(
            processor
                .retire_openrouter_lease(&request.client_request_id, &request)
                .await,
            Err(ServerError::LeaseSettlementPending { .. })
        ));
        assert_eq!(state.lock().unwrap().events, ["disable"]);
        assert!(processor
            .store
            .due_openrouter_leases(current_timestamp())
            .is_empty());
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .status,
            NullifierStatus::Reserved
        );
        // Simulate delayed billing becoming visible during the drain interval.
        state.lock().unwrap().usage = 0.000005;
        processor
            .store
            .advance_openrouter_retirement(
                &request.client_request_id,
                "disabled",
                "disabled",
                0,
                None,
            )
            .unwrap();
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .charge_applied,
            Some(5)
        );
        assert_eq!(state.lock().unwrap().events, ["disable", "usage", "delete"]);
        server.abort();
    }

    #[test]
    fn removed_proof_backends_are_rejected_on_the_wire() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let mut request = serde_json::to_value(unverified_lease_request(&processor)).unwrap();
        request["proof"]["backend"] = "stwo_cairo".into();
        assert!(serde_json::from_value::<ApiRequestV2>(request).is_err());
    }

    #[tokio::test]
    async fn pre_oa_failure_rejects_every_mutated_reserved_retry() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let processor = oa_lease_processor(store.clone());
        let request = unverified_lease_request(&processor);
        let original_limit =
            pricing::micro_usd_to_usd(processor.lease_limit_micro_usd(&request).unwrap());

        // This is the durable state left after proof verification and lease
        // reservation but before OA successfully returns a key.
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease(&request, "oa_org", 100, 400, 400, original_limit)
            .unwrap();

        // A byte-identical transport retry remains resumable even though its
        // proof is not verified a second time.
        assert!(processor.validate_and_reserve(&request).unwrap().is_none());

        let changed_payload = format!(" {}", request.payload);
        let binding_replay_mutations = vec![
            (
                "client_request_id",
                mutated_request(&request, |value| {
                    value.client_request_id = "different-request-id".to_string()
                }),
            ),
            (
                "payload_and_payload_hash",
                mutated_request(&request, |value| {
                    value.payload = changed_payload.to_string();
                    value.payload_hash = canonical_payload_hash(changed_payload.as_bytes());
                }),
            ),
            (
                "active_root",
                mutated_request(&request, |value| {
                    value.public_inputs.active_root = Felt252::from_u64(901)
                }),
            ),
            (
                "state_signing_key_x",
                mutated_request(&request, |value| {
                    value.public_inputs.state_signing_key_x = Felt252::from_u64(902)
                }),
            ),
            (
                "state_signing_key_y",
                mutated_request(&request, |value| {
                    value.public_inputs.state_signing_key_y = Felt252::from_u64(903)
                }),
            ),
            (
                "request_time",
                mutated_request(&request, |value| value.public_inputs.request_time = 1),
            ),
            (
                "solvency_bound",
                mutated_request(&request, |value| {
                    value.public_inputs.solvency_bound = u128::MAX
                }),
            ),
            (
                "authorization_tag",
                mutated_request(&request, |value| {
                    value.public_inputs.authorization_tag = Felt252::from_u64(904)
                }),
            ),
            (
                "anonymous_commitment_x",
                mutated_request(&request, |value| {
                    value.public_inputs.anonymous_commitment_x = Felt252::from_u64(905)
                }),
            ),
            (
                "anonymous_commitment_y",
                mutated_request(&request, |value| {
                    value.public_inputs.anonymous_commitment_y = Felt252::from_u64(906)
                }),
            ),
            (
                "proof_string",
                mutated_request(&request, |value| {
                    value.proof.proof = "garbage-not-a-proof".to_string()
                }),
            ),
        ];
        let original_binding = api_request_binding(&request).unwrap();
        for (field, mutation) in binding_replay_mutations {
            assert_ne!(
                api_request_binding(&mutation).unwrap(),
                original_binding,
                "{field} was not covered by the complete request binding"
            );
            let result = processor.issue_openrouter_lease(&mutation).await;
            assert!(
                matches!(
                    &result,
                    Err(ServerError::Replay | ServerError::InvalidRequest(_))
                ),
                "reserved retry mutation in {field} was not rejected: {}",
                result
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "unexpected success".to_string())
            );
        }

        for (field, mutation) in [
            (
                "protocol_version",
                mutated_request(&request, |value| value.public_inputs.protocol_version += 1),
            ),
            (
                "chain_id",
                mutated_request(&request, |value| value.public_inputs.chain_id += 1),
            ),
            (
                "contract_address",
                mutated_request(&request, |value| {
                    value.public_inputs.contract_address = Felt252::from_u64(907)
                }),
            ),
        ] {
            assert_ne!(api_request_binding(&mutation).unwrap(), original_binding);
            let error = processor
                .issue_openrouter_lease(&mutation)
                .await
                .err()
                .unwrap_or_else(|| panic!("{field} mutation unexpectedly succeeded"));
            assert!(
                matches!(
                    &error,
                    ServerError::ProtocolMismatch(_) | ServerError::Replay
                ),
                "{field} mutation returned {error}"
            );
        }

        let payload_only = mutated_request(&request, |value| {
            value.payload = changed_payload.to_string()
        });
        let payload_hash_only = mutated_request(&request, |value| {
            value.payload_hash = Felt252::from_u64(908)
        });
        for (field, mutation) in [
            ("payload", payload_only),
            ("payload_hash", payload_hash_only),
        ] {
            assert_ne!(api_request_binding(&mutation).unwrap(), original_binding);
            let error = processor
                .issue_openrouter_lease(&mutation)
                .await
                .err()
                .unwrap_or_else(|| panic!("{field} mutation unexpectedly succeeded"));
            assert!(
                matches!(&error, ServerError::InvalidRequest(_) | ServerError::Replay),
                "{field} mutation returned {error}"
            );
        }

        let changed_nullifier = mutated_request(&request, |value| {
            value.public_inputs.request_nullifier = Felt252::from_u64(909)
        });
        assert_ne!(
            api_request_binding(&changed_nullifier).unwrap(),
            original_binding
        );
        let error = processor
            .issue_openrouter_lease(&changed_nullifier)
            .await
            .err()
            .expect("request_nullifier mutation unexpectedly succeeded");
        assert!(
            matches!(&error, ServerError::Replay),
            "request_nullifier mutation returned {error}"
        );

        let lease = store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(
            lease.api_request.public_inputs.solvency_bound,
            request.public_inputs.solvency_bound
        );
        assert_eq!(lease.spending_limit_usd.to_bits(), original_limit.to_bits());
        assert_eq!(lease.status, "provisioning");
        assert!(lease.key_hash.is_none());
    }
    #[test]
    fn native_oa_namespace_is_deployment_and_full_request_bound_and_persisted() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        let request = unverified_lease_request(&processor);
        let id = RequestProcessor::native_oa_request_id(&request).unwrap();
        assert_eq!(
            id,
            RequestProcessor::native_oa_request_id(&request.clone()).unwrap()
        );
        assert_eq!(id.len(), 73);
        for mutate in [
            (|r: &mut ApiRequestV2| r.public_inputs.chain_id += 1) as fn(&mut ApiRequestV2),
            |r| r.public_inputs.contract_address = Felt252::from_u64(999),
            |r| r.public_inputs.request_nullifier = Felt252::from_u64(998),
            |r| r.proof.proof.push('x'),
            |r| r.client_request_id.push('x'),
        ] {
            let mut different = request.clone();
            mutate(&mut different);
            assert_ne!(
                id,
                RequestProcessor::native_oa_request_id(&different).unwrap()
            );
        }
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease_with_oa_id(&request, "oa_org", 1, 2, 3, 1.0, Some(&id))
            .unwrap();
        let saved = store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(saved.oa_client_request_id.as_deref(), Some(id.as_str()));
        assert_eq!(saved.client_request_id, request.client_request_id);
        assert_eq!(processor.persisted_oa_request_id(&saved).unwrap(), id);
        processor.config.native_billing = Some(crate::native_billing::NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 4500,
        });
        assert_eq!(processor.persisted_oa_request_id(&saved).unwrap(), id);
        let mut corrupted = saved.clone();
        corrupted.oa_client_request_id = None;
        assert!(processor.persisted_oa_request_id(&corrupted).is_err());
        corrupted.oa_client_request_id = Some("different-deployment".into());
        assert!(processor.persisted_oa_request_id(&corrupted).is_err());
    }

    #[tokio::test]
    async fn native_oa_issuance_and_usage_use_same_persisted_upstream_namespace() {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let issuance_seen = seen.clone();
        let usage_seen = seen.clone();
        let now = current_timestamp();
        let app = Router::new()
            .route("/api/zkapi/request_key", post(move |Json(body): Json<Value>| {
                let seen = issuance_seen.clone();
                async move {
                    seen.lock().unwrap().push(body["client_request_id"].as_str().unwrap().into());
                    Json(json!({"source":"oa_org", "key":"runtime-key", "key_hash":"key-hash",
                        "credit_limit":1.0, "duration_minutes":5, "expires_at_unix":now+300,
                        "station_id":"station", "station_recently_attested":true,
                        "station_signature":"ab".repeat(64), "org_signature":"cd".repeat(64),
                        "verifier_url":"https://verifier.example", "openrouter_api_base":"https://openrouter.ai/api/v1"}))
                }
            }))
            .route("/api/zkapi/key_usage", post(move |Json(body): Json<Value>| {
                let seen = usage_seen.clone();
                async move {
                    seen.lock().unwrap().push(body["client_request_id"].as_str().unwrap().into());
                    Json(json!({"source":"oa_org", "version":1, "status":"pending",
                        "client_request_id":body["client_request_id"], "key_hash":"key-hash",
                        "station_request_id":"ab".repeat(32), "retry_after_seconds":1}))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(url, "test-secret".into()).unwrap(),
        ));
        processor.config.native_billing = Some(crate::native_billing::NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 4500,
        });
        let chain_server = unspent_rpc(&mut processor).await;
        let mut request = unverified_lease_request(&processor);
        request.payload = json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":{
            "asset":"native_eth","units_per_eth":1_000_000_000,"chain_id":1,
            "feed_address":"0x694aa1769357215de4fac081bf1f309adc325306","round_id":"123",
            "answer":"250000000000","decimals":8,"updated_at":now,"expires_at":now+4500
        }})
        .to_string();
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.solvency_bound = 400_000;
        let id = RequestProcessor::native_oa_request_id(&request).unwrap();
        // Resume at the already-verified durable boundary, avoiding mock proofs
        // at admission; the real-proof tests separately cover that boundary.
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease_with_oa_id(
                &request,
                "oa_org",
                now,
                now + 300,
                now + 300,
                1.0,
                Some(&id),
            )
            .unwrap();
        let issued = processor.issue_openrouter_lease(&request).await.unwrap();
        assert_eq!(issued.lease.client_request_id, request.client_request_id);
        let saved = store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert!(matches!(
            processor.settle_oa_org_lease(&saved).await,
            Err(ServerError::LeaseSettlementPending { .. })
        ));
        assert_eq!(*seen.lock().unwrap(), vec![id.clone(), id]);
        assert_eq!(
            store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap()
                .status,
            "active"
        );
        server.abort();
        chain_server.abort();
    }

    #[tokio::test]
    async fn native_lease_persists_frozen_quote_and_rejects_missing_or_changed_quotes() {
        use crate::native_billing::NativeBillingConfig;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        processor.config.contract_address = Felt252::from_u64(1);
        let config = NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 3600,
        };
        processor.config.native_billing = Some(config.clone());
        processor.native_oracle = NativeBillingOracle::new(
            config,
            1,
            "0x0000000000000000000000000000000000000001".into(),
        )
        .unwrap();
        let chain_server = unspent_rpc(&mut processor).await;
        let mut request = unverified_lease_request(&processor);
        request.payload = serde_json::to_string(&OpenRouterLeaseAuthorization::default()).unwrap();
        assert!(processor.lease_authorization(&request).is_err());
        let quote = NativeBillingQuote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: 1,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            round_id: "123".into(),
            answer: "250000000000".into(),
            decimals: 8,
            updated_at: 100,
            expires_at: 3700,
        };
        request.payload = serde_json::json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote}).to_string();
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.solvency_bound = 400_000;
        assert_eq!(
            processor.lease_limit_micro_usd(&request).unwrap(),
            1_000_000
        );
        assert_eq!(
            processor.lease_charge_units(&request, 123_456).unwrap(),
            49_383
        );
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::NativeQuoteExpired)
        ));
        assert!(store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        let expired = processor
            .expire_unaccepted_native_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(expired["status"], "expired_unaccepted");
        assert_eq!(
            expired["payload_hash"],
            serde_json::to_value(request.payload_hash).unwrap()
        );
        assert_eq!(
            expired["request_nullifier"],
            serde_json::to_value(request.public_inputs.request_nullifier).unwrap()
        );
        assert!(store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        // An expiry check must wait behind in-flight issuance. Simulate that
        // issuer accepting the request before it releases the shared lock.
        let issuance_guard = processor.lease_issue_lock.lock().await;
        let expiry_check =
            processor.expire_unaccepted_native_lease(&request.client_request_id, &request);
        tokio::pin!(expiry_check);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut expiry_check)
                .await
                .is_err()
        );
        store.reserve_openrouter_lease(&request).unwrap();
        drop(issuance_guard);
        assert!(matches!(expiry_check.await, Err(ServerError::LeasePending)));
        store
            .create_openrouter_lease_with_oa_id(
                &request,
                "oa_org",
                100,
                400,
                400,
                1.0,
                Some(&RequestProcessor::native_oa_request_id(&request).unwrap()),
            )
            .unwrap();
        let restored = store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(
            processor
                .lease_authorization(&restored.api_request)
                .unwrap()
                .1,
            quote.clone()
        );
        // Retry must reach the unavailable issuer, not fetch/reprice an expired
        // round. This confirms that a restarted lease uses its persisted quote.
        let error = processor
            .issue_openrouter_lease(&restored.api_request)
            .await
            .err()
            .unwrap();
        assert!(
            !error.to_string().contains("stale") && !error.to_string().contains("oracle"),
            "{error}"
        );
        let mut collision = restored.api_request.clone();
        collision.public_inputs.request_nullifier = Felt252::from_u64(999);
        assert!(matches!(
            processor.issue_openrouter_lease(&collision).await,
            Err(ServerError::Replay)
        ));
        assert!(store
            .lookup_by_nullifier(&collision.public_inputs.request_nullifier)
            .is_none());
        let mut mutation = restored.api_request.clone();
        let mut payload: serde_json::Value = serde_json::from_str(&mutation.payload).unwrap();
        payload["billing_quote"]["answer"] = "500000000000".into();
        mutation.payload = payload.to_string();
        mutation.payload_hash = canonical_payload_hash(mutation.payload.as_bytes());
        assert!(matches!(
            processor.issue_openrouter_lease(&mutation).await,
            Err(ServerError::Replay)
        ));
        let mut missing_config = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        missing_config.config.native_billing = None;
        assert!(missing_config.lease_authorization(&request).is_err());
        chain_server.abort();
    }
    #[tokio::test]
    async fn native_issuance_rechecks_expiry_after_delayed_oracle_read() {
        use crate::native_billing::NativeBillingConfig;
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        use std::time::Duration;
        use tokio::sync::Notify;

        let expires_at = current_timestamp() + 5;
        let updated_at = expires_at - 3600;
        let oracle_read_started = Arc::new(Notify::new());
        let finish_oracle_read = Arc::new(Notify::new());
        let started = oracle_read_started.clone();
        let finish = finish_oracle_read.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let started = started.clone();
                let finish = finish.clone();
                async move {
                    let data = request["params"][0]["data"].as_str().unwrap_or("");
                    let result = if request["method"] == "eth_chainId" {
                        "0x1".to_string()
                    } else if data == "0x313ce567" {
                        format!("0x{:064x}", 8)
                    } else if data == "0x4d1352fd" {
                        format!("0x{:064x}", 1_000_000_000)
                    } else {
                        assert_eq!(request["params"][1], "finalized");
                        if data.starts_with("0x9a6fc8f5") {
                            started.notify_one();
                            finish.notified().await;
                        } else {
                            assert_eq!(data, "0xfeaf968c");
                        }
                        format!(
                            "0x{:064x}{:064x}{:064x}{:064x}{:064x}",
                            123, 250_000_000_000u64, updated_at, updated_at, 123
                        )
                    };
                    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        processor.config.contract_address = Felt252::from_u64(1);
        let config = NativeBillingConfig {
            rpc_url,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 3600,
        };
        processor.config.native_billing = Some(config.clone());
        processor.native_oracle = NativeBillingOracle::new(
            config,
            1,
            "0x0000000000000000000000000000000000000001".into(),
        )
        .unwrap();
        let processor = Arc::new(processor);
        let mut request = unverified_lease_request(&processor);
        let quote = NativeBillingQuote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: 1,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            round_id: "123".into(),
            answer: "250000000000".into(),
            decimals: 8,
            updated_at,
            expires_at,
        };
        request.payload =
            json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                .to_string();
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.solvency_bound = 400_000;
        let issuer = processor.clone();
        let issued_request = request.clone();
        let issuance =
            tokio::spawn(async move { issuer.issue_openrouter_lease(&issued_request).await });
        tokio::time::timeout(Duration::from_secs(10), oracle_read_started.notified())
            .await
            .unwrap();
        while current_timestamp() < expires_at {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        finish_oracle_read.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), issuance)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(ServerError::NativeQuoteExpired)));
        assert!(store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        assert!(store
            .lookup_openrouter_lease(&request.client_request_id)
            .is_none());
        assert_eq!(
            processor
                .expire_unaccepted_native_lease(&request.client_request_id, &request)
                .await
                .unwrap()["status"],
            "expired_unaccepted"
        );
        server.abort();
    }
    #[tokio::test]
    async fn native_issuance_uses_latest_finalized_round_and_recovers_superseded_request() {
        use crate::native_billing::NativeBillingConfig;
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        use std::sync::atomic::{AtomicU64, Ordering};

        let updated_at = current_timestamp() - 30;
        let finalized_round = Arc::new(AtomicU64::new(123));
        let head_round = Arc::new(AtomicU64::new(124));
        let rpc_finalized = finalized_round.clone();
        let rpc_head = head_round.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let finalized = rpc_finalized.clone();
                let head = rpc_head.clone();
                async move {
                    let data = request["params"][0]["data"].as_str().unwrap_or("");
                    let result = if request["method"] == "eth_chainId" {
                        "0x1".to_string()
                    } else if data == "0x313ce567" {
                        format!("0x{:064x}", 8)
                    } else if data == "0x4d1352fd" {
                        format!("0x{:064x}", 1_000_000_000)
                    } else if data.starts_with("0xaad24061") {
                        assert_eq!(request["params"][1], "latest");
                        format!("0x{:064x}", 0)
                    } else {
                        let latest = if request["params"][1] == "finalized" {
                            finalized.load(Ordering::SeqCst)
                        } else {
                            head.load(Ordering::SeqCst)
                        };
                        let round = if data == "0xfeaf968c" {
                            latest
                        } else {
                            assert!(data.starts_with("0x9a6fc8f5"));
                            let round = u64::from_str_radix(&data[10..], 16).unwrap();
                            assert!(round <= latest);
                            round
                        };
                        let price = if round == 123 {
                            250_000_000_000u64
                        } else {
                            200_000_000_000u64
                        };
                        format!(
                            "0x{:064x}{:064x}{:064x}{:064x}{:064x}",
                            round, price, updated_at, updated_at, round
                        )
                    };
                    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        processor.config.contract_address = Felt252::from_u64(1);
        let config = NativeBillingConfig {
            rpc_url,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 4500,
        };
        processor.config.native_billing = Some(config.clone());
        processor.native_oracle = NativeBillingOracle::new(
            config,
            1,
            "0x0000000000000000000000000000000000000001".into(),
        )
        .unwrap();
        let oracle = &processor.native_oracle;
        let quote = oracle.quote(current_timestamp()).await.unwrap();
        assert_eq!(
            quote.round_id, "123",
            "head-only round must not influence pricing"
        );
        oracle.validate(&quote, current_timestamp()).await.unwrap();
        let mut request = unverified_lease_request(&processor);
        request.payload =
            json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                .to_string();
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.solvency_bound = 400_000;
        assert!(matches!(
            processor
                .expire_unaccepted_native_lease(&request.client_request_id, &request)
                .await,
            Err(ServerError::LeasePending)
        ));
        // Proof construction used round123. Once round124 finalizes, a new
        // issuance cannot choose the more favorable historical price123.
        finalized_round.store(124, Ordering::SeqCst);
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::NativeQuoteSuperseded)
        ));
        assert!(store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        let ack = processor
            .expire_unaccepted_native_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(ack["status"], "superseded_unaccepted");
        assert_eq!(
            ack["payload_hash"],
            serde_json::to_value(request.payload_hash).unwrap()
        );
        assert_eq!(
            ack["request_nullifier"],
            serde_json::to_value(request.public_inputs.request_nullifier).unwrap()
        );
        // A normal head reorg cannot revive an acknowledged old finalized quote.
        head_round.store(123, Ordering::SeqCst);
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::NativeQuoteSuperseded)
        ));
        // Simulate a previously accepted request from before finality advanced:
        // recovery never discards it and measured usage uses its frozen price.
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease_with_oa_id(
                &request,
                "oa_org",
                updated_at,
                updated_at + 300,
                updated_at + 300,
                1.0,
                Some(&RequestProcessor::native_oa_request_id(&request).unwrap()),
            )
            .unwrap();
        assert!(matches!(
            processor
                .expire_unaccepted_native_lease(&request.client_request_id, &request)
                .await,
            Err(ServerError::LeasePending)
        ));
        assert_eq!(
            processor.lease_charge_units(&request, 123_456).unwrap(),
            49_383
        );
        let error = processor
            .issue_openrouter_lease(&request)
            .await
            .err()
            .unwrap();
        assert!(!matches!(
            error,
            ServerError::NativeQuoteSuperseded | ServerError::NativeQuoteExpired
        ));
        server.abort();
    }
    #[test]
    fn native_quote_is_bound_by_real_browser_proof_and_settles_in_gwei() {
        use zkapi_browser::{
            BrowserWalletConfig, CompleteResponseArgs, ConfirmDepositArgs, PrepareRequestArgs,
        };
        use zkapi_core::merkle::MerkleTree;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store);
        processor.config.contract_address = Felt252::from_u64(1);
        processor.config.request_charge_cap = 400_000;
        processor.config.native_billing = Some(crate::native_billing::NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 3600,
        });
        let config = BrowserWalletConfig {
            protocol_version: 2,
            chain_id: 1,
            contract_address: processor.config.contract_address,
            request_charge_cap: 400_000,
            policy_charge_cap: 400_000,
            policy_enabled: false,
            state_signing_key: processor.state_signing_key(),
            clearance_signing_key: processor.clearance_signing_key(),
        };
        let params = zkapi_browser::generate_deposit_params();
        let state = zkapi_browser::confirm_deposit(
            &config,
            ConfirmDepositArgs {
                secret: params.secret,
                note_id: 0,
                amount: 2_000_000,
                expiry_ts: 4_000_000_000,
            },
        )
        .unwrap();
        let mut tree = MerkleTree::new();
        tree.set_leaf(
            0,
            core::note_leaf(0, &params.registration_commitment, 2_000_000, 4_000_000_000),
        );
        processor.update_root(tree.root());
        let now = current_timestamp();
        let quote = NativeBillingQuote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: 1,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            round_id: "123".into(),
            answer: "250000000000".into(),
            decimals: 8,
            updated_at: now,
            expires_at: now + 3600,
        };
        let payload=serde_json::json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote}).to_string();
        let key =
            std::fs::read(std::path::Path::new(&setup_directory()).join("request.pk")).unwrap();
        let prepared = zkapi_browser::prepare_request(
            &config,
            &state,
            PrepareRequestArgs {
                payload: payload.clone(),
                active_root: tree.root(),
                merkle_siblings: tree.get_siblings(0).to_vec(),
                client_request_id: "native-real-proof".into(),
                request_time: now,
                created_at_ms: now * 1000,
            },
            &key,
        )
        .unwrap();
        assert_eq!(prepared.request.payload, payload);
        let serialized = serde_json::to_string(&prepared.journal).unwrap();
        let journal: zkapi_browser::PendingRequestJournal =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(journal.prepared_request.payload, payload);
        let mut changed = prepared.request.clone();
        let mut changed_payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
        changed_payload["billing_quote"]["answer"] = "500000000000".into();
        changed.payload = changed_payload.to_string();
        changed.payload_hash = canonical_payload_hash(changed.payload.as_bytes());
        assert!(matches!(
            processor.validate_and_reserve(&changed),
            Err(ServerError::InvalidProof(_))
        ));
        let context = canonical_request_context(&changed.client_request_id, &changed.payload_hash);
        changed.public_inputs.authorization_tag =
            core::authorization_tag(&changed.public_inputs.request_nullifier, &context);
        assert!(matches!(
            processor.validate_and_reserve(&changed),
            Err(ServerError::InvalidProof(_))
        ));
        assert!(processor
            .validate_and_reserve(&prepared.request)
            .unwrap()
            .is_none());
        let charge = processor
            .lease_charge_units(&prepared.request, 123_456)
            .unwrap();
        assert_eq!(charge, 49_383);
        let response = processor
            .finalize_request(
                &prepared.request,
                SettlementResult {
                    status_code: 200,
                    payload: serde_json::json!({"billing_quote":quote,"usage_credits":123456})
                        .to_string(),
                    charge_applied: charge,
                    usage: None,
                    billing_label: "native-test".into(),
                },
                0,
                0,
            )
            .unwrap();
        let next = zkapi_browser::complete_response(
            &config,
            CompleteResponseArgs {
                state,
                journal,
                response,
            },
        )
        .unwrap();
        assert_eq!(next.current_balance, 2_000_000 - charge);
    }

    /// Review regression: a real signed-branch request proof whose state
    /// signature was forged with the published seed-0x1 secret mints nothing
    /// from a deployment with strong keys, through the full issuance path.
    #[tokio::test]
    async fn forged_development_key_state_signature_mints_nothing_under_strong_keys() {
        use crate::native_billing::NativeBillingConfig;
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        use zkapi_browser::{BrowserNoteState, BrowserWalletConfig, ConfirmDepositArgs};
        use zkapi_core::merkle::MerkleTree;
        use zkapi_proof::compact::{balance_commitment, CompactSigner};

        // The latest finalized oracle round, quoted by the forged payload, so
        // the request reaches proof admission exactly as it would over HTTP.
        let updated_at = current_timestamp() - 30;
        let reads = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorded = reads.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let recorded = recorded.clone();
                async move {
                    let data = request["params"][0]["data"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    recorded.lock().unwrap().push(data.clone());
                    let result = if request["method"] == "eth_chainId" {
                        "0x1".to_string()
                    } else if data == "0x313ce567" {
                        format!("0x{:064x}", 8)
                    } else if data == "0x4d1352fd" {
                        format!("0x{:064x}", 1_000_000_000)
                    } else {
                        assert_eq!(request["params"][1], "finalized");
                        format!(
                            "0x{:064x}{:064x}{:064x}{:064x}{:064x}",
                            123, 250_000_000_000u64, updated_at, updated_at, 123
                        )
                    };
                    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let rpc = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let (state_seed, clear_seed) = crate::signer::strong_test_seeds();
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let processor = RequestProcessor::try_new(
            ServerConfig {
                request_charge_cap: 400_000,
                contract_address: Felt252::from_u64(1),
                native_billing: Some(NativeBillingConfig {
                    rpc_url,
                    max_age_seconds: 3600,
                    ..crate::test_support::native_config()
                }),
                openrouter_leases: Some(crate::test_support::lease_config()),
                proof_setup_dir: setup_directory(),
                ..Default::default()
            },
            store.clone(),
            Arc::new(ServerSigner::try_new(&state_seed, &clear_seed).unwrap()),
            Felt252::ZERO,
        )
        .unwrap();

        // A 1 gwei note, then a "signed" state with an arbitrary anchor and an
        // inflated balance, signed with the publicly known development secret.
        let development = CompactSigner::from_seed(&Felt252::ONE);
        let config = BrowserWalletConfig {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Felt252::from_u64(1),
            request_charge_cap: 400_000,
            policy_charge_cap: 400_000,
            policy_enabled: false,
            state_signing_key: development.public_key(),
            clearance_signing_key: CompactSigner::from_seed(&Felt252::from_u64(2)).public_key(),
        };
        let params = zkapi_browser::generate_deposit_params();
        let genesis = zkapi_browser::confirm_deposit(
            &config,
            ConfirmDepositArgs {
                secret: params.secret,
                note_id: 0,
                amount: 1,
                expiry_ts: 4_000_000_000,
            },
        )
        .unwrap();
        let leaf = core::note_leaf(0, &params.registration_commitment, 1, 4_000_000_000);
        let balance = 1_777_000_000_000_000;
        let blinding = random_scalar();
        let anchor = random_field();
        let commitment = balance_commitment(balance, &blinding, &leaf);
        let message = core::state_message(
            2,
            1,
            &config.contract_address,
            &commitment.x,
            &commitment.y,
            &anchor,
        );
        let forged = BrowserNoteState {
            current_balance: balance,
            balance_blinding: blinding.to_hex(),
            current_commitment_x: commitment.x,
            current_commitment_y: commitment.y,
            current_anchor: anchor,
            is_genesis: false,
            state_signature: Some(development.sign(&message)),
            ..genesis
        };
        let mut tree = MerkleTree::new();
        tree.set_leaf(0, leaf);
        processor.update_root(tree.root());
        let quote = NativeBillingQuote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: 1,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            round_id: "123".into(),
            answer: "250000000000".into(),
            decimals: 8,
            updated_at,
            expires_at: updated_at + 3600,
        };
        let key =
            std::fs::read(std::path::Path::new(&setup_directory()).join("request.pk")).unwrap();
        let request = zkapi_browser::prepare_request(
            &config,
            &forged,
            zkapi_browser::PrepareRequestArgs {
                payload:
                    json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                        .to_string(),
                active_root: tree.root(),
                merkle_siblings: tree.get_siblings(0).to_vec(),
                client_request_id: "forged-development-key".into(),
                request_time: current_timestamp(),
                created_at_ms: current_timestamp_ms(),
            },
            &key,
        )
        .unwrap()
        .request;
        // The proof itself is genuine for the development key.
        assert!(processor
            .verifier
            .verify(&request.public_inputs, &request.proof)
            .unwrap());

        let error = processor
            .issue_openrouter_lease(&request)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&error, ServerError::InvalidRequest(message)
                if message == "state signing key does not match this deployment"),
            "{error}"
        );
        // Claiming this deployment's key instead leaves a signature the real
        // Groth16 verifier rejects.
        let mut relabelled = request.clone();
        let deployment_key = processor.state_signing_key();
        relabelled.public_inputs.state_signing_key_x = deployment_key.x;
        relabelled.public_inputs.state_signing_key_y = deployment_key.y;
        let error = processor
            .issue_openrouter_lease(&relabelled)
            .await
            .err()
            .unwrap();
        assert!(matches!(&error, ServerError::InvalidProof(_)), "{error}");

        assert!(store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        assert!(store
            .lookup_openrouter_lease(&request.client_request_id)
            .is_none());
        // Neither attempt reached the vault spend check that precedes key issuance.
        assert!(!reads
            .lock()
            .unwrap()
            .iter()
            .any(|data| data.starts_with("0xaad24061")));
        rpc.abort();
    }

    // ---- Bounded settlement (G5) -------------------------------------------

    /// A verified-boundary lease request with its own id and nullifier.
    fn lease_request_for(
        processor: &RequestProcessor,
        id: &str,
        nullifier: u64,
        payload: Option<String>,
    ) -> ApiRequestV2 {
        let mut request = unverified_lease_request(processor);
        request.client_request_id = id.to_string();
        if let Some(payload) = payload {
            request.payload = payload;
        }
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.request_nullifier = Felt252::from_u64(nullifier);
        let commitment = zkapi_proof::compact::balance_commitment(
            3_000_000,
            &Felt252::from_u64(13),
            &Felt252::from_u64(14),
        );
        request.public_inputs.anonymous_commitment_x = commitment.x;
        request.public_inputs.anonymous_commitment_y = commitment.y;
        request.proof.proof = base64::engine::general_purpose::STANDARD.encode(b"verified-proof");
        request
    }

    struct LeaseSetup<'a> {
        key_source: &'a str,
        expires_at: u64,
        deadline: Option<u64>,
        key_hash: Option<&'a str>,
        delivered: Option<bool>,
        ttl: Option<u64>,
    }

    /// Reserve `request` and record its lease row as issuance would.
    fn add_lease(processor: &RequestProcessor, request: &ApiRequestV2, setup: LeaseSetup<'_>) {
        processor.store.reserve_openrouter_lease(request).unwrap();
        let oa_id = (setup.key_source == "oa_org")
            .then(|| RequestProcessor::native_oa_request_id(request).unwrap());
        let limit = RequestProcessor::lease_terms(request)
            .ok()
            .and_then(|(_, quote)| {
                quote
                    .limit_micro_usd(request.public_inputs.solvency_bound)
                    .ok()
            })
            .map(pricing::micro_usd_to_usd)
            .unwrap_or(3.0);
        processor
            .store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request,
                key_source: setup.key_source,
                issued_at: setup.expires_at.saturating_sub(300),
                expires_at: setup.expires_at,
                settle_after: setup.expires_at,
                spending_limit_usd: limit,
                oa_client_request_id: oa_id.as_deref(),
                ttl_seconds: setup.ttl,
                settlement_deadline_at: setup.deadline,
                delivered: setup.delivered,
            })
            .unwrap();
        if let Some(hash) = setup.key_hash {
            processor
                .store
                .activate_openrouter_lease(&request.client_request_id, hash)
                .unwrap();
        }
    }

    fn record_of(processor: &RequestProcessor, request: &ApiRequestV2) -> TranscriptRecord {
        processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap()
    }

    fn payload_of(record: &TranscriptRecord) -> serde_json::Value {
        serde_json::from_str(record.response_payload.as_deref().unwrap()).unwrap()
    }

    fn review_of(processor: &RequestProcessor, request: &ApiRequestV2) -> Option<SettlementReview> {
        processor
            .store
            .settlement_reviews(100)
            .unwrap()
            .into_iter()
            .find(|stored| stored.review.client_request_id == request.client_request_id)
            .map(|stored| stored.review)
    }

    fn frozen_quote(request: &ApiRequestV2) -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(&request.payload).unwrap()["billing_quote"]
            .clone()
    }

    /// An OA usage relay that returns a finalized, station-signed receipt.
    async fn oa_usage_server(
        usage_credits: u128,
        expected_duration_minutes: u64,
    ) -> (
        String,
        tokio::task::JoinHandle<()>,
        Arc<std::sync::Mutex<usize>>,
    ) {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        let calls = Arc::new(std::sync::Mutex::new(0usize));
        let seen = calls.clone();
        let app = Router::new().route(
            "/api/zkapi/key_usage",
            post(move |Json(body): Json<Value>| {
                let seen = seen.clone();
                async move {
                    *seen.lock().unwrap() += 1;
                    assert_eq!(body["duration_minutes"], expected_duration_minutes);
                    let expires_at = body["expires_at_unix"].as_u64().unwrap() - 30;
                    Json(json!({"source":"oa_org", "version":1, "status":"finalized",
                        "client_request_id":body["client_request_id"], "station_request_id":"ab".repeat(32),
                        "key_hash":body["key_hash"], "usage_credits":usage_credits,
                        "credit_limit_credits":body["credit_limit_credits"], "expires_at_unix":expires_at,
                        "closed_at_unix":expires_at, "finalized_at_unix":expires_at + 1,
                        "station_id":"station", "station_signature":"ab".repeat(64),
                        "org_signature":"cd".repeat(64)}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, server, calls)
    }

    /// Report regression 1: usage far above the proof-bound budget used to
    /// make the conversion fail on every scan, for ever.
    #[tokio::test]
    async fn overflowing_usage_finalizes_clamped_instead_of_retrying() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage: 1e12,
            ..Default::default()
        }));
        let (processor, request, server) = retirement_processor(state.clone(), 0, None).await;
        let status = processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(status.status, "finalized");
        assert_eq!(status.charge_basis.as_deref(), Some("clamped"));
        let bound = request.public_inputs.solvency_bound;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert!(record.next_anchor.is_some() && record.next_state_sig.is_some());
        let expected = RequestProcessor::lease_terms(&request)
            .unwrap()
            .1
            .capped_charge_units(pricing::usd_to_micro_usd(1e12), bound);
        assert!(expected.clamped);
        assert_eq!(record.charge_applied, Some(expected.charge));
        assert!(expected.charge <= bound);
        let payload = payload_of(&record);
        assert_eq!(payload["type"], "openrouter_ephemeral_lease_settlement");
        assert_eq!(payload["charge_basis"], "clamped");
        assert_eq!(payload["reported_usage_micro_usd"], "1000000000000000000");
        assert_eq!(
            payload["charged_usage_micro_usd"],
            expected.charged_micro_usd.to_string()
        );
        assert_eq!(payload["billing_quote"], frozen_quote(&request));
        assert_eq!(
            review_of(&processor, &request).unwrap().reason,
            "usage_clamped"
        );
        let events = state.lock().unwrap().events.clone();
        assert_eq!(events, ["disable", "usage", "delete"]);
        // A later scan makes no provider calls and never re-signs.
        processor.settle_due_openrouter_leases().await;
        assert_eq!(state.lock().unwrap().events, events);
        assert_eq!(
            record_of(&processor, &request).next_state_sig,
            record.next_state_sig
        );
        server.abort();
    }

    /// Report regression 2: changing --native-price-* must not strand leases
    /// bound to the old quote policy.
    #[tokio::test]
    async fn lease_settles_unchanged_after_native_config_changes() {
        let changed = crate::native_billing::NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x0000000000000000000000000000000000000abc".into(),
            decimals: 9,
            max_age_seconds: 7200,
        };
        // Direct key, across a restart with the changed configuration.
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage: 0.000002,
            ..Default::default()
        }));
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("server.db");
        let (processor, request, server) =
            retirement_processor(state.clone(), 0, Some(&db_path)).await;
        assert!(processor.lease_authorization(&request).is_ok());
        let mut config = processor.config.clone();
        let signer = processor.signer.clone();
        drop(processor);
        config.native_billing = Some(changed.clone());
        let processor = RequestProcessor::try_new(
            config,
            Arc::new(NullifierStore::new(&db_path).unwrap()),
            signer,
            Felt252::ZERO,
        )
        .unwrap();
        assert!(processor.lease_authorization(&request).is_err());
        let status = processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(status.status, "finalized");
        let record = record_of(&processor, &request);
        // $1000/ETH frozen quote: 2 micro-USD is 2 gwei.
        assert_eq!(record.charge_applied, Some(2));
        assert_eq!(payload_of(&record)["billing_quote"], frozen_quote(&request));
        server.abort();

        // OA key, after the same configuration change.
        let issuance = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (mut processor, request, rpc) = issuance_processor(true, issuance).await;
        processor
            .store
            .activate_openrouter_lease(&request.client_request_id, "oa-hash")
            .unwrap();
        processor.config.native_billing = Some(changed);
        let (url, usage, calls) = oa_usage_server(1_000_000, 5).await;
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(url, "test-secret".into()).unwrap(),
        ));
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(1_000_000));
        assert_eq!(payload_of(&record)["billing_quote"], frozen_quote(&request));
        assert_eq!(*calls.lock().unwrap(), 1);
        rpc.abort();
        usage.abort();
    }

    /// Report regression 3: a transient failure retries until the lease's
    /// write-once deadline, then finalizes at the worst case without I/O.
    #[tokio::test]
    async fn transient_failure_retries_until_deadline_then_finalizes_worst_case() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage_unavailable: true,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let pending = lease_request_for(&processor, "before-deadline", 501, None);
        add_lease(
            &processor,
            &pending,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 1,
                deadline: Some(now + 3_600),
                key_hash: Some("hash-a"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let overdue = lease_request_for(&processor, "past-deadline", 502, None);
        add_lease(
            &processor,
            &overdue,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 200,
                deadline: Some(now - 140),
                key_hash: Some("hash-b"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        processor.settle_due_openrouter_leases().await;

        let retrying = processor
            .store
            .lookup_openrouter_lease(&pending.client_request_id)
            .unwrap();
        assert_eq!(retrying.status, "disabled");
        assert!(retrying.settlement_attempts >= 1);
        assert!(retrying.first_error_at.is_some());
        assert_eq!(
            record_of(&processor, &pending).status,
            NullifierStatus::Reserved
        );
        let status = processor
            .openrouter_lease_status(&pending.client_request_id)
            .unwrap();
        assert_eq!(status.settlement_deadline, Some(now + 3_600));

        let bound = overdue.public_inputs.solvency_bound;
        let record = record_of(&processor, &overdue);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(bound));
        let payload = payload_of(&record);
        assert_eq!(payload["type"], "openrouter_ephemeral_lease_settlement");
        assert_eq!(payload["charge_basis"], "worst_case");
        assert_eq!(payload["settlement_reason"], "settlement_deadline");
        assert_eq!(payload["settlement_deadline"], now - 140);
        assert_eq!(payload["billing_quote"], frozen_quote(&overdue));
        let review = review_of(&processor, &overdue).unwrap();
        assert_eq!(review.reason, "deadline_worst_case");
        assert_eq!(review.charge_applied, Some(bound));
        let status = processor
            .openrouter_lease_status(&overdue.client_request_id)
            .unwrap();
        assert_eq!(status.status, "finalized");
        assert_eq!(status.charge_basis.as_deref(), Some("worst_case"));
        assert_eq!(status.settlement_deadline, None);
        // The finalized lease's key is disabled and deleted in the background.
        assert_eq!(
            processor.settlement_counts().unwrap().pending_key_cleanups,
            0
        );
        server.abort();
    }

    /// The deadline is written once: a provider that keeps reporting the key
    /// enabled (disabled -> retiring -> disabled ...) cannot postpone it.
    #[tokio::test]
    async fn deadline_fires_while_provider_keeps_reporting_the_key_enabled() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            report_enabled: true,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let deadline = now + 2;
        let request = lease_request_for(&processor, "stuck-enabled", 503, None);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 10,
                deadline: Some(deadline),
                key_hash: Some("hash-enabled"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let mut first_error_at = None;
        for cycle in 1..=2 {
            processor.settle_due_openrouter_leases().await;
            let lease = processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap();
            assert_eq!(lease.status, "retiring");
            assert_eq!(lease.settlement_deadline_at, Some(deadline));
            assert_eq!(lease.settlement_attempts, cycle);
            first_error_at = first_error_at.or(lease.first_error_at);
            assert_eq!(lease.first_error_at, first_error_at);
        }
        while current_timestamp() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(
            record.charge_applied,
            Some(request.public_inputs.solvency_bound)
        );
        assert_eq!(payload_of(&record)["charge_basis"], "worst_case");
        server.abort();
    }

    #[tokio::test]
    async fn deadline_sweep_ignores_hung_provider() {
        use axum::{routing::any, Router};
        let calls = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen = calls.clone();
        let app = Router::new().route(
            "/v1/keys/{hash}",
            any(
                move |axum::extract::Path(hash): axum::extract::Path<String>| {
                    let seen = seen.clone();
                    async move {
                        seen.lock().unwrap().push(hash);
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.openrouter_leases.as_mut().unwrap().source =
            OpenRouterLeaseSourceConfig::OpenRouter {
                management_key: "test".into(),
                api_base: url.clone(),
            };
        processor.openrouter = Some(Arc::new(
            OpenRouterProvisioner::new("test".into(), url).unwrap(),
        ));
        processor.oa_org = None;
        processor.timing.attempt_timeout = std::time::Duration::from_millis(500);
        processor.timing.tick_budget = std::time::Duration::from_millis(500);
        processor.timing.cleanup_attempt_timeout = std::time::Duration::from_millis(200);
        let now = current_timestamp();
        let overdue = lease_request_for(&processor, "overdue", 504, None);
        add_lease(
            &processor,
            &overdue,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 100,
                deadline: Some(now - 1),
                key_hash: Some("overdue-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let hung = lease_request_for(&processor, "hung", 505, None);
        add_lease(
            &processor,
            &hung,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 1,
                deadline: Some(now + 3_600),
                key_hash: Some("hung-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            processor.settle_due_openrouter_leases(),
        )
        .await
        .expect("a hung provider stalled the settlement sweep");
        let record = record_of(&processor, &overdue);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(
            record.charge_applied,
            Some(overdue.public_inputs.solvency_bound)
        );
        let hung_lease = processor
            .store
            .lookup_openrouter_lease(&hung.client_request_id)
            .unwrap();
        assert_eq!(hung_lease.status, "retiring");
        assert_eq!(
            hung_lease.last_error.as_deref(),
            Some("internal error: settlement attempt timed out")
        );
        // The overdue lease was finalized before any provider call; only its
        // background key cleanup (which timed out) reached the provider.
        assert!(calls
            .lock()
            .unwrap()
            .iter()
            .all(|hash| hash == "hung-hash" || hash == "overdue-hash"));
        server.abort();
    }

    #[tokio::test]
    async fn revoking_lease_at_deadline_charges_persisted_usage() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            delete_unavailable: true,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let request = lease_request_for(&processor, "revoking", 506, None);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 100,
                deadline: Some(now - 1),
                key_hash: Some("hash-revoking"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        for (from, to, usage) in [
            ("active", "retiring", None),
            ("retiring", "disabled", None),
            ("disabled", "revoking", Some(0.000002)),
        ] {
            processor
                .store
                .advance_openrouter_retirement(&request.client_request_id, from, to, 0, usage)
                .unwrap();
        }
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        // The measured usage, not the solvency bound.
        assert_eq!(record.charge_applied, Some(2));
        let payload = payload_of(&record);
        assert_eq!(payload["charge_basis"], "measured");
        assert_eq!(payload["key_deleted"], false);
        assert_eq!(payload["settlement_reason"], "settlement_deadline");
        let review = review_of(&processor, &request).unwrap();
        assert_eq!(review.reason, "finalized_before_key_deletion");
        assert_eq!(review.charge_applied, Some(2));
        // Deletion keeps failing: the key stays queued and is retried later.
        assert_eq!(state.lock().unwrap().events, ["disable", "delete"]);
        assert_eq!(
            processor.settlement_counts().unwrap().pending_key_cleanups,
            1
        );
        server.abort();
    }

    #[tokio::test]
    async fn oa_receipt_above_limit_is_clamped_and_finalizes() {
        let issuance = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (mut processor, request, rpc) = issuance_processor(true, issuance).await;
        processor
            .store
            .activate_openrouter_lease(&request.client_request_id, "oa-hash")
            .unwrap();
        let (url, usage, _) = oa_usage_server(10_000_000, 5).await;
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(url, "test-secret".into()).unwrap(),
        ));
        processor.settle_due_openrouter_leases().await;
        let bound = request.public_inputs.solvency_bound;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(bound));
        let payload = payload_of(&record);
        assert_eq!(payload["type"], "oa_org_ephemeral_lease_settlement");
        assert_eq!(payload["usage_credits"], 10_000_000);
        assert_eq!(payload["charged_usage_credits"], 3_000_000);
        assert_eq!(payload["charge_basis"], "clamped");
        assert_eq!(
            review_of(&processor, &request).unwrap().reason,
            "usage_clamped"
        );
        assert_eq!(
            processor
                .openrouter_lease_status(&request.client_request_id)
                .unwrap()
                .charge_basis
                .as_deref(),
            Some("clamped")
        );
        rpc.abort();
        usage.abort();
    }

    #[tokio::test]
    async fn oa_usage_and_resumed_issuance_use_the_persisted_ttl() {
        let issuance = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (mut processor, _, rpc) = issuance_processor(true, issuance.clone()).await;
        let now = current_timestamp();
        let settled = lease_request_for(&processor, "persisted-ttl", 507, None);
        add_lease(
            &processor,
            &settled,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now - 1,
                deadline: Some(now + 3_600),
                key_hash: Some("ttl-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        // The configured TTL changes after the leases were bound.
        processor
            .config
            .openrouter_leases
            .as_mut()
            .unwrap()
            .ttl_seconds = 600;
        let (url, usage, calls) = oa_usage_server(1, 5).await;
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(url, "test-secret".into()).unwrap(),
        ));
        processor.settle_due_openrouter_leases().await;
        assert_eq!(*calls.lock().unwrap(), 1);
        assert_eq!(
            record_of(&processor, &settled).status,
            NullifierStatus::Finalized
        );
        usage.abort();

        // Resumed issuance requests, and accepts, the persisted 5 minutes.
        let resumed = lease_request_for(&processor, "resumed-ttl", 508, None);
        add_lease(
            &processor,
            &resumed,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now + 300,
                deadline: Some(now + 3_600),
                key_hash: None,
                delivered: Some(false),
                ttl: Some(300),
            },
        );
        let issuer = format!(
            "http://{}",
            rpc_address(&processor.config.native_billing.as_ref().unwrap().rpc_url)
        );
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(issuer, "test-secret".into()).unwrap(),
        ));
        let issued = processor.issue_openrouter_lease(&resumed).await.unwrap();
        assert!(issued.lease.expires_at <= current_timestamp() + 300);
        let lease = processor
            .store
            .lookup_openrouter_lease(&resumed.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "active");
        assert_eq!(lease.delivered, Some(true));
        assert_eq!(lease.ttl_seconds, Some(300));
        assert_eq!(issuance.lock().unwrap().creates, 1);
        rpc.abort();
    }

    /// The issuance mock serves its RPC under /rpc on the same listener.
    fn rpc_address(rpc_url: &str) -> String {
        rpc_url
            .trim_start_matches("http://")
            .trim_end_matches("/rpc")
            .to_string()
    }

    #[tokio::test]
    async fn abandoned_direct_provisioning_finalizes_zero_after_orphan_cleanup() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            fail_create: true,
            ..Default::default()
        }));
        let (mut processor, request, server) = issuance_processor(false, state.clone()).await;
        processor
            .config
            .openrouter_leases
            .as_mut()
            .unwrap()
            .ttl_seconds = 1;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Internal(_))
        ));
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "provisioning");
        assert_eq!(lease.delivered, Some(false));
        let reads = {
            let mut state = state.lock().unwrap();
            // The ambiguous create left a key behind under the request name.
            state.orphan_name = Some(format!("zkapi-{}", request.client_request_id));
            state.cleanup.clear();
            state.nullifier_reads
        };
        while current_timestamp() <= lease.settle_after {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        let payload = payload_of(&record);
        assert_eq!(payload["type"], "openrouter_ephemeral_lease_settlement");
        assert_eq!(payload["charge_basis"], "unissued");
        assert_eq!(payload["issued"], false);
        assert_eq!(payload["reason"], "issuance_not_completed");
        assert_eq!(payload["billing_quote"], frozen_quote(&request));
        {
            let state = state.lock().unwrap();
            // Disabled, then deleted; an unrelated key is untouched.
            assert_eq!(state.cleanup, ["disable:orphan-hash", "delete:orphan-hash"]);
            // A zero charge needs no chain read.
            assert_eq!(state.nullifier_reads, reads);
        }
        assert!(processor
            .recover_by_client_id(&request.client_request_id)
            .unwrap()
            .request_response
            .is_some());
        let creates = state.lock().unwrap().creates;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Replay)
        ));
        assert_eq!(state.lock().unwrap().creates, creates);
        server.abort();
    }

    /// The critique's orphan race: an exact retry in flight holds the issue
    /// lock, so zero finalization defers; after it, retries never mint a key.
    #[tokio::test]
    async fn zero_finalization_defers_to_in_flight_issuance() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(false, state.clone()).await;
        let guard = processor.lease_issue_lock.lock().await;
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap()
                .status,
            "provisioning"
        );
        assert_eq!(
            record_of(&processor, &request).status,
            NullifierStatus::Reserved
        );
        drop(guard);
        processor.settle_due_openrouter_leases().await;
        assert_eq!(record_of(&processor, &request).charge_applied, Some(0));
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Replay)
        ));
        assert_eq!(state.lock().unwrap().creates, 0);
        server.abort();
    }

    #[tokio::test]
    async fn activation_never_returned_to_the_client_finalizes_at_zero() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            consume_on_create: true,
            ..Default::default()
        }));
        let (mut processor, request, server) = issuance_processor(false, state.clone()).await;
        processor
            .config
            .openrouter_leases
            .as_mut()
            .unwrap()
            .ttl_seconds = 1;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::NullifierUsed)
        ));
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "active");
        assert_eq!(lease.delivered, Some(false));
        let reads = state.lock().unwrap().nullifier_reads;
        while current_timestamp() <= lease.settle_after {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.charge_applied, Some(0));
        let payload = payload_of(&record);
        assert_eq!(payload["charge_basis"], "unissued");
        assert_eq!(payload["reason"], "key_never_delivered");
        let state = state.lock().unwrap();
        assert_eq!(state.cleanup, ["disable:test-hash", "delete:test-hash"]);
        assert_eq!(state.nullifier_reads, reads);
        server.abort();
    }

    /// The worst case applies only to a key that may have been delivered.
    #[tokio::test]
    async fn worst_case_applies_only_to_possibly_delivered_leases() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage_unavailable: true,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state, 0, None).await;
        let now = current_timestamp();
        let mut cases = Vec::new();
        for (id, nullifier, key_hash, delivered, expected) in [
            (
                "delivered",
                511,
                Some("hash-1"),
                Some(true),
                Some(3_000_000),
            ),
            (
                "unknown-provenance",
                512,
                Some("hash-2"),
                None,
                Some(3_000_000),
            ),
            ("never-returned", 513, Some("hash-3"), Some(false), Some(0)),
            ("never-issued", 514, None, Some(false), Some(0)),
        ] {
            let request = lease_request_for(&processor, id, nullifier, None);
            add_lease(
                &processor,
                &request,
                LeaseSetup {
                    key_source: "openrouter",
                    expires_at: now - 100,
                    deadline: Some(now - 1),
                    key_hash,
                    delivered,
                    ttl: Some(300),
                },
            );
            cases.push((request, expected));
        }
        processor.settle_due_openrouter_leases().await;
        for (request, expected) in cases {
            let record = record_of(&processor, &request);
            assert_eq!(
                record.charge_applied, expected,
                "{}",
                request.client_request_id
            );
            let basis = payload_of(&record)["charge_basis"].clone();
            assert_eq!(
                basis,
                if expected == Some(0) {
                    "unissued"
                } else {
                    "worst_case"
                },
                "{}",
                request.client_request_id
            );
        }
        server.abort();
    }

    /// An honest user who escapes after a failed issuance is never charged,
    /// even once the server clock passes the lease's deadline.
    #[tokio::test]
    async fn honest_escape_after_failed_issuance_past_deadline_finalizes_at_zero() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            fail_create: true,
            ..Default::default()
        }));
        let (mut processor, request, server) = issuance_processor(false, state.clone()).await;
        let lease_config = processor.config.openrouter_leases.as_mut().unwrap();
        lease_config.ttl_seconds = 1;
        lease_config.settlement_deadline_seconds = 1;
        assert!(processor.issue_openrouter_lease(&request).await.is_err());
        state.lock().unwrap().spent = true; // the user escaped on chain
        let deadline = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap()
            .settlement_deadline_at
            .unwrap();
        while current_timestamp() <= deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let reads = state.lock().unwrap().nullifier_reads;
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        assert!(review_of(&processor, &request).is_none());
        assert_eq!(state.lock().unwrap().nullifier_reads, reads);
        server.abort();
    }

    #[tokio::test]
    async fn zero_usage_is_signed_without_a_chain_read() {
        // The fixture oracle RPC is unreachable: nothing here may need it.
        let state = Arc::new(std::sync::Mutex::new(RetirementMock::default()));
        let (processor, request, server) = retirement_processor(state, 0, None).await;
        processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        assert_eq!(payload_of(&record)["charge_basis"], "measured");
        server.abort();
    }

    #[test]
    fn finalize_request_clamps_charge_above_solvency_bound() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let request = reserved_request(&processor);
        let bound = request.public_inputs.solvency_bound;
        let response = processor
            .finalize_request(
                &request,
                SettlementResult {
                    status_code: 200,
                    payload: processor
                        .settlement_payload(&request, serde_json::json!({}))
                        .unwrap(),
                    charge_applied: bound + 1,
                    usage: None,
                    billing_label: "test".into(),
                },
                0,
                0,
            )
            .unwrap();
        assert_eq!(response.charge_applied, bound);
        assert_eq!(record_of(&processor, &request).charge_applied, Some(bound));
        // A successor for another deployment is never signed.
        let foreign = lease_request_for(&processor, "foreign", 515, None);
        processor.store.reserve_openrouter_lease(&foreign).unwrap();
        let mut foreign = foreign;
        foreign.public_inputs.chain_id = 5;
        assert!(processor
            .finalize_request(
                &foreign,
                SettlementResult {
                    status_code: 200,
                    payload: "{}".into(),
                    charge_applied: 0,
                    usage: None,
                    billing_label: "test".into(),
                },
                0,
                0,
            )
            .is_err());
    }

    #[tokio::test]
    async fn unsettleable_persisted_quote_finalizes_worst_case_immediately() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage: 0.000002,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let mut payload: serde_json::Value =
            serde_json::from_str(&crate::test_support::lease_payload(&processor.config, now))
                .unwrap();
        payload["billing_quote"]["expires_at"] = (now - 10).into(); // before updated_at
        let request = lease_request_for(&processor, "bad-quote", 516, Some(payload.to_string()));
        assert!(RequestProcessor::lease_terms(&request).is_err());
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 1,
                deadline: Some(now + 3_600),
                key_hash: Some("hash-bad"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(
            record.charge_applied,
            Some(request.public_inputs.solvency_bound)
        );
        let settled = payload_of(&record);
        assert_eq!(settled["charge_basis"], "worst_case");
        assert_eq!(settled["settlement_reason"], "unsettleable");
        // The untouched quote is echoed so that clients can match it.
        assert_eq!(settled["billing_quote"], payload["billing_quote"]);
        assert_eq!(
            review_of(&processor, &request).unwrap().reason,
            "unsettleable_worst_case"
        );
        server.abort();
    }

    #[tokio::test]
    async fn corrupted_binding_is_cancelled_never_signed() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock::default()));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let request = lease_request_for(&processor, "corrupt", 517, None);
        processor.store.reserve_openrouter_lease(&request).unwrap();
        // The lease row holds a different request than the reservation.
        let mut tampered = request.clone();
        tampered.proof.proof = base64::engine::general_purpose::STANDARD.encode(b"other-proof");
        processor
            .store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request: &tampered,
                key_source: "openrouter",
                issued_at: now - 400,
                expires_at: now - 100,
                settle_after: now - 100,
                spending_limit_usd: 3.0,
                oa_client_request_id: None,
                ttl_seconds: Some(300),
                settlement_deadline_at: Some(now - 1),
                delivered: Some(true),
            })
            .unwrap();
        processor
            .store
            .activate_openrouter_lease(&request.client_request_id, "hash-corrupt")
            .unwrap();
        processor.settle_due_openrouter_leases().await;
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "cancelled");
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert!(record.next_state_sig.is_none());
        assert_eq!(
            review_of(&processor, &request).unwrap().reason,
            "binding_corrupt"
        );
        // Its key is still stopped; the cancelled lease is never retried.
        assert_eq!(state.lock().unwrap().events, ["disable", "delete"]);
        processor.settle_due_openrouter_leases().await;
        assert_eq!(state.lock().unwrap().events, ["disable", "delete"]);
        assert_eq!(processor.settlement_counts().unwrap().cancelled, 1);
        server.abort();
    }

    #[tokio::test]
    async fn retire_endpoint_applies_fallback_past_deadline() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage_unavailable: true,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let request = lease_request_for(&processor, "retire-late", 518, None);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 100,
                deadline: Some(now - 1),
                key_hash: Some("hash-late"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let status = processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(status.status, "finalized");
        assert_eq!(status.charge_basis.as_deref(), Some("worst_case"));
        assert_eq!(
            status.charge_applied,
            Some(request.public_inputs.solvency_bound)
        );
        // No usage read: the deadline had passed.
        assert!(!state.lock().unwrap().events.contains(&"usage"));
        server.abort();
    }

    #[tokio::test]
    async fn issuance_rpc_failure_leaves_settleable_provisioning_row() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(false, state.clone()).await;
        // A bare reservation: issuance accepted the request, then stopped.
        processor
            .store
            .remove_failed_openrouter_lease(&request.client_request_id)
            .unwrap();
        state.lock().unwrap().fail_rpc = true;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Internal(_))
        ));
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "provisioning");
        assert_eq!(lease.delivered, Some(false));
        assert_eq!(lease.ttl_seconds, Some(300));
        let deadline = lease.settlement_deadline_at.unwrap();
        assert!(deadline >= lease.issued_at.saturating_add(300));
        assert_eq!(state.lock().unwrap().provider_calls, 0);
        assert_eq!(
            processor
                .recover_by_client_id(&request.client_request_id)
                .unwrap()
                .settlement_deadline,
            Some(deadline)
        );
        server.abort();
    }

    #[tokio::test]
    async fn expire_check_acknowledges_expired_quote_after_config_change() {
        use crate::native_billing::NativeBillingConfig;
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let now = current_timestamp();
        // Quotes made under a 3600 s policy; the server now runs 4500 s.
        processor.config.native_billing = Some(NativeBillingConfig {
            max_age_seconds: 4500,
            ..crate::test_support::native_config()
        });
        let quote = |updated_at: u64| {
            serde_json::json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":{
                "asset":"native_eth", "units_per_eth":1_000_000_000, "chain_id":1,
                "feed_address":"0x694aa1769357215de4fac081bf1f309adc325306", "round_id":"123",
                "answer":"100000000000", "decimals":8, "updated_at":updated_at,
                "expires_at":updated_at + 3600}})
            .to_string()
        };
        let expired = lease_request_for(&processor, "expired-quote", 519, Some(quote(100)));
        assert_eq!(
            processor
                .expire_unaccepted_native_lease(&expired.client_request_id, &expired)
                .await
                .unwrap()["status"],
            "expired_unaccepted"
        );
        let live = lease_request_for(&processor, "live-quote", 520, Some(quote(now)));
        assert!(matches!(
            processor
                .expire_unaccepted_native_lease(&live.client_request_id, &live)
                .await,
            Err(ServerError::InvalidRequest(_))
        ));
    }

    #[test]
    fn worst_case_response_completes_in_browser_wallet() {
        use zkapi_browser::{CompleteResponseArgs, PrepareRequestArgs};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.request_charge_cap = 400_000;
        let (config, state, tree) = crate::test_support::browser_note(&processor, 2_000_000);
        let now = current_timestamp();
        let payload = crate::test_support::lease_payload(&processor.config, now);
        let key =
            std::fs::read(std::path::Path::new(&setup_directory()).join("request.pk")).unwrap();
        let prepared = zkapi_browser::prepare_request(
            &config,
            &state,
            PrepareRequestArgs {
                payload,
                active_root: tree.root(),
                merkle_siblings: tree.get_siblings(0).to_vec(),
                client_request_id: "worst-case-wallet".into(),
                request_time: now,
                created_at_ms: now * 1000,
            },
            &key,
        )
        .unwrap();
        let request = prepared.request;
        assert!(processor.validate_and_reserve(&request).unwrap().is_none());
        processor
            .store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request: &request,
                key_source: "oa_org",
                issued_at: now - 400,
                expires_at: now - 100,
                settle_after: now - 100,
                spending_limit_usd: 0.4,
                oa_client_request_id: Some(
                    &RequestProcessor::native_oa_request_id(&request).unwrap(),
                ),
                ttl_seconds: Some(300),
                settlement_deadline_at: Some(now - 1),
                delivered: Some(true),
            })
            .unwrap();
        processor
            .store
            .activate_openrouter_lease(&request.client_request_id, "wallet-hash")
            .unwrap();
        runtime.block_on(processor.settle_due_openrouter_leases());
        let response = processor
            .recover_by_client_id(&request.client_request_id)
            .unwrap()
            .request_response
            .unwrap();
        assert_eq!(response.charge_applied, 400_000);
        let payload: serde_json::Value = serde_json::from_str(&response.response_payload).unwrap();
        assert_eq!(payload["charge_basis"], "worst_case");
        assert_eq!(payload["billing_quote"], frozen_quote(&request));
        let next = zkapi_browser::complete_response(
            &config,
            CompleteResponseArgs {
                state,
                journal: prepared.journal,
                response,
            },
        )
        .unwrap();
        assert_eq!(next.current_balance, 2_000_000 - 400_000);
    }

    #[test]
    fn settlement_overview_lists_pending_leases_and_reviews() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let now = current_timestamp();
        let request = lease_request_for(&processor, "pending-view", 521, None);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now + 100,
                deadline: Some(now + 1_000),
                key_hash: Some("view-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        processor
            .store
            .record_openrouter_lease_error(&request.client_request_id, "usage pending")
            .unwrap();
        let overview = processor.settlement_overview(10).unwrap();
        assert_eq!(overview.pending.len(), 1);
        let pending = &overview.pending[0];
        assert_eq!(pending.client_request_id, request.client_request_id);
        assert_eq!(pending.settlement_deadline, Some(now + 1_000));
        assert!(pending.seconds_until_deadline.unwrap() <= 1_000);
        assert_eq!(pending.attempts, 1);
        assert_eq!(overview.counts.pending, 1);
        assert_eq!(overview.counts.retrying, 1);
        assert!(overview.reviews.is_empty());
        let json = serde_json::to_value(&overview).unwrap();
        assert_eq!(json["counts"]["pending"], 1);
        assert_eq!(json["pending"][0]["last_error"], "usage pending");
    }

    // ---- Clearance ownership (G6) ------------------------------------------

    fn clearance(fixture: &crate::test_support::OwnershipFixture) -> ClearanceRequest {
        ClearanceRequest {
            withdrawal_nullifier: fixture.plan.public_inputs.withdrawal_nullifier,
            ownership_proof: Some(ClearanceOwnershipProof {
                public_inputs: fixture.plan.public_inputs.clone(),
                proof: fixture.plan.proof.clone(),
            }),
        }
    }

    /// A vault RPC whose currentRoot() is `root`; counts every call.
    async fn vault_root_rpc(
        processor: &mut RequestProcessor,
        root: Felt252,
    ) -> (
        Arc<std::sync::Mutex<Felt252>>,
        Arc<std::sync::Mutex<usize>>,
        tokio::task::JoinHandle<()>,
    ) {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        let current = Arc::new(std::sync::Mutex::new(root));
        let calls = Arc::new(std::sync::Mutex::new(0usize));
        let (served, counted) = (current.clone(), calls.clone());
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let (served, counted) = (served.clone(), counted.clone());
                async move {
                    *counted.lock().unwrap() += 1;
                    let result = if request["method"] == "eth_chainId" {
                        "0x1".to_string()
                    } else {
                        assert_eq!(request["params"][0]["data"], "0xfdab463d");
                        assert_eq!(request["params"][1], "latest");
                        format!("0x{}", hex::encode(served.lock().unwrap().as_bytes()))
                    };
                    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        configure_issuance_rpc(
            processor,
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (current, calls, server)
    }

    #[tokio::test]
    async fn clearance_without_ownership_proof_is_rejected_and_inserts_no_row() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let nullifier = Felt252::from_u64(4_242);
        let error = processor
            .process_clearance(&ClearanceRequest {
                withdrawal_nullifier: nullifier,
                ownership_proof: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(error, ServerError::ClearanceOwnershipRequired));
        assert!(!error.is_retriable());
        assert!(processor.store.lookup_by_nullifier(&nullifier).is_none());
    }

    #[tokio::test]
    async fn clearance_accepts_real_escape_form_ownership_proof() {
        let fixture = crate::test_support::ownership_fixture().await;
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.update_root(fixture.root);
        let request = clearance(fixture);
        let nullifier = request.withdrawal_nullifier;
        let response = processor.process_clearance(&request).await.unwrap();
        let message = core::clearance_message(
            processor.config.protocol_version,
            processor.config.chain_id,
            &processor.config.contract_address,
            &nullifier,
        );
        assert!(zkapi_proof::compact::verify_signature(
            &processor.clearance_signing_key(),
            &message,
            &response.signature
        )
        .unwrap());
        let record = processor.store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.status, NullifierStatus::ClearanceReserved);
        assert_eq!(
            processor
                .store
                .clearance_auth(&nullifier)
                .unwrap()
                .as_deref(),
            Some("ownership_proof")
        );
        // Idempotent for the owner.
        processor.process_clearance(&request).await.unwrap();
        assert_eq!(processor.store.get_all_nullifiers().len(), 1);
        // The reservation is permanent: the note state can never also be
        // spent on a request (the signed clearance has no expiry).
        let lease = lease_request_for(&processor, "after-clearance", 1, None);
        let mut lease = lease;
        lease.public_inputs.request_nullifier = nullifier;
        assert!(matches!(
            processor.validate_and_reserve(&lease),
            Err(ServerError::Replay)
        ));
        // The mutual close itself verifies with that clearance.
        let key =
            std::fs::read(std::path::Path::new(&setup_directory()).join("withdrawal.pk")).unwrap();
        let close = zkapi_browser::prepare_withdrawal(
            &fixture.wallet,
            &fixture.state,
            zkapi_browser::PrepareWithdrawalArgs {
                mode: "mutual".into(),
                destination: format!("0x{}", hex::encode(fixture.destination)),
                active_root: fixture.root,
                merkle_siblings: fixture.plan.siblings.clone(),
                clearance: Some(response),
            },
            &key,
        )
        .unwrap();
        assert!(close.public_inputs.has_clearance);
        assert_eq!(
            close.public_inputs.final_balance,
            request.ownership_proof.unwrap().public_inputs.final_balance
        );
    }

    #[tokio::test]
    async fn clearance_rejects_mismatched_mutual_foreign_or_tampered_proofs() {
        let fixture = crate::test_support::ownership_fixture().await;
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.update_root(fixture.root);
        let valid = clearance(fixture);
        let mutate = |change: &dyn Fn(&mut ClearanceRequest)| {
            let mut request = valid.clone();
            change(&mut request);
            request
        };
        fn inputs(request: &mut ClearanceRequest) -> &mut zkapi_types::WithdrawalPublicInputsV2 {
            &mut request.ownership_proof.as_mut().unwrap().public_inputs
        }
        let cases: Vec<(&str, ClearanceRequest)> = vec![
            (
                "other nullifier",
                mutate(&|r| r.withdrawal_nullifier = Felt252::from_u64(99)),
            ),
            ("mutual form", mutate(&|r| inputs(r).has_clearance = true)),
            (
                "contract",
                mutate(&|r| inputs(r).contract_address = Felt252::from_u64(2)),
            ),
            ("chain", mutate(&|r| inputs(r).chain_id = 5)),
            (
                "state key",
                mutate(&|r| inputs(r).state_signing_key_x = Felt252::from_u64(3)),
            ),
            (
                "clearance key",
                mutate(&|r| inputs(r).clearance_signing_key_y = Felt252::from_u64(4)),
            ),
            ("balance", mutate(&|r| inputs(r).final_balance += 1)),
            (
                "flipped proof byte",
                mutate(&|r| {
                    let proof = &mut r.ownership_proof.as_mut().unwrap().proof.proof;
                    let mut bytes = base64::engine::general_purpose::STANDARD
                        .decode(&*proof)
                        .unwrap();
                    bytes[40] ^= 1;
                    *proof = base64::engine::general_purpose::STANDARD.encode(bytes);
                }),
            ),
        ];
        for (label, request) in cases {
            let error = processor.process_clearance(&request).await.unwrap_err();
            let expected = match label {
                "other nullifier" | "mutual form" | "state key" | "clearance key" => {
                    matches!(error, ServerError::InvalidRequest(_))
                }
                "contract" | "chain" => matches!(error, ServerError::ProtocolMismatch(_)),
                _ => matches!(error, ServerError::InvalidProof(_)),
            };
            assert!(expected, "{label}: {error}");
            assert!(processor
                .store
                .lookup_by_nullifier(&request.withdrawal_nullifier)
                .is_none());
        }
        // A request proof is not an ownership proof, even on the wire.
        let request_proof = serde_json::json!({
            "withdrawal_nullifier": valid.withdrawal_nullifier,
            "ownership_proof": {
                "public_inputs": unverified_lease_request(&processor).public_inputs,
                "proof": valid.ownership_proof.as_ref().unwrap().proof,
            }
        });
        assert!(serde_json::from_value::<ClearanceRequest>(request_proof).is_err());
        assert!(processor.store.get_all_nullifiers().is_empty());
    }

    #[tokio::test]
    async fn clearance_root_window_and_vault_fallback() {
        let fixture = crate::test_support::ownership_fixture().await;
        let fake = crate::test_support::fake_tree_ownership_fixture().await;
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.timing.vault_root_ttl = std::time::Duration::ZERO;
        let vault_root = Felt252::from_u64(0x7007);
        let (served, calls, server) = vault_root_rpc(&mut processor, vault_root).await;
        // An unknown root the vault does not have: stale, reporting the
        // vault's root, and nothing reserved.
        let request = clearance(fake);
        match processor.process_clearance(&request).await {
            Err(ServerError::StaleRoot { latest_root }) => {
                assert_eq!(latest_root, vault_root.to_hex())
            }
            other => panic!("expected stale root, got {other:?}"),
        }
        assert!(processor.store.get_all_nullifiers().is_empty());
        assert_eq!(*calls.lock().unwrap(), 2);
        // The indexer lags, but the vault already has the proof's root.
        *served.lock().unwrap() = fixture.root;
        let request = clearance(fixture);
        processor.process_clearance(&request).await.unwrap();
        assert_eq!(*calls.lock().unwrap(), 4);
        assert!(processor.recent_roots.lock().unwrap().contains(
            &fixture.root,
            current_timestamp(),
            processor.config.clearance_root_window_seconds
        ));
        // A root last seen longer ago than the window is no longer accepted.
        let window = processor.config.clearance_root_window_seconds;
        processor.recent_roots.lock().unwrap().entries =
            VecDeque::from([(fixture.root, current_timestamp() - window - 1)]);
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.withdrawal_nullifier)
                .unwrap()
                .status,
            NullifierStatus::ClearanceReserved
        );
        let other = Arc::new(NullifierStore::in_memory().unwrap());
        let mut fresh = oa_lease_processor(other);
        fresh.timing.vault_root_ttl = std::time::Duration::ZERO;
        let (_, _, fresh_server) = vault_root_rpc(&mut fresh, vault_root).await;
        fresh.recent_roots.lock().unwrap().entries =
            VecDeque::from([(fixture.root, current_timestamp() - window - 1)]);
        assert!(matches!(
            fresh.process_clearance(&request).await,
            Err(ServerError::StaleRoot { .. })
        ));
        assert!(fresh.store.get_all_nullifiers().is_empty());
        server.abort();
        fresh_server.abort();
    }

    #[tokio::test]
    async fn ownership_proof_replay_hits_the_negative_cache_not_the_rpc() {
        let fake = crate::test_support::fake_tree_ownership_fixture().await;
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let vault_root = Felt252::from_u64(0x7008);
        let (served, calls, server) = vault_root_rpc(&mut processor, vault_root).await;
        let request = clearance(fake);
        for _ in 0..6 {
            match processor.process_clearance(&request).await {
                Err(ServerError::StaleRoot { latest_root }) => {
                    assert_eq!(latest_root, vault_root.to_hex())
                }
                other => panic!("expected stale root, got {other:?}"),
            }
        }
        // One eth_chainId + one currentRoot() for all six attempts.
        assert_eq!(*calls.lock().unwrap(), 2);
        assert!(processor.store.get_all_nullifiers().is_empty());
        // Once the cached vault read expires, a replay costs one shared read
        // (still no pairing check) while the vault root is unchanged.
        processor.timing.vault_root_ttl = std::time::Duration::ZERO;
        assert!(matches!(
            processor.process_clearance(&request).await,
            Err(ServerError::StaleRoot { .. })
        ));
        assert_eq!(*calls.lock().unwrap(), 4);
        // A vault that moves re-evaluates the pair rather than trusting it.
        *served.lock().unwrap() = Felt252::from_u64(0x7009);
        match processor.process_clearance(&request).await {
            Err(ServerError::StaleRoot { latest_root }) => {
                assert_eq!(latest_root, Felt252::from_u64(0x7009).to_hex())
            }
            other => panic!("expected stale root, got {other:?}"),
        }
        assert_eq!(*calls.lock().unwrap(), 6);
        // Without the negative cache, concurrent readers still share one read.
        processor
            .rejected_clearances
            .lock()
            .unwrap()
            .entries
            .clear();
        processor.timing.vault_root_ttl = std::time::Duration::from_secs(5);
        *processor.vault_root_cache.try_lock().unwrap() = None;
        let processor = Arc::new(processor);
        let attempts: Vec<_> = (0..4)
            .map(|_| {
                let processor = processor.clone();
                let request = request.clone();
                tokio::spawn(async move { processor.process_clearance(&request).await })
            })
            .collect();
        for attempt in attempts {
            assert!(matches!(
                attempt.await.unwrap(),
                Err(ServerError::StaleRoot { .. })
            ));
        }
        // Four concurrent requests: one more eth_chainId + currentRoot().
        assert_eq!(*calls.lock().unwrap(), 6 + 2);
        server.abort();
    }

    #[tokio::test]
    async fn vault_root_read_failures_are_cached_briefly() {
        let fake = crate::test_support::fake_tree_ownership_fixture().await;
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let calls = Arc::new(std::sync::Mutex::new(0usize));
        let counted = calls.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move || {
                let counted = counted.clone();
                async move {
                    *counted.lock().unwrap() += 1;
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        configure_issuance_rpc(
            &mut processor,
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let request = clearance(fake);
        for _ in 0..3 {
            let error = processor.process_clearance(&request).await.unwrap_err();
            assert!(
                matches!(&error, ServerError::Internal(message) if message.starts_with("vault read failed")),
                "{error}"
            );
            assert!(error.is_retriable());
        }
        // One failed eth_chainId for all three attempts.
        assert_eq!(*calls.lock().unwrap(), 1);
        assert!(processor.store.get_all_nullifiers().is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn legacy_clearance_flag_allows_proofless_only_when_enabled() {
        let fixture = crate::test_support::ownership_fixture().await;
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.allow_legacy_clearance = true;
        processor.config.legacy_clearance_max_per_minute = 2;
        let proofless = |n| ClearanceRequest {
            withdrawal_nullifier: Felt252::from_u64(n),
            ownership_proof: None,
        };
        processor.process_clearance(&proofless(1)).await.unwrap();
        assert_eq!(
            processor
                .store
                .clearance_auth(&Felt252::from_u64(1))
                .unwrap()
                .as_deref(),
            Some("legacy")
        );
        // Re-requesting an existing reservation creates no new row.
        processor.process_clearance(&proofless(1)).await.unwrap();
        // The in-process cap bounds new proof-less rows per minute.
        *processor.legacy_clearances.lock().unwrap() = LegacyClearanceWindow {
            minute: current_timestamp() / 60,
            admitted: 2,
            ..LegacyClearanceWindow::default()
        };
        let error = processor
            .process_clearance(&proofless(2))
            .await
            .unwrap_err();
        assert!(matches!(error, ServerError::LegacyClearanceCapacity { .. }));
        assert!(error.is_retriable());
        assert!(processor
            .store
            .lookup_by_nullifier(&Felt252::from_u64(2))
            .is_none());
        // An invalid proof is still rejected while the flag is on.
        processor.update_root(fixture.root);
        let mut tampered = clearance(fixture);
        tampered
            .ownership_proof
            .as_mut()
            .unwrap()
            .public_inputs
            .final_balance += 1;
        assert!(matches!(
            processor.process_clearance(&tampered).await,
            Err(ServerError::InvalidProof(_))
        ));
        assert!(processor
            .store
            .lookup_by_nullifier(&tampered.withdrawal_nullifier)
            .is_none());
    }

    #[test]
    fn legacy_clearance_window_resets_each_minute_and_logs_once() {
        let start = 1_700_000_040;
        let mut window = LegacyClearanceWindow::default();
        assert!(window.admit(start, 2).is_ok());
        assert!(window.admit(start + 1, 2).is_ok());
        let refusals: Vec<_> = [start + 15, start + 59]
            .into_iter()
            .map(|now| window.admit(now, 2).unwrap_err())
            .map(|r| (r.retry_after_seconds, r.first_in_window, r.rejected_total))
            .collect();
        assert_eq!(refusals, [(45, true, 1), (1, false, 2)]);
        assert_eq!(
            window.usage(start + 59, 2),
            LegacyClearanceUsage {
                window_used: 2,
                window_limit: 2,
                rejected_total: 2
            }
        );
        // A new minute brings a new budget and one more log line; the
        // rejection count is cumulative.
        assert_eq!(window.usage(start + 60, 2).window_used, 0);
        assert!(window.admit(start + 60, 2).is_ok());
        let refusal = window.admit(start + 60, 1).unwrap_err();
        assert_eq!(
            (refusal.retry_after_seconds, refusal.first_in_window),
            (60, true)
        );
        assert_eq!(refusal.rejected_total, 3);
    }

    /// Start a scenario on the real clock well inside one budget window.
    async fn inside_one_legacy_window() {
        let elapsed = current_timestamp() % 60;
        if elapsed > 50 {
            tokio::time::sleep(Duration::from_secs(60 - elapsed)).await;
        }
    }

    #[tokio::test]
    async fn junk_proofless_clearances_never_starve_an_ownership_proof() {
        let fixture = crate::test_support::ownership_fixture().await;
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.allow_legacy_clearance = true;
        processor.config.legacy_clearance_max_per_minute = 60;
        processor.update_root(fixture.root);
        inside_one_legacy_window().await;
        // Anyone can spend the shared budget on junk nullifiers.
        for junk in 0..60 {
            processor
                .process_clearance(&ClearanceRequest {
                    withdrawal_nullifier: Felt252::from_u64(0xdead_0000 + junk),
                    ownership_proof: None,
                })
                .await
                .unwrap();
        }
        // The owner's proof-less request is told that the budget, not
        // verification capacity, is exhausted, and reserves nothing...
        let nullifier = fixture.plan.public_inputs.withdrawal_nullifier;
        let error = processor
            .process_clearance(&ClearanceRequest {
                withdrawal_nullifier: nullifier,
                ownership_proof: None,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                ServerError::LegacyClearanceCapacity { retry_after_seconds }
                    if (1..=60).contains(&retry_after_seconds)
            ),
            "{error:?}"
        );
        assert_eq!(error.error_code(), "legacy_clearance_capacity");
        assert!(processor.store.lookup_by_nullifier(&nullifier).is_none());
        // ...and its ownership proof never consults the budget.
        processor
            .process_clearance(&clearance(fixture))
            .await
            .unwrap();
        assert_eq!(
            processor
                .store
                .clearance_auth(&nullifier)
                .unwrap()
                .as_deref(),
            Some("ownership_proof")
        );
        assert_eq!(processor.store.get_all_nullifiers().len(), 61);
        assert_eq!(
            processor.legacy_clearance_usage(),
            LegacyClearanceUsage {
                window_used: 60,
                window_limit: 60,
                rejected_total: 1
            }
        );
    }

    #[tokio::test]
    async fn clearance_never_reserves_lease_reserved_nullifier() {
        let fixture = crate::test_support::ownership_fixture().await;
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.update_root(fixture.root);
        let mut lease = lease_request_for(&processor, "spent-by-request", 1, None);
        lease.public_inputs.request_nullifier = fixture.plan.public_inputs.withdrawal_nullifier;
        processor.store.reserve_openrouter_lease(&lease).unwrap();
        assert!(matches!(
            processor.process_clearance(&clearance(fixture)).await,
            Err(ServerError::NullifierUsed)
        ));
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&lease.public_inputs.request_nullifier)
                .unwrap()
                .status,
            NullifierStatus::Reserved
        );
    }

    #[tokio::test]
    async fn clearance_verification_capacity_is_bounded() {
        let fixture = crate::test_support::ownership_fixture().await;
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.update_root(fixture.root);
        let permits = processor
            .clearance_permits
            .acquire_many(CLEARANCE_VERIFY_PERMITS as u32)
            .await
            .unwrap();
        let error = processor
            .process_clearance(&clearance(fixture))
            .await
            .unwrap_err();
        assert!(matches!(error, ServerError::CapacityExhausted));
        assert!(processor.store.get_all_nullifiers().is_empty());
        drop(permits);
        processor
            .process_clearance(&clearance(fixture))
            .await
            .unwrap();
    }
}
