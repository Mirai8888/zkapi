//! Durable event-to-submission loop for v2 escape challenges.
//!
//! The configured RPC must expose an operator-controlled transaction signer.
//! Keys are never loaded by this service; the sender must be dedicated to it.
//! Only Finalized server transcripts are challenge evidence. Challenges are
//! EIP-1559 transactions whose fees the daemon proposes and escalates, within
//! its caps and a per-transaction fee ceiling, by same-nonce replacement as
//! deadlines approach. Every obligation's state, deadline and blocking reason
//! is published on the operator status endpoint (see `challenge_status`).

use crate::{
    challenge_status::{
        self, unix_now, AlarmPolicy, BlockedReason, ChainStatus, ChallengeStatus,
        DetachedNonceStatus, EvidenceKind, IndexerState, IndexerStatus, MissedRecord,
        ObligationState, ObligationStatus, PollStatus, RemainingThresholds, SenderStatus, Severity,
        StatusHandle,
    },
    error::ServerError,
    nullifier_store::{DeploymentBinding, NullifierStore},
    watcher::{ChallengeWatcher, EvidenceStatus, SettlementProgress},
};
use anyhow::{anyhow, bail, ensure, Context};
use base64::Engine;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use zkapi_proof::compact::RequestVerifier;
use zkapi_types::{
    wire::{Groth16ProofWire, ProofBackendWire},
    Felt252, MERKLE_DEPTH,
};

const ESCAPE_EVENT: &str =
    "EscapeWithdrawalInitiated(uint32,uint256,uint128,address,uint64,uint256)";
const GWEI: u128 = 1_000_000_000;
/// Older candidate hashes beyond this many are dropped from a nonce's record.
const MAX_SUPERSEDED_HASHES: usize = 32;
/// The signer may make several sequential upstream calls for one send.
const SEND_TIMEOUT: Duration = Duration::from_secs(95);
const INDEXER_TIMEOUT: Duration = Duration::from_secs(10);
/// Challenge gas assumed for balance alarms before any estimate (a measured
/// real-Groth16 challenge is about 6.3M gas, plus the daemon's 20% margin).
const DEFAULT_CHALLENGE_GAS: u128 = 7_600_000;
/// Critical obligations and an indexer divergence are re-logged this often.
const RELOG_SECONDS: u64 = 300;
/// Indexer-listed escapes missing from the checkpoint checked per poll.
const MAX_ESCAPE_CHECKS_PER_POLL: usize = 64;
/// A listed note the vault holds no escape for is still read on every
/// listing until reads this far apart have found none: the indexer's head
/// view can be ahead of this daemon's RPC, so a fresh escape can read as
/// absent at first.
const DEAD_ESCAPE_CONFIRM_SECONDS: u64 = 60;
/// After that, it is read again only once this many listings have passed,
/// so such entries cannot spend the per-poll budget of the others.
const DEAD_ESCAPE_RECHECK_POLLS: u64 = 16;
const MAX_ERROR_CHARS: usize = 512;

/// EIP-1559 fee proposals. The signer enforces its own caps, which must be at
/// least these. A same-nonce replacement raises the tip by the minimum valid
/// step and the fee cap by `bump_percent`; two replacements stay reserved for
/// the critical threshold. Every bid keeps gas limit x maxFeePerGas within
/// the transaction fee ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeePolicy {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub priority_fee_per_gas: u128,
    /// Highest gas limit x maxFeePerGas of one challenge transaction (wei).
    pub tx_fee_cap_wei: u128,
    pub bump_after_blocks: u64,
    pub bump_percent: u64,
}

impl FeePolicy {
    pub const DEFAULT_PRIORITY_FEE_PER_GAS: u128 = 2 * GWEI;
    /// 1 ether, the default `--rpc.txfeecap` of geth and reth: their RPC
    /// refuses a transaction whose gas limit x maxFeePerGas exceeds it.
    pub const DEFAULT_TX_FEE_CAP_WEI: u128 = 1_000_000_000_000_000_000;
    pub const DEFAULT_BUMP_AFTER_BLOCKS: u64 = 3;
    pub const DEFAULT_BUMP_PERCENT: u64 = 25;

    pub fn new(max_fee_per_gas: u128, max_priority_fee_per_gas: u128) -> Self {
        Self {
            max_fee_per_gas,
            max_priority_fee_per_gas,
            priority_fee_per_gas: Self::DEFAULT_PRIORITY_FEE_PER_GAS,
            tx_fee_cap_wei: Self::DEFAULT_TX_FEE_CAP_WEI,
            bump_after_blocks: Self::DEFAULT_BUMP_AFTER_BLOCKS,
            bump_percent: Self::DEFAULT_BUMP_PERCENT,
        }
    }

    /// A transaction fee ceiling as the signer reads it: a positive decimal
    /// wei amount without sign, leading zeros or spaces; empty means the
    /// default.
    pub fn parse_tx_fee_cap(value: &str) -> Result<u128, String> {
        if value.is_empty() {
            return Ok(Self::DEFAULT_TX_FEE_CAP_WEI);
        }
        if value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("must be a positive decimal integer in wei".into());
        }
        value
            .parse()
            .map_err(|_| "exceeds the largest supported amount".into())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.priority_fee_per_gas > 0,
            "priority fee per gas must be positive"
        );
        ensure!(
            self.max_priority_fee_per_gas <= self.max_fee_per_gas,
            "max priority fee per gas must not exceed max fee per gas"
        );
        // Nodes accept a same-nonce replacement only when both fees rise by
        // at least 10%, so the tip needs room above the first bid: twice the
        // first tip allows about five replacements before the critical
        // threshold and the two reserved for it.
        ensure!(
            self.max_priority_fee_per_gas >= self.priority_fee_per_gas.saturating_mul(2),
            "max priority fee per gas must be at least twice the priority fee per gas, leaving tip headroom for same-nonce replacement"
        );
        ensure!(
            self.max_fee_per_gas <= u128::MAX / 1_000,
            "max fee per gas is implausibly large"
        );
        ensure!(
            self.tx_fee_cap_wei > 0,
            "transaction fee cap must be positive"
        );
        ensure!(
            self.bump_after_blocks >= 1,
            "fee bump interval must be at least one block"
        );
        ensure!(
            (10..=100).contains(&self.bump_percent),
            "fee bump percent must be between 10 and 100"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ChallengeServiceConfig {
    pub rpc_url: String,
    pub indexer_url: String,
    pub sender: String,
    pub contract_address: Felt252,
    pub chain_id: u64,
    pub from_block: u64,
    pub confirmations: u64,
    pub checkpoint: PathBuf,
    pub proof_setup_dir: PathBuf,
    pub fee: FeePolicy,
    pub alarms: AlarmPolicy,
}

/// Attempts on one reserved nonce. Every field is written before a send, so a
/// crash or ambiguous result never loses what may have been broadcast.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct NonceAttempts {
    /// Earlier candidate hashes on the nonce, oldest first. Any may still mine.
    #[serde(default)]
    superseded_hashes: Vec<String>,
    /// Fees (0x-hex wei) of the latest attempt. A send on a nonce that an
    /// earlier attempt may hold must outbid them, so they are the highest of
    /// any attempt that may still be in a pool; a re-send of a nonce that no
    /// attempt holds may lower them to the current caps and ceiling.
    #[serde(default)]
    max_fee_per_gas: Option<String>,
    #[serde(default)]
    max_priority_fee_per_gas: Option<String>,
    /// Gas limit of the latest attempt.
    #[serde(default)]
    gas_limit: Option<u64>,
    #[serde(default)]
    submitted_block: Option<u64>,
    #[serde(default)]
    attempts: u32,
    /// The nonce was reserved by an older daemon that kept no attempt record,
    /// so it may hold an attempt this record does not describe.
    #[serde(default)]
    unrecorded_attempt: bool,
    /// Digest of (noteId, request inputs, proof) first sent on the nonce;
    /// replacements may change only siblings, gas and fees.
    #[serde(default)]
    evidence_digest: Option<String>,
    /// The vault root the latest attempt's siblings hash to.
    #[serde(default)]
    submitted_root: Option<Felt252>,
    /// An attempt may hold the nonce without a known hash, so a re-send must
    /// be a valid replacement of the persisted fees.
    #[serde(default)]
    unknown_attempt: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PendingChallenge {
    nullifier: Felt252,
    transaction_hash: Option<String>,
    /// Persist before sending so an ambiguous RPC failure retries the same nonce.
    nonce: Option<u64>,
    #[serde(default)]
    deadline_reported: bool,
    #[serde(default)]
    first_seen_at: Option<u64>,
    #[serde(default)]
    challenge_deadline: Option<u64>,
    #[serde(flatten)]
    attempt: NonceAttempts,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Checkpoint {
    sender: String,
    chain_id: u64,
    contract_address: Felt252,
    from_block: u64,
    next_block: u64,
    last_block_hash: Option<String>,
    pending: BTreeMap<u32, PendingChallenge>,
    /// A completed/replaced withdrawal must not discard an in-flight nonce.
    #[serde(default)]
    detached_nonces: BTreeMap<u64, DetachedNonce>,
    #[serde(default)]
    missed_total: u64,
    #[serde(default)]
    last_missed: Option<MissedRecord>,
    /// Timestamp of the last block the event scan covered.
    #[serde(default)]
    scanned_through_timestamp: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DetachedNonce {
    note_id: u32,
    nullifier: Felt252,
    transaction_hash: Option<String>,
    #[serde(flatten)]
    attempt: NonceAttempts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NonceState {
    Free,
    /// Reserved, and no known or hidden attempt occupies it: it was dropped,
    /// refused before broadcast, or never sent.
    Reserved,
    /// Reserved and possibly held by an attempt without a known hash, so a
    /// re-send must be a valid replacement of the persisted fees.
    Held,
    Pending,
    Mined,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HeadInfo {
    number: u64,
    timestamp: u64,
    base_fee: Option<u128>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fees {
    pub max_fee: u128,
    pub tip: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FeePlan {
    /// No earlier attempt can occupy the nonce.
    First,
    /// Re-send after every earlier attempt left the pools.
    Resend(Fees),
    /// Must be a valid replacement of every earlier attempt.
    Bump(Fees),
}

#[derive(Clone, Debug)]
struct Evaluation {
    state: ObligationState,
    evidence: Option<EvidenceKind>,
    blocked: Option<BlockedReason>,
    detail: Option<String>,
    settlement: Option<SettlementProgress>,
    evaluated_at: u64,
}

impl Evaluation {
    fn new(state: ObligationState, evidence: Option<EvidenceKind>) -> Self {
        Self {
            state,
            evidence,
            blocked: None,
            detail: None,
            settlement: None,
            evaluated_at: 0,
        }
    }

    fn blocked(mut self, reason: BlockedReason, detail: impl Into<String>) -> Self {
        self.blocked = Some(reason);
        self.detail = Some(bounded(&detail.into()));
        self
    }

    fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(bounded(&detail.into()));
        self
    }
}

struct WithdrawalState {
    exists: bool,
    nullifier: Felt252,
    deadline: u64,
}

/// A note the indexer lists as pending while the vault holds no escape for
/// it: the list lags the vault, or its log source missed the escape's end
/// and keeps the entry until a resync. Never kept for a tracked note, whose
/// vault record every poll reads.
struct DeadEscape {
    /// The listed nullifier; another one listed for the note is read at once.
    nullifier: Felt252,
    /// When the vault was first read without the escape.
    first_seen: u64,
    /// When the vault was last read without it.
    last_seen: u64,
    /// The listing in which the vault was last read for it.
    checked_at: u64,
    /// The head of a poll after the first read without the escape, so at or
    /// above that read's block.
    read_by: Option<u64>,
    /// A list served at a block between two reads without the escape named
    /// the note: the indexer has processed a block in which the vault held
    /// none, so its list does not merely lag the vault.
    bracketed: bool,
}

impl DeadEscape {
    /// Reads at least `seconds` apart have found no escape.
    fn absent_for(&self, seconds: u64) -> bool {
        self.last_seen.saturating_sub(self.first_seen) >= seconds
    }

    /// A read in this poll, at or above its `head`, brackets a list served
    /// at block `listed` with the first read: `listed` lies from `read_by`
    /// up to `head`. A list served without its block cannot be placed, and
    /// only time decides.
    fn brackets(&self, listed: Option<u64>, head: u64) -> bool {
        listed.is_none_or(|block| self.read_by.is_some_and(|read| read <= block) && block <= head)
    }

    /// Reported as a disagreement: reads `warning` seconds apart have found
    /// no escape, and a list served between two of them named the note.
    fn reported(&self, warning: u64) -> bool {
        self.bracketed && self.absent_for(warning)
    }

    /// Skipped at this listing: confirmed, and between its re-reads, unless
    /// its report, due `warning` seconds after the first read, waits for a
    /// read and this listing (`brackets`) or an earlier one can complete it.
    fn resting(&self, listing: u64, now: u64, warning: u64, brackets: bool) -> bool {
        self.absent_for(DEAD_ESCAPE_CONFIRM_SECONDS)
            && listing - self.checked_at < DEAD_ESCAPE_RECHECK_POLLS
            && (self.reported(warning)
                || now.saturating_sub(self.first_seen) < warning
                || !(self.bracketed || brackets))
    }
}

/// A JSON-RPC error object. Display stays `"{method}: {error_json}"`.
#[derive(Debug)]
pub(crate) struct RpcError {
    method: String,
    error: Value,
}

impl RpcError {
    fn code(&self) -> Option<i64> {
        self.error.get("code").and_then(Value::as_i64)
    }

    fn reason(&self) -> Option<&str> {
        self.error.get("data")?.get("reason")?.as_str()
    }

    fn transaction_hash(&self) -> Option<String> {
        let hash = self.error.get("data")?.get("transaction_hash")?.as_str()?;
        let digits = hash.strip_prefix("0x")?;
        (digits.len() == 64 && digits.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.method, self.error)
    }
}

impl std::error::Error for RpcError {}

/// An HTTP-level RPC failure. It never includes the URL, which may embed a key.
#[derive(Debug)]
struct TransportError {
    method: String,
    message: String,
    /// No connection was made, so the request never reached the signer.
    unsent: bool,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.method, self.message)
    }
}

impl std::error::Error for TransportError {}

/// Startup check of the server database's deployment binding.
#[derive(Debug)]
pub enum DeploymentCheckError {
    /// The database or vault definitively belongs to another deployment.
    Mismatch(String),
    /// The check could not complete; retry.
    Unavailable(anyhow::Error),
}

impl std::fmt::Display for DeploymentCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mismatch(message) => write!(f, "{message}"),
            Self::Unavailable(error) => write!(f, "deployment binding check unavailable: {error}"),
        }
    }
}

impl std::error::Error for DeploymentCheckError {}

/// Outcome classes of a failed `eth_sendTransaction`.
enum SendFailure {
    /// -32602/-32601/-32003: a definitive refusal; nothing was broadcast.
    Refused(Option<String>),
    /// A connection never made, or a signer-reported failure before
    /// broadcast (transient); nothing was broadcast.
    NotBroadcast(BlockedReason),
    /// Possibly broadcast, with the candidate hash when the signer reports it.
    Ambiguous(Option<String>),
}

enum IndexerFailure {
    Status(u16),
    Transport(String),
    Decode(String),
}

impl std::fmt::Display for IndexerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(code) => write!(f, "HTTP {code}"),
            Self::Transport(error) | Self::Decode(error) => write!(f, "{error}"),
        }
    }
}

pub struct ChallengeService {
    config: ChallengeServiceConfig,
    client: reqwest::Client,
    watcher: ChallengeWatcher,
    verifier: RequestVerifier,
    checkpoint: Checkpoint,
    status: StatusHandle,
    started_at: u64,
    // Vault immutables, read once per process.
    challenge_period: Option<u64>,
    vault_state_key: Option<(Felt252, Felt252)>,
    vault_warning: Option<String>,
    startup_warning: Option<String>,
    config_warnings: Vec<String>,
    head: Option<HeadInfo>,
    /// Latest head number and the wall time it was first observed.
    head_seen: Option<(u64, u64)>,
    vault_root: Option<Felt252>,
    /// Latest-block nonce count from the most recent nonce reconciliation.
    latest_nonce_count: Option<u64>,
    poll: PollStatus,
    indexer: IndexerStatus,
    indexer_logged_at: Option<u64>,
    /// Pending-escapes listings processed since the daemon started.
    escape_listings: u64,
    /// The listed note the next listing's vault reads start at.
    escape_cursor: u32,
    /// Listed notes the vault held no escape for when last read.
    dead_escapes: BTreeMap<u32, DeadEscape>,
    sender: SenderStatus,
    sender_balance: Option<u128>,
    /// The signer's transaction fee cap, from `zkapi_signerStatus` or a
    /// `tx_fee_above_cap` refusal.
    signer_tx_fee_cap: Option<u128>,
    /// The lowest transaction fee (gas limit x maxFeePerGas) that the signer's
    /// node refused as above its RPC fee cap (`upstream_tx_fee_cap`). Kept
    /// until restart; the node's cap is never reported.
    node_refused_tx_fee: Option<u128>,
    last_observed_at: Option<u64>,
    last_gas: Option<u128>,
    evaluations: BTreeMap<u32, Evaluation>,
    previous_evaluations: BTreeMap<u32, Evaluation>,
    /// Per note: when it became blocked, and for how many evaluations.
    blocked_since: BTreeMap<u32, (u64, u32)>,
    /// Fees read from a pending transaction whose fees were not persisted.
    observed_fees: BTreeMap<u32, Fees>,
    nonce_failures: BTreeMap<u32, String>,
    detached_status: Vec<DetachedNonceStatus>,
    logged: BTreeMap<u32, (ObligationState, Severity, Option<BlockedReason>, u64)>,
}

impl ChallengeService {
    pub fn new(config: ChallengeServiceConfig, store: Arc<NullifierStore>) -> anyhow::Result<Self> {
        ensure!(
            config.contract_address.as_bytes()[..12]
                .iter()
                .all(|byte| *byte == 0),
            "vault address exceeds 20 bytes"
        );
        let sender = config
            .sender
            .strip_prefix("0x")
            .context("sender must be a 0x-prefixed address")?;
        ensure!(
            hex::decode(sender)?.len() == 20,
            "sender must be a 20-byte address"
        );
        config.fee.validate()?;
        config.alarms.validate().map_err(anyhow::Error::msg)?;
        let checkpoint: Checkpoint = if config.checkpoint.exists() {
            serde_json::from_slice(&std::fs::read(&config.checkpoint)?)?
        } else {
            Checkpoint {
                sender: config.sender.to_ascii_lowercase(),
                chain_id: config.chain_id,
                contract_address: config.contract_address,
                from_block: config.from_block,
                next_block: config.from_block,
                last_block_hash: None,
                pending: BTreeMap::new(),
                detached_nonces: BTreeMap::new(),
                missed_total: 0,
                last_missed: None,
                scanned_through_timestamp: None,
            }
        };
        ensure!(
            checkpoint.sender == config.sender.to_ascii_lowercase()
                && checkpoint.chain_id == config.chain_id
                && checkpoint.contract_address == config.contract_address
                && checkpoint.from_block == config.from_block,
            "challenge checkpoint belongs to another deployment"
        );
        let mut config_warnings = Vec::new();
        if config.chain_id == 1 && config.fee.max_fee_per_gas < 100 * GWEI {
            config_warnings.push("fee cap below typical Mainnet base-fee peaks".to_string());
        }
        let started_at = unix_now();
        let sender = SenderStatus {
            address: config.sender.to_ascii_lowercase(),
            // No challenge can lock more than the transaction fee ceiling.
            min_balance_wei: config
                .alarms
                .min_sender_balance_wei
                .unwrap_or(
                    DEFAULT_CHALLENGE_GAS
                        .saturating_mul(config.fee.max_fee_per_gas)
                        .min(config.fee.tx_fee_cap_wei),
                )
                .to_string(),
            max_fee_per_gas_wei: config.fee.max_fee_per_gas.to_string(),
            max_priority_fee_per_gas_wei: config.fee.max_priority_fee_per_gas.to_string(),
            priority_fee_per_gas_wei: config.fee.priority_fee_per_gas.to_string(),
            tx_fee_cap_wei: config.fee.tx_fee_cap_wei.to_string(),
            ..Default::default()
        };
        let status = Arc::new(RwLock::new(ChallengeStatus::initial(
            ChainStatus::default(),
            sender.clone(),
            started_at,
        )));
        let mut service = Self {
            verifier: RequestVerifier::load(&config.proof_setup_dir)?,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
            watcher: ChallengeWatcher::new(store),
            checkpoint,
            status,
            started_at,
            challenge_period: None,
            vault_state_key: None,
            vault_warning: None,
            startup_warning: None,
            config_warnings,
            head: None,
            head_seen: None,
            vault_root: None,
            latest_nonce_count: None,
            poll: PollStatus::default(),
            indexer: IndexerStatus::default(),
            indexer_logged_at: None,
            escape_listings: 0,
            escape_cursor: 0,
            dead_escapes: BTreeMap::new(),
            sender,
            sender_balance: None,
            signer_tx_fee_cap: None,
            node_refused_tx_fee: None,
            last_observed_at: None,
            last_gas: None,
            evaluations: BTreeMap::new(),
            previous_evaluations: BTreeMap::new(),
            blocked_since: BTreeMap::new(),
            observed_fees: BTreeMap::new(),
            nonce_failures: BTreeMap::new(),
            detached_status: Vec::new(),
            logged: BTreeMap::new(),
            config,
        };
        service.publish();
        Ok(service)
    }

    /// Shared handle for the status listener.
    pub fn status_handle(&self) -> StatusHandle {
        self.status.clone()
    }

    /// The status as the listener would serve it now.
    pub fn status(&self) -> ChallengeStatus {
        let snapshot = match self.status.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        challenge_status::evaluate(&snapshot, &self.config.alarms, unix_now())
    }

    /// Refuse a server database that is not bound to this deployment: the
    /// binding row must name this chain and vault, and its state signing key
    /// must equal the vault's immutable key read over the RPC. A daemon on the
    /// wrong database would report every fraudulent escape as no evidence.
    pub async fn verify_deployment_binding(
        &mut self,
    ) -> Result<DeploymentBinding, DeploymentCheckError> {
        let result = self.check_deployment_binding().await;
        self.startup_warning = match &result {
            Ok(_) => None,
            Err(error) => Some(format!("deployment binding not verified: {error}")),
        };
        self.publish();
        result
    }

    async fn check_deployment_binding(
        &mut self,
    ) -> Result<DeploymentBinding, DeploymentCheckError> {
        let binding = self
            .watcher
            .deployment_binding()
            .map_err(|error| DeploymentCheckError::Unavailable(anyhow!(error)))?
            .ok_or_else(|| {
                DeploymentCheckError::Mismatch(
                    "server database has no deployment binding; upgrade and start the API server first"
                        .into(),
                )
            })?;
        if binding.chain_id != self.config.chain_id
            || binding.contract_address != self.vault_address()
        {
            return Err(DeploymentCheckError::Mismatch(format!(
                "server database is bound to chain {} vault {}, not chain {} vault {}",
                binding.chain_id,
                binding.contract_address,
                self.config.chain_id,
                self.vault_address()
            )));
        }
        let chain = self
            .rpc("eth_chainId", json!([]))
            .await
            .and_then(|value| quantity(&value))
            .map_err(DeploymentCheckError::Unavailable)?;
        if chain != self.config.chain_id {
            return Err(DeploymentCheckError::Mismatch(
                "RPC chain ID does not match challenge deployment".into(),
            ));
        }
        let key = self
            .read_state_key()
            .await
            .map_err(DeploymentCheckError::Unavailable)?;
        if key != (binding.state_signing_key.x, binding.state_signing_key.y) {
            return Err(DeploymentCheckError::Mismatch(
                "server database state signing key differs from the vault's stateSigningKeyX/Y"
                    .into(),
            ));
        }
        self.vault_state_key = Some(key);
        Ok(binding)
    }

    /// Scan a bounded event range, persist it, then reconcile and submit work.
    /// Errors leave the durable queue intact for the next poll or restart.
    pub async fn poll_once(&mut self) -> anyhow::Result<()> {
        self.poll.last_started_at = Some(unix_now());
        if let Ok(mut status) = self.status.write() {
            status.poll.last_started_at = self.poll.last_started_at;
        }
        let mut evaluated = BTreeSet::new();
        let mut scanned_head = None;
        let result = self.poll_inner(&mut evaluated, &mut scanned_head).await;
        if let Some(head) = scanned_head {
            // Every obligation the loop did not reach is still observed, so
            // its deadline and blocking reason stay visible.
            let blocker = self.queue_blocker();
            let unevaluated: Vec<u32> = self
                .checkpoint
                .pending
                .keys()
                .filter(|note| !evaluated.contains(note))
                .copied()
                .collect();
            for note in unevaluated {
                let blocked = match self.nonce_failures.remove(&note) {
                    Some(error) => Some((BlockedReason::RpcError, error)),
                    None => match blocker {
                        Some((nonce, owner)) => Some((
                            BlockedReason::NonceBlocked,
                            format!("queued behind unresolved nonce {nonce} (note {owner})"),
                        )),
                        None => result.as_ref().err().map(|error| {
                            (
                                BlockedReason::RpcError,
                                format!("poll aborted before this obligation: {error}"),
                            )
                        }),
                    },
                };
                if let Err(error) = self.observe_only(note, &head, blocked).await {
                    self.evaluate_failure(note, BlockedReason::RpcError, &error);
                }
            }
        }
        self.nonce_failures.clear();
        self.finish_poll(&result);
        result
    }

    async fn poll_inner(
        &mut self,
        evaluated: &mut BTreeSet<u32>,
        scanned_head: &mut Option<HeadInfo>,
    ) -> anyhow::Result<()> {
        let chain = self.rpc("eth_chainId", json!([])).await?;
        ensure!(
            quantity(&chain)? == self.config.chain_id,
            "RPC chain ID does not match challenge deployment"
        );
        let head = self.fetch_head().await?;
        self.scan_events(head.number).await?;
        self.poll.last_scan_success_at = Some(unix_now());
        self.previous_evaluations = std::mem::take(&mut self.evaluations);
        *scanned_head = Some(head.clone());
        self.load_vault_constants().await;
        self.sync_pending_escapes(head.number).await?;
        if self.observation_due() {
            self.observe_sender().await;
            self.observe_indexer(&head).await;
        }
        self.reconcile_detached_nonces().await?;
        // Each note gets a fresh current-root path. A previous successful
        // challenge can change that root before the next submission.
        let mut notes: Vec<_> = self.checkpoint.pending.keys().copied().collect();
        // Durable ambiguous sends from *previous* polls must run before newly
        // eligible notes, irrespective of note ID or event arrival order.
        notes.sort_by_key(|note| {
            let pending = &self.checkpoint.pending[note];
            (
                pending.nonce.is_none() || pending.transaction_hash.is_some(),
                pending.nonce,
                *note,
            )
        });
        let mut first_error = None;
        for note in notes {
            // Nonce ownership is independent of the withdrawal's deadline,
            // evidence and current state. In particular, an ambiguous send
            // which has mined must not prevent other notes from progressing.
            let nonce_state = match self.reconcile_nonce(note).await {
                Ok(state) => state,
                Err(error) => {
                    self.nonce_failures
                        .insert(note, format!("nonce status unavailable: {error}"));
                    first_error.get_or_insert(error);
                    break; // No safe new allocation when nonce status is unknown.
                }
            };
            evaluated.insert(note);
            let owned_nonce = self.checkpoint.pending[&note].nonce;
            if let Err(error) = self.reconcile(note, nonce_state, &head).await {
                tracing::error!(note_id = note, error = %error, "escape challenge requires retry");
                if !self.evaluations.contains_key(&note) {
                    self.evaluate_failure(note, BlockedReason::RpcError, &error);
                }
                if first_error.is_none() {
                    first_error = Some(error);
                }
                // Invalid evidence or a stale path on one note must not starve
                // other notes. An ambiguous send is different: resolve its
                // reserved nonce before asking the signer for another one.
            }
            if nonce_state != NonceState::Mined
                && (self.checkpoint.pending.get(&note).is_some_and(|pending| {
                    pending.nonce.is_some() && pending.transaction_hash.is_none()
                }) || owned_nonce
                    .is_some_and(|nonce| self.checkpoint.detached_nonces.contains_key(&nonce)))
            {
                break;
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn fetch_head(&mut self) -> anyhow::Result<HeadInfo> {
        let block = self
            .rpc("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let number = match block.get("number").filter(|value| !value.is_null()) {
            Some(number) => quantity(number)?,
            None => quantity(&self.rpc("eth_blockNumber", json!([])).await?)?,
        };
        let head = HeadInfo {
            number,
            timestamp: quantity(&block["timestamp"]).context("latest block lacks a timestamp")?,
            base_fee: block
                .get("baseFeePerGas")
                .filter(|value| !value.is_null())
                .map(quantity_u128)
                .transpose()?,
        };
        if self.head_seen.is_none_or(|(seen, _)| seen != number) {
            self.head_seen = Some((number, unix_now()));
        }
        self.head = Some(head.clone());
        Ok(head)
    }

    async fn scan_events(&mut self, latest: u64) -> anyhow::Result<()> {
        if let Some(expected) = &self.checkpoint.last_block_hash {
            let block = self
                .rpc(
                    "eth_getBlockByNumber",
                    json!([format!("0x{:x}", self.checkpoint.next_block - 1), false]),
                )
                .await?;
            if block.get("hash").and_then(Value::as_str) != Some(expected.as_str()) {
                tracing::warn!("challenge cursor was reorganized; replaying deployment events");
                self.checkpoint.next_block = self.config.from_block;
                self.checkpoint.last_block_hash = None;
                self.persist()?;
            }
        }
        let Some(safe_head) = latest.checked_sub(self.config.confirmations) else {
            return Ok(());
        };
        if self.checkpoint.next_block > safe_head {
            return Ok(());
        }
        let to = safe_head.min(self.checkpoint.next_block.saturating_add(999));
        let before = self
            .rpc("eth_getBlockByNumber", json!([format!("0x{to:x}"), false]))
            .await?;
        let before_hash = before["hash"].as_str().context("scan block lacks hash")?;
        let logs = self.rpc("eth_getLogs", json!([{
            "address": self.vault_address(), "fromBlock": format!("0x{:x}", self.checkpoint.next_block),
            "toBlock": format!("0x{to:x}"), "topics": [format!("0x{}", hex::encode(Keccak256::digest(ESCAPE_EVENT.as_bytes())))]
        }])).await?;
        let after = self
            .rpc("eth_getBlockByNumber", json!([format!("0x{to:x}"), false]))
            .await?;
        let after_hash = after["hash"].as_str().context("scan block lacks hash")?;
        ensure!(
            before_hash == after_hash,
            "chain reorganized while reading escape events; retrying range"
        );
        for log in logs.as_array().context("RPC logs must be an array")? {
            if log.get("removed").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let topics = log["topics"]
                .as_array()
                .context("escape event lacks topics")?;
            ensure!(topics.len() == 2, "malformed escape event topics");
            let note = quantity(&topics[1])?;
            ensure!(note <= u32::MAX as u64, "escape note ID exceeds uint32");
            let words = words(&log["data"])?;
            ensure!(words.len() == 5, "malformed escape event data");
            self.track_escape(note as u32, words[0], felt_u64(&words[3]).ok());
        }
        self.checkpoint.last_block_hash = Some(after_hash.to_owned());
        self.checkpoint.next_block = to.saturating_add(1);
        self.checkpoint.scanned_through_timestamp = after
            .get("timestamp")
            .and_then(|value| quantity(value).ok());
        self.persist()
    }

    /// Track an escape from an event or the indexer's pending list. The
    /// caller persists the checkpoint.
    fn track_escape(&mut self, note: u32, nullifier: Felt252, deadline: Option<u64>) -> bool {
        if let Some(existing) = self.checkpoint.pending.get_mut(&note) {
            if existing.nullifier == nullifier {
                if existing.challenge_deadline.is_none() && deadline.is_some() {
                    existing.challenge_deadline = deadline;
                    return true;
                }
                return false;
            }
        }
        self.detach_nonce(note);
        self.forget_observations(note);
        let mut pending = PendingChallenge {
            nullifier,
            challenge_deadline: deadline,
            first_seen_at: Some(unix_now()),
            ..Default::default()
        };
        // Replaying historical events may temporarily replace this note and
        // then restore its current nullifier. Recover its exact reservation
        // instead of stranding it.
        let restored_nonce = self
            .checkpoint
            .detached_nonces
            .iter()
            .find(|(_, entry)| entry.note_id == note && entry.nullifier == nullifier)
            .map(|(nonce, _)| *nonce);
        if let Some(nonce) = restored_nonce {
            let entry = self.checkpoint.detached_nonces.remove(&nonce).unwrap();
            pending.nonce = Some(nonce);
            pending.transaction_hash = entry.transaction_hash;
            pending.attempt = entry.attempt;
        }
        self.checkpoint.pending.insert(note, pending);
        true
    }

    /// Completeness against a lagging `eth_getLogs` replica: for every note the
    /// indexer lists that the checkpoint does not track as listed, track the
    /// escape the vault's `pendingWithdrawals` holds. Only the note ID is
    /// taken from the list: the vault can change after the indexer's block,
    /// and a challenge and re-escape pair leaves the root unchanged, so an
    /// indexer that checks only its root can list a stale nullifier and
    /// deadline. Older indexers without the endpoint are tolerated with a
    /// status warning.
    ///
    /// Each poll reads at most MAX_ESCAPE_CHECKS_PER_POLL listed notes, from
    /// the note where the previous poll's reads stopped, wrapping around, so
    /// every listed note due for a read is read within
    /// ceil(n / MAX_ESCAPE_CHECKS_PER_POLL) polls. A listed, untracked note
    /// the vault holds no escape for stays due on every listing until reads
    /// DEAD_ESCAPE_CONFIRM_SECONDS apart have found none; it is then read
    /// again only every DEAD_ESCAPE_RECHECK_POLLS listings. It is reported as
    /// a disagreement, which calls for a resync, once reads
    /// --blocked-warning-seconds apart have found none and a list served at
    /// a block between two of them named it. A list served below the first
    /// such read may only lag the vault, and one beyond this poll's `head`
    /// may hold an escape this RPC does not show yet; neither is reported.
    /// The entry is due for its report's read as soon as the period has
    /// passed and a listing can complete it.
    async fn sync_pending_escapes(&mut self, head: u64) -> anyhow::Result<()> {
        let now = unix_now();
        let listed = match self
            .indexer_get::<PendingEscapesResponse>("/v1/escapes/pending")
            .await
        {
            Ok(listed) => listed,
            Err(IndexerFailure::Status(404)) => {
                self.indexer.pending_escapes = "unsupported".into();
                self.indexer.pending_escapes_unavailable_since = None;
                self.indexer.pending_escapes_disagreement = None;
                self.indexer.pending_escapes_disagreement_since = None;
                return Ok(());
            }
            Err(error) => {
                if self.indexer.pending_escapes != "unavailable" {
                    tracing::warn!(error = %error, "indexer pending-escapes list unavailable");
                }
                self.indexer.pending_escapes = "unavailable".into();
                self.indexer
                    .pending_escapes_unavailable_since
                    .get_or_insert(now);
                return Ok(());
            }
        };
        self.indexer.pending_escapes = "ok".into();
        self.indexer.pending_escapes_unavailable_since = None;
        self.escape_listings += 1;
        let listing = self.escape_listings;
        let warning = self.config.alarms.blocked_warning_seconds;
        let mut changed = false;
        let mut checked = 0;
        let mut disagreements = Vec::new();
        let differs = |escape: &PendingEscape, nullifier: Felt252, deadline: u64| {
            (nullifier != escape.withdrawal_nullifier
                || escape
                    .challenge_deadline
                    .is_some_and(|listed| listed != deadline))
            .then(|| {
                format!(
                    "note {} listed with nullifier {} and deadline {}, the vault holds {} until {deadline}",
                    escape.note_id,
                    escape.withdrawal_nullifier,
                    escape
                        .challenge_deadline
                        .map_or("unknown".into(), |listed| listed.to_string()),
                    nullifier
                )
            })
        };
        let listed_block = listed.block_number;
        let mut unread = Vec::new();
        for escape in listed.escapes {
            // A note tracked as listed is compared with the vault on every
            // reconcile, which also keeps its deadline.
            if let Some(pending) = self
                .checkpoint
                .pending
                .get(&escape.note_id)
                .filter(|pending| pending.nullifier == escape.withdrawal_nullifier)
            {
                if let Some(deadline) = pending.challenge_deadline {
                    disagreements.extend(differs(&escape, pending.nullifier, deadline));
                }
                continue;
            }
            unread.push(escape);
        }
        // A dead entry lasts while its note is listed under the same
        // nullifier and untracked: reconcile reads a tracked note every poll.
        let listed_as: BTreeMap<u32, Felt252> = unread
            .iter()
            .map(|escape| (escape.note_id, escape.withdrawal_nullifier))
            .collect();
        let tracked = &self.checkpoint.pending;
        self.dead_escapes.retain(|note, dead| {
            listed_as.get(note) == Some(&dead.nullifier) && !tracked.contains_key(note)
        });
        for dead in self.dead_escapes.values_mut() {
            // This poll's head was fetched after every earlier listing's reads.
            dead.read_by.get_or_insert(head);
        }
        unread.sort_by_key(|escape| escape.note_id);
        let start = unread.partition_point(|escape| escape.note_id < self.escape_cursor);
        unread.rotate_left(start);
        for escape in unread {
            if self.dead_escapes.get(&escape.note_id).is_some_and(|dead| {
                dead.resting(listing, now, warning, dead.brackets(listed_block, head))
            }) {
                continue;
            }
            if checked == MAX_ESCAPE_CHECKS_PER_POLL {
                self.escape_cursor = escape.note_id;
                break;
            }
            checked += 1;
            let state = match self.withdrawal_state(escape.note_id, None).await {
                Ok(state) => state,
                Err(error) => {
                    tracing::warn!(note_id = escape.note_id, error = %error, "could not confirm an indexer-listed escape");
                    continue;
                }
            };
            if !state.exists {
                if self.checkpoint.pending.contains_key(&escape.note_id) {
                    continue; // Tracked under another nullifier; reconcile retires it.
                }
                // The list may lag the vault, or never learn the escape ended;
                // or this RPC may not yet show a fresh escape.
                let dead = self
                    .dead_escapes
                    .entry(escape.note_id)
                    .or_insert(DeadEscape {
                        nullifier: escape.withdrawal_nullifier,
                        first_seen: now,
                        last_seen: now,
                        checked_at: listing,
                        read_by: None,
                        bracketed: false,
                    });
                dead.last_seen = now;
                dead.checked_at = listing;
                dead.bracketed |= dead.brackets(listed_block, head);
                continue;
            }
            self.dead_escapes.remove(&escape.note_id);
            disagreements.extend(differs(&escape, state.nullifier, state.deadline));
            // The vault is authoritative, whatever the list says.
            if self
                .checkpoint
                .pending
                .get(&escape.note_id)
                .is_some_and(|pending| pending.nullifier == state.nullifier)
            {
                continue;
            }
            let initiated = self
                .challenge_period
                .map(|period| state.deadline.saturating_sub(period));
            if initiated
                .zip(self.checkpoint.scanned_through_timestamp)
                .is_some_and(|(initiated, scanned)| initiated <= scanned)
            {
                tracing::warn!(
                    note_id = escape.note_id,
                    nullifier = %state.nullifier,
                    "escape missing from the event scan added from the indexer pending-escapes list; the RPC eth_getLogs may be lagging"
                );
            } else {
                tracing::info!(note_id = escape.note_id, nullifier = %state.nullifier, "escape ahead of the confirmed event scan added from the indexer pending-escapes list");
            }
            self.indexer.escapes_added_from_indexer += 1;
            changed |= self.track_escape(escape.note_id, state.nullifier, Some(state.deadline));
        }
        let mut since = self
            .indexer
            .pending_escapes_disagreement_since
            .unwrap_or(now);
        let persisted: Vec<_> = self
            .dead_escapes
            .iter()
            .filter(|(_, dead)| dead.reported(warning))
            .collect();
        if let Some(first_seen) = persisted.iter().map(|(_, dead)| dead.first_seen).min() {
            // Reads at both ends of the warning period found no escape, and a
            // list served at a block between two of them named the note: the
            // indexer's list has disagreed with the vault since the first.
            since = since.min(first_seen);
            disagreements.push(format!(
                "{} listed note(s) with no pending escape in the vault: {}",
                persisted.len(),
                persisted
                    .iter()
                    .map(|(note, dead)| format!(
                        "note {note} listed with nullifier {}",
                        dead.nullifier
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let disagreement = (!disagreements.is_empty()).then(|| bounded(&disagreements.join("; ")));
        if disagreement.is_some() && self.indexer.pending_escapes_disagreement.is_none() {
            tracing::warn!(
                detail = ?disagreement,
                "indexer pending-escapes list disagrees with the vault; tracking the vault's escapes"
            );
        }
        self.indexer.pending_escapes_disagreement_since = disagreement.as_ref().map(|_| since);
        self.indexer.pending_escapes_disagreement = disagreement;
        if changed {
            self.persist()?;
        }
        Ok(())
    }

    /// The vault holds a different escape for a tracked note: the owner
    /// escaped again after a challenge, or an event replay tracked an older
    /// escape. Track the vault's; the old reservation stays detached until
    /// its nonce is consumed or released.
    fn follow_vault_escape(
        &mut self,
        note: u32,
        tracked: Felt252,
        state: &WithdrawalState,
    ) -> anyhow::Result<()> {
        tracing::warn!(
            note_id = note,
            tracked = %tracked,
            vault = %state.nullifier,
            "the vault holds a different escape than the one tracked for this note; tracking the vault's"
        );
        self.track_escape(note, state.nullifier, Some(state.deadline));
        self.persist()
    }

    fn observation_due(&mut self) -> bool {
        let now = unix_now();
        let due = self
            .last_observed_at
            .is_none_or(|at| now.saturating_sub(at) >= self.config.alarms.observe_interval_seconds);
        if due {
            self.last_observed_at = Some(now);
        }
        due
    }

    /// Tolerant: failures are recorded on the status and never abort a poll.
    /// The daemon never refuses to send because of the balance it observed.
    async fn observe_sender(&mut self) {
        let now = unix_now();
        match self
            .rpc("eth_getBalance", json!([self.config.sender, "latest"]))
            .await
            .and_then(|value| quantity_u128(&value))
        {
            Ok(balance) => {
                self.sender_balance = Some(balance);
                self.sender.balance_observed_at = Some(now);
                self.sender.balance_detail = None;
            }
            Err(error) if rpc_code(&error) == Some(-32601) => {
                self.sender_balance = None;
                self.sender.balance_detail =
                    Some("the signer RPC does not allow eth_getBalance".into());
            }
            Err(error) => self.sender.balance_detail = Some(bounded(&error.to_string())),
        }
        for tag in ["latest", "pending"] {
            let count = self
                .rpc("eth_getTransactionCount", json!([self.config.sender, tag]))
                .await
                .and_then(|value| quantity(&value))
                .ok();
            if tag == "latest" {
                self.sender.nonce_latest = count.or(self.sender.nonce_latest);
            } else {
                self.sender.nonce_pending = count.or(self.sender.nonce_pending);
            }
        }
        // The bundled signer reports its transaction fee cap; bids stay within
        // the lower of it and this daemon's. Without a report, a cap learned
        // from a refusal stays in force.
        match self
            .rpc("zkapi_signerStatus", json!([]))
            .await
            .and_then(|status| {
                status
                    .get("tx_fee_cap_wei")
                    .filter(|value| !value.is_null())
                    .map(quantity_u128)
                    .transpose()
            }) {
            Ok(Some(cap)) if cap > 0 => {
                self.signer_tx_fee_cap = Some(cap);
                self.sender.signer_status_detail = None;
            }
            Ok(Some(_)) => {
                self.sender.signer_status_detail =
                    Some("the signer reports a zero tx_fee_cap_wei; ignored".into());
            }
            Ok(None) => {
                self.sender.signer_status_detail =
                    Some("the signer does not report tx_fee_cap_wei".into());
            }
            Err(error) if rpc_code(&error) == Some(-32601) => {
                self.sender.signer_status_detail =
                    Some("the signer RPC does not provide zkapi_signerStatus".into());
            }
            Err(error) => self.sender.signer_status_detail = Some(bounded(&error.to_string())),
        }
    }

    /// Compare the indexer's served root with the vault. An exact verdict uses
    /// the vault root at the indexer's own block (EIP-1898 `blockHash`): equal
    /// means lagging, different means diverged, and an unknown hash is
    /// inconclusive. Expected lag is never counted as divergence.
    async fn observe_indexer(&mut self, head: &HeadInfo) {
        let response = match self.indexer_get::<TreeRootResponse>("/v1/tree/root").await {
            Ok(response) => response,
            Err(error) => {
                let phase = self.indexer_health_phase().await;
                match phase.as_deref() {
                    Some("diverged") => self.set_indexer_state(
                        IndexerState::Diverged,
                        Some("indexer /health reports diverged".into()),
                    ),
                    phase => self.set_indexer_state(
                        IndexerState::Unavailable,
                        Some(format!(
                            "indexer root unavailable ({error}); /health status {}",
                            phase.unwrap_or("unreachable")
                        )),
                    ),
                }
                return;
            }
        };
        self.indexer.root = Some(response.root);
        self.indexer.block_number = response.block_number;
        self.indexer.block_hash = response.block_hash.clone();
        let live = match self.live_root().await {
            Ok(root) => root,
            Err(error) => {
                self.indexer.detail = Some(bounded(&format!(
                    "vault currentRoot() unavailable: {error}"
                )));
                return;
            }
        };
        if response.root == live {
            self.indexer.lag_blocks = Some(0);
            self.set_indexer_state(IndexerState::Consistent, None);
            return;
        }
        let state = self
            .classify_root_mismatch(
                response.root,
                response.block_hash.as_deref(),
                response.block_number,
                head,
            )
            .await;
        let detail = match state {
            IndexerState::Diverged => "indexer root differs from the vault root",
            _ => "indexer root is behind the vault root",
        };
        self.set_indexer_state(state, Some(detail.into()));
    }

    async fn classify_root_mismatch(
        &mut self,
        indexer_root: Felt252,
        block_hash: Option<&str>,
        block_number: Option<u64>,
        head: &HeadInfo,
    ) -> IndexerState {
        self.indexer.lag_blocks = block_number.map(|block| head.number.saturating_sub(block));
        match block_hash {
            Some(hash) => match self.root_at_block_hash(hash).await {
                Ok(root) if root == indexer_root => IndexerState::Lagging,
                Ok(_) => IndexerState::Diverged,
                // The RPC does not know the indexer's block: inconclusive.
                Err(_) => IndexerState::Lagging,
            },
            None => {
                // An indexer without block metadata: a persistent mismatch
                // over time and observations is treated as divergence.
                let now = unix_now();
                let since = *self.indexer.mismatch_since.get_or_insert(now);
                self.indexer.consecutive_mismatches =
                    self.indexer.consecutive_mismatches.saturating_add(1);
                if now.saturating_sub(since) >= self.config.alarms.indexer_divergence_seconds
                    && self.indexer.consecutive_mismatches
                        >= self.config.alarms.indexer_divergence_polls
                {
                    IndexerState::Diverged
                } else {
                    IndexerState::Lagging
                }
            }
        }
    }

    fn set_indexer_state(&mut self, state: IndexerState, detail: Option<String>) {
        let now = unix_now();
        let previous = self.indexer.state;
        match state {
            IndexerState::Consistent => {
                self.indexer.mismatch_since = None;
                self.indexer.consecutive_mismatches = 0;
                self.indexer.unavailable_since = None;
            }
            IndexerState::Unavailable => {
                self.indexer.unavailable_since.get_or_insert(now);
            }
            IndexerState::Lagging | IndexerState::Diverged | IndexerState::Unknown => {
                self.indexer.unavailable_since = None;
            }
        }
        self.indexer.state = state;
        self.indexer.detail = detail;
        self.indexer.observed_at = Some(now);
        if state == IndexerState::Diverged {
            if previous != IndexerState::Diverged
                || self
                    .indexer_logged_at
                    .is_none_or(|at| now.saturating_sub(at) >= RELOG_SECONDS)
            {
                tracing::error!(
                    indexer_root = ?self.indexer.root,
                    vault_root = ?self.vault_root,
                    "indexer mirror diverged from vault currentRoot; challenges cannot be built until the indexer is resynced"
                );
                self.indexer_logged_at = Some(now);
            }
        } else if previous == IndexerState::Diverged {
            tracing::info!(state = ?state, "indexer mirror no longer diverges from vault currentRoot");
            self.indexer_logged_at = None;
        }
    }

    async fn load_vault_constants(&mut self) {
        let mut errors = Vec::new();
        if self.challenge_period.is_none() {
            match self
                .call(selector("challengePeriod()"))
                .await
                .and_then(|words| {
                    ensure!(words.len() == 1, "malformed challengePeriod response");
                    felt_u64(&words[0])
                }) {
                Ok(period) => self.challenge_period = Some(period),
                Err(error) => errors.push(format!("challengePeriod(): {error}")),
            }
        }
        if self.vault_state_key.is_none() {
            match self.read_state_key().await {
                Ok(key) => self.vault_state_key = Some(key),
                Err(error) => errors.push(format!("stateSigningKeyX/Y(): {error}")),
            }
        }
        self.vault_warning = (!errors.is_empty()).then(|| {
            bounded(&format!(
                "vault constants unavailable; retrying: {}",
                errors.join("; ")
            ))
        });
    }

    async fn read_state_key(&self) -> anyhow::Result<(Felt252, Felt252)> {
        let mut key = [Felt252::ZERO; 2];
        for (slot, getter) in key
            .iter_mut()
            .zip(["stateSigningKeyX()", "stateSigningKeyY()"])
        {
            let words = self.call(selector(getter)).await?;
            ensure!(words.len() == 1, "malformed {getter} response");
            *slot = words[0];
        }
        Ok((key[0], key[1]))
    }

    async fn reconcile(
        &mut self,
        note: u32,
        nonce_state: NonceState,
        head: &HeadInfo,
    ) -> anyhow::Result<()> {
        let pending = self.checkpoint.pending[&note].clone();
        let state = self.withdrawal_state(note, None).await?;
        if state.exists && state.nullifier != pending.nullifier {
            // Re-checked every poll, so a tip reorg back to the tracked escape
            // restores it with its reservation.
            return self.follow_vault_escape(note, pending.nullifier, &state);
        }
        if !state.exists {
            return self.retire_if_confirmed(note, &pending).await;
        }
        self.note_deadline(note, state.deadline)?;
        let evidence = self.watcher.evidence_status(&pending.nullifier);
        if head.timestamp >= state.deadline {
            // Keep the obligation until confirmed vault completion, including
            // the possibility of a reorg back before the deadline.
            return self
                .record_expiry(note, &evidence, state.deadline, Some(nonce_state))
                .await;
        }
        match evidence {
            Ok(EvidenceStatus::Ready(_)) => match nonce_state {
                NonceState::Mined => {
                    self.mined_unconfirmed(note).await;
                    Ok(())
                }
                NonceState::Pending => self.maybe_replace(note, head, true).await,
                NonceState::Held => self.maybe_replace(note, head, false).await,
                NonceState::Free => self.submit(note, None, head, FeePlan::First).await,
                NonceState::Reserved => {
                    let plan = self
                        .persisted_fees(note)
                        .map_or(FeePlan::First, FeePlan::Resend);
                    self.submit(note, pending.nonce, head, plan).await
                }
            },
            other => match self.evaluate_evidence(note, other) {
                Some(error) => Err(error),
                None => Ok(()),
            },
        }
    }

    /// Do not discard an obligation due to an unconfirmed challenge or
    /// finalization that a tip reorg could remove without changing the
    /// event-scan checkpoint block.
    async fn retire_if_confirmed(
        &mut self,
        note: u32,
        pending: &PendingChallenge,
    ) -> anyhow::Result<()> {
        let unconfirmed = Evaluation::new(ObligationState::ResolvedUnconfirmed, None).detail(
            "withdrawal no longer pending at the latest block; retirement waits for confirmations",
        );
        let latest = quantity(&self.rpc("eth_blockNumber", json!([])).await?)?;
        let Some(confirmed) = latest.checked_sub(self.config.confirmations) else {
            self.record(note, unconfirmed);
            return Ok(());
        };
        let confirmed_state = self.withdrawal_state(note, Some(confirmed)).await?;
        if confirmed_state.exists && confirmed_state.nullifier == pending.nullifier {
            self.record(note, unconfirmed);
            return Ok(());
        }
        // A nonce no attempt was broadcast on is released rather than kept.
        self.release_if_never_broadcast(note).await;
        self.detach_nonce(note);
        self.checkpoint.pending.remove(&note);
        self.forget_observations(note);
        self.persist()?;
        tracing::info!(note_id = note, nullifier = %pending.nullifier, "escape obligation resolved at confirmation depth");
        Ok(())
    }

    /// In-memory observations belong to one obligation, not to its note.
    fn forget_observations(&mut self, note: u32) {
        self.evaluations.remove(&note);
        self.previous_evaluations.remove(&note);
        self.blocked_since.remove(&note);
        self.observed_fees.remove(&note);
        self.logged.remove(&note);
    }

    /// Read-only evaluation for an obligation the poll loop did not reach. It
    /// still records missed deadlines, so a note that expires entirely behind
    /// a blocked nonce is counted.
    async fn observe_only(
        &mut self,
        note: u32,
        head: &HeadInfo,
        blocked: Option<(BlockedReason, String)>,
    ) -> anyhow::Result<()> {
        let pending = self.checkpoint.pending[&note].clone();
        let state = self.withdrawal_state(note, None).await?;
        if state.exists && state.nullifier != pending.nullifier {
            return self.follow_vault_escape(note, pending.nullifier, &state);
        }
        if !state.exists {
            self.record(
                note,
                Evaluation::new(ObligationState::ResolvedUnconfirmed, None).detail(
                    "withdrawal no longer pending at the latest block; retirement waits for confirmations",
                ),
            );
            return Ok(());
        }
        self.note_deadline(note, state.deadline)?;
        let evidence = self.watcher.evidence_status(&pending.nullifier);
        if head.timestamp >= state.deadline {
            return self
                .record_expiry(note, &evidence, state.deadline, None)
                .await;
        }
        match evidence {
            Ok(EvidenceStatus::Ready(_)) => {
                let state = if pending.transaction_hash.is_some() {
                    ObligationState::Submitted
                } else {
                    ObligationState::Ready
                };
                let mut evaluation = Evaluation::new(state, Some(EvidenceKind::Finalized));
                if let Some((reason, detail)) = blocked {
                    evaluation = evaluation.blocked(reason, detail);
                }
                self.record(note, evaluation);
            }
            other => {
                self.evaluate_evidence(note, other);
            }
        }
        Ok(())
    }

    /// Record a non-Ready evidence state. Returns the error a reconcile must
    /// propagate (corrupt evidence or an unreadable database).
    fn evaluate_evidence(
        &mut self,
        note: u32,
        evidence: Result<EvidenceStatus, ServerError>,
    ) -> Option<anyhow::Error> {
        match evidence {
            Err(error) => {
                let error = anyhow!("evidence database read failed: {error}");
                self.record(
                    note,
                    Evaluation::new(ObligationState::Ready, Some(EvidenceKind::Unavailable))
                        .blocked(BlockedReason::EvidenceDbError, error.to_string()),
                );
                Some(error)
            }
            Ok(EvidenceStatus::Corrupt(reason)) => {
                let error = anyhow!("corrupt finalized evidence: {reason}");
                self.record(
                    note,
                    Evaluation::new(ObligationState::Ready, Some(EvidenceKind::Corrupt))
                        .blocked(BlockedReason::EvidenceInvalid, error.to_string()),
                );
                Some(error)
            }
            Ok(EvidenceStatus::AwaitingSettlement(progress)) => {
                let thresholds = self.thresholds();
                let deadline = self.checkpoint.pending[&note].challenge_deadline;
                let mut evaluation = if let Some(error) = &progress.lease_read_error {
                    Evaluation::new(
                        ObligationState::AwaitingSettlement,
                        Some(EvidenceKind::Unavailable),
                    )
                    .blocked(
                        BlockedReason::EvidenceDbError,
                        format!("lease row unreadable; settlement cannot progress: {error}"),
                    )
                } else if progress.lease_status.is_none() {
                    Evaluation::new(
                        ObligationState::AwaitingSettlement,
                        Some(EvidenceKind::ReservedWithoutLease),
                    )
                    .detail("reservation has no lease row; issuance never completed")
                } else if progress.lease_status.as_deref() == Some("cancelled") {
                    Evaluation::new(
                        ObligationState::AwaitingSettlement,
                        Some(EvidenceKind::Reserved),
                    )
                    .detail("lease cancelled for a corrupt binding; no evidence will be produced")
                } else {
                    // The write-once settlement deadline bounds when evidence
                    // exists; rows without one fall back to the next attempt.
                    let late = progress.evidence_expected_by().zip(deadline).is_some_and(
                        |(expected_by, deadline)| {
                            expected_by
                                >= deadline.saturating_sub(thresholds.critical_remaining_seconds)
                        },
                    );
                    let overdue = progress.settle_after.is_some_and(|settle_after| {
                        unix_now()
                            > settle_after
                                .saturating_add(self.config.alarms.settlement_overdue_seconds)
                    });
                    Evaluation::new(
                        ObligationState::AwaitingSettlement,
                        Some(EvidenceKind::Reserved),
                    )
                    .detail(if late {
                        "settlement scheduled after the challenge critical threshold"
                    } else if overdue {
                        "settlement overdue; is the API server settling?"
                    } else {
                        "awaiting finalized settlement"
                    })
                };
                evaluation.settlement = Some(progress);
                self.record(note, evaluation);
                None
            }
            Ok(EvidenceStatus::ClearanceOnly) => {
                self.record(
                    note,
                    Evaluation::new(ObligationState::NoEvidence, Some(EvidenceKind::Clearance))
                        .detail("nullifier is reserved only for a withdrawal clearance"),
                );
                None
            }
            Ok(EvidenceStatus::Unknown) => {
                self.record(
                    note,
                    Evaluation::new(ObligationState::NoEvidence, Some(EvidenceKind::Unknown))
                        .detail("no server request at this nullifier"),
                );
                None
            }
            Ok(EvidenceStatus::Ready(_)) => None,
        }
    }

    /// The deadline passed: a missed challenge when evidence existed or was
    /// expected, otherwise an expiry without evidence. An unmined reserved
    /// nonce of an expired obligation still blocks new allocations, unless no
    /// attempt on it was broadcast.
    async fn record_expiry(
        &mut self,
        note: u32,
        evidence: &Result<EvidenceStatus, ServerError>,
        deadline: u64,
        nonce_state: Option<NonceState>,
    ) -> anyhow::Result<()> {
        let (kind, settlement, missed_reason) = match evidence {
            Err(_) => (
                EvidenceKind::Unavailable,
                None,
                Some("evidence database unreadable at the deadline"),
            ),
            Ok(EvidenceStatus::Ready(_)) => (
                EvidenceKind::Finalized,
                None,
                Some("challenge not mined before the deadline"),
            ),
            Ok(EvidenceStatus::Corrupt(_)) => (
                EvidenceKind::Corrupt,
                None,
                Some("finalized evidence corrupt at the deadline"),
            ),
            Ok(EvidenceStatus::AwaitingSettlement(progress)) => {
                let never = progress.lease_read_error.is_none()
                    && (progress.lease_status.is_none()
                        || progress.lease_status.as_deref() == Some("cancelled"));
                (
                    if progress.lease_read_error.is_some() {
                        EvidenceKind::Unavailable
                    } else if progress.lease_status.is_none() {
                        EvidenceKind::ReservedWithoutLease
                    } else {
                        EvidenceKind::Reserved
                    },
                    Some(progress.clone()),
                    (!never).then_some("request still settling at the deadline"),
                )
            }
            Ok(EvidenceStatus::ClearanceOnly) => (EvidenceKind::Clearance, None, None),
            Ok(EvidenceStatus::Unknown) => (EvidenceKind::Unknown, None, None),
        };
        let mut evaluation = match missed_reason {
            Some(reason) => {
                self.record_missed(note, deadline, reason)?;
                Evaluation::new(ObligationState::Missed, Some(kind)).detail(reason)
            }
            None => Evaluation::new(ObligationState::ExpiredWithoutEvidence, Some(kind))
                .detail("deadline passed without challenge evidence"),
        };
        evaluation.settlement = settlement;
        if matches!(nonce_state, Some(NonceState::Reserved | NonceState::Held)) {
            if self.release_if_never_broadcast(note).await {
                self.persist()?;
            } else {
                let nonce = self.checkpoint.pending[&note].nonce.unwrap_or_default();
                self.record(
                    note,
                    evaluation.blocked(
                        BlockedReason::NonceBlocked,
                        format!("expired obligation retains unmined reserved nonce {nonce}, which an attempt may hold; resolve it at the signer"),
                    ),
                );
                bail!("expired challenge retains an unmined reserved nonce; signer intervention required before allocating another nonce");
            }
        }
        self.record(note, evaluation);
        Ok(())
    }

    fn record_missed(&mut self, note: u32, deadline: u64, reason: &str) -> anyhow::Result<()> {
        let entry = self.checkpoint.pending.get_mut(&note).unwrap();
        if entry.deadline_reported {
            return Ok(());
        }
        entry.deadline_reported = true;
        let nullifier = entry.nullifier;
        self.checkpoint.missed_total = self.checkpoint.missed_total.saturating_add(1);
        self.checkpoint.last_missed = Some(MissedRecord {
            note_id: note,
            nullifier,
            challenge_deadline: deadline,
            reason: reason.into(),
            recorded_at: unix_now(),
        });
        tracing::error!(note_id = note, nullifier = %nullifier, reason, "MISSED escape challenge deadline");
        self.persist()
    }

    fn note_deadline(&mut self, note: u32, deadline: u64) -> anyhow::Result<()> {
        let entry = self.checkpoint.pending.get_mut(&note).unwrap();
        if entry.challenge_deadline != Some(deadline) {
            entry.challenge_deadline = Some(deadline);
            self.persist()?;
        }
        Ok(())
    }

    /// The nonce was consumed while the withdrawal is still pending, so the
    /// mined challenge reverted (for example after a front-running deposit).
    /// It keeps its deadline-derived severity until resubmission.
    async fn mined_unconfirmed(&mut self, note: u32) {
        let pending = self.checkpoint.pending[&note].clone();
        let mut detail = "nonce consumed while the withdrawal is still pending; resubmitting after confirmations".to_string();
        for hash in pending
            .transaction_hash
            .iter()
            .chain(pending.attempt.superseded_hashes.last())
        {
            if let Ok(receipt) = self.rpc("eth_getTransactionReceipt", json!([hash])).await {
                if receipt.get("status").and_then(Value::as_str) == Some("0x0") {
                    detail = format!("challenge {hash} reverted; resubmitting after confirmations");
                    break;
                }
            }
        }
        self.record(
            note,
            Evaluation::new(
                ObligationState::MinedUnconfirmed,
                Some(EvidenceKind::Finalized),
            )
            .detail(detail),
        );
    }

    /// Replace the queue-head attempt on its nonce when it has waited
    /// `bump_after_blocks`, the base fee rose above its fee cap, the queue is
    /// critical, or the vault root moved so it would revert. The attempt is
    /// either a known pending transaction (`visible`) or one without a known
    /// hash that may hold the nonce, which is outbid at the same pace.
    async fn maybe_replace(
        &mut self,
        note: u32,
        head: &HeadInfo,
        visible: bool,
    ) -> anyhow::Result<()> {
        let pending = self.checkpoint.pending[&note].clone();
        let nonce = pending.nonce.context("pending challenge lacks a nonce")?;
        let (submitted, waiting) = if visible {
            (
                Evaluation::new(ObligationState::Submitted, Some(EvidenceKind::Finalized)),
                format!("pending on nonce {nonce}"),
            )
        } else {
            (
                Evaluation::new(ObligationState::Ready, Some(EvidenceKind::Finalized)),
                format!("nonce {nonce} may be held by an attempt without a known hash"),
            )
        };
        let hold = |evaluation: Evaluation, detail: String| {
            if visible {
                evaluation.detail(detail)
            } else {
                evaluation.blocked(BlockedReason::SendAmbiguous, detail)
            }
        };
        if self.latest_nonce_count != Some(nonce) {
            self.record(
                note,
                hold(submitted, format!("{waiting}, behind an earlier challenge")),
            );
            return Ok(());
        }
        let old = self.persisted_fees(note).or_else(|| {
            visible
                .then(|| self.observed_fees.get(&note).copied())
                .flatten()
        });
        let Some(old) = old else {
            if !visible {
                // A reservation from an older daemon: its fees are unknown.
                return self.submit(note, Some(nonce), head, FeePlan::First).await;
            }
            self.record(
                note,
                submitted.detail(format!("{waiting} with unknown fees; not replaceable")),
            );
            return Ok(());
        };
        let critical = self.queue_severity(note, head) == Severity::Critical;
        // The ceiling at the gas limit of the latest attempt; the send itself
        // plans with the exact gas limit.
        let tx_fee_limit = pending
            .attempt
            .gas_limit
            .map(u128::from)
            .or(self.last_gas)
            .map(|gas| self.tx_fee_limit(gas));
        let policy = &self.config.fee;
        let waited = pending
            .attempt
            .submitted_block
            .is_none_or(|block| head.number.saturating_sub(block) >= policy.bump_after_blocks);
        let base_above = head.base_fee.is_some_and(|base| base > old.max_fee);
        let max_fee_cap = policy
            .max_fee_per_gas
            .min(tx_fee_limit.unwrap_or(u128::MAX));
        let below_critical = critical
            && (old.max_fee < headroom(max_fee_cap)
                || old.tip < headroom(policy.max_priority_fee_per_gas));
        let stale_root = match pending.attempt.submitted_root {
            Some(root) => self.live_root().await.is_ok_and(|live| live != root),
            None => false,
        };
        if !(waited || base_above || below_critical || stale_root) {
            self.record(note, hold(submitted, waiting));
            return Ok(());
        }
        // Skip the path and simulation work while no valid bump exists. A
        // pending attempt that cannot be outbid within the caps and the
        // transaction fee ceiling is kept, and observed until it mines.
        match plan_fees(
            &self.config.fee,
            FeePlan::Bump(old),
            head.base_fee,
            critical,
            tx_fee_limit,
            None,
        ) {
            Ok(Some(_)) => {}
            Ok(None) => {
                let detail = format!(
                    "{waiting}; the remaining fee headroom is reserved for the critical threshold"
                );
                // Reported as blocked, so a challenge that stays pending after
                // its budget is spent escalates with time like an exhausted cap.
                let evaluation = if visible {
                    submitted.blocked(BlockedReason::FeeReserveHeld, detail)
                } else {
                    hold(submitted, detail)
                };
                self.record(note, evaluation);
                return Ok(());
            }
            Err(reason) => {
                self.record(
                    note,
                    submitted.blocked(
                        reason,
                        format!(
                            "{waiting} at max fee {} and tip {} wei; no valid replacement within the caps{}",
                            old.max_fee,
                            old.tip,
                            if reason == BlockedReason::TxFeeCapReached {
                                format!(" and the transaction fee ceiling of {} wei", self.tx_fee_cap())
                            } else {
                                String::new()
                            }
                        ),
                    ),
                );
                return Ok(());
            }
        }
        self.submit(note, Some(nonce), head, FeePlan::Bump(old))
            .await
    }

    /// Build, simulate and send a challenge on a new or reused nonce. The
    /// nonce, fees and evidence digest are persisted before the send.
    async fn submit(
        &mut self,
        note: u32,
        reuse: Option<u64>,
        head: &HeadInfo,
        plan: FeePlan,
    ) -> anyhow::Result<()> {
        let pending = self.checkpoint.pending[&note].clone();
        let base_state = if matches!(plan, FeePlan::Bump(_)) && pending.transaction_hash.is_some() {
            ObligationState::Submitted
        } else {
            ObligationState::Ready
        };
        macro_rules! blocked {
            ($reason:expr, $error:expr) => {{
                let error: anyhow::Error = $error;
                self.record(
                    note,
                    Evaluation::new(base_state, Some(EvidenceKind::Finalized))
                        .blocked($reason, error.to_string()),
                );
                return Err(error);
            }};
        }
        let path_url = format!("/v1/tree/notes/{note}/zero-path");
        let response = match self.indexer_get::<PathResponse>(&path_url).await {
            Ok(response) => response,
            Err(IndexerFailure::Decode(error)) => blocked!(
                BlockedReason::IndexerInvalidResponse,
                anyhow!("indexer returned a malformed zero path: {error}")
            ),
            Err(error) => blocked!(
                BlockedReason::IndexerUnavailable,
                anyhow!("indexer zero-path request failed: {error}")
            ),
        };
        if response.note_id != note || response.leaf != Felt252::ZERO {
            blocked!(
                BlockedReason::IndexerInvalidResponse,
                anyhow!("indexer returned the wrong zero slot")
            );
        }
        let Ok(siblings) = <[Felt252; MERKLE_DEPTH]>::try_from(response.siblings) else {
            blocked!(
                BlockedReason::IndexerInvalidResponse,
                anyhow!("indexer path must have 32 siblings")
            );
        };
        let path_root = zkapi_core::v2::merkle_root(note, &Felt252::ZERO, &siblings);
        if response.root.is_some_and(|root| root != path_root) {
            blocked!(
                BlockedReason::IndexerInvalidResponse,
                anyhow!("indexer zero path does not hash to its reported root")
            );
        }
        let root = match self.live_root().await {
            Ok(root) => root,
            Err(error) => blocked!(BlockedReason::RpcError, error),
        };
        if path_root != root {
            let state = self
                .classify_root_mismatch(
                    path_root,
                    response.block_hash.as_deref(),
                    response.block_number,
                    head,
                )
                .await;
            if state == IndexerState::Diverged {
                self.set_indexer_state(
                    IndexerState::Diverged,
                    Some("indexer zero path differs from the vault root".into()),
                );
            }
            let reason = if self.indexer.state == IndexerState::Diverged {
                BlockedReason::IndexerDiverged
            } else {
                BlockedReason::IndexerPathBehind
            };
            blocked!(
                reason,
                anyhow!("indexer path is behind the current vault root")
            );
        }
        let action = match self
            .watcher
            .build_challenge_action(note, &pending.nullifier, siblings)
        {
            Ok(action) => action,
            Err(error) if error.starts_with("evidence database read failed") => {
                blocked!(BlockedReason::EvidenceDbError, anyhow!(error))
            }
            Err(error) => blocked!(BlockedReason::EvidenceInvalid, anyhow!(error)),
        };
        if action.request_inputs.chain_id != self.config.chain_id
            || action.request_inputs.contract_address != self.config.contract_address
        {
            blocked!(
                BlockedReason::EvidenceInvalid,
                anyhow!("archived proof belongs to another deployment")
            );
        }
        match self.vault_state_key {
            None => blocked!(
                BlockedReason::RpcError,
                anyhow!("vault state signing key not yet read")
            ),
            Some(key)
                if key
                    != (
                        action.request_inputs.state_signing_key_x,
                        action.request_inputs.state_signing_key_y,
                    ) =>
            {
                blocked!(
                    BlockedReason::EvidenceInvalid,
                    anyhow!("archived proof state key differs from vault immutable key (server signing-key misconfiguration)")
                )
            }
            Some(_) => {}
        }
        let proof = Groth16ProofWire {
            backend: ProofBackendWire::Groth16Bn254,
            proof: base64::engine::general_purpose::STANDARD.encode(&action.proof_artifact),
        };
        match self.verifier.verify(&action.request_inputs, &proof) {
            Ok(true) => {}
            Ok(false) => blocked!(
                BlockedReason::EvidenceInvalid,
                anyhow!("archived challenge proof failed verification")
            ),
            Err(error) => blocked!(BlockedReason::EvidenceInvalid, error),
        }
        let digest = action.evidence_digest();
        if pending
            .attempt
            .evidence_digest
            .as_ref()
            .is_some_and(|recorded| *recorded != digest)
        {
            blocked!(
                BlockedReason::EvidenceInvalid,
                anyhow!("a replacement would change the challenged note, request inputs or proof on its nonce")
            );
        }
        let calldata = match action.calldata() {
            Ok(calldata) => calldata,
            Err(error) => blocked!(BlockedReason::EvidenceInvalid, anyhow!(error)),
        };
        let data = format!("0x{}", hex::encode(calldata));
        let mut transaction =
            json!({ "from": self.config.sender, "to": self.vault_address(), "data": data });
        // Simulate against the live contract to check keys, proof, deadline and
        // path together, including races with unrelated tree updates.
        if let Err(error) = self.rpc("eth_call", json!([transaction, "latest"])).await {
            return self.simulation_failed(note, base_state, error);
        }
        let estimated_gas = match self
            .rpc("eth_estimateGas", json!([transaction]))
            .await
            .and_then(|value| quantity(&value))
        {
            Ok(gas) => gas,
            Err(error) => return self.simulation_failed(note, base_state, error),
        };
        let gas = estimated_gas
            .checked_add(estimated_gas / 5)
            .context("challenge gas estimate overflow")?;
        self.last_gas = Some(gas as u128);
        let nonce = match reuse {
            Some(nonce) => nonce,
            None => {
                let chain_nonce = self.transaction_count("pending").await?;
                if self
                    .checkpoint
                    .pending
                    .values()
                    .any(|entry| entry.nonce == Some(chain_nonce))
                    || self.checkpoint.detached_nonces.contains_key(&chain_nonce)
                {
                    blocked!(
                        BlockedReason::NonceConflict,
                        anyhow!("RPC pending nonce conflicts with a durable challenge reservation")
                    );
                }
                chain_nonce
            }
        };
        let critical = self.queue_severity(note, head) == Severity::Critical;
        let affordable = self
            .sender_balance
            .map(|balance| balance / (gas as u128).max(1));
        // The signer and its node refuse gas x maxFeePerGas above the ceiling.
        let tx_fee_limit = self.tx_fee_limit(gas as u128);
        let fees = match plan_fees(
            &self.config.fee,
            plan,
            head.base_fee,
            critical,
            Some(tx_fee_limit),
            affordable,
        ) {
            Ok(Some(fees)) => fees,
            Ok(None) => {
                // Only a replacement keeps the reserve, as in maybe_replace.
                let (reason, waiting) = if pending.transaction_hash.is_some() {
                    (
                        BlockedReason::FeeReserveHeld,
                        format!("pending on nonce {nonce}"),
                    )
                } else {
                    (
                        BlockedReason::SendAmbiguous,
                        format!("nonce {nonce} may be held by an attempt without a known hash"),
                    )
                };
                self.record(
                    note,
                    Evaluation::new(base_state, Some(EvidenceKind::Finalized)).blocked(
                        reason,
                        format!("{waiting}; the remaining fee headroom is reserved for the critical threshold"),
                    ),
                );
                return Ok(());
            }
            Err(reason) => {
                // Nothing is sent; retried next poll. A reused nonce that no
                // attempt was broadcast on is released.
                let detail = match reason {
                    BlockedReason::BaseFeeAboveFeeCap => format!(
                        "base fee {} wei exceeds the usable fee cap",
                        head.base_fee.unwrap_or_default()
                    ),
                    BlockedReason::TxFeeCapReached => format!(
                        "the transaction fee ceiling of {} wei allows a maxFeePerGas of at most {tx_fee_limit} wei at {gas} gas; base fee {} wei{}",
                        self.tx_fee_cap(),
                        head.base_fee.unwrap_or_default(),
                        if matches!(plan, FeePlan::Bump(_)) {
                            "; no valid replacement"
                        } else {
                            ""
                        }
                    ),
                    BlockedReason::InsufficientBalance => format!(
                        "sender balance {} wei cannot fund a valid bid at {gas} gas",
                        self.sender_balance.unwrap_or_default()
                    ),
                    BlockedReason::TipCapReached => {
                        "no valid replacement: the tip cap is reached".into()
                    }
                    _ => "no valid replacement: the fee cap is reached".into(),
                };
                if reuse.is_some() && self.release_if_never_broadcast(note).await {
                    self.persist()?;
                }
                self.record(
                    note,
                    Evaluation::new(base_state, Some(EvidenceKind::Finalized))
                        .blocked(reason, detail),
                );
                return Ok(());
            }
        };
        if let FeePlan::Resend(old) = plan {
            if fees.max_fee < old.max_fee || fees.tip < old.tip {
                tracing::warn!(
                    note_id = note,
                    nonce,
                    previous_max_fee_per_gas = old.max_fee,
                    previous_max_priority_fee_per_gas = old.tip,
                    max_fee_per_gas = fees.max_fee,
                    max_priority_fee_per_gas = fees.tip,
                    "re-sending a nonce no attempt holds below its earlier bid, within the current caps, transaction fee ceiling and balance"
                );
            }
        }
        // Write ahead: a crash or ambiguous result after this point never
        // loses the reservation, the fees that may be in a pool, or the call.
        // A bid outbids every attempt that may hold the nonce, so its fees
        // are the highest in any pool; a re-send of a nonce no attempt holds
        // keeps its earlier fees within the current caps and ceiling.
        let rollback = {
            let entry = self.checkpoint.pending.get_mut(&note).unwrap();
            let rollback = (
                entry.nonce,
                entry.transaction_hash.clone(),
                entry.attempt.clone(),
            );
            entry.nonce = Some(nonce);
            if let Some(hash) = entry.transaction_hash.take() {
                push_superseded(&mut entry.attempt, hash);
            }
            entry.attempt.max_fee_per_gas = Some(format!("0x{:x}", fees.max_fee));
            entry.attempt.max_priority_fee_per_gas = Some(format!("0x{:x}", fees.tip));
            entry.attempt.gas_limit = Some(gas);
            entry.attempt.attempts = entry.attempt.attempts.saturating_add(1);
            entry.attempt.submitted_block = Some(head.number);
            entry.attempt.evidence_digest = Some(digest);
            entry.attempt.submitted_root = Some(root);
            entry.attempt.unknown_attempt = true;
            rollback
        };
        self.persist()?;
        transaction["gas"] = json!(format!("0x{gas:x}"));
        transaction["nonce"] = json!(format!("0x{nonce:x}"));
        transaction["maxFeePerGas"] = json!(format!("0x{:x}", fees.max_fee));
        transaction["maxPriorityFeePerGas"] = json!(format!("0x{:x}", fees.tip));
        let sent = self
            .rpc_with_timeout(
                "eth_sendTransaction",
                json!([transaction]),
                Some(SEND_TIMEOUT),
            )
            .await
            .and_then(|hash| {
                hash.as_str()
                    .map(str::to_owned)
                    .context("transaction response lacks hash")
            });
        match sent {
            Ok(hash) => {
                let entry = self.checkpoint.pending.get_mut(&note).unwrap();
                entry.transaction_hash = Some(hash.clone());
                entry.attempt.unknown_attempt = false;
                self.persist()?;
                tracing::info!(
                    note_id = note,
                    nonce,
                    transaction_hash = %hash,
                    max_fee_per_gas = fees.max_fee,
                    max_priority_fee_per_gas = fees.tip,
                    "submitted escape challenge"
                );
                self.record(
                    note,
                    Evaluation::new(ObligationState::Submitted, Some(EvidenceKind::Finalized))
                        .detail(format!("pending on nonce {nonce}")),
                );
                Ok(())
            }
            Err(error) => {
                self.send_failed(
                    note,
                    nonce,
                    (gas, fees.max_fee),
                    base_state,
                    rollback,
                    error,
                )
                .await
            }
        }
    }

    /// `sent` is the gas limit and maxFeePerGas of the failed send.
    async fn send_failed(
        &mut self,
        note: u32,
        nonce: u64,
        sent: (u64, u128),
        base_state: ObligationState,
        rollback: (Option<u64>, Option<String>, NonceAttempts),
        error: anyhow::Error,
    ) -> anyhow::Result<()> {
        let (gas, max_fee) = sent;
        let reason = match classify_send_error(&error) {
            SendFailure::Refused(reason) => {
                self.roll_back_unsent(note, nonce, rollback).await;
                if reason.as_deref() == Some("tx_fee_above_cap") {
                    // Later bids stay within the signer's cap.
                    if let Some(cap) = refused_tx_fee_cap(&error, gas) {
                        self.signer_tx_fee_cap = Some(cap);
                    }
                }
                if reason.as_deref() == Some("upstream_tx_fee_cap") {
                    self.learn_node_tx_fee_bound(note, refused_tx_fee(&error, gas, max_fee));
                }
                refusal_reason(reason.as_deref())
            }
            SendFailure::NotBroadcast(reason) => {
                self.roll_back_unsent(note, nonce, rollback).await;
                reason
            }
            SendFailure::Ambiguous(hash) => {
                // Keep the write-ahead record; a candidate hash lets the next
                // poll find the transaction, otherwise re-sends must bump.
                if let Some(hash) = hash {
                    let entry = self.checkpoint.pending.get_mut(&note).unwrap();
                    entry.transaction_hash = Some(hash);
                    entry.attempt.unknown_attempt = false;
                }
                BlockedReason::SendAmbiguous
            }
        };
        self.persist()?;
        self.record(
            note,
            Evaluation::new(base_state, Some(EvidenceKind::Finalized))
                .blocked(reason, error.to_string()),
        );
        Err(error)
    }

    /// Nothing was broadcast: restore the nonce's earlier record, counting the
    /// attempt, and release the nonce when no attempt can occupy it, so that a
    /// failure lasting until the deadline cannot stall later notes. The caller
    /// persists.
    async fn roll_back_unsent(
        &mut self,
        note: u32,
        nonce: u64,
        rollback: (Option<u64>, Option<String>, NonceAttempts),
    ) {
        let (previous_nonce, previous_hash, previous_attempt) = rollback;
        let entry = self.checkpoint.pending.get_mut(&note).unwrap();
        // A reservation an older daemon made without a record may hold an
        // attempt the record does not describe.
        let unrecorded_attempt = previous_attempt.unrecorded_attempt
            || (previous_nonce.is_some() && previous_attempt.attempts == 0);
        entry.nonce = previous_nonce.or(Some(nonce));
        entry.transaction_hash = previous_hash;
        entry.attempt = NonceAttempts {
            attempts: entry.attempt.attempts,
            unrecorded_attempt,
            ..previous_attempt
        };
        self.release_if_never_broadcast(note).await;
    }

    /// Release the note's reserved nonce when no attempt recorded on it was
    /// broadcast and neither the latest nor the pending count has passed it.
    /// The caller persists.
    async fn release_if_never_broadcast(&mut self, note: u32) -> bool {
        let Some(nonce) = self
            .checkpoint
            .pending
            .get(&note)
            .filter(|pending| never_broadcast(pending.transaction_hash.as_ref(), &pending.attempt))
            .and_then(|pending| pending.nonce)
        else {
            return false;
        };
        if !self.nonce_unused(nonce).await {
            return false;
        }
        let entry = self.checkpoint.pending.get_mut(&note).unwrap();
        entry.nonce = None;
        entry.transaction_hash = None;
        entry.attempt = NonceAttempts::default();
        self.observed_fees.remove(&note);
        tracing::info!(
            note_id = note,
            nonce,
            "released a reserved nonce that no attempt was broadcast on"
        );
        true
    }

    /// Neither the latest nor the pending transaction count has passed `nonce`.
    async fn nonce_unused(&self, nonce: u64) -> bool {
        self.transaction_count("latest")
            .await
            .is_ok_and(|count| count <= nonce)
            && self
                .transaction_count("pending")
                .await
                .is_ok_and(|count| count <= nonce)
    }

    /// The transaction fee ceiling in force: the lowest of this daemon's, the
    /// signer's and the bound learned from the signer's node.
    fn tx_fee_cap(&self) -> u128 {
        self.config
            .fee
            .tx_fee_cap_wei
            .min(self.signer_tx_fee_cap.unwrap_or(u128::MAX))
            .min(self.node_tx_fee_bound().unwrap_or(u128::MAX))
    }

    /// The ceiling the node's refusals imply: 10/11 of the lowest transaction
    /// fee it refused, which exceeded its RPC fee cap. The node refuses before
    /// its pool and never reports that cap, so each refusal lowers the bids
    /// that follow by at least 9% until one is accepted; the bound stays above
    /// 10/11 of the node's cap.
    fn node_tx_fee_bound(&self) -> Option<u128> {
        self.node_refused_tx_fee
            .map(headroom)
            .filter(|bound| *bound > 0)
    }

    fn learn_node_tx_fee_bound(&mut self, note: u32, refused: u128) {
        let lowest = self
            .node_refused_tx_fee
            .map_or(refused, |lowest| lowest.min(refused));
        self.node_refused_tx_fee = Some(lowest);
        tracing::warn!(
            note_id = note,
            refused_tx_fee_wei = refused,
            node_tx_fee_cap_bound_wei = headroom(lowest),
            "the signer's node refused the transaction fee as above its RPC fee cap; later bids stay within 10/11 of the lowest refused fee until restart"
        );
    }

    /// The highest maxFeePerGas the ceiling allows at `gas`.
    fn tx_fee_limit(&self, gas: u128) -> u128 {
        self.tx_fee_cap() / gas.max(1)
    }

    fn simulation_failed(
        &mut self,
        note: u32,
        base_state: ObligationState,
        error: anyhow::Error,
    ) -> anyhow::Result<()> {
        let revert = vault_revert(&error);
        let reason = match revert {
            Some("NotPendingWithdrawal()" | "ReplayedNullifier()") => {
                // A race with the chain tip: only the confirmed-depth path
                // ever retires an obligation, so re-check next poll.
                self.record(
                    note,
                    Evaluation::new(
                        ObligationState::ResolvedUnconfirmed,
                        Some(EvidenceKind::Finalized),
                    )
                    .detail(format!(
                        "simulation reverted {}; re-checking the withdrawal next poll",
                        revert.unwrap_or_default()
                    )),
                );
                return Ok(());
            }
            Some("StaleRoot()") => BlockedReason::IndexerPathBehind,
            Some(_) => BlockedReason::SimulationReverted,
            None if error.downcast_ref::<RpcError>().is_some() => BlockedReason::SimulationReverted,
            None => BlockedReason::RpcError,
        };
        let detail = match revert {
            Some(name) => format!("simulation reverted {name}: {error}"),
            None => error.to_string(),
        };
        self.record(
            note,
            Evaluation::new(base_state, Some(EvidenceKind::Finalized)).blocked(reason, detail),
        );
        Err(error)
    }

    /// Retain ownership even if the note's withdrawal is completed or replaced.
    /// The caller persists the queue change and this reservation atomically.
    fn detach_nonce(&mut self, note: u32) {
        if let Some(pending) = self.checkpoint.pending.get(&note) {
            if let Some(nonce) = pending.nonce {
                self.checkpoint.detached_nonces.insert(
                    nonce,
                    DetachedNonce {
                        note_id: note,
                        nullifier: pending.nullifier,
                        transaction_hash: pending.transaction_hash.clone(),
                        attempt: pending.attempt.clone(),
                    },
                );
            }
        }
    }

    async fn transaction_count(&self, tag: &str) -> anyhow::Result<u64> {
        quantity(
            &self
                .rpc("eth_getTransactionCount", json!([self.config.sender, tag]))
                .await?,
        )
    }

    async fn nonce_counts(&mut self) -> anyhow::Result<(u64, u64)> {
        let head = quantity(&self.rpc("eth_blockNumber", json!([])).await?)?;
        let latest = self.transaction_count("latest").await?;
        let confirmed = if let Some(block) = head.checked_sub(self.config.confirmations) {
            self.transaction_count(&format!("0x{block:x}")).await?
        } else {
            0
        };
        self.latest_nonce_count = Some(latest);
        // A reorg or newly mined block may race the two reads. Never retire a
        // reservation whose consumption the latest nonce read did not observe.
        Ok((latest, confirmed.min(latest)))
    }

    async fn reconcile_nonce(&mut self, note: u32) -> anyhow::Result<NonceState> {
        let pending = self.checkpoint.pending[&note].clone();
        let Some(nonce) = pending.nonce else {
            return Ok(NonceState::Free);
        };
        let (latest, confirmed) = self.nonce_counts().await?;
        if confirmed > nonce {
            let entry = self.checkpoint.pending.get_mut(&note).unwrap();
            entry.nonce = None;
            entry.transaction_hash = None;
            entry.attempt = NonceAttempts::default();
            self.observed_fees.remove(&note);
            self.persist()?;
            return Ok(NonceState::Free);
        }
        if latest > nonce {
            // Let other notes advance, but retain this ownership until enough
            // confirmations have passed to protect against a tip reorg.
            return Ok(NonceState::Mined);
        }
        // Probe only the current and the most recent superseded candidate.
        for hash in pending
            .transaction_hash
            .iter()
            .chain(pending.attempt.superseded_hashes.last())
        {
            let transaction = self.rpc("eth_getTransactionByHash", json!([hash])).await?;
            if !transaction.is_null() {
                match transaction_fees(&transaction) {
                    Some(fees) => {
                        self.observed_fees.insert(note, fees);
                    }
                    None => {
                        self.observed_fees.remove(&note);
                    }
                }
                return Ok(NonceState::Pending);
            }
        }
        if let Some(hash) = pending.transaction_hash {
            // Unknown to the RPC, but it may still mine: keep the candidate
            // until the nonce is consumed.
            let entry = self.checkpoint.pending.get_mut(&note).unwrap();
            entry.transaction_hash = None;
            push_superseded(&mut entry.attempt, hash);
            self.persist()?;
        }
        // The sender is dedicated, so a pending count past this unmined nonce
        // means an attempt without a known hash occupies it.
        if pending.attempt.unknown_attempt || self.transaction_count("pending").await? > nonce {
            return Ok(NonceState::Held);
        }
        Ok(NonceState::Reserved)
    }

    async fn reconcile_detached_nonces(&mut self) -> anyhow::Result<()> {
        if self.checkpoint.detached_nonces.is_empty() {
            self.detached_status.clear();
            return Ok(());
        }
        let (latest, confirmed) = self.nonce_counts().await?;
        self.checkpoint
            .detached_nonces
            .retain(|nonce, _| *nonce >= confirmed);
        // An unmined nonce that no attempt was broadcast on cannot be pending
        // anywhere: release it instead of blocking every later allocation.
        let unsent: Vec<u64> = self
            .checkpoint
            .detached_nonces
            .iter()
            .filter(|(nonce, entry)| {
                **nonce >= latest
                    && never_broadcast(entry.transaction_hash.as_ref(), &entry.attempt)
            })
            .map(|(nonce, _)| *nonce)
            .collect();
        for nonce in unsent {
            if self.nonce_unused(nonce).await {
                let entry = self.checkpoint.detached_nonces.remove(&nonce).unwrap();
                tracing::info!(
                    note_id = entry.note_id,
                    nonce,
                    "released a detached nonce that no attempt was broadcast on"
                );
            }
        }
        self.persist()?;
        self.detached_status = self
            .checkpoint
            .detached_nonces
            .iter()
            .map(|(nonce, entry)| {
                let wei = |value: &Option<String>| {
                    value
                        .as_deref()
                        .and_then(parse_hex_u128)
                        .map(|wei| wei.to_string())
                };
                DetachedNonceStatus {
                    nonce: *nonce,
                    note_id: entry.note_id,
                    nullifier: entry.nullifier,
                    transaction_hash: entry.transaction_hash.clone(),
                    superseded_hashes: entry.attempt.superseded_hashes.clone(),
                    max_fee_per_gas_wei: wei(&entry.attempt.max_fee_per_gas),
                    max_priority_fee_per_gas_wei: wei(&entry.attempt.max_priority_fee_per_gas),
                    gas_limit: entry.attempt.gas_limit,
                    mined: *nonce < latest,
                }
            })
            .collect();
        if let Some((nonce, entry)) = self
            .checkpoint
            .detached_nonces
            .iter()
            .find(|(nonce, _)| **nonce >= latest)
        {
            bail!(
                "unmined reserved nonce {nonce} for completed or replaced note {} requires signer intervention; refusing conflicting challenge submission",
                entry.note_id
            );
        }
        Ok(())
    }

    /// The first unresolved nonce that blocks new allocations, if any.
    fn queue_blocker(&self) -> Option<(u64, u32)> {
        self.detached_status
            .iter()
            .find(|entry| !entry.mined)
            .map(|entry| (entry.nonce, entry.note_id))
            .or_else(|| {
                self.checkpoint
                    .pending
                    .iter()
                    .filter(|(_, entry)| entry.transaction_hash.is_none())
                    .find_map(|(note, entry)| entry.nonce.map(|nonce| (nonce, *note)))
            })
    }

    /// Escalation urgency for a send: the most urgent deadline among this
    /// obligation and every obligation queued behind it (holding a later
    /// nonce, or waiting for one) whose evidence exists or is expected.
    fn queue_severity(&self, note: u32, head: &HeadInfo) -> Severity {
        let thresholds = self.thresholds();
        let own_nonce = self
            .checkpoint
            .pending
            .get(&note)
            .and_then(|entry| entry.nonce);
        self.checkpoint
            .pending
            .iter()
            .filter(|(other, entry)| {
                **other == note
                    || match (own_nonce, entry.nonce) {
                        (Some(own), Some(theirs)) => theirs > own,
                        (_, None) => true,
                        (None, Some(_)) => false,
                    }
            })
            .filter(|(other, entry)| {
                **other == note
                    || match self.watcher.evidence_status(&entry.nullifier) {
                        Ok(EvidenceStatus::Ready(_)) => true,
                        Ok(EvidenceStatus::AwaitingSettlement(progress)) => {
                            progress.lease_status.is_some()
                        }
                        _ => false,
                    }
            })
            .filter_map(|(_, entry)| entry.challenge_deadline)
            // An expired obligation can no longer be challenged.
            .filter(|deadline| *deadline > head.timestamp)
            .map(|deadline| {
                challenge_status::deadline_severity(Some(deadline - head.timestamp), thresholds)
            })
            .max()
            .unwrap_or(Severity::Ok)
    }

    fn persisted_fees(&self, note: u32) -> Option<Fees> {
        let attempt = &self.checkpoint.pending.get(&note)?.attempt;
        Some(Fees {
            max_fee: parse_hex_u128(attempt.max_fee_per_gas.as_deref()?)?,
            tip: parse_hex_u128(attempt.max_priority_fee_per_gas.as_deref()?)?,
        })
    }

    fn thresholds(&self) -> RemainingThresholds {
        self.config
            .alarms
            .remaining_thresholds(self.challenge_period)
    }

    fn record(&mut self, note: u32, mut evaluation: Evaluation) {
        let now = unix_now();
        match evaluation.blocked {
            Some(_) => {
                let entry = self.blocked_since.entry(note).or_insert((now, 0));
                entry.1 = entry.1.saturating_add(1);
            }
            None => {
                self.blocked_since.remove(&note);
            }
        }
        evaluation.evaluated_at = now;
        self.evaluations.insert(note, evaluation);
    }

    /// Keep the last known state of an obligation that could not be
    /// evaluated, marked with why.
    fn evaluate_failure(&mut self, note: u32, reason: BlockedReason, error: &anyhow::Error) {
        let previous = self
            .evaluations
            .get(&note)
            .or_else(|| self.previous_evaluations.get(&note))
            .cloned()
            .unwrap_or_else(|| Evaluation::new(ObligationState::Unevaluated, None));
        self.record(note, previous.blocked(reason, error.to_string()));
    }

    fn finish_poll(&mut self, result: &anyhow::Result<()>) {
        let now = unix_now();
        self.poll.last_completed_at = Some(now);
        match result {
            Ok(()) => {
                self.poll.consecutive_failures = 0;
                self.poll.last_error = None;
                self.poll.last_success_at = Some(now);
            }
            Err(error) => {
                self.poll.consecutive_failures = self.poll.consecutive_failures.saturating_add(1);
                self.poll.last_error = Some(bounded(&error.to_string()));
            }
        }
        self.publish();
    }

    fn publish(&mut self) {
        let now = unix_now();
        let snapshot = self.build_status(now);
        let current = challenge_status::evaluate(&snapshot, &self.config.alarms, now);
        self.log_transitions(&current, now);
        match self.status.write() {
            Ok(mut status) => *status = current,
            Err(poisoned) => *poisoned.into_inner() = current,
        }
    }

    fn build_status(&self, now: u64) -> ChallengeStatus {
        let head = self.head.as_ref();
        let fee = &self.config.fee;
        let gas = self.last_gas.unwrap_or(DEFAULT_CHALLENGE_GAS);
        let proposed = head.map(|head| {
            head.base_fee
                .map_or(fee.max_fee_per_gas, |base| {
                    fee.max_fee_per_gas.min(
                        base.saturating_mul(2)
                            .saturating_add(fee.priority_fee_per_gas),
                    )
                })
                .min(self.tx_fee_limit(gas))
        });
        let mut obligations = Vec::new();
        let mut outstanding = 0u64;
        for (note, pending) in &self.checkpoint.pending {
            let evaluation = self.evaluations.get(note);
            let state = evaluation.map_or(ObligationState::Unevaluated, |e| e.state);
            let settlement = evaluation.and_then(|e| e.settlement.clone());
            let wei = |value: &Option<String>| {
                value
                    .as_deref()
                    .and_then(parse_hex_u128)
                    .map(|wei| wei.to_string())
            };
            let obligation = ObligationStatus {
                note_id: *note,
                nullifier: pending.nullifier,
                state,
                severity: Severity::Ok,
                challenge_deadline: pending.challenge_deadline,
                seconds_remaining: None,
                evidence: evaluation.and_then(|e| e.evidence),
                blocked_reason: evaluation.and_then(|e| e.blocked),
                detail: evaluation.and_then(|e| e.detail.clone()),
                blocked_since: self.blocked_since.get(note).map(|(since, _)| *since),
                consecutive_failures: self.blocked_since.get(note).map_or(0, |(_, count)| *count),
                settlement,
                nonce: pending.nonce,
                transaction_hash: pending.transaction_hash.clone(),
                superseded_hashes: pending.attempt.superseded_hashes.clone(),
                max_fee_per_gas_wei: wei(&pending.attempt.max_fee_per_gas),
                max_priority_fee_per_gas_wei: wei(&pending.attempt.max_priority_fee_per_gas),
                attempts: pending.attempt.attempts,
                submitted_block: pending.attempt.submitted_block,
                first_seen_at: pending.first_seen_at,
                evaluated_at: evaluation.map(|e| e.evaluated_at),
            };
            let may_need_gas = match state {
                ObligationState::Unevaluated
                | ObligationState::Ready
                | ObligationState::Submitted
                | ObligationState::MinedUnconfirmed => true,
                ObligationState::AwaitingSettlement => {
                    !challenge_status::evidence_never_expected(&obligation)
                }
                _ => false,
            };
            if may_need_gas {
                outstanding += 1;
            }
            obligations.push(obligation);
        }
        let mut sender = self.sender.clone();
        sender.balance_wei = self.sender_balance.map(|balance| balance.to_string());
        sender.outstanding_obligations = outstanding;
        sender.proposed_max_fee_per_gas_wei = proposed.map(|fee| fee.to_string());
        sender.required_balance_wei = proposed.filter(|_| outstanding > 0).map(|fee| {
            (outstanding as u128)
                .saturating_mul(gas)
                .saturating_mul(fee)
                .to_string()
        });
        sender.signer_tx_fee_cap_wei = self.signer_tx_fee_cap.map(|cap| cap.to_string());
        sender.node_tx_fee_cap_bound_wei = self.node_tx_fee_bound().map(|bound| bound.to_string());
        sender.effective_tx_fee_cap_wei = self.tx_fee_cap().to_string();
        sender.challenge_gas_limit = self.last_gas.and_then(|gas| u64::try_from(gas).ok());
        sender.tx_fee_cap_max_fee_per_gas_wei =
            self.last_gas.map(|gas| self.tx_fee_limit(gas).to_string());
        let mut config_warnings = self.config_warnings.clone();
        config_warnings.extend(self.startup_warning.clone());
        config_warnings.extend(self.vault_warning.clone());
        if let Some(signer) = self
            .signer_tx_fee_cap
            .filter(|cap| *cap != fee.tx_fee_cap_wei)
        {
            config_warnings.push(format!(
                "the signer's tx_fee_cap_wei {signer} differs from --tx-fee-cap-wei {}; bids stay within the lower",
                fee.tx_fee_cap_wei
            ));
        }
        if let Some((refused, bound)) = self.node_refused_tx_fee.zip(self.node_tx_fee_bound()) {
            config_warnings.push(format!(
                "the signer's node refused a transaction fee of {refused} wei (upstream_tx_fee_cap): its RPC fee cap is below the ceiling, so bids stay within {bound} wei until restart; set ZKAPI_CHALLENGE_TX_FEE_CAP_WEI for the signer and this daemon to the node's --rpc.txfeecap and restart both, or raise the node's cap and restart this daemon"
            ));
        }
        // A real challenge needs about 7.6M gas: a fee cap above the ceiling
        // per gas is never reached.
        let challenge_gas = gas.max(DEFAULT_CHALLENGE_GAS);
        if fee.max_fee_per_gas.saturating_mul(challenge_gas) > self.tx_fee_cap() {
            config_warnings.push(format!(
                "--max-fee-per-gas-wei {} x {challenge_gas} gas exceeds the transaction fee ceiling of {} wei; bids stop at {} wei per gas (raise the ceiling with the upstream node's RPC fee cap, or lower the fee cap)",
                fee.max_fee_per_gas,
                self.tx_fee_cap(),
                self.tx_fee_limit(challenge_gas)
            ));
        }
        let mut indexer = self.indexer.clone();
        if indexer.root.is_none() && indexer.state == IndexerState::Unknown {
            indexer.detail = Some("not yet observed".into());
        }
        let mut status = ChallengeStatus::initial(
            ChainStatus {
                chain_id: self.config.chain_id,
                vault: self.vault_address(),
                latest_block: head.map(|head| head.number),
                latest_block_timestamp: head.map(|head| head.timestamp),
                head_observed_at: self.head_seen.map(|(_, at)| at),
                head_age_seconds: None,
                base_fee_per_gas_wei: head
                    .and_then(|head| head.base_fee)
                    .map(|fee| fee.to_string()),
                scan_next_block: self.checkpoint.next_block,
                scan_lag_blocks: head.map(|head| {
                    head.number
                        .checked_sub(self.config.confirmations)
                        .map_or(0, |safe| {
                            safe.saturating_add(1)
                                .saturating_sub(self.checkpoint.next_block)
                        })
                }),
                confirmations: self.config.confirmations,
                challenge_period_seconds: self.challenge_period,
                vault_root: self.vault_root,
            },
            sender,
            self.started_at,
        );
        status.generated_at = now;
        status.poll = self.poll.clone();
        status.indexer = indexer;
        status.obligations = obligations;
        status.detached_nonces = self.detached_status.clone();
        status.missed_total = self.checkpoint.missed_total;
        status.last_missed = self.checkpoint.last_missed.clone();
        status.config_warnings = config_warnings;
        status
    }

    /// Log each obligation's state transitions at a level matching its
    /// severity, and re-log critical ones periodically.
    fn log_transitions(&mut self, status: &ChallengeStatus, now: u64) {
        self.logged
            .retain(|note, _| self.checkpoint.pending.contains_key(note));
        for o in &status.obligations {
            let key = (o.state, o.severity, o.blocked_reason);
            let relog = o.severity == Severity::Critical
                && self
                    .logged
                    .get(&o.note_id)
                    .is_some_and(|(.., at)| now.saturating_sub(*at) >= RELOG_SECONDS);
            if self
                .logged
                .get(&o.note_id)
                .is_some_and(|(state, severity, blocked, _)| (*state, *severity, *blocked) == key)
                && !relog
            {
                continue;
            }
            self.logged
                .insert(o.note_id, (o.state, o.severity, o.blocked_reason, now));
            let state = challenge_status::wire_name(o.state);
            let blocked = o.blocked_reason.map(challenge_status::wire_name);
            match o.severity {
                Severity::Ok => {
                    tracing::info!(note_id = o.note_id, nullifier = %o.nullifier, state, severity = "ok", blocked_reason = ?blocked, seconds_remaining = ?o.seconds_remaining, "challenge obligation status changed")
                }
                Severity::Warning => {
                    tracing::warn!(note_id = o.note_id, nullifier = %o.nullifier, state, severity = "warning", blocked_reason = ?blocked, seconds_remaining = ?o.seconds_remaining, detail = ?o.detail, "challenge obligation status changed")
                }
                Severity::Critical => {
                    tracing::error!(note_id = o.note_id, nullifier = %o.nullifier, state, severity = "critical", blocked_reason = ?blocked, seconds_remaining = ?o.seconds_remaining, detail = ?o.detail, "challenge obligation status changed")
                }
            }
        }
    }

    fn vault_address(&self) -> String {
        format!(
            "0x{}",
            hex::encode(&self.config.contract_address.as_bytes()[12..])
        )
    }

    async fn withdrawal_state(
        &self,
        note: u32,
        block: Option<u64>,
    ) -> anyhow::Result<WithdrawalState> {
        let mut query = selector("pendingWithdrawals(uint32)");
        query.extend_from_slice(Felt252::from_u64(note as u64).as_bytes());
        let state = match block {
            None => self.call(query).await?,
            Some(block) => self.call_at(query, json!(format!("0x{block:x}"))).await?,
        };
        ensure!(
            state.len() == 6,
            if block.is_none() {
                "malformed pending withdrawal response"
            } else {
                "malformed confirmed withdrawal response"
            }
        );
        Ok(WithdrawalState {
            exists: state[0] != Felt252::ZERO,
            nullifier: state[2],
            deadline: felt_u64(&state[5])?,
        })
    }

    async fn live_root(&mut self) -> anyhow::Result<Felt252> {
        let root = self.call(selector("currentRoot()")).await?;
        ensure!(root.len() == 1, "malformed currentRoot response");
        self.vault_root = Some(root[0]);
        Ok(root[0])
    }

    /// The vault root at a block named by hash (EIP-1898).
    async fn root_at_block_hash(&self, block_hash: &str) -> anyhow::Result<Felt252> {
        let root = self
            .call_at(
                selector("currentRoot()"),
                json!({ "blockHash": block_hash }),
            )
            .await?;
        ensure!(root.len() == 1, "malformed currentRoot response");
        Ok(root[0])
    }

    async fn call(&self, data: Vec<u8>) -> anyhow::Result<Vec<Felt252>> {
        self.call_at(data, json!("latest")).await
    }

    async fn call_at(&self, data: Vec<u8>, block: Value) -> anyhow::Result<Vec<Felt252>> {
        words(&self.rpc("eth_call", json!([{ "to": self.vault_address(), "data": format!("0x{}", hex::encode(data)) }, block])).await?)
    }

    async fn rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        self.rpc_with_timeout(method, params, None).await
    }

    async fn rpc_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Value> {
        let mut request = self
            .client
            .post(&self.config.rpc_url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }));
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let transport = |error: reqwest::Error| TransportError {
            method: method.into(),
            unsent: error.is_connect() || error.is_builder(),
            message: error.without_url().to_string(),
        };
        let response: Value = request
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(transport)?
            .json()
            .await
            .map_err(transport)?;
        if let Some(error) = response.get("error") {
            return Err(RpcError {
                method: method.into(),
                error: error.clone(),
            }
            .into());
        }
        response
            .get("result")
            .cloned()
            .with_context(|| format!("{method}: missing RPC result"))
    }

    /// The indexer's internal /health phase (`syncing`, `diverged`, ...),
    /// which it reports with a 503 whenever it is not serving.
    async fn indexer_health_phase(&self) -> Option<String> {
        let response = self
            .client
            .get(format!(
                "{}/health",
                self.config.indexer_url.trim_end_matches('/')
            ))
            .timeout(INDEXER_TIMEOUT)
            .send()
            .await
            .ok()?;
        response.json::<IndexerHealth>().await.ok()?.status
    }

    async fn indexer_get<T: DeserializeOwned>(&self, path: &str) -> Result<T, IndexerFailure> {
        let response = self
            .client
            .get(format!(
                "{}{path}",
                self.config.indexer_url.trim_end_matches('/')
            ))
            .timeout(INDEXER_TIMEOUT)
            .send()
            .await
            .map_err(|error| IndexerFailure::Transport(error.without_url().to_string()))?;
        if !response.status().is_success() {
            return Err(IndexerFailure::Status(response.status().as_u16()));
        }
        response
            .json()
            .await
            .map_err(|error| IndexerFailure::Decode(error.without_url().to_string()))
    }

    fn persist(&self) -> anyhow::Result<()> {
        let path = &self.config.checkpoint;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("tmp");
        let mut file = std::fs::File::create(&temporary)?;
        std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(&self.checkpoint)?)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}

/// Plan the fees of one send at its exact gas limit. `tx_fee_limit` is the
/// highest maxFeePerGas the transaction fee ceiling allows at that gas limit
/// and bounds every bid like a lower fee cap. A bump raises the tip by the
/// minimum valid replacement step and the fee cap by `bump_percent`.
///
/// Two valid replacements stay in reserve for the critical threshold: other
/// bids stay within 10/11 of 10/11 of the caps, unless the base fee needs
/// more, or rose above a pending bid that cannot otherwise be outbid. A
/// critical send bids 10/11 of the caps, then the caps. `Ok(None)` keeps a
/// pending attempt when only that reserve is left.
fn plan_fees(
    policy: &FeePolicy,
    plan: FeePlan,
    base_fee: Option<u128>,
    critical: bool,
    tx_fee_limit: Option<u128>,
    affordable: Option<u128>,
) -> Result<Option<Fees>, BlockedReason> {
    let caps = Fees {
        max_fee: policy
            .max_fee_per_gas
            .min(tx_fee_limit.unwrap_or(u128::MAX)),
        tip: policy.max_priority_fee_per_gas,
    };
    if base_fee.is_some_and(|base| base > policy.max_fee_per_gas) {
        return Err(BlockedReason::BaseFeeAboveFeeCap);
    }
    if base_fee.is_some_and(|base| base > caps.max_fee) {
        return Err(BlockedReason::TxFeeCapReached);
    }
    let reserve = |steps: u32| {
        (0..steps).fold(caps, |fees, _| Fees {
            max_fee: headroom(fees.max_fee),
            tip: headroom(fees.tip),
        })
    };
    // Just under the caps, unless the base fee already exceeds that bid.
    let critical_target = match base_fee {
        Some(base) if base > headroom(caps.max_fee) => caps,
        _ => reserve(1),
    };
    // The limits of every other bid, raised only as far as the base fee needs.
    let limit = match base_fee {
        Some(base) if base > headroom(caps.max_fee) => caps,
        Some(base) if base > reserve(2).max_fee => reserve(1),
        _ => reserve(2),
    };
    let bid = |tip: u128| {
        base_fee.map_or(limit.max_fee, |base| {
            limit
                .max_fee
                .min(base.saturating_mul(2).saturating_add(tip))
        })
    };
    // A max fee the ceiling keeps from rising 10% (or below the raised tip)
    // is reported first: raising only the tip cap cannot help then.
    let cap_reason = |old: Fees| {
        let pinned = min_bump(old.max_fee).max(min_bump(old.tip)) > caps.max_fee;
        if pinned && caps.max_fee < policy.max_fee_per_gas {
            BlockedReason::TxFeeCapReached
        } else if min_bump(old.tip) > caps.tip {
            BlockedReason::TipCapReached
        } else {
            BlockedReason::FeeCapReached
        }
    };
    let bump = |old: Fees, limit: Fees| {
        let tip = min_bump(old.tip)
            .max(policy.priority_fee_per_gas)
            .min(limit.tip);
        let mut max_fee = old
            .max_fee
            .saturating_mul(100 + policy.bump_percent as u128)
            .div_ceil(100);
        if let Some(base) = base_fee {
            max_fee = max_fee.max(base.saturating_mul(2).saturating_add(tip));
        }
        let fees = Fees {
            max_fee: max_fee.min(limit.max_fee),
            tip,
        };
        is_valid_bump(old, fees).then_some(fees)
    };
    // A target's tip never exceeds its max fee, which the ceiling can lower
    // below the tip cap.
    let escalate = |old: Fees| {
        [critical_target, caps]
            .into_iter()
            .map(|fees| Fees {
                tip: fees.tip.min(fees.max_fee),
                ..fees
            })
            .find(|fees| is_valid_bump(old, *fees))
            .ok_or_else(|| cap_reason(old))
    };
    let mut fees = match plan {
        FeePlan::First if critical => critical_target,
        FeePlan::First => Fees {
            max_fee: bid(policy.priority_fee_per_gas),
            tip: policy.priority_fee_per_gas,
        },
        FeePlan::Resend(old) => {
            let tip = old.tip.min(caps.tip);
            let fees = Fees {
                max_fee: old.max_fee.min(caps.max_fee).max(bid(tip)),
                tip,
            };
            if critical {
                Fees {
                    max_fee: fees.max_fee.max(critical_target.max_fee),
                    tip: fees.tip.max(critical_target.tip),
                }
            } else {
                fees
            }
        }
        FeePlan::Bump(old) if critical => escalate(old)?,
        FeePlan::Bump(old) => match bump(old, limit) {
            Some(fees) => fees,
            // The pending bid can no longer be included: spend the reserve.
            None if base_fee.is_some_and(|base| base > old.max_fee) => escalate(old)?,
            None if bump(old, caps).is_none() => return Err(cap_reason(old)),
            None => return Ok(None),
        },
    };
    fees.tip = fees.tip.min(fees.max_fee);
    let mut clamped = false;
    if let Some(limit) = affordable.filter(|limit| fees.max_fee > *limit) {
        fees.max_fee = limit;
        fees.tip = fees.tip.min(limit);
        clamped = true;
    }
    let includable = fees.tip > 0 && base_fee.is_none_or(|base| fees.max_fee >= base);
    let valid = match plan {
        FeePlan::Bump(old) => is_valid_bump(old, fees),
        _ => true,
    };
    if clamped && !(includable && valid) {
        return Err(BlockedReason::InsufficientBalance);
    }
    if !includable {
        return Err(BlockedReason::BaseFeeAboveFeeCap);
    }
    Ok(Some(fees))
}

/// Every attempt recorded on a nonce was a definite non-broadcast: a signer
/// refusal, a failure the signer reports before broadcasting, or a connection
/// never made. Any other attempt leaves a candidate hash or an unknown attempt,
/// and a reservation an older daemon made leaves no record at all.
fn never_broadcast(transaction_hash: Option<&String>, attempt: &NonceAttempts) -> bool {
    transaction_hash.is_none()
        && attempt.superseded_hashes.is_empty()
        && !attempt.unknown_attempt
        && !attempt.unrecorded_attempt
        && attempt.attempts > 0
}

/// The blocked reason of a definitive signer refusal.
fn refusal_reason(reason: Option<&str>) -> BlockedReason {
    match reason {
        Some("base_fee_above_max_fee") => BlockedReason::BaseFeeAboveMaxFee,
        Some("insufficient_balance") => BlockedReason::InsufficientBalance,
        Some("tx_fee_above_cap") => BlockedReason::TxFeeAboveCap,
        Some("upstream_tx_fee_cap") => BlockedReason::UpstreamTxFeeCap,
        _ => BlockedReason::SignerRefused,
    }
}

/// The signer's transaction fee cap from a `tx_fee_above_cap` refusal: its
/// `tx_fee_cap_wei`, or else `max_fee_per_gas_allowed` x the gas limit.
fn refused_tx_fee_cap(error: &anyhow::Error, gas: u64) -> Option<u128> {
    let data = error.downcast_ref::<RpcError>()?.error.get("data")?;
    let field = |name: &str| data.get(name).and_then(|value| quantity_u128(value).ok());
    field("tx_fee_cap_wei")
        .or_else(|| {
            Some(
                field("max_fee_per_gas_allowed")?
                    .saturating_mul(field("gas_limit").unwrap_or(u128::from(gas))),
            )
        })
        .filter(|cap| *cap > 0)
}

/// Gas limit x maxFeePerGas of a refused send: the refusal's `gas_limit` and
/// `max_fee_per_gas` (the bundled signer reports both with
/// `upstream_tx_fee_cap`), else the send's own. A reported fee that leaves
/// no bound (zero) cannot be what the node refused; like a zero signer cap,
/// it is ignored for the send's own.
fn refused_tx_fee(error: &anyhow::Error, gas: u64, max_fee: u128) -> u128 {
    let data = error
        .downcast_ref::<RpcError>()
        .and_then(|rpc| rpc.error.get("data"));
    let field = |name: &str| {
        data.and_then(|data| data.get(name))
            .and_then(|value| quantity_u128(value).ok())
    };
    let reported = field("gas_limit")
        .unwrap_or(u128::from(gas))
        .saturating_mul(field("max_fee_per_gas").unwrap_or(max_fee));
    if headroom(reported) > 0 {
        reported
    } else {
        u128::from(gas).saturating_mul(max_fee)
    }
}

/// The smallest value nodes accept as a 10% replacement bump.
fn min_bump(value: u128) -> u128 {
    value.saturating_mul(110).div_ceil(100)
}

/// The largest value that still leaves one valid bump below `cap`.
fn headroom(cap: u128) -> u128 {
    cap.saturating_mul(10) / 11
}

/// Geth, reth, erigon and besu replace a pending transaction only when both
/// fees rise by at least 10%.
fn is_valid_bump(old: Fees, new: Fees) -> bool {
    new.max_fee >= min_bump(old.max_fee) && new.tip >= min_bump(old.tip) && new.tip <= new.max_fee
}

/// Fees of a pending transaction object; a legacy one bids its gas price as
/// both fees.
fn transaction_fees(transaction: &Value) -> Option<Fees> {
    let field = |name: &str| {
        transaction
            .get(name)
            .filter(|value| !value.is_null())
            .and_then(|value| quantity_u128(value).ok())
    };
    match (field("maxFeePerGas"), field("maxPriorityFeePerGas")) {
        (Some(max_fee), Some(tip)) => Some(Fees { max_fee, tip }),
        _ => field("gasPrice").map(|price| Fees {
            max_fee: price,
            tip: price,
        }),
    }
}

fn push_superseded(attempt: &mut NonceAttempts, hash: String) {
    if !attempt.superseded_hashes.contains(&hash) {
        attempt.superseded_hashes.push(hash);
    }
    let excess = attempt
        .superseded_hashes
        .len()
        .saturating_sub(MAX_SUPERSEDED_HASHES);
    attempt.superseded_hashes.drain(..excess);
}

fn classify_send_error(error: &anyhow::Error) -> SendFailure {
    if error
        .downcast_ref::<TransportError>()
        .is_some_and(|transport| transport.unsent)
    {
        return SendFailure::NotBroadcast(BlockedReason::RpcError);
    }
    // Timeouts, HTTP errors and broken responses may follow a broadcast.
    let Some(rpc) = error.downcast_ref::<RpcError>() else {
        return SendFailure::Ambiguous(None);
    };
    match (rpc.code(), rpc.reason()) {
        (Some(-32602 | -32601 | -32003), reason) => SendFailure::Refused(reason.map(str::to_owned)),
        (Some(-32000), Some("simulation_failed")) => {
            SendFailure::NotBroadcast(BlockedReason::SimulationReverted)
        }
        (
            Some(-32000),
            Some(
                "upstream_unavailable"
                | "upstream_rejected"
                | "upstream_chain_mismatch"
                | "base_fee_unavailable",
            ),
        ) => SendFailure::NotBroadcast(BlockedReason::RpcError),
        _ => SendFailure::Ambiguous(rpc.transaction_hash()),
    }
}

/// The vault custom error a simulation reverted with, when the RPC passes the
/// revert data through.
fn vault_revert(error: &anyhow::Error) -> Option<&'static str> {
    let rpc = error.downcast_ref::<RpcError>()?;
    let candidates = [
        rpc.error.get("data").and_then(Value::as_str),
        rpc.error
            .get("data")
            .and_then(|data| data.get("data"))
            .and_then(Value::as_str),
        rpc.error.get("message").and_then(Value::as_str),
    ];
    [
        "StaleRoot()",
        "UnknownRoot()",
        "ChallengeExpired()",
        "NotPendingWithdrawal()",
        "ChallengedNullifier()",
        "ReplayedNullifier()",
    ]
    .into_iter()
    .find(|signature| {
        let selector = hex::encode(selector(signature));
        candidates
            .iter()
            .flatten()
            .any(|text| text.to_ascii_lowercase().contains(&selector))
    })
}

fn rpc_code(error: &anyhow::Error) -> Option<i64> {
    error.downcast_ref::<RpcError>()?.code()
}

fn bounded(text: &str) -> String {
    text.chars().take(MAX_ERROR_CHARS).collect()
}

#[derive(Deserialize)]
struct PathResponse {
    note_id: u32,
    leaf: Felt252,
    siblings: Vec<Felt252>,
    #[serde(default)]
    root: Option<Felt252>,
    #[serde(default)]
    block_number: Option<u64>,
    #[serde(default)]
    block_hash: Option<String>,
}

#[derive(Deserialize)]
struct TreeRootResponse {
    root: Felt252,
    #[serde(default)]
    block_number: Option<u64>,
    #[serde(default)]
    block_hash: Option<String>,
}

#[derive(Deserialize)]
struct IndexerHealth {
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize)]
struct PendingEscapesResponse {
    /// The block of the indexer's view the list was taken from.
    #[serde(default)]
    block_number: Option<u64>,
    escapes: Vec<PendingEscape>,
}

/// Only the note ID is authoritative; the vault supplies the rest.
#[derive(Deserialize)]
struct PendingEscape {
    note_id: u32,
    withdrawal_nullifier: Felt252,
    #[serde(default)]
    challenge_deadline: Option<u64>,
}

fn selector(signature: &str) -> Vec<u8> {
    Keccak256::digest(signature.as_bytes())[..4].to_vec()
}
fn quantity(value: &Value) -> anyhow::Result<u64> {
    let value = quantity_u128(value)?;
    u64::try_from(value).context("quantity exceeds uint64")
}
fn quantity_u128(value: &Value) -> anyhow::Result<u128> {
    let value = value
        .as_str()
        .context("expected hex quantity")?
        .strip_prefix("0x")
        .context("hex quantity lacks prefix")?;
    parse_digits_u128(value).context("quantity exceeds uint128")
}
fn parse_hex_u128(value: &str) -> Option<u128> {
    parse_digits_u128(value.strip_prefix("0x")?)
}
fn parse_digits_u128(digits: &str) -> Option<u128> {
    if digits.chars().all(|c| c == '0') {
        return Some(0);
    }
    u128::from_str_radix(digits.trim_start_matches('0'), 16).ok()
}
fn felt_u64(value: &Felt252) -> anyhow::Result<u64> {
    ensure!(
        value.as_bytes()[..24].iter().all(|byte| *byte == 0),
        "value exceeds uint64"
    );
    Ok(u64::from_be_bytes(
        value.as_bytes()[24..].try_into().unwrap(),
    ))
}
fn words(value: &Value) -> anyhow::Result<Vec<Felt252>> {
    let raw = value
        .as_str()
        .context("expected ABI bytes")?
        .strip_prefix("0x")
        .context("ABI bytes lack prefix")?;
    let bytes = hex::decode(raw)?;
    ensure!(bytes.len().is_multiple_of(32), "malformed ABI words");
    Ok(bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|chunk| Felt252(*chunk))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watcher::tests::{
        finalized_transcript, finalized_v2_request, two_finalized_v2_requests,
    };
    use axum::{
        extract::{Path, State},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::{get, post},
        Json, Router,
    };
    use std::{collections::VecDeque, sync::Mutex};
    use zkapi_types::wire::{ApiRequestV2, CurvePointWire};

    const ONE_ETHER: u128 = 1_000_000_000_000_000_000;

    struct MockChain {
        nullifier: Felt252,
        active: bool,
        confirmed_active: bool,
        mined_nonce: u64,
        pending_nonce: Option<u64>,
        confirmed_nonce: Option<u64>,
        transaction_known: bool,
        withdrawals: BTreeMap<u32, (bool, Felt252, u64)>,
        event_note: u32,
        fail_note_one: bool,
        reorg_during_scan: bool,
        block_hash: String,
        sends: Vec<Value>,
        fail_first_send: bool,
        root: Felt252,
        siblings: [Felt252; MERKLE_DEPTH],
        head_number: u64,
        head_timestamp: u64,
        /// Deadline of note 0 (and of notes without an explicit withdrawal).
        deadline: u64,
        base_fee: Option<u128>,
        state_key: (Felt252, Felt252),
        balance: Option<u128>,
        fail_all: bool,
        send_errors: VecDeque<Value>,
        refuse_notes: BTreeSet<u32>,
        drop_logs: bool,
        /// None: an indexer that predates /v1/escapes/pending.
        escapes: Option<Vec<Value>>,
        /// The block the pending-escapes list is served at; None: the head.
        escapes_block: Option<u64>,
        indexer_root: Option<Value>,
        indexer_health: &'static str,
        roots_by_hash: BTreeMap<String, Felt252>,
        path_unavailable: u32,
        path_meta: Option<Value>,
        simulation_error: Option<Value>,
        legacy_gas_price: Option<u128>,
        /// eth_estimateGas answer; the default 10M gas gives a 12M gas limit.
        estimate: u64,
        /// Sends whose gas x maxFeePerGas exceeds the cap are refused with
        /// the reason: `tx_fee_above_cap` (the bundled signer),
        /// `upstream_tx_fee_cap` (its node), or `broadcast_ambiguous` (an
        /// earlier signer relaying its node's rejection, with a hash no node
        /// knows).
        tx_fee_cap: Option<(u128, &'static str)>,
        fee_capped_sends: usize,
        fee_capped_hashes: BTreeSet<String>,
        /// The zkapi_signerStatus result; None: an RPC without the method.
        signer_status: Option<Value>,
        /// pendingWithdrawals reads per note.
        withdrawal_reads: BTreeMap<u32, usize>,
    }

    impl MockChain {
        fn new(nullifier: Felt252, state_key: (Felt252, Felt252)) -> Self {
            let siblings = zkapi_core::v2::zero_hashes()[..MERKLE_DEPTH]
                .try_into()
                .unwrap();
            let now = unix_now();
            Self {
                nullifier,
                active: true,
                confirmed_active: true,
                mined_nonce: 3,
                pending_nonce: None,
                confirmed_nonce: None,
                transaction_known: true,
                withdrawals: BTreeMap::new(),
                event_note: 0,
                fail_note_one: false,
                reorg_during_scan: false,
                block_hash: "0xforkA".into(),
                sends: vec![],
                fail_first_send: false,
                root: zkapi_core::v2::merkle_root(0, &Felt252::ZERO, &siblings),
                siblings,
                head_number: 5,
                head_timestamp: now,
                deadline: now + 100,
                base_fee: Some(GWEI),
                state_key,
                balance: Some(1_000 * GWEI * GWEI),
                fail_all: false,
                send_errors: VecDeque::new(),
                refuse_notes: BTreeSet::new(),
                drop_logs: false,
                escapes: Some(vec![]),
                escapes_block: None,
                indexer_root: None,
                indexer_health: "ok",
                roots_by_hash: BTreeMap::new(),
                path_unavailable: 0,
                path_meta: None,
                simulation_error: None,
                legacy_gas_price: None,
                estimate: 10_000_000,
                tx_fee_cap: None,
                fee_capped_sends: 0,
                fee_capped_hashes: BTreeSet::new(),
                signer_status: None,
                withdrawal_reads: BTreeMap::new(),
            }
        }
    }

    fn encoded(values: &[Felt252]) -> Value {
        json!(format!(
            "0x{}",
            hex::encode(
                values
                    .iter()
                    .flat_map(|v| v.as_bytes().iter().copied())
                    .collect::<Vec<_>>()
            )
        ))
    }

    fn hex_quantity(value: u128) -> Value {
        json!(format!("0x{value:x}"))
    }

    fn rpc_error(code: i64, message: &str) -> Response {
        Json(json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": code, "message": message } }))
            .into_response()
    }

    fn call_data(signature: &str) -> String {
        format!("0x{}", hex::encode(selector(signature)))
    }

    async fn rpc(
        State(state): State<Arc<Mutex<MockChain>>>,
        Json(request): Json<Value>,
    ) -> Response {
        let mut state = state.lock().unwrap();
        if state.fail_all {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let method = request["method"].as_str().unwrap();
        let result = match method {
            "eth_chainId" => json!("0x1"),
            "eth_blockNumber" => hex_quantity(state.head_number as u128),
            "eth_getBlockByNumber" => {
                let mut block = json!({
                    "hash": state.block_hash,
                    "number": hex_quantity(state.head_number as u128),
                    "timestamp": hex_quantity(state.head_timestamp as u128),
                });
                if let Some(fee) = state.base_fee {
                    block["baseFeePerGas"] = hex_quantity(fee);
                }
                block
            }
            "eth_getLogs" => {
                if state.reorg_during_scan {
                    state.block_hash = "0xforkB".into();
                    state.reorg_during_scan = false;
                }
                if state.drop_logs {
                    json!([])
                } else {
                    json!([{
                        "topics": [format!("0x{}", hex::encode(Keccak256::digest(ESCAPE_EVENT.as_bytes()))), format!("0x{:064x}", state.event_note)],
                        "data": encoded(&[state.nullifier, Felt252::from_u64(100), Felt252::from_u64(5), Felt252::from_u64(state.deadline), state.root])
                    }])
                }
            }
            "eth_call" => {
                let data = request["params"][0]["data"].as_str().unwrap();
                let block = &request["params"][1];
                if state.fail_note_one
                    && data
                        == format!(
                            "{}{}",
                            call_data("pendingWithdrawals(uint32)"),
                            hex::encode(Felt252::ONE.as_bytes())
                        )
                {
                    return rpc_error(-32000, "temporary note-state failure");
                }
                if data.starts_with(&call_data("pendingWithdrawals(uint32)")) {
                    let note = u32::from_str_radix(&data[data.len() - 8..], 16).unwrap();
                    *state.withdrawal_reads.entry(note).or_default() += 1;
                    if let Some((active, nullifier, deadline)) = state.withdrawals.get(&note) {
                        encoded(&[
                            Felt252::from_u64(*active as u64),
                            Felt252::from_u64(8),
                            *nullifier,
                            Felt252::from_u64(100),
                            Felt252::from_u64(5),
                            Felt252::from_u64(*deadline),
                        ])
                    } else {
                        encoded(&[
                            Felt252::from_u64(if *block == "latest" {
                                state.active as u64
                            } else {
                                state.confirmed_active as u64
                            }),
                            Felt252::from_u64(8),
                            state.nullifier,
                            Felt252::from_u64(100),
                            Felt252::from_u64(5),
                            Felt252::from_u64(state.deadline),
                        ])
                    }
                } else if data == call_data("currentRoot()") {
                    match block.get("blockHash").and_then(Value::as_str) {
                        Some(hash) => match state.roots_by_hash.get(hash) {
                            Some(root) => encoded(&[*root]),
                            None => return rpc_error(-32000, "header for hash not found"),
                        },
                        None => encoded(&[state.root]),
                    }
                } else if data == call_data("challengePeriod()") {
                    encoded(&[Felt252::from_u64(86_400)])
                } else if data == call_data("stateSigningKeyX()") {
                    encoded(&[state.state_key.0])
                } else if data == call_data("stateSigningKeyY()") {
                    encoded(&[state.state_key.1])
                } else if data.starts_with(&call_data(crate::watcher::CHALLENGE_SIGNATURE)) {
                    if let Some(error) = &state.simulation_error {
                        return Json(json!({ "jsonrpc": "2.0", "id": 1, "error": error }))
                            .into_response();
                    }
                    json!("0x")
                } else {
                    json!("0x")
                }
            }
            "eth_estimateGas" => hex_quantity(state.estimate as u128),
            "eth_getTransactionCount" => hex_quantity(if request["params"][1] == "pending" {
                state.pending_nonce.unwrap_or(state.mined_nonce)
            } else if request["params"][1] == "latest" {
                state.mined_nonce
            } else {
                state.confirmed_nonce.unwrap_or(state.mined_nonce)
            } as u128),
            "eth_getBalance" => match state.balance {
                Some(balance) => hex_quantity(balance),
                None => return rpc_error(-32601, "RPC method is not allowed"),
            },
            "eth_sendTransaction" => {
                let transaction = request["params"][0].clone();
                state.sends.push(transaction.clone());
                if let Some(error) = state.send_errors.pop_front() {
                    return Json(json!({ "jsonrpc": "2.0", "id": 1, "error": error }))
                        .into_response();
                }
                if state.fail_first_send {
                    state.fail_first_send = false;
                    return rpc_error(-32000, "temporary signer failure");
                }
                let note = u32::from_str_radix(&transaction["data"].as_str().unwrap()[10..74], 16)
                    .unwrap();
                if state.refuse_notes.contains(&note) {
                    return Json(json!({ "jsonrpc": "2.0", "id": 1, "error": {
                        "code": -32602, "message": "Requested fees are outside the configured bounds",
                        "data": { "reason": "fee_out_of_bounds" } } }))
                    .into_response();
                }
                if let Some((cap, reason)) = state.tx_fee_cap {
                    let gas = quantity_u128(&transaction["gas"]).unwrap();
                    let max_fee = quantity_u128(&transaction["maxFeePerGas"]).unwrap();
                    if gas * max_fee > cap {
                        state.fee_capped_sends += 1;
                        let (code, data) = match reason {
                            "tx_fee_above_cap" => (
                                -32003,
                                json!({ "reason": reason, "gas_limit": hex_quantity(gas),
                                    "max_fee_per_gas": hex_quantity(max_fee),
                                    "tx_fee_cap_wei": hex_quantity(cap),
                                    "max_fee_per_gas_allowed": hex_quantity(cap / gas) }),
                            ),
                            "upstream_tx_fee_cap" => (
                                -32003,
                                json!({ "reason": reason, "gas_limit": hex_quantity(gas),
                                    "max_fee_per_gas": hex_quantity(max_fee) }),
                            ),
                            _ => {
                                let hash = format!(
                                    "0x{:064x}",
                                    0xdead_0000_0000u64 + state.sends.len() as u64
                                );
                                state.fee_capped_hashes.insert(hash.clone());
                                (
                                    -32000,
                                    json!({ "reason": reason, "transaction_hash": hash }),
                                )
                            }
                        };
                        return Json(json!({ "jsonrpc": "2.0", "id": 1, "error": {
                            "code": code, "message": "Transaction fee exceeds the cap", "data": data } }))
                        .into_response();
                    }
                }
                let nonce = quantity(&transaction["nonce"]).unwrap();
                state.pending_nonce = Some(
                    state
                        .pending_nonce
                        .unwrap_or(state.mined_nonce)
                        .max(nonce + 1),
                );
                json!(format!("0x{:064x}", state.sends.len()))
            }
            "eth_getTransactionByHash" => {
                if !state.transaction_known
                    || state
                        .fee_capped_hashes
                        .contains(request["params"][0].as_str().unwrap())
                {
                    Value::Null
                } else {
                    let hash = request["params"][0].as_str().unwrap();
                    let mut transaction = json!({ "hash": hash, "blockNumber": Value::Null });
                    let sent = parse_hex_u128(hash)
                        .and_then(|index| state.sends.get((index as usize).checked_sub(1)?));
                    if let Some(sent) = sent {
                        transaction["maxFeePerGas"] = sent["maxFeePerGas"].clone();
                        transaction["maxPriorityFeePerGas"] = sent["maxPriorityFeePerGas"].clone();
                    } else if let Some(price) = state.legacy_gas_price {
                        transaction["type"] = json!("0x0");
                        transaction["gasPrice"] = hex_quantity(price);
                    }
                    transaction
                }
            }
            "eth_getTransactionReceipt" => Value::Null,
            "zkapi_signerStatus" => match &state.signer_status {
                Some(status) => status.clone(),
                None => return rpc_error(-32601, "RPC method is not allowed"),
            },
            _ => panic!("unexpected RPC method {method}"),
        };
        Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result })).into_response()
    }

    fn unavailable() -> Response {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "unavailable", "error_code": "indexer_unavailable",
                "error_message": "indexer is not ready", "retriable": true, "retry_after_seconds": 5})),
        )
            .into_response()
    }

    async fn path(State(state): State<Arc<Mutex<MockChain>>>, Path(note): Path<u32>) -> Response {
        let mut state = state.lock().unwrap();
        if state.path_unavailable > 0 {
            state.path_unavailable -= 1;
            return unavailable();
        }
        let mut body =
            json!({"note_id": note, "leaf": Felt252::ZERO, "siblings": state.siblings.to_vec()});
        if let Some(meta) = state.path_meta.as_ref().and_then(Value::as_object) {
            for (key, value) in meta {
                body[key] = value.clone();
            }
        }
        Json(body).into_response()
    }

    async fn tree_root(State(state): State<Arc<Mutex<MockChain>>>) -> Response {
        let state = state.lock().unwrap();
        if state.indexer_health != "ok" {
            return unavailable();
        }
        Json(
            state
                .indexer_root
                .clone()
                .unwrap_or(json!({ "root": state.root })),
        )
        .into_response()
    }

    async fn indexer_health(State(state): State<Arc<Mutex<MockChain>>>) -> Response {
        let state = state.lock().unwrap();
        let code = if state.indexer_health == "ok" {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        (code, Json(json!({ "status": state.indexer_health }))).into_response()
    }

    async fn pending_escapes(State(state): State<Arc<Mutex<MockChain>>>) -> Response {
        let state = state.lock().unwrap();
        match &state.escapes {
            None => StatusCode::NOT_FOUND.into_response(),
            Some(escapes) => Json(json!({
                "block_number": state.escapes_block.unwrap_or(state.head_number),
                "block_hash": state.block_hash, "root": state.root, "escapes": escapes,
            }))
            .into_response(),
        }
    }

    struct Fixture {
        store: Arc<NullifierStore>,
        config: ChallengeServiceConfig,
        chain: Arc<Mutex<MockChain>>,
        server: tokio::task::JoinHandle<()>,
        _directory: tempfile::TempDir,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl Fixture {
        async fn new() -> Self {
            let (store, request) = finalized_v2_request().await;
            Self::with_store(store, &request).await
        }

        async fn with_store(store: Arc<NullifierStore>, request: &ApiRequestV2) -> Self {
            let public = &request.public_inputs;
            let chain = Arc::new(Mutex::new(MockChain::new(
                public.request_nullifier,
                (public.state_signing_key_x, public.state_signing_key_y),
            )));
            let app = Router::new()
                .route("/", post(rpc))
                .route("/v1/tree/notes/{note}/zero-path", get(path))
                .route("/v1/tree/root", get(tree_root))
                .route("/v1/escapes/pending", get(pending_escapes))
                .route("/health", get(indexer_health))
                .with_state(chain.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let directory = tempfile::tempdir().unwrap();
            let config = ChallengeServiceConfig {
                rpc_url: url.clone(),
                indexer_url: url,
                sender: "0x0000000000000000000000000000000000000001".into(),
                contract_address: public.contract_address,
                chain_id: 1,
                from_block: 0,
                confirmations: 2,
                checkpoint: directory.path().join("checkpoint.json"),
                proof_setup_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../protocol/setup/v2"),
                // A transaction fee ceiling the mock's 12M gas limit never
                // reaches at these caps; the ceiling tests use real figures.
                fee: FeePolicy {
                    tx_fee_cap_wei: 10 * ONE_ETHER,
                    ..FeePolicy::new(100 * GWEI, 10 * GWEI)
                },
                // The mock deadline is 100 s away: severity ok unless a test
                // moves the chain clock.
                alarms: AlarmPolicy {
                    warning_remaining_seconds: Some(50),
                    critical_remaining_seconds: Some(10),
                    observe_interval_seconds: 0,
                    ..Default::default()
                },
            };
            Self {
                store,
                config,
                chain,
                server,
                _directory: directory,
            }
        }

        fn service(&self) -> ChallengeService {
            ChallengeService::new(self.config.clone(), self.store.clone()).unwrap()
        }

        fn service_with(
            &self,
            change: impl FnOnce(&mut ChallengeServiceConfig),
        ) -> ChallengeService {
            let mut config = self.config.clone();
            change(&mut config);
            ChallengeService::new(config, self.store.clone()).unwrap()
        }

        fn sends(&self) -> Vec<Value> {
            self.chain.lock().unwrap().sends.clone()
        }

        /// pendingWithdrawals reads of `note` so far.
        fn withdrawal_reads(&self, note: u32) -> usize {
            let chain = self.chain.lock().unwrap();
            chain.withdrawal_reads.get(&note).copied().unwrap_or(0)
        }

        fn reserve(&self, service: &mut ChallengeService, note: u32, expired: bool) {
            let mut chain = self.chain.lock().unwrap();
            let nullifier = chain.nullifier;
            let deadline = if expired {
                chain.head_timestamp
            } else {
                chain.deadline
            };
            chain.withdrawals.insert(note, (true, nullifier, deadline));
            service.checkpoint.pending.insert(
                note,
                PendingChallenge {
                    nullifier,
                    nonce: Some(3),
                    ..Default::default()
                },
            );
            service.persist().unwrap();
        }

        /// Track a further live escape of the fixture's nullifier on `note`.
        fn track(&self, service: &mut ChallengeService, note: u32, deadline: u64) {
            let mut chain = self.chain.lock().unwrap();
            let nullifier = chain.nullifier;
            chain.withdrawals.insert(note, (true, nullifier, deadline));
            service.checkpoint.pending.insert(
                note,
                PendingChallenge {
                    nullifier,
                    challenge_deadline: Some(deadline),
                    ..Default::default()
                },
            );
            service.persist().unwrap();
        }
    }

    fn obligation(status: &ChallengeStatus, note: u32) -> ObligationStatus {
        status
            .obligations
            .iter()
            .find(|o| o.note_id == note)
            .cloned()
            .unwrap_or_else(|| panic!("no obligation for note {note}: {status:?}"))
    }

    fn fee(transaction: &Value, field: &str) -> u128 {
        parse_hex_u128(transaction[field].as_str().unwrap()).unwrap()
    }

    /// (noteId word, 12-word request tuple, siblings, proof) of challenge calldata.
    fn decode_call(transaction: &Value) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let data = hex::decode(&transaction["data"].as_str().unwrap()[2..]).unwrap();
        assert_eq!(data[..4], selector(crate::watcher::CHALLENGE_SIGNATURE));
        let word = |index: usize| 4 + index * 32;
        (
            data[word(0)..word(1)].to_vec(),
            data[word(1)..word(13)].to_vec(),
            data[word(14)..word(46)].to_vec(),
            data[word(47)..].to_vec(),
        )
    }

    fn alternate_tree() -> ([Felt252; MERKLE_DEPTH], Felt252) {
        let mut siblings: [Felt252; MERKLE_DEPTH] = zkapi_core::v2::zero_hashes()[..MERKLE_DEPTH]
            .try_into()
            .unwrap();
        siblings[0] = Felt252::from_u64(5);
        let root = zkapi_core::v2::merkle_root(0, &Felt252::ZERO, &siblings);
        (siblings, root)
    }

    #[tokio::test]
    async fn expired_ambiguous_mined_nonce_allows_queue_progress_across_restart() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, true);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.confirmed_nonce = Some(3);
        }
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(fixture.sends()[0]["nonce"], "0x4");
        assert_eq!(
            service.checkpoint.pending[&1].nonce,
            Some(3),
            "retain tip-reorg protection"
        );
        assert!(service.checkpoint.pending[&1].deadline_reported);
        let status = service.status();
        assert_eq!(obligation(&status, 1).state, ObligationState::Missed);
        assert_eq!(status.missed_total, 1);
        assert_eq!(status.last_missed.as_ref().unwrap().note_id, 1);
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(
            fixture.sends().len(),
            1,
            "restart cannot duplicate submission"
        );
        assert_eq!(service.status().missed_total, 1, "a miss is counted once");
        fixture.chain.lock().unwrap().confirmed_nonce = Some(4);
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.pending[&1].nonce, None);
        assert_eq!(fixture.sends().len(), 1);
    }

    #[tokio::test]
    async fn expired_ambiguous_unmined_nonce_blocks_conflicts_even_when_pending_count_advances() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, true);
        fixture.chain.lock().unwrap().pending_nonce = Some(4);
        drop(service);
        let mut service = fixture.service();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("unmined reserved nonce"));
        assert!(fixture.sends().is_empty());
        assert_eq!(service.checkpoint.pending[&1].nonce, Some(3));
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        // Both obligations stay visible: the expired one blocks the queue.
        let status = service.status();
        let blocking = obligation(&status, 1);
        assert_eq!(blocking.state, ObligationState::Missed);
        assert_eq!(blocking.blocked_reason, Some(BlockedReason::NonceBlocked));
        let queued = obligation(&status, 0);
        assert_eq!(queued.state, ObligationState::Ready);
        assert_eq!(queued.blocked_reason, Some(BlockedReason::NonceBlocked));
        assert!(queued
            .detail
            .unwrap()
            .contains("queued behind unresolved nonce 3 (note 1)"));
        assert_eq!(status.status, Severity::Critical);
    }

    #[tokio::test]
    async fn completed_withdrawal_retains_ambiguous_nonce_through_restart_and_tip_reorg() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, false);
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .get_mut(&1)
            .unwrap()
            .0 = false;
        service.poll_once().await.unwrap();
        assert!(!service.checkpoint.pending.contains_key(&1));
        assert!(service.checkpoint.detached_nonces.contains_key(&3));
        assert!(fixture.sends().is_empty());
        drop(service);
        let mut service = fixture.service();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("requires signer intervention"));
        // An unmined detached nonce is critical on the status endpoint.
        let status = service.status();
        assert_eq!(status.detached_nonces.len(), 1);
        assert_eq!(status.detached_nonces[0].nonce, 3);
        assert!(!status.detached_nonces[0].mined);
        assert_eq!(status.status, Severity::Critical);
        assert_eq!(
            obligation(&status, 0).blocked_reason,
            Some(BlockedReason::NonceBlocked)
        );
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.confirmed_nonce = Some(3);
        }
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        assert!(service.checkpoint.detached_nonces.contains_key(&3));
        assert!(service.status().detached_nonces[0].mined);
        // A tip reorg undoes consumption, so the durable reservation blocks
        // fresh nonce allocation again rather than silently forgetting it.
        fixture.chain.lock().unwrap().mined_nonce = 3;
        drop(service);
        let mut service = fixture.service();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("requires signer intervention"));
        assert_eq!(fixture.sends().len(), 1);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 5;
            chain.confirmed_nonce = Some(5);
            chain.active = false;
            chain.confirmed_active = false;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.detached_nonces.is_empty());
        assert!(service.checkpoint.pending.is_empty());
        assert!(service.status().detached_nonces.is_empty());
    }

    #[tokio::test]
    async fn replacement_withdrawal_event_does_not_discard_old_reserved_nonce() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let old_nullifier = Felt252::from_u64(999);
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier: old_nullifier,
                nonce: Some(3),
                ..Default::default()
            },
        );
        service.persist().unwrap();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("requires signer intervention"));
        assert_eq!(
            service.checkpoint.detached_nonces[&3].nullifier,
            old_nullifier
        );
        assert_eq!(
            service.checkpoint.pending[&0].nullifier,
            fixture.chain.lock().unwrap().nullifier
        );
        assert!(fixture.sends().is_empty());
        drop(service);
        fixture.chain.lock().unwrap().mined_nonce = 4;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.detached_nonces.is_empty());
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(fixture.sends()[0]["nonce"], "0x4");
    }

    #[tokio::test]
    async fn event_replay_restores_reservation_when_its_original_nullifier_returns() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let original_nullifier = fixture.chain.lock().unwrap().nullifier;
        fixture.reserve(&mut service, 0, false);
        // An intervening fork presents a different withdrawal for this note,
        // in its events and in the vault's state.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.nullifier = Felt252::from_u64(999);
            chain.withdrawals.get_mut(&0).unwrap().1 = Felt252::from_u64(999);
        }
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("requires signer intervention"));
        assert!(service.checkpoint.detached_nonces.contains_key(&3));
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.nullifier = original_nullifier;
            chain.withdrawals.get_mut(&0).unwrap().1 = original_nullifier;
            chain.block_hash = "0xforkB".into();
        }
        drop(service);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.detached_nonces.is_empty());
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(fixture.sends()[0]["nonce"], "0x3");
    }

    #[tokio::test]
    async fn lagging_rpc_pending_count_cannot_reuse_another_notes_known_nonce() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, true);
        service
            .checkpoint
            .pending
            .get_mut(&1)
            .unwrap()
            .transaction_hash = Some("0xsubmitted".into());
        service.persist().unwrap();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("conflicts with a durable challenge reservation"));
        assert!(fixture.sends().is_empty());
        assert_eq!(service.checkpoint.pending[&1].nonce, Some(3));
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::NonceConflict)
        );
    }

    #[tokio::test]
    async fn event_to_submission_retries_after_restart_and_preserves_v2_calldata() {
        let fixture = Fixture::new().await;
        let (_, request) = finalized_v2_request().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.reorg_during_scan = true;
            chain.fail_first_send = true;
        }
        let siblings = zkapi_core::v2::zero_hashes()[..MERKLE_DEPTH]
            .try_into()
            .unwrap();
        let expected = ChallengeWatcher::new(fixture.store.clone())
            .build_challenge_action(0, &request.public_inputs.request_nullifier, siblings)
            .unwrap()
            .calldata()
            .unwrap();
        let mut service = fixture.service();
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("chain reorganized while reading escape events"));
        assert_eq!(service.checkpoint.next_block, 0);
        assert!(service.checkpoint.pending.is_empty());
        assert!(fixture.sends().is_empty());
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("temporary signer failure"));
        assert_eq!(service.checkpoint.next_block, 4);
        assert_eq!(service.checkpoint.pending[&0].nonce, Some(3));
        assert!(
            service.checkpoint.pending[&0].attempt.unknown_attempt,
            "an unclassified send error may have broadcast"
        );
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::SendAmbiguous)
        );
        drop(service);
        let mut restarted = fixture.service();
        // The unknown attempt may hold the nonce, so the retry must outbid it,
        // at the same pace as any replacement rather than on every poll.
        restarted.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        let held = obligation(&restarted.status(), 0);
        assert_eq!(held.blocked_reason, Some(BlockedReason::SendAmbiguous));
        assert!(held.detail.unwrap().contains("without a known hash"));
        fixture.chain.lock().unwrap().head_number += 3;
        restarted.poll_once().await.unwrap();
        {
            let sends = fixture.sends();
            assert_eq!(sends.len(), 2);
            // Exactly the EIP-1559 fields; never value, chainId, type or gasPrice.
            for send in &sends {
                let mut keys: Vec<_> = send.as_object().unwrap().keys().cloned().collect();
                keys.sort();
                assert_eq!(
                    keys,
                    [
                        "data",
                        "from",
                        "gas",
                        "maxFeePerGas",
                        "maxPriorityFeePerGas",
                        "nonce",
                        "to"
                    ]
                );
            }
            // The first bid is twice the 1 gwei base fee plus the 2 gwei tip.
            assert_eq!(sends[0]["maxFeePerGas"], "0xee6b2800");
            assert_eq!(sends[0]["maxPriorityFeePerGas"], "0x77359400");
            for field in ["from", "to", "data", "gas", "nonce"] {
                assert_eq!(
                    sends[0][field], sends[1][field],
                    "retry uses the same transaction nonce and payload"
                );
            }
            // The unknown attempt may hold the nonce: the retry is a valid
            // replacement of it, never a lower or equal bid.
            for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
                assert!(fee(&sends[1], field) >= min_bump(fee(&sends[0], field)));
            }
            assert_eq!(sends[1]["data"], format!("0x{}", hex::encode(expected)));
        }
        restarted.poll_once().await.unwrap();
        assert_eq!(
            fixture.sends().len(),
            2,
            "pending receipt must not cause another send"
        );
        assert_eq!(
            obligation(&restarted.status(), 0).state,
            ObligationState::Submitted
        );
        // A reverted challenge refreshes the live path and is resubmitted.
        // A reverted transaction consumes its nonce while leaving the
        // withdrawal active; receipt availability is not needed to recover.
        fixture.chain.lock().unwrap().mined_nonce += 1;
        restarted.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 3);
        assert_eq!(fixture.sends()[2]["nonce"], "0x4");
        // A latest-block success alone must not drop the obligation: it can
        // disappear in a tip reorg while the scan checkpoint stays canonical.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.active = false;
            chain.mined_nonce = 5;
            chain.confirmed_nonce = Some(4);
        }
        restarted.poll_once().await.unwrap();
        assert!(!restarted.checkpoint.pending.is_empty());
        assert_eq!(
            obligation(&restarted.status(), 0).state,
            ObligationState::ResolvedUnconfirmed
        );
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.confirmed_active = false;
            chain.confirmed_nonce = None;
        }
        restarted.poll_once().await.unwrap();
        assert!(restarted.checkpoint.pending.is_empty());
        assert!(restarted.status().obligations.is_empty());

        // A restored ambiguous nonce for a higher note ID must be handled
        // before an earlier note becomes eligible, even if its state RPC fails.
        // Otherwise the new note can steal/replace the reserved transaction.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.active = true;
            chain.confirmed_active = true;
            chain.fail_note_one = true;
            chain.mined_nonce = 3;
            chain.pending_nonce = None;
            chain.sends.clear();
        }
        restarted.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier: request.public_inputs.request_nullifier,
                ..Default::default()
            },
        );
        restarted.checkpoint.pending.insert(
            1,
            PendingChallenge {
                nullifier: Felt252::from_u64(999),
                nonce: Some(3),
                ..Default::default()
            },
        );
        restarted.persist().unwrap();
        assert!(restarted
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("temporary note-state failure"));
        assert!(fixture.sends().is_empty());
        assert!(restarted.checkpoint.pending[&0].nonce.is_none());
        let status = restarted.status();
        assert_eq!(
            obligation(&status, 1).blocked_reason,
            Some(BlockedReason::RpcError)
        );
        assert_eq!(
            obligation(&status, 0).blocked_reason,
            Some(BlockedReason::NonceBlocked)
        );
    }

    #[tokio::test]
    async fn issued_lease_escape_waits_for_finalized_settlement_then_challenges() {
        let (_, request) = finalized_v2_request().await;
        let nullifier = request.public_inputs.request_nullifier;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        store.reserve_openrouter_lease(&request).unwrap();
        let now = unix_now();
        store
            .create_openrouter_lease(&request, "oa_org", now, now + 20, now + 30, 1.0)
            .unwrap();
        store
            .activate_openrouter_lease(&request.client_request_id, "issued-key-hash")
            .unwrap();
        let fixture = Fixture::with_store(store.clone(), &request).await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(
            fixture.sends().is_empty(),
            "an issued lease is not evidence"
        );
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        let status = service.status();
        let awaiting = obligation(&status, 0);
        assert_eq!(awaiting.state, ObligationState::AwaitingSettlement);
        assert_eq!(awaiting.evidence, Some(EvidenceKind::Reserved));
        let settlement = awaiting.settlement.unwrap();
        assert_eq!(settlement.lease_status.as_deref(), Some("active"));
        assert!(settlement.key_issued);
        assert!(
            (99..=100).contains(&awaiting.seconds_remaining.unwrap()),
            "{:?}",
            awaiting.seconds_remaining
        );
        assert_eq!(awaiting.severity, Severity::Ok);
        // Bounded settlement writes the Finalized transcript.
        store
            .finalize(&nullifier, &finalized_transcript(&request, 1))
            .unwrap();
        let siblings = zkapi_core::v2::zero_hashes()[..MERKLE_DEPTH]
            .try_into()
            .unwrap();
        let expected = ChallengeWatcher::new(store)
            .build_challenge_action(0, &nullifier, siblings)
            .unwrap()
            .calldata()
            .unwrap();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0]["nonce"], "0x3");
        assert_eq!(sends[0]["data"], format!("0x{}", hex::encode(expected)));
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::Submitted
        );
    }

    #[tokio::test]
    async fn awaiting_settlement_past_deadline_is_missed_and_critical() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        store.reserve_openrouter_lease(&request).unwrap();
        let now = unix_now();
        store
            .create_openrouter_lease(&request, "openrouter", now, now + 20, now + 30, 1.0)
            .unwrap();
        store
            .activate_openrouter_lease(&request.client_request_id, "issued-key-hash")
            .unwrap();
        let fixture = Fixture::with_store(store, &request).await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(service.status().status, Severity::Ok);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline;
            chain.head_number += 1;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending[&0].deadline_reported);
        let status = service.status();
        assert_eq!(status.missed_total, 1);
        assert_eq!(status.last_missed.as_ref().unwrap().note_id, 0);
        let missed = obligation(&status, 0);
        assert_eq!(missed.state, ObligationState::Missed);
        assert_eq!(missed.severity, Severity::Critical);
        assert_eq!(status.status, Severity::Critical);
        service.poll_once().await.unwrap();
        assert_eq!(service.status().missed_total, 1);
        assert!(fixture.sends().is_empty());
        // A missed obligation ages out once the vault shows the withdrawal
        // resolved at confirmation depth.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.active = false;
            chain.confirmed_active = false;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        let status = service.status();
        assert_eq!(status.status, Severity::Ok, "{:?}", status.alarms);
        assert_eq!(status.missed_total, 1);
    }

    #[tokio::test]
    async fn reservation_without_lease_expires_without_missed_alarm() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        store.reserve_openrouter_lease(&request).unwrap();
        let fixture = Fixture::with_store(store, &request).await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let orphan = obligation(&service.status(), 0);
        assert_eq!(orphan.state, ObligationState::AwaitingSettlement);
        assert_eq!(orphan.evidence, Some(EvidenceKind::ReservedWithoutLease));
        assert_eq!(orphan.severity, Severity::Warning);
        assert!(orphan.detail.unwrap().contains("no lease row"));
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline;
        }
        service.poll_once().await.unwrap();
        let status = service.status();
        let expired = obligation(&status, 0);
        assert_eq!(expired.state, ObligationState::ExpiredWithoutEvidence);
        assert_eq!(expired.severity, Severity::Ok);
        assert_eq!(status.missed_total, 0);
        assert!(!service.checkpoint.pending[&0].deadline_reported);
        assert!(fixture.sends().is_empty());
    }

    #[tokio::test]
    async fn settlement_scheduled_after_critical_threshold_is_critical_immediately() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        store.reserve_openrouter_lease(&request).unwrap();
        let fixture = Fixture::with_store(store.clone(), &request).await;
        let deadline = fixture.chain.lock().unwrap().deadline;
        // Settlement is not due until after deadline - critical_remaining.
        store
            .create_openrouter_lease(
                &request,
                "oa_org",
                deadline - 50,
                deadline - 5,
                deadline - 5,
                1.0,
            )
            .unwrap();
        store
            .activate_openrouter_lease(&request.client_request_id, "issued-key-hash")
            .unwrap();
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let late = obligation(&service.status(), 0);
        assert_eq!(late.state, ObligationState::AwaitingSettlement);
        assert!(
            late.seconds_remaining.unwrap() > 10,
            "not yet in the critical window"
        );
        assert_eq!(late.severity, Severity::Critical);
        assert!(late
            .detail
            .unwrap()
            .contains("settlement scheduled after the challenge critical threshold"));
    }

    #[tokio::test]
    async fn settlement_deadline_takes_precedence_over_the_next_attempt() {
        // The write-once deadline bounds when the server finalizes the lease
        // (at worst case if needed); the next attempt may fail and move.
        for (settle_after_offset, deadline_offset, critical) in [(50, 5, true), (5, 50, false)] {
            let (_, request) = finalized_v2_request().await;
            let store = Arc::new(NullifierStore::in_memory().unwrap());
            store.reserve_openrouter_lease(&request).unwrap();
            let fixture = Fixture::with_store(store.clone(), &request).await;
            let deadline = fixture.chain.lock().unwrap().deadline;
            store
                .create_openrouter_lease_bound(&crate::nullifier_store::NewOpenRouterLease {
                    request: &request,
                    key_source: "openrouter",
                    issued_at: deadline - 100,
                    expires_at: deadline - settle_after_offset,
                    settle_after: deadline - settle_after_offset,
                    spending_limit_usd: 1.0,
                    oa_client_request_id: None,
                    ttl_seconds: Some(60),
                    settlement_deadline_at: Some(deadline - deadline_offset),
                    delivered: Some(true),
                })
                .unwrap();
            store
                .activate_openrouter_lease(&request.client_request_id, "issued-key-hash")
                .unwrap();
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            let status = obligation(&service.status(), 0);
            assert_eq!(status.state, ObligationState::AwaitingSettlement);
            let settlement = status.settlement.as_ref().unwrap();
            assert_eq!(
                settlement.settle_after,
                Some(deadline - settle_after_offset)
            );
            assert_eq!(
                settlement.settlement_deadline_at,
                Some(deadline - deadline_offset)
            );
            assert!(
                status.seconds_remaining.unwrap() > 10,
                "not yet in the critical window"
            );
            let detail = status.detail.unwrap();
            if critical {
                assert_eq!(status.severity, Severity::Critical);
                assert!(
                    detail.contains("settlement scheduled after the challenge critical threshold"),
                    "{detail}"
                );
            } else {
                assert_eq!(status.severity, Severity::Ok);
                assert_eq!(detail, "awaiting finalized settlement");
            }
        }
    }

    #[tokio::test]
    async fn signer_refusal_is_reported_on_status_with_remaining_deadline() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().refuse_notes.insert(0);
        let mut service = fixture.service();
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(
            error.contains("Requested fees are outside the configured bounds"),
            "{error}"
        );
        assert_eq!(fixture.sends().len(), 1);
        // Nothing was broadcast, so the refused nonce is released.
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        let status = service.status();
        let refused = obligation(&status, 0);
        assert_eq!(refused.state, ObligationState::Ready);
        assert_eq!(refused.blocked_reason, Some(BlockedReason::SignerRefused));
        assert!(refused
            .detail
            .unwrap()
            .contains("Requested fees are outside the configured bounds"));
        let remaining = refused.seconds_remaining.unwrap();
        assert!((99..=100).contains(&remaining), "{remaining}");
        assert_eq!(refused.severity, Severity::Critical);
        assert_eq!(status.status, Severity::Critical);
        let response = tower::ServiceExt::oneshot(
            challenge_status::router(service.status_handle(), fixture.config.alarms.clone()),
            axum::http::Request::builder()
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn definitive_refusal_until_deadline_does_not_stall_later_notes() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let later = fixture.chain.lock().unwrap().deadline + 1_000;
        fixture.track(&mut service, 1, later);
        fixture.chain.lock().unwrap().refuse_notes.insert(0);
        assert!(service.poll_once().await.is_err());
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(decode_call(&sends[0]).0, Felt252::from_u64(0).as_bytes());
        assert_eq!(decode_call(&sends[1]).0, Felt252::from_u64(1).as_bytes());
        // The refused nonce was released and reused by the next note.
        assert_eq!(sends[0]["nonce"], "0x3");
        assert_eq!(sends[1]["nonce"], "0x3");
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(service.checkpoint.pending[&1].nonce, Some(3));
        // The refusal persists; note 1 is unaffected.
        assert!(service.poll_once().await.is_err());
        assert_eq!(fixture.sends().len(), 3);
        assert_eq!(fixture.sends()[2]["nonce"], "0x4");
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        // At note 0's deadline nothing stalls the queue either.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline;
        }
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 3);
        let status = service.status();
        assert_eq!(obligation(&status, 0).state, ObligationState::Missed);
        assert_eq!(obligation(&status, 1).state, ObligationState::Submitted);
    }

    #[tokio::test]
    async fn pending_challenge_is_replaced_on_same_nonce_with_bumped_fees_and_same_call() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1, "no bump before bump_after_blocks");
        let first_hash = service.checkpoint.pending[&0]
            .transaction_hash
            .clone()
            .unwrap();
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        for field in ["from", "to", "nonce", "data", "gas"] {
            assert_eq!(sends[0][field], sends[1][field], "{field}");
        }
        for (field, cap) in [
            ("maxFeePerGas", 100 * GWEI),
            ("maxPriorityFeePerGas", 10 * GWEI),
        ] {
            assert!(
                fee(&sends[1], field) >= min_bump(fee(&sends[0], field)),
                "{field}"
            );
            assert!(fee(&sends[1], field) <= cap, "{field}");
        }
        // The tip rises by the minimum valid step, the fee cap by 25%.
        assert_eq!(fee(&sends[1], "maxPriorityFeePerGas"), 2_200_000_000);
        assert_eq!(fee(&sends[1], "maxFeePerGas"), 5 * GWEI);
        let pending = &service.checkpoint.pending[&0];
        assert_eq!(pending.attempt.superseded_hashes, vec![first_hash.clone()]);
        assert_eq!(pending.attempt.attempts, 2);
        assert_ne!(pending.transaction_hash.as_ref(), Some(&first_hash));
        let status = obligation(&service.status(), 0);
        assert_eq!(status.superseded_hashes, vec![first_hash]);
        assert_eq!(status.max_fee_per_gas_wei.as_deref(), Some("5000000000"));

        // An ambiguous replacement followed by a restart never bids lower.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain
                .send_errors
                .push_back(json!({ "code": -32000, "message": "upstream timeout" }));
            chain.head_number += 3;
        }
        assert!(service.poll_once().await.is_err());
        let ambiguous = fixture.sends()[2].clone();
        assert!(fee(&ambiguous, "maxFeePerGas") >= min_bump(5 * GWEI));
        drop(service);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.transaction_known = false;
            chain.head_number += 3;
        }
        let mut restarted = fixture.service();
        restarted.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 4);
        assert_eq!(sends[3]["nonce"], ambiguous["nonce"]);
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(
                fee(&sends[3], field) >= min_bump(fee(&ambiguous, field)),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn ambiguous_send_held_by_an_unknown_attempt_rebids_both_fees() {
        // The signer returns a candidate hash for an ambiguous broadcast.
        let fixture = Fixture::new().await;
        let candidate = format!("0x{:064x}", 0xabcdu64);
        fixture.chain.lock().unwrap().send_errors.push_back(json!({
            "code": -32000, "message": "Transaction broadcast outcome is unknown",
            "data": { "reason": "broadcast_ambiguous", "transaction_hash": candidate }
        }));
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        let pending = &service.checkpoint.pending[&0];
        assert_eq!(
            pending.transaction_hash.as_deref(),
            Some(candidate.as_str())
        );
        assert!(!pending.attempt.unknown_attempt);
        // The RPC does not know the hash, but the pending count shows the
        // nonce is occupied, and the base fee then exceeds the first bid.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.transaction_known = false;
            chain.pending_nonce = Some(4);
            chain.base_fee = Some(10 * GWEI);
        }
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0]["nonce"], sends[1]["nonce"]);
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(
                fee(&sends[1], field) >= min_bump(fee(&sends[0], field)),
                "{field}"
            );
        }
        assert!(fee(&sends[1], "maxFeePerGas") >= 20 * GWEI);
        assert_eq!(
            service.checkpoint.pending[&0].attempt.superseded_hashes,
            vec![candidate]
        );

        // An unclassifiable failure (no hash) also makes the next send bump.
        let fixture = Fixture::new().await;
        fixture
            .chain
            .lock()
            .unwrap()
            .send_errors
            .push_back(json!({ "code": -32603, "message": "Signer request failed" }));
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        assert!(service.checkpoint.pending[&0].attempt.unknown_attempt);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1, "no re-bid on every poll");
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(
                fee(&sends[1], field) >= min_bump(fee(&sends[0], field)),
                "{field}"
            );
        }

        // A signer-reported failure before broadcast needs no bump, and its
        // nonce is released.
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().send_errors.push_back(json!({
            "code": -32000, "message": "Upstream RPC request failed",
            "data": { "reason": "upstream_unavailable" }
        }));
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        assert!(!service.checkpoint.pending[&0].attempt.unknown_attempt);
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::RpcError)
        );
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0], sends[1]);
    }

    #[tokio::test]
    async fn base_fee_above_cap_reports_blocked_and_submits_after_it_falls() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().base_fee = Some(150 * GWEI);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        assert!(fixture.sends().is_empty());
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        let blocked = obligation(&service.status(), 0);
        assert_eq!(blocked.state, ObligationState::Ready);
        assert_eq!(
            blocked.blocked_reason,
            Some(BlockedReason::BaseFeeAboveFeeCap)
        );
        fixture.chain.lock().unwrap().base_fee = Some(30 * GWEI);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(fee(&sends[0], "maxFeePerGas"), 62 * GWEI);
        assert_eq!(fee(&sends[0], "maxPriorityFeePerGas"), 2 * GWEI);
        // A base fee above the pending bid triggers a replacement, within the
        // non-critical limit that keeps two replacements for the critical
        // threshold.
        fixture.chain.lock().unwrap().base_fee = Some(70 * GWEI);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(
            fee(&sends[1], "maxFeePerGas"),
            headroom(headroom(100 * GWEI))
        );
        assert_eq!(fee(&sends[1], "maxPriorityFeePerGas"), 2_200_000_000);
        // Above the cap nothing more can be done but report it.
        fixture.chain.lock().unwrap().base_fee = Some(120 * GWEI);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 2);
        let blocked = obligation(&service.status(), 0);
        assert_eq!(blocked.state, ObligationState::Submitted);
        assert_eq!(
            blocked.blocked_reason,
            Some(BlockedReason::BaseFeeAboveFeeCap)
        );
    }

    #[tokio::test]
    async fn critical_deadline_escalates_pending_challenge_to_fee_caps() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline - 5;
        }
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        // Just under the caps, keeping one valid bump of headroom.
        assert_eq!(fee(&sends[1], "maxFeePerGas"), headroom(100 * GWEI));
        assert_eq!(fee(&sends[1], "maxPriorityFeePerGas"), headroom(10 * GWEI));
        assert_eq!(sends[1]["nonce"], sends[0]["nonce"]);
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 3);
        assert_eq!(fee(&sends[2], "maxFeePerGas"), 100 * GWEI);
        assert_eq!(fee(&sends[2], "maxPriorityFeePerGas"), 10 * GWEI);
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 3, "no valid bump above the caps");
        let capped = obligation(&service.status(), 0);
        assert_eq!(capped.blocked_reason, Some(BlockedReason::TipCapReached));
        assert_eq!(capped.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn critical_queued_obligation_escalates_the_head_replacement() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().deadline += 1_000;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fee(&fixture.sends()[0], "maxFeePerGas"), 4 * GWEI);
        // A second escape near its deadline queues behind the head nonce.
        let near = fixture.chain.lock().unwrap().head_timestamp + 5;
        fixture.track(&mut service, 1, near);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 3);
        let by_nonce = |nonce: &str| {
            sends
                .iter()
                .filter(|send| send["nonce"] == nonce)
                .cloned()
                .collect::<Vec<_>>()
        };
        let head = by_nonce("0x3");
        assert_eq!(head.len(), 2, "the non-critical head is replaced");
        assert_eq!(fee(&head[1], "maxFeePerGas"), headroom(100 * GWEI));
        let queued = by_nonce("0x4");
        assert_eq!(queued.len(), 1);
        assert_eq!(fee(&queued[0], "maxFeePerGas"), headroom(100 * GWEI));
    }

    #[tokio::test]
    async fn stale_root_replacement_refreshes_only_siblings() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let (siblings, root) = alternate_tree();
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.siblings = siblings;
            chain.root = root;
        }
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(
            sends.len(),
            2,
            "a pending call against an old root would revert"
        );
        assert_eq!(sends[0]["nonce"], sends[1]["nonce"]);
        let (note0, inputs0, siblings0, proof0) = decode_call(&sends[0]);
        let (note1, inputs1, siblings1, proof1) = decode_call(&sends[1]);
        assert_eq!(note0, note1);
        assert_eq!(inputs0, inputs1);
        assert_eq!(proof0, proof1);
        assert_ne!(siblings0, siblings1);
        assert_eq!(&siblings1[..32], siblings[0].as_bytes());
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(
                fee(&sends[1], field) >= min_bump(fee(&sends[0], field)),
                "{field}"
            );
        }
        assert_eq!(
            service.checkpoint.pending[&0].attempt.submitted_root,
            Some(root)
        );
    }

    #[tokio::test]
    async fn replacement_waits_while_an_earlier_nonce_is_pending() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let deadline = fixture.chain.lock().unwrap().deadline;
        fixture.track(&mut service, 1, deadline);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0]["nonce"], "0x3");
        assert_eq!(sends[1]["nonce"], "0x4");
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 3, "only the queue head is replaced");
        assert_eq!(sends[2]["nonce"], "0x3");
        assert!(obligation(&service.status(), 1)
            .detail
            .unwrap()
            .contains("behind an earlier challenge"));
        // Once nonce 3 is consumed, nonce 4 is the head and is replaced.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.confirmed_nonce = Some(3);
            chain.head_number += 3;
        }
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 4);
        assert_eq!(sends[3]["nonce"], "0x4");
        // The consumed nonce left the withdrawal pending: a revert keeps its
        // deadline-derived severity.
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::MinedUnconfirmed
        );
    }

    #[tokio::test]
    async fn not_pending_withdrawal_revert_is_resolved_unconfirmed_and_retried() {
        let fixture = Fixture::new().await;
        let revert = |signature: &str| {
            json!({ "code": 3, "message": "execution reverted",
                "data": format!("0x{}", hex::encode(selector(signature))) })
        };
        fixture.chain.lock().unwrap().simulation_error = Some(revert("NotPendingWithdrawal()"));
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(fixture.sends().is_empty());
        assert!(
            service.checkpoint.pending.contains_key(&0),
            "only confirmed depth retires"
        );
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::ResolvedUnconfirmed
        );
        fixture.chain.lock().unwrap().simulation_error = Some(revert("StaleRoot()"));
        assert!(service.poll_once().await.is_err());
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::IndexerPathBehind)
        );
        fixture.chain.lock().unwrap().simulation_error = Some(revert("ChallengeExpired()"));
        assert!(service.poll_once().await.is_err());
        let expired = obligation(&service.status(), 0);
        assert_eq!(
            expired.blocked_reason,
            Some(BlockedReason::SimulationReverted)
        );
        assert!(expired.detail.unwrap().contains("ChallengeExpired()"));
        fixture.chain.lock().unwrap().simulation_error = None;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
    }

    #[tokio::test]
    async fn insufficient_balance_clamps_fee_and_reports_aggregate_alarm() {
        let fixture = Fixture::new().await;
        // The mock estimate is 10M gas, so the gas limit is 12M.
        fixture.chain.lock().unwrap().balance = Some(12_000_000 * 3 * GWEI);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(fee(&sends[0], "maxFeePerGas"), 3 * GWEI);
        assert_eq!(fee(&sends[0], "maxPriorityFeePerGas"), 2 * GWEI);
        let status = service.status();
        assert_eq!(
            status.sender.balance_wei.as_deref(),
            Some("36000000000000000")
        );
        assert_eq!(status.sender.outstanding_obligations, 1);
        assert_eq!(
            status.sender.required_balance_wei.as_deref(),
            Some("48000000000000000")
        );
        assert!(status
            .alarms
            .iter()
            .any(|alarm| alarm.contains("cannot fund every outstanding challenge")));
        assert!(status.status >= Severity::Warning);
        // A replacement the balance cannot fund is not sent.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.balance = Some(12_000_000 * GWEI / 2);
            chain.head_number += 3;
        }
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::InsufficientBalance)
        );
        // A signer that disallows eth_getBalance leaves the balance unknown.
        fixture.chain.lock().unwrap().balance = None;
        service.poll_once().await.unwrap();
        let sender = service.status().sender;
        assert_eq!(sender.balance_wei, None);
        assert!(sender
            .balance_detail
            .unwrap()
            .contains("does not allow eth_getBalance"));
    }

    #[tokio::test]
    async fn indexer_root_mismatch_escalates_to_divergence_alarm() {
        // Heuristic mode: an indexer without block metadata.
        let fixture = Fixture::new().await;
        let (siblings, other_root) = alternate_tree();
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.siblings = siblings;
            chain.indexer_root = Some(json!({ "root": other_root }));
        }
        let mut service = fixture.service_with(|config| {
            config.alarms.indexer_divergence_seconds = 0;
            config.alarms.indexer_divergence_polls = 3;
        });
        assert!(service.poll_once().await.is_err());
        let status = service.status();
        assert_eq!(status.indexer.state, IndexerState::Lagging);
        assert_eq!(
            obligation(&status, 0).blocked_reason,
            Some(BlockedReason::IndexerPathBehind)
        );
        assert!(service.poll_once().await.is_err());
        let status = service.status();
        assert_eq!(status.indexer.state, IndexerState::Diverged);
        assert_eq!(
            obligation(&status, 0).blocked_reason,
            Some(BlockedReason::IndexerDiverged)
        );
        assert_eq!(status.status, Severity::Critical);
        assert!(status
            .alarms
            .iter()
            .any(|alarm| alarm.contains("indexer mirror diverged")));
        assert!(fixture.sends().is_empty());

        // Exact mode: the vault root at the indexer's own block differs.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            let live = chain.root;
            chain.siblings = siblings;
            let meta = json!({ "root": other_root, "block_number": 5, "block_hash": "0xindexer" });
            chain.indexer_root = Some(meta.clone());
            chain.path_meta = Some(meta);
            chain.roots_by_hash.insert("0xindexer".into(), live);
        }
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        let status = service.status();
        assert_eq!(status.indexer.state, IndexerState::Diverged);
        assert_eq!(
            obligation(&status, 0).blocked_reason,
            Some(BlockedReason::IndexerDiverged)
        );
        assert_eq!(status.status, Severity::Critical);

        // A consistent but lagging root is not an alarm, nor is a block hash
        // this RPC does not know.
        for known in [true, false] {
            let fixture = Fixture::new().await;
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.siblings = siblings;
                let meta = json!({ "root": other_root, "block_number": 4, "block_hash": "0xold" });
                chain.indexer_root = Some(meta.clone());
                chain.path_meta = Some(meta);
                if known {
                    chain.roots_by_hash.insert("0xold".into(), other_root);
                }
            }
            let mut service = fixture.service();
            for _ in 0..3 {
                assert!(service.poll_once().await.is_err());
            }
            let status = service.status();
            assert_eq!(status.indexer.state, IndexerState::Lagging);
            assert_eq!(status.indexer.lag_blocks, Some(1));
            assert_eq!(
                obligation(&status, 0).blocked_reason,
                Some(BlockedReason::IndexerPathBehind)
            );
            assert_eq!(status.status, Severity::Ok, "{:?}", status.alarms);
        }
    }

    #[tokio::test]
    async fn indexer_unavailable_for_several_polls_still_challenges_after_recovery() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().path_unavailable = 3;
        let mut service = fixture.service_with(|config| config.alarms.blocked_warning_seconds = 0);
        for _ in 0..3 {
            let error = service.poll_once().await.unwrap_err().to_string();
            assert!(
                error.contains("indexer zero-path request failed: HTTP 503"),
                "{error}"
            );
            let unavailable = obligation(&service.status(), 0);
            assert_eq!(
                unavailable.blocked_reason,
                Some(BlockedReason::IndexerUnavailable)
            );
            assert_eq!(unavailable.severity, Severity::Warning);
            assert!(fixture.sends().is_empty());
        }
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        let recovered = obligation(&service.status(), 0);
        assert_eq!(recovered.state, ObligationState::Submitted);
        assert_eq!(recovered.blocked_reason, None);
        assert_eq!(recovered.blocked_since, None);

        // An unavailable indexer is visible on the status too.
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().indexer_health = "rebuilding";
        let mut service = fixture.service_with(|config| config.alarms.blocked_warning_seconds = 0);
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.indexer.state, IndexerState::Unavailable);
        assert!(status.indexer.detail.unwrap().contains("rebuilding"));
        assert!(status
            .alarms
            .iter()
            .any(|alarm| alarm.contains("indexer unavailable")));
    }

    #[tokio::test]
    async fn escape_missing_from_lagging_get_logs_is_added_from_indexer_pending_list() {
        let fixture = Fixture::new().await;
        let deadline = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            let listed = json!([
                { "note_id": 0, "withdrawal_nullifier": chain.nullifier, "challenge_deadline": chain.deadline },
                // Listed with a stale nullifier and deadline: the vault's
                // escape of note 7 is tracked instead.
                { "note_id": 7, "withdrawal_nullifier": Felt252::from_u64(77), "challenge_deadline": chain.deadline },
            ]);
            chain.escapes = Some(listed.as_array().unwrap().clone());
            let deadline = chain.deadline;
            chain
                .withdrawals
                .insert(7, (true, Felt252::from_u64(78), deadline + 5));
            deadline
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(
            service.checkpoint.next_block, 4,
            "the lagging scan moved on"
        );
        assert_eq!(
            service
                .checkpoint
                .pending
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            [0, 7]
        );
        assert_eq!(
            service.checkpoint.pending[&7].nullifier,
            Felt252::from_u64(78)
        );
        // Note 7's escape has no server request: nothing to send.
        assert_eq!(fixture.sends().len(), 1);
        let status = service.status();
        assert_eq!(status.indexer.pending_escapes, "ok");
        assert_eq!(status.indexer.escapes_added_from_indexer, 2);
        assert_eq!(obligation(&status, 0).challenge_deadline, Some(deadline));
        assert_eq!(
            obligation(&status, 7).challenge_deadline,
            Some(deadline + 5)
        );
        assert_eq!(obligation(&status, 7).state, ObligationState::NoEvidence);
        assert!(status
            .indexer
            .pending_escapes_disagreement
            .unwrap()
            .starts_with("note 7 listed with nullifier"));

        // An indexer that predates the endpoint is tolerated with a warning.
        fixture.chain.lock().unwrap().escapes = None;
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.indexer.pending_escapes, "unsupported");
        assert_eq!(status.status, Severity::Warning);
    }

    #[tokio::test]
    async fn re_escape_with_a_different_nullifier_after_confirmed_challenge_is_challenged_again() {
        let (store, first, second) = two_finalized_v2_requests().await;
        let fixture = Fixture::with_store(store, &first).await;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        let nullifier_word = |send: &Value| decode_call(send).1[8 * 32..9 * 32].to_vec();
        assert_eq!(
            nullifier_word(&sends[0]),
            first.public_inputs.request_nullifier.as_bytes()
        );
        // The challenge mines and the withdrawal is resolved at confirmation depth.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.mined_nonce = 4;
            chain.active = false;
            chain.confirmed_active = false;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        // The owner escapes again at another anchor: a new obligation.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.nullifier = second.public_inputs.request_nullifier;
            chain.active = true;
            chain.confirmed_active = true;
            chain.head_number += 1;
        }
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[1]["nonce"], "0x4");
        assert_eq!(
            nullifier_word(&sends[1]),
            second.public_inputs.request_nullifier.as_bytes()
        );
        assert_eq!(
            service.checkpoint.pending[&0].nullifier,
            second.public_inputs.request_nullifier
        );
    }

    #[tokio::test]
    async fn evidence_database_error_is_critical_not_silent() {
        let (_, request) = finalized_v2_request().await;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let server = NullifierStore::new(&path).unwrap();
        server.reserve_openrouter_lease(&request).unwrap();
        server
            .finalize(
                &request.public_inputs.request_nullifier,
                &finalized_transcript(&request, 1),
            )
            .unwrap();
        let reader = Arc::new(NullifierStore::open_read_only(&path).unwrap());
        let fixture = Fixture::with_store(reader, &request).await;
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TABLE nullifiers;")
            .unwrap();
        let mut service = fixture.service();
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(error.contains("evidence database read failed"), "{error}");
        assert!(fixture.sends().is_empty());
        let status = service.status();
        let unreadable = obligation(&status, 0);
        assert_eq!(
            unreadable.blocked_reason,
            Some(BlockedReason::EvidenceDbError)
        );
        assert_eq!(unreadable.evidence, Some(EvidenceKind::Unavailable));
        assert_eq!(unreadable.severity, Severity::Critical);
        assert_eq!(status.status, Severity::Critical);
    }

    #[tokio::test]
    async fn archived_state_key_mismatch_is_evidence_invalid() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().state_key.0 = Felt252::from_u64(5);
        let mut service = fixture.service();
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(
            error.contains("differs from vault immutable key"),
            "{error}"
        );
        assert!(fixture.sends().is_empty());
        let invalid = obligation(&service.status(), 0);
        assert_eq!(invalid.blocked_reason, Some(BlockedReason::EvidenceInvalid));
        assert_eq!(invalid.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn legacy_checkpoint_without_fee_fields_loads_and_replaces_only_with_a_valid_bump() {
        let fixture = Fixture::new().await;
        let nullifier = fixture.chain.lock().unwrap().nullifier;
        // A checkpoint written by the previous daemon, with a pending type-0
        // transaction whose fees it never recorded.
        std::fs::write(
            &fixture.config.checkpoint,
            serde_json::to_vec(&json!({
                "sender": "0x0000000000000000000000000000000000000001",
                "chain_id": 1, "contract_address": fixture.config.contract_address,
                "from_block": 0, "next_block": 4, "last_block_hash": "0xforkA",
                "pending": { "0": { "nullifier": nullifier, "transaction_hash": "0xlegacy",
                    "nonce": 3, "deadline_reported": false } },
                "detached_nonces": {}
            }))
            .unwrap(),
        )
        .unwrap();
        // 1.1 x 9.5 gwei exceeds the 10 gwei tip cap: no valid replacement.
        fixture.chain.lock().unwrap().legacy_gas_price = Some(9_500_000_000);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(fixture.sends().is_empty());
        let capped = obligation(&service.status(), 0);
        assert_eq!(capped.state, ObligationState::Submitted);
        assert_eq!(capped.blocked_reason, Some(BlockedReason::TipCapReached));
        // A gas price both caps exceed by 10% is replaced on its nonce.
        fixture.chain.lock().unwrap().legacy_gas_price = Some(5 * GWEI);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0]["nonce"], "0x3");
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(fee(&sends[0], field) >= min_bump(5 * GWEI), "{field}");
        }
        assert_eq!(
            service.checkpoint.pending[&0].attempt.superseded_hashes,
            vec!["0xlegacy".to_string()]
        );
    }

    #[tokio::test]
    async fn fee_policy_validation_rejects_invalid_caps() {
        let valid = FeePolicy::new(100 * GWEI, 10 * GWEI);
        assert!(valid.validate().is_ok());
        for (policy, message) in [
            (
                FeePolicy {
                    max_priority_fee_per_gas: 200 * GWEI,
                    ..valid.clone()
                },
                "must not exceed max fee",
            ),
            (
                FeePolicy {
                    priority_fee_per_gas: 0,
                    ..valid.clone()
                },
                "must be positive",
            ),
            (
                FeePolicy {
                    max_priority_fee_per_gas: 3 * GWEI,
                    ..valid.clone()
                },
                "at least twice",
            ),
            (
                FeePolicy {
                    bump_after_blocks: 0,
                    ..valid.clone()
                },
                "at least one block",
            ),
            (
                FeePolicy {
                    bump_percent: 9,
                    ..valid.clone()
                },
                "between 10 and 100",
            ),
            (
                FeePolicy {
                    bump_percent: 101,
                    ..valid.clone()
                },
                "between 10 and 100",
            ),
        ] {
            let error = policy.validate().unwrap_err().to_string();
            assert!(error.contains(message), "{error}");
        }
        let fixture = Fixture::new().await;
        let mut config = fixture.config.clone();
        config.fee.max_priority_fee_per_gas = 3 * GWEI;
        assert!(ChallengeService::new(config, fixture.store.clone()).is_err());
        let mut config = fixture.config.clone();
        config.alarms.critical_remaining_seconds = Some(60);
        assert!(ChallengeService::new(config, fixture.store.clone()).is_err());
        // A low Mainnet cap is a configuration warning, not an error.
        let mut config = fixture.config.clone();
        config.fee = FeePolicy::new(50 * GWEI, 10 * GWEI);
        let service = ChallengeService::new(config, fixture.store.clone()).unwrap();
        assert!(service
            .status()
            .config_warnings
            .iter()
            .any(|warning| warning.contains("Mainnet")));
    }

    #[test]
    fn fee_plans_bid_bump_and_escalate_within_caps() {
        let policy = FeePolicy::new(100 * GWEI, 10 * GWEI);
        let plan = |plan, base, critical, affordable| {
            plan_fees(&policy, plan, base, critical, None, affordable)
        };
        let fees = |max_fee, tip| Fees { max_fee, tip };
        let caps = fees(100 * GWEI, 10 * GWEI);
        let reserve = |fees: Fees| Fees {
            max_fee: headroom(fees.max_fee),
            tip: headroom(fees.tip),
        };
        // A first bid is twice the base fee plus the tip, within 10/11 of
        // 10/11 of the cap, or as much more as the base fee needs.
        assert_eq!(
            plan(FeePlan::First, Some(GWEI), false, None),
            Ok(Some(fees(4 * GWEI, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(60 * GWEI), false, None),
            Ok(Some(fees(reserve(reserve(caps)).max_fee, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(85 * GWEI), false, None),
            Ok(Some(fees(reserve(caps).max_fee, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(95 * GWEI), false, None),
            Ok(Some(fees(100 * GWEI, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, None, false, None),
            Ok(Some(fees(reserve(reserve(caps)).max_fee, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(101 * GWEI), false, None),
            Err(BlockedReason::BaseFeeAboveFeeCap)
        );
        // Critical: just under both caps, then the caps, then nothing.
        let critical = plan(FeePlan::First, Some(GWEI), true, None)
            .unwrap()
            .unwrap();
        assert_eq!(critical, fees(90_909_090_909, 9_090_909_090));
        assert_eq!(
            plan(FeePlan::Bump(critical), Some(GWEI), true, None),
            Ok(Some(caps))
        );
        assert_eq!(
            plan(FeePlan::Bump(caps), Some(GWEI), true, None),
            Err(BlockedReason::TipCapReached)
        );
        // A base fee above the critical bid goes straight to the caps.
        assert_eq!(
            plan(FeePlan::First, Some(95 * GWEI), true, None),
            Ok(Some(caps))
        );
        // A normal bump raises the tip minimally and the fee cap by 25%.
        assert_eq!(
            plan(
                FeePlan::Bump(fees(4 * GWEI, 2 * GWEI)),
                Some(GWEI),
                false,
                None
            ),
            Ok(Some(fees(5 * GWEI, 2_200_000_000)))
        );
        let mut current = fees(4 * GWEI, 2 * GWEI);
        let mut bumps = 0;
        while let Ok(Some(next)) = plan(FeePlan::Bump(current), Some(GWEI), false, None) {
            assert!(is_valid_bump(current, next));
            assert!(next.max_fee <= caps.max_fee && next.tip <= caps.tip);
            current = next;
            bumps += 1;
        }
        assert!(bumps >= 7, "only {bumps} replacements before a cap");
        // Then the last two replacements wait for the critical threshold.
        assert!(current.tip <= reserve(reserve(caps)).tip);
        assert_eq!(
            plan(FeePlan::Bump(current), Some(GWEI), false, None),
            Ok(None)
        );
        let first = plan(FeePlan::Bump(current), Some(GWEI), true, None)
            .unwrap()
            .unwrap();
        assert_eq!(first, reserve(caps));
        assert_eq!(
            plan(FeePlan::Bump(first), Some(GWEI), true, None),
            Ok(Some(caps))
        );
        // A pending bid below the base fee spends the reserve for inclusion.
        assert_eq!(
            plan(
                FeePlan::Bump(fees(50 * GWEI, 8 * GWEI)),
                Some(55 * GWEI),
                false,
                None
            ),
            Ok(Some(reserve(caps)))
        );
        // Re-sending a dropped bid needs no bump but follows the base fee.
        assert_eq!(
            plan(
                FeePlan::Resend(fees(4 * GWEI, 2 * GWEI)),
                Some(10 * GWEI),
                false,
                None
            ),
            Ok(Some(fees(22 * GWEI, 2 * GWEI)))
        );
        // The balance clamp keeps a valid bid or reports the shortfall.
        assert_eq!(
            plan(FeePlan::First, Some(GWEI), false, Some(3 * GWEI)),
            Ok(Some(fees(3 * GWEI, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(GWEI), false, Some(GWEI / 2)),
            Err(BlockedReason::InsufficientBalance)
        );
        assert_eq!(
            plan(
                FeePlan::Bump(fees(4 * GWEI, 2 * GWEI)),
                Some(GWEI),
                false,
                Some(4_200_000_000)
            ),
            Err(BlockedReason::InsufficientBalance)
        );

        // The transaction fee ceiling bounds every bid like a lower fee cap:
        // 1 ether over a real challenge's 7,534,341 gas is about 132.7 gwei.
        let policy = FeePolicy::new(300 * GWEI, 10 * GWEI);
        let limit = ONE_ETHER / 7_534_341;
        let plan =
            |plan, base, critical| plan_fees(&policy, plan, base, critical, Some(limit), None);
        let ceiling = fees(limit, 10 * GWEI);
        assert_eq!(
            plan(FeePlan::First, Some(70 * GWEI), false),
            Ok(Some(fees(reserve(reserve(ceiling)).max_fee, 2 * GWEI)))
        );
        let critical = plan(FeePlan::First, Some(10 * GWEI), true)
            .unwrap()
            .unwrap();
        assert_eq!(critical, reserve(ceiling));
        assert_eq!(
            plan(FeePlan::Bump(critical), Some(10 * GWEI), true),
            Ok(Some(ceiling))
        );
        assert_eq!(
            plan(FeePlan::Bump(fees(limit, 5 * GWEI)), Some(10 * GWEI), true),
            Err(BlockedReason::TxFeeCapReached)
        );
        // With both fees at their limits the ceiling is named: a higher tip
        // cap alone cannot make a replacement valid. A tip at its cap below
        // the ceiling is the tip cap's.
        assert_eq!(
            plan(FeePlan::Bump(ceiling), Some(10 * GWEI), true),
            Err(BlockedReason::TxFeeCapReached)
        );
        assert_eq!(
            plan(
                FeePlan::Bump(fees(limit / 2, 10 * GWEI)),
                Some(10 * GWEI),
                true
            ),
            Err(BlockedReason::TipCapReached)
        );
        assert_eq!(
            plan(
                FeePlan::Resend(fees(142 * GWEI, 2 * GWEI)),
                Some(10 * GWEI),
                false
            ),
            Ok(Some(fees(limit, 2 * GWEI)))
        );
        assert_eq!(
            plan(FeePlan::First, Some(140 * GWEI), false),
            Err(BlockedReason::TxFeeCapReached)
        );
        assert_eq!(
            plan(FeePlan::First, Some(301 * GWEI), true),
            Err(BlockedReason::BaseFeeAboveFeeCap)
        );
        // A legacy transaction bids its gas price as both fees.
        assert_eq!(
            transaction_fees(&json!({ "gasPrice": "0x2540be400" })),
            Some(fees(10 * GWEI, 10 * GWEI))
        );
        assert_eq!(
            transaction_fees(
                &json!({ "maxFeePerGas": "0x3", "maxPriorityFeePerGas": "0x2", "gasPrice": "0x1" })
            ),
            Some(fees(3, 2))
        );
    }

    #[tokio::test]
    async fn send_errors_are_classified_by_broadcast_risk() {
        let rpc = |error: Value| {
            anyhow::Error::from(RpcError {
                method: "eth_sendTransaction".into(),
                error,
            })
        };
        let classify = |error: Value| classify_send_error(&rpc(error));
        assert!(matches!(
            classify(json!({ "code": -32602, "message": "m", "data": { "reason": "fee_out_of_bounds" } })),
            SendFailure::Refused(Some(reason)) if reason == "fee_out_of_bounds"
        ));
        assert!(matches!(
            classify(
                json!({ "code": -32003, "message": "m", "data": { "reason": "insufficient_balance" } })
            ),
            SendFailure::Refused(Some(_))
        ));
        assert!(matches!(
            classify(json!({ "code": -32601, "message": "m" })),
            SendFailure::Refused(None)
        ));
        // The signer's and its node's transaction fee caps refuse before any
        // pool, each under its own reason.
        for (reason, blocked) in [
            ("tx_fee_above_cap", BlockedReason::TxFeeAboveCap),
            ("upstream_tx_fee_cap", BlockedReason::UpstreamTxFeeCap),
            ("base_fee_above_max_fee", BlockedReason::BaseFeeAboveMaxFee),
            ("insufficient_balance", BlockedReason::InsufficientBalance),
            ("fee_out_of_bounds", BlockedReason::SignerRefused),
        ] {
            assert!(matches!(
                classify(json!({ "code": -32003, "message": "m", "data": { "reason": reason } })),
                SendFailure::Refused(Some(refused)) if refused == reason
            ));
            assert_eq!(refusal_reason(Some(reason)), blocked);
        }
        let capped = |data: Value| rpc(json!({ "code": -32003, "message": "m", "data": data }));
        assert_eq!(
            refused_tx_fee_cap(
                &capped(
                    json!({ "reason": "tx_fee_above_cap", "gas_limit": "0x72f6c5",
                    "tx_fee_cap_wei": "0xde0b6b3a7640000", "max_fee_per_gas_allowed": "0x1ee6c4df42" })
                ),
                1
            ),
            Some(ONE_ETHER)
        );
        assert_eq!(
            refused_tx_fee_cap(
                &capped(json!({ "reason": "tx_fee_above_cap", "max_fee_per_gas_allowed": "0x64" })),
                7
            ),
            Some(700)
        );
        assert_eq!(
            refused_tx_fee_cap(&capped(json!({ "reason": "tx_fee_above_cap" })), 7),
            None
        );
        // The refused fee of upstream_tx_fee_cap: as reported, else the
        // send's own, also for a report that leaves no bound.
        let refused = |data: Value| refused_tx_fee(&capped(data), 7, 100);
        assert_eq!(
            refused(
                json!({ "reason": "upstream_tx_fee_cap", "gas_limit": "0x5", "max_fee_per_gas": "0x40" })
            ),
            320
        );
        assert_eq!(refused(json!({ "reason": "upstream_tx_fee_cap" })), 700);
        for zero in [
            json!({ "reason": "upstream_tx_fee_cap", "gas_limit": "0x0", "max_fee_per_gas": "0x0" }),
            json!({ "reason": "upstream_tx_fee_cap", "max_fee_per_gas": "0x0" }),
            json!({ "reason": "upstream_tx_fee_cap", "gas_limit": "0x1", "max_fee_per_gas": "0x1" }),
        ] {
            assert_eq!(refused(zero.clone()), 700, "{zero}");
        }
        assert!(matches!(
            classify(
                json!({ "code": -32000, "message": "m", "data": { "reason": "simulation_failed" } })
            ),
            SendFailure::NotBroadcast(BlockedReason::SimulationReverted)
        ));
        assert!(matches!(
            classify(
                json!({ "code": -32000, "message": "m", "data": { "reason": "upstream_unavailable" } })
            ),
            SendFailure::NotBroadcast(BlockedReason::RpcError)
        ));
        let hash = format!("0x{}", "ab".repeat(32));
        assert!(matches!(
            classify(json!({ "code": -32000, "message": "m",
                "data": { "reason": "broadcast_ambiguous", "transaction_hash": hash } })),
            SendFailure::Ambiguous(Some(candidate)) if candidate == hash
        ));
        // Anything unrecognised may have broadcast; a malformed hash is ignored.
        assert!(matches!(
            classify(
                json!({ "code": -32000, "message": "m", "data": { "transaction_hash": "0x12" } })
            ),
            SendFailure::Ambiguous(None)
        ));
        assert!(matches!(
            classify(json!({ "code": -32603, "message": "Signer request failed" })),
            SendFailure::Ambiguous(None)
        ));
        // A refused connection never reached the signer; other transport
        // failures (timeouts, HTTP errors) may follow a broadcast.
        let fixture = Fixture::new().await;
        let unreachable =
            fixture.service_with(|config| config.rpc_url = "http://127.0.0.1:9/v3/key".into());
        let error = unreachable
            .rpc("eth_sendTransaction", json!([]))
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("/v3/key"), "{error}");
        assert!(matches!(
            classify_send_error(&error),
            SendFailure::NotBroadcast(BlockedReason::RpcError)
        ));
        fixture.chain.lock().unwrap().fail_all = true;
        let error = fixture
            .service()
            .rpc("eth_sendTransaction", json!([]))
            .await
            .unwrap_err();
        assert!(matches!(
            classify_send_error(&error),
            SendFailure::Ambiguous(None)
        ));
        // Vault custom errors are found in revert data or the message.
        assert_eq!(hex::encode(selector("StaleRoot()")), "607447de");
        let revert = |error: Value| vault_revert(&rpc(error));
        assert_eq!(
            revert(json!({ "code": 3, "message": "execution reverted", "data": "0x607447de" })),
            Some("StaleRoot()")
        );
        assert_eq!(
            revert(
                json!({ "code": -32000, "message": "execution reverted: custom error 0x607447de" })
            ),
            Some("StaleRoot()")
        );
        assert_eq!(
            revert(json!({ "code": -32000, "message": "m", "data": {
                "data": format!("0x{}", hex::encode(selector("NotPendingWithdrawal()"))) } })),
            Some("NotPendingWithdrawal()")
        );
        assert_eq!(
            revert(
                json!({ "code": -32000, "message": "Upstream RPC rejected the request",
                "data": { "reason": "upstream_rejected" } })
            ),
            None
        );
    }

    #[tokio::test]
    async fn missed_deadline_behind_a_blocked_nonce_is_recorded() {
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        // Note 1 holds an unresolved reserved nonce and its state is unreadable,
        // so the loop stops before note 0, whose deadline passes meanwhile.
        fixture.reserve(&mut service, 1, false);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.fail_note_one = true;
            chain.head_timestamp = chain.deadline;
        }
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("temporary note-state failure"));
        assert!(fixture.sends().is_empty());
        assert!(service.checkpoint.pending[&0].deadline_reported);
        let status = service.status();
        assert_eq!(obligation(&status, 0).state, ObligationState::Missed);
        assert_eq!(status.missed_total, 1);
        assert_eq!(
            obligation(&status, 1).blocked_reason,
            Some(BlockedReason::RpcError)
        );
        drop(service);
        assert_eq!(fixture.service().checkpoint.missed_total, 1, "persisted");
    }

    #[tokio::test]
    async fn deployment_binding_must_match_config_and_vault_state_key() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let fixture = Fixture::with_store(store.clone(), &request).await;
        let mut service = fixture.service();
        let mismatch = |result: Result<DeploymentBinding, DeploymentCheckError>| match result {
            Err(DeploymentCheckError::Mismatch(message)) => message,
            other => panic!("expected a mismatch, got {other:?}"),
        };
        assert!(
            mismatch(service.verify_deployment_binding().await).contains("no deployment binding")
        );
        assert!(service
            .status()
            .config_warnings
            .iter()
            .any(|warning| warning.contains("deployment binding not verified")));
        let public = &request.public_inputs;
        let binding = DeploymentBinding {
            chain_id: 1,
            contract_address: format!("0x{:040x}", 0xdead),
            state_signing_key: CurvePointWire {
                x: public.state_signing_key_x,
                y: public.state_signing_key_y,
            },
            clearance_signing_key: CurvePointWire {
                x: Felt252::from_u64(1),
                y: Felt252::from_u64(2),
            },
            challenge_period_seconds: 86_400,
            verified_at: 1,
            verified_block: None,
        };
        store.write_deployment_binding(&binding).unwrap();
        assert_eq!(service.verify_deployment_binding().await.unwrap(), binding);
        assert!(service.status().config_warnings.is_empty());
        for (wrong, message) in [
            (
                DeploymentBinding {
                    chain_id: 11_155_111,
                    ..binding.clone()
                },
                "bound to chain 11155111",
            ),
            (
                DeploymentBinding {
                    contract_address: format!("0x{:040x}", 0xbeef),
                    ..binding.clone()
                },
                "beef",
            ),
        ] {
            store.write_deployment_binding(&wrong).unwrap();
            assert!(mismatch(service.verify_deployment_binding().await).contains(message));
        }
        store.write_deployment_binding(&binding).unwrap();
        fixture.chain.lock().unwrap().state_key.1 = Felt252::from_u64(9);
        assert!(mismatch(service.verify_deployment_binding().await)
            .contains("state signing key differs"));
        fixture.chain.lock().unwrap().fail_all = true;
        assert!(matches!(
            service.verify_deployment_binding().await,
            Err(DeploymentCheckError::Unavailable(_))
        ));
    }

    /// The gas limit of a measured real Groth16 challenge (estimate + 20%).
    const REAL_GAS_LIMIT: u128 = 7_534_341;

    /// Every send kept gas limit x maxFeePerGas within `cap`.
    fn within(sends: &[Value], cap: u128) -> bool {
        sends
            .iter()
            .all(|send| fee(send, "gas") * fee(send, "maxFeePerGas") <= cap)
    }

    /// Mainnet caps of 300 and 10 gwei with the default 1 ether ceiling.
    fn mainnet_fees(config: &mut ChallengeServiceConfig) {
        config.fee = FeePolicy::new(300 * GWEI, 10 * GWEI);
    }

    #[tokio::test]
    async fn rpc_fee_cap_bids_stay_within_the_ceiling_and_later_notes_are_challenged() {
        // A node with the default 1 ether RPC fee cap refuses a costlier bid
        // before its pool; an earlier signer reported that as possibly
        // broadcast, which locked the nonce at the refused fee.
        for refusal in ["broadcast_ambiguous", "tx_fee_above_cap"] {
            let fixture = Fixture::new().await;
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.tx_fee_cap = Some((ONE_ETHER, refusal));
                chain.estimate = 6_278_618;
                // A Mainnet spike, below the daemon's cap.
                chain.base_fee = Some(70 * GWEI);
                chain.deadline += 10_000;
            }
            let mut service = fixture.service_with(mainnet_fees);
            service.poll_once().await.unwrap();
            fixture.chain.lock().unwrap().drop_logs = true;
            assert!(fee(&fixture.sends()[0], "maxFeePerGas") >= 70 * GWEI);
            // The spike ends; the challenge stays pending meanwhile.
            fixture.chain.lock().unwrap().base_fee = Some(10 * GWEI);
            for _ in 0..20 {
                fixture.chain.lock().unwrap().head_number += 3;
                service.poll_once().await.unwrap();
            }
            // Kept: the spike bid's max fee is at the non-critical limit, so
            // the rest of the headroom is held for the critical threshold.
            let head = obligation(&service.status(), 0);
            assert_eq!(head.state, ObligationState::Submitted, "{refusal}");
            assert_eq!(
                head.blocked_reason,
                Some(BlockedReason::FeeReserveHeld),
                "{refusal}"
            );
            // A later escape is challenged on the next nonce at once.
            let later = fixture.chain.lock().unwrap().deadline + 5_000;
            fixture.track(&mut service, 1, later);
            fixture.chain.lock().unwrap().head_number += 3;
            service.poll_once().await.unwrap();
            let sends = fixture.sends();
            let queued: Vec<_> = sends
                .iter()
                .filter(|send| decode_call(send).0 == Felt252::from_u64(1).as_bytes())
                .collect();
            assert_eq!(queued.len(), 1, "{refusal}");
            assert_eq!(queued[0]["nonce"], "0x4");
            assert!(within(&sends, ONE_ETHER), "{refusal}");
            assert_eq!(fixture.chain.lock().unwrap().fee_capped_sends, 0);
            assert_eq!(service.status().status, Severity::Warning, "{refusal}");
        }
    }

    #[tokio::test]
    async fn critical_escalation_stays_within_the_rpc_fee_cap_at_low_base_fee() {
        for refusal in ["broadcast_ambiguous", "tx_fee_above_cap"] {
            let fixture = Fixture::new().await;
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.tx_fee_cap = Some((ONE_ETHER, refusal));
                chain.estimate = 6_278_618;
                chain.base_fee = Some(10 * GWEI);
                // First seen inside the critical threshold.
                chain.head_timestamp = chain.deadline - 5;
            }
            let mut service = fixture.service_with(mainnet_fees);
            for _ in 0..6 {
                service.poll_once().await.unwrap();
                fixture.chain.lock().unwrap().head_number += 3;
            }
            let sends = fixture.sends();
            assert_eq!(
                fixture.chain.lock().unwrap().fee_capped_sends,
                0,
                "{refusal}"
            );
            // 10/11 of the ceiling's fee per gas, then the ceiling itself.
            let limit = ONE_ETHER / REAL_GAS_LIMIT;
            assert_eq!(sends.len(), 2, "{refusal}");
            assert_eq!(fee(&sends[0], "maxFeePerGas"), headroom(limit));
            assert_eq!(fee(&sends[1], "maxFeePerGas"), limit);
            assert!(within(&sends, ONE_ETHER));
            // Then the pending bid is kept, and the ceiling is reported.
            let capped = obligation(&service.status(), 0);
            assert_eq!(capped.state, ObligationState::Submitted);
            assert_eq!(capped.blocked_reason, Some(BlockedReason::TxFeeCapReached));
            assert!(capped
                .detail
                .unwrap()
                .contains("and the transaction fee ceiling of 1000000000000000000 wei"));
        }
    }

    #[tokio::test]
    async fn signer_tx_fee_cap_bounds_bids_and_its_refusals_are_reported() {
        let half = ONE_ETHER / 2;
        let critical_at_low_base_fee = |chain: &mut MockChain| {
            chain.estimate = 6_278_618;
            chain.base_fee = Some(10 * GWEI);
            chain.head_timestamp = chain.deadline - 5;
        };
        // The signer reports a lower cap: bids stay within it, with a warning.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            critical_at_low_base_fee(&mut chain);
            chain.tx_fee_cap = Some((half, "tx_fee_above_cap"));
            chain.signer_status = Some(json!({ "tx_fee_cap_wei": hex_quantity(half) }));
        }
        let mut service = fixture.service_with(mainnet_fees);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(
            fee(&sends[0], "maxFeePerGas"),
            headroom(half / REAL_GAS_LIMIT)
        );
        let status = service.status();
        assert_eq!(status.sender.tx_fee_cap_wei, ONE_ETHER.to_string());
        assert_eq!(status.sender.signer_tx_fee_cap_wei, Some(half.to_string()));
        assert_eq!(status.sender.effective_tx_fee_cap_wei, half.to_string());
        assert!(status
            .config_warnings
            .iter()
            .any(|warning| warning.contains("differs from --tx-fee-cap-wei")));
        // A zero report is malformed and leaves the cap in force.
        fixture.chain.lock().unwrap().signer_status = Some(json!({ "tx_fee_cap_wei": "0x0" }));
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.sender.effective_tx_fee_cap_wei, half.to_string());
        assert!(status
            .sender
            .signer_status_detail
            .unwrap()
            .contains("zero tx_fee_cap_wei"));

        // A signer that does not report it refuses the bid with its cap: a
        // definitive refusal that bounds the next bid.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            critical_at_low_base_fee(&mut chain);
            chain.tx_fee_cap = Some((half, "tx_fee_above_cap"));
        }
        let mut service = fixture.service_with(mainnet_fees);
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(error.contains("tx_fee_above_cap"), "{error}");
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        let refused = obligation(&service.status(), 0);
        assert_eq!(refused.blocked_reason, Some(BlockedReason::TxFeeAboveCap));
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[1]["nonce"], "0x3");
        assert!(within(&sends[1..], half));
        assert_eq!(fixture.chain.lock().unwrap().fee_capped_sends, 1);
        assert_eq!(
            service.status().sender.signer_tx_fee_cap_wei,
            Some(half.to_string())
        );

        // Its node's lower RPC fee cap is a definitive refusal too, and needs
        // the operator at once.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            critical_at_low_base_fee(&mut chain);
            chain.tx_fee_cap = Some((half, "upstream_tx_fee_cap"));
        }
        let mut service = fixture.service_with(mainnet_fees);
        assert!(service.poll_once().await.is_err());
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        let refused = obligation(&service.status(), 0);
        assert_eq!(
            refused.blocked_reason,
            Some(BlockedReason::UpstreamTxFeeCap)
        );
        assert_eq!(refused.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn base_fee_above_the_tx_fee_ceiling_reports_tx_fee_cap_reached() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.tx_fee_cap = Some((ONE_ETHER, "tx_fee_above_cap"));
            chain.estimate = 6_278_618;
            // Above the 132.7 gwei the ceiling allows, below the 300 gwei cap.
            chain.base_fee = Some(140 * GWEI);
        }
        let mut service = fixture.service_with(mainnet_fees);
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        assert!(fixture.sends().is_empty());
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        let limit = ONE_ETHER / REAL_GAS_LIMIT;
        let status = service.status();
        let blocked = obligation(&status, 0);
        assert_eq!(blocked.state, ObligationState::Ready);
        assert_eq!(blocked.blocked_reason, Some(BlockedReason::TxFeeCapReached));
        assert!(blocked
            .detail
            .unwrap()
            .contains(&format!("allows a maxFeePerGas of at most {limit} wei")));
        assert!(status.alarms.contains(&format!(
            "warning: transaction fee ceiling {ONE_ETHER} wei allows a maxFeePerGas of at most {limit} wei at {REAL_GAS_LIMIT} gas; base fee {} wei",
            140 * GWEI
        )));
        // A 300 gwei cap is never reached under a 1 ether ceiling.
        assert!(status
            .config_warnings
            .iter()
            .any(|warning| warning.contains("exceeds the transaction fee ceiling")));
        // Once the base fee falls, the challenge is sent within the ceiling.
        fixture.chain.lock().unwrap().base_fee = Some(100 * GWEI);
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert!(within(&sends, ONE_ETHER));
        assert_eq!(fixture.chain.lock().unwrap().fee_capped_sends, 0);
    }

    #[tokio::test]
    async fn bids_above_the_ceiling_are_observed_or_re_planned_never_resent() {
        // A pending challenge bid above the ceiling, for example under an
        // earlier daemon: no replacement fits, so it is kept and observed.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.estimate = 6_278_618;
            chain.base_fee = Some(10 * GWEI);
            chain.head_timestamp = chain.deadline - 5;
        }
        let mut service = fixture.service_with(|config| {
            config.fee = FeePolicy {
                tx_fee_cap_wei: 10 * ONE_ETHER,
                ..FeePolicy::new(300 * GWEI, 10 * GWEI)
            }
        });
        service.poll_once().await.unwrap();
        let first = fixture.sends()[0].clone();
        assert!(fee(&first, "gas") * fee(&first, "maxFeePerGas") > ONE_ETHER);
        drop(service);
        fixture.chain.lock().unwrap().tx_fee_cap = Some((ONE_ETHER, "tx_fee_above_cap"));
        let mut service = fixture.service_with(mainnet_fees);
        for _ in 0..3 {
            fixture.chain.lock().unwrap().head_number += 3;
            service.poll_once().await.unwrap();
        }
        assert_eq!(fixture.sends().len(), 1, "no refused bid is re-sent");
        let kept = obligation(&service.status(), 0);
        assert_eq!(kept.state, ObligationState::Submitted);
        assert_eq!(kept.blocked_reason, Some(BlockedReason::TxFeeCapReached));
        assert!(kept.detail.unwrap().contains("transaction fee ceiling"));

        // A nonce an earlier daemon locked at a refused 142 gwei bid, whose
        // candidate hash no node knows: nothing holds it, so it is re-planned
        // within the ceiling.
        let fixture = Fixture::new().await;
        let refused_hash = format!("0x{:064x}", 0xdead_0000_0000u64);
        let nullifier = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.tx_fee_cap = Some((ONE_ETHER, "broadcast_ambiguous"));
            chain.fee_capped_hashes.insert(refused_hash.clone());
            chain.estimate = 6_278_618;
            chain.base_fee = Some(10 * GWEI);
            chain.deadline += 10_000;
            chain.nullifier
        };
        let mut service = fixture.service_with(mainnet_fees);
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier,
                nonce: Some(3),
                attempt: NonceAttempts {
                    superseded_hashes: vec![refused_hash],
                    max_fee_per_gas: Some(format!("0x{:x}", 142 * GWEI)),
                    max_priority_fee_per_gas: Some(format!("0x{:x}", 2 * GWEI)),
                    attempts: 21,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        service.persist().unwrap();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0]["nonce"], "0x3");
        assert!(within(&sends, ONE_ETHER));
        assert_eq!(fixture.chain.lock().unwrap().fee_capped_sends, 0);
        // The record now holds that bid, so replacements are planned from it.
        assert_eq!(
            service.persisted_fees(0),
            Some(Fees {
                max_fee: ONE_ETHER / REAL_GAS_LIMIT,
                tip: 2 * GWEI
            })
        );
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::Submitted
        );
    }

    #[tokio::test]
    async fn not_broadcast_nonce_is_released_and_later_notes_are_challenged() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.base_fee = Some(30 * GWEI);
            chain.send_errors.push_back(json!({
                "code": -32000, "message": "Challenge simulation failed",
                "data": { "reason": "simulation_failed" } }));
        }
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        fixture.chain.lock().unwrap().drop_logs = true;
        // The signer reports the failure before broadcasting: the fresh
        // nonce is released at once.
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        // The base fee then stays above the 100 gwei cap until the deadline.
        fixture.chain.lock().unwrap().base_fee = Some(150 * GWEI);
        service.poll_once().await.unwrap();
        let later = fixture.chain.lock().unwrap().deadline + 5_000;
        fixture.track(&mut service, 1, later);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline;
        }
        service.poll_once().await.unwrap();
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::Missed
        );
        // The escaper finalizes, and fees normalise.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.active = false;
            chain.confirmed_active = false;
            chain.base_fee = Some(10 * GWEI);
            chain.head_number += 3;
        }
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2);
        assert_eq!(decode_call(&sends[1]).0, Felt252::from_u64(1).as_bytes());
        assert_eq!(sends[1]["nonce"], "0x3");
        assert!(!service.checkpoint.pending.contains_key(&0));
        let status = service.status();
        assert!(status.detached_nonces.is_empty());
        assert_eq!(obligation(&status, 1).state, ObligationState::Submitted);
        assert_eq!(status.missed_total, 1);
    }

    #[tokio::test]
    async fn never_broadcast_reservations_left_by_an_earlier_daemon_are_released() {
        // The record an earlier daemon kept after attempts that all failed
        // before broadcast.
        let unsent = || NonceAttempts {
            attempts: 1,
            ..Default::default()
        };
        // An expired obligation releases its nonce instead of blocking.
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let (nullifier, deadline) = {
            let chain = fixture.chain.lock().unwrap();
            (chain.nullifier, chain.deadline)
        };
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier,
                nonce: Some(3),
                challenge_deadline: Some(deadline),
                attempt: unsent(),
                ..Default::default()
            },
        );
        fixture.track(&mut service, 1, deadline + 1_000);
        fixture.chain.lock().unwrap().head_timestamp = deadline;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), 1);
        assert_eq!(decode_call(&sends[0]).0, Felt252::from_u64(1).as_bytes());
        assert_eq!(sends[0]["nonce"], "0x3");
        assert_eq!(
            obligation(&service.status(), 0).state,
            ObligationState::Missed
        );

        // So does a detached one.
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        service.checkpoint.detached_nonces.insert(
            3,
            DetachedNonce {
                note_id: 5,
                nullifier: Felt252::from_u64(5),
                transaction_hash: None,
                attempt: unsent(),
            },
        );
        service.persist().unwrap();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.detached_nonces.is_empty());
        assert!(service.status().detached_nonces.is_empty());
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(fixture.sends()[0]["nonce"], "0x3");

        // And one whose withdrawal is resolved, instead of detaching it.
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        let nullifier = fixture.chain.lock().unwrap().nullifier;
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier,
                nonce: Some(3),
                attempt: unsent(),
                ..Default::default()
            },
        );
        service.persist().unwrap();
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.active = false;
            chain.confirmed_active = false;
        }
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        assert!(service.checkpoint.detached_nonces.is_empty());
        let later = fixture.chain.lock().unwrap().deadline + 1_000;
        fixture.track(&mut service, 1, later);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1);
        assert_eq!(fixture.sends()[0]["nonce"], "0x3");

        // A reservation an earlier daemon made without any attempt record is
        // never released, even after a refusal of this daemon's attempt.
        let fixture = Fixture::new().await;
        let mut service = fixture.service();
        fixture.reserve(&mut service, 1, false);
        fixture.chain.lock().unwrap().refuse_notes.insert(1);
        assert!(service.poll_once().await.is_err());
        let held = &service.checkpoint.pending[&1];
        assert_eq!(held.nonce, Some(3));
        assert!(held.attempt.unrecorded_attempt);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline;
        }
        assert!(service
            .poll_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("signer intervention required"));
        assert_eq!(service.checkpoint.pending[&1].nonce, Some(3));
    }

    #[tokio::test]
    async fn critical_replacements_remain_after_non_critical_bumps_spend_their_budget() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.estimate = 6_278_618;
            chain.base_fee = Some(10 * GWEI);
            chain.deadline += 10_000;
        }
        // The documented minimum tip cap: twice the 2 gwei first tip.
        let mut service =
            fixture.service_with(|config| config.fee = FeePolicy::new(130 * GWEI, 4 * GWEI));
        service.poll_once().await.unwrap();
        fixture.chain.lock().unwrap().drop_logs = true;
        for _ in 0..12 {
            // Not mined for three blocks each time.
            fixture.chain.lock().unwrap().head_number += 3;
            service.poll_once().await.unwrap();
        }
        let last = fixture.sends().last().unwrap().clone();
        assert!(fixture.sends().len() > 5);
        assert!(fee(&last, "maxPriorityFeePerGas") <= headroom(headroom(4 * GWEI)));
        let waiting = obligation(&service.status(), 0);
        assert_eq!(waiting.blocked_reason, Some(BlockedReason::FeeReserveHeld));
        assert!(waiting
            .detail
            .unwrap()
            .contains("reserved for the critical threshold"));
        // The base fee rises above the pending bid, below the cap, as the
        // obligation turns critical.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.base_fee = Some(110 * GWEI);
            chain.head_timestamp = chain.deadline - 5;
            chain.head_number += 3;
        }
        let before = fixture.sends().len();
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), before + 1, "a critical replacement is sent");
        let critical = &sends[before];
        assert_eq!(critical["nonce"], last["nonce"]);
        assert!(fee(critical, "maxFeePerGas") >= 110 * GWEI);
        for field in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(
                fee(critical, field) >= min_bump(fee(&last, field)),
                "{field}"
            );
        }
        // And one more, at the caps.
        fixture.chain.lock().unwrap().head_number += 3;
        service.poll_once().await.unwrap();
        let sends = fixture.sends();
        assert_eq!(sends.len(), before + 2);
        assert_eq!(fee(&sends[before + 1], "maxFeePerGas"), 130 * GWEI);
        assert_eq!(fee(&sends[before + 1], "maxPriorityFeePerGas"), 4 * GWEI);
    }

    #[tokio::test]
    async fn back_run_re_escape_is_challenged_when_the_listing_is_stale() {
        let (store, first, second) = two_finalized_v2_requests().await;
        let fixture = Fixture::with_store(store, &first).await;
        let a = first.public_inputs.request_nullifier;
        let b = second.public_inputs.request_nullifier;
        let mut service = fixture.service_with(|config| config.alarms.blocked_warning_seconds = 0);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1, "escape A challenged");
        {
            let mut chain = fixture.chain.lock().unwrap();
            // The challenge of A mined, and in the same block the owner
            // escaped again with B, another finalized request.
            chain.mined_nonce = 4;
            chain.nullifier = b;
            chain.head_number += 3;
            // The scan misses B, and the indexer, whose log source dropped
            // the root-neutral pair, still lists A.
            chain.drop_logs = true;
            chain.escapes = Some(vec![json!({
                "note_id": 0, "withdrawal_nullifier": a, "challenge_deadline": chain.deadline
            })]);
        }
        for _ in 0..3 {
            service.poll_once().await.unwrap();
        }
        let sends = fixture.sends();
        assert_eq!(sends.len(), 2, "B is challenged");
        assert_eq!(sends[1]["nonce"], "0x4");
        assert_eq!(decode_call(&sends[1]).1[8 * 32..9 * 32], b.as_bytes()[..]);
        assert_eq!(service.checkpoint.pending[&0].nullifier, b);
        let status = service.status();
        assert!(status
            .indexer
            .pending_escapes_disagreement
            .as_ref()
            .unwrap()
            .starts_with("note 0 listed with nullifier"));
        assert!(status
            .alarms
            .iter()
            .any(|alarm| alarm.contains("pending-escapes list disagrees with the vault")));
        assert_eq!(status.missed_total, 0);
    }

    #[tokio::test]
    async fn indexer_listed_note_with_a_stale_nullifier_tracks_the_vaults_escape() {
        let fixture = Fixture::new().await;
        let live = {
            let mut chain = fixture.chain.lock().unwrap();
            // The event scan misses the live escape.
            chain.drop_logs = true;
            // The indexer lists note 0 with an earlier, challenged escape.
            chain.escapes = Some(vec![json!({
                "note_id": 0, "withdrawal_nullifier": Felt252::from_u64(0x384),
                "challenge_deadline": chain.deadline
            })]);
            chain.nullifier
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.pending[&0].nullifier, live);
        assert_eq!(fixture.sends().len(), 1);
        let status = service.status();
        assert_eq!(status.indexer.escapes_added_from_indexer, 1);
        assert!(status.indexer.pending_escapes_disagreement.is_some());
        // Past its deadline it would be counted, never silently dropped.
        assert_eq!(obligation(&status, 0).state, ObligationState::Submitted);
    }

    #[tokio::test]
    async fn signer_base_fee_refusal_of_a_stale_bid_has_its_own_reason() {
        let fixture = Fixture::new().await;
        fixture.chain.lock().unwrap().send_errors.push_back(json!({
            "code": -32003, "message": "Base fee exceeds the transaction max fee per gas",
            "data": { "reason": "base_fee_above_max_fee",
                "base_fee_per_gas": "0x12a05f200", "max_fee_per_gas": "0xee6b2800" }
        }));
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::BaseFeeAboveMaxFee)
        );
        // The next poll bids again from the current base fee.
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 2);
        assert_eq!(obligation(&service.status(), 0).blocked_reason, None);
    }

    #[test]
    fn tx_fee_cap_is_a_strict_positive_decimal() {
        let parse = FeePolicy::parse_tx_fee_cap;
        assert_eq!(parse(""), Ok(FeePolicy::DEFAULT_TX_FEE_CAP_WEI));
        assert_eq!(parse("1"), Ok(1));
        assert_eq!(parse("1000000000000000000"), Ok(ONE_ETHER));
        for invalid in [
            "0",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1e18",
            "0x10",
            "1.5",
            "340282366920938463463374607431768211456",
        ] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
        let policy = FeePolicy {
            tx_fee_cap_wei: 0,
            ..FeePolicy::new(100 * GWEI, 10 * GWEI)
        };
        assert!(policy
            .validate()
            .unwrap_err()
            .to_string()
            .contains("transaction fee cap must be positive"));
    }

    /// (gas limit x maxFeePerGas, accepted) of every send, in order.
    fn sent_tx_fees(fixture: &Fixture, cap: u128) -> Vec<(u128, bool)> {
        fixture
            .sends()
            .iter()
            .map(|send| {
                let tx_fee = fee(send, "gas") * fee(send, "maxFeePerGas");
                (tx_fee, tx_fee <= cap)
            })
            .collect()
    }

    #[tokio::test]
    async fn node_fee_cap_below_the_ceiling_is_learned_from_its_refusals() {
        // The node behind the signer caps transaction fees at 0.5 ether,
        // below the 1 ether ceiling both services were given.
        let node_cap = ONE_ETHER / 2;
        for signer_reports_its_cap in [false, true] {
            // First seen inside the critical threshold at a low base fee,
            // where a 22 gwei bid (0.17 ether) would be included.
            let fixture = Fixture::new().await;
            {
                let mut chain = fixture.chain.lock().unwrap();
                chain.tx_fee_cap = Some((node_cap, "upstream_tx_fee_cap"));
                chain.estimate = 6_278_618;
                chain.base_fee = Some(10 * GWEI);
                chain.head_timestamp = chain.deadline - 9;
                if signer_reports_its_cap {
                    chain.signer_status =
                        Some(json!({ "tx_fee_cap_wei": hex_quantity(ONE_ETHER) }));
                }
            }
            let mut service = fixture.service_with(mainnet_fees);
            // A refusal is critical at once, and nothing holds the nonce.
            assert!(service.poll_once().await.is_err());
            let refused = obligation(&service.status(), 0);
            assert_eq!(
                refused.blocked_reason,
                Some(BlockedReason::UpstreamTxFeeCap)
            );
            assert_eq!(refused.severity, Severity::Critical);
            assert_eq!(service.checkpoint.pending[&0].nonce, None);
            for _ in 0..5 {
                let _ = service.poll_once().await;
                fixture.chain.lock().unwrap().head_number += 1;
            }
            // Each refusal lowers the next bid until the node accepts one.
            let sent = sent_tx_fees(&fixture, node_cap);
            let refusals: Vec<u128> = sent
                .iter()
                .take_while(|(_, accepted)| !accepted)
                .map(|(tx_fee, _)| *tx_fee)
                .collect();
            assert!(
                refusals.windows(2).all(|pair| pair[1] <= headroom(pair[0])),
                "{sent:?}"
            );
            assert!(refusals.len() <= 4, "{sent:?}");
            let (accepted, _) = sent[refusals.len()];
            assert!(accepted <= node_cap && accepted > node_cap / 2, "{sent:?}");
            assert_eq!(fixture.sends()[refusals.len()]["nonce"], "0x3");
            assert_eq!(
                fixture.chain.lock().unwrap().fee_capped_sends,
                refusals.len()
            );
            let status = service.status();
            let submitted = obligation(&status, 0);
            assert_eq!(submitted.state, ObligationState::Submitted);
            assert_ne!(
                submitted.blocked_reason,
                Some(BlockedReason::UpstreamTxFeeCap)
            );
            // The bound stays in force and on /status until restart.
            let bound = headroom(*refusals.last().unwrap());
            assert_eq!(
                status.sender.node_tx_fee_cap_bound_wei,
                Some(bound.to_string())
            );
            assert_eq!(status.sender.effective_tx_fee_cap_wei, bound.to_string());
            assert!(status
                .config_warnings
                .iter()
                .any(|warning| warning.contains(&format!(
                    "the signer's node refused a transaction fee of {} wei",
                    refusals.last().unwrap()
                ))));
        }

        // A non-critical spike: the reserve-limited bid of 109.7 gwei (0.83
        // ether) is refused, while about 66 gwei would be included.
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.tx_fee_cap = Some((node_cap, "upstream_tx_fee_cap"));
            chain.signer_status = Some(json!({ "tx_fee_cap_wei": hex_quantity(ONE_ETHER) }));
            chain.estimate = 6_278_618;
            chain.base_fee = Some(60 * GWEI);
            chain.deadline += 10_000;
        }
        let mut service = fixture.service_with(mainnet_fees);
        for _ in 0..4 {
            let _ = service.poll_once().await;
            fixture.chain.lock().unwrap().head_number += 1;
        }
        let sent = sent_tx_fees(&fixture, node_cap);
        let refused = sent.iter().take_while(|(_, accepted)| !accepted).count();
        assert!((1..=3).contains(&refused), "{sent:?}");
        assert!(sent.len() > refused, "{sent:?}");
        assert!(fee(&fixture.sends()[refused], "maxFeePerGas") > 60 * GWEI);
        assert!(sent[refused..].iter().all(|(_, accepted)| *accepted));
        let o = obligation(&service.status(), 0);
        assert_eq!(o.state, ObligationState::Submitted);
        assert_eq!(o.blocked_reason, None);
        assert_eq!(o.severity, Severity::Ok);
    }

    #[tokio::test]
    async fn re_escape_without_an_indexer_listing_is_followed_from_the_vault() {
        // An indexer that predates /v1/escapes/pending (404), or lists nothing:
        // only the per-poll vault read finds the re-escape.
        for listing in [None, Some(vec![])] {
            let (store, first, second) = two_finalized_v2_requests().await;
            let fixture = Fixture::with_store(store, &first).await;
            let b = second.public_inputs.request_nullifier;
            let mut service = fixture.service();
            service.poll_once().await.unwrap();
            assert_eq!(fixture.sends().len(), 1, "escape A challenged");
            {
                // The challenge of A mined, and in the same block the owner
                // escaped again with B, whose log the scan drops.
                let mut chain = fixture.chain.lock().unwrap();
                chain.mined_nonce = 4;
                chain.nullifier = b;
                chain.head_number += 3;
                chain.drop_logs = true;
                chain.escapes = listing.clone();
            }
            for _ in 0..3 {
                let _ = service.poll_once().await;
                fixture.chain.lock().unwrap().head_number += 1;
            }
            let sends = fixture.sends();
            assert_eq!(sends.len(), 2, "B is challenged: {listing:?}");
            assert_eq!(sends[1]["nonce"], "0x4");
            assert_eq!(decode_call(&sends[1]).1[8 * 32..9 * 32], b.as_bytes()[..]);
            assert_eq!(service.checkpoint.pending[&0].nullifier, b);
            assert_eq!(service.status().missed_total, 0);
        }
    }

    #[tokio::test]
    async fn observe_only_follows_the_vaults_escape_while_the_queue_is_blocked() {
        let (store, first, second) = two_finalized_v2_requests().await;
        let fixture = Fixture::with_store(store, &first).await;
        let b = second.public_inputs.request_nullifier;
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 1, "escape A challenged");
        let deadline_b = {
            let mut chain = fixture.chain.lock().unwrap();
            // A's challenge mined and the owner escaped again with B; neither
            // the scan nor the indexer reports B.
            chain.mined_nonce = 4;
            chain.nullifier = b;
            chain.deadline += 500;
            chain.head_number += 3;
            chain.drop_logs = true;
            chain.escapes = None;
            // Note 9 holds a nonce reserved without a known hash, so every
            // poll stops there and only observes note 0.
            let deadline = chain.deadline;
            chain
                .withdrawals
                .insert(9, (true, Felt252::from_u64(12345), deadline + 50));
            deadline
        };
        service.checkpoint.pending.insert(
            9,
            PendingChallenge {
                nullifier: Felt252::from_u64(12345),
                nonce: Some(5),
                ..Default::default()
            },
        );
        service.persist().unwrap();
        for _ in 0..2 {
            let _ = service.poll_once().await;
            fixture.chain.lock().unwrap().head_number += 1;
        }
        assert_eq!(service.checkpoint.pending[&0].nullifier, b);
        let o = obligation(&service.status(), 0);
        assert_eq!(o.challenge_deadline, Some(deadline_b));
        assert_eq!(o.state, ObligationState::Ready);
        assert_eq!(o.blocked_reason, Some(BlockedReason::NonceBlocked));
    }

    #[tokio::test]
    async fn plan_refusal_releases_a_never_broadcast_reservation_at_once() {
        let fixture = Fixture::new().await;
        let nullifier = {
            let mut chain = fixture.chain.lock().unwrap();
            // Above the 100 gwei fee cap: the plan refuses to send.
            chain.base_fee = Some(150 * GWEI);
            chain.drop_logs = true;
            chain.nullifier
        };
        let mut service = fixture.service();
        // An earlier daemon's record of an attempt that failed before
        // broadcast on nonce 3.
        service.checkpoint.pending.insert(
            0,
            PendingChallenge {
                nullifier,
                nonce: Some(3),
                attempt: NonceAttempts {
                    attempts: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        service.persist().unwrap();
        service.poll_once().await.unwrap();
        assert!(fixture.sends().is_empty());
        assert_eq!(service.checkpoint.pending[&0].nonce, None);
        assert_eq!(
            obligation(&service.status(), 0).blocked_reason,
            Some(BlockedReason::BaseFeeAboveFeeCap)
        );
    }

    #[tokio::test]
    async fn held_fee_reserve_is_reported_and_escalates_with_blocked_time() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.base_fee = Some(10 * GWEI);
            chain.deadline += 10_000;
        }
        // The documented minimum tip cap, twice the 2 gwei first tip, with
        // the blocked-time thresholds collapsed.
        let mut service = fixture.service_with(|config| {
            config.fee = FeePolicy {
                tx_fee_cap_wei: 10 * ONE_ETHER,
                ..FeePolicy::new(130 * GWEI, 4 * GWEI)
            };
            config.alarms.blocked_warning_seconds = 0;
            config.alarms.critical_blocked_seconds = 0;
        });
        service.poll_once().await.unwrap();
        fixture.chain.lock().unwrap().drop_logs = true;
        for _ in 0..12 {
            // Not mined for three blocks each time.
            fixture.chain.lock().unwrap().head_number += 3;
            service.poll_once().await.unwrap();
        }
        // Five replacements, then the rest is held for the critical threshold.
        let sends = fixture.sends();
        assert_eq!(sends.len(), 6);
        assert!(sends
            .iter()
            .all(|send| fee(send, "maxPriorityFeePerGas") <= headroom(headroom(4 * GWEI))));
        let status = service.status();
        let held = obligation(&status, 0);
        assert_eq!(held.state, ObligationState::Submitted);
        assert_eq!(held.blocked_reason, Some(BlockedReason::FeeReserveHeld));
        assert!(held
            .detail
            .unwrap()
            .contains("the remaining fee headroom is reserved for the critical threshold"));
        // The hold is not re-armed by each poll: its blocked time runs on.
        assert!(held.consecutive_failures > 1);
        assert_eq!(held.severity, Severity::Critical);
        assert!(status
            .alarms
            .contains(&"critical: note 0 submitted (fee_reserve_held)".to_string()));
        // At the critical threshold the reserve is spent at once.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_timestamp = chain.deadline - 5;
            chain.head_number += 3;
        }
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sends().len(), 7);
        assert_eq!(obligation(&service.status(), 0).blocked_reason, None);
    }

    #[test]
    fn critical_escalation_keeps_a_valid_replacement_under_a_ceiling_below_the_tip_cap() {
        // A ceiling of 6 gwei per gas, below the 10 gwei tip cap.
        let policy = FeePolicy::new(100 * GWEI, 10 * GWEI);
        let plan = |plan| plan_fees(&policy, plan, Some(GWEI), true, Some(6 * GWEI), None);
        let first = plan(FeePlan::First).unwrap().unwrap();
        let reserve = headroom(6 * GWEI);
        assert_eq!(
            first,
            Fees {
                max_fee: reserve,
                tip: reserve
            }
        );
        let next = plan(FeePlan::Bump(first)).unwrap().unwrap();
        assert_eq!(
            next,
            Fees {
                max_fee: 6 * GWEI,
                tip: 6 * GWEI
            }
        );
        assert!(is_valid_bump(first, next));
        assert_eq!(
            plan(FeePlan::Bump(next)),
            Err(BlockedReason::TxFeeCapReached)
        );
    }

    #[tokio::test]
    async fn fee_cap_lock_detached_before_the_upgrade_shows_its_bid_for_the_runbook() {
        // An earlier daemon locked nonce 3 at a 142 gwei bid its node refused
        // (an earlier signer reported a candidate hash no node knows), and
        // the escape was finalized before the upgrade. The nonce cannot be
        // told apart from a broadcast one, so it needs the manual runbook.
        let fixture = Fixture::new().await;
        let refused_hash = format!("0x{:064x}", 0xdead_0000_0000u64);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.fee_capped_hashes.insert(refused_hash.clone());
            chain.estimate = 6_278_618;
            chain.deadline += 10_000;
        }
        let mut service = fixture.service_with(mainnet_fees);
        service.checkpoint.detached_nonces.insert(
            3,
            DetachedNonce {
                note_id: 5,
                nullifier: Felt252::from_u64(5),
                transaction_hash: None,
                attempt: NonceAttempts {
                    superseded_hashes: vec![refused_hash.clone()],
                    max_fee_per_gas: Some(format!("0x{:x}", 142 * GWEI)),
                    max_priority_fee_per_gas: Some(format!("0x{:x}", 2 * GWEI)),
                    attempts: 21,
                    ..Default::default()
                },
            },
        );
        service.persist().unwrap();
        let error = service.poll_once().await.unwrap_err().to_string();
        assert!(error.contains("requires signer intervention"), "{error}");
        assert!(fixture.sends().is_empty());
        let status = service.status();
        assert_eq!(status.status, Severity::Critical);
        let detached = &status.detached_nonces[0];
        assert_eq!(detached.nonce, 3);
        assert!(!detached.mined);
        assert_eq!(detached.superseded_hashes, vec![refused_hash]);
        assert_eq!(detached.max_fee_per_gas_wei, Some((142 * GWEI).to_string()));
        assert_eq!(detached.gas_limit, None);
    }

    /// Review regression (node fee bound): a signer other than the bundled
    /// one can refuse with upstream_tx_fee_cap while reporting a zero gas
    /// limit or fee per gas. As with a zero signer cap, that zero is
    /// ignored: the refused send's own gas x maxFeePerGas is learned, so
    /// later refusals keep lowering the bid until the node accepts one, and
    /// the node-refusal warning shows.
    #[tokio::test]
    async fn refusal_reporting_a_zero_fee_still_lowers_the_bids() {
        let node_cap = ONE_ETHER / 2;
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.tx_fee_cap = Some((node_cap, "upstream_tx_fee_cap"));
            chain.estimate = 6_278_618;
            chain.base_fee = Some(10 * GWEI);
            chain.head_timestamp = chain.deadline - 9;
            chain.send_errors.push_back(json!({ "code": -32003,
                "message": "Upstream RPC refused the transaction fee",
                "data": { "reason": "upstream_tx_fee_cap", "gas_limit": "0x0", "max_fee_per_gas": "0x0" } }));
        }
        let mut service = fixture.service_with(mainnet_fees);
        assert!(service.poll_once().await.is_err());
        let sends = fixture.sends();
        let refused = fee(&sends[0], "gas") * fee(&sends[0], "maxFeePerGas");
        assert_eq!(service.node_refused_tx_fee, Some(refused));
        assert_eq!(
            service.status().sender.node_tx_fee_cap_bound_wei,
            Some(headroom(refused).to_string())
        );
        for _ in 0..5 {
            let _ = service.poll_once().await;
            fixture.chain.lock().unwrap().head_number += 1;
        }
        let sent = sent_tx_fees(&fixture, node_cap);
        let accepted = sent.iter().position(|(_, accepted)| *accepted);
        let accepted = accepted.unwrap_or_else(|| panic!("no bid was accepted: {sent:?}"));
        assert!(
            sent[..=accepted]
                .windows(2)
                .all(|pair| pair[1].0 <= headroom(pair[0].0)),
            "{sent:?}"
        );
        let status = service.status();
        assert_eq!(obligation(&status, 0).state, ObligationState::Submitted);
        assert!(status
            .config_warnings
            .iter()
            .any(|warning| warning.contains("upstream_tx_fee_cap")));
    }

    /// An escape of `note`, as the indexer's pending-escapes list names it.
    fn listed(note: u32, nullifier: Felt252, deadline: u64) -> Value {
        json!({ "note_id": note, "withdrawal_nullifier": nullifier, "challenge_deadline": deadline })
    }

    /// Review regression (pending-escapes backstop): a listed note whose
    /// vault record does not exist (a dead entry, which a lossy log source
    /// leaves in the indexer until a resync) stays due until reads
    /// DEAD_ESCAPE_CONFIRM_SECONDS apart find no escape, and each poll's
    /// reads resume where the previous poll's budget ran out. So 100 dead
    /// entries at low note IDs never starve a live escape listed after them:
    /// it is tracked within ceil(101 / 64) polls. Once confirmed, they are
    /// no longer read on every poll.
    #[tokio::test]
    async fn dead_listed_escapes_never_starve_a_live_one() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            // Only the indexer lists the live escape.
            chain.drop_logs = true;
            let (nullifier, deadline) = (chain.nullifier, chain.deadline);
            let mut escapes = Vec::new();
            for note in 0..100 {
                // Paid out or closed in the vault; the indexer missed it.
                chain.withdrawals.insert(note, (false, Felt252::ZERO, 0));
                escapes.push(listed(note, Felt252::from_u64(0x384), deadline));
            }
            chain.withdrawals.insert(500, (true, nullifier, deadline));
            escapes.push(listed(500, nullifier, deadline));
            chain.escapes = Some(escapes);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        // The budget ran out at note 64; the next poll starts there.
        assert_eq!(service.escape_cursor, 64);
        assert!(!service.checkpoint.pending.contains_key(&500));
        for _ in 1..101usize.div_ceil(MAX_ESCAPE_CHECKS_PER_POLL) {
            service.poll_once().await.unwrap();
        }
        assert!(
            service.checkpoint.pending.contains_key(&500),
            "the live escape was starved by dead entries"
        );
        assert_eq!(fixture.sends().len(), 1, "the live escape is challenged");
        assert_eq!(
            obligation(&service.status(), 500).state,
            ObligationState::Submitted
        );
        // Confirmed dead entries are not read again on every poll.
        for dead in service.dead_escapes.values_mut() {
            dead.first_seen -= DEAD_ESCAPE_CONFIRM_SECONDS;
        }
        let reads = |fixture: &Fixture| -> Vec<usize> {
            (0..100)
                .map(|note| fixture.withdrawal_reads(note))
                .collect()
        };
        let before = reads(&fixture);
        for _ in 0..3 {
            service.poll_once().await.unwrap();
        }
        assert_eq!(reads(&fixture), before);
    }

    /// Review regression (cursor): listed notes whose vault escape is live
    /// under another nullifier than listed (stale hints) are read on every
    /// listing, as the vault's escape is tracked for them. 70 of them at low
    /// note IDs never starve an untracked live escape listed after them:
    /// each poll's reads resume where the previous poll's budget ran out.
    #[tokio::test]
    async fn stale_hints_never_starve_a_live_escape() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            let (nullifier, deadline) = (chain.nullifier, chain.deadline);
            let mut escapes = Vec::new();
            for note in 0..70 {
                // The owner escaped again; the indexer lists the old escape.
                chain
                    .withdrawals
                    .insert(note, (true, Felt252::from_u64(78), deadline));
                escapes.push(listed(note, Felt252::from_u64(0x384), deadline));
            }
            chain.withdrawals.insert(500, (true, nullifier, deadline));
            escapes.push(listed(500, nullifier, deadline));
            chain.escapes = Some(escapes);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(service.escape_cursor, 64);
        assert_eq!(service.checkpoint.pending.len(), 64);
        service.poll_once().await.unwrap();
        assert!(
            service.checkpoint.pending.contains_key(&500),
            "the live escape was starved by stale hints"
        );
        assert!((0..70)
            .all(|note| service.checkpoint.pending[&note].nullifier == Felt252::from_u64(78)));
        // This poll read notes 64 to 69, note 500 and notes 0 to 56.
        assert_eq!(service.escape_cursor, 57);
        let detail = service
            .status()
            .indexer
            .pending_escapes_disagreement
            .unwrap();
        assert!(
            detail.starts_with("note 64 listed with nullifier 0x384"),
            "{detail}"
        );
    }

    /// Review regression (stale first read): this daemon's RPC can lag the
    /// indexer's head view, so a fresh escape the event scan missed can read
    /// as absent at first; and an indexer that missed a challenge and
    /// re-escape pair lists the ended escape's nullifier while the vault
    /// held none for a moment. Neither waits for the dead-entry back-off:
    /// both are read again at the next listing and tracked.
    #[tokio::test]
    async fn dead_entries_stay_due_until_confirmed() {
        let fixture = Fixture::new().await;
        let (nullifier, deadline) = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            let (nullifier, deadline) = (chain.nullifier, chain.deadline);
            chain.withdrawals.insert(500, (false, Felt252::ZERO, 0));
            chain.withdrawals.insert(7, (false, Felt252::ZERO, 0));
            chain.escapes = Some(vec![
                listed(7, Felt252::from_u64(0x384), deadline),
                listed(500, nullifier, deadline),
            ]);
            (nullifier, deadline)
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.is_empty());
        assert_eq!(service.dead_escapes.len(), 2);
        {
            let mut chain = fixture.chain.lock().unwrap();
            // This RPC now shows the escape, and the owner escaped again.
            chain.withdrawals.insert(500, (true, nullifier, deadline));
            chain
                .withdrawals
                .insert(7, (true, Felt252::from_u64(78), deadline + 5));
        }
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.pending[&500].nullifier, nullifier);
        assert_eq!(
            service.checkpoint.pending[&7].nullifier,
            Felt252::from_u64(78)
        );
        assert!(service.dead_escapes.is_empty());
        assert_eq!(fixture.sends().len(), 1, "the fresh escape is challenged");
        // Once confirmed, it rests between re-reads: a later re-escape is
        // tracked at the DEAD_ESCAPE_RECHECK_POLLS-th listing.
        fixture.chain.lock().unwrap().escapes =
            Some(vec![listed(9, Felt252::from_u64(0x384), deadline)]);
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .insert(9, (false, Felt252::ZERO, 0));
        service.poll_once().await.unwrap();
        service.dead_escapes.get_mut(&9).unwrap().first_seen -= DEAD_ESCAPE_CONFIRM_SECONDS;
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .insert(9, (true, Felt252::from_u64(79), deadline));
        for _ in 1..DEAD_ESCAPE_RECHECK_POLLS {
            service.poll_once().await.unwrap();
        }
        assert_eq!(fixture.withdrawal_reads(9), 1);
        assert!(!service.checkpoint.pending.contains_key(&9));
        service.poll_once().await.unwrap();
        assert_eq!(
            service.checkpoint.pending[&9].nullifier,
            Felt252::from_u64(79)
        );
    }

    /// A dead entry is reported under the indexer's
    /// pending_escapes_disagreement once reads --blocked-warning-seconds
    /// apart found no escape, so the "resync the indexer" alarm reaches the
    /// operator. The read that completes the period is made as soon as it is
    /// due, and no report goes out without it. The entry is then read again
    /// every DEAD_ESCAPE_RECHECK_POLLS listings, stays reported, and is
    /// forgotten once unlisted.
    #[tokio::test]
    async fn dead_listed_escape_is_reported_once_it_persists() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            chain.withdrawals.insert(1, (false, Felt252::ZERO, 0));
            let deadline = chain.deadline;
            chain.escapes = Some(vec![listed(1, Felt252::from_u64(0x384), deadline)]);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        // The list may only lag the vault: nothing is reported yet.
        let status = service.status();
        assert_eq!(status.indexer.pending_escapes_disagreement, None);
        assert_eq!(status.status, Severity::Ok, "{:?}", status.alarms);
        // Confirmed a minute after the first read, and the warning period
        // has passed since the first read: its report waits for a read.
        let warning = service.config.alarms.blocked_warning_seconds;
        {
            let dead = service.dead_escapes.get_mut(&1).unwrap();
            dead.first_seen -= warning;
            dead.last_seen -= warning - DEAD_ESCAPE_CONFIRM_SECONDS;
        }
        // A read that fails confirms nothing.
        fixture.chain.lock().unwrap().fail_note_one = true;
        service.poll_once().await.unwrap();
        assert_eq!(service.status().indexer.pending_escapes_disagreement, None);
        fixture.chain.lock().unwrap().fail_note_one = false;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.withdrawal_reads(1), 2);
        let reported = |service: &ChallengeService| {
            let status = service.status();
            let detail = status.indexer.pending_escapes_disagreement.clone().unwrap();
            assert!(
                detail.contains("note 1 listed with nullifier 0x384")
                    && detail.contains("no pending escape"),
                "{detail}"
            );
            assert!(
                status.alarms.iter().any(|alarm| alarm
                    .contains("pending-escapes list disagrees with the vault")
                    && alarm.contains("resync the indexer")),
                "{:?}",
                status.alarms
            );
            assert_eq!(status.status, Severity::Warning);
        };
        reported(&service);
        // Read again only every DEAD_ESCAPE_RECHECK_POLLS listings.
        for _ in 1..DEAD_ESCAPE_RECHECK_POLLS {
            service.poll_once().await.unwrap();
        }
        assert_eq!(fixture.withdrawal_reads(1), 2);
        reported(&service);
        service.poll_once().await.unwrap();
        assert_eq!(
            fixture.withdrawal_reads(1),
            3,
            "a dead entry is still read now and then"
        );
        reported(&service);
        // A resynced indexer no longer lists it.
        fixture.chain.lock().unwrap().escapes = Some(vec![]);
        service.poll_once().await.unwrap();
        assert!(service.dead_escapes.is_empty());
        assert_eq!(service.status().indexer.pending_escapes_disagreement, None);
    }

    /// Review regression (report without a confirming read): a dead entry
    /// whose warning period has passed since its first read is read before
    /// it is reported. Here the vault holds an escape by then, which is
    /// tracked; nothing is reported as missing from the vault.
    #[tokio::test]
    async fn a_dead_entry_found_live_at_its_report_read_is_tracked() {
        let fixture = Fixture::new().await;
        let (nullifier, deadline) = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            let (nullifier, deadline) = (chain.nullifier, chain.deadline);
            chain.withdrawals.insert(500, (false, Felt252::ZERO, 0));
            chain.escapes = Some(vec![listed(500, nullifier, deadline)]);
            (nullifier, deadline)
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let warning = service.config.alarms.blocked_warning_seconds;
        {
            let dead = service.dead_escapes.get_mut(&500).unwrap();
            dead.first_seen -= warning;
            dead.last_seen -= warning - DEAD_ESCAPE_CONFIRM_SECONDS;
        }
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .insert(500, (true, nullifier, deadline));
        service.poll_once().await.unwrap();
        assert!(service.checkpoint.pending.contains_key(&500));
        assert!(service.dead_escapes.is_empty());
        let status = service.status();
        assert_eq!(status.indexer.pending_escapes_disagreement, None);
        assert!(
            !status
                .alarms
                .iter()
                .any(|alarm| alarm.contains("no pending escape in the vault")),
            "{:?}",
            status.alarms
        );
    }

    /// Review regression (lag or loss): a list served at a block that may
    /// lie below a vault read that found no escape may only lag the vault,
    /// as the list of an indexer whose view stalled before a payout does
    /// (its root is unchanged, so its status stays consistent). However long
    /// reads keep finding no escape, that is not reported and asks for no
    /// resync, and neither is a list served at a block this daemon's RPC has
    /// not reached. Once a list served between two reads that found no
    /// escape still names the note, the indexer has processed a block in
    /// which the vault held none: it is reported at once.
    #[tokio::test]
    async fn a_lagging_list_is_reported_only_once_served_past_an_absent_read() {
        let fixture = Fixture::new().await;
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            // Paid out; the indexer's view is a block behind the head.
            chain.withdrawals.insert(1, (false, Felt252::ZERO, 0));
            let deadline = chain.deadline;
            chain.escapes = Some(vec![listed(1, Felt252::from_u64(0x384), deadline)]);
            chain.escapes_block = Some(chain.head_number - 1);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        // Confirmed, and the warning period has passed since the first read.
        let warning = service.config.alarms.blocked_warning_seconds;
        {
            let dead = service.dead_escapes.get_mut(&1).unwrap();
            dead.first_seen -= warning;
            dead.last_seen -= warning - DEAD_ESCAPE_CONFIRM_SECONDS;
        }
        let not_reported = |service: &ChallengeService| {
            let status = service.status();
            assert_eq!(status.indexer.pending_escapes_disagreement, None);
            assert_eq!(status.status, Severity::Ok, "{:?}", status.alarms);
        };
        // The first read ran at block 5 or above, which only the next poll's
        // head (8) bounds; the indexer's view stalls at block 6.
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.head_number = 8;
            chain.escapes_block = Some(6);
        }
        // The entry rests; its re-read spans the warning period.
        for _ in 0..DEAD_ESCAPE_RECHECK_POLLS {
            service.poll_once().await.unwrap();
            not_reported(&service);
        }
        assert_eq!(fixture.withdrawal_reads(1), 2);
        assert!(service.dead_escapes[&1].absent_for(warning));
        // A list served beyond this daemon's head may hold an escape its
        // RPC does not show yet.
        fixture.chain.lock().unwrap().escapes_block = Some(10);
        service.poll_once().await.unwrap();
        not_reported(&service);
        assert_eq!(fixture.withdrawal_reads(1), 2);
        // The RPC reaches that block, and the vault still holds no escape.
        fixture.chain.lock().unwrap().head_number = 10;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.withdrawal_reads(1), 3);
        let status = service.status();
        let detail = status.indexer.pending_escapes_disagreement.unwrap();
        assert!(
            detail.contains("note 1 listed with nullifier 0x384"),
            "{detail}"
        );
        assert!(
            status
                .alarms
                .iter()
                .any(|alarm| alarm.contains("no pending escape")
                    && alarm.contains("resync the indexer")),
            "{:?}",
            status.alarms
        );
        // Shown once, it stays reported while the note is listed, also after
        // a re-read in a listing served beyond this daemon's head.
        fixture.chain.lock().unwrap().escapes_block = Some(12);
        for _ in 0..DEAD_ESCAPE_RECHECK_POLLS {
            service.poll_once().await.unwrap();
        }
        assert_eq!(fixture.withdrawal_reads(1), 4);
        assert!(service
            .status()
            .indexer
            .pending_escapes_disagreement
            .is_some());
    }

    /// Review regression (relisted note): a confirmed dead entry rests only
    /// while its note is listed under the same nullifier. Once the indexer
    /// lists the note's live escape, which the event scan missed, the note
    /// is read at the next listing and tracked, without waiting for the
    /// DEAD_ESCAPE_RECHECK_POLLS back-off.
    #[tokio::test]
    async fn a_dead_entry_relisted_under_another_nullifier_is_read_at_once() {
        let fixture = Fixture::new().await;
        let deadline = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            chain.withdrawals.insert(9, (false, Felt252::ZERO, 0));
            let deadline = chain.deadline;
            chain.escapes = Some(vec![listed(9, Felt252::from_u64(0x384), deadline)]);
            deadline
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        service.dead_escapes.get_mut(&9).unwrap().first_seen -= DEAD_ESCAPE_CONFIRM_SECONDS;
        // Confirmed: it rests.
        service.poll_once().await.unwrap();
        assert_eq!(fixture.withdrawal_reads(9), 1);
        let renewed = Felt252::from_u64(0x4f);
        {
            let mut chain = fixture.chain.lock().unwrap();
            chain.withdrawals.insert(9, (true, renewed, deadline));
            chain.escapes = Some(vec![listed(9, renewed, deadline)]);
        }
        service.poll_once().await.unwrap();
        assert_eq!(service.checkpoint.pending[&9].nullifier, renewed);
        assert!(service.dead_escapes.is_empty());
    }

    /// Review regression: a note tracked under the vault's escape, while the
    /// indexer still lists an older nullifier the vault once held no escape
    /// for, is not reported as missing from the vault. Reconcile reads a
    /// tracked note every poll, so no dead entry is kept for it.
    #[tokio::test]
    async fn a_tracked_note_is_never_reported_as_dead() {
        let fixture = Fixture::new().await;
        let deadline = {
            let mut chain = fixture.chain.lock().unwrap();
            chain.drop_logs = true;
            chain.withdrawals.insert(7, (false, Felt252::ZERO, 0));
            let deadline = chain.deadline;
            chain.escapes = Some(vec![listed(7, Felt252::from_u64(0x384), deadline)]);
            deadline
        };
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let warning = service.config.alarms.blocked_warning_seconds;
        service.dead_escapes.get_mut(&7).unwrap().first_seen -= warning;
        // The event scan tracks the owner's new escape.
        let renewed = Felt252::from_u64(78);
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .insert(7, (true, renewed, deadline));
        service.checkpoint.pending.insert(
            7,
            PendingChallenge {
                nullifier: renewed,
                challenge_deadline: Some(deadline),
                ..Default::default()
            },
        );
        service.poll_once().await.unwrap();
        assert!(service.dead_escapes.is_empty());
        let detail = service
            .status()
            .indexer
            .pending_escapes_disagreement
            .unwrap();
        assert!(
            detail.contains("note 7 listed with nullifier 0x384")
                && detail.contains("the vault holds")
                && !detail.contains("no pending escape"),
            "{detail}"
        );
        // Its escape ends; it is retired, never kept as a dead entry while
        // tracked.
        fixture
            .chain
            .lock()
            .unwrap()
            .withdrawals
            .insert(7, (false, Felt252::ZERO, 0));
        service.poll_once().await.unwrap();
        assert!(service.dead_escapes.is_empty());
        assert!(!service.checkpoint.pending.contains_key(&7));
    }
}
