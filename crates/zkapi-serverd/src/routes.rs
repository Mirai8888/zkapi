//! Axum HTTP routes for the zkAPI server.
//!
//! Endpoints:
//! - GET  /health                   -- process health and config summary
//! - GET  /v1/attestation           -- published signer metadata for deployments
//! - POST /v2/openrouter/leases     -- open a prompt-private runtime-key lease
//! - POST /v2/openrouter/leases/:id -- retire a rejected runtime-key lease
//! - POST /v2/withdraw/clearance    -- request mutual-close clearance; requires
//!   an escape-form withdrawal proof of note ownership unless the transitional
//!   legacy flag is set
//! - GET  /v2/requests/:id          -- recover by client_request_id
//! - GET  /v2/nullifiers/:nullifier -- recover by nullifier
//! - GET  /v1/dashboard/settlement  -- operator-only pending leases and reviews

use std::convert::Infallible;
use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::Stream;
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};

use zkapi_types::wire::{
    ApiRequestV2, ClearanceRequest, ClearanceResponseV2, CurvePointWire, ErrorResponse,
    OpenRouterLeaseStatusResponse, RecoveryResponseV2,
};
use zkapi_types::Felt252;

use crate::config::ServerConfig;
use crate::dashboard::{
    DashboardEvent, DashboardHub, DashboardTotals, SettlementCounts, SettlementOverview,
};
use crate::error::ServerError;
use crate::native_billing::{vault_address_hex, NativeBillingOracle, VaultSigningKeys};
use crate::nullifier_store::{DeploymentBinding, KeySourceBacklog, NullifierStore};
use crate::oa_org::IssuedOpenRouterLease;
use crate::processor::RequestProcessor;
use crate::signer::ServerSigner;
use crate::testnet_auth::{
    handle_auth_check, require_testnet_password, TestnetPassword, TESTNET_PASSWORD_HEADER,
};

/// Shared application state.
type AppState = Arc<RequestProcessor>;

// Keep handler error variants small without changing their status, headers or body.
struct ErrorHttpResponse(Box<(StatusCode, HeaderMap, Json<ErrorResponse>)>);

impl IntoResponse for ErrorHttpResponse {
    fn into_response(self) -> Response {
        (*self.0).into_response()
    }
}

// Compact proofs are small; leave headroom for ordinary API payloads.
const PROTOCOL_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// Retry policy for reading the vault's immutable keys at startup.
#[derive(Clone, Copy, Debug)]
struct StartupRetry {
    attempts: u32,
    first_delay: Duration,
}

/// Five attempts with 1, 2, 4 and 8 s backoff; each RPC call keeps the
/// oracle's 15 s timeout. A wrong chain or a key mismatch is never retried.
const VAULT_BINDING_RETRY: StartupRetry = StartupRetry {
    attempts: 5,
    first_delay: Duration::from_secs(1),
};
/// Background re-verification of a recorded binding retries indefinitely.
const VAULT_REVERIFY_FIRST_DELAY: Duration = Duration::from_secs(1);
const VAULT_REVERIFY_MAX_DELAY: Duration = Duration::from_secs(60);

/// Start the HTTP server with the given config.
///
/// The signing seeds must pass the operator key policy, and their public keys
/// must equal the vault's immutable stateSigningKeyX/Y and
/// clearanceSigningKeyX/Y, read over the native billing RPC (which must serve
/// `chain_id`), before the database is opened for writes. The verified binding
/// is recorded in the database; a restart with a matching record starts
/// without the RPC and re-verifies in the background. The lease settlement
/// timing must then fit the vault's challengePeriod() (from that binding):
/// every possibly delivered lease reaches a signed transcript in time.
pub async fn run_server(config: ServerConfig) -> anyhow::Result<()> {
    run_server_with(config, VAULT_BINDING_RETRY).await
}

async fn run_server_with(mut config: ServerConfig, retry: StartupRetry) -> anyhow::Result<()> {
    if let Some(password) = TestnetPassword::from_env()? {
        config.testnet_password = Some(password);
    }
    config.validate_native_mode()?;
    let signer = Arc::new(
        ServerSigner::try_new(&config.state_seed, &config.clear_seed).context(
            "refusing to start: invalid signing seeds (ZKAPI_STATE_SEED / ZKAPI_CLEAR_SEED)",
        )?,
    );
    let (binding, binding_source) = establish_deployment_binding(&config, &signer, retry).await?;
    if let Some(lease) = config.openrouter_leases.as_ref() {
        lease.validate_settlement_timing(binding.challenge_period_seconds)?;
    }
    if config.allow_legacy_clearance {
        tracing::warn!(
            max_per_minute = config.legacy_clearance_max_per_minute,
            "--allow-legacy-clearance: clearance reserves nullifiers without a note ownership proof; disable after the migration window"
        );
    }
    let store = Arc::new(NullifierStore::new(&config.db_path)?);
    let initial_root = if let Some(indexer_url) = config.indexer_url.as_deref() {
        match fetch_indexer_root(indexer_url).await {
            Ok(root) => root,
            Err(err) => {
                tracing::warn!("failed to fetch initial root from indexer: {}", err);
                startup_root_from_vault(&config).await
            }
        }
    } else {
        config.initial_root
    };
    let dashboard = Arc::new(DashboardHub::new(500));
    let signing_keys = VaultSigningKeys {
        state: signer.state_public_key(),
        clearance: signer.clearance_public_key(),
    };
    let processor = Arc::new(
        RequestProcessor::try_new(config.clone(), store, signer, initial_root)?
            .with_dashboard(dashboard),
    );
    // Read while holding the writer lock, before anything is written.
    ensure_key_sources_drained(&config, processor.store())?;
    // Record a fresh verification only while holding the writer lock.
    if binding_source == BindingSource::VerifiedNow {
        processor.store().write_deployment_binding(&binding)?;
    }
    if let Some(indexer_url) = config.indexer_url.clone() {
        spawn_root_poller(
            processor.clone(),
            indexer_url,
            Duration::from_millis(config.root_poll_interval_ms),
        );
    }
    if let Some(lease) = config.openrouter_leases.as_ref() {
        spawn_openrouter_lease_settler(
            processor.clone(),
            Duration::from_secs(lease.settlement_poll_seconds.max(1)),
        );
    }
    let router = create_router(processor);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Server listening on {}", config.listen_addr);
    let serve = axum::serve(listener, router).into_future();
    if binding_source == BindingSource::Recorded {
        // Started without the RPC gate: stop serving, and so signing, if the
        // vault definitively contradicts the recorded binding.
        tokio::select! {
            result = serve => result?,
            Err(mismatch) = reverify_deployment_binding(&config, &binding, &signing_keys, VAULT_REVERIFY_FIRST_DELAY) => {
                return Err(mismatch);
            }
        }
    } else {
        serve.await?;
    }
    Ok(())
}

/// The vault's currentRoot() for a server whose indexer cannot serve a
/// verified root at startup (unverified, stale or replaying), instead of
/// --initial-root (0x0 by default), which would refuse every new request as
/// stale_root until the poller reads a verified root. Clearance already
/// accepts the same read; --initial-root remains the fallback.
async fn startup_root_from_vault(config: &ServerConfig) -> Felt252 {
    let read = async {
        anyhow::Ok(
            NativeBillingOracle::for_server(config)?
                .vault_current_root()
                .await?,
        )
    };
    match read.await {
        Ok(root) => {
            tracing::info!(
                root = %root,
                "starting with the vault's currentRoot() until the indexer serves a verified root"
            );
            root
        }
        Err(error) => {
            tracing::warn!(error = %error, "vault currentRoot() unavailable at startup; using --initial-root");
            config.initial_root
        }
    }
}

/// Whether the deployment binding was verified against the vault during this
/// startup or read from a previous successful verification in the database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindingSource {
    VerifiedNow,
    Recorded,
}

/// Bind this database to the vault's immutable keys before it is opened for
/// writes. A database bound to another deployment is refused without any RPC.
async fn establish_deployment_binding(
    config: &ServerConfig,
    signer: &ServerSigner,
    retry: StartupRetry,
) -> anyhow::Result<(DeploymentBinding, BindingSource)> {
    let contract_address = vault_address_hex(&config.contract_address);
    if let Some(recorded) = recorded_deployment_binding(&config.db_path) {
        anyhow::ensure!(
            recorded.chain_id == config.chain_id && recorded.contract_address == contract_address,
            "refusing to start: server database {} is bound to vault {} on chain {}, not vault {} on chain {}; use a separate database for each deployment",
            config.db_path,
            recorded.contract_address,
            recorded.chain_id,
            contract_address,
            config.chain_id
        );
        if recorded.state_signing_key == signer.state_public_key()
            && recorded.clearance_signing_key == signer.clearance_public_key()
        {
            tracing::info!(
                vault = %recorded.contract_address,
                chain_id = recorded.chain_id,
                verified_at = recorded.verified_at,
                "starting from the recorded vault signing-key binding; re-verifying in the background"
            );
            return Ok((recorded, BindingSource::Recorded));
        }
        tracing::warn!(
            "configured signing keys differ from the keys recorded for this vault; checking the vault"
        );
    }
    let binding = verify_vault_binding(config, signer, retry).await?;
    Ok((binding, BindingSource::VerifiedNow))
}

/// Read the binding of an existing database without opening it for writes.
/// One that cannot be read this way (an older schema, a hot journal) falls
/// back to the vault check rather than failing open.
fn recorded_deployment_binding(db_path: &str) -> Option<DeploymentBinding> {
    if !std::path::Path::new(db_path).is_file() {
        return None;
    }
    match NullifierStore::open_read_only(db_path).and_then(|store| store.read_deployment_binding())
    {
        Ok(binding) => binding,
        Err(error) => {
            tracing::warn!(error = %error, "cannot read the recorded deployment binding; checking the vault");
            None
        }
    }
}

struct VaultDeployment {
    keys: VaultSigningKeys,
    challenge_period_seconds: u64,
}

enum VaultReadError {
    WrongChain(u64),
    Unavailable(String),
}

/// eth_chainId, then the four immutable key getters and challengePeriod(),
/// all at "latest". Nothing else is read at startup.
async fn read_vault_deployment(
    oracle: &NativeBillingOracle,
    chain_id: u64,
) -> Result<VaultDeployment, VaultReadError> {
    // rpc() already maps failures to generic messages that never contain the URL.
    let unavailable = |error: ServerError| {
        VaultReadError::Unavailable(match error {
            ServerError::InvalidRequest(message) | ServerError::Internal(message) => message,
            other => other.to_string(),
        })
    };
    let served = oracle.rpc_chain_id().await.map_err(unavailable)?;
    if served != chain_id {
        return Err(VaultReadError::WrongChain(served));
    }
    Ok(VaultDeployment {
        keys: oracle.vault_signing_keys().await.map_err(unavailable)?,
        challenge_period_seconds: oracle.vault_challenge_period().await.map_err(unavailable)?,
    })
}

fn wrong_chain_message(served: u64, expected: u64) -> String {
    format!(
        "native billing RPC serves chain {served}, but --chain-id is {expected}; the vault signing-key check needs an RPC on the vault's chain"
    )
}

/// The startup gate for a database with no matching recorded binding.
async fn verify_vault_binding(
    config: &ServerConfig,
    signer: &ServerSigner,
    retry: StartupRetry,
) -> anyhow::Result<DeploymentBinding> {
    let oracle = NativeBillingOracle::for_server(config)?;
    let derived = VaultSigningKeys {
        state: signer.state_public_key(),
        clearance: signer.clearance_public_key(),
    };
    let mut delay = retry.first_delay;
    let mut attempt = 0;
    let vault = loop {
        attempt += 1;
        match read_vault_deployment(&oracle, config.chain_id).await {
            Ok(vault) => break vault,
            Err(VaultReadError::WrongChain(served)) => {
                anyhow::bail!(wrong_chain_message(served, config.chain_id))
            }
            Err(VaultReadError::Unavailable(error)) if attempt >= retry.attempts => {
                anyhow::bail!(
                    "could not read the vault's pinned signing keys over the native billing RPC after {attempt} attempts: {error}"
                )
            }
            Err(VaultReadError::Unavailable(error)) => {
                tracing::warn!(attempt, error = %error, "vault signing-key check failed; retrying");
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2);
            }
        }
    };
    ensure_vault_keys_match(config, &derived, &vault.keys)?;
    let contract_address = vault_address_hex(&config.contract_address);
    tracing::info!(
        vault = %contract_address,
        chain_id = config.chain_id,
        state_signing_key_x = %derived.state.x,
        state_signing_key_y = %derived.state.y,
        clearance_signing_key_x = %derived.clearance.x,
        clearance_signing_key_y = %derived.clearance.y,
        challenge_period_seconds = vault.challenge_period_seconds,
        "server signing keys match the vault's immutable keys"
    );
    Ok(DeploymentBinding {
        chain_id: config.chain_id,
        contract_address,
        state_signing_key: derived.state,
        clearance_signing_key: derived.clearance,
        challenge_period_seconds: vault.challenge_period_seconds,
        verified_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        verified_block: None,
    })
}

fn ensure_vault_keys_match(
    config: &ServerConfig,
    derived: &VaultSigningKeys,
    vault: &VaultSigningKeys,
) -> anyhow::Result<()> {
    if derived == vault {
        return Ok(());
    }
    let verdict = |matches: bool| if matches { "ok" } else { "MISMATCH" };
    let mut message = format!(
        "server signing keys do not match the vault's immutable keys (vault {}, chain {}): \
         state {} (vault x={},y={}; ZKAPI_STATE_SEED derives x={},y={}), \
         clearance {} (vault x={},y={}; ZKAPI_CLEAR_SEED derives x={},y={})",
        vault_address_hex(&config.contract_address),
        config.chain_id,
        verdict(vault.state == derived.state),
        vault.state.x,
        vault.state.y,
        derived.state.x,
        derived.state.y,
        verdict(vault.clearance == derived.clearance),
        vault.clearance.x,
        vault.clearance.y,
        derived.clearance.x,
        derived.clearance.y,
    );
    if vault.state == derived.clearance && vault.clearance == derived.state {
        message.push_str("; ZKAPI_STATE_SEED and ZKAPI_CLEAR_SEED appear swapped");
    }
    message.push_str(
        ". Use the seeds whose `zkapi signing-keys` output was passed to the vault constructor; vault keys cannot change without redeploying.",
    );
    anyhow::bail!(message)
}

/// Re-verify a recorded binding while serving. Unavailable or wrong-chain RPCs
/// cannot prove a mismatch and are retried indefinitely; only vault keys (or a
/// challenge period) that contradict the record, or the keys this server signs
/// with, end the server. Startup uses a record only for the keys it was
/// configured with; comparing the live keys too keeps a server from signing
/// under keys the vault never pinned should that check ever fail.
async fn reverify_deployment_binding(
    config: &ServerConfig,
    recorded: &DeploymentBinding,
    signing_keys: &VaultSigningKeys,
    first_delay: Duration,
) -> anyhow::Result<Infallible> {
    let oracle = NativeBillingOracle::for_server(config)?;
    let expected = VaultSigningKeys {
        state: recorded.state_signing_key.clone(),
        clearance: recorded.clearance_signing_key.clone(),
    };
    let mut delay = first_delay;
    loop {
        match read_vault_deployment(&oracle, config.chain_id).await {
            Ok(vault) => {
                let outcome = ensure_vault_keys_match(config, signing_keys, &vault.keys)
                    .and_then(|()| ensure_vault_keys_match(config, &expected, &vault.keys))
                    .and_then(|()| {
                    anyhow::ensure!(
                        vault.challenge_period_seconds == recorded.challenge_period_seconds,
                        "vault challengePeriod() is {} s, but this database recorded {} s for vault {}",
                        vault.challenge_period_seconds,
                        recorded.challenge_period_seconds,
                        recorded.contract_address
                    );
                    Ok(())
                });
                if let Err(mismatch) = outcome {
                    tracing::error!(
                        error = %mismatch,
                        "the vault contradicts this database's recorded deployment binding; shutting down instead of signing"
                    );
                    return Err(mismatch);
                }
                tracing::info!(
                    vault = %recorded.contract_address,
                    chain_id = recorded.chain_id,
                    "re-verified the recorded vault signing-key binding"
                );
                return std::future::pending().await;
            }
            Err(VaultReadError::WrongChain(served)) => {
                tracing::error!(
                    "{}; signing continues under the recorded binding",
                    wrong_chain_message(served, config.chain_id)
                );
            }
            Err(VaultReadError::Unavailable(error)) => {
                tracing::warn!(error = %error, "vault signing-key re-verification failed; retrying");
            }
        }
        tokio::time::sleep(delay).await;
        delay = delay.saturating_mul(2).min(VAULT_REVERIFY_MAX_DELAY);
    }
}

/// How an operator configures each lease key source.
fn key_source_setting(source: &str) -> &'static str {
    match source {
        "openrouter" => {
            "direct OpenRouter: ZKAPI_OPENROUTER_MANAGEMENT_KEY or --openrouter-management-key"
        }
        "oa_org" => "OA org: --oa-org-url with ZKAPI_OA_ORG_SHARED_SECRET",
        _ => "unknown",
    }
}

/// Only the key source that issued a lease can measure its usage, and only
/// the direct source deletes direct keys. Refuse to start while the database
/// holds, of a known key source other than the configured one, leases that
/// only that source can settle (possibly delivered, with no committed charge,
/// before their settlement deadline) or queued deletions of its direct keys
/// that may still be usable: each such lease would be finalized at its
/// settlement deadline without a usage measurement, and those keys would stay
/// usable until they expire. A lease's issuer is its key source and the
/// identity recorded at activation (the OA org URL or the OpenRouter API
/// base), so another org or API base counts as another source. A lease
/// activated by an earlier release records none: it is taken as the
/// configured issuer's when its key source matches, unless the database
/// holds such rows recorded under another issuer of that key source, which
/// has then been running since the upgrade and is taken to own them too (a
/// start under that issuer takes them as its own, so the two answers agree).
/// Rows any configuration finalizes without provider I/O (never delivered,
/// committed to a zero or conceded charge, past their settlement deadline) do
/// not count, nor do rows of a source this release does not know, which it
/// never settles or charges (so a rollback stays safe).
/// `allow_key_source_switch` accepts those charges and starts: for a database
/// that holds such rows of two or more issuers, which no single credential
/// can drain, or an issuer that can no longer be reached.
fn ensure_key_sources_drained(config: &ServerConfig, store: &NullifierStore) -> anyhow::Result<()> {
    let Some(lease) = config.openrouter_leases.as_ref() else {
        return Ok(());
    };
    let configured = lease.source.label();
    let identity = lease.source.identity();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let backlog = store.key_source_backlog(now)?;
    // Deletions count only for direct OpenRouter, the only source that
    // deletes keys.
    let deletions = |source: &str, backlog: &KeySourceBacklog| {
        if source == "openrouter" {
            backlog.queued_key_deletions
        } else {
            0
        }
    };
    let needs_issuer = |source: &str, backlog: &KeySourceBacklog| {
        matches!(source, "openrouter" | "oa_org")
            && (backlog.unsettled_leases > 0 || deletions(source, backlog) > 0)
    };
    let another_issuer_of_this_source = backlog.iter().any(|((source, recorded), backlog)| {
        source == configured
            && recorded
                .as_deref()
                .is_some_and(|recorded| recorded != identity)
            && needs_issuer(source, backlog)
    });
    let configured_issuer = |source: &str, recorded: &Option<String>| {
        source == configured
            && match recorded.as_deref() {
                Some(recorded) => recorded == identity,
                None => !another_issuer_of_this_source,
            }
    };
    let (mut own_recorded, mut own_unrecorded, mut own_deletions) = (0u64, 0u64, 0u64);
    for ((source, recorded), backlog) in &backlog {
        if configured_issuer(source, recorded) {
            if recorded.is_some() {
                own_recorded += backlog.unsettled_leases;
            } else {
                own_unrecorded += backlog.unsettled_leases;
            }
            own_deletions += deletions(source, backlog);
        }
    }
    let stranded: Vec<_> = backlog
        .iter()
        .filter(|((source, recorded), backlog)| {
            !configured_issuer(source, recorded) && needs_issuer(source, backlog)
        })
        .collect();
    if stranded.is_empty() {
        if config.allow_key_source_switch {
            tracing::info!(
                "--allow-key-source-switch is set, but no other key source has leases to settle; remove it"
            );
        }
        return Ok(());
    }
    // Rows recording no issuer are taken as those of the other issuer of
    // their key source when there is one, so they add no issuer of their own.
    let recorded_sources: std::collections::BTreeSet<&str> = stranded
        .iter()
        .filter(|((_, recorded), _)| recorded.is_some())
        .map(|((source, _), _)| source.as_str())
        .collect();
    let issuers = stranded
        .iter()
        .filter(|((source, recorded), _)| {
            recorded.is_some() || !recorded_sources.contains(source.as_str())
        })
        .count()
        + usize::from(own_recorded + own_unrecorded + own_deletions > 0);
    let stranded: Vec<String> = stranded
        .into_iter()
        .map(|((source, recorded), backlog)| {
            let issuer = match recorded {
                Some(recorded) => format!(" issued through {recorded}"),
                None => " activated before this release, recording no issuer".to_string(),
            };
            format!(
                "{} unsettled lease(s) and {} queued key deletion(s) of key source '{source}'{issuer} ({})",
                backlog.unsettled_leases,
                deletions(source, backlog),
                key_source_setting(source)
            )
        })
        .collect();
    if config.allow_key_source_switch {
        tracing::warn!(
            configured,
            stranded = %stranded.join("; "),
            "--allow-key-source-switch: starting although this key source can neither measure nor delete these; each such lease will be finalized at its settlement deadline without a usage measurement (normally at its full solvency bound). Remove the flag once they are settled."
        );
        return Ok(());
    }
    let remedy = if issuers > 1 {
        let own = own_recorded + own_unrecorded;
        let held = if own + own_deletions == 0 {
            format!("These belong to {issuers} issuers")
        } else {
            let rows = [
                (own > 0).then(|| format!("{own} such lease(s)")),
                (own_deletions > 0).then(|| format!("{own_deletions} queued key deletion(s)")),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" and ");
            let unrecorded = if own_unrecorded > 0 {
                format!(
                    " ({own_unrecorded} of these lease(s), activated before this release, record no issuer and are taken as its own)"
                )
            } else {
                String::new()
            };
            format!("It also holds {rows} of '{configured}' issued through {identity}{unrecorded}")
        };
        let (tell, order) = if issuers == 2 {
            (
                "a start under the other without the flag refuses while any remain",
                "and then restart under the other without the flag, before its remaining leases reach their deadlines",
            )
        } else {
            (
                "a start under another one without the flag lists them while any remain",
                "and repeat under each of the others in turn, starting the last one without the flag, before their remaining leases reach their deadlines",
            )
        };
        format!(
            "{held}, so no single credential can drain it: start under one of them with --allow-key-source-switch (ZKAPI_ALLOW_KEY_SOURCE_SWITCH=true), stop routing new requests to the server, wait until that one's leases are settled ({tell}), {order}."
        )
    } else {
        "Drain the previous key source first: restart with its credential and URL, stop routing new requests to the server, and wait until GET /v1/dashboard/settlement reports counts.pending 0 (and, for 'openrouter', counts.pending_key_cleanups 0); then switch. If that source can no longer be reached, or still serves those leases at a new URL, start with --allow-key-source-switch (ZKAPI_ALLOW_KEY_SOURCE_SWITCH=true), and remove it once they are settled.".to_string()
    };
    anyhow::bail!(
        "refusing to start: server database {} holds {}, but this server is configured for key source '{configured}' at {identity} ({}), which can neither measure nor delete them: each such lease (possibly delivered, with no committed charge) would be finalized at its settlement deadline without a usage measurement, normally at its full solvency bound. {remedy} See docs/native-eth-billing.md, \"Changing the key source\".",
        config.db_path,
        stranded.join("; "),
        key_source_setting(configured)
    );
}

/// Create the Axum router with all zkAPI server routes.
pub fn create_router(processor: Arc<RequestProcessor>) -> Router {
    let password = processor.config().testnet_password.clone();
    // Preserve the local dashboard's existing CORS policy. Password-gated
    // Sepolia additionally permits explicit credential headers below.
    let dashboard = Router::new()
        .route("/v1/dashboard/summary", get(handle_dashboard_summary))
        .route("/v1/dashboard/recent", get(handle_dashboard_recent))
        .route("/v1/dashboard/events", get(handle_dashboard_events))
        .route("/v1/dashboard/settlement", get(handle_dashboard_settlement))
        .layer(CorsLayer::very_permissive());

    let router = Router::new()
        .route("/", get(handle_health))
        .route("/health", get(handle_health))
        .route("/v1/attestation", get(handle_attestation))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::HEAD]),
        )
        .route("/v2/auth", get(handle_auth_check))
        .route("/v2/billing/quote", get(handle_native_billing_quote))
        .route("/v2/openrouter/leases", post(handle_openrouter_lease))
        .route(
            "/v2/openrouter/leases/{client_request_id}",
            get(handle_openrouter_lease_status).post(handle_openrouter_lease_retirement),
        )
        .route(
            "/v2/openrouter/leases/{client_request_id}/expire",
            post(handle_native_lease_expiry),
        )
        .route("/v2/withdraw/clearance", post(handle_clearance))
        .route(
            "/v2/requests/{client_request_id}",
            get(handle_recovery_by_id),
        )
        .route(
            "/v2/nullifiers/{nullifier}",
            get(handle_recovery_by_nullifier),
        )
        .merge(dashboard)
        .layer(DefaultBodyLimit::max(PROTOCOL_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn_with_state(
            password.clone(),
            require_testnet_password,
        ))
        .with_state(processor);

    if password.is_some() {
        // The shared password is not an account cookie; no credentialed CORS.
        router.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::HEAD, Method::POST, Method::OPTIONS])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderName::from_static(TESTNET_PASSWORD_HEADER),
                ]),
        )
    } else {
        router
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    protocol_version: u16,
    chain_id: u64,
    contract_address: Felt252,
    current_root: Felt252,
    provider: &'static str,
    indexer_url: Option<String>,
    policy_enabled: bool,
    auth_scheme: &'static str,
    request_modes: Vec<&'static str>,
    testnet_password_required: bool,
    /// POST /v2/withdraw/clearance requires `ownership_proof`.
    clearance_ownership_proof_required: bool,
    /// New proof-less clearances admitted this minute.
    legacy_clearance_window_used: u32,
    /// Their per-minute limit, shared by every caller; 0 while legacy
    /// clearance is off.
    legacy_clearance_window_limit: u32,
    /// Proof-less clearances refused by that limit since the process started.
    legacy_clearance_rejected_total: u64,
}

#[derive(Debug, Serialize)]
struct AttestationResponse {
    status: &'static str,
    protocol_version: u16,
    chain_id: u64,
    contract_address: Felt252,
    current_root: Felt252,
    state_signing_key: CurvePointWire,
    clearance_signing_key: CurvePointWire,
    auth_scheme: &'static str,
}

async fn handle_health(State(processor): State<AppState>) -> Json<HealthResponse> {
    let config = processor.config();
    let legacy = processor.legacy_clearance_usage();
    Json(HealthResponse {
        status: "ok",
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        current_root: processor.current_root(),
        provider: "native_leases",
        indexer_url: config.indexer_url.clone(),
        policy_enabled: false,
        auth_scheme: "state-anchor",
        request_modes: vec!["direct_openrouter"],
        testnet_password_required: config.testnet_password.is_some(),
        clearance_ownership_proof_required: !config.allow_legacy_clearance,
        legacy_clearance_window_used: legacy.window_used,
        legacy_clearance_window_limit: legacy.window_limit,
        legacy_clearance_rejected_total: legacy.rejected_total,
    })
}

async fn handle_attestation(State(processor): State<AppState>) -> Json<AttestationResponse> {
    let config = processor.config();
    Json(AttestationResponse {
        status: "ok",
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        current_root: processor.current_root(),
        state_signing_key: processor.state_signing_key(),
        clearance_signing_key: processor.clearance_signing_key(),
        auth_scheme: "state-anchor",
    })
}

async fn handle_openrouter_lease(
    State(processor): State<AppState>,
    Json(api_request): Json<ApiRequestV2>,
) -> Result<(StatusCode, Json<IssuedOpenRouterLease>), ErrorHttpResponse> {
    processor
        .issue_openrouter_lease(&api_request)
        .await
        .map(|response| (StatusCode::CREATED, Json(response)))
        .map_err(|error| error_to_response(&error, &api_request.client_request_id, &processor))
}

/// 404 for a lease the store does not hold, and (with error_code
/// lease_record_unreadable, not retriable) for a lease row it cannot decode:
/// either way GET /v2/nullifiers/{request_nullifier} is authoritative. A
/// store that cannot be read is a retriable 500 database_error.
async fn handle_openrouter_lease_status(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
) -> Response {
    match processor.openrouter_lease_status(&client_request_id) {
        Ok(Some(status)) => Json::<OpenRouterLeaseStatusResponse>(status).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => error_to_response(&error, &client_request_id, &processor).into_response(),
    }
}

async fn handle_openrouter_lease_retirement(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
    Json(api_request): Json<ApiRequestV2>,
) -> Result<Json<OpenRouterLeaseStatusResponse>, ErrorHttpResponse> {
    processor
        .retire_openrouter_lease(&client_request_id, &api_request)
        .await
        .map(Json)
        .map_err(|error| error_to_response(&error, &client_request_id, &processor))
}

/// POST /v2/withdraw/clearance -- request a clearance signature.
async fn handle_clearance(
    State(processor): State<AppState>,
    Json(clearance_req): Json<ClearanceRequest>,
) -> Result<Json<ClearanceResponseV2>, ErrorHttpResponse> {
    processor
        .process_clearance(&clearance_req)
        .await
        .map(Json)
        .map_err(|e| {
            error_to_response(&e, &clearance_req.withdrawal_nullifier.to_hex(), &processor)
        })
}

/// GET /v1/requests/:client_request_id -- recover a response by client request ID.
async fn handle_recovery_by_id(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
) -> Result<Json<RecoveryResponseV2>, ErrorHttpResponse> {
    processor
        .recover_by_client_id(&client_request_id)
        .map(Json)
        .map_err(|e| error_to_response(&e, &client_request_id, &processor))
}

/// GET /v1/nullifiers/:nullifier -- recover a response by nullifier hex.
async fn handle_recovery_by_nullifier(
    State(processor): State<AppState>,
    Path(nullifier_hex): Path<String>,
) -> Result<Json<RecoveryResponseV2>, ErrorHttpResponse> {
    let nullifier = Felt252::from_hex(&nullifier_hex).map_err(|e| {
        let err = ServerError::InvalidRequest(format!("invalid nullifier hex: {}", e));
        error_to_response(&err, &nullifier_hex, &processor)
    })?;

    processor
        .recover_by_nullifier(&nullifier)
        .map(Json)
        .map_err(|e| error_to_response(&e, &nullifier_hex, &processor))
}

async fn handle_native_lease_expiry(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
    Json(request): Json<ApiRequestV2>,
) -> Result<(HeaderMap, Json<serde_json::Value>), ErrorHttpResponse> {
    let status = processor
        .expire_unaccepted_native_lease(&client_request_id, &request)
        .await
        .map_err(|error| error_to_response(&error, &client_request_id, &processor))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok((headers, Json(status)))
}

async fn handle_native_billing_quote(
    State(processor): State<AppState>,
) -> Result<(HeaderMap, Json<crate::native_billing::NativeBillingQuote>), ErrorHttpResponse> {
    let quote = processor
        .native_billing_quote()
        .await
        .map_err(|error| error_to_response(&error, "billing-quote", &processor))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok((headers, Json(quote)))
}

/// Server identity + signing capacity for the dashboard header panel.
#[derive(Debug, Serialize)]
struct ServerIdentity {
    protocol_version: u16,
    chain_id: u64,
    contract_address: Felt252,
    current_root: Felt252,
    provider: &'static str,
    upstream_kind: Option<String>,
    upstream_api_base: Option<String>,
    auth_scheme: &'static str,
    policy_enabled: bool,
    request_charge_cap: u128,
    request_charge_cap_usd: Option<f64>,
    credits_per_usd: Option<f64>,
    billing_asset: &'static str,
    state_signing_key: CurvePointWire,
    clearance_signing_key: CurvePointWire,
    openrouter_leases_enabled: bool,
}

#[derive(Debug, Serialize)]
struct DashboardSummary {
    server: ServerIdentity,
    totals: DashboardTotals,
    started_ms: u64,
    recent_count: usize,
    /// None when the settlement counts cannot be read.
    settlement: Option<SettlementCounts>,
}

/// GET /v1/dashboard/summary -- server identity + running totals.
async fn handle_dashboard_summary(State(processor): State<AppState>) -> Json<DashboardSummary> {
    let config = processor.config();
    let (upstream_kind, upstream_api_base) = config
        .openrouter_leases
        .as_ref()
        .map(|lease| match &lease.source {
            crate::config::OpenRouterLeaseSourceConfig::OpenRouter { api_base, .. } => {
                (Some("openrouter".to_string()), Some(api_base.clone()))
            }
            crate::config::OpenRouterLeaseSourceConfig::OaOrg { org_base_url, .. } => {
                (Some("oa_org".to_string()), Some(org_base_url.clone()))
            }
        })
        .unwrap_or_default();
    let server = ServerIdentity {
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        current_root: processor.current_root(),
        provider: "native_leases",
        upstream_kind,
        upstream_api_base,
        auth_scheme: "state-anchor",
        policy_enabled: false,
        request_charge_cap: config.request_charge_cap,
        request_charge_cap_usd: None,
        credits_per_usd: None,
        billing_asset: "native_eth",
        state_signing_key: processor.state_signing_key(),
        clearance_signing_key: processor.clearance_signing_key(),
        openrouter_leases_enabled: processor.openrouter_leases_enabled(),
    };
    let (totals, started_ms, recent_count) = match processor.dashboard() {
        Some(hub) => (hub.totals(), hub.started_ms, hub.recent().len()),
        None => (DashboardTotals::default(), 0, 0),
    };
    let settlement = processor
        .settlement_counts()
        .map_err(|error| tracing::warn!(error = %error, "settlement counts unavailable"))
        .ok();
    Json(DashboardSummary {
        server,
        totals,
        started_ms,
        recent_count,
        settlement,
    })
}

#[derive(serde::Deserialize)]
struct SettlementQuery {
    limit: Option<usize>,
}

/// GET /v1/dashboard/settlement -- pending leases, deadlines and reviews.
/// Operator-only: the production gateway does not proxy /v1/dashboard/*.
async fn handle_dashboard_settlement(
    State(processor): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<SettlementQuery>,
) -> Result<Json<SettlementOverview>, ErrorHttpResponse> {
    let limit = query.limit.unwrap_or(200).clamp(1, 1_000);
    processor
        .settlement_overview(limit)
        .map(Json)
        .map_err(|error| error_to_response(&error, "settlement", &processor))
}

/// GET /v1/dashboard/recent -- the recent request feed (newest last).
async fn handle_dashboard_recent(State(processor): State<AppState>) -> Json<Vec<DashboardEvent>> {
    let events = processor
        .dashboard()
        .map(|hub| hub.recent())
        .unwrap_or_default();
    Json(events)
}

/// GET /v1/dashboard/events -- Server-Sent-Events stream of live requests.
async fn handle_dashboard_events(
    State(processor): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = processor.dashboard().map(|hub| hub.subscribe());
    let stream = futures_util::stream::unfold(rx, |state| async move {
        let mut rx = state?;
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let data = serde_json::to_string(&event).unwrap_or_default();
                    let sse = Event::default().event("request").data(data);
                    return Some((Ok(sse), Some(rx)));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Convert a ServerError into an HTTP error response.
fn error_to_response(
    err: &ServerError,
    client_request_id: &str,
    processor: &RequestProcessor,
) -> ErrorHttpResponse {
    // A clearance StaleRoot carries the vault root it read; report that,
    // not this server's possibly lagging indexer root.
    let latest_root = match err {
        ServerError::StaleRoot { latest_root } => {
            Some(Felt252::from_hex(latest_root).unwrap_or_else(|_| processor.current_root()))
        }
        _ => None,
    };
    ErrorHttpResponse(Box::new(build_error_response(
        err,
        client_request_id,
        latest_root,
    )))
}

fn build_error_response(
    err: &ServerError,
    client_request_id: &str,
    latest_root: Option<Felt252>,
) -> (StatusCode, HeaderMap, Json<ErrorResponse>) {
    let status_code = match err {
        ServerError::InvalidProof(_)
        | ServerError::InvalidRequest(_)
        | ServerError::OaKeyPolicyRejected
        | ServerError::ClearanceOwnershipRequired
        | ServerError::ProtocolMismatch(_) => StatusCode::BAD_REQUEST,
        ServerError::StaleRoot { .. }
        | ServerError::NativeQuoteExpired
        | ServerError::NativeQuoteSuperseded => StatusCode::CONFLICT,
        ServerError::Replay | ServerError::NullifierUsed => StatusCode::CONFLICT,
        ServerError::LeasePending | ServerError::LeaseSettlementPending { .. } => {
            StatusCode::CONFLICT
        }
        ServerError::NoteExpired => StatusCode::GONE,
        // Like an unknown lease, it sends clients to the authoritative
        // nullifier record (GET /v2/nullifiers/{request_nullifier}).
        ServerError::LeaseRecordUnreadable => StatusCode::NOT_FOUND,
        ServerError::CapacityExhausted | ServerError::LegacyClearanceCapacity { .. } => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        ServerError::Internal(_) | ServerError::Database(_) | ServerError::Unsettleable(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        ServerError::OaRateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
    };

    let retry_after_seconds = match err {
        ServerError::OaRateLimited {
            retry_after_seconds,
            ..
        }
        | ServerError::LeaseSettlementPending {
            retry_after_seconds,
        }
        | ServerError::LegacyClearanceCapacity {
            retry_after_seconds,
        } => Some(*retry_after_seconds),
        _ => None,
    };
    let mut headers = HeaderMap::new();
    if let Some(retry_after_seconds) = retry_after_seconds {
        let retry_after = HeaderValue::from_str(&retry_after_seconds.to_string())
            .expect("a decimal u64 is always a valid Retry-After header");
        headers.insert(RETRY_AFTER, retry_after);
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let body = ErrorResponse {
        status: "error".to_string(),
        client_request_id: client_request_id.to_string(),
        error_code: err.error_code().to_string(),
        error_message: err.to_string(),
        retriable: err.is_retriable(),
        latest_root,
        server_time_ms: Some(now_ms),
        retry_after_seconds,
    };

    (status_code, headers, Json(body))
}

fn spawn_openrouter_lease_settler(processor: Arc<RequestProcessor>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            processor.settle_due_openrouter_leases().await;
        }
    });
}

fn spawn_root_poller(processor: Arc<RequestProcessor>, indexer_url: String, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            match fetch_indexer_root(&indexer_url).await {
                Ok(root) => processor.update_root(root),
                Err(err) => tracing::warn!("failed to refresh root from indexer: {}", err),
            }
        }
    });
}

async fn fetch_indexer_root(indexer_url: &str) -> anyhow::Result<Felt252> {
    #[derive(serde::Deserialize)]
    struct RootResponse {
        root: Felt252,
    }

    let base = indexer_url.trim_end_matches('/');
    let url = format!("{base}/v1/tree/root");
    let response = reqwest::get(&url).await?;
    let response = response.error_for_status()?;
    Ok(response.json::<RootResponse>().await?.root)
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;

    #[tokio::test]
    async fn startup_requires_native_billing_before_opening_database() {
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("must-not-exist.db");
        let config = crate::config::ServerConfig {
            db_path: db_path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let error = run_server(config).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("native ETH billing configuration is required"));
        assert!(!db_path.exists());
    }

    #[tokio::test]
    async fn compact_http_errors_preserve_status_headers_and_json() {
        for error in [
            ServerError::OaRateLimited {
                reason: "oa_hourly_issuance_budget".to_string(),
                retry_after_seconds: 37,
            },
            ServerError::LeaseSettlementPending {
                retry_after_seconds: 15,
            },
            ServerError::InvalidRequest("invalid request".to_string()),
        ] {
            let (status, headers, Json(body)) =
                build_error_response(&error, "lease-request-123", None);
            let expected_headers = headers.clone();
            let expected_body = serde_json::to_value(&body).unwrap();
            let response =
                ErrorHttpResponse(Box::new((status, headers, Json(body)))).into_response();

            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get(RETRY_AFTER),
                expected_headers.get(RETRY_AFTER)
            );
            assert_eq!(response.headers()["content-type"], "application/json");
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let actual_body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(actual_body, expected_body);
        }
    }

    #[test]
    fn oa_rate_limit_maps_to_retriable_429_with_retry_metadata() {
        let error = ServerError::OaRateLimited {
            reason: "oa_hourly_issuance_budget".to_string(),
            retry_after_seconds: 37,
        };

        let (status, headers, Json(response)) =
            build_error_response(&error, "lease-request-123", None);

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "37");
        assert_eq!(response.error_code, "oa_hourly_issuance_budget");
        assert!(response.retriable);
        assert_eq!(response.retry_after_seconds, Some(37));

        let serialized = serde_json::to_value(response).unwrap();
        assert_eq!(serialized["retry_after_seconds"], 37);
        assert_eq!(serialized["error_code"], "oa_hourly_issuance_budget");
    }

    #[test]
    fn new_error_codes_map_to_http() {
        for (error, status, code, retriable) in [
            (
                ServerError::ClearanceOwnershipRequired,
                StatusCode::BAD_REQUEST,
                "clearance_ownership_required",
                false,
            ),
            (
                ServerError::Unsettleable("corrupt quote".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "lease_unsettleable",
                false,
            ),
            (
                ServerError::CapacityExhausted,
                StatusCode::SERVICE_UNAVAILABLE,
                "capacity_exhausted",
                true,
            ),
        ] {
            let (actual, _, Json(body)) = build_error_response(&error, "clearance", None);
            assert_eq!(actual, status, "{code}");
            assert_eq!(body.error_code, code);
            assert_eq!(body.retriable, retriable, "{code}");
        }
    }

    #[test]
    fn legacy_clearance_capacity_is_a_distinct_503_with_retry_after() {
        let error = ServerError::LegacyClearanceCapacity {
            retry_after_seconds: 42,
        };
        let (status, headers, Json(body)) = build_error_response(&error, "clearance", None);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "42");
        assert_eq!(body.error_code, "legacy_clearance_capacity");
        assert!(body.retriable);
        assert_eq!(body.retry_after_seconds, Some(42));
        // Verification saturation keeps its own code.
        let (status, headers, Json(body)) =
            build_error_response(&ServerError::CapacityExhausted, "clearance", None);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(headers.get(RETRY_AFTER).is_none());
        assert_eq!(body.error_code, "capacity_exhausted");
    }

    #[test]
    fn stale_root_errors_report_the_root_carried_by_the_error() {
        let processor = crate::routes::settlement_route_tests::processor(false);
        processor.update_root(Felt252::from_u64(5));
        let vault_root = Felt252::from_u64(0x7007);
        let ErrorHttpResponse(response) = error_to_response(
            &ServerError::StaleRoot {
                latest_root: vault_root.to_hex(),
            },
            "clearance",
            &processor,
        );
        let (status, _, Json(body)) = *response;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.error_code, "stale_root");
        assert!(body.retriable);
        assert_eq!(body.latest_root, Some(vault_root));
    }

    #[test]
    fn lease_settlement_pending_maps_to_retriable_409_with_retry_metadata() {
        let error = ServerError::LeaseSettlementPending {
            retry_after_seconds: 15,
        };

        let (status, headers, Json(response)) =
            build_error_response(&error, "lease-request-123", None);

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "15");
        assert_eq!(response.error_code, "lease_settlement_pending");
        assert!(response.retriable);
        assert_eq!(response.retry_after_seconds, Some(15));
    }
}

#[cfg(test)]
mod startup_tests {
    use super::*;
    use crate::native_billing::{
        NativeBillingConfig, CHALLENGE_PERIOD_SELECTOR, CLEARANCE_SIGNING_KEY_X_SELECTOR,
        CLEARANCE_SIGNING_KEY_Y_SELECTOR, CURRENT_ROOT_SELECTOR, STATE_SIGNING_KEY_X_SELECTOR,
        STATE_SIGNING_KEY_Y_SELECTOR,
    };
    use crate::signer::strong_test_seeds;
    use serde_json::{json, Value};
    use std::sync::Mutex;
    use tokio::sync::Semaphore;

    const TEST_RETRY: StartupRetry = StartupRetry {
        attempts: 3,
        first_delay: Duration::from_millis(1),
    };
    const KEY_READS: [&str; 5] = [
        STATE_SIGNING_KEY_X_SELECTOR,
        STATE_SIGNING_KEY_Y_SELECTOR,
        CLEARANCE_SIGNING_KEY_X_SELECTOR,
        CLEARANCE_SIGNING_KEY_Y_SELECTOR,
        CHALLENGE_PERIOD_SELECTOR,
    ];

    /// Independent strong seeds for a vault the configured seeds do not match.
    fn other_strong_seeds() -> (Felt252, Felt252) {
        (
            Felt252::from_hex("0x2c9e7a5b3d1f8e6c4a2b0d9f7e5c3a1b8d6f4e2c0a9b7d5e3f1c8a6b4d2e0f")
                .unwrap(),
            Felt252::from_hex("0x47b2e9d6c3a0f7e4b1d8c5a2f9e6b3d0c7a4f1e8b5d2c9a6f3e0b7d4c1a8e5")
                .unwrap(),
        )
    }

    fn keys_of((state, clearance): (Felt252, Felt252)) -> VaultSigningKeys {
        let signer = ServerSigner::try_new(&state, &clearance).unwrap();
        VaultSigningKeys {
            state: signer.state_public_key(),
            clearance: signer.clearance_public_key(),
        }
    }

    #[derive(Clone)]
    struct VaultRpc {
        chain: &'static str,
        /// None answers every eth_call with "0x": no code at the vault address.
        keys: Option<VaultSigningKeys>,
        unavailable: bool,
        /// Holds every response until permits are added.
        gate: Option<Arc<Semaphore>>,
        challenge_period: u64,
        /// Answers currentRoot() when set.
        root: Option<Felt252>,
    }

    impl VaultRpc {
        fn serving(keys: VaultSigningKeys) -> Self {
            Self {
                chain: "0x1",
                keys: Some(keys),
                unavailable: false,
                gate: None,
                challenge_period: 86_400,
                root: None,
            }
        }
    }

    type Calls = Arc<Mutex<Vec<(String, String, String)>>>;

    /// Records (method, call data, block) and answers like the vault would.
    async fn vault_rpc(vault: VaultRpc) -> (String, Calls) {
        let calls: Calls = Arc::default();
        let recorded = calls.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let vault = vault.clone();
                let calls = recorded.clone();
                async move {
                    if let Some(gate) = vault.gate.as_ref() {
                        let _permit = gate.acquire().await.unwrap();
                    }
                    let method = request["method"].as_str().unwrap_or_default().to_string();
                    let data = request["params"][0]["data"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let block = request["params"][1]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    calls
                        .lock()
                        .unwrap()
                        .push((method.clone(), data.clone(), block));
                    if vault.unavailable {
                        return Err(StatusCode::SERVICE_UNAVAILABLE);
                    }
                    let word = |value: &Felt252| format!("0x{}", hex::encode(value.as_bytes()));
                    let result = match (method.as_str(), vault.keys.as_ref()) {
                        ("eth_chainId", _) => vault.chain.to_string(),
                        ("eth_call", None) => "0x".to_string(),
                        ("eth_call", Some(keys)) => match data.as_str() {
                            STATE_SIGNING_KEY_X_SELECTOR => word(&keys.state.x),
                            STATE_SIGNING_KEY_Y_SELECTOR => word(&keys.state.y),
                            CLEARANCE_SIGNING_KEY_X_SELECTOR => word(&keys.clearance.x),
                            CLEARANCE_SIGNING_KEY_Y_SELECTOR => word(&keys.clearance.y),
                            CHALLENGE_PERIOD_SELECTOR => {
                                format!("0x{:064x}", vault.challenge_period)
                            }
                            CURRENT_ROOT_SELECTOR if vault.root.is_some() => {
                                word(vault.root.as_ref().unwrap())
                            }
                            _ => return Err(StatusCode::BAD_REQUEST),
                        },
                        _ => return Err(StatusCode::BAD_REQUEST),
                    };
                    Ok(Json(json!({"jsonrpc":"2.0", "id":1, "result":result})))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, calls)
    }

    fn config(rpc_url: &str, db_path: &std::path::Path, seeds: (Felt252, Felt252)) -> ServerConfig {
        ServerConfig {
            contract_address: Felt252::from_u64(0x1234),
            state_seed: seeds.0,
            clear_seed: seeds.1,
            db_path: db_path.to_string_lossy().into_owned(),
            native_billing: Some(NativeBillingConfig {
                rpc_url: rpc_url.into(),
                ..crate::test_support::native_config()
            }),
            openrouter_leases: Some(crate::test_support::lease_config()),
            proof_setup_dir: format!("{}/../../protocol/setup/v2", env!("CARGO_MANIFEST_DIR")),
            ..Default::default()
        }
    }

    fn recorded_binding(seeds: (Felt252, Felt252)) -> DeploymentBinding {
        let keys = keys_of(seeds);
        DeploymentBinding {
            chain_id: 1,
            contract_address: "0x0000000000000000000000000000000000001234".into(),
            state_signing_key: keys.state,
            clearance_signing_key: keys.clearance,
            challenge_period_seconds: 86_400,
            verified_at: 1_700_000_000,
            verified_block: None,
        }
    }

    async fn free_listen_addr() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().to_string()
    }

    async fn wait_for_health(listen_addr: &str) {
        let url = format!("http://{listen_addr}/health");
        for _ in 0..400 {
            if let Ok(response) = reqwest::get(&url).await {
                if response.status().is_success() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("server never became healthy");
    }

    fn methods(calls: &Calls) -> Vec<(String, String, String)> {
        calls.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn startup_refuses_unsafe_seeds_before_any_rpc_or_database() {
        let (strong_state, strong_clear) = strong_test_seeds();
        let (rpc, calls) = vault_rpc(VaultRpc::serving(keys_of(strong_test_seeds()))).await;
        let felt = |hex: &str| Felt252::from_hex(hex).unwrap();
        let l = "0x60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1";
        let one_plus_l = "0x60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f2";
        let two_plus_3l = "0x12259d6b14729c0fa51e1a247090812301bcc928ab62ca1f3657c794ab6374d5";
        let unset = ServerConfig::default();
        for (state_seed, clear_seed) in [
            (unset.state_seed, unset.clear_seed),
            (felt("0x0"), strong_clear),
            (felt("1"), strong_clear),
            (felt("0X1"), strong_clear),
            (felt("0x0001"), strong_clear),
            (felt(l), strong_clear),
            (felt(one_plus_l), strong_clear),
            (strong_state, felt(two_plus_3l)),
            (strong_state, felt("0x2")),
            (felt("0x1"), felt("0x2")),
            (felt("0x2"), felt("0x1")),
            (felt("0x7"), felt("0x8")),
            (felt("0xb"), felt("0xc")),
            (felt("0x2a"), strong_clear),
            (strong_state, felt("0x63")),
            (strong_state, strong_state),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let db_path = directory.path().join("must-not-exist.db");
            let error =
                run_server_with(config(&rpc, &db_path, (state_seed, clear_seed)), TEST_RETRY)
                    .await
                    .unwrap_err();
            let message = format!("{error:#}");
            assert!(
                message.contains("refusing to start: invalid signing seeds"),
                "{state_seed}/{clear_seed}: {message}"
            );
            assert!(!message.contains(&strong_state.to_hex()[2..]));
            assert!(!message.contains(&strong_clear.to_hex()[2..]));
            assert!(!db_path.exists());
        }
        assert!(methods(&calls).is_empty(), "the RPC was contacted");
    }

    #[tokio::test]
    async fn startup_refuses_vault_signing_key_mismatch_before_opening_database() {
        let (rpc, calls) = vault_rpc(VaultRpc::serving(keys_of(other_strong_seeds()))).await;
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("must-not-exist.db");
        // Bounded: a regressed key check would start serving, not return.
        let error = tokio::time::timeout(
            Duration::from_secs(20),
            run_server_with(config(&rpc, &db_path, strong_test_seeds()), TEST_RETRY),
        )
        .await
        .expect("the server started under keys the vault does not pin")
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("do not match the vault's immutable keys")
                && error.contains("state MISMATCH")
                && error.contains("clearance MISMATCH")
                && !error.contains("swapped"),
            "{error}"
        );
        assert!(!db_path.exists());
        // A mismatch is definitive: one read of the chain and the vault, no retry.
        assert_eq!(methods(&calls).len(), 1 + KEY_READS.len());
    }

    #[tokio::test]
    async fn startup_refuses_settlement_timing_beyond_half_the_challenge_period() {
        let seeds = strong_test_seeds();
        let (rpc, _) = vault_rpc(VaultRpc {
            challenge_period: 3_600,
            ..VaultRpc::serving(keys_of(seeds))
        })
        .await;
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("must-not-exist.db");
        let error = run_server_with(config(&rpc, &db_path, seeds), TEST_RETRY)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("exceeds half of the vault challengePeriod() (3600 s)"),
            "{error}"
        );
        assert!(!db_path.exists());
        // A recorded binding is checked the same way, without the RPC.
        let recorded = tempfile::tempdir().unwrap();
        let db_path = recorded.path().join("server.db");
        NullifierStore::new(&db_path)
            .unwrap()
            .write_deployment_binding(&DeploymentBinding {
                challenge_period_seconds: 3_600,
                ..recorded_binding(seeds)
            })
            .unwrap();
        let error = run_server_with(config(&rpc, &db_path, seeds), TEST_RETRY)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("challengePeriod()"), "{error}");
    }

    #[tokio::test]
    async fn vault_binding_accepts_matching_keys_read_at_latest() {
        let seeds = strong_test_seeds();
        let (rpc, calls) = vault_rpc(VaultRpc::serving(keys_of(seeds))).await;
        let directory = tempfile::tempdir().unwrap();
        let config = config(&rpc, &directory.path().join("server.db"), seeds);
        let signer = ServerSigner::try_new(&seeds.0, &seeds.1).unwrap();
        let binding = verify_vault_binding(&config, &signer, TEST_RETRY)
            .await
            .unwrap();
        assert_eq!(
            binding,
            DeploymentBinding {
                verified_at: binding.verified_at,
                ..recorded_binding(seeds)
            }
        );
        assert!(binding.verified_at > 1_700_000_000);
        // Only eth_chainId, the four key getters and challengePeriod(), at
        // "latest": no feed decimals() or nativeAssetWeiPerUnit() at startup.
        let calls = methods(&calls);
        assert_eq!(calls[0].0, "eth_chainId");
        let reads: Vec<_> = calls[1..]
            .iter()
            .map(|(method, data, block)| {
                assert_eq!((method.as_str(), block.as_str()), ("eth_call", "latest"));
                data.as_str()
            })
            .collect();
        assert_eq!(reads, KEY_READS);
    }

    #[tokio::test]
    async fn vault_binding_reports_swapped_seeds() {
        let (state, clear) = strong_test_seeds();
        let (rpc, _) = vault_rpc(VaultRpc::serving(keys_of((clear, state)))).await;
        let directory = tempfile::tempdir().unwrap();
        let config = config(&rpc, &directory.path().join("server.db"), (state, clear));
        let signer = ServerSigner::try_new(&state, &clear).unwrap();
        let error = verify_vault_binding(&config, &signer, TEST_RETRY)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("appear swapped"), "{error}");
    }

    #[tokio::test]
    async fn vault_binding_refuses_rpc_on_another_chain_without_retrying() {
        let seeds = strong_test_seeds();
        let (rpc, calls) = vault_rpc(VaultRpc {
            chain: "0xaa36a7",
            ..VaultRpc::serving(keys_of(seeds))
        })
        .await;
        let directory = tempfile::tempdir().unwrap();
        let config = config(&rpc, &directory.path().join("server.db"), seeds);
        let signer = ServerSigner::try_new(&seeds.0, &seeds.1).unwrap();
        let error = verify_vault_binding(&config, &signer, TEST_RETRY)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("serves chain 11155111, but --chain-id is 1"),
            "{error}"
        );
        assert_eq!(
            methods(&calls)
                .iter()
                .map(|call| call.0.as_str())
                .collect::<Vec<_>>(),
            ["eth_chainId"]
        );
    }

    #[tokio::test]
    async fn vault_binding_retries_unavailable_rpc_then_refuses() {
        let seeds = strong_test_seeds();
        let (rpc, calls) = vault_rpc(VaultRpc {
            unavailable: true,
            ..VaultRpc::serving(keys_of(seeds))
        })
        .await;
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("must-not-exist.db");
        let error = run_server_with(config(&rpc, &db_path, seeds), TEST_RETRY)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("after 3 attempts"), "{error}");
        assert!(!error.contains(&rpc), "{error}");
        assert_eq!(methods(&calls).len(), 3);
        assert!(!db_path.exists());
    }

    #[tokio::test]
    async fn vault_binding_refuses_address_without_vault_code() {
        let seeds = strong_test_seeds();
        let (rpc, calls) = vault_rpc(VaultRpc {
            keys: None,
            ..VaultRpc::serving(keys_of(seeds))
        })
        .await;
        let directory = tempfile::tempdir().unwrap();
        let config = config(&rpc, &directory.path().join("server.db"), seeds);
        let signer = ServerSigner::try_new(&seeds.0, &seeds.1).unwrap();
        let error = verify_vault_binding(&config, &signer, TEST_RETRY)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("after 3 attempts") && error.contains("no 32-byte word"),
            "{error}"
        );
        assert_eq!(methods(&calls).len(), 3 * 2);
    }

    #[test]
    fn startup_records_binding_then_restarts_without_rpc() {
        let seeds = strong_test_seeds();
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("server.db");

        // First start: the vault check passes and the binding is recorded.
        let first = tokio::runtime::Runtime::new().unwrap();
        first.block_on(async {
            let (rpc, _) = vault_rpc(VaultRpc::serving(keys_of(seeds))).await;
            let mut config = config(&rpc, &db_path, seeds);
            config.listen_addr = free_listen_addr().await;
            tokio::spawn(run_server_with(config.clone(), TEST_RETRY));
            wait_for_health(&config.listen_addr).await;
        });
        // Dropping the runtime stops the server and releases its writer lock.
        // A child process spawned concurrently by another test can briefly
        // hold a duplicate of the lock descriptor, so wait for the release.
        drop(first);
        let released = std::time::Instant::now();
        while crate::writer_lock::ServerWriterLock::acquire(&db_path).is_err() {
            assert!(released.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(10));
        }
        let recorded = NullifierStore::open_read_only(&db_path)
            .unwrap()
            .read_deployment_binding()
            .unwrap()
            .unwrap();
        assert_eq!(
            recorded,
            DeploymentBinding {
                verified_at: recorded.verified_at,
                ..recorded_binding(seeds)
            }
        );

        // Restart while the RPC is down: a single-attempt gate would refuse, so
        // becoming healthy proves the recorded binding was used.
        let second = tokio::runtime::Runtime::new().unwrap();
        second.block_on(async {
            let (rpc, calls) = vault_rpc(VaultRpc {
                unavailable: true,
                ..VaultRpc::serving(keys_of(seeds))
            })
            .await;
            let mut config = config(&rpc, &db_path, seeds);
            config.listen_addr = free_listen_addr().await;
            let server = tokio::spawn(run_server_with(
                config.clone(),
                StartupRetry {
                    attempts: 1,
                    first_delay: Duration::from_millis(1),
                },
            ));
            wait_for_health(&config.listen_addr).await;
            // The background re-verification keeps trying without stopping the server.
            while methods(&calls).is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(!server.is_finished());
        });
        drop(second);
    }

    #[tokio::test]
    async fn restart_stops_serving_when_the_vault_contradicts_the_recorded_binding() {
        let seeds = strong_test_seeds();
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("server.db");
        NullifierStore::new(&db_path)
            .unwrap()
            .write_deployment_binding(&recorded_binding(seeds))
            .unwrap();
        let gate = Arc::new(Semaphore::new(0));
        let (rpc, _) = vault_rpc(VaultRpc {
            gate: Some(gate.clone()),
            ..VaultRpc::serving(keys_of(other_strong_seeds()))
        })
        .await;
        let mut config = config(&rpc, &db_path, seeds);
        config.listen_addr = free_listen_addr().await;
        let server = tokio::spawn(run_server_with(config.clone(), TEST_RETRY));
        // Serving before the RPC has answered anything: no startup gate ran.
        wait_for_health(&config.listen_addr).await;
        gate.add_permits(1_000);
        let error = tokio::time::timeout(Duration::from_secs(30), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("do not match the vault's immutable keys"),
            "{error}"
        );
        assert_eq!(
            NullifierStore::open_read_only(&db_path)
                .unwrap()
                .read_deployment_binding()
                .unwrap(),
            Some(recorded_binding(seeds))
        );
    }

    #[tokio::test]
    async fn restart_refuses_a_database_bound_to_another_deployment_before_rpc() {
        let seeds = strong_test_seeds();
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("server.db");
        let other_vault = DeploymentBinding {
            contract_address: "0x0000000000000000000000000000000000009999".into(),
            ..recorded_binding(seeds)
        };
        NullifierStore::new(&db_path)
            .unwrap()
            .write_deployment_binding(&other_vault)
            .unwrap();
        let (rpc, calls) = vault_rpc(VaultRpc::serving(keys_of(seeds))).await;
        let error = run_server_with(config(&rpc, &db_path, seeds), TEST_RETRY)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("is bound to vault 0x0000000000000000000000000000000000009999"),
            "{error}"
        );
        assert!(methods(&calls).is_empty());
        assert_eq!(
            NullifierStore::open_read_only(&db_path)
                .unwrap()
                .read_deployment_binding()
                .unwrap(),
            Some(other_vault)
        );
    }

    #[tokio::test]
    async fn background_reverification_retries_until_the_vault_answers() {
        let seeds = strong_test_seeds();
        let directory = tempfile::tempdir().unwrap();
        let recorded = recorded_binding(seeds);
        for vault in [
            VaultRpc {
                unavailable: true,
                ..VaultRpc::serving(keys_of(seeds))
            },
            VaultRpc {
                chain: "0xaa36a7",
                ..VaultRpc::serving(keys_of(seeds))
            },
            VaultRpc {
                keys: None,
                ..VaultRpc::serving(keys_of(seeds))
            },
            VaultRpc::serving(keys_of(seeds)),
        ] {
            let matching =
                vault.keys == Some(keys_of(seeds)) && !vault.unavailable && vault.chain == "0x1";
            let (rpc, calls) = vault_rpc(vault).await;
            let config = config(&rpc, &directory.path().join("server.db"), seeds);
            // Neither an outage, a wrong chain nor a missing vault is definitive.
            assert!(tokio::time::timeout(
                Duration::from_millis(300),
                reverify_deployment_binding(
                    &config,
                    &recorded,
                    &keys_of(seeds),
                    Duration::from_millis(1)
                ),
            )
            .await
            .is_err());
            let calls = methods(&calls);
            if matching {
                // Verified once, then idle.
                assert_eq!(calls.len(), 1 + KEY_READS.len());
            } else {
                assert!(calls.len() > 2);
            }
        }
        let (rpc, _) = vault_rpc(VaultRpc::serving(keys_of(other_strong_seeds()))).await;
        let config = config(&rpc, &directory.path().join("server.db"), seeds);
        let error = reverify_deployment_binding(
            &config,
            &recorded,
            &keys_of(seeds),
            Duration::from_millis(1),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("do not match the vault's immutable keys"),
            "{error}"
        );
    }

    /// Final review (seam:tests-ci#5): a restart on a recorded database with
    /// other signing seeds must run the vault check before serving, and
    /// refuse. Nothing else covered the recorded-binding shortcut's key
    /// comparison.
    #[tokio::test]
    async fn restart_with_changed_seeds_rechecks_the_vault_before_serving() {
        let seeds = strong_test_seeds();
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("server.db");
        NullifierStore::new(&db_path)
            .unwrap()
            .write_deployment_binding(&recorded_binding(seeds))
            .unwrap();
        // The vault answers only once the test has checked that nothing is
        // served meanwhile.
        let gate = Arc::new(Semaphore::new(0));
        let (rpc, calls) = vault_rpc(VaultRpc {
            gate: Some(gate.clone()),
            ..VaultRpc::serving(keys_of(seeds))
        })
        .await;
        let mut config = config(&rpc, &db_path, other_strong_seeds());
        config.listen_addr = free_listen_addr().await;
        let server = tokio::spawn(run_server_with(config.clone(), TEST_RETRY));
        let health = format!("http://{}/health", config.listen_addr);
        for _ in 0..20 {
            assert!(
                reqwest::get(&health).await.is_err(),
                "served under seeds the vault was not checked against"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        gate.add_permits(1_000);
        let error = tokio::time::timeout(Duration::from_secs(20), server)
            .await
            .expect("the server kept running under unverified seeds")
            .unwrap()
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("do not match the vault's immutable keys"),
            "{error}"
        );
        assert_eq!(methods(&calls).len(), 1 + KEY_READS.len());
        // The record is unchanged.
        assert_eq!(
            NullifierStore::open_read_only(&db_path)
                .unwrap()
                .read_deployment_binding()
                .unwrap(),
            Some(recorded_binding(seeds))
        );
    }

    /// Defense in depth for the same shortcut: background re-verification
    /// compares the keys this server signs with, not only the recorded ones.
    #[tokio::test]
    async fn background_reverification_compares_the_live_signing_keys() {
        let seeds = strong_test_seeds();
        let directory = tempfile::tempdir().unwrap();
        let (rpc, _) = vault_rpc(VaultRpc::serving(keys_of(seeds))).await;
        let config = config(&rpc, &directory.path().join("server.db"), seeds);
        let error = tokio::time::timeout(
            Duration::from_secs(20),
            reverify_deployment_binding(
                &config,
                &recorded_binding(seeds),
                &keys_of(other_strong_seeds()),
                Duration::from_millis(1),
            ),
        )
        .await
        .expect("live keys the vault never pinned were accepted")
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("do not match the vault's immutable keys"),
            "{error}"
        );
    }

    /// Optional review nit (seam:ops-config#9): with the indexer unavailable at
    /// startup, the server starts at the vault's currentRoot(), not at 0x0.
    #[tokio::test]
    async fn startup_without_an_indexer_root_uses_the_vault_root() {
        let seeds = strong_test_seeds();
        let vault_root = Felt252::from_u64(0x7007);
        let (rpc, _) = vault_rpc(VaultRpc {
            root: Some(vault_root),
            ..VaultRpc::serving(keys_of(seeds))
        })
        .await;
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(&rpc, &directory.path().join("server.db"), seeds);
        config.listen_addr = free_listen_addr().await;
        // Nothing listens there: the indexer is unavailable.
        config.indexer_url = Some("http://127.0.0.1:9".into());
        let server = tokio::spawn(run_server_with(config.clone(), TEST_RETRY));
        wait_for_health(&config.listen_addr).await;
        let health: Value = reqwest::get(format!("http://{}/health", config.listen_addr))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(health["current_root"], json!(vault_root));
        server.abort();
    }

    /// A delivered lease row as an earlier release's issuance leaves it, of
    /// `key_source`, with no recorded issuer identity.
    fn stored_lease(store: &NullifierStore, id: &str, nullifier: u64, key_source: &str) {
        stored_lease_from(store, id, nullifier, key_source, None);
    }

    /// A delivered lease row as issuance leaves it, of `key_source` and
    /// issued through `identity`.
    fn stored_lease_from(
        store: &NullifierStore,
        id: &str,
        nullifier: u64,
        key_source: &str,
        identity: Option<&str>,
    ) {
        let request: ApiRequestV2 = serde_json::from_value(json!({
            "client_request_id": id,
            "payload": "{}",
            "payload_hash": "0x1",
            "public_inputs": {
                "protocol_version": 2, "chain_id": 1, "contract_address": "0x1234",
                "active_root": "0x0", "state_signing_key_x": "0x1", "state_signing_key_y": "0x2",
                "request_time": 1, "solvency_bound": 10,
                "request_nullifier": format!("0x{nullifier:x}"),
                "authorization_tag": "0x3", "anonymous_commitment_x": "0x4",
                "anonymous_commitment_y": "0x5"
            },
            "proof": {"backend": "groth16_bn254", "proof": "AA=="}
        }))
        .unwrap();
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease(&request, key_source, 10, 4_000_000_000, 4_000_000_000, 1.0)
            .unwrap();
        store
            .activate_openrouter_lease_from(id, &format!("{id}-hash"), identity)
            .unwrap();
    }

    /// Final review (seam:settlement-lifecycle#2): a server configured for one
    /// key source cannot measure or delete another source's keys, so it
    /// refuses to start until the other source's leases and queued direct-key
    /// deletions are drained.
    #[test]
    fn startup_refuses_a_key_source_switch_until_the_old_source_drains() {
        let seeds = strong_test_seeds();
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("server.db");
        {
            let store = NullifierStore::new(&db_path).unwrap();
            store
                .write_deployment_binding(&recorded_binding(seeds))
                .unwrap();
            stored_lease(&store, "direct-lease", 0x51, "openrouter");
            stored_lease(&store, "oa-lease", 0x52, "oa_org");
            // A source this release does not know never blocks startup.
            stored_lease(&store, "future-lease", 0x53, "future_source");
        }
        let start_with = |source: crate::config::OpenRouterLeaseSourceConfig,
                          allow_switch: bool| {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let database = db_path.clone();
            let outcome = runtime.block_on(async move {
                let (rpc, _) = vault_rpc(VaultRpc::serving(keys_of(seeds))).await;
                let mut config = config(&rpc, &database, seeds);
                config.listen_addr = free_listen_addr().await;
                config.openrouter_leases.as_mut().unwrap().source = source;
                config.allow_key_source_switch = allow_switch;
                let server = tokio::spawn(run_server_with(config.clone(), TEST_RETRY));
                let url = format!("http://{}/health", config.listen_addr);
                for _ in 0..400 {
                    if server.is_finished() {
                        return Err(server.await.unwrap().unwrap_err().to_string());
                    }
                    if reqwest::get(&url)
                        .await
                        .is_ok_and(|r| r.status().is_success())
                    {
                        server.abort();
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                panic!("the server neither started nor refused");
            });
            // Dropping the runtime releases the writer lock.
            drop(runtime);
            let released = std::time::Instant::now();
            while crate::writer_lock::ServerWriterLock::acquire(&db_path).is_err() {
                assert!(released.elapsed() < Duration::from_secs(10));
                std::thread::sleep(Duration::from_millis(10));
            }
            outcome
        };
        let start = |source| start_with(source, false);
        let oa = || crate::test_support::lease_config().source;
        let direct = || crate::config::OpenRouterLeaseSourceConfig::OpenRouter {
            management_key: "test".into(),
            api_base: "http://127.0.0.1:9".into(),
        };
        let error = start(oa()).unwrap_err();
        assert!(
            error.contains(
                "1 unsettled lease(s) and 0 queued key deletion(s) of key source 'openrouter'"
            ) && error.contains("configured for key source 'oa_org'")
                && error.contains("Changing the key source")
                && !error.contains("future_source"),
            "{error}"
        );
        let error = start(direct()).unwrap_err();
        assert!(
            error.contains(
                "1 unsettled lease(s) and 0 queued key deletion(s) of key source 'oa_org'"
            ) && error.contains("configured for key source 'openrouter'"),
            "{error}"
        );
        // Final review, round 1: a database holding unsettled leases of both
        // sources is refused under either one, so the refusal names the
        // override, which starts it under either.
        for error in [start(oa()).unwrap_err(), start(direct()).unwrap_err()] {
            assert!(
                error.contains("It also holds 1 such lease(s) of")
                    && error.contains("no single credential can drain it")
                    && error.contains("--allow-key-source-switch"),
                "{error}"
            );
        }
        start_with(oa(), true).unwrap();
        start_with(direct(), true).unwrap();
        // The direct lease settles, but its key's deletion is still queued.
        let finalize = |id: &str| {
            NullifierStore::new(&db_path).unwrap().execute_for_test(
                "UPDATE openrouter_leases SET status = 'finalized' WHERE client_request_id = ?1",
                [id],
            );
        };
        finalize("direct-lease");
        NullifierStore::new(&db_path).unwrap().execute_for_test(
            "INSERT INTO provider_key_cleanup (client_request_id, key_source, key_hash, key_name,
                next_attempt_at, created_at)
             VALUES ('direct-lease', 'openrouter', 'direct-lease-hash', 'zkapi-direct-lease', 0, 0)",
            [],
        );
        let error = start(oa()).unwrap_err();
        assert!(
            error.contains(
                "0 unsettled lease(s) and 1 queued key deletion(s) of key source 'openrouter'"
            ),
            "{error}"
        );
        NullifierStore::new(&db_path)
            .unwrap()
            .execute_for_test("DELETE FROM provider_key_cleanup", []);
        // Drained: the OA server starts, still holding its own pending lease.
        start(oa()).unwrap();
        // The direct server still refuses until the OA lease settles.
        assert!(start(direct()).is_err());
        finalize("oa-lease");
        start(direct()).unwrap();
    }

    /// Final review, round 1: only rows that need the other source's
    /// credential block startup: possibly delivered leases with no committed
    /// charge, and deletions of direct keys that may still be usable. A
    /// never-issued provisioning row, a lease whose key was never delivered,
    /// a conceded or zero-committed lease, a terminal lease and the deletion
    /// of an expired key finalize (or are moot) under any configuration.
    #[test]
    fn key_source_check_counts_only_what_needs_the_other_credential() {
        let store = NullifierStore::in_memory().unwrap();
        let mut config = ServerConfig {
            openrouter_leases: Some(crate::test_support::lease_config()),
            ..Default::default()
        };
        let set = |sql: &str, id: &str| store.execute_for_test(sql, [id]);
        // A never-issued provisioning row (no key hash).
        stored_lease(&store, "provisioning", 0x60, "openrouter");
        set(
            "UPDATE openrouter_leases SET status = 'provisioning', key_hash = NULL
             WHERE client_request_id = ?1",
            "provisioning",
        );
        stored_lease(&store, "never-delivered", 0x61, "openrouter");
        set(
            "UPDATE openrouter_leases SET delivered = 0 WHERE client_request_id = ?1",
            "never-delivered",
        );
        stored_lease(&store, "conceded", 0x62, "openrouter");
        set(
            "UPDATE openrouter_leases SET charge_basis = 'operator_conceded' WHERE client_request_id = ?1",
            "conceded",
        );
        stored_lease(&store, "zero", 0x63, "openrouter");
        set(
            "UPDATE openrouter_leases SET charge_basis = 'unissued', delivered = 0 WHERE client_request_id = ?1",
            "zero",
        );
        stored_lease(&store, "finalized", 0x64, "openrouter");
        set(
            "UPDATE openrouter_leases SET status = 'finalized' WHERE client_request_id = ?1",
            "finalized",
        );
        stored_lease(&store, "expired", 0x65, "openrouter");
        set(
            "UPDATE openrouter_leases SET status = 'finalized', expires_at = 1 WHERE client_request_id = ?1",
            "expired",
        );
        let queue_deletion = |id: &str| {
            store.execute_for_test(
                "INSERT INTO provider_key_cleanup (client_request_id, key_source, key_hash, key_name,
                    next_attempt_at, created_at)
                 VALUES (?1, 'openrouter', ?1, ?1, 0, 0)",
                [id],
            )
        };
        queue_deletion("expired");
        // Final round (server-fixup2#3): a lease past its settlement deadline,
        // which any configuration finalizes at once without provider I/O.
        stored_lease(&store, "past-deadline", 0x67, "openrouter");
        set(
            "UPDATE openrouter_leases SET settlement_deadline_at = 100 WHERE client_request_id = ?1",
            "past-deadline",
        );
        ensure_key_sources_drained(&config, &store).unwrap();

        // A possibly delivered direct lease needs the direct credential...
        stored_lease(&store, "delivered", 0x66, "openrouter");
        let error = ensure_key_sources_drained(&config, &store)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(
                "1 unsettled lease(s) and 0 queued key deletion(s) of key source 'openrouter'"
            ) && error.contains("Drain the previous key source first")
                && error.contains("--allow-key-source-switch"),
            "{error}"
        );
        // ...until its settlement deadline, which it then is finalized at.
        set(
            "UPDATE openrouter_leases SET settlement_deadline_at = 4000000000 WHERE client_request_id = ?1",
            "delivered",
        );
        assert!(ensure_key_sources_drained(&config, &store).is_err());
        set(
            "UPDATE openrouter_leases SET settlement_deadline_at = 100 WHERE client_request_id = ?1",
            "delivered",
        );
        ensure_key_sources_drained(&config, &store).unwrap();
        // So does the deletion of a key that has not expired.
        set(
            "UPDATE openrouter_leases SET status = 'finalized' WHERE client_request_id = ?1",
            "delivered",
        );
        queue_deletion("delivered");
        let error = ensure_key_sources_drained(&config, &store)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(
                "0 unsettled lease(s) and 1 queued key deletion(s) of key source 'openrouter'"
            ),
            "{error}"
        );
        // The operator's override accepts the charges and starts.
        config.allow_key_source_switch = true;
        ensure_key_sources_drained(&config, &store).unwrap();
    }

    /// Final round (server-fixup2#2): another OA org, or another OpenRouter
    /// API base, cannot measure or delete the keys the previous one issued,
    /// so it counts as another key source. A rotated credential of the same
    /// org or API base does not. Leases activated by an earlier release
    /// record no issuer: see
    /// `key_source_check_takes_unrecorded_leases_as_the_recorded_issuers`.
    #[test]
    fn key_source_check_tells_issuers_of_one_source_apart() {
        use crate::config::OpenRouterLeaseSourceConfig;
        let store = NullifierStore::in_memory().unwrap();
        let configured = |source: OpenRouterLeaseSourceConfig, allow_switch: bool| ServerConfig {
            openrouter_leases: Some(crate::config::OpenRouterLeaseConfig {
                source,
                ..crate::test_support::lease_config()
            }),
            allow_key_source_switch: allow_switch,
            ..Default::default()
        };
        let org = |url: &str, secret: &str| OpenRouterLeaseSourceConfig::OaOrg {
            org_base_url: url.into(),
            shared_secret: secret.into(),
        };
        let direct = |base: &str, key: &str| OpenRouterLeaseSourceConfig::OpenRouter {
            management_key: key.into(),
            api_base: base.into(),
        };
        let check = |source, allow_switch| {
            ensure_key_sources_drained(&configured(source, allow_switch), &store)
                .map_err(|error| error.to_string())
        };
        let org_a = "https://org-a.example";
        stored_lease_from(&store, "org-a-lease", 0x71, "oa_org", Some(org_a));
        // A lease activated before this release records no issuer. Next to
        // org A's, it is taken as org A's (final round, fixup3): org B is
        // told to drain org A first, as a start under org A passes.
        stored_lease(&store, "legacy-lease", 0x72, "oa_org");
        check(org("https://org-a.example/", "rotated"), false).unwrap();
        let error = check(org("https://org-b.example", "b"), false).unwrap_err();
        assert!(
            error.contains(
                "1 unsettled lease(s) and 0 queued key deletion(s) of key source 'oa_org' \
                 issued through https://org-a.example (OA org"
            ) && error.contains(
                "1 unsettled lease(s) and 0 queued key deletion(s) of key source 'oa_org' \
                 activated before this release, recording no issuer (OA org"
            ) && error.contains("configured for key source 'oa_org' at https://org-b.example")
                && error.contains(
                    "Drain the previous key source first: restart with its credential and URL"
                )
                && !error.contains("It also holds")
                && !error.contains("no single credential")
                && error.contains("Changing the key source"),
            "{error}"
        );
        store.execute_for_test(
            "UPDATE openrouter_leases SET status = 'finalized' WHERE client_request_id = ?1",
            ["legacy-lease"],
        );
        let error = check(org("https://org-b.example", "b"), false).unwrap_err();
        assert!(
            error.contains(
                "Drain the previous key source first: restart with its credential and URL"
            ),
            "{error}"
        );
        check(org("https://org-b.example", "b"), true).unwrap();
        // Leases of two orgs: refused under either, started with the flag.
        stored_lease_from(
            &store,
            "org-b-lease",
            0x73,
            "oa_org",
            Some("https://org-b.example"),
        );
        for url in [org_a, "https://org-b.example"] {
            let error = check(org(url, "s"), false).unwrap_err();
            assert!(
                error.contains("It also holds 1 such lease(s)")
                    && error.contains("no single credential can drain it"),
                "{error}"
            );
            check(org(url, "s"), true).unwrap();
        }
        for id in ["org-a-lease", "org-b-lease"] {
            store.execute_for_test(
                "UPDATE openrouter_leases SET status = 'finalized' WHERE client_request_id = ?1",
                [id],
            );
        }
        // Direct OpenRouter: the API base, and the deletion of a key it
        // issued, which another API base cannot delete.
        let base = "https://openrouter.ai/api";
        stored_lease_from(&store, "direct-lease", 0x74, "openrouter", Some(base));
        check(direct("https://openrouter.ai/api/", "rotated-key"), false).unwrap();
        let other = || direct("https://proxy.example/api", "key");
        let error = check(other(), false).unwrap_err();
        assert!(
            error.contains(
                "1 unsettled lease(s) and 0 queued key deletion(s) of key source 'openrouter' \
                 issued through https://openrouter.ai/api (direct OpenRouter"
            ),
            "{error}"
        );
        store.execute_for_test(
            "UPDATE openrouter_leases SET status = 'finalized' WHERE client_request_id = ?1",
            ["direct-lease"],
        );
        check(other(), false).unwrap();
        store.execute_for_test(
            "INSERT INTO provider_key_cleanup (client_request_id, key_source, key_hash, key_name,
                next_attempt_at, created_at)
             VALUES ('direct-lease', 'openrouter', 'direct-lease-hash', 'zkapi-direct-lease', 0, 0)",
            [],
        );
        let error = check(other(), false).unwrap_err();
        assert!(
            error.contains(
                "0 unsettled lease(s) and 1 queued key deletion(s) of key source 'openrouter' \
                 issued through https://openrouter.ai/api"
            ),
            "{error}"
        );
        check(direct(base, "rotated-key"), false).unwrap();
    }

    /// Final round (fixup3): a lease activated by an earlier release records
    /// no issuer. It is taken as the configured issuer's when its key source
    /// matches, unless the database holds rows still to settle recorded under
    /// another issuer of that key source: that one has been running since the
    /// upgrade, takes them as its own when started, and settles them. Every
    /// start then gives the same answer, and the remedy counts issuers, not
    /// whether the configured one holds any.
    #[test]
    fn key_source_check_takes_unrecorded_leases_as_the_recorded_issuers() {
        use crate::config::OpenRouterLeaseSourceConfig;
        let store = NullifierStore::in_memory().unwrap();
        let check = |source: OpenRouterLeaseSourceConfig| {
            let config = ServerConfig {
                openrouter_leases: Some(crate::config::OpenRouterLeaseConfig {
                    source,
                    ..crate::test_support::lease_config()
                }),
                ..Default::default()
            };
            ensure_key_sources_drained(&config, &store).map_err(|error| error.to_string())
        };
        let org = |url: &str| OpenRouterLeaseSourceConfig::OaOrg {
            org_base_url: url.into(),
            shared_secret: "secret".into(),
        };
        let base = "https://openrouter.ai/api";
        let direct = || OpenRouterLeaseSourceConfig::OpenRouter {
            management_key: "key".into(),
            api_base: base.into(),
        };
        let finalize = |id: &str| {
            store.execute_for_test(
                "UPDATE openrouter_leases SET status = 'finalized' WHERE client_request_id = ?1",
                [id],
            )
        };
        let (org_a, org_b, org_c) = (
            "https://org-a.example",
            "https://org-b.example",
            "https://org-c.example",
        );
        let unrecorded = "1 unsettled lease(s) and 0 queued key deletion(s) of key source \
                          'oa_org' activated before this release, recording no issuer (OA org";
        // Alone, it is taken as whichever org is configured (which the check
        // cannot tell apart; the docs say to drain such leases first).
        stored_lease(&store, "legacy", 0x80, "oa_org");
        check(org(org_a)).unwrap();
        check(org(org_b)).unwrap();

        // Next to a lease recorded under org A: org A's. Org A starts, and
        // org B is told to drain org A first, not that no single credential
        // can drain the database.
        stored_lease_from(&store, "org-a", 0x81, "oa_org", Some(org_a));
        check(org(org_a)).unwrap();
        let error = check(org(org_b)).unwrap_err();
        assert!(
            error.contains(unrecorded)
                && error.contains("Drain the previous key source first")
                && !error.contains("It also holds")
                && !error.contains("no single credential"),
            "{error}"
        );

        // Next to leases of orgs A and B: neither's, and no third issuer.
        stored_lease_from(&store, "org-b", 0x82, "oa_org", Some(org_b));
        for (url, other) in [(org_a, org_b), (org_b, org_a)] {
            let error = check(org(url)).unwrap_err();
            assert!(
                error.contains(&format!(
                    "of key source 'oa_org' issued through {other} (OA org"
                )) && error.contains(unrecorded)
                    && error.contains(&format!(
                        "It also holds 1 such lease(s) of 'oa_org' issued through {url}, \
                         so no single credential can drain it"
                    ))
                    && error.contains("a start under the other without the flag refuses")
                    && error.contains("and then restart under the other without the flag"),
                "{error}"
            );
        }
        // Org C holds none of them: still two issuers.
        let error = check(org(org_c)).unwrap_err();
        assert!(
            error.contains(unrecorded)
                && error
                    .contains("These belong to 2 issuers, so no single credential can drain it")
                && error.contains("and then restart under the other without the flag")
                && !error.contains("It also holds")
                && !error.contains("Drain the previous key source first"),
            "{error}"
        );
        // With a lease of org C too: three issuers.
        stored_lease_from(&store, "org-c", 0x83, "oa_org", Some(org_c));
        let error = check(org(org_c)).unwrap_err();
        assert!(
            error.contains(
                "It also holds 1 such lease(s) of 'oa_org' issued through https://org-c.example, \
                 so no single credential can drain it"
            ) && error.contains("a start under another one without the flag lists them")
                && error.contains("repeat under each of the others in turn"),
            "{error}"
        );
        for id in ["org-a", "org-b", "org-c"] {
            finalize(id);
        }

        // With no other issuer of its source left, it is taken as the
        // configured org's again, and named so next to another source type.
        check(org(org_b)).unwrap();
        stored_lease_from(&store, "direct", 0x84, "openrouter", Some(base));
        let error = check(org(org_b)).unwrap_err();
        assert!(
            error.contains(
                "It also holds 1 such lease(s) of 'oa_org' issued through https://org-b.example \
                 (1 of these lease(s), activated before this release, record no issuer and are \
                 taken as its own), so no single credential can drain it"
            ),
            "{error}"
        );
        let error = check(direct()).unwrap_err();
        assert!(
            error.contains(unrecorded)
                && error.contains(
                    "It also holds 1 such lease(s) of 'openrouter' issued through \
                     https://openrouter.ai/api, so no single credential can drain it"
                ),
            "{error}"
        );

        // A queued deletion of a direct key the configured API base issued
        // is its own too: another source's lease is then a second issuer.
        finalize("legacy");
        finalize("direct");
        store.execute_for_test(
            "INSERT INTO provider_key_cleanup (client_request_id, key_source, key_hash, key_name,
                next_attempt_at, created_at)
             VALUES ('direct', 'openrouter', 'direct-hash', 'zkapi-direct', 0, 0)",
            [],
        );
        check(direct()).unwrap();
        stored_lease_from(&store, "org-a-2", 0x85, "oa_org", Some(org_a));
        let error = check(direct()).unwrap_err();
        assert!(
            error.contains(
                "It also holds 1 queued key deletion(s) of 'openrouter' issued through \
                 https://openrouter.ai/api, so no single credential can drain it"
            ),
            "{error}"
        );
    }
}

#[cfg(test)]
pub(crate) mod settlement_route_tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    pub(crate) fn processor(allow_legacy_clearance: bool) -> RequestProcessor {
        RequestProcessor::try_new(
            ServerConfig {
                contract_address: Felt252::from_u64(123),
                native_billing: Some(crate::test_support::native_config()),
                openrouter_leases: Some(crate::test_support::lease_config()),
                proof_setup_dir: crate::test_support::setup_directory(),
                allow_legacy_clearance,
                ..Default::default()
            },
            Arc::new(NullifierStore::in_memory().unwrap()),
            Arc::new(ServerSigner::new(
                &Felt252::from_u64(7),
                &Felt252::from_u64(8),
            )),
            Felt252::ZERO,
        )
        .unwrap()
    }

    async fn get_json(app: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn health_reports_clearance_ownership_requirement() {
        for (legacy, required, limit) in [(false, true, 0), (true, false, 60)] {
            let app = create_router(Arc::new(processor(legacy)));
            let (status, body) = get_json(&app, "/health").await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["clearance_ownership_proof_required"], required);
            assert_eq!(body["legacy_clearance_window_used"], 0);
            assert_eq!(body["legacy_clearance_window_limit"], limit);
            assert_eq!(body["legacy_clearance_rejected_total"], 0);
            // No settlement data on the public health endpoint.
            assert!(body.get("settlement").is_none());
        }
    }

    #[tokio::test]
    async fn proofless_clearance_is_rejected_over_http() {
        let processor = Arc::new(processor(false));
        let app = create_router(processor.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v2/withdraw/clearance")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"withdrawal_nullifier":"0x2a"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1 << 16).await.unwrap())
                .unwrap();
        assert_eq!(body["error_code"], "clearance_ownership_required");
        assert_eq!(body["retriable"], false);
        assert!(processor
            .store()
            .lookup_by_nullifier(&Felt252::from_u64(42))
            .is_none());
    }

    async fn post_clearance(
        app: &Router,
        request: &ClearanceRequest,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v2/withdraw/clearance")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, headers) = (response.status(), response.headers().clone());
        let body = to_bytes(response.into_body(), 1 << 16).await.unwrap();
        (status, headers, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn junk_exhausting_the_legacy_budget_gets_its_own_code_and_shows_on_health() {
        let fixture = crate::test_support::ownership_fixture().await;
        let (state_seed, clear_seed) = crate::test_support::OWNERSHIP_SEEDS;
        let processor = RequestProcessor::try_new(
            ServerConfig {
                allow_legacy_clearance: true,
                legacy_clearance_max_per_minute: 60,
                ..crate::test_support::ownership_server_config()
            },
            Arc::new(NullifierStore::in_memory().unwrap()),
            Arc::new(ServerSigner::new(
                &Felt252::from_u64(state_seed),
                &Felt252::from_u64(clear_seed),
            )),
            fixture.root,
        )
        .unwrap();
        let app = create_router(Arc::new(processor));
        // Stay inside one budget window on the real clock.
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            % 60;
        if elapsed > 50 {
            tokio::time::sleep(Duration::from_secs(60 - elapsed)).await;
        }
        let proofless = |nullifier| ClearanceRequest {
            withdrawal_nullifier: nullifier,
            ownership_proof: None,
        };
        for junk in 0..60 {
            let junk = proofless(Felt252::from_u64(0xdead_0000 + junk));
            assert_eq!(post_clearance(&app, &junk).await.0, StatusCode::OK);
        }
        let nullifier = fixture.plan.public_inputs.withdrawal_nullifier;
        let (status, headers, body) = post_clearance(&app, &proofless(nullifier)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error_code"], "legacy_clearance_capacity");
        assert_eq!(body["retriable"], true);
        let retry_after: u64 = headers[RETRY_AFTER].to_str().unwrap().parse().unwrap();
        assert!((1..=60).contains(&retry_after), "{retry_after}");
        assert_eq!(body["retry_after_seconds"], retry_after);
        // The owner's ownership proof is admitted regardless.
        let proved = ClearanceRequest {
            withdrawal_nullifier: nullifier,
            ownership_proof: Some(zkapi_types::wire::ClearanceOwnershipProof {
                public_inputs: fixture.plan.public_inputs.clone(),
                proof: fixture.plan.proof.clone(),
            }),
        };
        let (status, _, body) = post_clearance(&app, &proved).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["withdrawal_nullifier"],
            serde_json::to_value(nullifier).unwrap()
        );
        let (_, health) = get_json(&app, "/health").await;
        assert_eq!(health["legacy_clearance_window_used"], 60);
        assert_eq!(health["legacy_clearance_window_limit"], 60);
        assert_eq!(health["legacy_clearance_rejected_total"], 1);
    }

    #[tokio::test]
    async fn dashboard_settlement_endpoint_lists_pending_leases_and_counts() {
        let processor = Arc::new(processor(false));
        let request: ApiRequestV2 = serde_json::from_value(serde_json::json!({
            "client_request_id": "dashboard-lease",
            "payload": "{}",
            "payload_hash": "0x1",
            "public_inputs": {
                "protocol_version": 2, "chain_id": 1, "contract_address": "0x7b",
                "active_root": "0x0", "state_signing_key_x": "0x1", "state_signing_key_y": "0x2",
                "request_time": 1, "solvency_bound": 10, "request_nullifier": "0x99",
                "authorization_tag": "0x3", "anonymous_commitment_x": "0x4",
                "anonymous_commitment_y": "0x5"
            },
            "proof": {"backend": "groth16_bn254", "proof": "AA=="}
        }))
        .unwrap();
        let store = processor.store();
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease(&request, "oa_org", 10, 4_000_000_000, 4_000_000_000, 1.0)
            .unwrap();
        store
            .record_openrouter_lease_error("dashboard-lease", "usage pending")
            .unwrap();
        let app = create_router(processor.clone());
        let (status, overview) = get_json(&app, "/v1/dashboard/settlement?limit=5").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(overview["counts"]["pending"], 1);
        assert_eq!(overview["counts"]["retrying"], 1);
        assert_eq!(
            overview["pending"][0]["client_request_id"],
            "dashboard-lease"
        );
        assert_eq!(overview["pending"][0]["attempts"], 1);
        assert_eq!(overview["pending"][0]["last_error"], "usage pending");
        assert_eq!(
            overview["settlement_deadline_seconds"],
            crate::config::DEFAULT_SETTLEMENT_DEADLINE_SECONDS
        );
        assert!(overview["reviews"].as_array().unwrap().is_empty());
        let (status, summary) = get_json(&app, "/v1/dashboard/summary").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(summary["settlement"]["pending"], 1);
        assert_eq!(summary["settlement"]["provisioning"], 1);
    }
}
