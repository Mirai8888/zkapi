//! Axum HTTP routes for the zkAPI server.
//!
//! Endpoints:
//! - GET  /health                   -- process health and config summary
//! - GET  /v1/attestation           -- published signer metadata for deployments
//! - POST /v2/openrouter/leases     -- open a prompt-private runtime-key lease
//! - POST /v2/openrouter/leases/:id -- retire a rejected runtime-key lease
//! - POST /v2/withdraw/clearance    -- request mutual-close clearance
//! - GET  /v2/requests/:id          -- recover by client_request_id
//! - GET  /v2/nullifiers/:nullifier -- recover by nullifier

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
use crate::dashboard::{DashboardEvent, DashboardHub, DashboardTotals};
use crate::error::ServerError;
use crate::native_billing::{vault_address_hex, NativeBillingOracle, VaultSigningKeys};
use crate::nullifier_store::{DeploymentBinding, NullifierStore};
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
/// without the RPC and re-verifies in the background.
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
    let store = Arc::new(NullifierStore::new(&config.db_path)?);
    let initial_root = if let Some(indexer_url) = config.indexer_url.as_deref() {
        match fetch_indexer_root(indexer_url).await {
            Ok(root) => root,
            Err(err) => {
                tracing::warn!("failed to fetch initial root from indexer: {}", err);
                config.initial_root
            }
        }
    } else {
        config.initial_root
    };
    let dashboard = Arc::new(DashboardHub::new(500));
    let processor = Arc::new(
        RequestProcessor::try_new(config.clone(), store, signer, initial_root)?
            .with_dashboard(dashboard),
    );
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
            Err(mismatch) = reverify_deployment_binding(&config, &binding, VAULT_REVERIFY_FIRST_DELAY) => {
                return Err(mismatch);
            }
        }
    } else {
        serve.await?;
    }
    Ok(())
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
/// challenge period) that contradict the record end the server.
async fn reverify_deployment_binding(
    config: &ServerConfig,
    recorded: &DeploymentBinding,
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
                let outcome = ensure_vault_keys_match(config, &expected, &vault.keys).and_then(|()| {
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

/// Create the Axum router with all zkAPI server routes.
pub fn create_router(processor: Arc<RequestProcessor>) -> Router {
    let password = processor.config().testnet_password.clone();
    // Preserve the local dashboard's existing CORS policy. Password-gated
    // Sepolia additionally permits explicit credential headers below.
    let dashboard = Router::new()
        .route("/v1/dashboard/summary", get(handle_dashboard_summary))
        .route("/v1/dashboard/recent", get(handle_dashboard_recent))
        .route("/v1/dashboard/events", get(handle_dashboard_events))
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

async fn handle_openrouter_lease_status(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
) -> Result<Json<OpenRouterLeaseStatusResponse>, StatusCode> {
    processor
        .openrouter_lease_status(&client_request_id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
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

/// POST /v1/withdraw/clearance -- request a clearance signature.
async fn handle_clearance(
    State(processor): State<AppState>,
    Json(clearance_req): Json<ClearanceRequest>,
) -> Result<Json<ClearanceResponseV2>, ErrorHttpResponse> {
    processor
        .process_clearance(&clearance_req)
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
    Json(DashboardSummary {
        server,
        totals,
        started_ms,
        recent_count,
    })
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
    let latest_root = if matches!(err, ServerError::StaleRoot { .. }) {
        Some(processor.current_root())
    } else {
        None
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
        | ServerError::ProtocolMismatch(_) => StatusCode::BAD_REQUEST,
        ServerError::StaleRoot { .. }
        | ServerError::NativeQuoteExpired
        | ServerError::NativeQuoteSuperseded => StatusCode::CONFLICT,
        ServerError::Replay | ServerError::NullifierUsed => StatusCode::CONFLICT,
        ServerError::LeasePending | ServerError::LeaseSettlementPending { .. } => {
            StatusCode::CONFLICT
        }
        ServerError::NoteExpired => StatusCode::GONE,
        ServerError::CapacityExhausted => StatusCode::SERVICE_UNAVAILABLE,
        ServerError::Internal(_) | ServerError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        ServerError::OaRateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
    };

    let retry_after_seconds = match err {
        ServerError::OaRateLimited {
            retry_after_seconds,
            ..
        }
        | ServerError::LeaseSettlementPending {
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
        CLEARANCE_SIGNING_KEY_Y_SELECTOR, STATE_SIGNING_KEY_X_SELECTOR,
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
    }

    impl VaultRpc {
        fn serving(keys: VaultSigningKeys) -> Self {
            Self {
                chain: "0x1",
                keys: Some(keys),
                unavailable: false,
                gate: None,
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
                            CHALLENGE_PERIOD_SELECTOR => format!("0x{:064x}", 86_400),
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
        let error = run_server_with(config(&rpc, &db_path, strong_test_seeds()), TEST_RETRY)
            .await
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
                reverify_deployment_binding(&config, &recorded, Duration::from_millis(1)),
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
        let error = reverify_deployment_binding(&config, &recorded, Duration::from_millis(1))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("do not match the vault's immutable keys"),
            "{error}"
        );
    }
}
