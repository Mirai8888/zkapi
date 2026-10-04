//! Operator-run v2 challenge daemon; see docs/challenge-service.md.
use anyhow::Context;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use zkapi_serverd::{
    challenge_service::{
        ChallengeService, ChallengeServiceConfig, DeploymentCheckError, FeePolicy,
    },
    challenge_status::{self, AlarmPolicy},
    nullifier_store::NullifierStore,
};
use zkapi_types::Felt252;

#[derive(Parser)]
#[command(
    about = "Challenge consumed-state escape withdrawals using the v2 server transcript database"
)]
struct Args {
    /// Operator-controlled RPC supporting eth_sendTransaction for --sender.
    #[arg(long, env = "ZKAPI_CHALLENGE_RPC_URL")]
    rpc_url: String,
    #[arg(long, env = "ZKAPI_CHALLENGE_INDEXER_URL")]
    indexer_url: String,
    /// Dedicated gas-paying account managed by the configured signer RPC.
    #[arg(long, env = "ZKAPI_CHALLENGE_SENDER")]
    sender: String,
    #[arg(long)]
    contract_address: String,
    #[arg(long)]
    chain_id: u64,
    /// Vault deployment block; never start at the current head on a restart.
    #[arg(long)]
    from_block: u64,
    #[arg(long, default_value_t = 2)]
    confirmations: u64,
    /// The API server's database, opened read-only. Start the upgraded API
    /// server first: it records the verified deployment binding.
    #[arg(long)]
    db_path: PathBuf,
    #[arg(long)]
    checkpoint: PathBuf,
    #[arg(long)]
    proof_setup_dir: PathBuf,
    #[arg(long, default_value_t = 1000)]
    poll_interval_ms: u64,
    /// Highest maxFeePerGas (wei) the daemon proposes; at most the signer's cap.
    #[arg(long, env = "ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI")]
    max_fee_per_gas_wei: u128,
    /// Highest maxPriorityFeePerGas (wei); at most the signer's tip cap and at
    /// least twice --priority-fee-per-gas-wei.
    #[arg(long, env = "ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI")]
    max_priority_fee_per_gas_wei: u128,
    /// Tip of a first attempt (wei).
    #[arg(long, env = "ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI", default_value_t = FeePolicy::DEFAULT_PRIORITY_FEE_PER_GAS)]
    priority_fee_per_gas_wei: u128,
    /// Highest gas limit x maxFeePerGas of one challenge (wei); at most the
    /// upstream node's RPC fee cap (geth --rpc.txfeecap). Bids also stay
    /// within the signer's tx_fee_cap_wei when it reports a lower one.
    #[arg(
        long,
        env = "ZKAPI_CHALLENGE_TX_FEE_CAP_WEI",
        default_value_t = FeePolicy::DEFAULT_TX_FEE_CAP_WEI,
        value_parser = FeePolicy::parse_tx_fee_cap
    )]
    tx_fee_cap_wei: u128,
    /// Blocks a challenge may stay pending before a same-nonce replacement.
    #[arg(long, default_value_t = FeePolicy::DEFAULT_BUMP_AFTER_BLOCKS)]
    fee_bump_after_blocks: u64,
    /// Fee-cap increase of a replacement, in percent (10-100).
    #[arg(long, default_value_t = FeePolicy::DEFAULT_BUMP_PERCENT)]
    fee_bump_percent: u64,
    /// Internal status listener (GET /livez, /health, /status). Never publish it.
    #[arg(
        long,
        env = "ZKAPI_CHALLENGE_STATUS_LISTEN",
        default_value = "127.0.0.1:3002"
    )]
    status_listen: SocketAddr,
    /// Remaining seconds at which an obligation warns (default challengePeriod/2).
    #[arg(long)]
    warning_remaining_seconds: Option<u64>,
    /// Remaining seconds at which an obligation is critical and fees escalate
    /// to the caps (default challengePeriod/4).
    #[arg(long)]
    critical_remaining_seconds: Option<u64>,
    #[arg(long, default_value_t = 120)]
    blocked_warning_seconds: u64,
    #[arg(long, default_value_t = 1800)]
    critical_blocked_seconds: u64,
    #[arg(long, default_value_t = 3600)]
    settlement_overdue_seconds: u64,
    #[arg(long, default_value_t = 600)]
    indexer_divergence_seconds: u64,
    #[arg(long, default_value_t = 3)]
    indexer_divergence_polls: u32,
    #[arg(long, default_value_t = 64)]
    indexer_lag_warning_blocks: u64,
    #[arg(long, default_value_t = 300)]
    stale_poll_seconds: u64,
    #[arg(long, default_value_t = 300)]
    startup_grace_seconds: u64,
    /// Interval of the sender balance and indexer root observations.
    #[arg(long, default_value_t = 15)]
    observe_interval_seconds: u64,
    /// Default: 7.6M gas times --max-fee-per-gas-wei, at most --tx-fee-cap-wei.
    #[arg(long)]
    min_sender_balance_wei: Option<u128>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    anyhow::ensure!(args.poll_interval_ms > 0, "poll interval must be positive");
    anyhow::ensure!(
        args.db_path.is_file(),
        "server transcript database does not exist"
    );
    if let Some(parent) = args
        .checkpoint
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(args.checkpoint.with_extension("lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("another challenge daemon holds this checkpoint")?;
    let alarms = AlarmPolicy {
        warning_remaining_seconds: args.warning_remaining_seconds,
        critical_remaining_seconds: args.critical_remaining_seconds,
        blocked_warning_seconds: args.blocked_warning_seconds,
        critical_blocked_seconds: args.critical_blocked_seconds,
        settlement_overdue_seconds: args.settlement_overdue_seconds,
        indexer_divergence_seconds: args.indexer_divergence_seconds,
        indexer_divergence_polls: args.indexer_divergence_polls,
        indexer_lag_warning_blocks: args.indexer_lag_warning_blocks,
        stale_poll_seconds: args.stale_poll_seconds,
        startup_grace_seconds: args.startup_grace_seconds,
        observe_interval_seconds: args.observe_interval_seconds,
        min_sender_balance_wei: args.min_sender_balance_wei,
    };
    let config = ChallengeServiceConfig {
        rpc_url: args.rpc_url,
        indexer_url: args.indexer_url,
        sender: args.sender,
        contract_address: Felt252::from_hex(&args.contract_address).map_err(anyhow::Error::msg)?,
        chain_id: args.chain_id,
        from_block: args.from_block,
        confirmations: args.confirmations,
        checkpoint: args.checkpoint,
        proof_setup_dir: args.proof_setup_dir,
        fee: FeePolicy {
            max_fee_per_gas: args.max_fee_per_gas_wei,
            max_priority_fee_per_gas: args.max_priority_fee_per_gas_wei,
            priority_fee_per_gas: args.priority_fee_per_gas_wei,
            tx_fee_cap_wei: args.tx_fee_cap_wei,
            bump_after_blocks: args.fee_bump_after_blocks,
            bump_percent: args.fee_bump_percent,
        },
        alarms: alarms.clone(),
    };
    // Least privilege: the API server is the only writer of this database.
    let store = Arc::new(NullifierStore::open_read_only(&args.db_path)?);
    let mut service = ChallengeService::new(config, store)?;
    let listener = tokio::net::TcpListener::bind(args.status_listen)
        .await
        .with_context(|| format!("failed to bind --status-listen {}", args.status_listen))?;
    tracing::info!(address = %listener.local_addr()?, "challenge status listening (internal only)");
    let status = challenge_status::router(service.status_handle(), alarms);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, status).await {
            tracing::error!(error = %error, "challenge status listener failed");
        }
    });
    // Never poll a database bound to another deployment: every escape would
    // read as having no evidence and silently go unchallenged.
    loop {
        match service.verify_deployment_binding().await {
            Ok(binding) => {
                tracing::info!(
                    chain_id = binding.chain_id,
                    vault = %binding.contract_address,
                    "server database deployment binding verified against the vault"
                );
                break;
            }
            Err(DeploymentCheckError::Mismatch(message)) => anyhow::bail!(message),
            Err(error) => {
                tracing::warn!(error = %error, "deployment binding verification will retry");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
        }
    }
    let mut ticker = tokio::time::interval(Duration::from_millis(args.poll_interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = ticker.tick() => if let Err(error) = service.poll_once().await {
                tracing::error!(error = %error, "challenge poll failed; durable work will retry");
            }
        }
    }
}
