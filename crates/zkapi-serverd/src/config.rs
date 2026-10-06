//! Server configuration.

use zkapi_types::Felt252;

/// Default time after a lease's natural settlement start (issuance + TTL +
/// grace) at which an unsettled, possibly delivered lease is force-finalized.
pub const DEFAULT_SETTLEMENT_DEADLINE_SECONDS: u64 = 21_600;
/// Minimum retry window that a settlement deadline must leave after grace.
pub const MIN_SETTLEMENT_RETRY_WINDOW_SECONDS: u64 = 900;
/// Bound on the background sweep's own latency (tick budget plus attempt
/// timeout) used by the startup timing check.
pub const SETTLEMENT_SWEEP_SLACK_SECONDS: u64 = 600;
/// How long a root the server observed stays acceptable for clearance.
pub const DEFAULT_CLEARANCE_ROOT_WINDOW_SECONDS: u64 = 3_600;
pub const MIN_CLEARANCE_ROOT_WINDOW_SECONDS: u64 = 60;
pub const MAX_CLEARANCE_ROOT_WINDOW_SECONDS: u64 = 86_400;
/// In-process cap on new proof-less (legacy) clearance reservations.
pub const DEFAULT_LEGACY_CLEARANCE_MAX_PER_MINUTE: u32 = 60;

/// Source used to provision prompt-private, short-lived OpenRouter keys.
#[derive(Clone)]
pub enum OpenRouterLeaseSourceConfig {
    /// Mint child keys directly with an OpenRouter management key.
    OpenRouter {
        management_key: String,
        /// OpenRouter API base without `/v1`.
        api_base: String,
    },
    /// Ask an OA org to relay key creation to a verifier-enrolled station.
    OaOrg {
        org_base_url: String,
        /// Dedicated zkAPI service credential configured by the org.
        shared_secret: String,
    },
}

impl OpenRouterLeaseSourceConfig {
    pub fn label(&self) -> &'static str {
        match self {
            Self::OpenRouter { .. } => "openrouter",
            Self::OaOrg { .. } => "oa_org",
        }
    }
}

impl std::fmt::Debug for OpenRouterLeaseSourceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenRouter { api_base, .. } => formatter
                .debug_struct("OpenRouter")
                .field("management_key", &"[configured]")
                .field("api_base", api_base)
                .finish(),
            Self::OaOrg { org_base_url, .. } => formatter
                .debug_struct("OaOrg")
                .field("org_base_url", org_base_url)
                .field("shared_secret", &"[configured]")
                .finish(),
        }
    }
}

/// Prompt-private lease configuration for native ETH billing.
#[derive(Debug, Clone)]
pub struct OpenRouterLeaseConfig {
    pub source: OpenRouterLeaseSourceConfig,
    /// Runtime-key validity window.
    pub ttl_seconds: u64,
    /// Delay after expiry (and after disabling directly managed keys) before
    /// reading aggregate usage, allowing in-flight calls and accounting to drain.
    pub settlement_grace_seconds: u64,
    /// Background settlement scan interval.
    pub settlement_poll_seconds: u64,
    /// Seconds after a lease's issuance + TTL + grace by which an unsettled
    /// lease is finalized: a lease that may have been delivered at its measured
    /// (or, failing that, worst-case) charge. Written once per lease row.
    pub settlement_deadline_seconds: u64,
}

impl OpenRouterLeaseConfig {
    /// Every lease that may have been delivered must reach a Finalized
    /// transcript well inside the vault's escape challenge period:
    /// ttl + grace + deadline + 2*poll + slack <= challengePeriod / 2.
    pub fn validate_settlement_timing(&self, challenge_period_seconds: u64) -> anyhow::Result<()> {
        let minimum = self
            .settlement_grace_seconds
            .checked_add(MIN_SETTLEMENT_RETRY_WINDOW_SECONDS)
            .ok_or_else(|| anyhow::anyhow!("settlement grace overflows"))?;
        anyhow::ensure!(
            self.settlement_deadline_seconds >= minimum,
            "--openrouter-settlement-deadline-seconds ({}) must leave at least {} s of retries after the settlement grace ({} s)",
            self.settlement_deadline_seconds,
            MIN_SETTLEMENT_RETRY_WINDOW_SECONDS,
            self.settlement_grace_seconds
        );
        let bound = self
            .ttl_seconds
            .checked_add(self.settlement_grace_seconds)
            .and_then(|value| value.checked_add(self.settlement_deadline_seconds))
            .and_then(|value| {
                value.checked_add(self.settlement_poll_seconds.max(1).checked_mul(2)?)
            })
            .and_then(|value| value.checked_add(SETTLEMENT_SWEEP_SLACK_SECONDS))
            .ok_or_else(|| anyhow::anyhow!("lease settlement timing overflows"))?;
        anyhow::ensure!(
            bound <= challenge_period_seconds / 2,
            "refusing to start: lease TTL ({} s) + settlement grace ({} s) + settlement deadline ({} s) + 2 x poll ({} s) + {} s = {} s exceeds half of the vault challengePeriod() ({} s); lower --openrouter-settlement-deadline-seconds or the lease TTL",
            self.ttl_seconds,
            self.settlement_grace_seconds,
            self.settlement_deadline_seconds,
            self.settlement_poll_seconds.max(1),
            SETTLEMENT_SWEEP_SLACK_SECONDS,
            bound,
            challenge_period_seconds
        );
        Ok(())
    }
}

/// Configuration for the zkAPI server.
#[derive(Clone)]
pub struct ServerConfig {
    /// Protocol version (must be 2).
    pub protocol_version: u16,
    /// Chain ID this server is bound to.
    pub chain_id: u64,
    /// Optional shared Sepolia service gate; contains only a redacted digest.
    pub testnet_password: Option<crate::testnet_auth::TestnetPassword>,
    /// On-chain contract address.
    pub contract_address: Felt252,
    /// Minimum proof-bound lease budget, in whole gwei.
    pub request_charge_cap: u128,
    /// HTTP listen address (e.g. "0.0.0.0:3000").
    pub listen_addr: String,
    /// Path to the SQLite database file.
    pub db_path: String,
    /// Required secret seed for the proof-friendly state-signing key. There is
    /// no default: zero means unset, and startup refuses any seed whose key is
    /// not the vault's immutable stateSigningKeyX/Y.
    pub state_seed: Felt252,
    /// Required secret seed for the clearance-signing key; startup requires
    /// its key to equal the vault's clearanceSigningKeyX/Y.
    pub clear_seed: Felt252,
    /// Initial Merkle root the server should accept until the indexer updates it.
    pub initial_root: Felt252,
    /// Optional base URL for an indexer that serves the latest tree root.
    pub indexer_url: Option<String>,
    /// Poll interval for indexer root refresh.
    pub root_poll_interval_ms: u64,
    /// Required prompt-private OpenRouter lease configuration.
    pub openrouter_leases: Option<OpenRouterLeaseConfig>,
    /// Required native ETH oracle configuration, checked before server startup.
    pub native_billing: Option<crate::native_billing::NativeBillingConfig>,
    /// Directory containing the v2 Groth16 proving/verifying key files.
    pub proof_setup_dir: String,
    /// Transitional: let POST /v2/withdraw/clearance reserve a nullifier
    /// without an ownership proof (older clients). Off by default.
    pub allow_legacy_clearance: bool,
    /// In-process cap on new proof-less clearance reservations per minute.
    pub legacy_clearance_max_per_minute: u32,
    /// How long after the server last observed a Merkle root a clearance
    /// ownership proof may still use it.
    pub clearance_root_window_seconds: u64,
    /// Start even though the database holds leases (or live direct-key
    /// deletions) of a lease key source other than the configured one, which
    /// this server can neither measure nor delete: each such lease is
    /// finalized at its settlement deadline without a usage measurement.
    /// Off by default; startup otherwise refuses until they drain.
    pub allow_key_source_switch: bool,
}

impl ServerConfig {
    pub fn validate_testnet_auth(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.testnet_password.is_none()
                || self.chain_id == crate::testnet_auth::SEPOLIA_CHAIN_ID,
            "ZKAPI_TESTNET_PASSWORD is only supported on Sepolia (chain ID 11155111)"
        );
        Ok(())
    }

    /// Reject incomplete native configurations before startup opens any state.
    pub fn validate_native_mode(&self) -> anyhow::Result<()> {
        self.validate_testnet_auth()?;
        anyhow::ensure!(
            self.native_billing.is_some(),
            "native ETH billing configuration is required"
        );
        anyhow::ensure!(
            self.openrouter_leases.is_some(),
            "native ETH requires prompt-private leases"
        );
        anyhow::ensure!(
            self.request_charge_cap > 0
                && self.request_charge_cap <= crate::native_billing::MAX_SAFE_UNITS,
            "native request cap must fit browser-safe gwei units"
        );
        anyhow::ensure!(
            (MIN_CLEARANCE_ROOT_WINDOW_SECONDS..=MAX_CLEARANCE_ROOT_WINDOW_SECONDS)
                .contains(&self.clearance_root_window_seconds),
            "--clearance-root-window-seconds must be between {MIN_CLEARANCE_ROOT_WINDOW_SECONDS} and {MAX_CLEARANCE_ROOT_WINDOW_SECONDS}"
        );
        Ok(())
    }
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive on purpose: a new field fails to compile here until its
        // author decides whether it is secret.
        let Self {
            protocol_version,
            chain_id,
            testnet_password,
            contract_address,
            request_charge_cap,
            listen_addr,
            db_path,
            state_seed: _,
            clear_seed: _,
            initial_root,
            indexer_url,
            root_poll_interval_ms,
            openrouter_leases,
            native_billing,
            proof_setup_dir,
            allow_legacy_clearance,
            legacy_clearance_max_per_minute,
            clearance_root_window_seconds,
            allow_key_source_switch,
        } = self;
        formatter
            .debug_struct("ServerConfig")
            .field("protocol_version", protocol_version)
            .field("chain_id", chain_id)
            .field("testnet_password", testnet_password)
            .field("contract_address", contract_address)
            .field("request_charge_cap", request_charge_cap)
            .field("listen_addr", listen_addr)
            .field("db_path", db_path)
            .field("state_seed", &"[redacted]")
            .field("clear_seed", &"[redacted]")
            .field("initial_root", initial_root)
            .field("indexer_url", indexer_url)
            .field("root_poll_interval_ms", root_poll_interval_ms)
            .field("openrouter_leases", openrouter_leases)
            // NativeBillingConfig's Debug redacts its RPC URL (provider API keys).
            .field("native_billing", native_billing)
            .field("proof_setup_dir", proof_setup_dir)
            .field("allow_legacy_clearance", allow_legacy_clearance)
            .field(
                "legacy_clearance_max_per_minute",
                legacy_clearance_max_per_minute,
            )
            .field(
                "clearance_root_window_seconds",
                clearance_root_window_seconds,
            )
            .field("allow_key_source_switch", allow_key_source_switch)
            .finish()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            protocol_version: 2,
            chain_id: 1,
            testnet_password: None,
            contract_address: Felt252::ZERO,
            request_charge_cap: 1_000_000,
            listen_addr: "0.0.0.0:3000".to_string(),
            db_path: "zkapi_server.db".to_string(),
            // Zero means unset; ServerSigner::try_new and run_server reject it.
            state_seed: Felt252::ZERO,
            clear_seed: Felt252::ZERO,
            initial_root: Felt252::ZERO,
            indexer_url: None,
            root_poll_interval_ms: 1_000,
            openrouter_leases: None,
            native_billing: None,
            proof_setup_dir: "protocol/setup/v2".to_string(),
            allow_legacy_clearance: false,
            legacy_clearance_max_per_minute: DEFAULT_LEGACY_CLEARANCE_MAX_PER_MINUTE,
            clearance_root_window_seconds: DEFAULT_CLEARANCE_ROOT_WINDOW_SECONDS,
            allow_key_source_switch: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_debug_redacts_signing_seeds_and_credentials() {
        let (state_seed, clear_seed) = crate::signer::strong_test_seeds();
        let mut config = ServerConfig {
            state_seed,
            clear_seed,
            testnet_password: Some(
                crate::testnet_auth::TestnetPassword::new("SECRET-TESTNET-PASSWORD").unwrap(),
            ),
            native_billing: Some(crate::native_billing::NativeBillingConfig {
                rpc_url: "https://eth-mainnet.example/v2/SECRET_PROVIDER_KEY".into(),
                ..crate::test_support::native_config()
            }),
            openrouter_leases: Some(OpenRouterLeaseConfig {
                source: OpenRouterLeaseSourceConfig::OpenRouter {
                    management_key: "sk-or-v1-SECRET_MANAGEMENT_KEY".into(),
                    api_base: "https://openrouter.example/api".into(),
                },
                ..crate::test_support::lease_config()
            }),
            ..Default::default()
        };
        let mut rendered = vec![format!("{config:?}"), format!("{config:#?}")];
        config.openrouter_leases = Some(crate::test_support::lease_config());
        rendered.push(format!("{config:#?}"));
        for output in rendered {
            for secret in [
                state_seed.to_hex(),
                clear_seed.to_hex(),
                state_seed.to_hex()[2..].to_string(),
                clear_seed.to_hex()[2..].to_string(),
                "SECRET_PROVIDER_KEY".into(),
                "SECRET_MANAGEMENT_KEY".into(),
                "SECRET-TESTNET-PASSWORD".into(),
                "test-secret".into(),
            ] {
                assert!(!output.contains(&secret), "{output}");
            }
            assert!(output.contains("[redacted]"));
            assert!(output.contains("chain_id"));
            assert!(output.contains("0x694aa1769357215de4fac081bf1f309adc325306"));
        }
    }

    #[test]
    fn settlement_timing_validation() {
        let lease = crate::test_support::lease_config();
        assert_eq!(
            lease.settlement_deadline_seconds,
            DEFAULT_SETTLEMENT_DEADLINE_SECONDS
        );
        // Defaults fit a 24 h challenge period: 300 + 0 + 21600 + 2 + 600.
        lease.validate_settlement_timing(86_400).unwrap();
        let cli_defaults = OpenRouterLeaseConfig {
            settlement_grace_seconds: 5,
            settlement_poll_seconds: 2,
            ..crate::test_support::lease_config()
        };
        cli_defaults.validate_settlement_timing(86_400).unwrap();
        // Exactly at the bound passes; one second over fails.
        let at_bound = 43_200 - (300 + 600 + 2);
        let mut tight = OpenRouterLeaseConfig {
            settlement_deadline_seconds: at_bound,
            ..crate::test_support::lease_config()
        };
        tight.validate_settlement_timing(86_400).unwrap();
        tight.settlement_deadline_seconds += 1;
        let error = tight
            .validate_settlement_timing(86_400)
            .unwrap_err()
            .to_string();
        assert!(error.contains("challengePeriod()"), "{error}");
        let long = OpenRouterLeaseConfig {
            settlement_deadline_seconds: 43_000,
            ..crate::test_support::lease_config()
        };
        assert!(long.validate_settlement_timing(86_400).is_err());
        // A short challenge period (e.g. a test vault) needs a short deadline.
        assert!(lease.validate_settlement_timing(3_600).is_err());
        // The deadline must leave a retry window after the drain grace.
        let short = OpenRouterLeaseConfig {
            settlement_grace_seconds: 120,
            settlement_deadline_seconds: 120 + MIN_SETTLEMENT_RETRY_WINDOW_SECONDS - 1,
            ..crate::test_support::lease_config()
        };
        let error = short
            .validate_settlement_timing(86_400)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must leave at least 900 s"), "{error}");
        let overflow = OpenRouterLeaseConfig {
            settlement_deadline_seconds: u64::MAX,
            ..crate::test_support::lease_config()
        };
        assert!(overflow.validate_settlement_timing(u64::MAX).is_err());
    }

    #[test]
    fn clearance_root_window_is_bounded() {
        let mut config = ServerConfig {
            native_billing: Some(crate::test_support::native_config()),
            openrouter_leases: Some(crate::test_support::lease_config()),
            ..Default::default()
        };
        assert!(!config.allow_legacy_clearance);
        assert_eq!(config.legacy_clearance_max_per_minute, 60);
        config.validate_native_mode().unwrap();
        for window in [0, 59, 86_401] {
            config.clearance_root_window_seconds = window;
            assert!(config.validate_native_mode().is_err(), "{window}");
        }
        for window in [60, 86_400] {
            config.clearance_root_window_seconds = window;
            config.validate_native_mode().unwrap();
        }
    }
}
