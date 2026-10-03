//! Server configuration.

use zkapi_types::Felt252;

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
}
