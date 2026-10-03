use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zkapi_serverd::config::{OpenRouterLeaseConfig, OpenRouterLeaseSourceConfig, ServerConfig};
use zkapi_serverd::signer::ServerSigner;
use zkapi_types::Felt252;

#[derive(Debug, Parser)]
#[command(name = "zkapi", about = "Native ETH zkAPI operator commands")]
struct Cli {
    #[arg(long, default_value_t = 2)]
    protocol_version: u16,
    #[arg(long, default_value_t = 1)]
    chain_id: u64,
    #[arg(long, default_value = "0x0")]
    contract_address: String,
    #[arg(long, default_value_t = 50_000)]
    request_charge_cap: u128,
    // Help must never print environment values (hide_env_values on every env arg).
    #[arg(
        long,
        env = "ZKAPI_PROOF_SETUP_DIR",
        default_value = "protocol/setup/v2",
        hide_env_values = true
    )]
    proof_setup_dir: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Generate a fresh development setup in a new directory.
    Setup {
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Derive the deployment-pinned public signing keys for the vault constructor.
    ///
    /// Reads ZKAPI_STATE_SEED and ZKAPI_CLEAR_SEED (preferred; flags are visible
    /// in the process list). Both are required hex field elements with no
    /// defaults. Zero, subgroup-order multiples, guessable values, the published
    /// development keys (seeds 0x1/0x2 in any spelling, in either role) and one
    /// seed reused for both roles are rejected. Generate each seed with:
    /// printf '0x%s\n' "$(openssl rand -hex 31)"
    SigningKeys {
        /// State-signing secret seed; overrides ZKAPI_STATE_SEED. No default.
        #[arg(long)]
        state_seed: Option<String>,
        /// Clearance-signing secret seed; overrides ZKAPI_CLEAR_SEED. No default.
        #[arg(long)]
        clear_seed: Option<String>,
    },
    /// Run the native ETH API server.
    ///
    /// ZKAPI_STATE_SEED and ZKAPI_CLEAR_SEED are required and have no
    /// defaults. Startup refuses unless their public keys equal the vault's
    /// immutable stateSigningKeyX/Y and clearanceSigningKeyX/Y, read over
    /// --native-billing-rpc-url, which must serve --chain-id.
    #[command(name = "serverd", alias = "server")]
    Serverd {
        #[arg(long, default_value = "127.0.0.1:3000")]
        listen: String,
        /// OpenRouter management API base for direct lease provisioning.
        #[arg(long, default_value = "https://openrouter.ai/api")]
        openrouter_api_base: String,
        /// OpenRouter Management API key used only to mint bounded runtime leases.
        #[arg(long)]
        openrouter_management_key: Option<String>,
        /// OA org base URL used to obtain station-issued, verifier-backed keys.
        #[arg(long)]
        oa_org_url: Option<String>,
        /// Validity of each prompt-private runtime key.
        #[arg(long, default_value_t = 300)]
        openrouter_lease_ttl_seconds: u64,
        /// Usage propagation delay after key expiry before settlement.
        #[arg(long, default_value_t = 5)]
        openrouter_settlement_grace_seconds: u64,
        #[arg(long, default_value_t = 2)]
        openrouter_settlement_poll_seconds: u64,
        /// Required native ETH oracle RPC for gwei billing and the startup vault
        /// signing-key check; must serve --chain-id. May embed a provider key.
        #[arg(
            long,
            env = "ZKAPI_NATIVE_BILLING_RPC_URL",
            required = true,
            hide_env_values = true
        )]
        native_billing_rpc_url: Option<String>,
        #[arg(
            long,
            env = "ZKAPI_NATIVE_PRICE_FEED_ADDRESS",
            required = true,
            hide_env_values = true
        )]
        native_price_feed_address: Option<String>,
        /// Must equal the published manifest's native price feed decimals.
        #[arg(
            long,
            env = "ZKAPI_NATIVE_PRICE_FEED_DECIMALS",
            default_value_t = 8,
            hide_env_values = true
        )]
        native_price_feed_decimals: u8,
        /// Must equal the published manifest's native_price_max_age_seconds.
        #[arg(
            long,
            env = "ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS",
            default_value_t = 4500,
            hide_env_values = true
        )]
        native_price_max_age_seconds: u64,
        #[arg(long, default_value = "zkapi-server.db")]
        db_path: String,
        /// Required state-signing secret seed; overrides ZKAPI_STATE_SEED
        /// (preferred; flags are visible in the process list). No default.
        #[arg(long)]
        state_seed: Option<String>,
        /// Required clearance-signing secret seed; overrides ZKAPI_CLEAR_SEED.
        /// No default.
        #[arg(long)]
        clear_seed: Option<String>,
        #[arg(long, default_value = "0x0")]
        initial_root: String,
        #[arg(long)]
        indexer_url: Option<String>,
        #[arg(long, default_value_t = 1_000)]
        root_poll_interval_ms: u64,
    },
    Indexer {
        #[arg(long, default_value = "127.0.0.1:3001")]
        listen: String,
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,
        #[arg(long)]
        contract_address: String,
        #[arg(long, default_value_t = 0)]
        from_block: u64,
        #[arg(long, default_value_t = 1_000)]
        poll_interval_ms: u64,
        #[arg(long)]
        cursor_path: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .init();

    let cli = Cli::parse();

    match cli.command.clone() {
        Commands::Setup { output_dir } => {
            anyhow::ensure!(
                !output_dir.exists(),
                "refusing to overwrite an existing setup directory"
            );
            zkapi_proof::compact::setup(&output_dir)?;
            print_json(&serde_json::json!({
                "status": "ok",
                "proof_backend": "groth16_bn254",
                "output_dir": output_dir,
            }))?;
        }
        Commands::SigningKeys {
            state_seed,
            clear_seed,
        } => {
            let (state_seed, clear_seed) =
                operator_signing_seeds(state_seed, clear_seed, |name| std::env::var(name).ok())?;
            let signer = ServerSigner::try_new(&state_seed, &clear_seed)?;
            print_json(&serde_json::json!({
                "state_signing_key": signer.state_public_key(),
                "clearance_signing_key": signer.clearance_public_key(),
            }))?;
        }
        Commands::Serverd {
            listen,
            openrouter_api_base,
            openrouter_management_key,
            oa_org_url,
            openrouter_lease_ttl_seconds,
            openrouter_settlement_grace_seconds,
            openrouter_settlement_poll_seconds,
            native_billing_rpc_url,
            native_price_feed_address,
            native_price_feed_decimals,
            native_price_max_age_seconds,
            db_path,
            state_seed,
            clear_seed,
            initial_root,
            indexer_url,
            root_poll_interval_ms,
        } => {
            // Fail fast, before any provider or oracle configuration; run_server
            // re-validates the seeds and checks their keys against the vault.
            let (state_seed, clear_seed) =
                operator_signing_seeds(state_seed, clear_seed, |name| std::env::var(name).ok())?;
            let openrouter_api_base_for_leases = openrouter_api_base.clone();
            let openrouter_management_key = resolve_secret(
                openrouter_management_key,
                std::env::var("ZKAPI_OPENROUTER_MANAGEMENT_KEY").ok(),
            );
            let oa_org_shared_secret =
                resolve_secret(None, std::env::var("ZKAPI_OA_ORG_SHARED_SECRET").ok());
            let lease_source = match (openrouter_management_key, oa_org_url, oa_org_shared_secret) {
                (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                    anyhow::bail!(
                        "configure either direct OpenRouter management or OA org key issuance, not both"
                    )
                }
                (Some(management_key), None, None) => {
                    Some(OpenRouterLeaseSourceConfig::OpenRouter {
                        management_key,
                        api_base: openrouter_api_base_for_leases,
                    })
                }
                (None, Some(org_base_url), Some(shared_secret)) => {
                    Some(OpenRouterLeaseSourceConfig::OaOrg {
                        org_base_url,
                        shared_secret,
                    })
                }
                (None, Some(_), None) => {
                    anyhow::bail!("--oa-org-url requires an OA org shared secret")
                }
                (None, None, Some(_)) => {
                    anyhow::bail!("an OA org shared secret requires --oa-org-url")
                }
                (None, None, None) => anyhow::bail!(
                    "configure an OA org or OpenRouter management credential for native leases"
                ),
            };
            let openrouter_leases = lease_source.map(|source| OpenRouterLeaseConfig {
                source,
                ttl_seconds: openrouter_lease_ttl_seconds,
                settlement_grace_seconds: openrouter_settlement_grace_seconds,
                settlement_poll_seconds: openrouter_settlement_poll_seconds,
            });
            let native_billing = match (native_billing_rpc_url, native_price_feed_address) {
                (Some(rpc_url), Some(feed_address)) => {
                    Some(zkapi_serverd::native_billing::NativeBillingConfig {
                        rpc_url,
                        feed_address: feed_address.to_lowercase(),
                        decimals: native_price_feed_decimals,
                        max_age_seconds: native_price_max_age_seconds,
                    })
                }
                _ => anyhow::bail!("native ETH requires both oracle RPC and pinned feed address"),
            };
            let config = ServerConfig {
                protocol_version: cli.protocol_version,
                chain_id: cli.chain_id,
                testnet_password: None, // Loaded from the private server environment at startup.
                contract_address: parse_felt("contract address", &cli.contract_address)?,
                request_charge_cap: cli.request_charge_cap,
                listen_addr: listen,
                db_path,
                state_seed,
                clear_seed,
                initial_root: parse_felt("initial root", &initial_root)?,
                indexer_url,
                root_poll_interval_ms,
                openrouter_leases,
                native_billing,
                proof_setup_dir: cli.proof_setup_dir.clone(),
            };
            zkapi_serverd::routes::run_server(config).await?;
        }
        Commands::Indexer {
            listen,
            rpc_url,
            contract_address,
            from_block,
            poll_interval_ms,
            cursor_path,
        } => {
            let config = zkapi_indexerd::IndexerConfig {
                listen_addr: listen,
                rpc_url,
                contract_address,
                from_block,
                poll_interval_ms,
                cursor_path,
            };
            zkapi_indexerd::run_indexer(config).await?;
        }
    }
    Ok(())
}

fn log_filter() -> tracing_subscriber::EnvFilter {
    const DEFAULT: &str = "warn,zkapi=info,zkapi_serverd=info,zkapi_indexerd=info";
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| DEFAULT.into());

    // ark-r1cs-std instruments fine-grained field operations at INFO under the
    // `r1cs` target. Enabling those spans while proving debug-formats growing
    // constraint systems, turning a ~3-second proof into multi-gigabyte work.
    // Keep them disabled even when a caller uses a broad `RUST_LOG=info`.
    suppress_r1cs_info(filter)
}

fn suppress_r1cs_info(filter: tracing_subscriber::EnvFilter) -> tracing_subscriber::EnvFilter {
    filter.add_directive("r1cs=warn".parse().expect("valid r1cs log directive"))
}

fn parse_felt(label: &str, value: &str) -> anyhow::Result<Felt252> {
    Felt252::from_hex(value).map_err(|err| anyhow::anyhow!("invalid {label}: {err}"))
}

fn resolve_secret(cli_value: Option<String>, env_value: Option<String>) -> Option<String> {
    cli_value.or(env_value).filter(|value| !value.is_empty())
}

/// A required signing seed: the flag wins, an explicit empty flag never falls
/// back to the environment, and there is no default. Never echoes the value.
fn required_seed(
    role: &str,
    flag: &str,
    env_name: &str,
    cli_value: Option<String>,
    env_value: Option<String>,
) -> anyhow::Result<Felt252> {
    let value = resolve_secret(cli_value, env_value).ok_or_else(|| {
        anyhow::anyhow!(
            "{env_name} (or {flag}) is required and must not be empty; there is no default {role} signing seed"
        )
    })?;
    // Felt252::from_hex accepts a sign and slices by byte offset (panicking on
    // non-ASCII text), so admit only plain hex digits before parsing.
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(&value);
    anyhow::ensure!(
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()),
        "{env_name} (or {flag}) must be a hex field element: an optional 0x followed by hex digits"
    );
    Felt252::from_hex(&value).map_err(|error| {
        anyhow::anyhow!("{env_name} (or {flag}) is not a valid {role} seed: {error}")
    })
}

/// Resolve both signing seeds and apply the operator key policy shared with
/// run_server: no zero, subgroup-order multiple, published development key,
/// guessable secret or reused key.
fn operator_signing_seeds(
    state_flag: Option<String>,
    clear_flag: Option<String>,
    env: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<(Felt252, Felt252)> {
    let state_seed = required_seed(
        "state",
        "--state-seed",
        "ZKAPI_STATE_SEED",
        state_flag,
        env("ZKAPI_STATE_SEED"),
    )?;
    let clear_seed = required_seed(
        "clearance",
        "--clear-seed",
        "ZKAPI_CLEAR_SEED",
        clear_flag,
        env("ZKAPI_CLEAR_SEED"),
    )?;
    ServerSigner::try_new(&state_seed, &clear_seed)
        .context("invalid signing seeds (ZKAPI_STATE_SEED / ZKAPI_CLEAR_SEED)")?;
    Ok((state_seed, clear_seed))
}

fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_wallet_and_auth_commands_are_rejected() {
        for command in [
            "client",
            "clientd",
            "keygen",
            "prepare-deposit",
            "confirm-deposit",
            "withdraw",
            "request",
        ] {
            assert!(Cli::try_parse_from(["zkapi", command]).is_err());
        }
        assert!(
            Cli::try_parse_from(["zkapi", "--auth-scheme", "blind-signature", "signing-keys"])
                .is_err()
        );
    }

    #[test]
    fn native_server_requires_oracle_and_feed() {
        assert!(Cli::try_parse_from(["zkapi", "serverd"]).is_err());
        assert!(Cli::try_parse_from([
            "zkapi",
            "serverd",
            "--native-billing-rpc-url",
            "https://rpc.example"
        ])
        .is_err());
        let cli = Cli::try_parse_from([
            "zkapi",
            "--chain-id",
            "11155111",
            "serverd",
            "--native-billing-rpc-url",
            "https://rpc.example",
            "--native-price-feed-address",
            "0x694AA1769357215DE4FAC081bf1f309aDC325306",
            "--oa-org-url",
            "https://org.example",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Serverd {
                native_billing_rpc_url: Some(_),
                native_price_feed_address: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn indexer_and_signing_commands_remain_available() {
        assert!(Cli::try_parse_from(["zkapi", "indexer", "--contract-address", "0x1234"]).is_ok());
        assert!(Cli::try_parse_from([
            "zkapi",
            "signing-keys",
            "--state-seed",
            STRONG_STATE_SEED,
            "--clear-seed",
            STRONG_CLEAR_SEED
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["zkapi", "setup"]).is_err());
    }

    // Independent 31-byte seeds that pass the operator key policy.
    const STRONG_STATE_SEED: &str =
        "0x5f3c8a91e2d4b7061a9c3e5f7082b4d6e8f0a1c3b5d7e9f1a2b4c6d8e0f1a3";
    const STRONG_CLEAR_SEED: &str =
        "0x1d7e4b2a9c6f3e8d5b0a7c4e1f9d6b3a8c5e2f7d4a1b9e6c3f8a5d2b7e4c19";

    fn env_with<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    fn state_seed(cli: Option<&str>, env: Option<&str>) -> anyhow::Result<Felt252> {
        required_seed(
            "state",
            "--state-seed",
            "ZKAPI_STATE_SEED",
            cli.map(str::to_string),
            env.map(str::to_string),
        )
    }

    #[test]
    fn signing_seeds_are_mandatory_and_empty_means_missing() {
        for (cli, env) in [
            (None, None),
            (Some(""), None),
            (None, Some("")),
            (Some(""), Some("")),
            (Some(""), Some(STRONG_STATE_SEED)),
        ] {
            let error = state_seed(cli, env).unwrap_err().to_string();
            assert!(
                error.contains("ZKAPI_STATE_SEED (or --state-seed) is required")
                    && error.contains("no default state signing seed"),
                "{cli:?}/{env:?}: {error}"
            );
        }
        // The flag wins over the environment; the environment fills an absent flag.
        let strong = |hex| Felt252::from_hex(hex).unwrap();
        assert_eq!(
            state_seed(Some(STRONG_STATE_SEED), Some(STRONG_CLEAR_SEED)).unwrap(),
            strong(STRONG_STATE_SEED)
        );
        assert_eq!(
            state_seed(None, Some(STRONG_CLEAR_SEED)).unwrap(),
            strong(STRONG_CLEAR_SEED)
        );
    }

    #[test]
    fn seed_values_are_validated_without_echo_or_panic() {
        // A smart quote pasted from a document used to panic inside Felt252::from_hex.
        let smart_quoted = format!("0x{}\u{201d}", "ab".repeat(30));
        let too_long = format!("0x{}", "c".repeat(65));
        for value in [
            smart_quoted.as_str(),
            too_long.as_str(),
            "seed-SECRET-VALUE",
            "+1",
            "0x+1",
            "-1",
            " 0x1",
            "0x1 ",
            "0x",
            "0X",
            "0xg1",
            "0x0x1",
        ] {
            let error = state_seed(Some(value), None).unwrap_err().to_string();
            assert!(error.contains("ZKAPI_STATE_SEED"), "{error}");
            for secret in [smart_quoted.as_str(), too_long.as_str(), "SECRET"] {
                assert!(!error.contains(secret), "{error}");
            }
        }
    }

    #[test]
    fn signing_keys_refuses_development_degenerate_and_reused_seeds() {
        let l = "0x60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1";
        let one_plus_l = "0x60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f2";
        let two_plus_3l = "0x12259d6b14729c0fa51e1a247090812301bcc928ab62ca1f3657c794ab6374d5";
        for (state, clear) in [
            ("0x1", STRONG_CLEAR_SEED),
            ("1", STRONG_CLEAR_SEED),
            ("0X1", STRONG_CLEAR_SEED),
            ("0x0001", STRONG_CLEAR_SEED),
            ("+1", STRONG_CLEAR_SEED),
            (one_plus_l, STRONG_CLEAR_SEED),
            (STRONG_STATE_SEED, "0x2"),
            (STRONG_STATE_SEED, two_plus_3l),
            ("0x2", "0x1"),
            ("0x0", STRONG_CLEAR_SEED),
            (l, STRONG_CLEAR_SEED),
            ("0x7", "0x8"),
            ("0xb", "0xc"),
            ("0x2a", STRONG_CLEAR_SEED),
            (STRONG_STATE_SEED, "0x63"),
            (STRONG_STATE_SEED, STRONG_STATE_SEED),
        ] {
            // Exactly as `zkapi signing-keys --state-seed .. --clear-seed ..` parses them.
            let cli = Cli::try_parse_from([
                "zkapi",
                "signing-keys",
                "--state-seed",
                state,
                "--clear-seed",
                clear,
            ])
            .unwrap();
            let Commands::SigningKeys {
                state_seed,
                clear_seed,
            } = cli.command
            else {
                panic!("expected signing-keys");
            };
            assert!(
                operator_signing_seeds(state_seed, clear_seed, |_| None).is_err(),
                "{state}/{clear}"
            );
        }
        let (state, clear) = operator_signing_seeds(
            Some(STRONG_STATE_SEED.into()),
            Some(STRONG_CLEAR_SEED.into()),
            |_| None,
        )
        .unwrap();
        assert_eq!(state, Felt252::from_hex(STRONG_STATE_SEED).unwrap());
        assert_eq!(clear, Felt252::from_hex(STRONG_CLEAR_SEED).unwrap());
    }

    #[test]
    fn serverd_explicit_empty_seed_never_falls_back_to_the_environment() {
        let cli = Cli::try_parse_from([
            "zkapi",
            "serverd",
            "--native-billing-rpc-url",
            "https://rpc.example",
            "--native-price-feed-address",
            "0x694AA1769357215DE4FAC081bf1f309aDC325306",
            "--state-seed",
            "",
        ])
        .unwrap();
        let Commands::Serverd {
            state_seed,
            clear_seed,
            ..
        } = cli.command
        else {
            panic!("expected serverd");
        };
        assert_eq!(state_seed.as_deref(), Some(""));
        let configured = [
            ("ZKAPI_STATE_SEED", STRONG_STATE_SEED),
            ("ZKAPI_CLEAR_SEED", STRONG_CLEAR_SEED),
        ];
        let error = operator_signing_seeds(state_seed, clear_seed, env_with(&configured))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("ZKAPI_STATE_SEED (or --state-seed) is required"),
            "{error}"
        );
        assert!(operator_signing_seeds(None, None, env_with(&configured)).is_ok());
        let swapped = [("ZKAPI_STATE_SEED", "0x2"), ("ZKAPI_CLEAR_SEED", "0x1")];
        let error = operator_signing_seeds(None, None, env_with(&swapped)).unwrap_err();
        assert!(format!("{error:#}").contains("published development key"));
    }

    #[test]
    fn seed_arguments_never_render_environment_values_in_help() {
        use clap::CommandFactory;
        let command = Cli::command();
        let mut env_backed = 0;
        for arg in command.get_arguments().chain(
            command
                .get_subcommands()
                .flat_map(|subcommand| subcommand.get_arguments()),
        ) {
            if arg.get_env().is_some() {
                env_backed += 1;
                assert!(arg.is_hide_env_values_set(), "{}", arg.get_id());
            }
        }
        assert!(env_backed >= 5);
        for name in ["signing-keys", "serverd"] {
            let mut subcommand = command.find_subcommand(name).unwrap().clone();
            for id in ["state_seed", "clear_seed"] {
                let arg = subcommand
                    .get_arguments()
                    .find(|arg| arg.get_id() == id)
                    .unwrap();
                assert!(arg.get_env().is_none(), "{name} {id}");
            }
            let help = subcommand.render_long_help().to_string();
            assert!(help.contains("ZKAPI_STATE_SEED"), "{help}");
            assert!(!help.contains("then 0x1") && !help.contains("then 0x2"));
        }
    }

    #[test]
    fn native_price_freshness_defaults_to_the_shipped_4500_seconds() {
        use clap::CommandFactory;
        let command = Cli::command();
        let serverd = command.find_subcommand("serverd").unwrap();
        for (id, env) in [
            (
                "native_price_max_age_seconds",
                "ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS",
            ),
            (
                "native_price_feed_decimals",
                "ZKAPI_NATIVE_PRICE_FEED_DECIMALS",
            ),
        ] {
            let arg = serverd
                .get_arguments()
                .find(|arg| arg.get_id() == id)
                .unwrap();
            assert_eq!(arg.get_env(), Some(std::ffi::OsStr::new(env)));
        }
        if std::env::var_os("ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS").is_some()
            || std::env::var_os("ZKAPI_NATIVE_PRICE_FEED_DECIMALS").is_some()
        {
            eprintln!("skipping default checks: ZKAPI_NATIVE_PRICE_* is set in this environment");
            return;
        }
        let parse = |extra: &[&str]| {
            let mut args = vec![
                "zkapi",
                "serverd",
                "--native-billing-rpc-url",
                "https://rpc.example",
                "--native-price-feed-address",
                "0x694AA1769357215DE4FAC081bf1f309aDC325306",
            ];
            args.extend_from_slice(extra);
            match Cli::try_parse_from(args).unwrap().command {
                Commands::Serverd {
                    native_price_max_age_seconds,
                    native_price_feed_decimals,
                    ..
                } => (native_price_max_age_seconds, native_price_feed_decimals),
                _ => panic!("expected serverd"),
            }
        };
        assert_eq!(parse(&[]), (4500, 8));
        assert_eq!(
            parse(&[
                "--native-price-max-age-seconds",
                "3600",
                "--native-price-feed-decimals",
                "18"
            ]),
            (3600, 18)
        );
    }
}
