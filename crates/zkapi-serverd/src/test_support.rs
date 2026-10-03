//! Native lease fixtures; never compiled into the server binary.
use crate::config::{
    OpenRouterLeaseConfig, OpenRouterLeaseSourceConfig, ServerConfig,
    DEFAULT_SETTLEMENT_DEADLINE_SECONDS,
};
use crate::native_billing::NativeBillingConfig;

/// A settlement deadline no lifecycle test reaches. Most lifecycle fixtures
/// use 1970 timestamps, which a real deadline would force-finalize at once.
pub(crate) const TEST_DEADLINE_DISABLED: u64 = u64::MAX / 4;

pub(crate) fn native_config() -> NativeBillingConfig {
    NativeBillingConfig {
        rpc_url: "http://127.0.0.1:9".into(),
        feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
        decimals: 8,
        max_age_seconds: 4500,
    }
}

pub(crate) fn lease_config() -> OpenRouterLeaseConfig {
    OpenRouterLeaseConfig {
        source: OpenRouterLeaseSourceConfig::OaOrg {
            org_base_url: "http://127.0.0.1:9".into(),
            shared_secret: "test-secret".into(),
        },
        ttl_seconds: 300,
        settlement_grace_seconds: 0,
        settlement_poll_seconds: 1,
        settlement_deadline_seconds: DEFAULT_SETTLEMENT_DEADLINE_SECONDS,
    }
}

pub(crate) fn lease_payload(config: &ServerConfig, now: u64) -> String {
    let native = config.native_billing.as_ref().unwrap();
    // A fixed $1000/ETH test quote makes one micro-USD equal one gwei.
    serde_json::json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":{
        "asset":"native_eth", "units_per_eth":1_000_000_000, "chain_id":config.chain_id,
        "feed_address":native.feed_address, "round_id":"123", "answer":"100000000000",
        "decimals":native.decimals, "updated_at":now, "expires_at":now+native.max_age_seconds,
    }})
    .to_string()
}

/// A genesis browser note under `processor`'s deployment and keys, as the
/// only leaf of a fresh tree whose root the processor has observed.
pub(crate) fn browser_note(
    processor: &crate::processor::RequestProcessor,
    deposit: u128,
) -> (
    zkapi_browser::BrowserWalletConfig,
    zkapi_browser::BrowserNoteState,
    zkapi_core::merkle::MerkleTree,
) {
    let config = processor.config();
    let wallet = zkapi_browser::BrowserWalletConfig {
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        request_charge_cap: config.request_charge_cap,
        policy_charge_cap: config.request_charge_cap,
        policy_enabled: false,
        state_signing_key: processor.state_signing_key(),
        clearance_signing_key: processor.clearance_signing_key(),
    };
    let params = zkapi_browser::generate_deposit_params();
    let state = zkapi_browser::confirm_deposit(
        &wallet,
        zkapi_browser::ConfirmDepositArgs {
            secret: params.secret,
            note_id: 0,
            amount: deposit,
            expiry_ts: 4_000_000_000,
        },
    )
    .unwrap();
    let mut tree = zkapi_core::merkle::MerkleTree::new();
    tree.set_leaf(
        0,
        zkapi_core::v2::note_leaf(0, &params.registration_commitment, deposit, 4_000_000_000),
    );
    processor.update_root(tree.root());
    (wallet, state, tree)
}

/// Real escape-form withdrawal proofs for clearance tests. Proving is slow in
/// debug builds, so each is generated once per test binary.
pub(crate) struct OwnershipFixture {
    pub(crate) wallet: zkapi_browser::BrowserWalletConfig,
    pub(crate) state: zkapi_browser::BrowserNoteState,
    /// The note's tree root (the processor fixture must observe it).
    pub(crate) root: zkapi_types::Felt252,
    pub(crate) destination: [u8; 20],
    pub(crate) plan: zkapi_browser::WithdrawalPlan,
}

/// Deployment of `ownership_processor`: the keys and identity the cached
/// proofs are bound to.
pub(crate) fn ownership_server_config() -> ServerConfig {
    ServerConfig {
        request_charge_cap: 1,
        contract_address: zkapi_types::Felt252::from_u64(1),
        native_billing: Some(native_config()),
        openrouter_leases: Some(lease_config()),
        proof_setup_dir: setup_directory(),
        ..Default::default()
    }
}

pub(crate) fn setup_directory() -> String {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/setup/v2")
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .to_string()
}

/// Seeds of `ownership_processor` (fixtures only; never served).
pub(crate) const OWNERSHIP_SEEDS: (u64, u64) = (11, 12);

fn ownership_signer() -> crate::signer::ServerSigner {
    crate::signer::ServerSigner::new(
        &zkapi_types::Felt252::from_u64(OWNERSHIP_SEEDS.0),
        &zkapi_types::Felt252::from_u64(OWNERSHIP_SEEDS.1),
    )
}

fn prove_ownership(fake_tree: bool) -> OwnershipFixture {
    let config = ownership_server_config();
    let signer = ownership_signer();
    let wallet = zkapi_browser::BrowserWalletConfig {
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        request_charge_cap: config.request_charge_cap,
        policy_charge_cap: config.request_charge_cap,
        policy_enabled: false,
        state_signing_key: signer.state_public_key(),
        clearance_signing_key: signer.clearance_public_key(),
    };
    let params = zkapi_browser::generate_deposit_params();
    let deposit = 1_950_000;
    let state = zkapi_browser::confirm_deposit(
        &wallet,
        zkapi_browser::ConfirmDepositArgs {
            secret: params.secret,
            note_id: 0,
            amount: deposit,
            expiry_ts: 4_000_000_000,
        },
    )
    .unwrap();
    let mut tree = zkapi_core::merkle::MerkleTree::new();
    tree.set_leaf(
        0,
        zkapi_core::v2::note_leaf(0, &params.registration_commitment, deposit, 4_000_000_000),
    );
    if fake_tree {
        // A genesis note in a tree that no vault ever had: the proof itself
        // verifies, but its root is unknown to the server and the vault.
        tree.set_leaf(1, zkapi_types::Felt252::from_u64(0xfa4e));
    }
    let destination = [0x11u8; 20];
    let key =
        std::fs::read(std::path::Path::new(&setup_directory()).join("withdrawal.pk")).unwrap();
    let plan = zkapi_browser::prepare_withdrawal(
        &wallet,
        &state,
        zkapi_browser::PrepareWithdrawalArgs {
            mode: "escape".into(),
            destination: format!("0x{}", hex::encode(destination)),
            active_root: tree.root(),
            merkle_siblings: tree.get_siblings(0).to_vec(),
            clearance: None,
        },
        &key,
    )
    .unwrap();
    OwnershipFixture {
        wallet,
        state,
        root: tree.root(),
        destination,
        plan,
    }
}

/// A real escape proof for a note in a tree the processor fixture observes.
pub(crate) async fn ownership_fixture() -> &'static OwnershipFixture {
    static FIXTURE: tokio::sync::OnceCell<OwnershipFixture> = tokio::sync::OnceCell::const_new();
    FIXTURE
        .get_or_init(|| async {
            tokio::task::spawn_blocking(|| prove_ownership(false))
                .await
                .unwrap()
        })
        .await
}

/// A real escape proof over a fake genesis tree: valid, but at a root no
/// vault knows.
pub(crate) async fn fake_tree_ownership_fixture() -> &'static OwnershipFixture {
    static FIXTURE: tokio::sync::OnceCell<OwnershipFixture> = tokio::sync::OnceCell::const_new();
    FIXTURE
        .get_or_init(|| async {
            tokio::task::spawn_blocking(|| prove_ownership(true))
                .await
                .unwrap()
        })
        .await
}
