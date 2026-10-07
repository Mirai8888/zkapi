//! End-to-end tests of the companion's exits against an in-process operator
//! (protocol server and indexer) and a simulated vault behind JSON-RPC: the
//! escape routes, the mutual close's decision, E0's bounds on a hanging
//! operator, the stale-device pre-check, the three path sources, E5 after a
//! raise and E6.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use zkapi_core::v2 as core;
use zkapi_proof::compact::{CompactSigner, WithdrawalVerifier};
use zkapi_types::{Felt252, WithdrawalPublicInputsV2C, MERKLE_DEPTH};

use super::*;
use crate::service::{AuthService, ConfirmDepositRequest, WithdrawalMode};

const SETUP_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/setup/v2-concession-dev"
);
const VAULT: [u8; 20] = [0x5a; 20];
const NOTE_ID: u32 = 3;
const DEPOSIT: u128 = 1_500_000;
const DESTINATION: &str = "0x2222222222222222222222222222222222222222";

/// The simulated vault and operator.
#[derive(Default)]
struct World {
    // Operator.
    nullifiers: HashMap<String, Value>,
    requests: HashMap<String, Value>,
    evidence: HashMap<String, Value>,
    clearance: Option<(u16, Value)>,
    hang: bool,
    operator_calls: usize,
    // Indexer.
    indexer_root: Felt252,
    indexer_path: Vec<Felt252>,
    // Chain.
    known_roots: HashSet<Felt252>,
    note_status: u8,
    pending: Option<chain::PendingEscape>,
    challenged: HashSet<Felt252>,
    logs: Vec<Value>,
    receipts: HashMap<String, Value>,
    block: u64,
    now: u64,
}

type Shared = Arc<Mutex<World>>;

fn word(value: impl Into<u128>) -> String {
    format!("{:064x}", value.into())
}

fn felt_word(value: &Felt252) -> String {
    hex::encode(value.0)
}

fn rpc_result(result: Value) -> Response {
    Json(json!({"jsonrpc": "2.0", "id": 1, "result": result})).into_response()
}

async fn rpc(State(world): State<Shared>, Json(body): Json<Value>) -> Response {
    let world = world.lock().unwrap();
    let params = &body["params"];
    match body["method"].as_str().unwrap_or("") {
        "eth_chainId" => rpc_result(json!("0x1")),
        "eth_getBlockByNumber" => {
            let tag = params[0].as_str().unwrap_or("latest");
            let (number, timestamp) = match tag {
                "finalized" => (world.block, world.now),
                _ => (world.block, world.now),
            };
            rpc_result(json!({
                "number": format!("0x{number:x}"),
                "timestamp": format!("0x{timestamp:x}"),
                "hash": format!("0x{}", "33".repeat(32)),
            }))
        }
        "eth_getTransactionReceipt" => rpc_result(
            world
                .receipts
                .get(params[0].as_str().unwrap_or(""))
                .cloned()
                .unwrap_or(Value::Null),
        ),
        "eth_getLogs" => {
            let filter = &params[0];
            let topic0: Vec<String> = match &filter["topics"][0] {
                Value::String(topic) => vec![topic.to_lowercase()],
                Value::Array(topics) => topics
                    .iter()
                    .filter_map(|topic| topic.as_str().map(str::to_lowercase))
                    .collect(),
                _ => Vec::new(),
            };
            let topic1 = filter["topics"][1].as_str().map(str::to_lowercase);
            let from = chain::quantity(&filter["fromBlock"]).unwrap_or(0);
            let to = chain::quantity(&filter["toBlock"]).unwrap_or(u64::MAX);
            let logs: Vec<Value> = world
                .logs
                .iter()
                .filter(|log| {
                    let block = chain::quantity(&log["blockNumber"]).unwrap();
                    let topics = log["topics"].as_array().unwrap();
                    block >= from
                        && block <= to
                        && (topic0.is_empty()
                            || topic0.contains(&topics[0].as_str().unwrap().to_lowercase()))
                        && topic1.as_ref().is_none_or(|expected| {
                            topics
                                .get(1)
                                .and_then(Value::as_str)
                                .is_some_and(|topic| topic.eq_ignore_ascii_case(expected))
                        })
                })
                .cloned()
                .collect();
            rpc_result(json!(logs))
        }
        "eth_call" => {
            let data = params[0]["data"].as_str().unwrap_or("");
            let selector = &data[2..10];
            let argument = &data[10..];
            let result = match selector {
                chain::NOTES => format!(
                    "0x{}{}{}{}",
                    word(0u8),
                    word(DEPOSIT),
                    word(4_000_000_000u64),
                    word(world.note_status)
                ),
                chain::PENDING_WITHDRAWALS => match world.pending {
                    Some(pending) => format!(
                        "0x{}{}{}{}{}{}{}",
                        word(1u8),
                        word(0u8),
                        felt_word(&pending.nullifier),
                        word(pending.final_balance),
                        "0".repeat(24),
                        hex::encode(pending.destination),
                        word(pending.deadline)
                    ),
                    None => format!("0x{}", "0".repeat(64 * 6)),
                },
                chain::PENDING_CONCESSIONS => match world.pending {
                    Some(pending) => format!(
                        "0x{}{}{}",
                        felt_word(&pending.next_nullifier),
                        word(pending.state_balance),
                        word(pending.conceded)
                    ),
                    None => format!("0x{}", "0".repeat(64 * 3)),
                },
                chain::CHALLENGED_NULLIFIERS => {
                    let nullifier = Felt252::from_hex(&format!("0x{argument}")).unwrap();
                    format!(
                        "0x{}",
                        word(u8::from(world.challenged.contains(&nullifier)))
                    )
                }
                chain::IS_KNOWN_ROOT => {
                    let root = Felt252::from_hex(&format!("0x{argument}")).unwrap();
                    format!("0x{}", word(u8::from(world.known_roots.contains(&root))))
                }
                chain::EFFECTIVE_EXPIRY => format!("0x{}", word(4_000_000_000u64)),
                _ => return (StatusCode::BAD_REQUEST, "unknown selector").into_response(),
            };
            rpc_result(json!(result))
        }
        _ => (StatusCode::BAD_REQUEST, "unknown method").into_response(),
    }
}

async fn operator_pause(world: &Shared) -> bool {
    let hang = {
        let mut world = world.lock().unwrap();
        world.operator_calls += 1;
        world.hang
    };
    if hang {
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
    hang
}

async fn nullifier_route(
    State(world): State<Shared>,
    AxumPath(nullifier): AxumPath<String>,
) -> Response {
    operator_pause(&world).await;
    let world = world.lock().unwrap();
    Json(
        world
            .nullifiers
            .get(&nullifier)
            .cloned()
            .unwrap_or(json!({"status": "not_found", "nullifier_status": "unknown"})),
    )
    .into_response()
}

async fn evidence_route(
    State(world): State<Shared>,
    AxumPath(nullifier): AxumPath<String>,
) -> Response {
    operator_pause(&world).await;
    let world = world.lock().unwrap();
    match world.evidence.get(&nullifier) {
        Some(body) => Json(body.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn request_route(State(world): State<Shared>, AxumPath(id): AxumPath<String>) -> Response {
    operator_pause(&world).await;
    let world = world.lock().unwrap();
    match world.requests.get(&id) {
        Some(body) => Json(body.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn clearance_route(State(world): State<Shared>) -> Response {
    operator_pause(&world).await;
    let world = world.lock().unwrap();
    match &world.clearance {
        Some((status, body)) => {
            (StatusCode::from_u16(*status).unwrap(), Json(body.clone())).into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"status": "error", "client_request_id": "", "error_code": "maintenance",
                "error_message": "down", "retriable": true}),
            ),
        )
            .into_response(),
    }
}

struct Harness {
    _directory: tempfile::TempDir,
    config: AuthConfig,
    service: Arc<AuthService>,
    world: Shared,
    server: tokio::task::JoinHandle<()>,
    secret: Felt252,
    leaf: Felt252,
    deposit_root: Felt252,
    deposit_siblings: Vec<Felt252>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Harness {
    /// A note deposited next to two others, confirmed with or without its
    /// deposit-time path.
    async fn new(keep_deposit_path: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let world: Shared = Arc::new(Mutex::new(World {
            note_status: 1,
            block: 100,
            now: now_seconds(),
            ..Default::default()
        }));
        let router = Router::new()
            .route("/rpc", post(rpc))
            .route("/v2/nullifiers/{nullifier}", get(nullifier_route))
            .route("/v2/nullifiers/{nullifier}/evidence", get(evidence_route))
            .route("/v2/requests/{id}", get(request_route))
            .route("/v2/withdraw/clearance", post(clearance_route))
            .route(
                "/v1/tree/root",
                get(|State(world): State<Shared>| async move {
                    Json(json!({"root": world.lock().unwrap().indexer_root}))
                }),
            )
            .route(
                "/v1/tree/notes/{note}/path",
                get(|State(world): State<Shared>| async move {
                    Json(json!({"siblings": world.lock().unwrap().indexer_path}))
                }),
            )
            .with_state(world.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            contract_address: zkapi_types::serialization::address_to_felt(&VAULT),
            protocol_server_url: url.clone(),
            indexer_url: url.clone(),
            demo_rpc_url: Some(format!("{url}/rpc")),
            proof_setup_dir: SETUP_DIR.into(),
            state_signing_key: CompactSigner::from_seed(&Felt252::from_u64(11)).public_key(),
            clearance_signing_key: CompactSigner::from_seed(&Felt252::from_u64(12)).public_key(),
            deploy_block: 1,
            ..Default::default()
        };
        // Notes 1 and 2 were deposited first; the tree is append-only.
        let secret = Felt252::from_u64(4242);
        let leaf = core::note_leaf(
            NOTE_ID,
            &core::registration_commitment(&secret),
            DEPOSIT,
            4_000_000_000,
        );
        let mut tree = zkapi_client::tree::SparseTree::new();
        let mut logs = Vec::new();
        for (index, (note, owner)) in [(1u32, 7u64), (2, 8), (NOTE_ID, 0)].into_iter().enumerate() {
            let commitment = if note == NOTE_ID {
                core::registration_commitment(&secret)
            } else {
                core::registration_commitment(&Felt252::from_u64(owner))
            };
            tree.set_leaf(
                note,
                core::note_leaf(note, &commitment, DEPOSIT, 4_000_000_000),
            );
            logs.push(json!({
                "address": format!("0x{}", hex::encode(VAULT)),
                "blockNumber": format!("0x{:x}", 10 + index),
                "logIndex": "0x0",
                "removed": false,
                "topics": [zkapi_client::tree::NOTE_DEPOSITED_TOPIC, format!("0x{}", word(note)),
                    format!("0x{}", felt_word(&commitment))],
                "data": format!("0x{}{}{}", word(DEPOSIT), word(4_000_000_000u64), felt_word(&tree.root())),
            }));
        }
        let deposit_root = tree.root();
        let deposit_siblings = tree.siblings(NOTE_ID).to_vec();
        {
            let mut world = world.lock().unwrap();
            world.logs = logs;
            world.known_roots.insert(deposit_root);
            world.indexer_root = deposit_root;
            world.indexer_path = deposit_siblings.clone();
        }
        let service = AuthService::new(config.clone()).unwrap();
        service
            .confirm_deposit(ConfirmDepositRequest {
                secret,
                note_id: NOTE_ID,
                amount: DEPOSIT,
                expiry_ts: 4_000_000_000,
                deposit_root: keep_deposit_path.then_some(deposit_root),
                deposit_siblings: keep_deposit_path.then(|| deposit_siblings.clone()),
            })
            .await
            .unwrap();
        Self {
            _directory: directory,
            config,
            service,
            world,
            server,
            secret,
            leaf,
            deposit_root,
            deposit_siblings,
        }
    }

    fn wallet(&self) -> zkapi_client::wallet::Wallet {
        super::super::load_wallet(&self.config).unwrap()
    }

    fn nullifier(&self) -> Felt252 {
        self.wallet().current_nullifier().unwrap()
    }

    /// A request at the current state with `bound`, sent `age` seconds ago;
    /// its journal stays pending.
    fn release_request(&self, bound: u128, age: u64) {
        let path = self.config.state_dir.join("note_state.json");
        let mut state = zkapi_client::note_state::NoteState::load(&path).unwrap();
        state.bound_at_state = bound;
        state.save(&path).unwrap();
        zkapi_client::journal::PendingRequestJournal::write(
            &self.config.state_dir.join("pending_journal.json"),
            &zkapi_client::journal::PendingRequestJournal {
                exists: true,
                client_request_id: "withheld".into(),
                nullifier: self.nullifier(),
                payload_hash: Felt252::ONE,
                user_rerandomization: Felt252::ONE,
                created_at_ms: now_seconds().saturating_sub(age) * 1_000,
                prepared_request: None,
            },
        )
        .unwrap();
    }

    fn set_reading(&self, status: &str) {
        let nullifier = self.nullifier();
        self.world.lock().unwrap().nullifiers.insert(
            nullifier.to_string(),
            json!({"status": "ok", "nullifier_status": status}),
        );
    }

    async fn prepare(
        &self,
        conceded: Option<&str>,
        early: Option<EarlyExit>,
    ) -> Result<Value, AuthError> {
        self.service
            .oa_escape_prepare(EscapePrepareRequest {
                destination: DESTINATION.into(),
                conceded: conceded.map(str::to_string),
                early_exit: early,
            })
            .await
    }

    /// What the vault does with `plan`'s calldata: verify it like the
    /// adapter, then record the pending escape.
    fn initiate(&self, plan: &Value) {
        let inputs: WithdrawalPublicInputsV2C =
            serde_json::from_value(plan["public_inputs"].clone()).unwrap();
        let proof: zkapi_types::wire::Groth16ProofWire =
            serde_json::from_value(plan["proof"].clone()).unwrap();
        let calldata = plan["calldata"].as_str().unwrap();
        assert_eq!(calldata.len(), 2 + 836 * 2);
        assert_eq!(
            calldata,
            chain::withdrawal_calldata(chain::INITIATE_ESCAPE, &inputs, &proof).unwrap()
        );
        assert_eq!(inputs.kind, 0);
        assert!(inputs.valid_until >= now_seconds());
        assert!(WithdrawalVerifier::load(SETUP_DIR)
            .unwrap()
            .verify(&inputs, &proof)
            .unwrap());
        let mut world = self.world.lock().unwrap();
        assert!(world.known_roots.contains(&inputs.active_root));
        world.note_status = 2;
        world.pending = Some(chain::PendingEscape {
            nullifier: inputs.withdrawal_nullifier,
            final_balance: inputs.final_balance,
            destination: inputs.destination,
            deadline: now_seconds() - 1,
            next_nullifier: inputs.next_nullifier,
            state_balance: inputs.final_balance + inputs.conceded,
            conceded: inputs.conceded,
        });
        world.block += 1;
    }

    /// `raiseEscapeConcession` to `conceded`.
    fn raise(&self, conceded: u128) {
        let mut world = self.world.lock().unwrap();
        let mut pending = world.pending.unwrap();
        pending.conceded = conceded;
        pending.final_balance = pending.state_balance - conceded;
        world.pending = Some(pending);
        world.block += 1;
        let block = world.block;
        world.logs.push(json!({
            "address": format!("0x{}", hex::encode(VAULT)),
            "blockNumber": format!("0x{block:x}"),
            "logIndex": "0x0",
            "removed": false,
            "topics": [chain::escape_concession_raised_topic(), format!("0x{}", word(NOTE_ID))],
            "data": format!("0x{}{}{}", felt_word(&pending.nullifier), word(conceded), word(pending.final_balance)),
        }));
    }

    /// `finalizeEscapeWithdrawal`, paying or (`credited`) crediting.
    fn finalize(&self, credited: bool) -> String {
        let mut world = self.world.lock().unwrap();
        let pending = world.pending.take().unwrap();
        world.note_status = 3;
        world.block += 1;
        let hash = format!("0x{}", "ab".repeat(32));
        let destination = format!("{}{}", "0".repeat(24), hex::encode(pending.destination));
        let mut logs = Vec::new();
        if credited {
            logs.push(json!({
                "address": format!("0x{}", hex::encode(VAULT)), "removed": false,
                "topics": [chain::escape_payout_deferred_topic(), format!("0x{}", word(NOTE_ID)), format!("0x{destination}")],
                "data": format!("0x{}", word(pending.final_balance)),
            }));
        }
        logs.push(json!({
            "address": format!("0x{}", hex::encode(VAULT)), "removed": false,
            "topics": [chain::escape_finalized_topic(), format!("0x{}", word(NOTE_ID))],
            "data": format!("0x{}{}{}", felt_word(&pending.nullifier), word(pending.final_balance), destination),
        }));
        let block = world.block;
        world.receipts.insert(
            hash.clone(),
            json!({"status": "0x1", "transactionHash": hash, "blockNumber": format!("0x{block:x}"),
                "blockHash": format!("0x{}", "33".repeat(32)), "logs": logs}),
        );
        hash
    }
}

/// E2 step 5 then E4 and E5: the operator refuses the clearance, the mutual
/// close turns into an escape conceding nothing, the owner confirms it, the
/// escape is proved from the deposit-time path with no indexer, initiated,
/// raised by the challenger, finalized; the payout matcher follows the raise
/// and the note closes, which releases the exit lock.
#[tokio::test]
async fn a_refused_clearance_escapes_and_a_raised_escape_finalizes() {
    let harness = Harness::new(true).await;
    let refused = harness
        .service
        .oa_prepare_withdrawal([0x22; 20], false)
        .await;
    let detail = match &refused {
        Err(AuthError::EscapeRequired(detail)) => detail.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(detail["reason"], "mutual_refused");
    assert_eq!(detail["conceded"], "0");
    // From now on the indexer serves a path at a root the vault never held:
    // the escape uses the deposit-time path, so no indexer read matters.
    harness.world.lock().unwrap().indexer_root = Felt252::from_u64(99);
    // The owner sees the decision before any escape proof exists.
    let decision = harness.prepare(None, None).await.unwrap();
    assert_eq!(decision["status"], "decision");
    assert_eq!(decision["conceded"], "0");
    assert_eq!(decision["payout"], DEPOSIT.to_string());
    let lock = harness.wallet().exit_lock().unwrap().unwrap();
    assert!(lock.released.iter().all(|proof| proof.kind == 2));
    // A concession the rules do not allow is refused.
    assert!(matches!(
        harness.prepare(Some("5"), None).await,
        Err(AuthError::ConcededMismatch(_))
    ));
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared");
    assert_eq!(plan["path_source"], "deposit");
    assert_eq!(
        plan["public_inputs"]["active_root"],
        json!(harness.deposit_root)
    );
    // Asking again hands out the same plan, not a second proof.
    let again = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(again["proof"], plan["proof"]);
    assert_eq!(
        harness
            .wallet()
            .exit_lock()
            .unwrap()
            .unwrap()
            .released
            .iter()
            .filter(|proof| proof.kind == 0)
            .count(),
        1
    );
    // No request proof while the escape is under way (C3).
    assert!(matches!(
        harness.wallet().check_request_allowed(),
        Err(zkapi_client::error::ClientError::ExitLocked)
    ));
    let submitted = harness
        .service
        .oa_escape_submit(format!("0x{}", "cd".repeat(32)))
        .await
        .unwrap();
    assert_eq!(submitted["phase"], "submitted");
    harness.initiate(&plan);
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(status["phase"], "pending");
    assert_eq!(status["payout"], DEPOSIT.to_string());
    // The challenger raises the concession; the status follows it.
    harness.raise(300);
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(status["payout"], (DEPOSIT - 300).to_string());
    assert_eq!(status["finalizable"], true);
    let hash = harness.finalize(false);
    let done = harness
        .service
        .oa_escape_finalize(hash.clone())
        .await
        .unwrap();
    assert_eq!(done["status"], "complete");
    assert_eq!(done["payout"], (DEPOSIT - 300).to_string());
    assert_eq!(done["conceded_final"], "300");
    // Nothing was released at this state, so any raise exceeds its bound.
    assert_eq!(done["concession_exceeded_bound"], true);
    assert!(harness.wallet().state().is_none());
    assert!(harness.wallet().exit_lock().unwrap().is_none());
    // The reservation the refused mutual close made is complete too.
    assert_eq!(
        harness.service.oa_withdrawal_status().await.unwrap()["phase"],
        "complete"
    );
    // Idempotent.
    harness.service.oa_escape_finalize(hash).await.unwrap();
}

/// E5: a finalized payout that matches neither B − c nor any raise is
/// refused, and nothing is closed; a credited payout is reported.
#[tokio::test]
async fn the_payout_matcher_refuses_unexplained_amounts_and_reports_credits() {
    let harness = Harness::new(true).await;
    harness.release_request(1_000, 100_000);
    harness.set_reading("unknown");
    let decision = harness.prepare(None, None).await.unwrap();
    // The request is old and the server knows nothing of it: fresh state,
    // an escape the owner asked for concedes nothing.
    assert_eq!(decision["conceded"], "0", "{decision}");
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    harness.initiate(&plan);
    // Paid less than B with no raise on record.
    {
        let mut world = harness.world.lock().unwrap();
        let mut pending = world.pending.unwrap();
        pending.final_balance -= 1;
        world.pending = Some(pending);
    }
    let hash = harness.finalize(true);
    let refused = harness.service.oa_escape_finalize(hash.clone()).await;
    assert!(
        matches!(refused, Err(AuthError::InvalidInput(_))),
        "{refused:?}"
    );
    assert!(harness.wallet().state().is_some());
    // The amount the raise explains is accepted, credited or not.
    let harness = Harness::new(true).await;
    harness.release_request(1_000, 100_000);
    harness.set_reading("unknown");
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    harness.initiate(&plan);
    harness.raise(800);
    let hash = harness.finalize(true);
    let done = harness.service.oa_escape_finalize(hash).await.unwrap();
    assert_eq!(done["payout_credited"], true);
    assert_eq!(done["concession_exceeded_bound"], false);
    assert!(done["claim_calldata"]
        .as_str()
        .unwrap()
        .starts_with("0x88c10aee"));
}

/// E3: a request withheld at the state makes the escape wait until T; the
/// owner may exit early conceding nothing or the bound; at T the escape
/// concedes the bound. The mutual close waits too.
#[tokio::test]
async fn a_withheld_request_waits_for_t_then_concedes_the_bound() {
    let harness = Harness::new(true).await;
    harness.release_request(1_000, 60);
    harness.set_reading("reserved");
    assert!(matches!(
        harness
            .service
            .oa_prepare_withdrawal([0x22; 20], false)
            .await,
        Err(AuthError::PendingSettlement)
    ));
    let waiting = harness.prepare(None, None).await.unwrap();
    assert_eq!(waiting["status"], "wait");
    let until = waiting["wait_until"].as_u64().unwrap();
    assert!(until > now_seconds() + 21_000 && until <= now_seconds() + 21_905 + 900);
    let early = harness
        .prepare(None, Some(EarlyExit::ConcedeNothing))
        .await
        .unwrap();
    assert_eq!(
        (early["status"].as_str(), early["conceded"].as_str()),
        (Some("decision"), Some("0"))
    );
    let early = harness
        .prepare(None, Some(EarlyExit::ConcedeBound))
        .await
        .unwrap();
    assert_eq!(early["conceded"], "1000");
    // A request sent long ago is past T: the bound is conceded.
    let harness = Harness::new(true).await;
    harness.release_request(1_000, 100_000);
    harness.set_reading("reserved");
    let decision = harness.prepare(None, None).await.unwrap();
    assert_eq!(
        (decision["conceded"].as_str(), decision["reason"].as_str()),
        (Some("1000"), Some("at_deadline"))
    );
    let plan = harness.prepare(Some("1000"), None).await.unwrap();
    assert_eq!(plan["payout"], (DEPOSIT - 1_000).to_string());
    assert_eq!(plan["public_inputs"]["conceded"], 1_000);
}

/// E0: an operator that hangs cannot hold the exit decision: every call is
/// bounded and counted as unreachable, and past must_initiate_by no
/// operator call is made at all.
#[tokio::test]
async fn a_hanging_operator_cannot_delay_the_exit() {
    let harness = Harness::new(true).await;
    harness.release_request(1_000, 60);
    harness.world.lock().unwrap().hang = true;
    let started = Instant::now();
    let decision = harness
        .prepare(None, Some(EarlyExit::ConcedeNothing))
        .await
        .unwrap();
    assert_eq!(decision["conceded"], "0");
    let plan = harness
        .prepare(Some("0"), Some(EarlyExit::ConcedeNothing))
        .await
        .unwrap();
    assert_eq!(plan["status"], "prepared");
    // Two decisions, each with a bounded recovery pass and reading, plus the
    // bounded pre-check and E1 reruns: far below the 30 s the operator hangs.
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "{:?}",
        started.elapsed()
    );

    // Past must_initiate_by: nothing is asked of the operator.
    let harness = Harness::new(true).await;
    let path = harness.config.state_dir.join("note_state.json");
    let mut state = zkapi_client::note_state::NoteState::load(&path).unwrap();
    state.expiry_ts = now_seconds() + 1_000;
    state.save(&path).unwrap();
    harness.world.lock().unwrap().hang = true;
    let calls = harness.world.lock().unwrap().operator_calls;
    let decision = harness.prepare(None, None).await.unwrap();
    assert_eq!(decision["reason"], "mutual_cutoff");
    assert_eq!(harness.world.lock().unwrap().operator_calls, calls);
}

/// E4 step 2: a request proof at N+ that verifies under the request key means
/// another device spent this state; an answer that does not verify is
/// ignored.
#[tokio::test]
async fn the_stale_device_pre_check_refuses_only_on_verified_evidence() {
    let harness = Harness::new(true).await;
    // A real request proof from the successor state, made by "another
    // device": a copy of the wallet that spent this state.
    let copy = tempfile::tempdir().unwrap();
    std::fs::copy(
        harness.config.state_dir.join("note_state.json"),
        copy.path().join("note_state.json"),
    )
    .unwrap();
    let mut other_config = harness.config.clone();
    other_config.state_dir = copy.path().to_path_buf();
    let mut other = super::super::load_wallet(&other_config).unwrap();
    let request = other
        .prepare_request_with_bound(
            "{}",
            zkapi_types::canonical_payload_hash(b"{}"),
            harness.deposit_root,
            harness.deposit_siblings.clone(),
            1_000,
        )
        .unwrap();
    let signer = CompactSigner::from_seed(&Felt252::from_u64(11));
    let anonymous = zkapi_types::wire::CurvePointWire {
        x: request.public_inputs.anonymous_commitment_x,
        y: request.public_inputs.anonymous_commitment_y,
    };
    let delta = zkapi_proof::compact::random_scalar();
    let next = zkapi_proof::compact::server_update(&anonymous, 10, &delta).unwrap();
    let anchor = core::next_anchor(&request.public_inputs.request_nullifier);
    let body = "{}".to_string();
    other
        .complete_pending_response(&zkapi_types::wire::RequestResponseV2 {
            status: "ok".into(),
            client_request_id: request.client_request_id.clone(),
            request_nullifier: request.public_inputs.request_nullifier,
            response_code: 200,
            response_hash: zkapi_types::canonical_response_hash(body.as_bytes()),
            response_payload: body,
            charge_applied: 10,
            next_commitment: next.clone(),
            next_anchor: anchor,
            blind_delta_srv: delta,
            next_state_signature: signer.sign(&core::state_message(
                2,
                1,
                &harness.config.contract_address,
                &next.x,
                &next.y,
                &anchor,
            )),
            policy_reason_code: None,
            policy_evidence_hash: None,
        })
        .unwrap();
    let spent = other
        .prepare_request_with_bound(
            "{}",
            zkapi_types::canonical_payload_hash(b"{}"),
            harness.deposit_root,
            harness.deposit_siblings.clone(),
            1_000,
        )
        .unwrap();
    let successor = harness.wallet().current_successor_nullifier().unwrap();
    assert_eq!(spent.public_inputs.request_nullifier, successor);
    // A forged answer (a proof that does not verify) is ignored.
    let mut forged = serde_json::to_value(&spent).unwrap();
    forged["public_inputs"]["request_time"] = json!(1);
    harness.world.lock().unwrap().evidence.insert(
        successor.to_string(),
        json!({"public_inputs": forged["public_inputs"], "proof": forged["proof"]}),
    );
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared");
    // Verified evidence refuses a new escape (here: after the first expired).
    let harness = Harness::new(true).await;
    harness.world.lock().unwrap().evidence.insert(
        successor.to_string(),
        json!({"public_inputs": spent.public_inputs, "proof": spent.proof}),
    );
    let refused = harness.prepare(Some("0"), None).await;
    assert!(
        matches!(refused, Err(AuthError::DeviceNotNewest)),
        "{refused:?}"
    );
    let lock = harness.wallet().exit_lock().unwrap().unwrap();
    assert!(lock.released.is_empty(), "nothing was released");
}

/// E4 step 1 without a saved path: the indexer's path only at a root the
/// vault knows, else a rebuild from the vault's logs.
#[tokio::test]
async fn without_a_deposit_path_the_escape_uses_a_known_root_or_rebuilds() {
    let harness = Harness::new(false).await;
    assert!(harness.wallet().deposit_path().is_none());
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["path_source"], "indexer");

    let harness = Harness::new(false).await;
    {
        let mut world = harness.world.lock().unwrap();
        // The indexer reports a root the vault never held (a lying or
        // diverged indexer).
        let mut lying = world.indexer_path.clone();
        lying[0] = Felt252::from_u64(5);
        world.indexer_path = lying;
        world.indexer_root = Felt252::from_u64(6);
    }
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["path_source"], "rebuild");
    assert_eq!(
        plan["public_inputs"]["active_root"],
        json!(harness.deposit_root)
    );
    assert_eq!(harness.leaf, harness.wallet().current_note_leaf().unwrap());
    let _ = harness.secret;
}

/// E6: an escape that never landed keeps the lock until its proof is dead at
/// a finalized block; then the lock is released and chats may resume.
#[tokio::test]
async fn an_escape_that_never_landed_releases_the_lock_once_dead() {
    let harness = Harness::new(true).await;
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    let valid_until = plan["valid_until"].as_u64().unwrap();
    let status = harness.service.oa_escape_status().await.unwrap();
    assert!(status["exit_lock"].is_object());
    assert!(matches!(
        harness.wallet().check_request_allowed(),
        Err(zkapi_client::error::ClientError::ExitLocked)
    ));
    harness.world.lock().unwrap().now = valid_until + 901;
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(status["phase"], "expired");
    assert!(harness.wallet().exit_lock().unwrap().is_none());
    harness.wallet().check_request_allowed().unwrap();
    // A defeat (another device spent the successor) is reported as such.
    let harness = Harness::new(true).await;
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    let nullifier: Felt252 = serde_json::from_value(plan["withdrawal_nullifier"].clone()).unwrap();
    harness.world.lock().unwrap().challenged.insert(nullifier);
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(status["phase"], "defeated");
    assert_eq!(status["error"], "device_not_newest");
}

/// C1: two services on one state directory (the bridge and, say, the exit
/// kit in one process) share the wallet's lock: an exit decision and a
/// request preparation never interleave. Either the request was durable
/// before the decision (which then sees it and waits), or the decision's
/// exit lock was durable before the request (which is refused). Without the
/// process-wide lock the two services would fail with wallet_busy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exit_decision_and_a_request_preparation_never_interleave() {
    for round in 0..4 {
        let harness = Harness::new(true).await;
        harness.set_reading("reserved");
        let second = AuthService::new(harness.config.clone()).unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let (exit_barrier, request_barrier) = (barrier.clone(), barrier.clone());
        let service = harness.service.clone();
        let exit = tokio::spawn(async move {
            exit_barrier.wait().await;
            service
                .oa_escape_prepare(EscapePrepareRequest {
                    destination: DESTINATION.into(),
                    conceded: None,
                    early_exit: None,
                })
                .await
        });
        let config = harness.config.clone();
        let request = tokio::spawn(async move {
            request_barrier.wait().await;
            if round % 2 == 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            second.request_through_lock(&config).await
        });
        let (exit, request) = (exit.await.unwrap(), request.await.unwrap());
        let decision = exit.expect("the decision never fails with wallet_busy");
        match request {
            // The request came first: the decision saw it (E3 waits).
            Ok(()) => assert_eq!(decision["status"], "wait", "round {round}: {decision}"),
            // The decision came first: no request proof under its lock.
            Err(AuthError::ExitLocked) => {
                assert_eq!(decision["status"], "decision", "round {round}: {decision}")
            }
            Err(other) => panic!("round {round}: {other:?}"),
        }
    }
}

impl AuthService {
    /// A request preparation through the wallet lock, as the lease path
    /// makes one (a real proof, the bound and the journal).
    async fn request_through_lock(&self, config: &AuthConfig) -> Result<(), AuthError> {
        let config = config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let indexer = self.indexer.clone();
        super::super::spawn_blocking(move || {
            let _guard = wallet_mutex.lock().unwrap();
            let _lockfile = super::super::acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = super::super::load_wallet(&config)?;
            let runtime = super::super::current_thread_runtime()?;
            let state = wallet.state().unwrap().clone();
            let (root, siblings) = runtime.block_on(async {
                Ok::<_, AuthError>((
                    indexer.root().await?,
                    indexer.note_path(state.note_id).await?,
                ))
            })?;
            wallet
                .prepare_request_with_bound(
                    "{}",
                    zkapi_types::canonical_payload_hash(b"{}"),
                    root,
                    siblings,
                    1_000,
                )
                .map(|_| ())
                .map_err(Into::into)
        })
        .await
    }
}

#[test]
fn merkle_depth_is_the_vaults() {
    assert_eq!(MERKLE_DEPTH, 32);
    let _ = WithdrawalMode::Escape;
}
