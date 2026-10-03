//! SQLite-backed nullifier and transcript store.
//!
//! Stores nullifier reservations and finalized transcripts. Each nullifier
//! progresses through: Reserved -> Finalized (or ClearanceReserved for withdrawals).

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha3::{Digest, Keccak256};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use zkapi_types::wire::{ApiRequestV2, CurvePointWire};
use zkapi_types::{Felt252, NullifierStatus, SchnorrSignature};

use crate::error::ServerError;

/// A transcript record stored in the database.
#[derive(Debug, Clone)]
pub struct TranscriptRecord {
    pub nullifier: Felt252,
    pub status: NullifierStatus,
    pub reservation_kind: String,
    pub client_request_id: Option<String>,
    pub payload_hash: Option<Felt252>,
    pub charge_applied: Option<u128>,
    pub response_code: Option<u16>,
    pub response_payload: Option<String>,
    pub response_hash: Option<Felt252>,
    pub next_commitment_x: Option<Felt252>,
    pub next_commitment_y: Option<Felt252>,
    pub next_anchor: Option<Felt252>,
    pub blind_delta_srv: Option<Felt252>,
    pub next_state_sig: Option<SchnorrSignature>,
    pub policy_reason_code: Option<u32>,
    pub policy_evidence_hash: Option<Felt252>,
    pub proof_blob: Option<Vec<u8>>,
    pub request_inputs_json: Option<String>,
    /// Domain-separated digest of the complete canonical v2 API request.
    /// Reserved retries must match this before proof verification is skipped.
    pub api_request_binding: Option<String>,
    pub created_at: u64,
    pub finalized_at: Option<u64>,
}

/// Whether an OA provisioning attempt can safely be cancelled without usage.
/// An absent key hash does not establish non-issuance: the upstream response
/// may have been lost after a key was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OaProvisioningOutcome {
    NotStarted,
    MayHaveIssued,
    ConfirmedUnissued,
}

impl OaProvisioningOutcome {
    fn from_db(value: &str) -> Self {
        match value {
            "not_started" => Self::NotStarted,
            "confirmed_unissued" => Self::ConfirmedUnissued,
            // Historical rows and unknown values must never enable a refund.
            _ => Self::MayHaveIssued,
        }
    }
}

/// Durable metadata for one prompt-private OpenRouter lease. The plaintext
/// runtime key is deliberately never stored.
#[derive(Debug, Clone)]
pub struct OpenRouterLeaseRecord {
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub api_request: ApiRequestV2,
    /// Native OA requests use a deployment/proof-bound upstream namespace.
    /// Optional for decoding historical rows; new OA leases require a bound ID.
    pub oa_client_request_id: Option<String>,
    pub key_hash: Option<String>,
    pub key_source: String,
    pub(crate) oa_provisioning_outcome: OaProvisioningOutcome,
    pub status: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub settle_after: u64,
    pub spending_limit_usd: f64,
    pub usage_usd: Option<f64>,
    pub charge_applied: Option<u128>,
    pub last_error: Option<String>,
    /// Lease TTL frozen at creation; None for rows from before it was kept.
    pub ttl_seconds: Option<u64>,
    /// Write-once settlement deadline; None until first assigned.
    pub settlement_deadline_at: Option<u64>,
    /// Failed settlement attempts, never reset.
    pub settlement_attempts: u64,
    /// First failed settlement attempt, never reset by phase transitions.
    pub first_error_at: Option<u64>,
    /// "measured", "clamped", "worst_case" or "unissued" once finalized.
    pub charge_basis: Option<String>,
    /// Key provenance: Some(true) once the runtime key was returned to the
    /// client; Some(false) while it never was (including issuer-side
    /// activations); None for rows recorded without provenance.
    pub delivered: Option<bool>,
    pub updated_at: u64,
}

/// A new lease row; see `NullifierStore::create_openrouter_lease_bound`.
pub struct NewOpenRouterLease<'a> {
    pub request: &'a ApiRequestV2,
    pub key_source: &'a str,
    pub issued_at: u64,
    pub expires_at: u64,
    pub settle_after: u64,
    pub spending_limit_usd: f64,
    pub oa_client_request_id: Option<&'a str>,
    pub ttl_seconds: Option<u64>,
    /// Written once: never changed by later transitions.
    pub settlement_deadline_at: Option<u64>,
    /// Some(false) for issuance rows: delivered only once marked.
    pub delivered: Option<bool>,
}

/// An operator-visible record of a settlement that needs review: a clamped
/// or worst-case charge, a key that could not be deleted first, or a corrupt
/// binding that was cancelled without signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementReview {
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub key_source: String,
    /// One of `SETTLEMENT_REVIEW_REASONS`.
    pub reason: String,
    pub charge_basis: Option<String>,
    /// Truncated to 500 characters when stored.
    pub detail: String,
    pub reported_usage_micro_usd: Option<u128>,
    pub charge_applied: Option<u128>,
    pub solvency_bound: u128,
}

/// The closed set of review reasons.
pub const SETTLEMENT_REVIEW_REASONS: &[&str] = &[
    "usage_clamped",
    "deadline_worst_case",
    "unsettleable_worst_case",
    "finalized_before_key_deletion",
    "binding_corrupt",
];

/// A stored review with its timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSettlementReview {
    pub review: SettlementReview,
    pub created_at: u64,
    pub acknowledged_at: Option<u64>,
}

/// A provider key of a terminal direct lease still to be disabled and
/// deleted: by hash when known, otherwise by the lease's request-unique name.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyCleanup<'a> {
    pub key_source: &'a str,
    pub key_hash: Option<&'a str>,
    pub key_name: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingKeyCleanup {
    pub client_request_id: String,
    pub key_source: String,
    pub key_hash: Option<String>,
    pub key_name: String,
    pub attempts: u64,
}

/// How a lease row is finalized; see `finalize_openrouter_lease_with`.
pub(crate) struct LeaseFinalization<'a> {
    pub usage_usd: f64,
    pub charge_applied: u128,
    pub charge_basis: &'a str,
    pub review: Option<&'a SettlementReview>,
    pub key_cleanup: Option<KeyCleanup<'a>>,
    /// Finalize only a never-issued row: still provisioning with no key.
    pub only_if_unissued: bool,
}

/// The deployment a server database serves (table `deployment_binding`, single
/// row id=1). serverd writes it only after verifying its derived signing keys
/// against the vault's immutable getters; zkapi-challenged requires it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentBinding {
    pub chain_id: u64,
    /// 0x followed by 40 lowercase hex digits.
    pub contract_address: String,
    pub state_signing_key: CurvePointWire,
    pub clearance_signing_key: CurvePointWire,
    pub challenge_period_seconds: u64,
    /// UNIX seconds of the successful vault read.
    pub verified_at: u64,
    pub verified_block: Option<u64>,
}

/// SQLite-backed nullifier store.
pub struct NullifierStore {
    conn: Mutex<Connection>,
}

/// Bind the complete semantically decoded v2 wire request. Serde emits struct
/// fields in declaration order, so equivalent JSON input has one canonical
/// representation while every downstream request field affects the digest.
pub(crate) fn api_request_binding(request: &ApiRequestV2) -> Result<String, ServerError> {
    let request = serde_json::to_vec(request).map_err(|error| {
        ServerError::Internal(format!("failed to serialize v2 request binding: {error}"))
    })?;
    let mut digest = Keccak256::new();
    digest.update(b"zkapi:v2:api-request-binding\0");
    digest.update(request);
    Ok(hex::encode(digest.finalize()))
}

impl NullifierStore {
    /// Open or create a nullifier store at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, ServerError> {
        let conn = Connection::open(path)
            .map_err(|e| ServerError::Database(format!("failed to open db: {}", e)))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS nullifiers (
                nullifier TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                reservation_kind TEXT NOT NULL DEFAULT 'proxy',
                client_request_id TEXT,
                payload_hash TEXT,
                charge_applied INTEGER,
                response_code INTEGER,
                response_payload TEXT,
                response_hash TEXT,
                next_commitment_x TEXT,
                next_commitment_y TEXT,
                next_anchor TEXT,
                blind_delta_srv TEXT,
                next_state_sig_epoch INTEGER,
                next_state_sig_root TEXT,
                next_state_sig_json TEXT,
                policy_reason_code INTEGER,
                policy_evidence_hash TEXT,
                proof_blob BLOB,
                request_inputs_json TEXT,
                api_request_binding TEXT,
                clearance_auth TEXT,
                created_at INTEGER NOT NULL,
                finalized_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS openrouter_leases (
                client_request_id TEXT PRIMARY KEY,
                request_nullifier TEXT NOT NULL UNIQUE,
                api_request_json TEXT NOT NULL,
                oa_client_request_id TEXT,
                key_hash TEXT UNIQUE,
                key_source TEXT NOT NULL DEFAULT 'openrouter',
                oa_provisioning_outcome TEXT NOT NULL DEFAULT 'may_have_issued',
                status TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                settle_after INTEGER NOT NULL,
                spending_limit_usd REAL NOT NULL,
                usage_usd REAL,
                charge_applied INTEGER,
                last_error TEXT,
                updated_at INTEGER NOT NULL,
                ttl_seconds INTEGER,
                settlement_deadline_at INTEGER,
                settlement_attempts INTEGER NOT NULL DEFAULT 0,
                first_error_at INTEGER,
                charge_basis TEXT,
                delivered INTEGER
            );
            CREATE TABLE IF NOT EXISTS deployment_binding (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                chain_id INTEGER NOT NULL,
                contract_address TEXT NOT NULL,
                state_key_x TEXT NOT NULL,
                state_key_y TEXT NOT NULL,
                clearance_key_x TEXT NOT NULL,
                clearance_key_y TEXT NOT NULL,
                challenge_period_seconds INTEGER NOT NULL,
                verified_at INTEGER NOT NULL,
                verified_block INTEGER
            );
            CREATE TABLE IF NOT EXISTS settlement_reviews (
                client_request_id TEXT PRIMARY KEY,
                request_nullifier TEXT NOT NULL,
                key_source TEXT NOT NULL,
                reason TEXT NOT NULL,
                charge_basis TEXT,
                detail TEXT NOT NULL,
                reported_usage_micro_usd TEXT,
                charge_applied INTEGER,
                solvency_bound TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                acknowledged_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS provider_key_cleanup (
                client_request_id TEXT PRIMARY KEY,
                key_source TEXT NOT NULL,
                key_hash TEXT,
                key_name TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL,
                last_error TEXT,
                created_at INTEGER NOT NULL
            );",
        )
        .map_err(|e| ServerError::Database(format!("failed to create table: {}", e)))?;

        // Checked, idempotent column migrations: a column a decoder reads by
        // name must exist, or opening fails instead of every row being
        // silently unreadable.
        for (table, column, definition) in [
            ("nullifiers", "next_state_sig_root", "TEXT"),
            ("nullifiers", "response_payload", "TEXT"),
            (
                "nullifiers",
                "reservation_kind",
                "TEXT NOT NULL DEFAULT 'proxy'",
            ),
            ("nullifiers", "api_request_binding", "TEXT"),
            ("nullifiers", "clearance_auth", "TEXT"),
            (
                "openrouter_leases",
                "key_source",
                "TEXT NOT NULL DEFAULT 'openrouter'",
            ),
            ("openrouter_leases", "oa_client_request_id", "TEXT"),
            ("openrouter_leases", "ttl_seconds", "INTEGER"),
            ("openrouter_leases", "settlement_deadline_at", "INTEGER"),
            (
                "openrouter_leases",
                "settlement_attempts",
                "INTEGER NOT NULL DEFAULT 0",
            ),
            ("openrouter_leases", "first_error_at", "INTEGER"),
            ("openrouter_leases", "charge_basis", "TEXT"),
            ("openrouter_leases", "delivered", "INTEGER"),
        ] {
            ensure_column(&conn, table, column, definition)?;
        }
        migrate_oa_provisioning_outcome(&conn)?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS openrouter_leases_status
                ON openrouter_leases(status, settle_after);
             CREATE INDEX IF NOT EXISTS openrouter_leases_deadline
                ON openrouter_leases(settlement_deadline_at);
             CREATE INDEX IF NOT EXISTS settlement_reviews_open
                ON settlement_reviews(acknowledged_at, created_at);",
        )
        .map_err(|e| ServerError::Database(format!("failed to create index: {e}")))?;
        backfill_openrouter_request_bindings(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory store (for testing).
    pub fn in_memory() -> Result<Self, ServerError> {
        Self::new(":memory:")
    }

    /// Open an existing server database for reading only: no DDL, migrations
    /// or backfills run, and every write fails. Refuses a schema that lacks a
    /// column the record decoders read, rather than misreporting evidence.
    pub fn open_read_only<P: AsRef<Path>>(path: P) -> Result<Self, ServerError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| ServerError::Database(format!("failed to open db read-only: {e}")))?;
        conn.execute_batch("PRAGMA query_only = ON")
            .map_err(|e| ServerError::Database(format!("failed to make db query-only: {e}")))?;
        for (table, required) in [
            ("nullifiers", TRANSCRIPT_RECORD_COLUMNS),
            ("openrouter_leases", OPENROUTER_LEASE_RECORD_COLUMNS),
        ] {
            let present = conn
                .prepare("SELECT name FROM pragma_table_info(?1)")
                .and_then(|mut statement| {
                    statement
                        .query_map([table], |row| row.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()
                })
                .map_err(|e| ServerError::Database(format!("schema check failed: {e}")))?;
            if required
                .iter()
                .any(|column| !present.iter().any(|name| name == column))
            {
                return Err(ServerError::Database(
                    "server database schema is older than this reader; upgrade and start the API server first"
                        .to_string(),
                ));
            }
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Record the vault-verified deployment this database serves.
    pub fn write_deployment_binding(&self, binding: &DeploymentBinding) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "INSERT INTO deployment_binding (
                id, chain_id, contract_address, state_key_x, state_key_y, clearance_key_x,
                clearance_key_y, challenge_period_seconds, verified_at, verified_block
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
                chain_id = excluded.chain_id, contract_address = excluded.contract_address,
                state_key_x = excluded.state_key_x, state_key_y = excluded.state_key_y,
                clearance_key_x = excluded.clearance_key_x,
                clearance_key_y = excluded.clearance_key_y,
                challenge_period_seconds = excluded.challenge_period_seconds,
                verified_at = excluded.verified_at, verified_block = excluded.verified_block",
            // u64 values above i64::MAX fail to bind instead of wrapping.
            params![
                binding.chain_id,
                binding.contract_address,
                binding.state_signing_key.x.to_hex(),
                binding.state_signing_key.y.to_hex(),
                binding.clearance_signing_key.x.to_hex(),
                binding.clearance_signing_key.y.to_hex(),
                binding.challenge_period_seconds,
                binding.verified_at,
                binding.verified_block,
            ],
        )
        .map_err(|error| {
            ServerError::Database(format!("deployment binding write failed: {error}"))
        })?;
        Ok(())
    }

    /// The recorded deployment, or None for a database that predates it.
    pub fn read_deployment_binding(&self) -> Result<Option<DeploymentBinding>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'deployment_binding')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| {
                ServerError::Database(format!("deployment binding lookup failed: {error}"))
            })?;
        if !exists {
            return Ok(None);
        }
        conn.query_row(
            "SELECT chain_id, contract_address, state_key_x, state_key_y, clearance_key_x,
                clearance_key_y, challenge_period_seconds, verified_at, verified_block
             FROM deployment_binding WHERE id = 1",
            [],
            row_to_deployment_binding,
        )
        .optional()
        .map_err(|error| ServerError::Database(format!("deployment binding read failed: {error}")))
    }

    /// Acquire the long-lived server writer lock for the actual SQLite file,
    /// not a possibly different config path. In-memory test stores are exempt.
    /// Ordinary store users such as the challenger do not acquire this lock.
    pub(crate) fn acquire_writer_lock(
        &self,
    ) -> Result<Option<crate::writer_lock::ServerWriterLock>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        match conn.path().filter(|path| !path.is_empty()) {
            Some(path) => crate::writer_lock::ServerWriterLock::acquire(Path::new(path)).map(Some),
            None => Ok(None),
        }
    }

    /// Reserve a nullifier. Returns Ok(()) if the nullifier was successfully reserved.
    /// Returns Err(Replay) if the nullifier already exists.
    #[cfg(test)]
    pub fn reserve(
        &self,
        nullifier: &Felt252,
        client_request_id: &str,
        payload_hash: &Felt252,
    ) -> Result<(), ServerError> {
        self.reserve_with_kind(nullifier, client_request_id, payload_hash, "proxy", None)
    }

    pub fn reserve_openrouter_lease(&self, request: &ApiRequestV2) -> Result<(), ServerError> {
        self.reserve_bound_v2(request, "openrouter_lease")
    }

    fn reserve_bound_v2(
        &self,
        request: &ApiRequestV2,
        reservation_kind: &str,
    ) -> Result<(), ServerError> {
        let binding = api_request_binding(request)?;
        self.reserve_with_kind(
            &request.public_inputs.request_nullifier,
            &request.client_request_id,
            &request.payload_hash,
            reservation_kind,
            Some(&binding),
        )
    }

    fn reserve_with_kind(
        &self,
        nullifier: &Felt252,
        client_request_id: &str,
        payload_hash: &Felt252,
        reservation_kind: &str,
        api_request_binding: Option<&str>,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        let now = current_timestamp();
        let null_hex = nullifier.to_hex();

        conn.execute(
            "INSERT INTO nullifiers (
                nullifier, status, reservation_kind, client_request_id, payload_hash,
                api_request_binding, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                null_hex,
                status_to_str(NullifierStatus::Reserved),
                reservation_kind,
                client_request_id,
                payload_hash.to_hex(),
                api_request_binding,
                now as i64,
            ],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return ServerError::Replay;
                }
            }
            ServerError::Database(format!("insert failed: {}", e))
        })?;

        Ok(())
    }

    /// Finalize a previously reserved nullifier with the full transcript.
    pub fn finalize(
        &self,
        nullifier: &Felt252,
        transcript: &TranscriptRecord,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        let now = current_timestamp();
        let null_hex = nullifier.to_hex();

        let sig_json = transcript
            .next_state_sig
            .as_ref()
            .map(|sig| serde_json::to_string(sig).unwrap_or_default());

        let rows = conn
            .execute(
                "UPDATE nullifiers SET
                    status = ?1,
                    charge_applied = ?2,
                    response_code = ?3,
                    response_payload = ?4,
                    response_hash = ?5,
                    next_commitment_x = ?6,
                    next_commitment_y = ?7,
                    next_anchor = ?8,
                    blind_delta_srv = ?9,
                    next_state_sig_epoch = ?10,
                    next_state_sig_root = ?11,
                    next_state_sig_json = ?12,
                    policy_reason_code = ?13,
                    policy_evidence_hash = ?14,
                    proof_blob = ?15,
                    request_inputs_json = ?16,
                    finalized_at = ?17
                 WHERE nullifier = ?18 AND status = ?19",
                params![
                    status_to_str(NullifierStatus::Finalized),
                    transcript.charge_applied.map(|c| c as i64),
                    transcript.response_code.map(|c| c as i32),
                    transcript.response_payload.as_deref(),
                    transcript.response_hash.map(|h| h.to_hex()),
                    transcript.next_commitment_x.map(|c| c.to_hex()),
                    transcript.next_commitment_y.map(|c| c.to_hex()),
                    transcript.next_anchor.map(|a| a.to_hex()),
                    transcript.blind_delta_srv.map(|b| b.to_hex()),
                    Option::<i32>::None,
                    Option::<String>::None,
                    sig_json,
                    transcript.policy_reason_code.map(|c| c as i32),
                    transcript.policy_evidence_hash.map(|h| h.to_hex()),
                    transcript.proof_blob.as_deref(),
                    transcript.request_inputs_json.as_deref(),
                    now as i64,
                    null_hex,
                    status_to_str(NullifierStatus::Reserved),
                ],
            )
            .map_err(|e| ServerError::Database(format!("finalize failed: {}", e)))?;

        if rows == 0 {
            return Err(ServerError::Internal(
                "nullifier not in Reserved state or does not exist".to_string(),
            ));
        }

        Ok(())
    }

    /// Look up a transcript record by nullifier.
    pub fn lookup_by_nullifier(&self, nullifier: &Felt252) -> Option<TranscriptRecord> {
        self.try_lookup_by_nullifier(nullifier).ok().flatten()
    }

    /// Like `lookup_by_nullifier`, but a lock or SQLite failure is an error,
    /// never a missing record.
    pub fn try_lookup_by_nullifier(
        &self,
        nullifier: &Felt252,
    ) -> Result<Option<TranscriptRecord>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        conn.query_row(
            "SELECT * FROM nullifiers WHERE nullifier = ?1",
            params![nullifier.to_hex()],
            row_to_record,
        )
        .optional()
        .map_err(|e| ServerError::Database(format!("nullifier lookup failed: {}", e)))
    }

    /// Look up a transcript record by client request ID.
    pub fn lookup_by_client_id(&self, client_request_id: &str) -> Option<TranscriptRecord> {
        let conn = self.conn.lock().ok()?;

        conn.query_row(
            "SELECT * FROM nullifiers WHERE client_request_id = ?1",
            params![client_request_id],
            row_to_record,
        )
        .optional()
        .ok()
        .flatten()
    }

    /// Reserve a nullifier for clearance (withdrawal signing). `auth` records
    /// how the caller proved note ownership: "ownership_proof" or "legacy".
    /// The reservation is permanent: the clearance signature never expires.
    pub fn reserve_clearance(&self, nullifier: &Felt252, auth: &str) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        let now = current_timestamp();
        let null_hex = nullifier.to_hex();

        conn.execute(
            "INSERT INTO nullifiers (nullifier, status, clearance_auth, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                null_hex,
                status_to_str(NullifierStatus::ClearanceReserved),
                auth,
                now as i64,
            ],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return ServerError::NullifierUsed;
                }
            }
            ServerError::Database(format!("clearance reserve failed: {}", e))
        })?;

        Ok(())
    }

    /// How a clearance reservation was authorized (None: before this was
    /// recorded, or not a clearance reservation).
    pub fn clearance_auth(&self, nullifier: &Felt252) -> Result<Option<String>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {e}")))?;
        conn.query_row(
            "SELECT clearance_auth FROM nullifiers WHERE nullifier = ?1",
            params![nullifier.to_hex()],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map(Option::flatten)
        .map_err(|e| ServerError::Database(format!("clearance lookup failed: {e}")))
    }

    /// Get all reserved (not yet finalized) entries, for crash recovery.
    pub fn get_reserved_entries(&self) -> Vec<TranscriptRecord> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut stmt = match conn.prepare("SELECT * FROM nullifiers WHERE status = ?1") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map(
            params![status_to_str(NullifierStatus::Reserved)],
            row_to_record,
        ) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Get all nullifiers (for challenge watcher).
    pub fn get_all_nullifiers(&self) -> Vec<TranscriptRecord> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut stmt = match conn.prepare("SELECT * FROM nullifiers") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map([], row_to_record) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Persist a lease before contacting OpenRouter, closing the normal crash
    /// window between nullifier reservation and external key provisioning.
    pub fn create_openrouter_lease(
        &self,
        request: &ApiRequestV2,
        key_source: &str,
        issued_at: u64,
        expires_at: u64,
        settle_after: u64,
        spending_limit_usd: f64,
    ) -> Result<(), ServerError> {
        self.create_openrouter_lease_with_oa_id(
            request,
            key_source,
            issued_at,
            expires_at,
            settle_after,
            spending_limit_usd,
            None,
        )
    }

    // Extends the legacy constructor without changing existing callers.
    #[allow(clippy::too_many_arguments)]
    pub fn create_openrouter_lease_with_oa_id(
        &self,
        request: &ApiRequestV2,
        key_source: &str,
        issued_at: u64,
        expires_at: u64,
        settle_after: u64,
        spending_limit_usd: f64,
        oa_client_request_id: Option<&str>,
    ) -> Result<(), ServerError> {
        self.create_openrouter_lease_bound(&NewOpenRouterLease {
            request,
            key_source,
            issued_at,
            expires_at,
            settle_after,
            spending_limit_usd,
            oa_client_request_id,
            ttl_seconds: None,
            settlement_deadline_at: None,
            delivered: None,
        })
    }

    /// Persist a lease with its frozen TTL and write-once settlement
    /// deadline. A row created without a deadline is assigned one, once, the
    /// first time the settler sees it.
    pub fn create_openrouter_lease_bound(
        &self,
        lease: &NewOpenRouterLease<'_>,
    ) -> Result<(), ServerError> {
        let request = lease.request;
        let request_json = serde_json::to_string(request).map_err(|error| {
            ServerError::Database(format!("lease serialization failed: {error}"))
        })?;
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "INSERT INTO openrouter_leases (
                client_request_id, request_nullifier, api_request_json, key_source, status,
                issued_at, expires_at, settle_after, spending_limit_usd, updated_at, oa_client_request_id,
                oa_provisioning_outcome, ttl_seconds, settlement_deadline_at, delivered
             ) VALUES (?1, ?2, ?3, ?4, 'provisioning', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                request.client_request_id,
                request.public_inputs.request_nullifier.to_hex(),
                request_json,
                lease.key_source,
                lease.issued_at as i64,
                lease.expires_at as i64,
                lease.settle_after as i64,
                lease.spending_limit_usd,
                current_timestamp() as i64,
                lease.oa_client_request_id,
                if lease.key_source == "oa_org" { "not_started" } else { "may_have_issued" },
                lease.ttl_seconds.map(sql_time),
                lease.settlement_deadline_at.map(sql_time),
                lease.delivered,
            ],
        )
        .map_err(|error| ServerError::Database(format!("lease insert failed: {error}")))?;
        Ok(())
    }

    /// Durably fence upstream I/O before sending an OA issuance request. Only
    /// the first attempt may establish confirmed non-issuance from a definitive
    /// rejection; a retry cannot erase an earlier ambiguous result. The caller
    /// must hold its issuance lock through the upstream call and classification.
    pub(crate) fn begin_oa_issuance(&self, client_request_id: &str) -> Result<bool, ServerError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                ServerError::Database(format!("OA issuance transaction failed: {error}"))
            })?;
        let prior = transaction
            .query_row(
                "SELECT oa_provisioning_outcome FROM openrouter_leases
                 WHERE client_request_id = ?1 AND key_source = 'oa_org'
                   AND status = 'provisioning' AND key_hash IS NULL",
                params![client_request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| {
                ServerError::Database(format!("OA issuance state read failed: {error}"))
            })?
            .ok_or_else(|| ServerError::Internal("lease cannot begin OA issuance".to_string()))?;
        let outcome = OaProvisioningOutcome::from_db(&prior);
        if outcome == OaProvisioningOutcome::ConfirmedUnissued {
            return Err(ServerError::Internal(
                "confirmed unissued lease cannot resume issuance".to_string(),
            ));
        }
        let rows = transaction
            .execute(
                "UPDATE openrouter_leases SET oa_provisioning_outcome = 'may_have_issued', updated_at = ?1
                 WHERE client_request_id = ?2 AND key_source = 'oa_org'
                   AND status = 'provisioning' AND key_hash IS NULL AND oa_provisioning_outcome = ?3",
                params![current_timestamp() as i64, client_request_id, prior],
            )
            .map_err(|error| ServerError::Database(format!("OA issuance fence failed: {error}")))?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "OA issuance state changed".to_string(),
            ));
        }
        transaction.commit().map_err(|error| {
            ServerError::Database(format!("OA issuance commit failed: {error}"))
        })?;
        Ok(outcome == OaProvisioningOutcome::NotStarted)
    }

    /// Mark a first attempt's definitive pre-issuance rejection for zero-charge
    /// recovery. This must never be called for an ambiguous or retried attempt.
    pub(crate) fn confirm_oa_unissued(&self, client_request_id: &str) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let now = current_timestamp() as i64;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases SET oa_provisioning_outcome = 'confirmed_unissued',
                    settle_after = ?1, updated_at = ?1
                 WHERE client_request_id = ?2 AND key_source = 'oa_org'
                   AND status = 'provisioning' AND key_hash IS NULL
                   AND oa_provisioning_outcome = 'may_have_issued'",
                params![now, client_request_id],
            )
            .map_err(|error| {
                ServerError::Database(format!("OA non-issuance update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "OA issuance state changed".to_string(),
            ));
        }
        Ok(())
    }

    pub fn update_openrouter_lease_timing(
        &self,
        client_request_id: &str,
        expires_at: u64,
        settle_after: u64,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases
                 SET expires_at = ?1, settle_after = ?2, updated_at = ?3
                 WHERE client_request_id = ?4 AND status = 'provisioning'",
                params![
                    expires_at as i64,
                    settle_after as i64,
                    current_timestamp() as i64,
                    client_request_id,
                ],
            )
            .map_err(|error| {
                ServerError::Database(format!("lease timing update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "lease was not in provisioning state".to_string(),
            ));
        }
        Ok(())
    }

    pub fn activate_openrouter_lease(
        &self,
        client_request_id: &str,
        key_hash: &str,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases
                 SET status = 'active', key_hash = ?1, updated_at = ?2
                 WHERE client_request_id = ?3 AND status = 'provisioning'",
                params![key_hash, current_timestamp() as i64, client_request_id],
            )
            .map_err(|error| ServerError::Database(format!("lease activation failed: {error}")))?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "lease was not in provisioning state".to_string(),
            ));
        }
        Ok(())
    }

    /// Record that the runtime key of an activated lease is being returned to
    /// the client. Only such a lease can be charged more than zero.
    pub(crate) fn mark_openrouter_lease_delivered(
        &self,
        client_request_id: &str,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases SET delivered = 1, updated_at = ?1
                 WHERE client_request_id = ?2 AND status = 'active'",
                params![current_timestamp() as i64, client_request_id],
            )
            .map_err(|error| {
                ServerError::Database(format!("lease delivery update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "lease was not active when its key was returned".to_string(),
            ));
        }
        Ok(())
    }

    /// Assign the write-once settlement deadline of a lease recorded without
    /// one (rows from before the upgrade) and return the stored value.
    pub(crate) fn assign_settlement_deadline(
        &self,
        client_request_id: &str,
        deadline: u64,
    ) -> Result<u64, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "UPDATE openrouter_leases SET settlement_deadline_at = ?1
             WHERE client_request_id = ?2 AND settlement_deadline_at IS NULL",
            params![sql_time(deadline), client_request_id],
        )
        .map_err(|error| ServerError::Database(format!("deadline assignment failed: {error}")))?;
        conn.query_row(
            "SELECT settlement_deadline_at FROM openrouter_leases WHERE client_request_id = ?1",
            params![client_request_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(|error| ServerError::Database(format!("deadline read failed: {error}")))?
        .map(|value| value.max(0) as u64)
        .ok_or_else(|| ServerError::Internal("lease deadline was not stored".into()))
    }

    /// Non-terminal leases still without a settlement deadline:
    /// (client_request_id, expires_at).
    pub(crate) fn leases_without_settlement_deadline(
        &self,
    ) -> Result<Vec<(String, u64)>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let mut statement = conn
            .prepare(
                "SELECT client_request_id, expires_at FROM openrouter_leases
                 WHERE settlement_deadline_at IS NULL
                   AND status NOT IN ('finalized', 'cancelled')",
            )
            .map_err(|error| ServerError::Database(format!("deadline scan failed: {error}")))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?.max(0) as u64,
                ))
            })
            .map_err(|error| ServerError::Database(format!("deadline scan failed: {error}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| ServerError::Database(format!("deadline scan failed: {error}")))
    }

    pub fn remove_failed_openrouter_lease(
        &self,
        client_request_id: &str,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "DELETE FROM openrouter_leases
             WHERE client_request_id = ?1 AND status = 'provisioning' AND key_hash IS NULL",
            params![client_request_id],
        )
        .map_err(|error| ServerError::Database(format!("lease cleanup failed: {error}")))?;
        Ok(())
    }

    pub fn lookup_openrouter_lease(
        &self,
        client_request_id: &str,
    ) -> Option<OpenRouterLeaseRecord> {
        self.try_lookup_openrouter_lease(client_request_id)
            .ok()
            .flatten()
    }

    /// Like `lookup_openrouter_lease`, but a lock, SQLite or decoding failure
    /// is an error, never a missing lease.
    pub fn try_lookup_openrouter_lease(
        &self,
        client_request_id: &str,
    ) -> Result<Option<OpenRouterLeaseRecord>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.query_row(
            "SELECT * FROM openrouter_leases WHERE client_request_id = ?1",
            params![client_request_id],
            row_to_openrouter_lease,
        )
        .optional()
        .map_err(|error| ServerError::Database(format!("lease lookup failed: {error}")))
    }

    /// Leases to settle now, least recently attempted first: delivered or
    /// possibly delivered leases after their drain (or settlement deadline),
    /// and never-issued provisioning rows of a known source, which finalize
    /// at zero. Unreadable rows are logged, never silently skipped; they are
    /// also counted by `settlement_counts`.
    pub fn due_openrouter_leases(&self, now: u64) -> Vec<OpenRouterLeaseRecord> {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                tracing::error!("settlement scan failed: database lock poisoned");
                return Vec::new();
            }
        };
        let mut statement = match conn.prepare(
            "SELECT * FROM openrouter_leases
             WHERE (status IN ('active', 'retiring', 'disabled', 'revoking')
                    AND (settle_after <= ?1 OR settlement_deadline_at <= ?1))
                OR (status = 'provisioning' AND key_hash IS NULL
                    AND key_source IN ('openrouter', 'oa_org')
                    AND (settle_after <= ?1 OR settlement_deadline_at <= ?1
                         OR oa_provisioning_outcome = 'confirmed_unissued'))
             ORDER BY updated_at ASC, settle_after ASC",
        ) {
            Ok(statement) => statement,
            Err(error) => {
                tracing::error!(error = %error, "settlement scan failed");
                return Vec::new();
            }
        };
        let rows = match statement.query_map(params![sql_time(now)], row_to_openrouter_lease) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(error = %error, "settlement scan failed");
                return Vec::new();
            }
        };
        rows.filter_map(|row| match row {
            Ok(lease) => Some(lease),
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "unreadable OpenRouter lease row cannot be settled; operator review required"
                );
                None
            }
        })
        .collect()
    }

    /// Record a failed settlement attempt. `first_error_at` is set once and
    /// never reset; `settlement_attempts` only grows.
    pub fn record_openrouter_lease_error(
        &self,
        client_request_id: &str,
        error: &str,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|cause| ServerError::Database(format!("lock poisoned: {cause}")))?;
        let now = current_timestamp() as i64;
        conn.execute(
            "UPDATE openrouter_leases SET last_error = ?1, updated_at = ?2,
                settlement_attempts = settlement_attempts + 1,
                first_error_at = COALESCE(first_error_at, ?2)
             WHERE client_request_id = ?3 AND status IN ('provisioning', 'active', 'retiring', 'disabled', 'revoking')",
            params![error, now, client_request_id],
        )
        .map_err(|cause| ServerError::Database(format!("lease error update failed: {cause}")))?;
        Ok(())
    }

    /// Persist the direct-key retirement state before each external side
    /// effect, so revocation and settlement resume after failures or restarts.
    pub fn advance_openrouter_retirement(
        &self,
        client_request_id: &str,
        from: &str,
        to: &str,
        settle_after: u64,
        usage_usd: Option<f64>,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases SET status = ?1, settle_after = ?2,
                usage_usd = COALESCE(?3, usage_usd), last_error = NULL, updated_at = ?4
             WHERE client_request_id = ?5 AND key_source = 'openrouter' AND status = ?6",
                params![
                    to,
                    settle_after as i64,
                    usage_usd,
                    current_timestamp() as i64,
                    client_request_id,
                    from
                ],
            )
            .map_err(|error| {
                ServerError::Database(format!("lease retirement update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "lease retirement state changed".to_string(),
            ));
        }
        Ok(())
    }

    pub fn finalize_openrouter_lease(
        &self,
        client_request_id: &str,
        usage_usd: f64,
        charge_applied: u128,
    ) -> Result<(), ServerError> {
        self.finalize_openrouter_lease_with(
            client_request_id,
            &LeaseFinalization {
                usage_usd,
                charge_applied,
                charge_basis: "measured",
                review: None,
                key_cleanup: None,
                only_if_unissued: false,
            },
        )
        .map(|_| ())
    }

    /// Finalize a lease row after its signed transcript committed, recording
    /// how the charge was determined, an optional review, and an optional
    /// provider-key cleanup, in one transaction. Returns false (and changes
    /// nothing) when the row is cancelled, or is no longer an unissued
    /// provisioning row for `only_if_unissued`.
    pub(crate) fn finalize_openrouter_lease_with(
        &self,
        client_request_id: &str,
        finalization: &LeaseFinalization<'_>,
    ) -> Result<bool, ServerError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ServerError::Database(format!("lease finalize failed: {error}")))?;
        let now = current_timestamp() as i64;
        let condition = if finalization.only_if_unissued {
            "status = 'provisioning' AND key_hash IS NULL"
        } else {
            "status != 'cancelled'"
        };
        let rows = transaction
            .execute(
                &format!(
                    "UPDATE openrouter_leases SET
                        status = 'finalized', usage_usd = ?1, charge_applied = ?2,
                        charge_basis = ?3, last_error = NULL, updated_at = ?4
                     WHERE client_request_id = ?5 AND {condition}"
                ),
                params![
                    finalization.usage_usd,
                    finalization.charge_applied as i64,
                    finalization.charge_basis,
                    now,
                    client_request_id,
                ],
            )
            .map_err(|error| ServerError::Database(format!("lease finalize failed: {error}")))?;
        if rows != 1 {
            return Ok(false);
        }
        if let Some(review) = finalization.review {
            insert_review(&transaction, review, now)?;
        }
        if let Some(cleanup) = finalization.key_cleanup {
            insert_key_cleanup(&transaction, client_request_id, &cleanup, now)?;
        }
        transaction
            .commit()
            .map_err(|error| ServerError::Database(format!("lease finalize failed: {error}")))?;
        Ok(true)
    }

    /// Mark a lease whose binding is corrupt as cancelled, with its review.
    /// Nothing is signed for it; its reservation stays Reserved.
    pub(crate) fn cancel_openrouter_lease(
        &self,
        client_request_id: &str,
        review: &SettlementReview,
    ) -> Result<(), ServerError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ServerError::Database(format!("lease cancel failed: {error}")))?;
        let now = current_timestamp() as i64;
        let rows = transaction
            .execute(
                "UPDATE openrouter_leases SET status = 'cancelled', last_error = ?1, updated_at = ?2
                 WHERE client_request_id = ?3
                   AND status IN ('provisioning', 'active', 'retiring', 'disabled', 'revoking')",
                params![truncate_detail(&review.detail), now, client_request_id],
            )
            .map_err(|error| ServerError::Database(format!("lease cancel failed: {error}")))?;
        if rows == 0 {
            // Already terminal: nothing to cancel or review.
            return Ok(());
        }
        insert_review(&transaction, review, now)?;
        transaction
            .commit()
            .map_err(|error| ServerError::Database(format!("lease cancel failed: {error}")))
    }

    /// Queue a terminal direct lease's provider key for background cleanup.
    pub(crate) fn enqueue_key_cleanup(
        &self,
        client_request_id: &str,
        cleanup: &KeyCleanup<'_>,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        insert_key_cleanup(
            &conn,
            client_request_id,
            cleanup,
            current_timestamp() as i64,
        )
    }

    /// Queued key cleanups whose next attempt is due, oldest first.
    pub(crate) fn due_key_cleanups(
        &self,
        now: u64,
        limit: usize,
    ) -> Result<Vec<PendingKeyCleanup>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let mut statement = conn
            .prepare(
                "SELECT client_request_id, key_source, key_hash, key_name, attempts
                 FROM provider_key_cleanup WHERE next_attempt_at <= ?1
                 ORDER BY next_attempt_at ASC LIMIT ?2",
            )
            .map_err(|error| ServerError::Database(format!("key cleanup scan failed: {error}")))?;
        let rows = statement
            .query_map(params![sql_time(now), limit as i64], |row| {
                Ok(PendingKeyCleanup {
                    client_request_id: row.get(0)?,
                    key_source: row.get(1)?,
                    key_hash: row.get(2)?,
                    key_name: row.get(3)?,
                    attempts: row.get::<_, i64>(4)?.max(0) as u64,
                })
            })
            .map_err(|error| ServerError::Database(format!("key cleanup scan failed: {error}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| ServerError::Database(format!("key cleanup scan failed: {error}")))
    }

    pub(crate) fn complete_key_cleanup(&self, client_request_id: &str) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "DELETE FROM provider_key_cleanup WHERE client_request_id = ?1",
            params![client_request_id],
        )
        .map_err(|error| ServerError::Database(format!("key cleanup update failed: {error}")))?;
        Ok(())
    }

    pub(crate) fn defer_key_cleanup(
        &self,
        client_request_id: &str,
        error: &str,
        next_attempt_at: u64,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|cause| ServerError::Database(format!("lock poisoned: {cause}")))?;
        conn.execute(
            "UPDATE provider_key_cleanup SET attempts = attempts + 1, last_error = ?1,
                next_attempt_at = ?2
             WHERE client_request_id = ?3",
            params![
                truncate_detail(error),
                sql_time(next_attempt_at),
                client_request_id
            ],
        )
        .map_err(|cause| ServerError::Database(format!("key cleanup update failed: {cause}")))?;
        Ok(())
    }

    /// Non-terminal leases, nearest settlement deadline first. Read-only.
    pub fn pending_openrouter_leases(
        &self,
        limit: usize,
    ) -> Result<Vec<OpenRouterLeaseRecord>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let mut statement = conn
            .prepare(
                "SELECT * FROM openrouter_leases
                 WHERE status NOT IN ('finalized', 'cancelled')
                 ORDER BY settlement_deadline_at IS NULL, settlement_deadline_at, expires_at
                 LIMIT ?1",
            )
            .map_err(|error| {
                ServerError::Database(format!("pending lease scan failed: {error}"))
            })?;
        let rows = statement
            .query_map(params![limit as i64], row_to_openrouter_lease)
            .map_err(|error| {
                ServerError::Database(format!("pending lease scan failed: {error}"))
            })?;
        // A view: unreadable rows are reported by settlement_counts instead.
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Settlement reviews, newest first. Read-only.
    pub fn settlement_reviews(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredSettlementReview>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let mut statement = conn
            .prepare(
                "SELECT client_request_id, request_nullifier, key_source, reason, charge_basis,
                    detail, reported_usage_micro_usd, charge_applied, solvency_bound, created_at,
                    acknowledged_at
                 FROM settlement_reviews ORDER BY created_at DESC, client_request_id LIMIT ?1",
            )
            .map_err(|error| ServerError::Database(format!("review scan failed: {error}")))?;
        let rows = statement
            .query_map(params![limit as i64], |row| {
                let decimal = |value: Option<String>| value.and_then(|v| v.parse::<u128>().ok());
                Ok(StoredSettlementReview {
                    review: SettlementReview {
                        client_request_id: row.get(0)?,
                        request_nullifier: Felt252::from_hex(&row.get::<_, String>(1)?)
                            .unwrap_or(Felt252::ZERO),
                        key_source: row.get(2)?,
                        reason: row.get(3)?,
                        charge_basis: row.get(4)?,
                        detail: row.get(5)?,
                        reported_usage_micro_usd: decimal(row.get(6)?),
                        charge_applied: row.get::<_, Option<i64>>(7)?.map(|value| value as u128),
                        solvency_bound: decimal(row.get(8)?).unwrap_or_default(),
                    },
                    created_at: row.get::<_, i64>(9)?.max(0) as u64,
                    acknowledged_at: row.get::<_, Option<i64>>(10)?.map(|value| value as u64),
                })
            })
            .map_err(|error| ServerError::Database(format!("review scan failed: {error}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| ServerError::Database(format!("review scan failed: {error}")))
    }

    /// Aggregate settlement state from raw SQL, so rows that cannot be
    /// decoded are still counted. Read-only.
    pub fn settlement_counts(
        &self,
        now: u64,
    ) -> Result<crate::dashboard::SettlementCounts, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let count = |sql: &str| -> Result<u64, ServerError> {
            conn.query_row(sql, [], |row| row.get::<_, i64>(0))
                .map(|value| value.max(0) as u64)
                .map_err(|error| ServerError::Database(format!("settlement count failed: {error}")))
        };
        let pending = count(
            "SELECT COUNT(*) FROM openrouter_leases WHERE status NOT IN ('finalized', 'cancelled')",
        )?;
        let retrying = count(
            "SELECT COUNT(*) FROM openrouter_leases
             WHERE status NOT IN ('finalized', 'cancelled')
               AND (settlement_attempts > 0 OR last_error IS NOT NULL)",
        )?;
        let provisioning =
            count("SELECT COUNT(*) FROM openrouter_leases WHERE status = 'provisioning'")?;
        let cancelled = count("SELECT COUNT(*) FROM openrouter_leases WHERE status = 'cancelled'")?;
        let unknown_status = count(
            "SELECT COUNT(*) FROM openrouter_leases WHERE status NOT IN
                ('provisioning', 'active', 'retiring', 'disabled', 'revoking', 'finalized', 'cancelled')",
        )?;
        let open_reviews =
            count("SELECT COUNT(*) FROM settlement_reviews WHERE acknowledged_at IS NULL")?;
        let pending_key_cleanups = count("SELECT COUNT(*) FROM provider_key_cleanup")?;
        let next_deadline: Option<i64> = conn
            .query_row(
                "SELECT MIN(settlement_deadline_at) FROM openrouter_leases
                 WHERE status NOT IN ('finalized', 'cancelled')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| ServerError::Database(format!("settlement count failed: {error}")))?;
        Ok(crate::dashboard::SettlementCounts {
            pending,
            retrying,
            provisioning,
            cancelled,
            unknown_status,
            open_reviews,
            pending_key_cleanups,
            next_deadline_in_seconds: next_deadline
                .map(|deadline| (deadline.max(0) as u64).saturating_sub(now)),
        })
    }
}

fn insert_review(
    conn: &Connection,
    review: &SettlementReview,
    now: i64,
) -> Result<(), ServerError> {
    debug_assert!(SETTLEMENT_REVIEW_REASONS.contains(&review.reason.as_str()));
    // Keyed by lease: a lease finalizes once, so its first reason is kept.
    conn.execute(
        "INSERT OR IGNORE INTO settlement_reviews (
            client_request_id, request_nullifier, key_source, reason, charge_basis, detail,
            reported_usage_micro_usd, charge_applied, solvency_bound, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            review.client_request_id,
            review.request_nullifier.to_hex(),
            review.key_source,
            review.reason,
            review.charge_basis,
            truncate_detail(&review.detail),
            review
                .reported_usage_micro_usd
                .map(|value| value.to_string()),
            review
                .charge_applied
                .map(|value| value.min(i64::MAX as u128) as i64),
            review.solvency_bound.to_string(),
            now,
        ],
    )
    .map_err(|error| ServerError::Database(format!("review insert failed: {error}")))?;
    Ok(())
}

fn insert_key_cleanup(
    conn: &Connection,
    client_request_id: &str,
    cleanup: &KeyCleanup<'_>,
    now: i64,
) -> Result<(), ServerError> {
    conn.execute(
        "INSERT OR IGNORE INTO provider_key_cleanup (
            client_request_id, key_source, key_hash, key_name, next_attempt_at, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![
            client_request_id,
            cleanup.key_source,
            cleanup.key_hash,
            cleanup.key_name,
            now
        ],
    )
    .map_err(|error| ServerError::Database(format!("key cleanup insert failed: {error}")))?;
    Ok(())
}

fn truncate_detail(detail: &str) -> String {
    detail.chars().take(500).collect()
}

/// UNIX seconds as a SQLite integer; far-future values saturate.
fn sql_time(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

/// Add a column a decoder reads by name unless it already exists. Failure is
/// an error, unless a concurrent opener added the column first.
fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), ServerError> {
    let present = |conn: &Connection| -> Result<bool, ServerError> {
        conn.prepare(&format!("PRAGMA table_info({table})"))
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get::<_, String>(1))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .map(|columns| columns.iter().any(|name| name == column))
            .map_err(|error| {
                ServerError::Database(format!("{table}.{column} migration read failed: {error}"))
            })
    };
    if present(conn)? {
        return Ok(());
    }
    if let Err(error) = conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    ) {
        if !present(conn)? {
            return Err(ServerError::Database(format!(
                "{table}.{column} migration failed: {error}"
            )));
        }
    }
    Ok(())
}

fn migrate_oa_provisioning_outcome(conn: &Connection) -> Result<(), ServerError> {
    let columns = conn
        .prepare("PRAGMA table_info(openrouter_leases)")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|error| {
            ServerError::Database(format!("OA outcome migration read failed: {error}"))
        })?;
    if !columns.iter().any(|name| name == "oa_provisioning_outcome") {
        conn.execute(
            "ALTER TABLE openrouter_leases ADD COLUMN oa_provisioning_outcome TEXT NOT NULL DEFAULT 'may_have_issued'",
            [],
        )
        .map_err(|error| ServerError::Database(format!("OA outcome migration failed: {error}")))?;
    }
    Ok(())
}

/// Older lease rows already contain the complete original request. Use that
/// durable copy to migrate their nullifier reservation safely; proxy
/// reservations have no equivalent source and intentionally remain unbound so
/// retries fail closed.
fn backfill_openrouter_request_bindings(conn: &Connection) -> Result<(), ServerError> {
    let rows = {
        let mut statement = conn
            .prepare(
                "SELECT client_request_id, request_nullifier, api_request_json
                 FROM openrouter_leases",
            )
            .map_err(|error| {
                ServerError::Database(format!("lease binding migration query failed: {error}"))
            })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| {
                ServerError::Database(format!("lease binding migration read failed: {error}"))
            })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|error| {
            ServerError::Database(format!("lease binding migration row failed: {error}"))
        })?
    };

    for (client_request_id, request_nullifier, request_json) in rows {
        let Ok(request) = serde_json::from_str::<ApiRequestV2>(&request_json) else {
            // A malformed durable lease cannot be resumed safely. Leave the
            // reservation unbound so validate_and_reserve rejects it.
            continue;
        };
        if request.client_request_id != client_request_id
            || request.public_inputs.request_nullifier.to_hex() != request_nullifier
        {
            continue;
        }
        let binding = api_request_binding(&request)?;
        conn.execute(
            "UPDATE nullifiers SET api_request_binding = ?1
             WHERE nullifier = ?2
               AND client_request_id = ?3
               AND payload_hash = ?4
               AND reservation_kind = 'openrouter_lease'
               AND api_request_binding IS NULL",
            params![
                binding,
                request_nullifier,
                client_request_id,
                request.payload_hash.to_hex(),
            ],
        )
        .map_err(|error| {
            ServerError::Database(format!("lease binding migration update failed: {error}"))
        })?;
    }
    Ok(())
}

/// Convert a NullifierStatus to its string representation for storage.
fn status_to_str(status: NullifierStatus) -> &'static str {
    match status {
        NullifierStatus::Reserved => "Reserved",
        NullifierStatus::Finalized => "Finalized",
        NullifierStatus::ClearanceReserved => "ClearanceReserved",
    }
}

/// Parse a status string from the database.
fn str_to_status(s: &str) -> NullifierStatus {
    match s {
        "Reserved" => NullifierStatus::Reserved,
        "Finalized" => NullifierStatus::Finalized,
        "ClearanceReserved" => NullifierStatus::ClearanceReserved,
        _ => NullifierStatus::Reserved, // fallback
    }
}

/// Parse an optional hex string into a Felt252.
fn parse_opt_felt(s: Option<String>) -> Option<Felt252> {
    s.and_then(|h| Felt252::from_hex(&h).ok())
}

/// Every `nullifiers` column `row_to_record` reads; `open_read_only` refuses a
/// schema without them. Whoever makes `row_to_record` read a column MUST add it.
pub(crate) const TRANSCRIPT_RECORD_COLUMNS: &[&str] = &[
    "nullifier",
    "status",
    "reservation_kind",
    "client_request_id",
    "payload_hash",
    "charge_applied",
    "response_code",
    "response_payload",
    "response_hash",
    "next_commitment_x",
    "next_commitment_y",
    "next_anchor",
    "blind_delta_srv",
    "next_state_sig_json",
    "policy_reason_code",
    "policy_evidence_hash",
    "proof_blob",
    "request_inputs_json",
    "api_request_binding",
    "created_at",
    "finalized_at",
];

/// Convert a database row into a TranscriptRecord.
fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<TranscriptRecord> {
    let nullifier_hex: String = row.get("nullifier")?;
    let status_str: String = row.get("status")?;
    let reservation_kind: String = row.get("reservation_kind")?;
    let client_request_id: Option<String> = row.get("client_request_id")?;
    let payload_hash: Option<String> = row.get("payload_hash")?;
    let charge_applied: Option<i64> = row.get("charge_applied")?;
    let response_code: Option<i32> = row.get("response_code")?;
    let response_payload: Option<String> = row.get("response_payload")?;
    let response_hash: Option<String> = row.get("response_hash")?;
    let next_commitment_x: Option<String> = row.get("next_commitment_x")?;
    let next_commitment_y: Option<String> = row.get("next_commitment_y")?;
    let next_anchor: Option<String> = row.get("next_anchor")?;
    let blind_delta_srv: Option<String> = row.get("blind_delta_srv")?;
    let next_state_sig_json: Option<String> = row.get("next_state_sig_json")?;
    let policy_reason_code: Option<i32> = row.get("policy_reason_code")?;
    let policy_evidence_hash: Option<String> = row.get("policy_evidence_hash")?;
    let proof_blob: Option<Vec<u8>> = row.get("proof_blob")?;
    let request_inputs_json: Option<String> = row.get("request_inputs_json")?;
    let api_request_binding: Option<String> = row.get("api_request_binding")?;
    let created_at: i64 = row.get("created_at")?;
    let finalized_at: Option<i64> = row.get("finalized_at")?;

    let next_state_sig =
        next_state_sig_json.and_then(|json| serde_json::from_str::<SchnorrSignature>(&json).ok());

    Ok(TranscriptRecord {
        nullifier: Felt252::from_hex(&nullifier_hex).unwrap_or(Felt252::ZERO),
        status: str_to_status(&status_str),
        reservation_kind,
        client_request_id,
        payload_hash: parse_opt_felt(payload_hash),
        charge_applied: charge_applied.map(|c| c as u128),
        response_code: response_code.map(|c| c as u16),
        response_payload,
        response_hash: parse_opt_felt(response_hash),
        next_commitment_x: parse_opt_felt(next_commitment_x),
        next_commitment_y: parse_opt_felt(next_commitment_y),
        next_anchor: parse_opt_felt(next_anchor),
        blind_delta_srv: parse_opt_felt(blind_delta_srv),
        next_state_sig,
        policy_reason_code: policy_reason_code.map(|c| c as u32),
        policy_evidence_hash: parse_opt_felt(policy_evidence_hash),
        proof_blob,
        request_inputs_json,
        api_request_binding,
        created_at: created_at as u64,
        finalized_at: finalized_at.map(|t| t as u64),
    })
}

/// Every `openrouter_leases` column `row_to_openrouter_lease` reads; keep in
/// sync exactly like `TRANSCRIPT_RECORD_COLUMNS`.
pub(crate) const OPENROUTER_LEASE_RECORD_COLUMNS: &[&str] = &[
    "client_request_id",
    "request_nullifier",
    "api_request_json",
    "oa_client_request_id",
    "key_hash",
    "key_source",
    "oa_provisioning_outcome",
    "status",
    "issued_at",
    "expires_at",
    "settle_after",
    "spending_limit_usd",
    "usage_usd",
    "charge_applied",
    "last_error",
    "ttl_seconds",
    "settlement_deadline_at",
    "settlement_attempts",
    "first_error_at",
    "charge_basis",
    "delivered",
    "updated_at",
];

fn row_to_openrouter_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<OpenRouterLeaseRecord> {
    let time = |column: &str| -> rusqlite::Result<Option<u64>> {
        Ok(row
            .get::<_, Option<i64>>(column)?
            .map(|value| value.max(0) as u64))
    };
    let request_json: String = row.get("api_request_json")?;
    let api_request = serde_json::from_str(&request_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            request_json.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    let nullifier: String = row.get("request_nullifier")?;
    Ok(OpenRouterLeaseRecord {
        client_request_id: row.get("client_request_id")?,
        request_nullifier: Felt252::from_hex(&nullifier).unwrap_or(Felt252::ZERO),
        api_request,
        oa_client_request_id: row.get("oa_client_request_id")?,
        key_hash: row.get("key_hash")?,
        key_source: row.get("key_source")?,
        oa_provisioning_outcome: OaProvisioningOutcome::from_db(
            &row.get::<_, String>("oa_provisioning_outcome")?,
        ),
        status: row.get("status")?,
        issued_at: row.get::<_, i64>("issued_at")? as u64,
        expires_at: row.get::<_, i64>("expires_at")? as u64,
        settle_after: row.get::<_, i64>("settle_after")? as u64,
        spending_limit_usd: row.get("spending_limit_usd")?,
        usage_usd: row.get("usage_usd")?,
        charge_applied: row
            .get::<_, Option<i64>>("charge_applied")?
            .map(|value| value as u128),
        last_error: row.get("last_error")?,
        ttl_seconds: time("ttl_seconds")?,
        settlement_deadline_at: time("settlement_deadline_at")?,
        settlement_attempts: time("settlement_attempts")?.unwrap_or(0),
        first_error_at: time("first_error_at")?,
        charge_basis: row.get("charge_basis")?,
        delivered: row
            .get::<_, Option<i64>>("delivered")?
            .map(|value| value != 0),
        updated_at: time("updated_at")?.unwrap_or(0),
    })
}

fn row_to_deployment_binding(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeploymentBinding> {
    fn felt(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Felt252> {
        let value: String = row.get(index)?;
        Felt252::from_hex(&value).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                error.into(),
            )
        })
    }
    Ok(DeploymentBinding {
        chain_id: row.get(0)?,
        contract_address: row.get(1)?,
        state_signing_key: CurvePointWire {
            x: felt(row, 2)?,
            y: felt(row, 3)?,
        },
        clearance_signing_key: CurvePointWire {
            x: felt(row, 4)?,
            y: felt(row, 5)?,
        },
        challenge_period_seconds: row.get(6)?,
        verified_at: row.get(7)?,
        verified_block: row.get(8)?,
    })
}

/// Get the current UNIX timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease_request(client_request_id: &str, nullifier: u64) -> ApiRequestV2 {
        use zkapi_types::wire::{Groth16ProofWire, ProofBackendWire};
        use zkapi_types::RequestPublicInputsV2;

        ApiRequestV2 {
            client_request_id: client_request_id.to_string(),
            payload: "{\"mode\":\"openrouter_ephemeral_lease\",\"version\":1}".to_string(),
            payload_hash: Felt252::from_u64(88),
            public_inputs: RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: Felt252::from_u64(2),
                active_root: Felt252::from_u64(3),
                state_signing_key_x: Felt252::from_u64(4),
                state_signing_key_y: Felt252::from_u64(5),
                request_time: 6,
                solvency_bound: 1_000,
                request_nullifier: Felt252::from_u64(nullifier),
                authorization_tag: Felt252::from_u64(7),
                anonymous_commitment_x: Felt252::from_u64(8),
                anonymous_commitment_y: Felt252::from_u64(9),
            },
            proof: Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: "public-proof".to_string(),
            },
        }
    }

    fn create_oa_lease(store: &NullifierStore, id: &str, nullifier: u64) {
        store
            .create_openrouter_lease_with_oa_id(
                &lease_request(id, nullifier),
                "oa_org",
                10,
                20,
                21,
                6.0,
                Some(&format!("bound-{id}")),
            )
            .unwrap();
    }

    #[test]
    fn oa_issuance_fence_preserves_ambiguity_across_retries() {
        let store = NullifierStore::in_memory().unwrap();
        create_oa_lease(&store, "ambiguous", 1);
        assert_eq!(
            store
                .lookup_openrouter_lease("ambiguous")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::NotStarted
        );
        assert!(store.due_openrouter_leases(20).is_empty());
        assert_eq!(store.due_openrouter_leases(21).len(), 1);
        assert!(store.confirm_oa_unissued("ambiguous").is_err());
        assert!(store.begin_oa_issuance("ambiguous").unwrap());
        assert_eq!(
            store
                .lookup_openrouter_lease("ambiguous")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
        store
            .record_openrouter_lease_error("ambiguous", "response lost")
            .unwrap();
        assert!(!store.begin_oa_issuance("ambiguous").unwrap());
        let lease = store.lookup_openrouter_lease("ambiguous").unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        assert_eq!(lease.last_error.as_deref(), Some("response lost"));
        assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
    }

    #[test]
    fn confirmed_unissued_oa_lease_is_due_immediately_and_cannot_resume() {
        let store = NullifierStore::in_memory().unwrap();
        create_oa_lease(&store, "rejected", 1);
        assert!(store.begin_oa_issuance("rejected").unwrap());
        let before = current_timestamp();
        store.confirm_oa_unissued("rejected").unwrap();
        let lease = store.lookup_openrouter_lease("rejected").unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
        assert!(lease.settle_after >= before);
        assert_eq!(store.due_openrouter_leases(0).len(), 1);
        assert!(store.begin_oa_issuance("rejected").is_err());
        assert!(store.confirm_oa_unissued("rejected").is_err());
        store
            .record_openrouter_lease_error("rejected", "recovery retry")
            .unwrap();
        assert_eq!(
            store
                .lookup_openrouter_lease("rejected")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
    }

    #[test]
    fn oa_outcome_changes_require_an_unissued_provisioning_oa_row() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("direct", 1), "openrouter", 10, 20, 21, 6.0)
            .unwrap();
        assert_eq!(
            store
                .lookup_openrouter_lease("direct")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        for id in ["missing", "direct"] {
            assert!(store.begin_oa_issuance(id).is_err());
            assert!(store.confirm_oa_unissued(id).is_err());
        }
        for (index, status, key_hash) in [
            (2, "active", None),
            (3, "finalized", None),
            (4, "provisioning", Some("provider-key-hash")),
        ] {
            let id = format!("guard-{index}");
            create_oa_lease(&store, &id, index);
            assert!(store.begin_oa_issuance(&id).unwrap());
            store.conn.lock().unwrap().execute(
                "UPDATE openrouter_leases SET status = ?1, key_hash = ?2 WHERE client_request_id = ?3",
                params![status, key_hash, id],
            ).unwrap();
            assert!(store.begin_oa_issuance(&id).is_err());
            assert!(store.confirm_oa_unissued(&id).is_err());
        }
        assert!(store.due_openrouter_leases(0).is_empty());
    }

    #[test]
    fn unknown_oa_outcome_is_ambiguous_and_still_due_for_zero_settlement() {
        let store = NullifierStore::in_memory().unwrap();
        create_oa_lease(&store, "unknown", 1);
        store.conn.lock().unwrap().execute(
            "UPDATE openrouter_leases SET oa_provisioning_outcome = 'future_or_invalid' WHERE client_request_id = 'unknown'",
            [],
        ).unwrap();
        assert_eq!(
            store
                .lookup_openrouter_lease("unknown")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        // Never delivered whatever the issuer did: still settled (at zero),
        // never silently skipped.
        assert!(store.due_openrouter_leases(20).is_empty());
        assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
        assert!(store.confirm_oa_unissued("unknown").is_err());
        assert!(!store.begin_oa_issuance("unknown").unwrap());
        assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
    }

    #[test]
    fn legacy_oa_leases_migrate_to_ambiguous_and_outcomes_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("leases.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE openrouter_leases (
                    client_request_id TEXT PRIMARY KEY, request_nullifier TEXT NOT NULL UNIQUE,
                    api_request_json TEXT NOT NULL, oa_client_request_id TEXT, key_hash TEXT UNIQUE,
                    key_source TEXT NOT NULL DEFAULT 'openrouter', status TEXT NOT NULL,
                    issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, settle_after INTEGER NOT NULL,
                    spending_limit_usd REAL NOT NULL, usage_usd REAL, charge_applied INTEGER,
                    last_error TEXT, updated_at INTEGER NOT NULL
                );",
            ).unwrap();
            let request = lease_request("legacy", 1);
            conn.execute(
                "INSERT INTO openrouter_leases (client_request_id, request_nullifier, api_request_json,
                    oa_client_request_id, key_source, status, issued_at, expires_at, settle_after,
                    spending_limit_usd, updated_at)
                 VALUES ('legacy', ?1, ?2, 'legacy-bound-id', 'oa_org', 'provisioning', 10, 20, 21, 6.0, 10)",
                params![request.public_inputs.request_nullifier.to_hex(), serde_json::to_string(&request).unwrap()],
            ).unwrap();
        }
        {
            let store = NullifierStore::new(&path).unwrap();
            assert_eq!(
                store
                    .lookup_openrouter_lease("legacy")
                    .unwrap()
                    .oa_provisioning_outcome,
                OaProvisioningOutcome::MayHaveIssued
            );
            assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
            assert!(!store.begin_oa_issuance("legacy").unwrap());
            create_oa_lease(&store, "never-started", 2);
            create_oa_lease(&store, "attempted", 3);
            assert!(store.begin_oa_issuance("attempted").unwrap());
            create_oa_lease(&store, "rejected", 4);
            assert!(store.begin_oa_issuance("rejected").unwrap());
            store.confirm_oa_unissued("rejected").unwrap();
        }
        let reopened = NullifierStore::new(&path).unwrap();
        assert_eq!(
            reopened
                .lookup_openrouter_lease("never-started")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::NotStarted
        );
        assert!(!reopened.begin_oa_issuance("attempted").unwrap());
        assert_eq!(
            reopened
                .lookup_openrouter_lease("rejected")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
        assert!(reopened.begin_oa_issuance("rejected").is_err());
        let mut due_ids: Vec<_> = reopened
            .due_openrouter_leases(21)
            .into_iter()
            .map(|lease| lease.client_request_id)
            .collect();
        due_ids.sort();
        assert_eq!(
            due_ids,
            vec!["attempted", "legacy", "never-started", "rejected"]
        );
    }

    #[test]
    fn test_reserve_and_lookup() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);
        let client_id = "test-req-1";
        let payload_hash = Felt252::from_u64(100);

        store.reserve(&nullifier, client_id, &payload_hash).unwrap();

        let record = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert_eq!(record.client_request_id.as_deref(), Some(client_id));
    }

    #[test]
    fn test_reserve_duplicate_fails() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);

        store
            .reserve(&nullifier, "req-1", &Felt252::from_u64(1))
            .unwrap();
        let result = store.reserve(&nullifier, "req-2", &Felt252::from_u64(2));
        assert!(result.is_err());
    }

    #[test]
    fn test_lookup_by_client_id() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);
        let client_id = "unique-client-id";

        store
            .reserve(&nullifier, client_id, &Felt252::from_u64(1))
            .unwrap();

        let record = store.lookup_by_client_id(client_id).unwrap();
        assert_eq!(record.nullifier, nullifier);
    }

    #[test]
    fn test_finalize() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);

        store
            .reserve(&nullifier, "req-1", &Felt252::from_u64(1))
            .unwrap();

        let transcript = TranscriptRecord {
            nullifier,
            status: NullifierStatus::Finalized,
            reservation_kind: "proxy".to_string(),
            client_request_id: Some("req-1".to_string()),
            payload_hash: Some(Felt252::from_u64(1)),
            charge_applied: Some(100),
            response_code: Some(200),
            response_payload: Some("{\"ok\":true}".to_string()),
            response_hash: Some(Felt252::from_u64(999)),
            next_commitment_x: Some(Felt252::from_u64(10)),
            next_commitment_y: Some(Felt252::from_u64(20)),
            next_anchor: Some(Felt252::from_u64(30)),
            blind_delta_srv: Some(Felt252::from_u64(40)),
            next_state_sig: None,
            policy_reason_code: None,
            policy_evidence_hash: None,
            proof_blob: None,
            request_inputs_json: None,
            api_request_binding: None,
            created_at: 0,
            finalized_at: None,
        };

        store.finalize(&nullifier, &transcript).unwrap();

        let record = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(100));
        assert_eq!(record.response_payload.as_deref(), Some("{\"ok\":true}"));
    }

    #[test]
    fn test_reserve_clearance() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);

        store
            .reserve_clearance(&nullifier, "ownership_proof")
            .unwrap();

        let record = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.status, NullifierStatus::ClearanceReserved);
        assert_eq!(
            store.clearance_auth(&nullifier).unwrap().as_deref(),
            Some("ownership_proof")
        );
        assert!(matches!(
            store.reserve_clearance(&nullifier, "legacy"),
            Err(ServerError::NullifierUsed)
        ));
        assert_eq!(store.clearance_auth(&Felt252::from_u64(43)).unwrap(), None);
    }

    #[test]
    fn test_get_reserved_entries() {
        let store = NullifierStore::in_memory().unwrap();

        store
            .reserve(&Felt252::from_u64(1), "r1", &Felt252::from_u64(10))
            .unwrap();
        store
            .reserve(&Felt252::from_u64(2), "r2", &Felt252::from_u64(20))
            .unwrap();

        let reserved = store.get_reserved_entries();
        assert_eq!(reserved.len(), 2);
    }

    #[test]
    fn openrouter_lease_never_persists_plaintext_key() {
        use zkapi_types::wire::{ApiRequestV2, Groth16ProofWire, ProofBackendWire};
        use zkapi_types::RequestPublicInputsV2;

        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(77);
        let request = ApiRequestV2 {
            client_request_id: "lease-1".to_string(),
            payload: "{\"mode\":\"openrouter_ephemeral_lease\",\"version\":1}".to_string(),
            payload_hash: Felt252::from_u64(88),
            public_inputs: RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: Felt252::from_u64(2),
                active_root: Felt252::from_u64(3),
                state_signing_key_x: Felt252::from_u64(4),
                state_signing_key_y: Felt252::from_u64(5),
                request_time: 6,
                solvency_bound: 1_000,
                request_nullifier: nullifier,
                authorization_tag: Felt252::from_u64(7),
                anonymous_commitment_x: Felt252::from_u64(8),
                anonymous_commitment_y: Felt252::from_u64(9),
            },
            proof: Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: "public-proof".to_string(),
            },
        };
        store.reserve_openrouter_lease(&request).unwrap();
        let reservation = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(
            reservation.api_request_binding.as_deref(),
            Some(api_request_binding(&request).unwrap().as_str())
        );
        store
            .create_openrouter_lease(&request, "openrouter", 10, 20, 21, 0.001)
            .unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE nullifiers SET api_request_binding = NULL WHERE nullifier = ?1",
                params![nullifier.to_hex()],
            )
            .unwrap();
            backfill_openrouter_request_bindings(&conn).unwrap();
        }
        assert_eq!(
            store
                .lookup_by_nullifier(&nullifier)
                .unwrap()
                .api_request_binding,
            Some(api_request_binding(&request).unwrap())
        );
        store
            .activate_openrouter_lease("lease-1", "safe-key-hash")
            .unwrap();

        let lease = store.lookup_openrouter_lease("lease-1").unwrap();
        assert_eq!(lease.key_hash.as_deref(), Some("safe-key-hash"));
        assert!(!serde_json::to_string(&lease.api_request)
            .unwrap()
            .contains("sk-or-"));
        assert_eq!(store.due_openrouter_leases(20).len(), 0);
        assert_eq!(store.due_openrouter_leases(21).len(), 1);
    }

    fn deployment_binding() -> DeploymentBinding {
        let signer = crate::signer::ServerSigner::new(&Felt252::from_u64(7), &Felt252::from_u64(8));
        DeploymentBinding {
            chain_id: 11_155_111,
            contract_address: "0x00000000000000000000000000000000000000aa".into(),
            state_signing_key: signer.state_public_key(),
            clearance_signing_key: signer.clearance_public_key(),
            challenge_period_seconds: 86_400,
            verified_at: 1_700_000_000,
            verified_block: None,
        }
    }

    fn finalized(nullifier: Felt252) -> TranscriptRecord {
        TranscriptRecord {
            nullifier,
            status: NullifierStatus::Finalized,
            reservation_kind: "proxy".to_string(),
            client_request_id: Some("req-1".to_string()),
            payload_hash: Some(Felt252::from_u64(1)),
            charge_applied: Some(100),
            response_code: Some(200),
            response_payload: Some("{}".to_string()),
            response_hash: Some(Felt252::from_u64(999)),
            next_commitment_x: None,
            next_commitment_y: None,
            next_anchor: Some(Felt252::from_u64(30)),
            blind_delta_srv: None,
            next_state_sig: None,
            policy_reason_code: None,
            policy_evidence_hash: None,
            proof_blob: Some(vec![7; 256]),
            request_inputs_json: Some("{}".to_string()),
            api_request_binding: None,
            created_at: 0,
            finalized_at: None,
        }
    }

    #[test]
    fn read_only_store_sees_server_writes_but_cannot_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let server = NullifierStore::new(&path).unwrap();
        let reader = NullifierStore::open_read_only(&path).unwrap();
        let nullifier = Felt252::from_u64(42);
        assert!(reader
            .try_lookup_by_nullifier(&nullifier)
            .unwrap()
            .is_none());
        assert_eq!(reader.read_deployment_binding().unwrap(), None);
        server
            .reserve(&nullifier, "req-1", &Felt252::from_u64(1))
            .unwrap();
        server.finalize(&nullifier, &finalized(nullifier)).unwrap();
        server
            .create_openrouter_lease(&lease_request("lease", 9), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        server
            .write_deployment_binding(&deployment_binding())
            .unwrap();

        let record = reader.try_lookup_by_nullifier(&nullifier).unwrap().unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.proof_blob.as_deref(), Some(&[7; 256][..]));
        assert_eq!(
            reader
                .try_lookup_openrouter_lease("lease")
                .unwrap()
                .unwrap()
                .status,
            "provisioning"
        );
        assert_eq!(
            reader.read_deployment_binding().unwrap(),
            Some(deployment_binding())
        );

        // Every write fails on the reader and leaves the database unchanged.
        assert!(reader
            .reserve_clearance(&Felt252::from_u64(43), "ownership_proof")
            .is_err());
        assert!(reader
            .reserve(&Felt252::from_u64(44), "req-2", &Felt252::from_u64(2))
            .is_err());
        assert!(reader
            .write_deployment_binding(&DeploymentBinding {
                chain_id: 1,
                ..deployment_binding()
            })
            .is_err());
        assert!(reader
            .record_openrouter_lease_error("lease", "reader write")
            .is_err());
        assert!(server.lookup_by_nullifier(&Felt252::from_u64(43)).is_none());
        assert!(server.lookup_by_nullifier(&Felt252::from_u64(44)).is_none());
        assert_eq!(
            server.read_deployment_binding().unwrap(),
            Some(deployment_binding())
        );
        assert!(server
            .lookup_openrouter_lease("lease")
            .unwrap()
            .last_error
            .is_none());

        // A read-only open never creates a database.
        let missing = directory.path().join("missing.db");
        assert!(NullifierStore::open_read_only(&missing).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn read_only_store_rejects_outdated_schema() {
        let directory = tempfile::tempdir().unwrap();
        let unrelated = directory.path().join("unrelated.db");
        Connection::open(&unrelated)
            .unwrap()
            .execute_batch("CREATE TABLE unrelated (value TEXT);")
            .unwrap();
        // A server database from before api_request_binding was read.
        let legacy = directory.path().join("legacy.db");
        let legacy_columns = TRANSCRIPT_RECORD_COLUMNS
            .iter()
            .filter(|column| **column != "api_request_binding")
            .copied()
            .collect::<Vec<_>>();
        Connection::open(&legacy)
            .unwrap()
            .execute_batch(&format!(
                "CREATE TABLE nullifiers ({}); CREATE TABLE openrouter_leases ({});",
                legacy_columns.join(", "),
                OPENROUTER_LEASE_RECORD_COLUMNS.join(", ")
            ))
            .unwrap();
        for path in [&unrelated, &legacy] {
            let error = NullifierStore::open_read_only(path)
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("schema is older"), "{error}");
        }
        // The read-only open did not migrate the file; the server's open does.
        let column_count = |path: &std::path::Path| -> i64 {
            Connection::open(path)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('nullifiers')
                     WHERE name = 'api_request_binding'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(column_count(&legacy), 0);
        NullifierStore::new(&legacy).unwrap();
        assert_eq!(column_count(&legacy), 1);
        assert!(NullifierStore::open_read_only(&legacy).is_ok());
    }

    #[test]
    fn deployment_binding_round_trips_and_is_absent_from_older_databases() {
        let store = NullifierStore::in_memory().unwrap();
        assert_eq!(store.read_deployment_binding().unwrap(), None);
        store
            .write_deployment_binding(&deployment_binding())
            .unwrap();
        assert_eq!(
            store.read_deployment_binding().unwrap(),
            Some(deployment_binding())
        );
        let reverified = DeploymentBinding {
            verified_at: 1_700_000_100,
            verified_block: Some(123),
            ..deployment_binding()
        };
        store.write_deployment_binding(&reverified).unwrap();
        assert_eq!(store.read_deployment_binding().unwrap(), Some(reverified));
        {
            // One row, felts as Felt252::to_hex prints them.
            let conn = store.conn.lock().unwrap();
            let (rows, address, state_x, clearance_y): (i64, String, String, String) = conn
                .query_row(
                    "SELECT COUNT(*), contract_address, state_key_x, clearance_key_y
                     FROM deployment_binding",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            assert_eq!(rows, 1);
            assert_eq!(address, deployment_binding().contract_address);
            assert_eq!(state_x, deployment_binding().state_signing_key.x.to_hex());
            assert_eq!(
                clearance_y,
                deployment_binding().clearance_signing_key.y.to_hex()
            );
        }
        assert!(store
            .write_deployment_binding(&DeploymentBinding {
                chain_id: u64::MAX,
                ..deployment_binding()
            })
            .is_err());

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        NullifierStore::new(&path).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TABLE deployment_binding;")
            .unwrap();
        assert_eq!(
            NullifierStore::open_read_only(&path)
                .unwrap()
                .read_deployment_binding()
                .unwrap(),
            None
        );
    }

    #[test]
    fn required_column_lists_cover_every_column_the_row_decoders_read() {
        // Tables holding only the listed columns: a decoder that reads any
        // other column fails here until its list is updated.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("minimal.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!(
                "CREATE TABLE nullifiers ({}); CREATE TABLE openrouter_leases ({});",
                TRANSCRIPT_RECORD_COLUMNS.join(", "),
                OPENROUTER_LEASE_RECORD_COLUMNS.join(", ")
            ))
            .unwrap();
            conn.execute(
                "INSERT INTO nullifiers (nullifier, status, reservation_kind, created_at)
                 VALUES (?1, 'Reserved', 'openrouter_lease', 1)",
                params![Felt252::from_u64(5).to_hex()],
            )
            .unwrap();
            let request = lease_request("minimal", 5);
            conn.execute(
                "INSERT INTO openrouter_leases (client_request_id, request_nullifier,
                    api_request_json, key_source, oa_provisioning_outcome, status, issued_at,
                    expires_at, settle_after, spending_limit_usd)
                 VALUES ('minimal', ?1, ?2, 'openrouter', 'may_have_issued', 'active', 1, 2, 3, 1.5)",
                params![
                    request.public_inputs.request_nullifier.to_hex(),
                    serde_json::to_string(&request).unwrap()
                ],
            )
            .unwrap();
        }
        let reader = NullifierStore::open_read_only(&path).unwrap();
        assert_eq!(
            reader
                .try_lookup_by_nullifier(&Felt252::from_u64(5))
                .unwrap()
                .unwrap()
                .reservation_kind,
            "openrouter_lease"
        );
        assert_eq!(
            reader
                .try_lookup_openrouter_lease("minimal")
                .unwrap()
                .unwrap()
                .status,
            "active"
        );
    }

    #[test]
    fn try_lookups_report_database_errors_instead_of_absence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let server = NullifierStore::new(&path).unwrap();
        server
            .create_openrouter_lease(&lease_request("corrupt", 6), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        server
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE openrouter_leases SET api_request_json = 'not json'",
                [],
            )
            .unwrap();
        let reader = NullifierStore::open_read_only(&path).unwrap();
        assert!(reader.try_lookup_openrouter_lease("corrupt").is_err());
        assert!(reader.lookup_openrouter_lease("corrupt").is_none());
        server
            .conn
            .lock()
            .unwrap()
            .execute_batch("DROP TABLE nullifiers; DROP TABLE openrouter_leases;")
            .unwrap();
        assert!(reader
            .try_lookup_by_nullifier(&Felt252::from_u64(1))
            .is_err());
        assert!(reader.lookup_by_nullifier(&Felt252::from_u64(1)).is_none());
        assert!(reader.try_lookup_openrouter_lease("corrupt").is_err());
    }

    fn review(id: &str, reason: &str) -> SettlementReview {
        SettlementReview {
            client_request_id: id.to_string(),
            request_nullifier: Felt252::from_u64(9),
            key_source: "openrouter".into(),
            reason: reason.into(),
            charge_basis: Some("worst_case".into()),
            detail: "x".repeat(800),
            reported_usage_micro_usd: Some(u128::MAX),
            charge_applied: Some(1_000),
            solvency_bound: 1_000,
        }
    }

    #[test]
    fn settlement_review_and_cancel_are_atomic_and_listed() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("worst", 1), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store
            .create_openrouter_lease(&lease_request("corrupt", 2), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store.activate_openrouter_lease("worst", "hash-1").unwrap();
        let worst = review("worst", "deadline_worst_case");
        assert!(store
            .finalize_openrouter_lease_with(
                "worst",
                &LeaseFinalization {
                    usage_usd: 0.0,
                    charge_applied: 1_000,
                    charge_basis: "worst_case",
                    review: Some(&worst),
                    key_cleanup: Some(KeyCleanup {
                        key_source: "openrouter",
                        key_hash: Some("hash-1"),
                        key_name: "zkapi-worst",
                    }),
                    only_if_unissued: false,
                },
            )
            .unwrap());
        let lease = store.lookup_openrouter_lease("worst").unwrap();
        assert_eq!(lease.status, "finalized");
        assert_eq!(lease.charge_applied, Some(1_000));
        assert_eq!(lease.charge_basis.as_deref(), Some("worst_case"));
        store
            .cancel_openrouter_lease("corrupt", &review("corrupt", "binding_corrupt"))
            .unwrap();
        let cancelled = store.lookup_openrouter_lease("corrupt").unwrap();
        assert_eq!(cancelled.status, "cancelled");
        assert_eq!(cancelled.last_error.as_ref().unwrap().len(), 500);
        // A cancelled row is terminal: neither finalized nor settled later.
        assert!(!store
            .finalize_openrouter_lease_with(
                "corrupt",
                &LeaseFinalization {
                    usage_usd: 0.0,
                    charge_applied: 0,
                    charge_basis: "measured",
                    review: None,
                    key_cleanup: None,
                    only_if_unissued: false,
                },
            )
            .unwrap());
        assert!(store.due_openrouter_leases(u64::MAX / 4).is_empty());
        let reviews = store.settlement_reviews(10).unwrap();
        assert_eq!(reviews.len(), 2);
        let stored = reviews
            .iter()
            .find(|stored| stored.review.client_request_id == "worst")
            .unwrap();
        assert_eq!(stored.review.detail.len(), 500);
        assert_eq!(stored.review.reported_usage_micro_usd, Some(u128::MAX));
        assert_eq!(stored.review.charge_applied, Some(1_000));
        assert_eq!(stored.acknowledged_at, None);
        // One review per lease: the first reason is kept.
        store
            .cancel_openrouter_lease("worst", &review("worst", "binding_corrupt"))
            .unwrap();
        assert_eq!(
            store.lookup_openrouter_lease("worst").unwrap().status,
            "finalized"
        );
        assert_eq!(store.settlement_reviews(10).unwrap().len(), 2);
        let counts = store.settlement_counts(0).unwrap();
        assert_eq!(
            (counts.pending, counts.cancelled, counts.open_reviews),
            (0, 1, 2)
        );
        assert_eq!(counts.pending_key_cleanups, 1);
        let queued = store.due_key_cleanups(u64::MAX / 4, 10).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].key_hash.as_deref(), Some("hash-1"));
        store
            .defer_key_cleanup("worst", "provider unavailable", u64::MAX / 8)
            .unwrap();
        assert!(store
            .due_key_cleanups(u64::MAX / 16, 10)
            .unwrap()
            .is_empty());
        assert_eq!(
            store.due_key_cleanups(u64::MAX / 4, 10).unwrap()[0].attempts,
            1
        );
        store.complete_key_cleanup("worst").unwrap();
        assert!(store.due_key_cleanups(u64::MAX / 4, 10).unwrap().is_empty());
    }

    #[test]
    fn unissued_finalization_is_conditional_on_an_unissued_row() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("raced", 1), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store.activate_openrouter_lease("raced", "issued").unwrap();
        let zero = LeaseFinalization {
            usage_usd: 0.0,
            charge_applied: 0,
            charge_basis: "unissued",
            review: None,
            key_cleanup: None,
            only_if_unissued: true,
        };
        assert!(!store
            .finalize_openrouter_lease_with("raced", &zero)
            .unwrap());
        assert_eq!(
            store.lookup_openrouter_lease("raced").unwrap().status,
            "active"
        );
        store
            .create_openrouter_lease(&lease_request("unissued", 2), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        assert!(store
            .finalize_openrouter_lease_with("unissued", &zero)
            .unwrap());
        assert_eq!(
            store.lookup_openrouter_lease("unissued").unwrap().status,
            "finalized"
        );
    }

    #[test]
    fn record_error_counts_attempts_and_first_error_survives_transitions() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("errors", 1), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store.activate_openrouter_lease("errors", "hash").unwrap();
        let fresh = store.lookup_openrouter_lease("errors").unwrap();
        assert_eq!((fresh.settlement_attempts, fresh.first_error_at), (0, None));
        store
            .record_openrouter_lease_error("errors", "first")
            .unwrap();
        let first = store.lookup_openrouter_lease("errors").unwrap();
        assert_eq!(first.settlement_attempts, 1);
        let first_error_at = first.first_error_at.unwrap();
        for (from, to) in [
            ("active", "retiring"),
            ("retiring", "disabled"),
            ("disabled", "retiring"),
        ] {
            store
                .advance_openrouter_retirement("errors", from, to, 0, None)
                .unwrap();
            store
                .record_openrouter_lease_error("errors", "again")
                .unwrap();
        }
        let lease = store.lookup_openrouter_lease("errors").unwrap();
        assert_eq!(lease.settlement_attempts, 4);
        assert_eq!(lease.first_error_at, Some(first_error_at));
        assert_eq!(lease.last_error.as_deref(), Some("again"));
    }

    #[test]
    fn settlement_deadline_is_write_once() {
        let store = NullifierStore::in_memory().unwrap();
        let request = lease_request("deadline", 1);
        store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request: &request,
                key_source: "oa_org",
                issued_at: 10,
                expires_at: 20,
                settle_after: 21,
                spending_limit_usd: 1.0,
                oa_client_request_id: Some("bound"),
                ttl_seconds: Some(600),
                settlement_deadline_at: Some(1_000),
                delivered: Some(false),
            })
            .unwrap();
        let lease = store.lookup_openrouter_lease("deadline").unwrap();
        assert_eq!(lease.ttl_seconds, Some(600));
        assert_eq!(lease.settlement_deadline_at, Some(1_000));
        assert_eq!(lease.delivered, Some(false));
        assert_eq!(
            store.assign_settlement_deadline("deadline", 5).unwrap(),
            1_000
        );
        store
            .update_openrouter_lease_timing("deadline", 900, 950)
            .unwrap();
        store.activate_openrouter_lease("deadline", "hash").unwrap();
        store.mark_openrouter_lease_delivered("deadline").unwrap();
        let lease = store.lookup_openrouter_lease("deadline").unwrap();
        assert_eq!(lease.settlement_deadline_at, Some(1_000));
        assert_eq!(lease.delivered, Some(true));
        // Due at the deadline even when settle_after is later.
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE openrouter_leases SET settle_after = 5000 WHERE client_request_id = 'deadline'",
                [],
            )
            .unwrap();
        assert!(store.due_openrouter_leases(999).is_empty());
        assert_eq!(store.due_openrouter_leases(1_000).len(), 1);
        // Rows recorded without a deadline are assigned once, then keep it.
        store
            .create_openrouter_lease(&lease_request("legacy", 2), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        assert_eq!(
            store.leases_without_settlement_deadline().unwrap(),
            vec![("legacy".to_string(), 20)]
        );
        assert_eq!(
            store.assign_settlement_deadline("legacy", 7_000).unwrap(),
            7_000
        );
        assert_eq!(
            store.assign_settlement_deadline("legacy", 9_000).unwrap(),
            7_000
        );
        assert!(store
            .leases_without_settlement_deadline()
            .unwrap()
            .is_empty());
        assert!(store.mark_openrouter_lease_delivered("legacy").is_err());
    }

    #[test]
    fn due_includes_direct_provisioning_after_settle_after() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("direct", 1), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store
            .create_openrouter_lease(
                &lease_request("unknown", 2),
                "future_source",
                10,
                20,
                21,
                1.0,
            )
            .unwrap();
        assert!(store.due_openrouter_leases(20).is_empty());
        let due = store.due_openrouter_leases(21);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].client_request_id, "direct");
        // Least recently attempted first.
        store
            .create_openrouter_lease(&lease_request("second", 3), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store
            .record_openrouter_lease_error("direct", "retry later")
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE openrouter_leases SET updated_at = 1 WHERE client_request_id = 'second'",
                [],
            )
            .unwrap();
        let order: Vec<_> = store
            .due_openrouter_leases(21)
            .into_iter()
            .map(|lease| lease.client_request_id)
            .collect();
        assert_eq!(order, ["second", "direct"]);
    }

    #[test]
    fn settlement_counts_include_unreadable_rows() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("ok", 1), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store
            .create_openrouter_lease(&lease_request("broken", 2), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store.assign_settlement_deadline("ok", 500).unwrap();
        store.record_openrouter_lease_error("ok", "failed").unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE openrouter_leases SET api_request_json = 'not json' WHERE client_request_id = 'broken'",
                [],
            )
            .unwrap();
        // The scan cannot decode the broken row...
        assert_eq!(store.due_openrouter_leases(21).len(), 1);
        assert_eq!(store.pending_openrouter_leases(10).unwrap().len(), 1);
        // ...but the operator counts include it.
        let counts = store.settlement_counts(100).unwrap();
        assert_eq!(counts.pending, 2);
        assert_eq!(counts.provisioning, 2);
        assert_eq!(counts.retrying, 1);
        assert_eq!(counts.next_deadline_in_seconds, Some(400));
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE openrouter_leases SET status = 'mystery' WHERE client_request_id = 'broken'",
                [],
            )
            .unwrap();
        assert_eq!(store.settlement_counts(100).unwrap().unknown_status, 1);
    }

    #[test]
    fn legacy_db_migrates_settlement_columns_reviews_and_clearance_auth() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE nullifiers (
                    nullifier TEXT PRIMARY KEY, status TEXT NOT NULL,
                    reservation_kind TEXT NOT NULL DEFAULT 'proxy', client_request_id TEXT,
                    payload_hash TEXT, charge_applied INTEGER, response_code INTEGER,
                    response_payload TEXT, response_hash TEXT, next_commitment_x TEXT,
                    next_commitment_y TEXT, next_anchor TEXT, blind_delta_srv TEXT,
                    next_state_sig_epoch INTEGER, next_state_sig_root TEXT, next_state_sig_json TEXT,
                    policy_reason_code INTEGER, policy_evidence_hash TEXT, proof_blob BLOB,
                    request_inputs_json TEXT, api_request_binding TEXT, created_at INTEGER NOT NULL,
                    finalized_at INTEGER
                );
                CREATE TABLE openrouter_leases (
                    client_request_id TEXT PRIMARY KEY, request_nullifier TEXT NOT NULL UNIQUE,
                    api_request_json TEXT NOT NULL, oa_client_request_id TEXT, key_hash TEXT UNIQUE,
                    key_source TEXT NOT NULL DEFAULT 'openrouter',
                    oa_provisioning_outcome TEXT NOT NULL DEFAULT 'may_have_issued',
                    status TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                    settle_after INTEGER NOT NULL, spending_limit_usd REAL NOT NULL, usage_usd REAL,
                    charge_applied INTEGER, last_error TEXT, updated_at INTEGER NOT NULL
                );
                INSERT INTO nullifiers (nullifier, status, created_at)
                    VALUES ('0x2a', 'ClearanceReserved', 1);",
            )
            .unwrap();
            let request = lease_request("legacy", 1);
            conn.execute(
                "INSERT INTO openrouter_leases (client_request_id, request_nullifier, api_request_json,
                    key_source, key_hash, status, issued_at, expires_at, settle_after, spending_limit_usd,
                    usage_usd, updated_at)
                 VALUES ('legacy', ?1, ?2, 'openrouter', 'hash', 'revoking', 10, 20, 21, 6.0, 0.5, 10)",
                params![
                    request.public_inputs.request_nullifier.to_hex(),
                    serde_json::to_string(&request).unwrap()
                ],
            )
            .unwrap();
        }
        let store = NullifierStore::new(&path).unwrap();
        let lease = store.lookup_openrouter_lease("legacy").unwrap();
        assert_eq!(lease.ttl_seconds, None);
        assert_eq!(lease.settlement_deadline_at, None);
        assert_eq!(lease.settlement_attempts, 0);
        assert_eq!(lease.first_error_at, None);
        assert_eq!(lease.charge_basis, None);
        assert_eq!(lease.delivered, None);
        assert_eq!(lease.updated_at, 10);
        assert_eq!(store.due_openrouter_leases(21).len(), 1);
        assert_eq!(store.clearance_auth(&Felt252::from_u64(42)).unwrap(), None);
        assert!(store.settlement_reviews(10).unwrap().is_empty());
        assert_eq!(store.settlement_counts(0).unwrap().pending, 1);
        drop(store);
        // Reopening is idempotent, and a read-only reader accepts the schema.
        NullifierStore::new(&path).unwrap();
        let reader = NullifierStore::open_read_only(&path).unwrap();
        assert_eq!(
            reader
                .try_lookup_openrouter_lease("legacy")
                .unwrap()
                .unwrap()
                .usage_usd,
            Some(0.5)
        );
    }
}
