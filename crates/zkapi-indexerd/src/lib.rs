//! Indexer: mirrors contract events into a local Merkle tree view.
//!
//! The indexer maintains a full copy of the on-chain Merkle tree by consuming
//! contract events in block order. It serves sibling paths and the latest root
//! to both the client and server, plus the open escape withdrawals to the
//! challenger.
//!
//! Every served view is a state the vault verifiably had: `currentRoot()` and
//! `nextNoteId()` read by block hash must equal the mirror. A durable
//! checkpoint is kept `confirmations` blocks below the head; reorgs are
//! absorbed or trigger a rebuild, and any unresolved mismatch fails closed
//! (HTTP 503) rather than serving a root the vault never had.
//!
//! The indexer is NOT trusted. Incorrect paths only cause proof or tx failure.

pub mod events;
pub mod http;
pub mod poller;
pub mod service;
#[cfg(test)]
mod test_chain;
pub mod tree_mirror;

pub use http::{create_router, run_indexer, IndexerConfig};
pub use poller::{BlockRef, JsonRpcLogPoller, PollOutcome, PollerConfig};
pub use service::{
    HealthResponse, IndexerService, NextNoteIdResponse, PendingEscapesResponse, ServiceSettings,
    SyncStatus, TreePathResponse, TreeRootResponse, TreeSnapshotResponse, TreeView,
};
pub use tree_mirror::{MirrorError, PendingEscape, TreeMirror};
