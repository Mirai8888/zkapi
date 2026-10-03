//! Local Merkle tree mirror maintained from contract events.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use zkapi_core::leaf::compute_note_leaf;
use zkapi_core::merkle::MerkleTree;
use zkapi_types::{Felt252, MERKLE_DEPTH};

use crate::events::VaultEvent;

/// An escape withdrawal the vault holds open until it is challenged or
/// finalized. The challenger uses this list as a completeness check for its
/// own escape-event scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingEscape {
    pub note_id: u32,
    pub withdrawal_nullifier: Felt252,
    pub challenge_deadline: u64,
}

/// Serializable state paired atomically with the indexer's block cursor.
///
/// Persisting only the cursor is unsafe because TreeMirror otherwise starts
/// empty after a process restart and skips the events needed to rebuild it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TreeMirrorSnapshot {
    pub next_note_id: u32,
    pub current_leaves: Vec<Felt252>,
    pub original_leaves: Vec<(u32, Felt252)>,
    pub pending_escapes: Vec<PendingEscape>,
}

/// A vault event that cannot follow the mirror's current state. The caller
/// discards the staged mirror the event was applied to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MirrorError {
    #[error("deposit for note {got} does not follow next note id {expected}")]
    NonContiguousDeposit { expected: u32, got: u32 },
    #[error("note {note_id} was never deposited")]
    UnknownNote { note_id: u32 },
    #[error("note {note_id} is not active")]
    NoteNotActive { note_id: u32 },
    #[error("note {note_id} has no pending escape withdrawal")]
    NoteNotPending { note_id: u32 },
    #[error("note {note_id} pending escape has a different withdrawal nullifier")]
    PendingNullifierMismatch { note_id: u32 },
    #[error("event root {event} does not match mirror root {mirror}")]
    RootMismatch { event: Felt252, mirror: Felt252 },
    #[error("note id space is exhausted")]
    NoteIdOverflow,
}

/// A mirror of the on-chain Merkle tree, maintained by consuming events.
#[derive(Clone)]
pub struct TreeMirror {
    tree: MerkleTree,
    next_note_id: u32,
    /// Original leaf values for each note (needed for challenge restores).
    original_leaves: HashMap<u32, Felt252>,
    /// Escape withdrawals that are neither challenged nor finalized.
    pending_escapes: BTreeMap<u32, PendingEscape>,
}

impl TreeMirror {
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::new(),
            next_note_id: 0,
            original_leaves: HashMap::new(),
            pending_escapes: BTreeMap::new(),
        }
    }

    /// Root of the empty tree, which the vault sets in its constructor.
    pub fn empty_root() -> Felt252 {
        static EMPTY_ROOT: OnceLock<Felt252> = OnceLock::new();
        *EMPTY_ROOT.get_or_init(|| MerkleTree::new().root())
    }

    /// True before the first deposit.
    pub fn is_empty(&self) -> bool {
        self.next_note_id == 0
    }

    /// Get the current root.
    pub fn root(&self) -> Felt252 {
        self.tree.root()
    }

    /// Get the next available note ID.
    pub fn next_note_id(&self) -> u32 {
        self.next_note_id
    }

    /// All current leaves, indexed 0..next_note_id.
    ///
    /// This backs the privacy-safe snapshot endpoint: a client fetches the same
    /// full leaf vector regardless of which note it cares about, rebuilds the
    /// tree locally, and derives any sibling path without revealing its note_id
    /// to the (untrusted) indexer.
    pub fn current_leaves(&self) -> Vec<Felt252> {
        (0..self.next_note_id)
            .map(|i| self.tree.get_leaf(i))
            .collect()
    }

    /// Open escape withdrawals in note-id order.
    pub fn pending_escapes(&self) -> Vec<PendingEscape> {
        self.pending_escapes.values().copied().collect()
    }

    /// Capture all state needed to restore paths and challengeable leaves.
    pub fn snapshot(&self) -> TreeMirrorSnapshot {
        let mut original_leaves: Vec<_> = self
            .original_leaves
            .iter()
            .map(|(note_id, leaf)| (*note_id, *leaf))
            .collect();
        original_leaves.sort_unstable_by_key(|(note_id, _)| *note_id);

        TreeMirrorSnapshot {
            next_note_id: self.next_note_id,
            current_leaves: self.current_leaves(),
            original_leaves,
            pending_escapes: self.pending_escapes(),
        }
    }

    /// Restore a mirror from an atomic cursor checkpoint.
    pub fn from_snapshot(snapshot: TreeMirrorSnapshot) -> Result<Self, String> {
        if snapshot.current_leaves.len() != snapshot.next_note_id as usize {
            return Err(format!(
                "snapshot has {} leaves but next_note_id is {}",
                snapshot.current_leaves.len(),
                snapshot.next_note_id
            ));
        }
        let mut original_leaves = HashMap::with_capacity(snapshot.original_leaves.len());
        for (note_id, leaf) in snapshot.original_leaves {
            if note_id >= snapshot.next_note_id {
                return Err("snapshot contains an original leaf beyond next_note_id".to_string());
            }
            if original_leaves.insert(note_id, leaf).is_some() {
                return Err(format!(
                    "snapshot repeats the original leaf of note {note_id}"
                ));
            }
        }
        if original_leaves.len() != snapshot.next_note_id as usize {
            return Err("snapshot is missing original leaves".to_string());
        }
        for (note_id, leaf) in snapshot.current_leaves.iter().enumerate() {
            if !leaf.is_zero() && original_leaves.get(&(note_id as u32)) != Some(leaf) {
                return Err(format!(
                    "snapshot leaf of note {note_id} is neither empty nor its deposited leaf"
                ));
            }
        }
        let mut pending_escapes = BTreeMap::new();
        for escape in snapshot.pending_escapes {
            let Some(leaf) = snapshot.current_leaves.get(escape.note_id as usize) else {
                return Err("snapshot contains a pending escape beyond next_note_id".to_string());
            };
            if !leaf.is_zero() {
                return Err(format!(
                    "snapshot has a pending escape for note {} whose leaf is active",
                    escape.note_id
                ));
            }
            if pending_escapes.insert(escape.note_id, escape).is_some() {
                return Err(format!(
                    "snapshot repeats the pending escape of note {}",
                    escape.note_id
                ));
            }
        }

        let mut tree = MerkleTree::new();
        for (note_id, leaf) in snapshot.current_leaves.iter().copied().enumerate() {
            if !leaf.is_zero() {
                tree.set_leaf(note_id as u32, leaf);
            }
        }

        Ok(Self {
            tree,
            next_note_id: snapshot.next_note_id,
            original_leaves,
            pending_escapes,
        })
    }

    /// Get the sibling path for a note's current leaf.
    pub fn get_path(&self, note_id: u32) -> [Felt252; MERKLE_DEPTH] {
        self.tree.get_siblings(note_id)
    }

    /// Get the sibling path for a zero leaf at the given index.
    /// This is the same as get_path since the tree stores the current state.
    pub fn get_zero_path(&self, note_id: u32) -> [Felt252; MERKLE_DEPTH] {
        self.tree.get_siblings(note_id)
    }

    /// Get the leaf value at a given index.
    pub fn get_leaf(&self, note_id: u32) -> Felt252 {
        self.tree.get_leaf(note_id)
    }

    /// Apply a contract event after checking that it can follow the mirrored
    /// vault state, including the root the vault emitted with it.
    ///
    /// On error the mirror may be partially updated and must be discarded.
    pub fn apply_event(&mut self, event: &VaultEvent) -> Result<(), MirrorError> {
        match event {
            VaultEvent::NoteDeposited {
                note_id,
                commitment,
                amount,
                expiry_ts,
                new_root,
            } => {
                // The vault assigns ids sequentially from 0, so a gap, a repeat
                // or a reordering means the log stream is incomplete.
                if *note_id != self.next_note_id {
                    return Err(MirrorError::NonContiguousDeposit {
                        expected: self.next_note_id,
                        got: *note_id,
                    });
                }
                let next_note_id = note_id.checked_add(1).ok_or(MirrorError::NoteIdOverflow)?;
                let leaf = compute_note_leaf(*note_id, commitment, *amount, *expiry_ts);
                self.tree.set_leaf(*note_id, leaf);
                self.original_leaves.insert(*note_id, leaf);
                self.next_note_id = next_note_id;
                self.require_root(new_root)
            }
            VaultEvent::MutualClose { note_id, .. } => {
                // The event carries no root; the batch-end state check covers it.
                self.require_active(*note_id)?;
                self.tree.set_leaf(*note_id, Felt252::ZERO);
                Ok(())
            }
            VaultEvent::EscapeWithdrawalInitiated {
                note_id,
                nullifier,
                challenge_deadline,
                new_root,
                ..
            } => {
                self.require_active(*note_id)?;
                self.tree.set_leaf(*note_id, Felt252::ZERO);
                self.pending_escapes.insert(
                    *note_id,
                    PendingEscape {
                        note_id: *note_id,
                        withdrawal_nullifier: *nullifier,
                        challenge_deadline: *challenge_deadline,
                    },
                );
                self.require_root(new_root)
            }
            VaultEvent::EscapeWithdrawalChallenged {
                note_id,
                nullifier,
                restored_root,
            } => {
                let original = self.require_pending(*note_id, nullifier)?;
                self.tree.set_leaf(*note_id, original);
                self.pending_escapes.remove(note_id);
                self.require_root(restored_root)
            }
            VaultEvent::EscapeWithdrawalFinalized {
                note_id, nullifier, ..
            } => {
                // The leaf was zeroed on initiation; only the escape closes.
                self.require_pending(*note_id, nullifier)?;
                self.pending_escapes.remove(note_id);
                Ok(())
            }
            VaultEvent::ExpiredClaimed {
                note_id, new_root, ..
            } => {
                self.require_active(*note_id)?;
                self.tree.set_leaf(*note_id, Felt252::ZERO);
                self.require_root(new_root)
            }
        }
    }

    fn original_leaf(&self, note_id: u32) -> Result<Felt252, MirrorError> {
        if note_id >= self.next_note_id {
            return Err(MirrorError::UnknownNote { note_id });
        }
        self.original_leaves
            .get(&note_id)
            .copied()
            .ok_or(MirrorError::UnknownNote { note_id })
    }

    fn require_active(&self, note_id: u32) -> Result<(), MirrorError> {
        let original = self.original_leaf(note_id)?;
        if self.tree.get_leaf(note_id) != original {
            return Err(MirrorError::NoteNotActive { note_id });
        }
        Ok(())
    }

    fn require_pending(&self, note_id: u32, nullifier: &Felt252) -> Result<Felt252, MirrorError> {
        let original = self.original_leaf(note_id)?;
        let escape = self
            .pending_escapes
            .get(&note_id)
            .ok_or(MirrorError::NoteNotPending { note_id })?;
        if !self.tree.get_leaf(note_id).is_zero() {
            return Err(MirrorError::NoteNotPending { note_id });
        }
        if escape.withdrawal_nullifier != *nullifier {
            return Err(MirrorError::PendingNullifierMismatch { note_id });
        }
        Ok(original)
    }

    fn require_root(&self, event_root: &Felt252) -> Result<(), MirrorError> {
        let mirror = self.root();
        if mirror != *event_root {
            return Err(MirrorError::RootMismatch {
                event: *event_root,
                mirror,
            });
        }
        Ok(())
    }

    /// Unchecked event application for tests that use placeholder roots.
    #[cfg(test)]
    pub(crate) fn process_event(&mut self, event: &VaultEvent) {
        match event {
            VaultEvent::NoteDeposited {
                note_id,
                commitment,
                amount,
                expiry_ts,
                ..
            } => {
                let leaf = compute_note_leaf(*note_id, commitment, *amount, *expiry_ts);
                self.tree.set_leaf(*note_id, leaf);
                self.original_leaves.insert(*note_id, leaf);
                self.next_note_id = self.next_note_id.max(note_id.saturating_add(1));
            }
            VaultEvent::MutualClose { note_id, .. } => {
                self.tree.set_leaf(*note_id, Felt252::ZERO);
            }
            VaultEvent::EscapeWithdrawalInitiated {
                note_id,
                nullifier,
                challenge_deadline,
                ..
            } => {
                // Leaf is zeroed immediately on initiation
                self.tree.set_leaf(*note_id, Felt252::ZERO);
                self.pending_escapes.insert(
                    *note_id,
                    PendingEscape {
                        note_id: *note_id,
                        withdrawal_nullifier: *nullifier,
                        challenge_deadline: *challenge_deadline,
                    },
                );
            }
            VaultEvent::EscapeWithdrawalChallenged { note_id, .. } => {
                // Restore the original leaf
                if let Some(original) = self.original_leaves.get(note_id) {
                    self.tree.set_leaf(*note_id, *original);
                }
                self.pending_escapes.remove(note_id);
            }
            VaultEvent::EscapeWithdrawalFinalized { note_id, .. } => {
                // Leaf was already zeroed during initiation
                self.pending_escapes.remove(note_id);
            }
            VaultEvent::ExpiredClaimed { note_id, .. } => {
                self.tree.set_leaf(*note_id, Felt252::ZERO);
            }
        }
    }
}

impl Default for TreeMirror {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deposit_and_close() {
        let mut mirror = TreeMirror::new();
        let commitment = Felt252::from_u64(12345);

        // Deposit
        mirror.process_event(&VaultEvent::NoteDeposited {
            note_id: 0,
            commitment,
            amount: 1000,
            expiry_ts: 1700000000,
            new_root: Felt252::ZERO, // We don't use this
        });

        let root_after_deposit = mirror.root();
        assert_ne!(root_after_deposit, MerkleTree::new().root());

        // Close
        mirror.process_event(&VaultEvent::MutualClose {
            note_id: 0,
            nullifier: Felt252::from_u64(999),
            final_balance: 900,
        });

        // Should be back to empty
        assert_eq!(mirror.root(), MerkleTree::new().root());
    }

    #[test]
    fn test_escape_and_challenge() {
        let mut mirror = TreeMirror::new();
        let commitment = Felt252::from_u64(12345);

        // Deposit
        mirror.process_event(&VaultEvent::NoteDeposited {
            note_id: 0,
            commitment,
            amount: 1000,
            expiry_ts: 1700000000,
            new_root: Felt252::ZERO,
        });
        let root_after_deposit = mirror.root();

        // Escape withdrawal initiation (zeroes leaf)
        mirror.process_event(&VaultEvent::EscapeWithdrawalInitiated {
            note_id: 0,
            nullifier: Felt252::from_u64(999),
            final_balance: 900,
            challenge_deadline: 1700086400,
            new_root: Felt252::ZERO,
        });
        assert_ne!(mirror.root(), root_after_deposit);

        // Challenge (restores leaf)
        mirror.process_event(&VaultEvent::EscapeWithdrawalChallenged {
            note_id: 0,
            nullifier: Felt252::from_u64(999),
            restored_root: Felt252::ZERO,
        });
        assert_eq!(mirror.root(), root_after_deposit);
    }

    #[test]
    fn test_multiple_deposits() {
        let mut mirror = TreeMirror::new();

        for i in 0..5 {
            mirror.process_event(&VaultEvent::NoteDeposited {
                note_id: i,
                commitment: Felt252::from_u64(i as u64 + 100),
                amount: 1000,
                expiry_ts: 1700000000,
                new_root: Felt252::ZERO,
            });
        }

        // All leaves should be accessible
        for i in 0..5 {
            let leaf = mirror.get_leaf(i);
            assert!(!leaf.is_zero());
        }
    }

    #[test]
    fn snapshot_round_trip_preserves_current_and_original_leaves() {
        let mut mirror = TreeMirror::new();
        for note_id in 0..3 {
            mirror.process_event(&VaultEvent::NoteDeposited {
                note_id,
                commitment: Felt252::from_u64(100 + note_id as u64),
                amount: 1_000,
                expiry_ts: 1_700_000_000,
                new_root: Felt252::ZERO,
            });
        }
        mirror.process_event(&VaultEvent::EscapeWithdrawalInitiated {
            note_id: 1,
            nullifier: Felt252::from_u64(999),
            final_balance: 900,
            challenge_deadline: 1_700_086_400,
            new_root: Felt252::ZERO,
        });

        let expected_root = mirror.root();
        let expected_path = mirror.get_path(2);
        let restored = TreeMirror::from_snapshot(mirror.snapshot()).unwrap();
        assert_eq!(restored.root(), expected_root);
        assert_eq!(restored.next_note_id(), 3);
        assert_eq!(restored.get_path(2), expected_path);
        assert_eq!(restored.pending_escapes(), mirror.pending_escapes());

        let mut restored = restored;
        restored.process_event(&VaultEvent::EscapeWithdrawalChallenged {
            note_id: 1,
            nullifier: Felt252::from_u64(999),
            restored_root: Felt252::ZERO,
        });
        assert!(!restored.get_leaf(1).is_zero());
    }

    /// Builds events whose roots are what the vault would emit, by replaying
    /// them on a reference mirror.
    struct Reference(TreeMirror);

    impl Reference {
        fn new() -> Self {
            Self(TreeMirror::new())
        }

        fn deposit(&mut self, commitment: u64) -> VaultEvent {
            let mut event = VaultEvent::NoteDeposited {
                note_id: self.0.next_note_id(),
                commitment: Felt252::from_u64(commitment),
                amount: 1_000,
                expiry_ts: 1_700_000_000,
                new_root: Felt252::ZERO,
            };
            self.0.process_event(&event);
            if let VaultEvent::NoteDeposited { new_root, .. } = &mut event {
                *new_root = self.0.root();
            }
            event
        }

        fn close(&mut self, note_id: u32) -> VaultEvent {
            let event = VaultEvent::MutualClose {
                note_id,
                nullifier: Felt252::from_u64(7_000 + note_id as u64),
                final_balance: 10,
            };
            self.0.process_event(&event);
            event
        }

        fn escape(&mut self, note_id: u32, nullifier: u64) -> VaultEvent {
            let mut event = VaultEvent::EscapeWithdrawalInitiated {
                note_id,
                nullifier: Felt252::from_u64(nullifier),
                final_balance: 10,
                challenge_deadline: 1_700_086_400,
                new_root: Felt252::ZERO,
            };
            self.0.process_event(&event);
            if let VaultEvent::EscapeWithdrawalInitiated { new_root, .. } = &mut event {
                *new_root = self.0.root();
            }
            event
        }

        fn challenge(&mut self, note_id: u32, nullifier: u64) -> VaultEvent {
            self.0
                .process_event(&VaultEvent::EscapeWithdrawalChallenged {
                    note_id,
                    nullifier: Felt252::from_u64(nullifier),
                    restored_root: Felt252::ZERO,
                });
            VaultEvent::EscapeWithdrawalChallenged {
                note_id,
                nullifier: Felt252::from_u64(nullifier),
                restored_root: self.0.root(),
            }
        }

        fn finalize(&mut self, note_id: u32, nullifier: u64) -> VaultEvent {
            let event = VaultEvent::EscapeWithdrawalFinalized {
                note_id,
                nullifier: Felt252::from_u64(nullifier),
                final_balance: 10,
            };
            self.0.process_event(&event);
            event
        }

        fn claim(&mut self, note_id: u32) -> VaultEvent {
            self.0.process_event(&VaultEvent::ExpiredClaimed {
                note_id,
                deposit_amount: 1_000,
                new_root: Felt252::ZERO,
            });
            VaultEvent::ExpiredClaimed {
                note_id,
                deposit_amount: 1_000,
                new_root: self.0.root(),
            }
        }
    }

    fn apply_all(mirror: &mut TreeMirror, events: &[VaultEvent]) {
        for event in events {
            mirror.apply_event(event).unwrap();
        }
    }

    #[test]
    fn apply_event_accepts_lifecycle_with_matching_roots() {
        let mut reference = Reference::new();
        let events = vec![
            reference.deposit(100),
            reference.deposit(101),
            reference.deposit(102),
            reference.escape(0, 900),
            reference.challenge(0, 900),
            // G2: a later escape of the same note uses a new nullifier.
            reference.escape(0, 901),
            reference.finalize(0, 901),
            reference.close(1),
            reference.claim(2),
        ];
        let mut mirror = TreeMirror::new();
        for (index, event) in events.iter().enumerate() {
            mirror.apply_event(event).unwrap();
            if index == 3 {
                assert_eq!(
                    mirror.pending_escapes(),
                    vec![PendingEscape {
                        note_id: 0,
                        withdrawal_nullifier: Felt252::from_u64(900),
                        challenge_deadline: 1_700_086_400,
                    }]
                );
            }
            if index == 4 {
                assert!(mirror.pending_escapes().is_empty());
                assert!(!mirror.get_leaf(0).is_zero());
            }
        }
        assert_eq!(mirror.root(), reference.0.root());
        assert_eq!(mirror.root(), TreeMirror::empty_root());
        assert_eq!(mirror.next_note_id(), 3);
        assert!(mirror.pending_escapes().is_empty());
    }

    #[test]
    fn apply_event_rejects_gap_and_duplicate_deposit() {
        let mut reference = Reference::new();
        let first = reference.deposit(100);
        let second = reference.deposit(101);

        let mut mirror = TreeMirror::new();
        assert_eq!(
            mirror.apply_event(&second),
            Err(MirrorError::NonContiguousDeposit {
                expected: 0,
                got: 1
            })
        );

        let mut mirror = TreeMirror::new();
        mirror.apply_event(&first).unwrap();
        assert_eq!(
            mirror.apply_event(&first),
            Err(MirrorError::NonContiguousDeposit {
                expected: 1,
                got: 0
            })
        );
    }

    #[test]
    fn apply_event_rejects_event_root_mismatch() {
        let mut mirror = TreeMirror::new();
        let error = mirror
            .apply_event(&VaultEvent::NoteDeposited {
                note_id: 0,
                commitment: Felt252::from_u64(100),
                amount: 1_000,
                expiry_ts: 1_700_000_000,
                new_root: Felt252::from_u64(1),
            })
            .unwrap_err();
        assert!(matches!(error, MirrorError::RootMismatch { .. }));

        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let mut escape = reference.escape(0, 900);
        if let VaultEvent::EscapeWithdrawalInitiated { new_root, .. } = &mut escape {
            *new_root = Felt252::from_u64(5);
        }
        let mut mirror = TreeMirror::new();
        mirror.apply_event(&deposit).unwrap();
        assert!(matches!(
            mirror.apply_event(&escape),
            Err(MirrorError::RootMismatch { .. })
        ));
    }

    #[test]
    fn apply_event_rejects_close_escape_or_claim_of_inactive_note() {
        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let close = reference.close(0);

        let mut unknown = TreeMirror::new();
        assert_eq!(
            unknown.apply_event(&close),
            Err(MirrorError::UnknownNote { note_id: 0 })
        );

        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &[deposit, close.clone()]);
        assert_eq!(
            mirror.clone().apply_event(&close),
            Err(MirrorError::NoteNotActive { note_id: 0 })
        );
        let escape = VaultEvent::EscapeWithdrawalInitiated {
            note_id: 0,
            nullifier: Felt252::from_u64(1),
            final_balance: 1,
            challenge_deadline: 1,
            new_root: mirror.root(),
        };
        assert_eq!(
            mirror.clone().apply_event(&escape),
            Err(MirrorError::NoteNotActive { note_id: 0 })
        );
        let claim = VaultEvent::ExpiredClaimed {
            note_id: 0,
            deposit_amount: 1_000,
            new_root: mirror.root(),
        };
        assert_eq!(
            mirror.apply_event(&claim),
            Err(MirrorError::NoteNotActive { note_id: 0 })
        );

        // A pending escape is not active either.
        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let escape = reference.escape(0, 900);
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &[deposit, escape]);
        assert_eq!(
            mirror.apply_event(&VaultEvent::MutualClose {
                note_id: 0,
                nullifier: Felt252::from_u64(1),
                final_balance: 1,
            }),
            Err(MirrorError::NoteNotActive { note_id: 0 })
        );
    }

    #[test]
    fn apply_event_rejects_challenge_or_finalize_without_pending_escape() {
        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let mut mirror = TreeMirror::new();
        mirror.apply_event(&deposit).unwrap();

        let challenge = VaultEvent::EscapeWithdrawalChallenged {
            note_id: 0,
            nullifier: Felt252::from_u64(900),
            restored_root: mirror.root(),
        };
        assert_eq!(
            mirror.clone().apply_event(&challenge),
            Err(MirrorError::NoteNotPending { note_id: 0 })
        );
        let finalize = VaultEvent::EscapeWithdrawalFinalized {
            note_id: 0,
            nullifier: Felt252::from_u64(900),
            final_balance: 1,
        };
        assert_eq!(
            mirror.clone().apply_event(&finalize),
            Err(MirrorError::NoteNotPending { note_id: 0 })
        );
        assert_eq!(
            mirror
                .clone()
                .apply_event(&VaultEvent::EscapeWithdrawalFinalized {
                    note_id: 4,
                    nullifier: Felt252::from_u64(900),
                    final_balance: 1,
                }),
            Err(MirrorError::UnknownNote { note_id: 4 })
        );

        // The vault emits the pending escape's own nullifier.
        let escape = reference.escape(0, 900);
        mirror.apply_event(&escape).unwrap();
        assert_eq!(
            mirror
                .clone()
                .apply_event(&VaultEvent::EscapeWithdrawalFinalized {
                    note_id: 0,
                    nullifier: Felt252::from_u64(901),
                    final_balance: 1,
                }),
            Err(MirrorError::PendingNullifierMismatch { note_id: 0 })
        );

        // A closed note (zero leaf, no pending escape) cannot be finalized.
        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let close = reference.close(0);
        let mut closed = TreeMirror::new();
        apply_all(&mut closed, &[deposit, close]);
        assert_eq!(
            closed.apply_event(&finalize),
            Err(MirrorError::NoteNotPending { note_id: 0 })
        );
    }

    #[test]
    fn from_snapshot_rejects_missing_or_inconsistent_original_leaves() {
        let mut reference = Reference::new();
        let events = vec![
            reference.deposit(100),
            reference.deposit(101),
            reference.escape(1, 900),
        ];
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &events);
        let snapshot = mirror.snapshot();
        assert!(TreeMirror::from_snapshot(snapshot.clone()).is_ok());

        let rejection = |snapshot: TreeMirrorSnapshot| TreeMirror::from_snapshot(snapshot).err();

        let mut missing = snapshot.clone();
        missing.original_leaves.remove(0);
        assert!(rejection(missing)
            .unwrap()
            .contains("missing original leaves"));

        let mut repeated = snapshot.clone();
        repeated.original_leaves[1].0 = 0;
        assert!(TreeMirror::from_snapshot(repeated).is_err());

        let mut beyond = snapshot.clone();
        beyond.original_leaves.push((2, Felt252::from_u64(3)));
        assert!(TreeMirror::from_snapshot(beyond).is_err());

        let mut foreign_leaf = snapshot.clone();
        foreign_leaf.current_leaves[0] = Felt252::from_u64(42);
        assert!(rejection(foreign_leaf)
            .unwrap()
            .contains("neither empty nor its deposited leaf"));

        let mut active_escape = snapshot.clone();
        active_escape.pending_escapes[0].note_id = 0;
        assert!(rejection(active_escape)
            .unwrap()
            .contains("whose leaf is active"));

        let mut orphan_escape = snapshot;
        orphan_escape.pending_escapes[0].note_id = 9;
        assert!(TreeMirror::from_snapshot(orphan_escape).is_err());
    }
}
