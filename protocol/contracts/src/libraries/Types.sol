// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Types – Shared zkAPI v2 data structures
library Types {
    enum NoteStatus {
        Uninitialized,
        Active,
        PendingWithdrawal,
        Closed
    }

    struct Note {
        bytes32 commitment;
        uint128 depositAmount;
        uint64 expiryTs;
        NoteStatus status;
    }

    /// @dev The 6-word getter clients and the challenger decode. The concession side is in
    ///      PendingConcession.
    struct PendingWithdrawalData {
        bool exists;
        /// @dev The escape proof's activeRoot; informational, the vault never reads it.
        uint256 activeRoot;
        uint256 withdrawalNullifier;
        /// @dev The current payout: the state balance minus the current concession.
        uint128 finalBalance;
        address destination;
        uint64 challengeDeadline;
    }

    /// @dev Field order is the exact Groth16 public-input order.
    struct RequestPublicInputs {
        uint16 protocolVersion;
        uint64 chainId;
        address contractAddress;
        uint256 activeRoot;
        uint256 stateSigningKeyX;
        uint256 stateSigningKeyY;
        uint64 requestTime;
        uint128 solvencyBound;
        uint256 requestNullifier;
        uint256 authorizationTag;
        uint256 anonymousCommitmentX;
        uint256 anonymousCommitmentY;
    }

    /// @dev Field order is the exact Groth16 public-input order (16 inputs). A static tuple, so its
    ///      ABI words are the public inputs in order.
    struct WithdrawalPublicInputs {
        uint16 protocolVersion;
        uint64 chainId;
        address contractAddress;
        uint256 activeRoot;
        uint256 stateSigningKeyX;
        uint256 stateSigningKeyY;
        uint256 clearanceSigningKeyX;
        uint256 clearanceSigningKeyY;
        uint32 noteId;
        /// @dev The payout: the state balance minus `conceded`.
        uint128 finalBalance;
        /// @dev Zero for an ownership proof (kind 2).
        address destination;
        /// @dev N_k = H(d_null', s, noteId, anchor) of the state the exit leaves.
        uint256 withdrawalNullifier;
        /// @dev 0 escape, 1 mutual close, 2 ownership proof (never accepted by the vault).
        uint8 kind;
        /// @dev N_{k+1}, the nullifier of the state's derived successor, for an escape; 0 otherwise.
        uint256 nextNullifier;
        /// @dev The amount an escape gives up; 0 unless kind is 0.
        uint128 conceded;
        /// @dev The latest second at which the vault accepts the proof.
        uint64 validUntil;
    }

    /// @dev The concession side of a pending escape (2 slots). For every pending escape,
    ///      pendingWithdrawals[n].finalBalance + conceded == stateBalance <= notes[n].depositAmount.
    struct PendingConcession {
        /// @dev N_{k+1}: only a request proof at this nullifier defeats the escape.
        uint256 nextNullifier;
        /// @dev B_k, the balance of the state the escape leaves.
        uint128 stateBalance;
        /// @dev c; a raise only ever increases it.
        uint128 conceded;
    }
}
