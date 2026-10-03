// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Events – All events emitted by ZkApiVault
abstract contract Events {
    event NoteDeposited(
        uint32 indexed noteId, bytes32 indexed commitment, uint128 amount, uint64 expiryTs, uint256 newRoot
    );

    event MutualClose(uint32 indexed noteId, uint256 nullifier, uint128 finalBalance, address destination);

    event EscapeWithdrawalInitiated(
        uint32 indexed noteId,
        uint256 nullifier,
        uint128 finalBalance,
        address destination,
        uint64 challengeDeadline,
        uint256 newRoot
    );

    event EscapeWithdrawalChallenged(uint32 indexed noteId, uint256 nullifier, uint256 restoredRoot);

    event EscapeWithdrawalFinalized(
        uint32 indexed noteId, uint256 nullifier, uint128 finalBalance, address destination
    );

    event ExpiredClaimed(uint32 indexed noteId, uint128 depositAmount, uint256 newRoot);

    event ProofAdapterSet(address indexed newAdapter);

    /// @notice Emitted when a scheduled treasury change takes effect.
    event TreasurySet(address indexed newTreasury);

    /// @notice `readyAt` is on the vault's active clock (wall clock minus all paused time).
    event TreasuryChangeScheduled(address indexed newTreasury, uint64 readyAt);

    event TreasuryChangeCancelled(address indexed cancelledTreasury);

    /// @notice A treasury push failed; `amount` gwei units were added to treasuryArrears.
    event TreasuryPaymentDeferred(address indexed treasury, uint128 amount);

    event TreasuryArrearsPaid(address indexed treasury, uint128 amount);

    /// @dev Same signatures as OpenZeppelin Pausable for monitoring compatibility.
    event Paused(address account);

    event Unpaused(address account);
}
