// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {Types} from "./libraries/Types.sol";
import {Errors} from "./libraries/Errors.sol";
import {Events} from "./libraries/Events.sol";
import {MerkleUpdateLib} from "./libraries/MerkleUpdateLib.sol";
import {NoteLeafLib} from "./libraries/NoteLeafLib.sol";
import {IZkApiProofAdapter} from "./interfaces/IZkApiProofAdapter.sol";

/// @title ZkApiVault
/// @notice Native ETH settlement in whole gwei with in-protocol BN254 Groth16 verification.
contract ZkApiVault is ReentrancyGuard, Ownable, Events {
    uint16 public constant PROTOCOL_VERSION = 2;
    uint64 public constant DEFAULT_CHALLENGE_PERIOD = 24 hours;
    uint64 public constant EXPIRY_BUCKET = 1 days;
    uint256 public constant MERKLE_DEPTH = 32;
    /// @notice How long a replaced root stays acceptable as a withdrawal proof's activeRoot.
    uint64 public constant ROOT_HISTORY_WINDOW = 1 days;
    /// @notice Lower bound of the treasury timelock; the delay is max(this, challengePeriod).
    uint64 public constant MIN_TREASURY_CHANGE_DELAY = 2 days;
    /// @notice Execution gas forwarded on treasury pushes; a failed push accrues to treasuryArrears.
    /// @dev A treasury that needs more gas to receive always accrues arrears. A caller cannot force
    ///      deferral by under-funding gas: when the push gets less than this, the 1/64 of gas the
    ///      vault keeps (under ~1.6k) cannot record arrears, so the whole call reverts.
    uint256 public constant TREASURY_PAYOUT_GAS = 100_000;
    /// @dev Lower bound of unpauseClaimGrace; the grace is max(this, challengePeriod).
    uint64 private constant MIN_UNPAUSE_CLAIM_GRACE = 1 days;

    /// Native asset sentinel retained for deployment and client compatibility.
    address public constant billingToken = address(0);
    uint256 public constant nativeAssetWeiPerUnit = 1 gwei;
    uint128 public constant MAX_NATIVE_UNITS = 9_007_199_254_740_991;
    uint64 public immutable noteTtl;
    uint64 public immutable challengePeriod;
    uint64 public immutable treasuryChangeDelay;
    /// @notice Unpaused time every note keeps after an unpause before claimExpired can take it.
    uint64 public immutable unpauseClaimGrace;
    uint128 public immutable requestChargeCap;
    IZkApiProofAdapter public immutable proofAdapter;
    uint256 public immutable stateSigningKeyX;
    uint256 public immutable stateSigningKeyY;
    uint256 public immutable clearanceSigningKeyX;
    uint256 public immutable clearanceSigningKeyY;

    address public treasury;
    bool public paused;
    /// @notice Start of the current pause; zero while unpaused.
    uint64 public pausedAt;
    uint256 public currentRoot;
    uint32 public nextNoteId;
    /// @notice Sum of all completed pause intervals, in seconds.
    uint64 public totalPausedDuration;
    /// @notice Treasury payouts (gwei units) whose push failed; see withdrawTreasuryArrears.
    uint128 public treasuryArrears;
    address public pendingTreasury;
    /// @notice Active-clock time (wall clock minus all paused time) from which acceptTreasury may
    ///         apply pendingTreasury; paused time never counts toward the delay.
    uint64 public pendingTreasuryReadyAt;
    /// @notice Time of the latest unpause; zero if the vault was never unpaused.
    uint64 public lastUnpausedAt;

    mapping(uint32 => Types.Note) public notes;
    mapping(uint32 => Types.PendingWithdrawalData) public pendingWithdrawals;
    mapping(uint256 => bool) public usedNullifiers;
    /// @notice Nullifiers whose escape was defeated by a challenge; they can never escape again.
    mapping(uint256 => bool) public challengedNullifiers;
    /// @notice Last time each root stopped being currentRoot; zero if it never was replaced.
    mapping(uint256 => uint64) public rootRetiredAt;
    /// @dev Expiry on the active (unpaused) clock. Zero means notes[noteId].expiryTs.
    mapping(uint32 => uint64) private _activeExpiry;

    modifier whenNotPaused() {
        if (paused) revert Errors.Paused();
        _;
    }

    constructor(
        address treasury_,
        uint64 noteTtl_,
        uint64 challengePeriod_,
        uint128 requestChargeCap_,
        address proofAdapter_,
        uint256 stateSigningKeyX_,
        uint256 stateSigningKeyY_,
        uint256 clearanceSigningKeyX_,
        uint256 clearanceSigningKeyY_,
        address owner_
    ) Ownable(owner_) {
        if (treasury_ == address(0) || proofAdapter_ == address(0) || challengePeriod_ == 0) {
            revert Errors.Unauthorized();
        }
        _requireField(stateSigningKeyX_);
        _requireField(stateSigningKeyY_);
        _requireField(clearanceSigningKeyX_);
        _requireField(clearanceSigningKeyY_);
        if (
            (stateSigningKeyX_ == 0 && stateSigningKeyY_ == 0)
                || (clearanceSigningKeyX_ == 0 && clearanceSigningKeyY_ == 0)
        ) revert Errors.InvalidDeploymentBinding();

        if (requestChargeCap_ == 0 || requestChargeCap_ > MAX_NATIVE_UNITS) {
            revert Errors.InvalidBalance();
        }
        treasury = treasury_;
        noteTtl = noteTtl_;
        challengePeriod = challengePeriod_;
        treasuryChangeDelay =
            challengePeriod_ > MIN_TREASURY_CHANGE_DELAY ? challengePeriod_ : MIN_TREASURY_CHANGE_DELAY;
        unpauseClaimGrace = challengePeriod_ > MIN_UNPAUSE_CLAIM_GRACE ? challengePeriod_ : MIN_UNPAUSE_CLAIM_GRACE;
        requestChargeCap = requestChargeCap_;
        proofAdapter = IZkApiProofAdapter(proofAdapter_);
        stateSigningKeyX = stateSigningKeyX_;
        stateSigningKeyY = stateSigningKeyY_;
        clearanceSigningKeyX = clearanceSigningKeyX_;
        clearanceSigningKeyY = clearanceSigningKeyY_;
        currentRoot = _computeEmptyTreeRoot();
    }

    function deposit(bytes32 commitment, uint128 amount, uint256[32] calldata siblings)
        external
        payable
        nonReentrant
        whenNotPaused
    {
        if (amount > MAX_NATIVE_UNITS || msg.value != uint256(amount) * nativeAssetWeiPerUnit) {
            revert Errors.InvalidNativeValue();
        }
        if (amount == 0) revert Errors.ZeroAmount();
        if (commitment == bytes32(0)) revert Errors.InvalidCommitment();
        _requireField(uint256(commitment));

        uint32 noteId = nextNoteId;
        uint256 rawExpiry = block.timestamp + noteTtl;
        uint256 bucketedExpiry = ((rawExpiry + EXPIRY_BUCKET - 1) / EXPIRY_BUCKET) * EXPIRY_BUCKET;
        if (bucketedExpiry > type(uint64).max) revert Errors.InvalidFelt();
        uint64 expiryTs = uint64(bucketedExpiry);
        uint256 newLeaf = NoteLeafLib.computeLeaf(noteId, commitment, amount, expiryTs);
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(currentRoot, noteId, 0, newLeaf, siblings);

        _setCurrentRoot(newRoot);
        notes[noteId] = Types.Note(commitment, amount, expiryTs, Types.NoteStatus.Active);
        // Deposits cannot happen while paused, so only completed pauses precede this note.
        uint64 pausedBefore = totalPausedDuration;
        if (pausedBefore != 0) _activeExpiry[noteId] = expiryTs - pausedBefore;
        nextNoteId = noteId + 1;
        emit NoteDeposited(noteId, commitment, amount, expiryTs, newRoot);
    }

    function mutualClose(
        Types.WithdrawalPublicInputs calldata inputs,
        bytes calldata proof,
        uint256[32] calldata siblings
    ) external nonReentrant whenNotPaused {
        _validateWithdrawalBinding(inputs);
        if (!inputs.hasClearance) revert Errors.InvalidDeploymentBinding();
        if (inputs.destination == address(0)) revert Errors.InvalidDestination();
        if (!isKnownRoot(inputs.activeRoot)) revert Errors.UnknownRoot();
        proofAdapter.assertValidWithdrawal(inputs, proof);
        _closeActive(inputs, siblings);
        emit MutualClose(inputs.noteId, inputs.withdrawalNullifier, inputs.finalBalance, inputs.destination);
    }

    function initiateEscapeWithdrawal(
        Types.WithdrawalPublicInputs calldata inputs,
        bytes calldata proof,
        uint256[32] calldata siblings
    ) external nonReentrant whenNotPaused {
        _validateWithdrawalBinding(inputs);
        if (inputs.hasClearance) revert Errors.InvalidDeploymentBinding();
        if (inputs.destination == address(0)) revert Errors.InvalidDestination();
        // A defeated escape stays defeated: its calldata is public, so anyone could replay it.
        // The note exits from its signed successor state (or a clearance-backed mutualClose).
        if (challengedNullifiers[inputs.withdrawalNullifier]) revert Errors.ChallengedNullifier();
        if (!isKnownRoot(inputs.activeRoot)) revert Errors.UnknownRoot();
        proofAdapter.assertValidWithdrawal(inputs, proof);

        Types.Note storage note = notes[inputs.noteId];
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        if (inputs.finalBalance > note.depositAmount) revert Errors.InvalidBalance();
        _consumeNullifier(inputs.withdrawalNullifier);

        // The proof may use a recent root; the leaf removal is always applied to the live root.
        uint256 oldRoot = currentRoot;
        uint256 leaf = _leaf(inputs.noteId, note);
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(oldRoot, inputs.noteId, leaf, 0, siblings);
        uint64 deadline = uint64(block.timestamp) + challengePeriod;
        _setCurrentRoot(newRoot);
        note.status = Types.NoteStatus.PendingWithdrawal;
        pendingWithdrawals[inputs.noteId] = Types.PendingWithdrawalData({
            exists: true,
            activeRoot: oldRoot,
            withdrawalNullifier: inputs.withdrawalNullifier,
            finalBalance: inputs.finalBalance,
            destination: inputs.destination,
            challengeDeadline: deadline
        });
        emit EscapeWithdrawalInitiated(
            inputs.noteId, inputs.withdrawalNullifier, inputs.finalBalance, inputs.destination, deadline, newRoot
        );
    }

    function challengeEscapeWithdrawal(
        uint32 noteId,
        Types.RequestPublicInputs calldata inputs,
        bytes calldata proof,
        uint256[32] calldata siblings
    ) external nonReentrant {
        Types.Note storage note = notes[noteId];
        Types.PendingWithdrawalData storage pending = pendingWithdrawals[noteId];
        if (note.status != Types.NoteStatus.PendingWithdrawal || !pending.exists) {
            revert Errors.NotPendingWithdrawal();
        }
        if (block.timestamp >= pending.challengeDeadline) revert Errors.ChallengeExpired();
        _validateRequestBinding(inputs);
        // Archived requests prove membership at the time of the request. Other
        // deposits or closes may change the root before this escape starts, so
        // the historical root must remain part of the original verified proof.
        // The matching nullifier binds that evidence to the withdrawn state.
        if (inputs.requestNullifier != pending.withdrawalNullifier) revert Errors.ReplayedNullifier();
        proofAdapter.assertValidRequest(inputs, proof);

        uint256 restoredRoot = MerkleUpdateLib.verifyAndUpdate(currentRoot, noteId, 0, _leaf(noteId, note), siblings);
        uint256 nullifier = pending.withdrawalNullifier;
        _setCurrentRoot(restoredRoot);
        note.status = Types.NoteStatus.Active;
        delete pendingWithdrawals[noteId];
        // A challenge cancels the payout without burning the nullifier, so a clearance-backed
        // mutualClose may still use it; it can never back another escape.
        delete usedNullifiers[nullifier];
        challengedNullifiers[nullifier] = true;
        _grantChallengeGrace(noteId, note);
        emit EscapeWithdrawalChallenged(noteId, nullifier, restoredRoot);
    }

    function finalizeEscapeWithdrawal(uint32 noteId) external nonReentrant {
        Types.Note storage note = notes[noteId];
        Types.PendingWithdrawalData storage pending = pendingWithdrawals[noteId];
        if (note.status != Types.NoteStatus.PendingWithdrawal || !pending.exists) {
            revert Errors.NotPendingWithdrawal();
        }
        if (block.timestamp < pending.challengeDeadline) revert Errors.ChallengeNotExpired();

        uint256 nullifier = pending.withdrawalNullifier;
        uint128 finalBalance = pending.finalBalance;
        address destination = pending.destination;
        uint128 operatorShare = note.depositAmount - finalBalance;
        note.status = Types.NoteStatus.Closed;
        delete pendingWithdrawals[noteId];
        _pay(destination, finalBalance, operatorShare);
        emit EscapeWithdrawalFinalized(noteId, nullifier, finalBalance, destination);
    }

    function claimExpired(uint32 noteId, uint256[32] calldata siblings) external nonReentrant whenNotPaused {
        Types.Note storage note = notes[noteId];
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        if (block.timestamp < _claimableAt(noteId, note)) revert Errors.NoteNotExpired();
        uint256 newRoot = MerkleUpdateLib.verifyAndUpdate(currentRoot, noteId, _leaf(noteId, note), 0, siblings);
        uint128 amount = note.depositAmount;
        _setCurrentRoot(newRoot);
        note.status = Types.NoteStatus.Closed;
        _payTreasury(amount);
        emit ExpiredClaimed(noteId, amount, newRoot);
    }

    /// @notice Schedules a treasury change; acceptTreasury applies it after treasuryChangeDelay of
    ///         unpaused time.
    function setTreasury(address newTreasury) external onlyOwner whenNotPaused {
        if (newTreasury == address(0) || newTreasury == address(this)) revert Errors.Unauthorized();
        uint64 readyAt = uint64(_activeClock()) + treasuryChangeDelay;
        pendingTreasury = newTreasury;
        pendingTreasuryReadyAt = readyAt;
        emit TreasuryChangeScheduled(newTreasury, readyAt);
    }

    function acceptTreasury() external onlyOwner whenNotPaused {
        address newTreasury = pendingTreasury;
        if (newTreasury == address(0)) revert Errors.NoPendingTreasuryChange();
        if (_activeClock() < pendingTreasuryReadyAt) revert Errors.TreasuryChangeNotReady();
        treasury = newTreasury;
        delete pendingTreasury;
        delete pendingTreasuryReadyAt;
        emit TreasurySet(newTreasury);
    }

    function cancelTreasuryChange() external onlyOwner {
        address cancelled = pendingTreasury;
        if (cancelled == address(0)) revert Errors.NoPendingTreasuryChange();
        delete pendingTreasury;
        delete pendingTreasuryReadyAt;
        emit TreasuryChangeCancelled(cancelled);
    }

    /// @notice Pays treasury shares whose push failed to the current treasury.
    function withdrawTreasuryArrears() external nonReentrant whenNotPaused {
        uint128 amount = treasuryArrears;
        if (amount == 0) revert Errors.ZeroAmount();
        treasuryArrears = 0;
        address recipient = treasury;
        _transfer(recipient, amount);
        emit TreasuryArrearsPaid(recipient, amount);
    }

    function pause() external onlyOwner whenNotPaused {
        paused = true;
        pausedAt = uint64(block.timestamp);
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        if (!paused) revert Errors.NotPaused();
        totalPausedDuration += uint64(block.timestamp) - pausedAt;
        paused = false;
        pausedAt = 0;
        lastUnpausedAt = uint64(block.timestamp);
        emit Unpaused(msg.sender);
    }

    /// @dev Prevents making a pause permanent by mistake. It does not bound the owner: pauses are
    ///      unbounded and transferOwnership stays open while paused (for key rotation), so the
    ///      owner can freeze funds indefinitely, though nothing can sweep them while paused.
    function renounceOwnership() public override onlyOwner whenNotPaused {
        super.renounceOwnership();
    }

    /// @notice True for the current root and for roots replaced within ROOT_HISTORY_WINDOW.
    function isKnownRoot(uint256 root) public view returns (bool) {
        if (root == currentRoot) return true;
        uint256 retiredAt = rootRetiredAt[root];
        return retiredAt != 0 && block.timestamp <= retiredAt + ROOT_HISTORY_WINDOW;
    }

    /// @notice Earliest wall-clock time claimExpired can succeed, assuming no further pause.
    /// @dev Equals expiryTs plus all pause time since the deposit (at least challengePeriod of
    ///      unpaused time after a successful challenge), and never less than unpauseClaimGrace
    ///      after the latest unpause. While paused it projects an immediate unpause and keeps
    ///      increasing. Zero for unknown notes.
    function effectiveExpiry(uint32 noteId) external view returns (uint64) {
        Types.Note storage note = notes[noteId];
        if (note.status == Types.NoteStatus.Uninitialized) return 0;
        uint256 wallClock = _claimableAt(noteId, note);
        return wallClock > type(uint64).max ? type(uint64).max : uint64(wallClock);
    }

    function _closeActive(Types.WithdrawalPublicInputs calldata inputs, uint256[32] calldata siblings) private {
        Types.Note storage note = notes[inputs.noteId];
        if (note.status != Types.NoteStatus.Active) revert Errors.NoteNotActive();
        if (inputs.finalBalance > note.depositAmount) revert Errors.InvalidBalance();
        _consumeNullifier(inputs.withdrawalNullifier);
        uint256 newRoot =
            MerkleUpdateLib.verifyAndUpdate(currentRoot, inputs.noteId, _leaf(inputs.noteId, note), 0, siblings);
        uint128 operatorShare = note.depositAmount - inputs.finalBalance;
        _setCurrentRoot(newRoot);
        note.status = Types.NoteStatus.Closed;
        _pay(inputs.destination, inputs.finalBalance, operatorShare);
    }

    function _pay(address destination, uint128 balance, uint128 operatorShare) private {
        if (balance != 0) _transfer(destination, balance);
        _payTreasury(operatorShare);
    }

    function _transfer(address destination, uint128 amount) private {
        (bool success,) = payable(destination).call{value: uint256(amount) * nativeAssetWeiPerUnit}("");
        if (!success) revert Errors.NativeTransferFailed();
    }

    /// @dev A treasury that reverts or runs out of gas cannot freeze mutualClose and
    ///      finalizeEscapeWithdrawal payouts (or claimExpired): its share is retained in
    ///      treasuryArrears. No return data is copied.
    function _payTreasury(uint128 amount) private {
        if (amount == 0) return;
        address recipient = treasury;
        uint256 value = uint256(amount) * nativeAssetWeiPerUnit;
        bool success;
        assembly ("memory-safe") {
            success := call(TREASURY_PAYOUT_GAS, recipient, value, 0, 0, 0, 0)
        }
        if (!success) {
            treasuryArrears += amount;
            emit TreasuryPaymentDeferred(recipient, amount);
        }
    }

    function _consumeNullifier(uint256 nullifier) private {
        if (usedNullifiers[nullifier]) revert Errors.ReplayedNullifier();
        usedNullifiers[nullifier] = true;
    }

    function _setCurrentRoot(uint256 newRoot) private {
        rootRetiredAt[currentRoot] = uint64(block.timestamp);
        currentRoot = newRoot;
    }

    /// @dev Delays, but does not prevent, an expiry sweep right after a challenge: the note keeps
    ///      at least challengePeriod of unpaused time to exit from its signed successor state.
    function _grantChallengeGrace(uint32 noteId, Types.Note storage note) private {
        uint256 graceEnd = _activeClock() + challengePeriod;
        if (graceEnd > _noteActiveExpiry(noteId, note)) {
            _activeExpiry[noteId] = graceEnd > type(uint64).max ? type(uint64).max : uint64(graceEnd);
        }
    }

    function _pausedDuration() private view returns (uint256) {
        return paused ? uint256(totalPausedDuration) + (block.timestamp - pausedAt) : totalPausedDuration;
    }

    /// @dev Wall-clock time minus all paused time; frozen while paused.
    function _activeClock() private view returns (uint256) {
        return block.timestamp - _pausedDuration();
    }

    /// @dev Wall-clock time from which claimExpired may take the note, assuming no further pause:
    ///      its active-clock expiry plus all paused time, but no earlier than unpauseClaimGrace after
    ///      the latest unpause (an immediate unpause is assumed while paused). The grace means a
    ///      pause can never leave a note less than that to exit, however briefly it lasted.
    function _claimableAt(uint32 noteId, Types.Note storage note) private view returns (uint256 claimableAt) {
        claimableAt = _noteActiveExpiry(noteId, note) + _pausedDuration();
        uint256 unpausedAt = paused ? block.timestamp : lastUnpausedAt;
        if (unpausedAt != 0 && unpausedAt + unpauseClaimGrace > claimableAt) {
            claimableAt = unpausedAt + unpauseClaimGrace;
        }
    }

    function _noteActiveExpiry(uint32 noteId, Types.Note storage note) private view returns (uint256) {
        uint64 adjusted = _activeExpiry[noteId];
        return adjusted == 0 ? note.expiryTs : adjusted;
    }

    function _validateRequestBinding(Types.RequestPublicInputs calldata inputs) private view {
        if (
            inputs.protocolVersion != PROTOCOL_VERSION || inputs.chainId != block.chainid
                || inputs.contractAddress != address(this) || inputs.stateSigningKeyX != stateSigningKeyX
                || inputs.stateSigningKeyY != stateSigningKeyY
        ) revert Errors.InvalidDeploymentBinding();
    }

    function _validateWithdrawalBinding(Types.WithdrawalPublicInputs calldata inputs) private view {
        if (
            inputs.protocolVersion != PROTOCOL_VERSION || inputs.chainId != block.chainid
                || inputs.contractAddress != address(this) || inputs.stateSigningKeyX != stateSigningKeyX
                || inputs.stateSigningKeyY != stateSigningKeyY || inputs.clearanceSigningKeyX != clearanceSigningKeyX
                || inputs.clearanceSigningKeyY != clearanceSigningKeyY
        ) revert Errors.InvalidDeploymentBinding();
    }

    function _leaf(uint32 noteId, Types.Note storage note) private view returns (uint256) {
        return NoteLeafLib.computeLeaf(noteId, note.commitment, note.depositAmount, note.expiryTs);
    }

    function _computeEmptyTreeRoot() private pure returns (uint256 root) {
        for (uint256 level = 0; level < MERKLE_DEPTH;) {
            root = MerkleUpdateLib.poseidonNodeHash(root, root);
            unchecked {
                ++level;
            }
        }
    }

    function _requireField(uint256 value) private pure {
        if (value >= MerkleUpdateLib.FIELD_MODULUS) revert Errors.InvalidFelt();
    }
}
