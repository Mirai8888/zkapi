// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {IZkApiProofAdapter} from "../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Events} from "../src/libraries/Events.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";

contract AcceptAllProofs is IZkApiProofAdapter {
    function assertValidRequest(Types.RequestPublicInputs calldata, bytes calldata) external pure {}
    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {}
}

contract RejectingTreasury {
    receive() external payable {
        revert();
    }
}

contract GasBurningTreasury {
    receive() external payable {
        while (true) {}
    }
}

/// Accepts payments with about 45k gas, well inside TREASURY_PAYOUT_GAS.
contract CostlyTreasury {
    uint256 public payments;
    mapping(uint256 => uint256) private receipts;

    receive() external payable {
        receipts[++payments] = msg.value;
    }
}

/// @dev Pause, expiry, treasury-timelock and guard-coverage regressions.
contract ZkApiVaultPauseTest is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint128 constant UNITS = 1_000_000;
    /// TREASURY_PAYOUT_GAS as the docs state it. Pinned here rather than read from the vault, so
    /// that raising the cap fails the gas-burning-treasury bounds.
    uint256 constant DOCUMENTED_PAYOUT_GAS = 100_000;
    address user = address(0x1234);
    address treasury = address(0x5678);
    ZkApiVault vault;
    uint256[32] emptySiblings;

    function setUp() public {
        vm.warp(1_700_000_000);
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = zero;
            zero = Bn254Poseidon.hash3(DOMAIN_NODE, zero, zero);
        }
        vault = new ZkApiVault(
            treasury, 30 days, 24 hours, 100_000, address(new AcceptAllProofs()), 11, 12, 13, 14, address(this)
        );
        vm.deal(user, 100 ether);
    }

    // ---------------------------------------------------------------- expiry

    function test_claimExpiredRevertsWhilePaused() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        uint256[32] memory path = _path(id);
        vm.warp(expiry);
        vault.pause();
        vm.expectRevert(Errors.Paused.selector);
        vault.claimExpired(id, path);
        vm.warp(expiry + 7 days);
        vault.unpause();
        // The note had already expired when the pause began, but nobody could claim it
        // while users were locked out, and its owner gets the unpause grace to exit.
        uint256 claimAt = expiry + 7 days + vault.unpauseClaimGrace();
        assertEq(vault.effectiveExpiry(id), claimAt);
        vm.warp(claimAt - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id, path);
        vm.warp(claimAt);
        vault.claimExpired(id, path);
        assertEq(treasury.balance, uint256(UNITS) * 1 gwei);
    }

    function test_pauseExtendsExpiryAndKeepsExitsAfterUnpause() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        uint256[32] memory path = _path(id);
        Types.WithdrawalPublicInputs memory close = _withdrawal(id, 99, true);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 98, false);
        vm.warp(expiry - 1 days);
        vault.pause();
        vm.expectRevert(Errors.Paused.selector);
        vault.mutualClose(close, "", path);
        vm.expectRevert(Errors.Paused.selector);
        vault.initiateEscapeWithdrawal(escape, "", path);
        vm.warp(expiry + 30 days);
        vault.unpause();
        // One day remained when the pause began; one day remains after it.
        assertEq(vault.effectiveExpiry(id), expiry + 31 days);

        uint256 snapshot = vm.snapshotState();
        vault.initiateEscapeWithdrawal(escape, "", path);
        vm.revertToState(snapshot);
        vault.mutualClose(close, "", path);
        assertEq(user.balance, 100 ether - uint256(UNITS) * 1 gwei + 700_000 gwei);
        vm.revertToState(snapshot);

        vm.warp(expiry + 31 days - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id, path);
        vm.warp(expiry + 31 days);
        vault.claimExpired(id, path);
    }

    function test_repeatedPausesAccumulateOnlyAfterDeposit() public {
        uint32 first = _deposit(42);
        vault.pause();
        vm.warp(block.timestamp + 3 days);
        vault.unpause();
        uint32 second = _deposit(43);
        vault.pause();
        vm.warp(block.timestamp + 5 days);
        vault.unpause();
        vault.pause();
        vault.unpause(); // zero-length pause
        (,, uint64 firstExpiry,) = vault.notes(first);
        (,, uint64 secondExpiry,) = vault.notes(second);
        assertEq(vault.totalPausedDuration(), 8 days);
        assertEq(vault.effectiveExpiry(first), firstExpiry + 8 days);
        assertEq(vault.effectiveExpiry(second), secondExpiry + 5 days);
    }

    function test_effectiveExpiryProjectsWhilePaused() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        assertEq(vault.effectiveExpiry(id), expiry);
        assertEq(vault.effectiveExpiry(7), 0);
        vault.pause();
        vm.warp(block.timestamp + 2 days);
        assertEq(vault.effectiveExpiry(id), expiry + 2 days);
        vm.warp(block.timestamp + 3 days);
        assertEq(vault.effectiveExpiry(id), expiry + 5 days);
    }

    function testFuzz_effectiveExpiryMatchesPauseModel(uint32[6] memory gaps, uint8 depositAfter) public {
        uint256 deposited = depositAfter % 4;
        uint32 id;
        uint256 pausedSinceDeposit;
        for (uint256 i = 0; i < 3; ++i) {
            if (i == deposited) id = _deposit(bytes32(uint256(42)));
            // Unpaused gaps can outlast the TTL, so both claim bounds below get exercised.
            vm.warp(block.timestamp + (gaps[2 * i] % 20 days));
            vault.pause();
            uint256 duration = gaps[2 * i + 1] % 10 days;
            vm.warp(block.timestamp + duration);
            vault.unpause();
            if (i >= deposited) pausedSinceDeposit += duration;
        }
        if (deposited == 3) id = _deposit(bytes32(uint256(42)));
        (,, uint64 expiry,) = vault.notes(id);
        // Expiry moves by the pause time since the deposit, and never lands inside the
        // grace that follows the latest unpause (which just happened).
        assertEq(vault.lastUnpausedAt(), block.timestamp);
        uint256 claimAt = uint256(expiry) + pausedSinceDeposit;
        uint256 graceEnd = block.timestamp + vault.unpauseClaimGrace();
        if (graceEnd > claimAt) claimAt = graceEnd;
        assertEq(vault.effectiveExpiry(id), claimAt);
        uint256[32] memory path = _path(id);
        vm.warp(claimAt - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id, path);
        vm.warp(claimAt);
        vault.claimExpired(id, path);
    }

    function test_inFlightEscapeResolvesWhilePaused() public {
        uint32 id = _deposit(42);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 101, false);
        Types.RequestPublicInputs memory request = _request(101);
        vault.initiateEscapeWithdrawal(escape, "", _path(id));
        uint256[32] memory zeroPath = _path(id);
        vault.pause();

        uint256 snapshot = vm.snapshotState();
        vault.challengeEscapeWithdrawal(id, request, "", zeroPath);
        (,,, Types.NoteStatus status) = vault.notes(id);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        assertFalse(vault.usedNullifiers(101));
        vm.revertToState(snapshot);

        (,,,,, uint64 deadline) = vault.pendingWithdrawals(id);
        vm.warp(deadline);
        uint256 before = user.balance;
        vault.finalizeEscapeWithdrawal(id);
        assertEq(user.balance - before, 700_000 gwei);
        assertEq(treasury.balance, 300_000 gwei);
    }

    function test_challengeDuringPauseGrantsGraceAfterUnpause() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 101, false);
        Types.RequestPublicInputs memory request = _request(101);
        vm.warp(expiry - 1 hours);
        vault.initiateEscapeWithdrawal(escape, "", _path(id));
        uint256[32] memory zeroPath = _path(id);
        vm.warp(expiry + 1 hours);
        vault.pause();
        vault.challengeEscapeWithdrawal(id, request, "", zeroPath);
        vm.warp(block.timestamp + 10 days);
        vault.unpause();
        uint256 graceEnd = block.timestamp + vault.challengePeriod();
        assertEq(vault.effectiveExpiry(id), graceEnd);
        uint256[32] memory path = _path(id);
        vm.warp(graceEnd - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id, path);
        vm.warp(graceEnd);
        vault.claimExpired(id, path);
    }

    function test_pauseJustBeforeExpiryLeavesClaimGraceAfterUnpause() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        uint256[32] memory path = _path(id);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 98, false);
        vm.warp(expiry - 1);
        vault.pause();
        uint256 unpausedAt = uint256(expiry) - 1 + 5 days;
        vm.warp(unpausedAt);
        vault.unpause();
        // One second of note time was left, but every unpause restores the full grace.
        uint256 claimAt = unpausedAt + vault.unpauseClaimGrace();
        assertEq(vault.lastUnpausedAt(), unpausedAt);
        assertEq(vault.effectiveExpiry(id), claimAt);
        vm.warp(claimAt - 1);
        uint256 snapshot = vm.snapshotState();
        vault.initiateEscapeWithdrawal(escape, "", path);
        vm.revertToState(snapshot);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id, path);
        vm.warp(claimAt);
        vault.claimExpired(id, path);
        assertEq(treasury.balance, uint256(UNITS) * 1 gwei);
    }

    /// A malicious owner front-runs every exit attempt with a short pause. Each pause costs it
    /// almost no expiry time, but each unpause restarts the claim grace, so the sweep never
    /// opens while the user keeps retrying more often than unpauseClaimGrace.
    function test_frontRunPausesCannotForceExpiry() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        uint256[32] memory path = _path(id);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 99, false);
        // Time is tracked locally: via-IR may reuse a cached block.timestamp across warps.
        uint256 time = vm.getBlockTimestamp();
        while (time < uint256(expiry) + 10 days) {
            vault.pause(); // mined just before the user's transaction
            vm.prank(user);
            vm.expectRevert(Errors.Paused.selector);
            vault.initiateEscapeWithdrawal(escape, "", path);
            time += 12;
            vm.warp(time);
            vault.unpause();
            time += 6 hours;
            vm.warp(time);
            vm.expectRevert(Errors.NoteNotExpired.selector);
            vault.claimExpired(id, path);
        }
        assertLt(vault.totalPausedDuration(), 1 hours);
        assertEq(vault.effectiveExpiry(id), vault.lastUnpausedAt() + vault.unpauseClaimGrace());
        // As soon as the owner stops pausing, the next attempt goes through.
        vm.prank(user);
        vault.initiateEscapeWithdrawal(escape, "", path);
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(id);
        vm.warp(deadline);
        vault.finalizeEscapeWithdrawal(id);
        assertEq(user.balance, 100 ether - uint256(UNITS) * 1 gwei + 700_000 gwei);
        assertEq(treasury.balance, 300_000 gwei);
    }

    /// Accepted residual: pauses are unbounded, so the owner (or a key lost after an accepted
    /// transfer) can freeze funds indefinitely, but nothing can sweep them while the vault stays
    /// paused.
    function test_unboundedPauseFreezesButCannotSeize() public {
        uint32 id = _deposit(42);
        uint256[32] memory path = _path(id);
        address lost = address(0xdead);
        vault.pause();
        vault.transferOwnership(lost);
        vm.prank(lost);
        vault.acceptOwnership();
        vm.warp(block.timestamp + 3650 days);
        vm.expectRevert(Errors.Paused.selector);
        vault.claimExpired(id, path);
        assertEq(address(vault).balance, uint256(UNITS) * 1 gwei);
        assertEq(treasury.balance, 0);
    }

    function test_pauseAndUnpauseEmitAndRejectRedundantCalls() public {
        vm.expectEmit(address(vault));
        emit Events.Paused(address(this));
        vault.pause();
        assertTrue(vault.paused());
        assertEq(vault.pausedAt(), block.timestamp);
        vm.expectRevert(Errors.Paused.selector);
        vault.pause();
        vm.warp(block.timestamp + 1 hours);
        vm.expectEmit(address(vault));
        emit Events.Unpaused(address(this));
        vault.unpause();
        assertEq(vault.totalPausedDuration(), 1 hours);
        assertEq(vault.pausedAt(), 0);
        vm.expectRevert(Errors.NotPaused.selector);
        vault.unpause();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        vault.pause();
    }

    function test_renounceOwnershipRevertsWhilePaused() public {
        vault.pause();
        vm.expectRevert(Errors.Paused.selector);
        vault.renounceOwnership();
        vault.unpause();
        vault.renounceOwnership();
        assertEq(vault.owner(), address(0));
    }

    function test_renounceOwnershipClearsPendingOwner() public {
        address rotated = address(0xB0B);
        vault.transferOwnership(rotated);
        vault.renounceOwnership();
        assertEq(vault.owner(), address(0));
        assertEq(vault.pendingOwner(), address(0));
        vm.prank(rotated);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, rotated));
        vault.acceptOwnership();
        assertEq(vault.owner(), address(0));
    }

    /// The exempt owner actions used for incident key rotation still work while paused. The
    /// old key stays in charge until the nominee accepts.
    function test_ownerKeyRotationWorksWhilePaused() public {
        address rotated = address(0xB0B);
        vault.pause();
        vm.expectEmit(address(vault));
        emit Ownable2Step.OwnershipTransferStarted(address(this), rotated);
        vault.transferOwnership(rotated);
        assertEq(vault.owner(), address(this));
        assertEq(vault.pendingOwner(), rotated);
        vm.prank(rotated);
        vm.expectEmit(address(vault));
        emit Ownable.OwnershipTransferred(address(this), rotated);
        vault.acceptOwnership();
        assertEq(vault.owner(), rotated);
        assertEq(vault.pendingOwner(), address(0));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        vault.unpause();
        vm.prank(rotated);
        vault.unpause();
        assertFalse(vault.paused());
        assertEq(vault.lastUnpausedAt(), block.timestamp);
    }

    /// A mistyped rotation during a pause no longer strands the vault: the old owner can still
    /// unpause and replace the nomination, after which the mistyped address cannot accept.
    function test_mistypedTransferWhilePausedLeavesOwnerInControl() public {
        address mistyped = address(0xdead);
        address rotated = address(0xB0B);
        vault.pause();
        vault.transferOwnership(mistyped);
        assertEq(vault.owner(), address(this));
        assertEq(vault.pendingOwner(), mistyped);
        vault.transferOwnership(rotated);
        assertEq(vault.pendingOwner(), rotated);
        vm.prank(mistyped);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, mistyped));
        vault.acceptOwnership();
        vault.unpause();
        assertFalse(vault.paused());
        assertEq(vault.owner(), address(this));
        assertEq(vault.pendingOwner(), rotated);
    }

    function test_onlyPendingOwnerCanAcceptOwnership() public {
        address rotated = address(0xB0B);
        vault.pause();
        vm.prank(rotated);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, rotated));
        vault.acceptOwnership();
        vault.transferOwnership(rotated);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        vault.acceptOwnership();
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        vault.acceptOwnership();
        // Nominating the zero address cancels the transfer.
        vault.transferOwnership(address(0));
        vm.prank(rotated);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, rotated));
        vault.acceptOwnership();
        assertEq(vault.owner(), address(this));
        assertEq(vault.pendingOwner(), address(0));
    }

    // -------------------------------------------------------------- treasury

    function test_setTreasuryIsTwoStepAndTimelocked() public {
        address next = address(0xA4513425);
        uint64 readyAt = uint64(block.timestamp) + vault.treasuryChangeDelay();
        vm.expectEmit(address(vault));
        emit Events.TreasuryChangeScheduled(next, readyAt);
        vault.setTreasury(next);
        assertEq(vault.treasury(), treasury);
        assertEq(vault.pendingTreasury(), next);
        assertEq(vault.pendingTreasuryReadyAt(), readyAt);
        vm.warp(readyAt - 1);
        vm.expectRevert(Errors.TreasuryChangeNotReady.selector);
        vault.acceptTreasury();
        vm.warp(readyAt);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        vault.acceptTreasury();
        vm.expectEmit(address(vault));
        emit Events.TreasurySet(next);
        vault.acceptTreasury();
        assertEq(vault.treasury(), next);
        assertEq(vault.pendingTreasury(), address(0));
        vm.expectRevert(Errors.NoPendingTreasuryChange.selector);
        vault.acceptTreasury();
        vm.expectRevert(Errors.Unauthorized.selector);
        vault.setTreasury(address(0));
        vm.expectRevert(Errors.Unauthorized.selector);
        vault.setTreasury(address(vault));
    }

    function test_rescheduleRestartsTreasuryTimelock() public {
        vault.setTreasury(address(0xA));
        uint256 firstReady = vault.pendingTreasuryReadyAt();
        vm.warp(firstReady - 1);
        vault.setTreasury(address(0xB));
        vm.warp(firstReady);
        vm.expectRevert(Errors.TreasuryChangeNotReady.selector);
        vault.acceptTreasury();
    }

    function test_treasuryChangeBlockedWhilePausedButCancellable() public {
        vault.setTreasury(address(0xA));
        uint256 readyAt = vault.pendingTreasuryReadyAt();
        vault.pause();
        vm.expectRevert(Errors.Paused.selector);
        vault.setTreasury(address(0xB));
        vm.warp(readyAt);
        vm.expectRevert(Errors.Paused.selector);
        vault.acceptTreasury();
        vm.expectEmit(address(vault));
        emit Events.TreasuryChangeCancelled(address(0xA));
        vault.cancelTreasuryChange();
        vault.unpause();
        vm.expectRevert(Errors.NoPendingTreasuryChange.selector);
        vault.acceptTreasury();
        assertEq(vault.treasury(), treasury);
    }

    function test_treasuryTimelockCountsOnlyUnpausedTime() public {
        uint256 time = vm.getBlockTimestamp();
        // An earlier pause leaves the active clock 3 days behind the wall clock.
        vault.pause();
        time += 3 days;
        vm.warp(time);
        vault.unpause();
        address next = address(0xA11CE);
        uint256 delay = vault.treasuryChangeDelay();
        uint64 readyAt = uint64(time - 3 days + delay);
        vm.expectEmit(address(vault));
        emit Events.TreasuryChangeScheduled(next, readyAt);
        vault.setTreasury(next);
        assertEq(vault.pendingTreasuryReadyAt(), readyAt);

        // Half the delay passes unpaused; then a long pause carries the wall clock past it.
        time += delay / 2;
        vm.warp(time);
        vault.pause();
        time += 10 * delay;
        vm.warp(time);
        vault.unpause();
        // Users still get the other half of the delay, unpaused, to react.
        vm.expectRevert(Errors.TreasuryChangeNotReady.selector);
        vault.acceptTreasury();
        time += delay / 2 - 1;
        vm.warp(time);
        vm.expectRevert(Errors.TreasuryChangeNotReady.selector);
        vault.acceptTreasury();
        vm.warp(time + 1);
        vault.acceptTreasury();
        assertEq(vault.treasury(), next);
    }

    function test_treasuryDelayAndClaimGraceAreAtLeastChallengePeriod() public {
        assertEq(vault.treasuryChangeDelay(), vault.MIN_TREASURY_CHANGE_DELAY());
        assertEq(vault.unpauseClaimGrace(), 1 days);
        ZkApiVault slow = new ZkApiVault(
            treasury, 30 days, 5 days, 100_000, address(new AcceptAllProofs()), 11, 12, 13, 14, address(this)
        );
        assertEq(slow.treasuryChangeDelay(), 5 days);
        assertEq(slow.unpauseClaimGrace(), 5 days);
        ZkApiVault fast = new ZkApiVault(
            treasury, 30 days, 1 hours, 100_000, address(new AcceptAllProofs()), 11, 12, 13, 14, address(this)
        );
        assertEq(fast.treasuryChangeDelay(), 2 days);
        assertEq(fast.unpauseClaimGrace(), 1 days);
    }

    function test_rejectingTreasuryCannotFreezePayouts() public {
        uint32 escaping = _deposit(42);
        uint32 expiring = _deposit(43);
        address rejecting = address(new RejectingTreasury());
        _switchTreasury(rejecting);
        vault.initiateEscapeWithdrawal(_withdrawal(escaping, 101, false), "", _path(escaping));
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(escaping);
        vm.warp(deadline);
        uint256 before = user.balance;
        vault.finalizeEscapeWithdrawal(escaping);
        assertEq(user.balance - before, 700_000 gwei);
        assertEq(vault.treasuryArrears(), 300_000);
        (,, uint64 expiry,) = vault.notes(expiring);
        vm.warp(expiry);
        vault.claimExpired(expiring, _path(expiring));
        assertEq(vault.treasuryArrears(), 300_000 + UNITS);
        assertEq(address(vault).balance, uint256(300_000 + UNITS) * 1 gwei);
        _switchTreasury(treasury);
        vm.expectEmit(address(vault));
        emit Events.TreasuryArrearsPaid(treasury, 300_000 + UNITS);
        vault.withdrawTreasuryArrears();
        assertEq(treasury.balance, uint256(300_000 + UNITS) * 1 gwei);
        assertEq(address(vault).balance, 0);
        vm.expectRevert(Errors.ZeroAmount.selector);
        vault.withdrawTreasuryArrears();
    }

    /// A treasury that burns all the gas it is given adds at most the documented cap (plus the
    /// arrears bookkeeping) to every payout that pushes to it, however much gas the caller sends.
    function test_gasBurningTreasuryIsBoundedOnMutualClose() public {
        uint32 id = _deposit(42);
        bytes memory close = abi.encodeCall(vault.mutualClose, (_withdrawal(id, 99, true), "", _path(id)));
        _assertGasBurningTreasuryBounded("mutualClose", close, 300_000);
    }

    /// The same bound on finalizeEscapeWithdrawal, a user's own exit.
    function test_gasBurningTreasuryIsBoundedOnEscapeFinalization() public {
        uint32 id = _deposit(42);
        vault.initiateEscapeWithdrawal(_withdrawal(id, 101, false), "", _path(id));
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(id);
        vm.warp(deadline);
        bytes memory finalize = abi.encodeCall(vault.finalizeEscapeWithdrawal, (id));
        _assertGasBurningTreasuryBounded("finalizeEscapeWithdrawal", finalize, 300_000);
    }

    /// The same bound on claimExpired.
    function test_gasBurningTreasuryIsBoundedOnExpiryClaim() public {
        uint32 id = _deposit(42);
        vm.warp(vault.effectiveExpiry(id));
        bytes memory claim = abi.encodeCall(vault.claimExpired, (id, _path(id)));
        _assertGasBurningTreasuryBounded("claimExpired", claim, UNITS);
    }

    /// A caller cannot starve a working treasury of gas to push its share into arrears: any
    /// gas limit either pays the treasury or reverts the whole close.
    function test_underfundedGasCannotForceTreasuryDeferral() public {
        uint32 id = _deposit(42);
        CostlyTreasury costly = new CostlyTreasury();
        _switchTreasury(address(costly));
        bytes memory close = abi.encodeCall(vault.mutualClose, (_withdrawal(id, 99, true), "", _path(id)));
        uint256 snapshot = vm.snapshotState();
        uint256 gasBefore = gasleft();
        (bool ok,) = address(vault).call(close);
        uint256 used = gasBefore - gasleft();
        assertTrue(ok);
        assertEq(costly.payments(), 1);
        vm.revertToState(snapshot);

        uint256 paid;
        uint256 reverted;
        for (uint256 limit = used - 150_000; limit <= used + 150_000; limit += 5_000) {
            (ok,) = address(vault).call{gas: limit}(close);
            if (ok) {
                ++paid;
                assertEq(costly.payments(), 1);
            } else {
                ++reverted;
                (,,, Types.NoteStatus status) = vault.notes(id);
                assertEq(uint256(status), uint256(Types.NoteStatus.Active));
            }
            assertEq(vault.treasuryArrears(), 0);
            vm.revertToState(snapshot);
        }
        assertGt(paid, 0);
        assertGt(reverted, 0);
    }

    // -------------------------------------------------------- guard coverage

    /// Every state-changing external function must be classified. Guarded ones
    /// must revert Paused(); only in-flight escape resolution and owner-recovery
    /// actions stay open while paused.
    function test_pauseGuardCoverage() public {
        string[9] memory guarded = [
            "deposit",
            "mutualClose",
            "initiateEscapeWithdrawal",
            "claimExpired",
            "setTreasury",
            "acceptTreasury",
            "withdrawTreasuryArrears",
            "renounceOwnership",
            "pause"
        ];
        string[6] memory exempt = [
            "challengeEscapeWithdrawal",
            "finalizeEscapeWithdrawal",
            "unpause",
            "cancelTreasuryChange",
            "transferOwnership",
            "acceptOwnership"
        ];
        string memory artifact = vm.readFile(string.concat(vm.projectRoot(), "/out/ZkApiVault.sol/ZkApiVault.json"));
        uint256 mutating;
        for (uint256 i = 0;; ++i) {
            string memory entry = string.concat(".abi[", vm.toString(i), "]");
            if (!vm.keyExistsJson(artifact, entry)) break;
            if (!_eq(vm.parseJsonString(artifact, string.concat(entry, ".type")), "function")) continue;
            string memory mutability = vm.parseJsonString(artifact, string.concat(entry, ".stateMutability"));
            if (_eq(mutability, "view") || _eq(mutability, "pure")) continue;
            string memory name = vm.parseJsonString(artifact, string.concat(entry, ".name"));
            uint256 matches;
            for (uint256 j = 0; j < guarded.length; ++j) {
                if (_eq(name, guarded[j])) ++matches;
            }
            for (uint256 j = 0; j < exempt.length; ++j) {
                if (_eq(name, exempt[j])) ++matches;
            }
            assertEq(matches, 1, string.concat("unclassified or duplicated pause policy: ", name));
            ++mutating;
        }
        assertEq(mutating, guarded.length + exempt.length, "stale pause classification");

        vault.pause();
        string[] memory signatures = vm.parseJsonKeys(artifact, ".methodIdentifiers");
        uint256 checked;
        for (uint256 i = 0; i < signatures.length; ++i) {
            string memory name = _name(signatures[i]);
            bool isGuarded;
            for (uint256 j = 0; j < guarded.length; ++j) {
                if (_eq(name, guarded[j])) isGuarded = true;
            }
            if (!isGuarded) continue;
            // Zero calldata decodes for every signature; the guard runs before any argument check.
            (bool success, bytes memory reason) =
                address(vault).call(abi.encodePacked(bytes4(keccak256(bytes(signatures[i]))), new bytes(70 * 32)));
            assertFalse(success, signatures[i]);
            assertEq(bytes4(reason), Errors.Paused.selector, signatures[i]);
            ++checked;
        }
        assertEq(checked, guarded.length);
    }

    // --------------------------------------------------------------- helpers

    function _deposit(bytes32 commitment) private returns (uint32 id) {
        id = vault.nextNoteId();
        uint256[32] memory path = _path(id);
        vm.prank(user);
        vault.deposit{value: uint256(UNITS) * 1 gwei}(commitment, UNITS, path);
    }

    function _deposit(uint256 commitment) private returns (uint32) {
        return _deposit(bytes32(commitment));
    }

    function _switchTreasury(address next) private {
        vault.setTreasury(next);
        vm.warp(block.timestamp + vault.treasuryChangeDelay());
        vault.acceptTreasury();
    }

    /// Runs `payout` twice from the same state and time: with the funded EOA treasury, which it
    /// must pay, then with a GasBurningTreasury, whose `share` it must defer to arrears. The second
    /// run gets 1M gas of headroom, 63/64 of which an uncapped push would burn. It may use at most
    /// the documented cap plus 30k more than the first: beyond the gas it forwards, a failed push
    /// only records the arrears (one SSTORE, at most 22,100) and emits TreasuryPaymentDeferred.
    function _assertGasBurningTreasuryBounded(string memory label, bytes memory payout, uint128 share) private {
        assertEq(vault.TREASURY_PAYOUT_GAS(), DOCUMENTED_PAYOUT_GAS, "documented cap");
        // A funded treasury, so the baseline push pays no new-account surcharge.
        vm.deal(treasury, 1 ether);
        vault.setTreasury(address(new GasBurningTreasury()));
        vm.warp(block.timestamp + vault.treasuryChangeDelay());
        uint256 snapshot = vm.snapshotState();
        uint256 baseline = _gasUsed(payout, 30_000_000);
        assertEq(treasury.balance, 1 ether + uint256(share) * 1 gwei, "baseline pays the treasury");
        vm.revertToState(snapshot);

        vault.acceptTreasury();
        uint256 used = _gasUsed(payout, baseline + 1_000_000);
        emit log_named_uint(string.concat(label, " gas with a normal treasury"), baseline);
        emit log_named_uint(string.concat(label, " gas with a gas-burning treasury"), used);
        assertEq(vault.treasuryArrears(), share, "share deferred");
        assertLt(used, baseline + DOCUMENTED_PAYOUT_GAS + 30_000, label);
    }

    function _gasUsed(bytes memory data, uint256 limit) private returns (uint256 used) {
        uint256 gasBefore = gasleft();
        (bool ok,) = address(vault).call{gas: limit}(data);
        used = gasBefore - gasleft();
        assertTrue(ok);
    }

    function _leafAt(uint32 index) private view returns (uint256) {
        if (index >= vault.nextNoteId()) return 0;
        (bytes32 commitment, uint128 amount, uint64 expiry, Types.NoteStatus status) = vault.notes(index);
        return status == Types.NoteStatus.Active ? NoteLeafLib.computeLeaf(index, commitment, amount, expiry) : 0;
    }

    /// Path for slots 0..3 of a tree whose other leaves are empty.
    function _path(uint32 index) private view returns (uint256[32] memory siblings) {
        require(index < 4, "test tree");
        siblings = emptySiblings;
        siblings[0] = _leafAt(index ^ 1);
        uint32 otherPair = (index >> 1) ^ 1;
        siblings[1] = Bn254Poseidon.hash3(DOMAIN_NODE, _leafAt(otherPair * 2), _leafAt(otherPair * 2 + 1));
    }

    function _withdrawal(uint32 id, uint256 nullifier, bool clearance)
        private
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        return Types.WithdrawalPublicInputs(
            2,
            uint64(block.chainid),
            address(vault),
            vault.currentRoot(),
            11,
            12,
            13,
            14,
            id,
            700_000,
            user,
            nullifier,
            clearance,
            100
        );
    }

    function _request(uint256 nullifier) private view returns (Types.RequestPublicInputs memory) {
        return Types.RequestPublicInputs(
            2,
            uint64(block.chainid),
            address(vault),
            vault.currentRoot(),
            11,
            12,
            uint64(block.timestamp),
            100_000,
            nullifier,
            1,
            2,
            3
        );
    }

    function _name(string memory signature) private pure returns (string memory) {
        bytes memory raw = bytes(signature);
        uint256 end;
        while (raw[end] != "(") ++end;
        bytes memory out = new bytes(end);
        for (uint256 i = 0; i < end; ++i) {
            out[i] = raw[i];
        }
        return string(out);
    }

    function _eq(string memory left, string memory right) private pure returns (bool) {
        return keccak256(bytes(left)) == keccak256(bytes(right));
    }
}
