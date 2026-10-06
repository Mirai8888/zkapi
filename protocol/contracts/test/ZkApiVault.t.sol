// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {IZkApiProofAdapter} from "../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";

/// @dev Isolates vault checks; the real adapter has separate Groth16 fixture tests.
contract MockProofAdapter is IZkApiProofAdapter {
    bytes32 private acceptedRequest;

    function acceptRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) external {
        acceptedRequest = keccak256(abi.encode(inputs, proof));
    }

    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) external view {
        if (keccak256(abi.encode(inputs, proof)) != acceptedRequest) revert Errors.InvalidProof();
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {}
}

contract ZkApiVaultTest is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint128 constant DEPOSIT = 1_000_000;
    uint256 constant STATE_X = 11;
    uint256 constant STATE_Y = 12;
    uint256 constant CLEAR_X = 13;
    uint256 constant CLEAR_Y = 14;

    MockProofAdapter adapter;
    ZkApiVault vault;
    address user = address(0x1234);
    address treasury = address(0x5678);
    uint256[32] emptySiblings;

    function setUp() public {
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = zero;
            zero = Bn254Poseidon.hash3(DOMAIN_NODE, zero, zero);
        }
        adapter = new MockProofAdapter();
        vault = new ZkApiVault(
            treasury, 30 days, 24 hours, 100_000, address(adapter), STATE_X, STATE_Y, CLEAR_X, CLEAR_Y, address(this)
        );
        vm.deal(user, uint256(DEPOSIT) * 1 gwei);
    }

    function test_depositAndMutualClose() public {
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(42)), DEPOSIT, emptySiblings);
        uint256 depositedRoot = vault.currentRoot();

        Types.WithdrawalPublicInputs memory inputs = Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: depositedRoot,
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            clearanceSigningKeyX: CLEAR_X,
            clearanceSigningKeyY: CLEAR_Y,
            noteId: 0,
            finalBalance: 700_000,
            destination: user,
            withdrawalNullifier: 99,
            hasClearance: true,
            withdrawalTag: 100
        });
        vault.mutualClose(inputs, "", emptySiblings);
        assertEq(user.balance, 700_000 gwei);
        assertEq(treasury.balance, 300_000 gwei);
        assertTrue(vault.usedNullifiers(99));
        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Closed));
    }

    function test_escapeHatchWaitsThenFinalizesFromAnyAccount() public {
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(42)), DEPOSIT, emptySiblings);
        uint256 depositedRoot = vault.currentRoot();

        Types.WithdrawalPublicInputs memory inputs = Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: depositedRoot,
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            clearanceSigningKeyX: CLEAR_X,
            clearanceSigningKeyY: CLEAR_Y,
            noteId: 0,
            finalBalance: 800_000,
            destination: user,
            withdrawalNullifier: 101,
            hasClearance: false,
            withdrawalTag: 102
        });
        vault.initiateEscapeWithdrawal(inputs, "", emptySiblings);

        (,,, Types.NoteStatus pendingStatus) = vault.notes(0);
        assertEq(uint256(pendingStatus), uint256(Types.NoteStatus.PendingWithdrawal));
        (bool exists,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        assertTrue(exists);
        assertEq(deadline, uint64(block.timestamp + 24 hours));
        assertTrue(vault.usedNullifiers(101));

        vm.expectRevert(Errors.ChallengeNotExpired.selector);
        vault.finalizeEscapeWithdrawal(0);

        vm.warp(deadline);
        vm.prank(address(0xbeef));
        vault.finalizeEscapeWithdrawal(0);

        assertEq(user.balance, 800_000 gwei);
        assertEq(treasury.balance, 200_000 gwei);
        (,,, Types.NoteStatus finalStatus) = vault.notes(0);
        assertEq(uint256(finalStatus), uint256(Types.NoteStatus.Closed));
        (bool stillExists,,,,,) = vault.pendingWithdrawals(0);
        assertFalse(stillExists);
    }

    function test_challengesRequestAtEscapeRoot() public {
        _depositFirstNote();
        Types.RequestPublicInputs memory request = _archiveRequest();
        _initiateEscape(emptySiblings);
        _challengeAndAssertRestored(request, emptySiblings, request.activeRoot);
    }

    function test_challengesHistoricalRequestAfterUnrelatedDeposit() public {
        _depositFirstNote();
        Types.RequestPublicInputs memory request = _archiveRequest();
        _depositSecondNote();
        uint256 escapeRoot = vault.currentRoot();
        assertNotEq(escapeRoot, request.activeRoot);
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);

        _initiateEscape(siblings);
        _challengeAndAssertRestored(request, siblings, escapeRoot);
        (,,, Types.NoteStatus otherStatus) = vault.notes(1);
        assertEq(uint256(otherStatus), uint256(Types.NoteStatus.Active));
        assertEq(address(vault).balance, 2 * uint256(DEPOSIT) * 1 gwei);
    }

    function test_challengesHistoricalRequestAfterUnrelatedClose() public {
        _depositFirstNote();
        _depositSecondNote();
        Types.RequestPublicInputs memory request = _archiveRequest();

        Types.WithdrawalPublicInputs memory other = _withdrawalInputs(1, 202, true);
        vault.mutualClose(other, "", _siblingsWithOtherLeaf(0));
        uint256 escapeRoot = vault.currentRoot();
        assertNotEq(escapeRoot, request.activeRoot);

        _initiateEscape(emptySiblings);
        _challengeAndAssertRestored(request, emptySiblings, escapeRoot);
        (,,, Types.NoteStatus otherStatus) = vault.notes(1);
        assertEq(uint256(otherStatus), uint256(Types.NoteStatus.Closed));
        assertEq(address(vault).balance, uint256(DEPOSIT) * 1 gwei);
    }

    function test_historicalChallengeRestoresAgainstTreeChangedWhilePending() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        Types.WithdrawalPublicInputs memory other = _withdrawalInputs(1, 202, true);
        vault.mutualClose(other, "", emptySiblings);

        _challengeAndAssertRestored(request, emptySiblings, request.activeRoot);
        (,,, Types.NoteStatus otherStatus) = vault.notes(1);
        assertEq(uint256(otherStatus), uint256(Types.NoteStatus.Closed));
        assertEq(address(vault).balance, uint256(DEPOSIT) * 1 gwei);
    }

    function test_historicalChallengeRejectsDifferentNullifier() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        request.requestNullifier += 1;
        adapter.acceptRequest(request, hex"cafe");
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);

        vm.expectRevert(Errors.ReplayedNullifier.selector);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", siblings);
        _assertPending();
    }

    function test_historicalChallengePreservesDeploymentAndKeyBinding() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);
        for (uint256 field = 0; field < 5; ++field) {
            Types.RequestPublicInputs memory invalid = _requestInputs(request.activeRoot);
            if (field == 0) invalid.protocolVersion += 1;
            if (field == 1) invalid.chainId += 1;
            if (field == 2) invalid.contractAddress = address(0xdead);
            if (field == 3) invalid.stateSigningKeyX += 1;
            if (field == 4) invalid.stateSigningKeyY += 1;
            // Even evidence accepted by the adapter must match this deployment.
            adapter.acceptRequest(invalid, hex"cafe");

            vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
            vault.challengeEscapeWithdrawal(0, invalid, hex"cafe", siblings);
            _assertPending();
        }
    }

    function test_historicalChallengeStillVerifiesOriginalProofAndRoot() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.challengeEscapeWithdrawal(0, request, hex"bad0", siblings);
        _assertPending();

        // Replacing the archived root must not bypass the adapter verification.
        (, uint256 escapeRoot,,,,) = vault.pendingWithdrawals(0);
        request.activeRoot = escapeRoot;
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", siblings);
        _assertPending();
    }

    function test_historicalChallengeStillRequiresCurrentRestorationWitness() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", emptySiblings);
        _assertPending();
    }

    function test_historicalChallengeStillExpiresAtDeadline() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);
        vm.warp(deadline);
        vm.expectRevert(Errors.ChallengeExpired.selector);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", siblings);
        _assertPending();
        vault.finalizeEscapeWithdrawal(0);
        assertEq(user.balance, 800_000 gwei);
    }

    function test_escapeAcceptsRecentRootAfterUnrelatedDeposit() public {
        _depositFirstNote();
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(0, 101, false);
        _depositSecondNote();
        assertNotEq(withdrawal.activeRoot, vault.currentRoot());
        assertTrue(vault.isKnownRoot(withdrawal.activeRoot));
        vault.initiateEscapeWithdrawal(withdrawal, "", _siblingsWithOtherLeaf(1));
        _assertPending();
    }

    function test_mutualCloseAcceptsRecentRootAfterUnrelatedDeposit() public {
        _depositFirstNote();
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(0, 99, true);
        _depositSecondNote();
        vault.mutualClose(withdrawal, "", _siblingsWithOtherLeaf(1));
        assertEq(user.balance, 800_000 gwei);
        assertEq(treasury.balance, 200_000 gwei);
    }

    function test_recentRootStillRequiresLiveSiblings() public {
        _depositFirstNote();
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(0, 101, false);
        Types.WithdrawalPublicInputs memory close = _withdrawalInputs(0, 99, true);
        _depositSecondNote();
        // Siblings for the proof root no longer match the live tree.
        assertTrue(vault.isKnownRoot(withdrawal.activeRoot));
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.initiateEscapeWithdrawal(withdrawal, "", emptySiblings);
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.mutualClose(close, "", emptySiblings);
    }

    /// Residual race: the restoration witness must match the live root, so an unrelated
    /// deposit mined first defeats a challenge built on older siblings. The challenger
    /// must rebuild the path and retry before the deadline.
    function test_challengeRacedByUnrelatedDepositSucceedsWithFreshSiblings() public {
        _depositFirstNote();
        Types.RequestPublicInputs memory request = _archiveRequest();
        _initiateEscape(emptySiblings);
        uint256[32] memory builtSiblings = emptySiblings;
        // The escaped leaf is out of the tree, so slot 1's witness is all empty.
        vm.deal(user, uint256(DEPOSIT) * 1 gwei);
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(43)), DEPOSIT, emptySiblings);
        vm.prank(treasury);
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", builtSiblings);
        _assertPending();
        uint256[32] memory freshSiblings = _siblingsWithOtherLeaf(1);
        vm.prank(treasury);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", freshSiblings);
        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        assertTrue(vault.challengedNullifiers(101));
    }

    function test_withdrawalRejectsUnknownRoot() public {
        _depositFirstNote();
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(0, 101, false);
        withdrawal.activeRoot = 12_345;
        vm.expectRevert(Errors.UnknownRoot.selector);
        vault.initiateEscapeWithdrawal(withdrawal, "", emptySiblings);
        withdrawal.hasClearance = true;
        vm.expectRevert(Errors.UnknownRoot.selector);
        vault.mutualClose(withdrawal, "", emptySiblings);
    }

    function test_withdrawalRejectsRootRetiredBeyondWindow() public {
        _depositFirstNote();
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(0, 101, false);
        _depositSecondNote();
        uint256 retiredAt = vault.rootRetiredAt(withdrawal.activeRoot);
        assertEq(retiredAt, block.timestamp);
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);
        uint256 window = vault.ROOT_HISTORY_WINDOW();
        vm.warp(retiredAt + window + 1);
        assertFalse(vault.isKnownRoot(withdrawal.activeRoot));
        vm.expectRevert(Errors.UnknownRoot.selector);
        vault.initiateEscapeWithdrawal(withdrawal, "", siblings);
        withdrawal.hasClearance = true;
        vm.expectRevert(Errors.UnknownRoot.selector);
        vault.mutualClose(withdrawal, "", siblings);
        withdrawal.hasClearance = false;
        vm.warp(retiredAt + window);
        vault.initiateEscapeWithdrawal(withdrawal, "", siblings);
    }

    /// The zero address and the vault itself (which cannot receive ETH) are refused before
    /// anything changes, so neither can become an escape's payee.
    function test_withdrawalRejectsZeroOrVaultDestination() public {
        _depositFirstNote();
        address[2] memory refused = [address(0), address(vault)];
        for (uint256 i = 0; i < refused.length; ++i) {
            Types.WithdrawalPublicInputs memory escape = _withdrawalInputs(0, 101, false);
            escape.destination = refused[i];
            vm.expectRevert(Errors.InvalidDestination.selector);
            vault.initiateEscapeWithdrawal(escape, "", emptySiblings);
            Types.WithdrawalPublicInputs memory close = _withdrawalInputs(0, 99, true);
            close.destination = refused[i];
            vm.expectRevert(Errors.InvalidDestination.selector);
            vault.mutualClose(close, "", emptySiblings);
        }
        assertFalse(vault.usedNullifiers(101));
        assertFalse(vault.usedNullifiers(99));
        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        (bool exists,,,,,) = vault.pendingWithdrawals(0);
        assertFalse(exists);
        assertEq(address(vault).balance, uint256(DEPOSIT) * 1 gwei);
    }

    function test_recurringRootIsCurrentThenRefreshedOnRetirement() public {
        _depositFirstNote();
        uint256 rootA = vault.currentRoot();
        _depositSecondNote();
        vm.warp(block.timestamp + vault.ROOT_HISTORY_WINDOW() + 1);
        assertFalse(vault.isKnownRoot(rootA));
        // Closing note 1 returns the tree to exactly rootA.
        vault.mutualClose(_withdrawalInputs(1, 202, true), "", _siblingsWithOtherLeaf(0));
        assertEq(vault.currentRoot(), rootA);
        assertTrue(vault.isKnownRoot(rootA));
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(0, 101, false);
        vm.deal(user, user.balance + uint256(DEPOSIT) * 1 gwei);
        uint256[32] memory slotTwo = emptySiblings;
        slotTwo[1] = Bn254Poseidon.hash3(DOMAIN_NODE, _leafOf(0), 0);
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(44)), DEPOSIT, slotTwo);
        assertEq(vault.rootRetiredAt(rootA), block.timestamp);
        uint256[32] memory pathZero = emptySiblings;
        pathZero[1] = Bn254Poseidon.hash3(DOMAIN_NODE, _leafOf(2), 0);
        vault.initiateEscapeWithdrawal(withdrawal, "", pathZero);
        _assertPending();
    }

    // Every root change retires the replaced root, so a withdrawal proven just before an
    // unrelated deposit, close, escape, challenge or expiry claim only needs fresh siblings.
    // Each transition below replaces a root the vault has not retired before.

    function test_depositRetiresReplacedRoot() public {
        _depositFirstNote();
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        uint256 oldRoot = vault.currentRoot();
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(0, 101, false);
        _depositSecondNote();
        _assertRetiredRootStillWithdraws(oldRoot, withdrawal);
    }

    function test_mutualCloseRetiresReplacedRoot() public {
        _depositFirstNote();
        _depositSecondNote();
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        uint256 oldRoot = vault.currentRoot();
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(0, 101, false);
        vault.mutualClose(_withdrawalInputs(1, 202, true), "", _path(1));
        _assertRetiredRootStillWithdraws(oldRoot, withdrawal);
    }

    function test_escapeRetiresReplacedRoot() public {
        _depositFirstNote();
        _depositSecondNote();
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        uint256 oldRoot = vault.currentRoot();
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(0, 99, true);
        vault.initiateEscapeWithdrawal(_withdrawalInputs(1, 202, false), "", _path(1));
        _assertRetiredRootStillWithdraws(oldRoot, withdrawal);
    }

    function test_challengeRetiresReplacedRoot() public {
        // With a third note, the escape below leaves a root the tree never had before, so
        // the challenge does not merely restore a root an earlier deposit retired.
        _depositFirstNote();
        _depositSecondNote();
        _depositThirdNote();
        Types.RequestPublicInputs memory request = _requestInputs(vault.currentRoot());
        request.requestNullifier = 202;
        adapter.acceptRequest(request, hex"cafe");
        vault.initiateEscapeWithdrawal(_withdrawalInputs(1, 202, false), "", _path(1));
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        uint256 oldRoot = vault.currentRoot();
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(0, 101, false);
        vault.challengeEscapeWithdrawal(1, request, hex"cafe", _path(1));
        _assertRetiredRootStillWithdraws(oldRoot, withdrawal);
    }

    function test_claimExpiredRetiresReplacedRoot() public {
        _depositFirstNote();
        vm.warp(vm.getBlockTimestamp() + 20 days);
        _depositSecondNote();
        vm.warp(vault.effectiveExpiry(0));
        uint256 oldRoot = vault.currentRoot();
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(1, 202, false);
        vault.claimExpired(0, _path(0));
        _assertRetiredRootStillWithdraws(oldRoot, withdrawal);
    }

    function test_challengeClearsNullifierThenMutualCloseAtSameAnchor() public {
        _depositFirstNote();
        Types.RequestPublicInputs memory request = _archiveRequest();
        _initiateEscape(emptySiblings);
        _challengeAndAssertRestored(request, emptySiblings, request.activeRoot);
        // The challenge blocks escapes only; a clearance (operator consent) still closes.
        vault.mutualClose(_withdrawalInputs(0, 101, true), "", emptySiblings);
        assertTrue(vault.usedNullifiers(101));
        assertTrue(vault.challengedNullifiers(101));
        assertEq(user.balance, 800_000 gwei);
        assertEq(treasury.balance, 200_000 gwei);
        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Closed));
    }

    function test_challengedNullifierCannotEscapeAgain() public {
        _depositFirstNote();
        Types.RequestPublicInputs memory request = _archiveRequest();
        Types.WithdrawalPublicInputs memory defeated = _withdrawalInputs(0, 101, false);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(defeated, "", emptySiblings);
        _challengeAndAssertRestored(request, emptySiblings, request.activeRoot);
        // The root is current again, so only the challenge record stops these.
        assertEq(vault.currentRoot(), defeated.activeRoot);

        vm.prank(user);
        vm.expectRevert(Errors.ChallengedNullifier.selector);
        vault.initiateEscapeWithdrawal(defeated, "", emptySiblings);
        // Anyone can replay the public calldata of the defeated escape.
        vm.prank(address(0xBAD));
        vm.expectRevert(Errors.ChallengedNullifier.selector);
        vault.initiateEscapeWithdrawal(defeated, "", emptySiblings);
        Types.WithdrawalPublicInputs memory redirected = _withdrawalInputs(0, 101, false);
        redirected.destination = address(0xC0FFEE);
        redirected.finalBalance = DEPOSIT;
        redirected.withdrawalTag = 103;
        vm.prank(user);
        vm.expectRevert(Errors.ChallengedNullifier.selector);
        vault.initiateEscapeWithdrawal(redirected, "", emptySiblings);

        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        (bool exists,,,,,) = vault.pendingWithdrawals(0);
        assertFalse(exists);
        assertFalse(vault.usedNullifiers(101));
        assertEq(address(vault).balance, uint256(DEPOSIT) * 1 gwei);
        assertEq(user.balance, 0);
        assertEq(treasury.balance, 0);
    }

    /// k served requests give k spent anchors; each stale escape is defeated once, and the
    /// current anchor still withdraws.
    function test_noteSurvivesKChallengeRoundsAndWithdrawsAtCurrentAnchor() public {
        _depositFirstNote();
        uint256 k = 4;
        for (uint256 i = 0; i < k; ++i) {
            uint256 spent = 1_000 + i;
            Types.RequestPublicInputs memory request = _requestInputs(vault.currentRoot());
            request.requestNullifier = spent;
            adapter.acceptRequest(request, hex"cafe");
            vault.initiateEscapeWithdrawal(_withdrawalInputs(0, spent, false), "", emptySiblings);
            vm.prank(treasury);
            vault.challengeEscapeWithdrawal(0, request, hex"cafe", emptySiblings);
            assertFalse(vault.usedNullifiers(spent));
            assertTrue(vault.challengedNullifiers(spent));
            (,,, Types.NoteStatus status) = vault.notes(0);
            assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        }
        for (uint256 i = 0; i < k; ++i) {
            Types.WithdrawalPublicInputs memory stale = _withdrawalInputs(0, 1_000 + i, false);
            vm.expectRevert(Errors.ChallengedNullifier.selector);
            vault.initiateEscapeWithdrawal(stale, "", emptySiblings);
        }
        assertFalse(vault.challengedNullifiers(2_000));

        uint256 snapshot = vm.snapshotState();
        vault.mutualClose(_withdrawalInputs(0, 2_000, true), "", emptySiblings);
        assertEq(user.balance, 800_000 gwei);
        assertEq(treasury.balance, 200_000 gwei);
        vm.revertToState(snapshot);

        // Without operator help: the current anchor was never spent, so no evidence defeats it.
        vault.initiateEscapeWithdrawal(_withdrawalInputs(0, 2_000, false), "", emptySiblings);
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline);
        vault.finalizeEscapeWithdrawal(0);
        assertEq(user.balance, 800_000 gwei);
        assertEq(treasury.balance, 200_000 gwei);
    }

    function test_challengeNearExpiryGrantsGraceBeforeClaim() public {
        _depositFirstNote();
        (,, uint64 expiry,) = vault.notes(0);
        vm.warp(expiry - 1 hours);
        Types.RequestPublicInputs memory request = _archiveRequest();
        _initiateEscape(emptySiblings);
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline - 1);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", emptySiblings);
        uint256 graceEnd = block.timestamp + vault.challengePeriod();
        assertEq(vault.effectiveExpiry(0), graceEnd);
        vm.warp(graceEnd - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0, emptySiblings);
        vm.warp(graceEnd);
        vault.claimExpired(0, emptySiblings);
        assertEq(treasury.balance, uint256(DEPOSIT) * 1 gwei);
    }

    /// The post-challenge grace only ever extends expiry: a challenge early in a note's life
    /// leaves its expiry where it was, rather than pulling it in to challengePeriod after the
    /// challenge (which would let claimExpired sweep a note just restored for its owner).
    function test_earlyChallengeNeverLowersExpiry() public {
        _depositFirstNote();
        (,, uint64 expiry,) = vault.notes(0);
        Types.RequestPublicInputs memory request = _archiveRequest();
        _initiateEscape(emptySiblings);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", emptySiblings);
        uint256 challengedAt = vm.getBlockTimestamp();
        assertLt(challengedAt + vault.challengePeriod(), expiry);
        assertEq(vault.effectiveExpiry(0), expiry);

        vm.warp(challengedAt + vault.challengePeriod());
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0, emptySiblings);
        vm.warp(expiry - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0, emptySiblings);
        vm.warp(expiry);
        vault.claimExpired(0, emptySiblings);
        assertEq(treasury.balance, uint256(DEPOSIT) * 1 gwei);
    }

    /// The same at the last moment of a challenge window that closes well before expiry.
    function test_challengeAtDeadlineFarFromExpiryKeepsExpiry() public {
        _depositFirstNote();
        (,, uint64 expiry,) = vault.notes(0);
        vm.warp(vm.getBlockTimestamp() + 10 days);
        Types.RequestPublicInputs memory request = _archiveRequest();
        _initiateEscape(emptySiblings);
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline - 1);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", emptySiblings);
        assertEq(vault.effectiveExpiry(0), expiry);
        vm.warp(uint256(deadline) - 1 + vault.challengePeriod());
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0, emptySiblings);
    }

    function _leafOf(uint32 noteId) private view returns (uint256) {
        (bytes32 commitment, uint128 amount, uint64 expiryTs,) = vault.notes(noteId);
        return NoteLeafLib.computeLeaf(noteId, commitment, amount, expiryTs);
    }

    function _depositFirstNote() private {
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(42)), DEPOSIT, emptySiblings);
    }

    function _depositSecondNote() private {
        vm.deal(user, user.balance + uint256(DEPOSIT) * 1 gwei);
        uint256[32] memory siblings = _siblingsWithOtherLeaf(0);
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(43)), DEPOSIT, siblings);
    }

    function _depositThirdNote() private {
        vm.deal(user, user.balance + uint256(DEPOSIT) * 1 gwei);
        uint256[32] memory siblings = _path(2);
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(44)), DEPOSIT, siblings);
    }

    function _siblingsWithOtherLeaf(uint32 otherNoteId) private view returns (uint256[32] memory siblings) {
        siblings = emptySiblings;
        (bytes32 commitment, uint128 amount, uint64 expiryTs,) = vault.notes(otherNoteId);
        siblings[0] = NoteLeafLib.computeLeaf(otherNoteId, commitment, amount, expiryTs);
    }

    /// Live-tree siblings for slots 0..3; later slots are empty.
    function _path(uint32 noteId) private view returns (uint256[32] memory siblings) {
        require(noteId < 4, "test tree");
        siblings = emptySiblings;
        siblings[0] = _liveLeaf(noteId ^ 1);
        uint32 otherPair = (noteId >> 1) ^ 1;
        siblings[1] = Bn254Poseidon.hash3(DOMAIN_NODE, _liveLeaf(otherPair * 2), _liveLeaf(otherPair * 2 + 1));
    }

    function _liveLeaf(uint32 noteId) private view returns (uint256) {
        if (noteId >= vault.nextNoteId()) return 0;
        (,,, Types.NoteStatus status) = vault.notes(noteId);
        return status == Types.NoteStatus.Active ? _leafOf(noteId) : 0;
    }

    function _requestInputs(uint256 root) private view returns (Types.RequestPublicInputs memory) {
        return Types.RequestPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: root,
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            requestTime: uint64(block.timestamp),
            solvencyBound: 100_000,
            requestNullifier: 101,
            authorizationTag: 103,
            anonymousCommitmentX: 104,
            anonymousCommitmentY: 105
        });
    }

    function _archiveRequest() private returns (Types.RequestPublicInputs memory request) {
        request = _requestInputs(vault.currentRoot());
        adapter.acceptRequest(request, hex"cafe");
        adapter.assertValidRequest(request, hex"cafe");
    }

    function _withdrawalInputs(uint32 noteId, uint256 nullifier, bool clearance)
        private
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        return Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: vault.currentRoot(),
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            clearanceSigningKeyX: CLEAR_X,
            clearanceSigningKeyY: CLEAR_Y,
            noteId: noteId,
            finalBalance: 800_000,
            destination: user,
            withdrawalNullifier: nullifier,
            hasClearance: clearance,
            withdrawalTag: 102
        });
    }

    function _initiateEscape(uint256[32] memory siblings) private {
        vault.initiateEscapeWithdrawal(_withdrawalInputs(0, 101, false), "", siblings);
    }

    function _pendingAfterRootChange() private returns (Types.RequestPublicInputs memory request) {
        _depositFirstNote();
        request = _archiveRequest();
        _depositSecondNote();
        _initiateEscape(_siblingsWithOtherLeaf(1));
    }

    function _assertPending() private view {
        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.PendingWithdrawal));
        (bool exists,,,,,) = vault.pendingWithdrawals(0);
        assertTrue(exists);
        assertTrue(vault.usedNullifiers(101));
    }

    /// The transition just made retired `oldRoot` now, and another note's withdrawal proven at
    /// it is accepted with fresh siblings.
    function _assertRetiredRootStillWithdraws(uint256 oldRoot, Types.WithdrawalPublicInputs memory withdrawal) private {
        assertNotEq(vault.currentRoot(), oldRoot);
        assertEq(vault.rootRetiredAt(oldRoot), vm.getBlockTimestamp());
        assertTrue(vault.isKnownRoot(oldRoot));
        assertEq(withdrawal.activeRoot, oldRoot);
        uint256[32] memory siblings = _path(withdrawal.noteId);
        Types.NoteStatus expected = Types.NoteStatus.PendingWithdrawal;
        if (withdrawal.hasClearance) {
            vault.mutualClose(withdrawal, "", siblings);
            expected = Types.NoteStatus.Closed;
        } else {
            vault.initiateEscapeWithdrawal(withdrawal, "", siblings);
        }
        (,,, Types.NoteStatus status) = vault.notes(withdrawal.noteId);
        assertEq(uint256(status), uint256(expected));
    }

    function _challengeAndAssertRestored(
        Types.RequestPublicInputs memory request,
        uint256[32] memory siblings,
        uint256 expectedRoot
    ) private {
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        // Archived authorizations need not be fresh when the challenge arrives.
        vm.warp(deadline - 1);
        vm.prank(treasury);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", siblings);
        assertEq(vault.currentRoot(), expectedRoot);
        (,,, Types.NoteStatus status) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        (bool exists,,,,,) = vault.pendingWithdrawals(0);
        assertFalse(exists);
        // A challenge is non-destructive: the escaped state is no longer burned, but it can
        // never back another escape.
        assertFalse(vault.usedNullifiers(101));
        assertTrue(vault.challengedNullifiers(101));
        vm.warp(deadline);
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.finalizeEscapeWithdrawal(0);
    }
}
