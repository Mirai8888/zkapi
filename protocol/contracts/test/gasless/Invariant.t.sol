// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {IEntryPoint, PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalAccount} from "../../src/gasless/ZkApiWithdrawalAccount.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {ToggleableDestination} from "../NativeEthVault.t.sol";
import {GaslessTestBase} from "./GaslessTestBase.sol";

/// @dev Owns a whole gasless deployment and drives it: sponsored and direct closes, sponsored and
///      direct escapes, raises, defeats, sponsored and direct finalizations, forwards, sweeps, credit
///      claims, policy changes, write-offs and time. Two payees (an EOA and a wallet that may refuse
///      ETH) give two transit accounts. Every sponsored operation goes through handleOps; refusals
///      and reverted executions are expected outcomes, not failures. Ghost sums track what the
///      paymaster may legitimately lose.
contract GaslessHandler is GaslessTestBase {
    uint256 public constant NOTE_AMOUNT = 100_000_000; // 0.1 ether in gwei units
    uint32 public constant MAX_NOTES = 8;

    ToggleableDestination public wallet;
    address[2] public payees;
    address[2] public accounts;
    uint256 public writtenOff;
    uint256 public ghostCreditsClaimed;
    uint256 public nullifierSeq = 10_000;
    uint256 public sponsoredOps;
    uint256 public revertedOps;
    uint256 public refusedOps;

    constructor() {
        _setUpGasless();
        wallet = new ToggleableDestination();
        payees = [address(0x9A7EE), address(wallet)];
        accounts = [_transit(ownerAddr, payees[0]), _transit(ownerAddr, payees[1])];
    }

    function paymasterAddress() external view returns (address) {
        return address(paymaster);
    }

    function vaultAddress() external view returns (address) {
        return address(vault);
    }

    function initialDeposit() external pure returns (uint256) {
        return INITIAL_DEPOSIT;
    }

    function userAddress() external view returns (address) {
        return user;
    }

    // ------------------------------------------------------------------------------ actions

    function deposit() external {
        if (vault.nextNoteId() >= MAX_NOTES || vault.paused()) return;
        _depositUnits(1000 + vault.nextNoteId(), uint128(NOTE_AMOUNT));
    }

    function sponsoredClose(uint32 noteSeed, uint128 balanceSeed, uint8 payeeSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint128 balance = uint128(bound(balanceSeed, 0, NOTE_AMOUNT));
        address payee_ = payees[payeeSeed % 2];
        uint256 nullifier = ++nullifierSeq;
        (PackedUserOperation memory op,) = _closeOpFor(payee_, id, nullifier, balance);
        _sponsored(op);
    }

    function directClose(uint32 noteSeed, uint128 balanceSeed, uint8 destSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint128 balance = uint128(bound(balanceSeed, 0, NOTE_AMOUNT));
        address destination = destSeed % 3 == 2 ? user : accounts[destSeed % 2];
        Types.WithdrawalPublicInputs memory inputs = _close(id, ++nullifierSeq, balance);
        inputs.destination = destination;
        vm.prank(user);
        try vault.mutualClose(inputs, PROOF) {} catch {}
    }

    function sponsoredEscape(uint32 noteSeed, uint128 balanceSeed, uint128 concededSeed, uint8 payeeSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint128 balance = uint128(bound(balanceSeed, 0, NOTE_AMOUNT));
        uint128 conceded = uint128(bound(concededSeed, 0, balance));
        uint256 nullifier = ++nullifierSeq;
        (PackedUserOperation memory op,) =
            _escapeOpFor(payees[payeeSeed % 2], id, nullifier, nullifier + 500_000, balance - conceded, conceded);
        _sponsored(op);
    }

    function directEscape(uint32 noteSeed, uint128 balanceSeed, uint8 destSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.Active);
        if (!ok) return;
        uint128 balance = uint128(bound(balanceSeed, 0, NOTE_AMOUNT));
        uint256 nullifier = ++nullifierSeq;
        Types.WithdrawalPublicInputs memory inputs = _escape(id, nullifier, nullifier + 500_000, balance, 0);
        inputs.destination = destSeed % 3 == 2 ? user : accounts[destSeed % 2];
        vm.prank(user);
        try vault.initiateEscapeWithdrawal(inputs, PROOF) {} catch {}
    }

    function raise(uint32 noteSeed, uint128 amountSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return;
        (,, uint256 nullifier,,,) = vault.pendingWithdrawals(id);
        uint128 amount = uint128(bound(amountSeed, 0, NOTE_AMOUNT));
        Types.RequestPublicInputs memory request = _evidence(nullifier, amount);
        vm.prank(challenger);
        try vault.raiseEscapeConcession(id, request, PROOF, amount) {} catch {}
    }

    function defeat(uint32 noteSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return;
        (uint256 next,,) = vault.pendingConcessions(id);
        Types.RequestPublicInputs memory request = _evidence(next, 100_000);
        vm.prank(challenger);
        try vault.challengeEscapeWithdrawal(id, request, PROOF) {} catch {}
    }

    function sponsoredFinalize(uint32 noteSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return;
        (,,,, address destination, uint64 deadline) = vault.pendingWithdrawals(id);
        uint8 which = destination == accounts[0] ? 0 : destination == accounts[1] ? 1 : 2;
        if (which == 2) return;
        if (vm.getBlockTimestamp() < deadline) vm.warp(deadline);
        _sponsored(_finalizeOpFor(payees[which], id));
    }

    function directFinalize(uint32 noteSeed) external {
        (bool ok, uint32 id) = _note(noteSeed, Types.NoteStatus.PendingWithdrawal);
        if (!ok) return;
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(id);
        if (vm.getBlockTimestamp() < deadline) vm.warp(deadline);
        vault.finalizeEscapeWithdrawal(id);
    }

    function forward(uint8 which) external {
        which = which % 2;
        if (accounts[which].code.length == 0 && accounts[which].balance == 0) return;
        _sponsored(_forwardOpFor(payees[which]));
    }

    function sweep(uint8 which) external {
        which = which % 2;
        address s = accounts[which];
        if (s.code.length == 0) factory.createAccount(ownerAddr, payees[which]);
        if (s.balance == 0) return;
        vm.prank(user);
        ZkApiWithdrawalAccount(payable(s)).sweep();
        assertEq(s.balance, 0, "swept");
    }

    function claimCredit(uint8 which) external {
        address payee_ = payees[which % 2];
        uint256 amount = paymaster.credits(payee_);
        if (amount == 0) return;
        vm.prank(user);
        try paymaster.claimCredit(payee_) {
            ghostCreditsClaimed += amount;
        } catch {}
    }

    function toggleWallet(bool accepting) external {
        wallet.setAccepting(accepting);
    }

    function setPolicy(uint64 flatFeeSeed, bool escapes, bool paused) external {
        ZkApiWithdrawalPaymaster.Policy memory p = _defaultPolicy();
        p.flatFeeWei = uint64(bound(flatFeeSeed, 0, 0.001 ether));
        p.escapesEnabled = escapes;
        p.sponsorshipPaused = paused;
        paymaster.setPolicy(p);
    }

    function writeOff(uint8 which) external {
        address s = accounts[which % 2];
        uint256 amount = paymaster.owed(s);
        if (amount == 0) return;
        paymaster.writeOffDebt(s);
        writtenOff += amount;
    }

    function allowForward(uint8 which) external {
        paymaster.allowForward(accounts[which % 2]);
    }

    function warp(uint32 seconds_) external {
        vm.warp(vm.getBlockTimestamp() + bound(seconds_, 1, 2 days));
    }

    // ------------------------------------------------------------------------------ helpers

    function _sponsored(PackedUserOperation memory op) internal {
        OpGas memory g = _gas(CLOSE, false);
        g;
        (bool ok, bytes memory data) = _tryHandle(op);
        if (!ok) {
            ++refusedOps;
            data;
            return;
        }
        ++sponsoredOps;
    }

    function _note(uint32 seed, Types.NoteStatus wanted) internal view returns (bool ok, uint32 id) {
        uint32 count = vault.nextNoteId();
        if (count == 0) return (false, 0);
        for (uint32 i = 0; i < count; ++i) {
            id = uint32((uint256(seed) + i) % count);
            if (_status(id) == wanted) return (true, id);
        }
        return (false, 0);
    }
}

/// @dev Invariants of the paymaster under random sequences of sponsored and direct exits:
///      - the paymaster's own balance is exactly the credited payouts;
///      - the float never loses more than it records: deposit + lost + shortfall + open debts +
///        written-off debts is at least the initial deposit;
///      - a transit account holds nothing after a forward or a sweep (asserted as they happen);
///      - the vault's own balance accounting still holds.
/// forge-config: default.invariant.fail-on-revert = true
contract GaslessInvariantTest is Test {
    GaslessHandler handler;
    ZkApiWithdrawalPaymaster paymaster;
    ZkApiVault vault;
    IEntryPoint entryPoint = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);

    function setUp() public {
        handler = new GaslessHandler();
        paymaster = ZkApiWithdrawalPaymaster(handler.paymasterAddress());
        vault = ZkApiVault(handler.vaultAddress());
        for (uint256 i = 0; i < 4; ++i) {
            handler.deposit();
        }
        targetContract(address(handler));
    }

    function invariant_paymasterBalanceIsTheCredits() public view {
        assertEq(address(paymaster).balance, paymaster.totalCredits());
        assertEq(paymaster.totalCredits(), paymaster.credits(handler.payees(0)) + paymaster.credits(handler.payees(1)));
    }

    function invariant_theFloatLosesOnlyWhatItRecords() public view {
        uint256 covered = entryPoint.balanceOf(address(paymaster)) + paymaster.lostWei() + paymaster.shortfallWei()
            + paymaster.owed(handler.accounts(0)) + paymaster.owed(handler.accounts(1)) + handler.writtenOff();
        assertGe(covered, handler.initialDeposit());
    }

    function invariant_vaultBalanceAccounting() public view {
        uint256 held;
        uint32 count = vault.nextNoteId();
        for (uint32 id = 0; id < count; ++id) {
            (, uint128 amount,, Types.NoteStatus status) = vault.notes(id);
            if (status == Types.NoteStatus.Active || status == Types.NoteStatus.PendingWithdrawal) held += amount;
        }
        held += vault.treasuryArrears();
        held += vault.escapePayoutCredits(handler.accounts(0)) + vault.escapePayoutCredits(handler.accounts(1))
        + vault.escapePayoutCredits(handler.userAddress());
        assertEq(address(vault).balance, held * 1 gwei);
    }
}
