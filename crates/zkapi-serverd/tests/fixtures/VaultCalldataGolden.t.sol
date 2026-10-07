// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Golden calldata of the revision-3 vault calls, as Solidity's abi.encodeCall
// encodes them: vault_calldata_golden.json is this test's output. Regenerate
// from a Foundry project with forge-std (for example protocol/contracts):
//   forge test --match-contract GoldenTest -vv
// and copy each logged hex string into the JSON. zkapi-serverd's
// watcher::tests::golden_calldata_matches_forge_abi_encode pins its encoders
// against it.

import {Test, console} from "forge-std/Test.sol";

// Types.sol of vault revision 3 (§4.1): field order == public-input order.
struct RequestPublicInputs {
    uint16 protocolVersion; uint64 chainId; address contractAddress; uint256 activeRoot;
    uint256 stateSigningKeyX; uint256 stateSigningKeyY; uint64 requestTime; uint128 solvencyBound;
    uint256 requestNullifier; uint256 authorizationTag; uint256 anonymousCommitmentX; uint256 anonymousCommitmentY;
}
struct WithdrawalPublicInputs {
    uint16 protocolVersion; uint64 chainId; address contractAddress; uint256 activeRoot;
    uint256 stateSigningKeyX; uint256 stateSigningKeyY;
    uint256 clearanceSigningKeyX; uint256 clearanceSigningKeyY;
    uint32 noteId; uint128 finalBalance; address destination; uint256 withdrawalNullifier;
    uint8 kind; uint256 nextNullifier; uint128 conceded; uint64 validUntil;
}

interface IVault {
    function challengeEscapeWithdrawal(uint32 noteId, RequestPublicInputs calldata inputs, bytes calldata proof) external;
    function raiseEscapeConcession(uint32 noteId, RequestPublicInputs calldata inputs, bytes calldata proof, uint128 amount) external;
    function initiateEscapeWithdrawal(WithdrawalPublicInputs calldata inputs, bytes calldata proof) external;
    function mutualClose(WithdrawalPublicInputs calldata inputs, bytes calldata proof) external;
    function retireClosedLeaf(uint32 noteId, uint256[32] calldata siblings) external;
}

contract GoldenTest is Test {
    function proof() internal pure returns (bytes memory out) {
        out = new bytes(256);
        for (uint256 i = 0; i < 256; i++) out[i] = bytes1(uint8(i + 1));
    }

    function request() internal pure returns (RequestPublicInputs memory r) {
        r.protocolVersion = 2;
        r.chainId = 11155111;
        r.contractAddress = 0x00112233445566778899AABbCCdDeeFf00112233;
        r.activeRoot = 0x0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9;
        r.stateSigningKeyX = 0x1111111111111111111111111111111111111111111111111111111111111111;
        r.stateSigningKeyY = 0x2222222222222222222222222222222222222222222222222222222222222222;
        r.requestTime = 1767225600;
        r.solvencyBound = type(uint128).max;
        r.requestNullifier = 0x0102030405060708091011121314151617181920212223242526272829303132;
        r.authorizationTag = 0x2a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849;
        r.anonymousCommitmentX = 0x0333333333333333333333333333333333333333333333333333333333333333;
        r.anonymousCommitmentY = 0x0444444444444444444444444444444444444444444444444444444444444444;
    }

    function withdrawal(uint8 kind) internal pure returns (WithdrawalPublicInputs memory w) {
        w.protocolVersion = 2;
        w.chainId = 1;
        w.contractAddress = 0x00112233445566778899AABbCCdDeeFf00112233;
        w.activeRoot = 0x0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9;
        w.stateSigningKeyX = 0x1111111111111111111111111111111111111111111111111111111111111111;
        w.stateSigningKeyY = 0x2222222222222222222222222222222222222222222222222222222222222222;
        w.clearanceSigningKeyX = 0x0555555555555555555555555555555555555555555555555555555555555555;
        w.clearanceSigningKeyY = 0x0666666666666666666666666666666666666666666666666666666666666666;
        w.noteId = type(uint32).max;
        w.finalBalance = 1_000_000_000_000_000_000;
        w.destination = 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF;
        w.withdrawalNullifier = 0x0102030405060708091011121314151617181920212223242526272829303132;
        w.kind = kind;
        if (kind == 0) {
            w.nextNullifier = 0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40;
            w.conceded = 123456789;
        }
        w.validUntil = type(uint64).max;
    }

    function test_print_golden_vectors() public pure {
        console.log("defeat");
        console.logBytes(abi.encodeCall(IVault.challengeEscapeWithdrawal, (type(uint32).max, request(), proof())));
        console.log("raise");
        console.logBytes(abi.encodeCall(IVault.raiseEscapeConcession, (7, request(), proof(), 123456789012345678901234567890)));
        console.log("escape");
        console.logBytes(abi.encodeCall(IVault.initiateEscapeWithdrawal, (withdrawal(0), proof())));
        console.log("close");
        console.logBytes(abi.encodeCall(IVault.mutualClose, (withdrawal(1), proof())));
        uint256[32] memory siblings;
        for (uint256 i = 0; i < 32; i++) siblings[i] = (i + 1) * 0x0101010101010101;
        console.log("retire");
        console.logBytes(abi.encodeCall(IVault.retireClosedLeaf, (9, siblings)));
    }
}
