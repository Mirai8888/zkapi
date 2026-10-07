// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SetupPolicy} from "../script/SetupPolicy.sol";

/// @dev Exposes the deployment script's setup policy.
contract DeploySetupPolicyHarness is SetupPolicy {
    function check(SetupFacts memory setup, uint256 chainId, bool local, bool allowDevSetup) external pure {
        _checkSetupPolicy(setup, chainId, local, allowDevSetup);
    }
}

/// @dev Deploy.s.sol deploys a single-party setup (dev, rehearsal) freely on local chains, off
///      local chains only with ALLOW_DEV_SETUP=1 and never on mainnet, and an mpc-1 setup off local
///      chains only with the committed ceremony manifest's verifying keys, so neither the label nor
///      a self-made manifest gets a forgeable vault onto a public chain.
contract DeploySetupPolicyTest is Test {
    uint256 constant LOCAL = 31_337;
    uint256 constant SEPOLIA = 11_155_111;
    uint256 constant MAINNET = 1;
    // The committed dev setup's verifying-key hashes (protocol/setup/v2-concession-dev).
    bytes32 constant DEV_REQUEST_VK = 0x4d6c1a19dafd1d93488bf60059ab458f4aa1849a405eb0b6e13fd7f3d575b872;
    bytes32 constant DEV_WITHDRAWAL_VK = 0x293e7d3c553b79f9389f4448a8c50e79aef637161ded055d541988a0135ec5dd;
    bytes32 constant CEREMONY_REQUEST_VK = keccak256("ceremony request vk");
    bytes32 constant CEREMONY_WITHDRAWAL_VK = keccak256("ceremony withdrawal vk");

    string constant SINGLE_PARTY_DEV =
        "setup dev is single-party: off local chains it deploys only the drill vault, with ALLOW_DEV_SETUP=1";
    string constant SINGLE_PARTY_REHEARSAL =
        "setup rehearsal is single-party: off local chains it deploys only the drill vault, with ALLOW_DEV_SETUP=1";
    string constant MAINNET_NEEDS_CEREMONY = "mainnet needs the ceremony setup (mpc-1)";
    string constant NOT_PINNED =
        "mpc-1 is not pinned yet: protocol/setup/v2-concession/manifest.json lands with the ceremony keys (G-SETUP step 7)";
    string constant NOT_THE_CEREMONY =
        "SETUP_MANIFEST's mpc-1 verifying keys are not the ceremony's (protocol/setup/v2-concession/manifest.json)";

    DeploySetupPolicyHarness harness;

    function setUp() public {
        harness = new DeploySetupPolicyHarness();
    }

    function _facts(string memory setupId, bytes32 request, bytes32 withdrawal, bool pinned)
        internal
        pure
        returns (SetupPolicy.SetupFacts memory facts)
    {
        facts.circuitId = "zkapi-v2-concession-v1";
        facts.setupId = setupId;
        facts.requestVkHash = request;
        facts.withdrawalVkHash = withdrawal;
        facts.ceremonyPinned = pinned;
        if (pinned) {
            facts.ceremonyRequestVkHash = CEREMONY_REQUEST_VK;
            facts.ceremonyWithdrawalVkHash = CEREMONY_WITHDRAWAL_VK;
        }
    }

    function test_singlePartySetupsDeployFreelyOnLocalChains() public view {
        harness.check(_facts("dev", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false), LOCAL, true, false);
        harness.check(_facts("rehearsal", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false), 1337, true, false);
    }

    /// Off local chains (Sepolia, or any other public chain) a single-party setup needs the drill
    /// vault's explicit opt-in.
    function test_singlePartySetupsNeedTheOptInOffLocalChains() public {
        uint256[3] memory chains = [SEPOLIA, 17_000, 8453];
        for (uint256 i = 0; i < chains.length; ++i) {
            vm.expectRevert(bytes(SINGLE_PARTY_DEV));
            harness.check(_facts("dev", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false), chains[i], false, false);
            vm.expectRevert(bytes(SINGLE_PARTY_REHEARSAL));
            harness.check(_facts("rehearsal", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, true), chains[i], false, false);
            harness.check(_facts("dev", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false), chains[i], false, true);
            harness.check(_facts("rehearsal", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, true), chains[i], false, true);
        }
    }

    function test_mainnetRefusesSinglePartySetupsEvenWithTheOptIn() public {
        bool[2] memory optIn = [false, true];
        for (uint256 i = 0; i < optIn.length; ++i) {
            vm.expectRevert(bytes(MAINNET_NEEDS_CEREMONY));
            harness.check(_facts("dev", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, true), MAINNET, false, optIn[i]);
            vm.expectRevert(bytes(MAINNET_NEEDS_CEREMONY));
            harness.check(_facts("rehearsal", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, true), MAINNET, false, optIn[i]);
        }
    }

    /// Before the ceremony keys are pinned no mpc-1 setup deploys off a local chain, whatever its
    /// manifest claims: a relabelled dev setup, or any self-made one.
    function test_mpc1NeedsTheCommittedCeremonyPins() public {
        uint256[2] memory chains = [SEPOLIA, MAINNET];
        for (uint256 i = 0; i < chains.length; ++i) {
            vm.expectRevert(bytes(NOT_PINNED));
            harness.check(_facts("mpc-1", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false), chains[i], false, true);
            vm.expectRevert(bytes(NOT_PINNED));
            harness.check(_facts("mpc-1", CEREMONY_REQUEST_VK, CEREMONY_WITHDRAWAL_VK, false), chains[i], false, false);
        }
    }

    /// Once pinned, an mpc-1 setup deploys only with both of the ceremony's verifying-key hashes.
    function test_mpc1MustMatchBothCeremonyVerifyingKeys() public {
        uint256[2] memory chains = [SEPOLIA, MAINNET];
        for (uint256 i = 0; i < chains.length; ++i) {
            harness.check(_facts("mpc-1", CEREMONY_REQUEST_VK, CEREMONY_WITHDRAWAL_VK, true), chains[i], false, false);
            vm.expectRevert(bytes(NOT_THE_CEREMONY));
            harness.check(_facts("mpc-1", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, true), chains[i], false, true);
            vm.expectRevert(bytes(NOT_THE_CEREMONY));
            harness.check(_facts("mpc-1", CEREMONY_REQUEST_VK, DEV_WITHDRAWAL_VK, true), chains[i], false, false);
            vm.expectRevert(bytes(NOT_THE_CEREMONY));
            harness.check(_facts("mpc-1", DEV_REQUEST_VK, CEREMONY_WITHDRAWAL_VK, true), chains[i], false, false);
        }
        // Local chains accept an mpc-1 setup that is not pinned (testing the import pipeline).
        harness.check(_facts("mpc-1", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false), LOCAL, true, false);
    }

    function test_refusesOtherCircuitsAndUnknownSetupIds() public {
        SetupPolicy.SetupFacts memory facts = _facts("dev", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false);
        facts.circuitId = "zkapi-v2-note-bound-v1";
        vm.expectRevert(bytes("SETUP_MANIFEST is not a zkapi-v2-concession-v1 setup"));
        harness.check(facts, LOCAL, true, false);
        string[3] memory unknown = ["mpc-2", "", "DEV"];
        for (uint256 i = 0; i < unknown.length; ++i) {
            vm.expectRevert(bytes("SETUP_MANIFEST names an unknown setup_id"));
            harness.check(_facts(unknown[i], CEREMONY_REQUEST_VK, CEREMONY_WITHDRAWAL_VK, true), LOCAL, true, true);
        }
    }
}
