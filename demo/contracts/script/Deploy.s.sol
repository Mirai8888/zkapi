// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {ZkApiVault} from "zkapi-contracts/ZkApiVault.sol";
import {Groth16ProofAdapter} from "zkapi-contracts/adapters/Groth16ProofAdapter.sol";

/// @title DeployScript – Local demo deployment for the zkAPI EF stack.
/// @notice Deploys the circuit-specific Groth16 verifier and native ETH
///         ZkApiVault, then writes constructor and native-asset metadata to
///         $OUTPUT_PATH. Add proof hashes and oracle pins separately when
///         preparing the SDK's public deployment manifest.
/// @dev    Reads these environment variables:
///           PRIVATE_KEY – deployer key (also the vault owner on local chains
///                         unless OWNER is set).
///           OWNER       – vault owner (pause/unpause, timelocked treasury changes).
///                         Required except on local chains (31337/1337); use a
///                         multisig or timelock contract.
///           TREASURY    – operator payout address.
///           OUTPUT_PATH – absolute path for the deployment manifest JSON.
///           STATE_SIGNING_KEY_X/Y – deployment-pinned Baby-JubJub key.
///           CLEARANCE_SIGNING_KEY_X/Y – deployment-pinned Baby-JubJub key.
///           CHALLENGE_PERIOD_SECONDS – escape delay; defaults to 24 hours.
///           CHAIN_ID – optional expected chain ID; mismatches abort deployment.
///           REQUEST_CHARGE_CAP – positive per-request gwei limit; defaults to 1,000,000.
contract DeployScript is Script {
    uint64 internal constant NOTE_TTL = 30 days;

    function run() external {
        require(block.chainid == vm.envOr("CHAIN_ID", block.chainid), "CHAIN_ID does not match RPC");
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        string memory outputPath = vm.envString("OUTPUT_PATH");
        address deployer = vm.addr(deployerKey);
        // The owner can pause every exit and schedule treasury changes, so public
        // deployments must name it explicitly instead of defaulting to the deployer.
        address owner =
            (block.chainid == 31337 || block.chainid == 1337) ? vm.envOr("OWNER", deployer) : vm.envAddress("OWNER");
        require(owner != address(0), "OWNER must be nonzero");
        uint256 stateKeyX = vm.envUint("STATE_SIGNING_KEY_X");
        uint256 stateKeyY = vm.envUint("STATE_SIGNING_KEY_Y");
        uint256 clearanceKeyX = vm.envUint("CLEARANCE_SIGNING_KEY_X");
        uint256 clearanceKeyY = vm.envUint("CLEARANCE_SIGNING_KEY_Y");
        uint256 challengePeriodValue = vm.envOr("CHALLENGE_PERIOD_SECONDS", uint256(24 hours));
        require(
            challengePeriodValue > 0 && challengePeriodValue <= type(uint64).max,
            "CHALLENGE_PERIOD_SECONDS must fit a positive uint64"
        );
        uint64 challengePeriod = uint64(challengePeriodValue);
        uint256 requestChargeCapValue = vm.envOr("REQUEST_CHARGE_CAP", uint256(1_000_000));
        require(
            requestChargeCapValue > 0 && requestChargeCapValue <= 9_007_199_254_740_991,
            "REQUEST_CHARGE_CAP must be positive safe gwei units"
        );
        uint128 requestChargeCap = uint128(requestChargeCapValue);
        address poseidonLibrary = vm.envOr("POSEIDON_ADDRESS", address(0));
        // Treasury receives the operator's consumed amount on settlement. Keep
        // it separate from the depositor so consumption is visible in the demo.
        address treasury = (block.chainid == 31337 || block.chainid == 1337)
            ? vm.envOr("TREASURY", address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8))
            : vm.envAddress("TREASURY");
        require(treasury != address(0), "TREASURY must be nonzero");

        vm.startBroadcast(deployerKey);

        Groth16ProofAdapter proofAdapter = new Groth16ProofAdapter();

        ZkApiVault vault = new ZkApiVault(
            treasury,
            NOTE_TTL,
            challengePeriod,
            requestChargeCap,
            address(proofAdapter),
            stateKeyX,
            stateKeyY,
            clearanceKeyX,
            clearanceKeyY,
            owner
        );

        vm.stopBroadcast();

        string memory manifest = "deployment";
        vm.serializeUint(manifest, "chainId", block.chainid);
        vm.serializeUint(manifest, "protocolVersion", 2);
        vm.serializeString(manifest, "circuitId", "zkapi-v2-note-bound-v1");
        vm.serializeAddress(manifest, "owner", owner);
        vm.serializeAddress(manifest, "vault", address(vault));
        vm.serializeAddress(manifest, "billingToken", vault.billingToken());
        vm.serializeAddress(manifest, "proofAdapter", address(proofAdapter));
        vm.serializeAddress(manifest, "poseidonLibrary", poseidonLibrary);
        vm.serializeAddress(manifest, "treasury", treasury);
        vm.serializeUint(manifest, "requestChargeCap", requestChargeCap);
        vm.serializeString(manifest, "billing_asset", "native_eth");
        vm.serializeString(manifest, "billing_unit", "gwei");
        vm.serializeUint(manifest, "nativeAssetWeiPerUnit", vault.nativeAssetWeiPerUnit());
        vm.serializeUint(manifest, "challengePeriod", challengePeriod);
        vm.serializeUint(manifest, "treasuryChangeDelay", vault.treasuryChangeDelay());
        vm.serializeUint(manifest, "rootHistoryWindow", vault.ROOT_HISTORY_WINDOW());
        vm.serializeUint(manifest, "stateSigningKeyX", stateKeyX);
        vm.serializeUint(manifest, "stateSigningKeyY", stateKeyY);
        vm.serializeUint(manifest, "clearanceSigningKeyX", clearanceKeyX);
        vm.serializeUint(manifest, "clearanceSigningKeyY", clearanceKeyY);
        string memory serialized = vm.serializeUint(manifest, "noteTtl", uint256(NOTE_TTL));
        vm.writeJson(serialized, outputPath);

        console2.log("vault       ", address(vault));
        console2.log("treasury    ", treasury);
        console2.log("owner       ", owner);
        if (block.chainid == 1 && owner.code.length == 0) {
            console2.log("WARNING: OWNER has no code; use a multisig or timelock contract on mainnet");
        }
        console2.log("proofAdapter", address(proofAdapter));
        console2.log("noteTtl     ", uint256(NOTE_TTL));
        console2.log("manifest    ", outputPath);
    }
}
