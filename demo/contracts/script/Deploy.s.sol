// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {ZkApiVault} from "zkapi-contracts/ZkApiVault.sol";
import {Groth16ProofAdapter} from "zkapi-contracts/adapters/Groth16ProofAdapter.sol";

/// @title DeployScript – zkAPI vault deployment (circuit zkapi-v2-concession-v1, vault revision 3).
/// @notice Links (or deploys) the Bn254Poseidon library, deploys the circuit-specific Groth16
///         verifier and the native ETH ZkApiVault with its 11 constructor arguments, checks the
///         adapter's circuit and verifying-key hashes against the setup manifest and the vault's
///         getters against the inputs, then writes the deployment manifest, including the actual
///         linked addresses and the three runtime codehashes, to $OUTPUT_PATH.
///         scripts/expected-codehashes.mjs recomputes those codehashes from the compiler output.
/// @dev    The script links the vault itself (creation code from out/ZkApiVault.sol/ZkApiVault.json
///         with the library placeholder replaced), so forge never links it.
///         Reads these environment variables:
///           PRIVATE_KEY – deployer key (also the vault owner on local chains
///                         unless OWNER is set).
///           OWNER       – vault owner (bounded pause, timelocked treasury changes).
///                         Required except on local chains (31337/1337); use a
///                         multisig or timelock contract. The constructor sets it
///                         directly; later transfers are two-step (transferOwnership
///                         nominates, the new owner calls acceptOwnership).
///           TREASURY    – operator payout address.
///           OUTPUT_PATH – absolute path for the deployment manifest JSON.
///           STATE_SIGNING_KEY_X/Y – deployment-pinned Baby-JubJub key.
///           CLEARANCE_SIGNING_KEY_X/Y – deployment-pinned Baby-JubJub key.
///           CHALLENGE_PERIOD_SECONDS – escape delay; defaults to 24 hours.
///           NOTE_TTL_SECONDS – note lifetime; defaults to 30 days.
///           MAX_PAUSE_DURATION_SECONDS – longest a pause blocks exits; at least twice the
///                         challenge period. Required except on local chains (default 7 days).
///           REQUEST_CHARGE_CAP – positive per-request gwei limit; defaults to 1,000,000.
///           SETUP_MANIFEST – the setup's manifest.json; the adapter's CIRCUIT_ID_HASH and VK hashes
///                         must match it. Required except on local chains (default
///                         protocol/setup/v2-concession-dev). Mainnet refuses the dev and
///                         rehearsal setups.
///           POSEIDON_ADDRESS – an already deployed Bn254Poseidon to link; its runtime codehash
///                         must equal the compiled library's at that address. Unset deploys a
///                         fresh library.
///           CHAIN_ID – optional expected chain ID; mismatches abort deployment.
contract DeployScript is Script {
    uint64 internal constant DEFAULT_NOTE_TTL = 30 days;
    uint64 internal constant LOCAL_MAX_PAUSE_DURATION = 7 days;
    uint256 internal constant VAULT_REVISION = 3;
    string internal constant DEFAULT_SETUP_MANIFEST = "../../protocol/setup/v2-concession-dev/manifest.json";

    struct Params {
        address deployer;
        address owner;
        address treasury;
        uint64 noteTtl;
        uint64 challengePeriod;
        uint64 maxPauseDuration;
        uint128 requestChargeCap;
        uint256 stateKeyX;
        uint256 stateKeyY;
        uint256 clearanceKeyX;
        uint256 clearanceKeyY;
    }

    struct Setup {
        string circuitId;
        string setupId;
        bytes32 requestVkHash;
        bytes32 withdrawalVkHash;
    }

    struct Deployed {
        address poseidon;
        bool poseidonReused;
        Groth16ProofAdapter adapter;
        ZkApiVault vault;
    }

    function run() external {
        require(block.chainid == vm.envOr("CHAIN_ID", block.chainid), "CHAIN_ID does not match RPC");
        bool local = block.chainid == 31337 || block.chainid == 1337;
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        string memory outputPath = vm.envString("OUTPUT_PATH");
        Params memory p = _params(vm.addr(deployerKey), local);
        Setup memory setup = _setup(local);

        address poseidonIn = vm.envOr("POSEIDON_ADDRESS", address(0));
        bytes memory poseidonRuntime = vm.getDeployedCode("Bn254Poseidon.sol:Bn254Poseidon");
        if (poseidonIn != address(0)) {
            require(
                poseidonIn.codehash == _libraryCodehash(poseidonRuntime, poseidonIn),
                "POSEIDON_ADDRESS runtime code is not the compiled Bn254Poseidon"
            );
        }

        vm.startBroadcast(deployerKey);
        Deployed memory d;
        d.poseidonReused = poseidonIn != address(0);
        d.poseidon = d.poseidonReused ? poseidonIn : _create(vm.getCode("Bn254Poseidon.sol:Bn254Poseidon"));
        d.adapter = new Groth16ProofAdapter();
        d.vault = ZkApiVault(
            _create(
                abi.encodePacked(
                    _linkedVaultCreationCode(d.poseidon),
                    abi.encode(
                        p.treasury,
                        p.noteTtl,
                        p.challengePeriod,
                        p.requestChargeCap,
                        address(d.adapter),
                        p.stateKeyX,
                        p.stateKeyY,
                        p.clearanceKeyX,
                        p.clearanceKeyY,
                        p.owner,
                        p.maxPauseDuration
                    )
                )
            )
        );
        vm.stopBroadcast();

        require(d.poseidon.codehash == _libraryCodehash(poseidonRuntime, d.poseidon), "linked library codehash");
        _checkAdapter(d.adapter, setup);
        _checkVault(d, p);
        _writeManifest(outputPath, d, p, setup);

        console2.log("vault        ", address(d.vault));
        console2.log("treasury     ", p.treasury);
        console2.log("owner        ", p.owner);
        if (block.chainid == 1 && p.owner.code.length == 0) {
            console2.log("WARNING: OWNER has no code; use a multisig or timelock contract on mainnet");
        }
        console2.log("proofAdapter ", address(d.adapter));
        console2.log("poseidon     ", d.poseidon, d.poseidonReused ? "(reused)" : "(deployed)");
        console2.log("setup        ", setup.circuitId, setup.setupId);
        console2.log("vault codehash");
        console2.logBytes32(address(d.vault).codehash);
        console2.log("adapter codehash");
        console2.logBytes32(address(d.adapter).codehash);
        console2.log("poseidon codehash");
        console2.logBytes32(d.poseidon.codehash);
        console2.log("manifest     ", outputPath);
    }

    function _params(address deployer, bool local) internal view returns (Params memory p) {
        p.deployer = deployer;
        // The owner can pause exits (for at most maxPauseDuration) and schedule treasury changes,
        // so public deployments must name it explicitly instead of defaulting to the deployer.
        p.owner = local ? vm.envOr("OWNER", deployer) : vm.envAddress("OWNER");
        require(p.owner != address(0), "OWNER must be nonzero");
        // Treasury receives the operator's consumed amount on settlement. Keep
        // it separate from the depositor so consumption is visible in the demo.
        p.treasury = local
            ? vm.envOr("TREASURY", address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8))
            : vm.envAddress("TREASURY");
        require(p.treasury != address(0), "TREASURY must be nonzero");
        p.stateKeyX = vm.envUint("STATE_SIGNING_KEY_X");
        p.stateKeyY = vm.envUint("STATE_SIGNING_KEY_Y");
        p.clearanceKeyX = vm.envUint("CLEARANCE_SIGNING_KEY_X");
        p.clearanceKeyY = vm.envUint("CLEARANCE_SIGNING_KEY_Y");
        p.challengePeriod =
            _positiveUint64(vm.envOr("CHALLENGE_PERIOD_SECONDS", uint256(24 hours)), "CHALLENGE_PERIOD_SECONDS");
        p.noteTtl = _positiveUint64(vm.envOr("NOTE_TTL_SECONDS", uint256(DEFAULT_NOTE_TTL)), "NOTE_TTL_SECONDS");
        uint256 maxPause = local
            ? vm.envOr("MAX_PAUSE_DURATION_SECONDS", uint256(LOCAL_MAX_PAUSE_DURATION))
            : vm.envUint("MAX_PAUSE_DURATION_SECONDS");
        p.maxPauseDuration = _positiveUint64(maxPause, "MAX_PAUSE_DURATION_SECONDS");
        require(
            uint256(p.maxPauseDuration) >= 2 * uint256(p.challengePeriod),
            "MAX_PAUSE_DURATION_SECONDS must be at least twice CHALLENGE_PERIOD_SECONDS"
        );
        uint256 cap = vm.envOr("REQUEST_CHARGE_CAP", uint256(1_000_000));
        require(cap > 0 && cap <= 9_007_199_254_740_991, "REQUEST_CHARGE_CAP must be positive safe gwei units");
        p.requestChargeCap = uint128(cap);
    }

    function _setup(bool local) internal view returns (Setup memory setup) {
        string memory path = local ? vm.envOr("SETUP_MANIFEST", DEFAULT_SETUP_MANIFEST) : vm.envString("SETUP_MANIFEST");
        string memory manifest = vm.readFile(path);
        setup.circuitId = vm.parseJsonString(manifest, ".circuit_id");
        setup.setupId = vm.parseJsonString(manifest, ".setup_id");
        setup.requestVkHash = vm.parseJsonBytes32(manifest, ".vk_keccak256.request");
        setup.withdrawalVkHash = vm.parseJsonBytes32(manifest, ".vk_keccak256.withdrawal");
        if (block.chainid == 1) {
            require(
                !_eq(setup.setupId, "dev") && !_eq(setup.setupId, "rehearsal"),
                "mainnet needs the ceremony setup (mpc-1)"
            );
        }
    }

    /// The adapter compiled into this script verifies the setup in SETUP_MANIFEST.
    function _checkAdapter(Groth16ProofAdapter adapter, Setup memory setup) internal view {
        require(adapter.CIRCUIT_ID_HASH() == keccak256(bytes(setup.circuitId)), "adapter CIRCUIT_ID_HASH != manifest");
        require(adapter.REQUEST_VK_HASH() == setup.requestVkHash, "adapter REQUEST_VK_HASH != manifest");
        require(adapter.WITHDRAWAL_VK_HASH() == setup.withdrawalVkHash, "adapter WITHDRAWAL_VK_HASH != manifest");
    }

    /// Post-deploy checks: the vault's getters equal the inputs and the expected constants.
    function _checkVault(Deployed memory d, Params memory p) internal view {
        ZkApiVault vault = d.vault;
        require(vault.PROTOCOL_VERSION() == 2, "PROTOCOL_VERSION");
        require(vault.CONCESSION_ESCAPE_VERSION() == 1, "CONCESSION_ESCAPE_VERSION");
        require(vault.ROOT_HISTORY_WINDOW() == 1 days, "ROOT_HISTORY_WINDOW");
        require(address(vault.proofAdapter()) == address(d.adapter), "proofAdapter");
        require(vault.owner() == p.owner && vault.treasury() == p.treasury, "owner or treasury");
        require(
            vault.noteTtl() == p.noteTtl && vault.challengePeriod() == p.challengePeriod
                && vault.maxPauseDuration() == p.maxPauseDuration && vault.requestChargeCap() == p.requestChargeCap,
            "periods or cap"
        );
        require(
            vault.stateSigningKeyX() == p.stateKeyX && vault.stateSigningKeyY() == p.stateKeyY
                && vault.clearanceSigningKeyX() == p.clearanceKeyX && vault.clearanceSigningKeyY() == p.clearanceKeyY,
            "signing keys"
        );
        require(vault.isKnownRoot(vault.currentRoot()), "empty root not recorded");
    }

    function _writeManifest(string memory outputPath, Deployed memory d, Params memory p, Setup memory setup) internal {
        ZkApiVault vault = d.vault;
        string memory m = "deployment";
        vm.serializeUint(m, "chainId", block.chainid);
        vm.serializeUint(m, "deployBlock", block.number);
        vm.serializeUint(m, "protocolVersion", vault.PROTOCOL_VERSION());
        vm.serializeUint(m, "vaultRevision", VAULT_REVISION);
        vm.serializeUint(m, "concessionEscapeVersion", vault.CONCESSION_ESCAPE_VERSION());
        vm.serializeString(m, "circuitId", setup.circuitId);
        vm.serializeString(m, "setupId", setup.setupId);
        vm.serializeBytes32(m, "circuitIdHash", d.adapter.CIRCUIT_ID_HASH());
        vm.serializeBytes32(m, "requestVkKeccak256", d.adapter.REQUEST_VK_HASH());
        vm.serializeBytes32(m, "withdrawalVkKeccak256", d.adapter.WITHDRAWAL_VK_HASH());
        vm.serializeAddress(m, "owner", p.owner);
        vm.serializeAddress(m, "vault", address(vault));
        vm.serializeAddress(m, "billingToken", vault.billingToken());
        vm.serializeAddress(m, "proofAdapter", address(d.adapter));
        vm.serializeAddress(m, "poseidonLibrary", d.poseidon);
        vm.serializeBool(m, "poseidonLibraryReused", d.poseidonReused);
        vm.serializeBytes32(m, "vaultRuntimeCodehash", address(vault).codehash);
        vm.serializeBytes32(m, "adapterRuntimeCodehash", address(d.adapter).codehash);
        vm.serializeBytes32(m, "poseidonRuntimeCodehash", d.poseidon.codehash);
        vm.serializeAddress(m, "treasury", p.treasury);
        vm.serializeUint(m, "requestChargeCap", p.requestChargeCap);
        vm.serializeString(m, "billing_asset", "native_eth");
        vm.serializeString(m, "billing_unit", "gwei");
        vm.serializeUint(m, "nativeAssetWeiPerUnit", vault.nativeAssetWeiPerUnit());
        vm.serializeUint(m, "challengePeriod", p.challengePeriod);
        vm.serializeUint(m, "maxPauseDuration", p.maxPauseDuration);
        vm.serializeUint(m, "pauseCooldown", vault.PAUSE_COOLDOWN());
        vm.serializeUint(m, "treasuryChangeDelay", vault.treasuryChangeDelay());
        vm.serializeUint(m, "unpauseClaimGrace", vault.unpauseClaimGrace());
        vm.serializeUint(m, "rootHistoryWindow", vault.ROOT_HISTORY_WINDOW());
        vm.serializeUint(m, "stateSigningKeyX", p.stateKeyX);
        vm.serializeUint(m, "stateSigningKeyY", p.stateKeyY);
        vm.serializeUint(m, "clearanceSigningKeyX", p.clearanceKeyX);
        vm.serializeUint(m, "clearanceSigningKeyY", p.clearanceKeyY);
        string memory serialized = vm.serializeUint(m, "noteTtl", uint256(p.noteTtl));
        vm.writeJson(serialized, outputPath);
    }

    /// ZkApiVault's creation code with every Bn254Poseidon placeholder replaced by `poseidon`.
    function _linkedVaultCreationCode(address poseidon) internal view returns (bytes memory) {
        string memory artifact = vm.readFile(string.concat(vm.projectRoot(), "/out/ZkApiVault.sol/ZkApiVault.json"));
        string memory code = vm.parseJsonString(artifact, ".bytecode.object");
        uint256 at = vm.indexOf(code, "__$");
        require(at != type(uint256).max, "ZkApiVault creation code has no library placeholder");
        bytes memory raw = bytes(code);
        bytes memory placeholder = new bytes(40);
        for (uint256 i = 0; i < 40; ++i) {
            placeholder[i] = raw[at + i];
        }
        require(placeholder[37] == "$" && placeholder[38] == "_" && placeholder[39] == "_", "placeholder shape");
        string memory linked = vm.replace(code, string(placeholder), _hex40(poseidon));
        require(vm.indexOf(linked, "__$") == type(uint256).max, "ZkApiVault links a library other than Bn254Poseidon");
        return vm.parseBytes(linked);
    }

    /// The runtime codehash of the compiled library deployed at `at`. A library with call
    /// protection starts with PUSH20 <its own address>, written at deployment; Bn254Poseidon's
    /// via-IR code has none (all its functions are pure), so its code does not depend on `at`.
    function _libraryCodehash(bytes memory runtime, address at) internal pure returns (bytes32) {
        if (runtime.length > 21 && uint8(runtime[0]) == 0x73 && bytes20(_slice20(runtime, 1)) == bytes20(0)) {
            bytes20 word = bytes20(at);
            for (uint256 i = 0; i < 20; ++i) {
                runtime[1 + i] = word[i];
            }
        }
        return keccak256(runtime);
    }

    function _slice20(bytes memory data, uint256 start) internal pure returns (bytes20 out) {
        assembly ("memory-safe") {
            out := mload(add(add(data, 0x20), start))
        }
    }

    function _create(bytes memory initcode) internal returns (address deployed) {
        assembly ("memory-safe") {
            deployed := create(0, add(initcode, 0x20), mload(initcode))
        }
        require(deployed != address(0), "contract creation failed");
    }

    function _hex40(address value) internal pure returns (string memory) {
        bytes memory digits = "0123456789abcdef";
        bytes memory out = new bytes(40);
        uint160 v = uint160(value);
        for (uint256 i = 40; i > 0; --i) {
            out[i - 1] = digits[v & 0xf];
            v >>= 4;
        }
        return string(out);
    }

    function _positiveUint64(uint256 value, string memory name) internal pure returns (uint64) {
        require(value > 0 && value <= type(uint64).max, string.concat(name, " must fit a positive uint64"));
        return uint64(value);
    }

    function _eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
