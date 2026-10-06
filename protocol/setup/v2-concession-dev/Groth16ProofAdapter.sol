// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";
import {Types} from "../libraries/Types.sol";
import {Errors} from "../libraries/Errors.sol";

/// @title Groth16ProofAdapter
/// @notice zkAPI verifier for circuit zkapi-v2-concession-v1, setup dev, generated from its
///         verifying keys. Verification is standard Groth16 over the 12 request and 16 withdrawal
///         public inputs, in the order of Types.RequestPublicInputs and Types.WithdrawalPublicInputs.
contract Groth16ProofAdapter is IZkApiProofAdapter {
    /// @notice keccak256("zkapi-v2-concession-v1"): the statement this adapter verifies.
    bytes32 public constant CIRCUIT_ID_HASH = 0xf464f910d858a070b2f88db1049aab19d8fabeed1e527920be90dc0c950b0687;
    /// @notice keccak256 of the request verifying key (arkworks compressed bytes of request.vk
    ///         without its header). Identifies the setup.
    bytes32 public constant REQUEST_VK_HASH = 0x4d6c1a19dafd1d93488bf60059ab458f4aa1849a405eb0b6e13fd7f3d575b872;
    /// @notice keccak256 of the withdrawal verifying key (withdrawal.vk without its header).
    bytes32 public constant WITHDRAWAL_VK_HASH = 0x293e7d3c553b79f9389f4448a8c50e79aef637161ded055d541988a0135ec5dd;

    uint256 private constant SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 private constant BASE_MODULUS =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point { uint256 x; uint256 y; }
    // Coordinates use arkworks order: c0 (real), then c1 (imaginary).
    struct G2Point { uint256[2] x; uint256[2] y; }
    struct Proof { G1Point a; G2Point b; G1Point c; }

    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof)
        external view override
    {
        uint256[12] memory values = [
            uint256(inputs.protocolVersion),
            uint256(inputs.chainId),
            uint256(uint160(inputs.contractAddress)),
            inputs.activeRoot,
            inputs.stateSigningKeyX,
            inputs.stateSigningKeyY,
            uint256(inputs.requestTime),
            uint256(inputs.solvencyBound),
            inputs.requestNullifier,
            inputs.authorizationTag,
            inputs.anonymousCommitmentX,
            inputs.anonymousCommitmentY
        ];
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyRequest(values, parsed)) revert Errors.InvalidProof();
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external view override
    {
        uint256[16] memory values = [
            uint256(inputs.protocolVersion),
            uint256(inputs.chainId),
            uint256(uint160(inputs.contractAddress)),
            inputs.activeRoot,
            inputs.stateSigningKeyX,
            inputs.stateSigningKeyY,
            inputs.clearanceSigningKeyX,
            inputs.clearanceSigningKeyY,
            uint256(inputs.noteId),
            uint256(inputs.finalBalance),
            uint256(uint160(inputs.destination)),
            inputs.withdrawalNullifier,
            uint256(inputs.kind),
            inputs.nextNullifier,
            uint256(inputs.conceded),
            uint256(inputs.validUntil)
        ];
        (Proof memory parsed, bool validEncoding) = _decodeProof(proof);
        if (!validEncoding || !_verifyWithdrawal(values, parsed)) revert Errors.InvalidProof();
    }

    function _verifyRequest(uint256[12] memory values, Proof memory proof) private view returns (bool) {
        G1Point memory accumulator = _requestIc(0);
        for (uint256 i = 0; i < 12; ++i) {
            if (values[i] >= SCALAR_MODULUS) return false;
            (G1Point memory term, bool mulOk) = _scalarMul(_requestIc(i + 1), values[i]);
            if (!mulOk) return false;
            bool addOk;
            (accumulator, addOk) = _add(accumulator, term);
            if (!addOk) return false;
        }
        return _pairing(
            _negate(proof.a), proof.b,
            _requestAlpha(), _requestBeta(),
            accumulator, _requestGamma(),
            proof.c, _requestDelta()
        );
    }

    function _verifyWithdrawal(uint256[16] memory values, Proof memory proof) private view returns (bool) {
        G1Point memory accumulator = _withdrawalIc(0);
        for (uint256 i = 0; i < 16; ++i) {
            if (values[i] >= SCALAR_MODULUS) return false;
            (G1Point memory term, bool mulOk) = _scalarMul(_withdrawalIc(i + 1), values[i]);
            if (!mulOk) return false;
            bool addOk;
            (accumulator, addOk) = _add(accumulator, term);
            if (!addOk) return false;
        }
        return _pairing(
            _negate(proof.a), proof.b,
            _withdrawalAlpha(), _withdrawalBeta(),
            accumulator, _withdrawalGamma(),
            proof.c, _withdrawalDelta()
        );
    }

    function _decodeProof(bytes calldata encoded) private pure returns (Proof memory proof, bool valid) {
        if (encoded.length != 256) return (proof, false);
        uint256[8] memory words;
        assembly ("memory-safe") {
            let start := encoded.offset
            mstore(words, calldataload(start))
            mstore(add(words, 0x20), calldataload(add(start, 0x20)))
            mstore(add(words, 0x40), calldataload(add(start, 0x40)))
            mstore(add(words, 0x60), calldataload(add(start, 0x60)))
            mstore(add(words, 0x80), calldataload(add(start, 0x80)))
            mstore(add(words, 0xa0), calldataload(add(start, 0xa0)))
            mstore(add(words, 0xc0), calldataload(add(start, 0xc0)))
            mstore(add(words, 0xe0), calldataload(add(start, 0xe0)))
        }
        for (uint256 i = 0; i < 8; ++i) if (words[i] >= BASE_MODULUS) return (proof, false);
        proof.a = G1Point(words[0], words[1]);
        proof.b = G2Point([words[2], words[3]], [words[4], words[5]]);
        proof.c = G1Point(words[6], words[7]);
        return (proof, true);
    }

    function _negate(G1Point memory point) private pure returns (G1Point memory) {
        if (point.x == 0 && point.y == 0) return G1Point(0, 0);
        return G1Point(point.x, BASE_MODULUS - (point.y % BASE_MODULUS));
    }

    function _add(G1Point memory a, G1Point memory b) private view returns (G1Point memory result, bool ok) {
        uint256[4] memory input = [a.x, a.y, b.x, b.y];
        assembly ("memory-safe") { ok := staticcall(gas(), 6, input, 0x80, result, 0x40) }
    }

    function _scalarMul(G1Point memory point, uint256 scalar)
        private view returns (G1Point memory result, bool ok)
    {
        uint256[3] memory input = [point.x, point.y, scalar];
        assembly ("memory-safe") { ok := staticcall(gas(), 7, input, 0x60, result, 0x40) }
    }

    function _pairing(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) private view returns (bool) {
        uint256[24] memory input;
        _writePair(input, 0, a1, a2);
        _writePair(input, 6, b1, b2);
        _writePair(input, 12, c1, c2);
        _writePair(input, 18, d1, d2);
        uint256[1] memory output;
        bool ok;
        assembly ("memory-safe") { ok := staticcall(gas(), 8, input, 0x300, output, 0x20) }
        return ok && output[0] == 1;
    }

    function _writePair(uint256[24] memory input, uint256 offset, G1Point memory g1, G2Point memory g2)
        private pure
    {
        input[offset] = g1.x;
        input[offset + 1] = g1.y;
        // EIP-197 expects the imaginary coefficient before the real coefficient.
        input[offset + 2] = g2.x[1];
        input[offset + 3] = g2.x[0];
        input[offset + 4] = g2.y[1];
        input[offset + 5] = g2.y[0];
    }

    function _requestAlpha() private pure returns (G1Point memory) {
        return G1Point(0x164336966ddb0f04dd52e38f28da5c4cf918f11c07d2eb9c03216fd7b1fe475a, 0x2ab1496b0cff88f17ad433895d5a06f05610497dab7cc9ae66b431c80152c720);
    }

    function _requestBeta() private pure returns (G2Point memory) {
        return G2Point([0x158d559c5767b348e841ba11a61952d169323d7da40e1f6125d63fdd5f50c37a, 0x17df76cc5e1cfb4ce19a10a6a7e9730c662a38549b167ab00a03cb93daa897ae], [0x021f499b0295378f6f80b11212612d9088a9f426603d0aec3af604aac91d921b, 0x0840ea18d81cb04479da978bc9af2323e534f30ec8ba60838d87f3a88859d199]);
    }

    function _requestGamma() private pure returns (G2Point memory) {
        return G2Point([0x2d6e2ba0830938dea6f4632a0b032978669cf301563bfd327cf7aaf1b511682e, 0x1d38946ea1ba8124e939275c5e32c301d9dd0c09ede76ff2d9e8ee5085ee8f74], [0x2c5df89305234cac5a3777f8b4c5fc675d22c72fb06686ee23238f3621daacea, 0x07fb010cf3508ced97eca037848cf4765d42e566550c53fa346385ea1dd90668]);
    }

    function _requestDelta() private pure returns (G2Point memory) {
        return G2Point([0x1fca454c8b876ac6e42c83c8c9b80131088622915a0b8217e6257e6c66e83c4c, 0x131e7d0334ab1d3a254dfaa2100000bdc335b15799d39f6d6ffd3e923e60ffa7], [0x139f8e1429a50da793444f7bb3a26fa7ff8d06cb5be83eeb6567131bbcc24aa5, 0x03f7c47f27a7caa460247e05ba32602361b0ee0e6c05adb5a1e01f79b8ac52f0]);
    }

    function _requestIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) return G1Point(0x0e6ae1f861cb945a48dd235032b5fb8892dd17a8d4b11322605aca761e427d39, 0x02e4230e181432ac916e1fa07e3654cb732fbdc4596157715222fd3a7685d482);
        if (index == 1) return G1Point(0x10701af929dcd2154a09de58dc37e76facb70ffa80cdaad5d5fb635caac23c9e, 0x1773186cc642f3ea77d07a765b2970eea2127ad65478918dba3e726bd0694ae5);
        if (index == 2) return G1Point(0x2909809bd1f4039a17fda7cd2fc1b658d01744930560731fb5a4f4f62be294a2, 0x1afd06ab844265f5bcbd46796a60370704099cf336d0588a4066852ef5aa5542);
        if (index == 3) return G1Point(0x22ddfe021f194ee84132535e74662100f650cde6f7ab1f2e1431960898ab2d4a, 0x18fcb970fd0994d9c6c847ebe4cb34dc43276cf4499bd66897a6a6dad4b61509);
        if (index == 4) return G1Point(0x2e2819614d5b41248cae521aa6edfbecb15bffa00019241f24e279e17112444e, 0x01e74b92aacfb1468a6999ac45c2e9ee6f40f5818163021998221197b3ac2ef8);
        if (index == 5) return G1Point(0x222617d4f2cb6ec74d0268056a1aba1ddc0d704c0b773c134f8d6c77678d2227, 0x07e9a78ddd8b879a000fcfc53e3a77a02f628e8721b9d4f494b3f983bc883e29);
        if (index == 6) return G1Point(0x2e18f87f22e15f85efcc281ecdcfa22d209c274db37837fdc2e16332caf837ac, 0x0ce2a92f4393868ad052ba0cf92b962eecd3cd3e71e6c56e8e7ec856a1371228);
        if (index == 7) return G1Point(0x2aafbbf0d12d34ef17de94b5a0e1d5b91fe1b7336990449984bb0f9f9975dfe2, 0x0cdd93e2940c6976da14f1abb6f80621135554fe80854a182b31ffebf4407fb9);
        if (index == 8) return G1Point(0x02b6c8a6c6fe5282d759bbba2b10b45774807917f4d3cd8d0c4e01397dd7dbb7, 0x01fe0d346859f5bad986c6daa0f246255d9bb061372400ea1aed362f3159c2b7);
        if (index == 9) return G1Point(0x2655de6b0ba0bc30e57e59ee26f92f6ef7f4c0ace99d3b2ac0e4d11143bf69b5, 0x12002f0e815d8a650a0a8f7c86d799b340866ce055b8ffb8099ec7be25cd81a0);
        if (index == 10) return G1Point(0x0381f73631c53ce88a02617678cfa13b11094906579531d77c84fe6368e5334f, 0x13a5388778f43ab171242cfc3147893e28c9eaec7a0e7ebcc150a3f2b60c1362);
        if (index == 11) return G1Point(0x2864cf225185b2a7f771eb20ccd7f653e732d6065f9451824d19612fb709a6a6, 0x0825922ed0aab00580b47e7f10193a567afdc6aa56ad8c03451d5c9bfff75686);
        if (index == 12) return G1Point(0x210c26b6fc400a7a163046ec16c1b8952b9711b31617e2d42e99d62107f72126, 0x102a35407acbfbdf15f3957ff46335ae9edd3e3dafe17adf5ece9d43498c8cc0);
        revert Errors.InvalidProof();
    }

    function _withdrawalAlpha() private pure returns (G1Point memory) {
        return G1Point(0x013a48bb95d5414d234ed76e6006ec13022cc8f1c436b4a8fd619d60aa835ece, 0x1532be7bfafa543a613dca5ec5b004386095321040674d8b3fa3a557fa9915f3);
    }

    function _withdrawalBeta() private pure returns (G2Point memory) {
        return G2Point([0x001f5bae30e5fd3611d58ebcfdb6d6366796cf78d711f19ee29095e5e75859c7, 0x052bfc119f3e417cf11d1fb5d17027c70e3cdc6e13161349eec54b2d2bc2cfbf], [0x0c0975bb59a81588b5acbe2c168b1be24cdd685c649cfd6d9e56245f96fdcbf4, 0x2ff043c1bdc241098373b727e7feec93b865c9d6e5b52691d42181674e2a34f7]);
    }

    function _withdrawalGamma() private pure returns (G2Point memory) {
        return G2Point([0x11bf49913e734a195448153cd758a4604184caf05bdeaff6d9d1f8912b747b91, 0x0f1088d099957fefff79d46bf7bda2560ca14406a3fe7110486bea4a8e63232c], [0x1211fb78d339964458d918be985f3ec261e0db212a886a012df1875cbc304920, 0x1ef3561ba4d57af9f1b95b8ac4b082627ae1911ccc5e7b9826e5c272ff90c054]);
    }

    function _withdrawalDelta() private pure returns (G2Point memory) {
        return G2Point([0x0a842abc4e31ef80a1414b732da5f64bd0de27dcf049cfb11cd466f67a1f5d47, 0x199039cef69f88f7b6ec5a411d79b89a158ed045fe7f7a5f61ad38bc799355de], [0x2a5144e65619cc46d19678a9e5e088c1c23a0b0d8717bf31d327b327c4e893e2, 0x050c5b257956e59a5d3ccbb597702eeb0668f6cf88524fbcd4a79c08b475bfff]);
    }

    function _withdrawalIc(uint256 index) private pure returns (G1Point memory) {
        if (index == 0) return G1Point(0x0d9d7206ae6ea1cedcfee3e391c4caf23cb061532d3a7662e255d5af8e2c9131, 0x000d92f644de5e9fcdc56ea4d9a8c338311cddfb74a3409bd87a94a350b00107);
        if (index == 1) return G1Point(0x160f345783d7a585e47be7bc33eb4b626e8b1e0f4fca6524c26be0a727bcb319, 0x1a95ba348a8d2e03a2e32db8aabbdba85249ac65df33b08641802dfad12505d0);
        if (index == 2) return G1Point(0x10eb297c355f1286f1ea9d46039b8a7f3344e5235369d62661091fef28db85c4, 0x080ddae1f9af8e838aa690ecc73885b0b0d4c8382c0fd82a98aca9c6ebcd8acd);
        if (index == 3) return G1Point(0x2c67c19a3dd8152bab6cdec889d6bb07fa14dc1feec679e372d328dd2e1f9c4d, 0x0b1eb639226f8e6e5eb54c2e3fda7ac4c57677da6b38defa872437db04f6763d);
        if (index == 4) return G1Point(0x0958a44e58974c7d36f769ef9a0d848b55057627fbf35a30923fd25ae9740352, 0x201156a98dd86f450f14cacd033f3dbd0cacb2ca6ef5cf7c0ff1241207ed0a06);
        if (index == 5) return G1Point(0x2d5d66eb69fafc0a884e49c603d4b7f3f0ec9e43bff46ca51e4e1b4c094b9372, 0x287acc3896f951b0a7e14ca66bdd3ac0ec5d8479b9c0a6cf1933c248c25d5ac9);
        if (index == 6) return G1Point(0x12c6ee3ae514e74e0fd64e20bb05cc51b05b3d32c4714d1a2bad296d5814c2d7, 0x292510b0849b89a50568a6cc53d1b77fa1d07f274c1de0cd250546f532a49364);
        if (index == 7) return G1Point(0x29c2c221fa5e87b26f9c8de3b661b95cecd7cc12a760d28d415f9c58eeb90ff2, 0x02d497cbebaf7d992d6807935e55d4e099ffef2ba274460d2deed6171392be22);
        if (index == 8) return G1Point(0x185dee5db72baf628dc687624274bbccc5d9a8a53c4d848c495a15961eab1a82, 0x0b2f92827f974b63b4e3c15dcaf72fbdd6ac82c9ab154657f362be0904db4203);
        if (index == 9) return G1Point(0x1deb52610cb739d7661eab585dcb109f81c60d25893e92d73e64ab2e7a5e1ac1, 0x1727c486d77fc6b1369b14c0a2e6cd83e4344be563d989e4ba3955e918eac444);
        if (index == 10) return G1Point(0x18c500edb74cc2c32eee95b44f692856a40a270e22f263362e2211a01d8a536d, 0x053449c5e970777c16f45264862aac2fabee7c8080363b3908cdd6c017d433f8);
        if (index == 11) return G1Point(0x22e79ce8e98c8b55adbb933f859c24a83b5c4ad2cfba1a1700bf3935061fd272, 0x2b043d1857d79754e0daaf316e7d8797bca6cb19c69afe0d7151a27f0835615e);
        if (index == 12) return G1Point(0x03848d81ab6eefbf795fded59d781cce5bc8e7de19c176f8c19cd0446b225b92, 0x01ede69895feeb6fe1cd85b8a03726450f8fdb552d1c1340bed8442d5fba09a8);
        if (index == 13) return G1Point(0x1d0a151399bf133f60e7c440083980e4f2a666175f08a6e477b6dc3d901d9822, 0x1588e8540fc0875fe3ed10c0e548555d694df72168f36e2a18dde62612a46b7f);
        if (index == 14) return G1Point(0x182287a9180dcfe66563d68c08c55b666f8e55c0c80e2336930ce8d978f69644, 0x2744410007eea7a4f03065a014626a9ba096756b6e25e97e5d61e401ed0b2a66);
        if (index == 15) return G1Point(0x1fa29fb153047b008cc4a502d63f695c32d1310e8d052f4408a6f464e97e4692, 0x114599a7c3250e67e3818528cefb7d01852d0d4163ff78388522e68ab3ebbcb2);
        if (index == 16) return G1Point(0x1b7b6055350781d48c48960ed4b422b37a44c4f3bb2eaaf8772d2ed426fb7089, 0x297d2b2efa23fb5be46026950ca15f0a30c5d5e9fd432cc78ebe2a1e941f6bb3);
        revert Errors.InvalidProof();
    }
}
