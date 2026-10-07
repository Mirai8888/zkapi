// scripts/expected-codehashes.mjs reads deployment manifests exactly: forge's serializeUint writes
// values up to 2^64 - 1 as bare JSON numbers, which JSON.parse would round above 2^53 - 1. It also
// finalizes Deploy.s.sol's provisional manifest against the chain (here a fake JSON-RPC).
// Run with: node --test demo/contracts/test/*.test.mjs (after forge build in protocol/contracts
// for the codehash case).
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
    deploymentInputs,
    expectedCodehashes,
    expectedRuntimeCode,
    finalizeDeployment,
    keccak256,
    parseDeployment,
    vaultImmutables,
} from '../../../scripts/expected-codehashes.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const ARTIFACTS = join(ROOT, 'protocol/contracts/out');

// A Baby-JubJub subgroup point whose y lies between 2^63 and 2^64 and is odd, so no double holds it.
const WIDE_Y_X = '0x05503c73ffee28fcacc324d533595173a637420b99492265bf57c2c286f59cd7';
const WIDE_Y_Y = '9223372036854775867';

function manifest(keyY) {
    return `{
  "poseidonLibrary": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
  "proofAdapter": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
  "noteTtl": 2592000,
  "challengePeriod": 86400,
  "maxPauseDuration": 604800,
  "requestChargeCap": 1000000,
  "stateSigningKeyX": "${BigInt(WIDE_Y_X)}",
  "stateSigningKeyY": ${keyY},
  "clearanceSigningKeyX": "13",
  "clearanceSigningKeyY": "14"
}`;
}

test('parseDeployment reads integers above 2^53 - 1 exactly', () => {
    const parsed = parseDeployment('{"a": 18446744073709551615, "b": 9007199254740993, "c": 7, "d": "123", "e": [9223372036854775867]}');
    assert.equal(parsed.a, 18446744073709551615n);
    assert.equal(parsed.b, 9007199254740993n);
    assert.equal(parsed.c, 7);
    assert.equal(parsed.d, '123');
    assert.equal(parsed.e[0], 9223372036854775867n);
    assert.equal(parseDeployment(manifest(WIDE_Y_Y)).stateSigningKeyY, BigInt(WIDE_Y_Y));
});

test('parseDeployment refuses numbers that are not exact integers', () => {
    for (const text of ['{"a": 1.5}', '{"a": 1e300}', '{"a": 9007199254740993.0}', '{"a": -9007199254740993}']) {
        assert.throws(() => parseDeployment(text), /is not an exact integer/, text);
    }
});

test('immutables refuse a JavaScript number that was already rounded', () => {
    const inputs = parseDeployment(manifest(`"${WIDE_Y_Y}"`));
    const words = vaultImmutables(inputs);
    assert.equal(words.stateSigningKeyY, BigInt(WIDE_Y_Y).toString(16).padStart(64, '0'));
    assert.deepEqual(vaultImmutables({ ...inputs, stateSigningKeyY: BigInt(WIDE_Y_Y) }), words);
    assert.deepEqual(vaultImmutables({ ...inputs, stateSigningKeyY: `0x${BigInt(WIDE_Y_Y).toString(16)}` }), words);
    // eslint-disable-next-line no-loss-of-precision
    assert.throws(() => vaultImmutables({ ...inputs, stateSigningKeyY: 9223372036854775867 }), /not a safe integer/);
    assert.throws(() => vaultImmutables({ ...inputs, noteTtl: 2 ** 60 }), /not a safe integer/);
});

test('a bare wide key and its decimal string give the same codehashes', { skip: !existsSync(ARTIFACTS) && 'run forge build in protocol/contracts first' }, () => {
    const bare = expectedCodehashes(ARTIFACTS, parseDeployment(manifest(WIDE_Y_Y)));
    const quoted = expectedCodehashes(ARTIFACTS, parseDeployment(manifest(`"${WIDE_Y_Y}"`)));
    assert.deepEqual(bare, quoted);
    // What a rounding parser would have computed differs.
    const rounded = expectedCodehashes(ARTIFACTS, { ...parseDeployment(manifest(`"${WIDE_Y_Y}"`)), stateSigningKeyY: String(Number(WIDE_Y_Y)) });
    assert.notEqual(rounded.vault_runtime_codehash, bare.vault_runtime_codehash);
});

// ------------------------------------------------------------------ finalizing a broadcast

const NO_ARTIFACTS = !existsSync(ARTIFACTS) && 'run forge build in protocol/contracts first';
const POSEIDON = '0x5fbdb2315678afecb367f032d93f642f64180aa3';
const ADAPTER = '0xe7f1725e7734ce288f8367e1bb143e90bb3f0512';
const VAULT = '0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0';
const OWNER = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
const TREASURY = '0x70997970c51812dc3a010c7d01b50e0d17dc79c8';
const TX = { poseidon: `0x${'a1'.repeat(32)}`, adapter: `0x${'a2'.repeat(32)}`, vault: `0x${'a3'.repeat(32)}` };
const selector = signature => keccak256(new TextEncoder().encode(signature)).slice(0, 10);
const word = addr => `0x${addr.slice(2).padStart(64, '0')}`;

/// Deploy.s.sol's provisional manifest of a broadcast run whose simulation saw head block 5.
function pendingManifest() {
    const inputs = parseDeployment(manifest(`"${WIDE_Y_Y}"`));
    inputs.poseidonLibrary = POSEIDON;
    inputs.proofAdapter = ADAPTER;
    const hashes = expectedCodehashes(ARTIFACTS, inputs);
    return {
        deploymentStatus: 'pending',
        chainId: 31337,
        deployBlockLowerBound: 5,
        vault: VAULT,
        owner: OWNER,
        treasury: TREASURY,
        poseidonLibraryReused: false,
        ...inputs,
        vaultRuntimeCodehash: hashes.vault_runtime_codehash,
        adapterRuntimeCodehash: hashes.adapter_runtime_codehash,
        poseidonRuntimeCodehash: hashes.poseidon_runtime_codehash,
    };
}

/// A chain on which the broadcast of `deployment` landed: the library and adapter in block 6 and
/// the vault in block 7, with head `latest`. forge's log pairs the first two hashes with each
/// other's addresses in `transactions`, as it does for creations mined in one block; its receipts
/// are right.
function chain(deployment, latest = 7) {
    const code = expectedRuntimeCode(ARTIFACTS, deploymentInputs(deployment));
    const state = {
        code: { [POSEIDON]: code.poseidon, [ADAPTER]: code.adapter, [VAULT]: code.vault },
        receipts: {
            [TX.poseidon]: { transactionHash: TX.poseidon, status: '0x1', blockNumber: '0x6', contractAddress: POSEIDON },
            [TX.adapter]: { transactionHash: TX.adapter, status: '0x1', blockNumber: '0x6', contractAddress: ADAPTER },
            [TX.vault]: { transactionHash: TX.vault, status: '0x1', blockNumber: '0x7', contractAddress: VAULT },
        },
        storage: { [selector('owner()')]: word(OWNER), [selector('treasury()')]: word(TREASURY) },
        chainId: '0x7a69',
        latest,
    };
    const log = {
        chain: 31337,
        transactions: [
            { hash: TX.poseidon, transactionType: 'CREATE', contractAddress: ADAPTER },
            { hash: TX.adapter, transactionType: 'CREATE', contractAddress: POSEIDON },
            { hash: TX.vault, transactionType: 'CREATE', contractAddress: VAULT },
        ],
        receipts: Object.values(state.receipts).map(receipt => ({ ...receipt })),
    };
    const rpc = async (method, params) => {
        if (method === 'eth_chainId') return state.chainId;
        if (method === 'eth_blockNumber') return `0x${state.latest.toString(16)}`;
        if (method === 'eth_getCode') return state.code[params[0].toLowerCase()] ?? '0x';
        if (method === 'eth_getTransactionReceipt') return state.receipts[params[0]] ?? null;
        if (method === 'eth_call' && params[0].to === VAULT) return state.storage[params[0].data];
        throw new Error(`unexpected ${method}`);
    };
    return { state, log, rpc };
}

const finalize = (deployment, { log, rpc }, confirmations = 1) =>
    finalizeDeployment({ artifacts: ARTIFACTS, deployment, broadcastLog: log, rpc, confirmations });

test('finalize records the block that created the vault, not the simulated head', { skip: NO_ARTIFACTS }, async () => {
    const deployment = pendingManifest();
    const { manifest: final, mismatches } = await finalize(deployment, chain(deployment));
    assert.deepEqual(mismatches, []);
    assert.equal(final.deploymentStatus, 'deployed');
    assert.equal(final.deployBlock, 7);
    assert.equal(final.deployBlockLowerBound, 5);
    // Matched through the receipts, not the log's transactions entries.
    assert.deepEqual(final.deployTransactions, { vault: TX.vault, proofAdapter: TX.adapter, poseidonLibrary: TX.poseidon });
    assert.equal(final.vaultRuntimeCodehash, deployment.vaultRuntimeCodehash);
    // A reused library has no creation to look for.
    const reused = { ...pendingManifest(), poseidonLibraryReused: true };
    const fake = chain(reused);
    delete fake.state.receipts[TX.poseidon];
    fake.log.receipts = fake.log.receipts.filter(receipt => receipt.transactionHash !== TX.poseidon);
    const { manifest: linked } = await finalize(reused, fake);
    assert.deepEqual(linked.deployTransactions, { vault: TX.vault, proofAdapter: TX.adapter });
});

test('finalize takes only the provisional manifest of a broadcast run', { skip: NO_ARTIFACTS }, async () => {
    for (const status of ['simulated', 'deployed', undefined]) {
        const deployment = { ...pendingManifest(), deploymentStatus: status };
        await assert.rejects(finalize(deployment, chain(deployment)), /finalize takes the provisional manifest/, String(status));
    }
});

test('finalize refuses creations that are missing, failed, elsewhere or not on chain', { skip: NO_ARTIFACTS }, async () => {
    const deployment = pendingManifest();
    const cases = [
        [fake => { fake.log.receipts = fake.log.receipts.filter(receipt => receipt.contractAddress !== VAULT); }, /0 receipts creating the vault/],
        [fake => { fake.log.receipts.push({ ...fake.log.receipts[2] }); }, /2 receipts creating the vault/],
        [fake => { delete fake.state.receipts[TX.vault]; }, /vault creation .* is not on chain/],
        [fake => { fake.state.receipts[TX.adapter].status = '0x0'; }, /proofAdapter creation .* failed on chain/],
        [fake => { fake.state.receipts[TX.poseidon].contractAddress = VAULT; }, /poseidonLibrary creation .* created/],
        [fake => { fake.state.receipts[TX.vault].blockNumber = '0x5'; }, /not after the simulated head 5/],
        [fake => { fake.state.chainId = '0xaa36a7'; }, /RPC serves chain 11155111/],
        [fake => { fake.log.chain = 1; }, /broadcast log is for chain 1/],
    ];
    for (const [corrupt, error] of cases) {
        const fake = chain(deployment);
        corrupt(fake);
        await assert.rejects(finalize(deployment, fake), error);
    }
});

test('finalize waits for confirmations', { skip: NO_ARTIFACTS }, async () => {
    const deployment = pendingManifest();
    await assert.rejects(finalize(deployment, chain(deployment, 7), 2), /1 confirmations, 2 required/);
    const { manifest: final } = await finalize(deployment, chain(deployment, 8), 2);
    assert.equal(final.deployBlock, 7);
});

test('finalize reports code and storage on chain that are not the manifest\'s, and writes nothing', { skip: NO_ARTIFACTS }, async () => {
    const deployment = pendingManifest();
    // The vault on chain was deployed with other keys than the manifest records.
    const other = chain({ ...deployment, stateSigningKeyY: String(BigInt(WIDE_Y_Y) + 2n) });
    const { manifest: none, mismatches } = await finalize(deployment, other);
    assert.equal(none, undefined);
    assert.deepEqual(mismatches.map(m => `${m.source}:${m.field}`), ['rpc:vault_runtime_codehash']);
    // The manifest's own codehashes are not the expected ones.
    const recorded = { ...deployment, adapterRuntimeCodehash: `0x${'00'.repeat(32)}` };
    const result = await finalize(recorded, chain(recorded));
    assert.deepEqual(result.mismatches.map(m => `${m.source}:${m.field}`), ['deployment:adapter_runtime_codehash']);
    // Owner and treasury are storage, which the codehash does not cover.
    const fake = chain(deployment);
    fake.state.storage[selector('owner()')] = word(TREASURY);
    fake.state.storage[selector('treasury()')] = word(OWNER);
    const swapped = await finalize(deployment, fake);
    assert.equal(swapped.manifest, undefined);
    assert.deepEqual(swapped.mismatches.map(m => m.field), ['owner', 'treasury']);
});
