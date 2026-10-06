import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { nativeFunding } from './helpers/native-fixtures.mjs';
import {
    DEPLOYMENT, DESTINATION, GENESIS_ANCHOR, HttpError, createHarness, memoryIndexedDb, noteState, nullifierFor,
    selectorOf, word
} from './helpers/request-archive-harness.mjs';

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };

const { configureBrowserSdk } = await import('../configure.js');
const store = await import('../services/browserWalletStore.js');
const { BrowserWalletRuntime } = await import('../services/browserWalletRuntime.js');
const { assertHardenedVault } = await import('../services/zkapiNativeEth.mjs');

configureBrowserSdk({ configUrl: 'https://app.example/zkapi/browser-config.json' });

const funding = nativeFunding();
const ROOT_HISTORY_WINDOW = selectorOf('ROOT_HISTORY_WINDOW()');
// What a node answers for a selector the contract does not implement and no
// fallback catches (anvil and current geth: code 3).
const REVERTED = Object.freeze({ code: 3, message: 'execution reverted', data: '0x' });

/** A JSON-RPC fake of the pinned vault: `answers` maps a call's data to a result, an error or a throwing HTTP status. */
function vaultRpc(t, answers) {
    const calls = [];
    t.mock.method(globalThis, 'fetch', async (url, init) => {
        assert.equal(url, funding.demo_rpc_url, 'only the pinned RPC is read');
        const { method, params } = JSON.parse(init.body);
        calls.push({ method, data: params?.[0]?.data ?? null });
        if (method === 'eth_chainId') return Response.json({ jsonrpc: '2.0', id: 1, result: '0xaa36a7' });
        assert.equal(method, 'eth_call');
        const answer = answers[params[0].data];
        if (answer === undefined) assert.fail(`Unexpected vault read ${params[0].data}`);
        if (answer?.status) return new Response('unavailable', { status: answer.status });
        return Response.json(answer?.code != null
            ? { jsonrpc: '2.0', id: 1, error: answer }
            : { jsonrpc: '2.0', id: 1, result: answer });
    });
    return calls;
}

test('the hardened interface check reads ROOT_HISTORY_WINDOW once and fails closed on a legacy vault', async t => {
    assert.equal(ROOT_HISTORY_WINDOW, '0x1fe72de0');
    const calls = vaultRpc(t, { [ROOT_HISTORY_WINDOW]: word(86_400) });
    await assertHardenedVault(funding);
    assert.deepEqual(calls.map(call => call.data).filter(Boolean), [ROOT_HISTORY_WINDOW]);

    for (const [label, answer] of [['a revert', REVERTED], ['a geth-style revert', { code: -32000, message: 'execution reverted' }],
        ['no contract code', '0x'], ['another window', word(3_600)]]) {
        t.mock.restoreAll();
        vaultRpc(t, { [ROOT_HISTORY_WINDOW]: answer });
        await assert.rejects(assertHardenedVault(funding), error => {
            assert.equal(error.code, 'vault_revision_mismatch', label);
            assert.match(error.message, /vault_revision/, label);
            return true;
        });
    }

    // An unavailable RPC is not a verdict about the vault.
    t.mock.restoreAll();
    vaultRpc(t, { [ROOT_HISTORY_WINDOW]: { status: 503 } });
    await assert.rejects(assertHardenedVault(funding), error => error.code !== 'vault_revision_mismatch');
});

async function hardenedProfileOnVault(t, rootHistoryWindow) {
    const config = JSON.parse(await readFile(new URL('../assets/config/sepolia.json', import.meta.url), 'utf8'));
    const trusted = { ...config.trusted_deployment, ...funding, rpc_url: funding.demo_rpc_url,
        billing_token_address: null, vault_revision: 2, clearance_ownership_proof: 'required' };
    const manifest = { ...trusted, protocol_version: 2, proof_backend: 'groth16_bn254',
        proof_setup: { circuit_id: trusted.circuit_id, request_proving_key_sha256: trusted.request_proving_key_sha256,
            withdrawal_proving_key_sha256: trusted.withdrawal_proving_key_sha256 },
        privacy_mode: { openrouter_inference_base: trusted.openrouter_inference_base, verifier_url: trusted.verifier_url } };
    const originalLocation = globalThis.location;
    t.after(() => { globalThis.location = originalLocation; });
    globalThis.location = { href: 'https://app.example/', search: '', origin: 'https://app.example' };
    const calls = vaultRpc(t, {
        '0x4d1352fd': word(1_000_000_000),
        '0x631b2f10': word(0),
        [ROOT_HISTORY_WINDOW]: rootHistoryWindow
    });
    const runtime = new BrowserWalletRuntime();
    runtime.loadBrowserConfig = async () => ({ ...config, trusted_deployment: trusted,
        deployment_manifest_url: 'https://protocol.example/config.json',
        allowed_deployment_manifest_urls: ['https://protocol.example/config.json'] });
    runtime.directJson = async () => manifest;
    return { runtime, calls };
}

test('a vault_revision 2 profile pinned to a vault without the hardened interface refuses to initialize', async t => {
    const { runtime, calls } = await hardenedProfileOnVault(t, REVERTED);
    await assert.rejects(runtime.initialize(), { code: 'vault_revision_mismatch' });
    assert.ok(calls.some(call => call.data === ROOT_HISTORY_WINDOW), 'the hardened-only view was read');
    assert.equal(runtime.worker, null, 'no proof worker exists');
    assert.equal(runtime.initialized, false);
});

test('a vault_revision 2 profile on a hardened vault passes the check and goes on to start its worker', async t => {
    const { runtime, calls } = await hardenedProfileOnVault(t, word(86_400));
    const reached = new Error('worker construction reached');
    const originalWorker = globalThis.Worker;
    t.after(() => { globalThis.Worker = originalWorker; });
    globalThis.Worker = class { constructor() { throw reached; } };
    await assert.rejects(runtime.initialize(), error => error === reached);
    assert.equal(calls.filter(call => call.data === ROOT_HISTORY_WINDOW).length, 1);
});

// A harness wallet whose trusted profile claims vault_revision 2 while its
// vault answers only the legacy views: the hardened-only reads revert.
async function hardenedClaimOnLegacyVault() {
    indexedDB.clear();
    const h = createHarness(BrowserWalletRuntime, { vaultRevision: 2, graceSeconds: 3_600 });
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state: noteState() });
    await h.runtime.reload();
    const read = h.runtime.vaultWord;
    h.runtime.vaultWord = async (data, signal) => {
        if (data.startsWith('0x7cb4a03c') || data.startsWith('0x6cda756a')) {
            h.chain.reads.push(data);
            throw Object.assign(new Error('The ETH price RPC could not return a verified quote.'), { code: 'rpc_call_reverted' });
        }
        return read(data, signal);
    };
    return h;
}

async function transmit(h) {
    h.server.leasePost = () => {
        h.chain.root = '0x78';
        throw new HttpError('The proof root is stale.', 409, 'stale_root', { latest_root: '0x78' });
    };
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'stale_root' });
}

test('under a hardened profile a reverted challengedNullifiers read is a configuration error, never "not challenged"', async () => {
    const h = await hardenedClaimOnLegacyVault();
    await transmit(h);
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), { code: 'vault_revision_mismatch' });
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0, 'no escape proof is generated');
    assert.ok(h.chain.reads.some(read => read.startsWith('0x6cda756a')));
    await assert.rejects(h.runtime.vaultNullifierChallenged(nullifierFor(GENESIS_ANCHOR)), { code: 'vault_revision_mismatch' });

    // A transient read failure keeps its fail-safe answer: the gas estimate
    // still reverts ChallengedNullifier() on a hardened vault.
    h.runtime.vaultWord = async () => { throw new Error('RPC unavailable'); };
    assert.equal(await h.runtime.vaultNullifierChallenged(nullifierFor(GENESIS_ANCHOR)), false);
});

test('under a hardened profile a reverted effectiveExpiry read is a configuration error, never "not imminent"', async () => {
    const h = await hardenedClaimOnLegacyVault();
    await h.runtime.prepareLeaseRequest();
    h.server.leaseStatus = () => ({ status: 'revoking' });
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }),
        { code: 'vault_revision_mismatch' });
    assert.ok(h.chain.reads.some(read => read.startsWith('0x7cb4a03c')));
    assert.ok((await store.readBrowserWallet()).journal, 'the journal stays');
    await assert.rejects(h.runtime.escapeExpiryImminent(noteState()), { code: 'vault_revision_mismatch' });

    h.runtime.vaultWord = async () => { throw new Error('RPC unavailable'); };
    assert.equal(await h.runtime.escapeExpiryImminent(noteState()), false, 'an unreadable expiry only waits for the grace');

    // A strict profile never reads these views as a capability claim.
    indexedDB.clear();
    const strict = createHarness(BrowserWalletRuntime, {});
    strict.runtime.vaultWord = async () => {
        throw Object.assign(new Error('reverted'), { code: 'rpc_call_reverted' });
    };
    assert.equal(await strict.runtime.escapeExpiryImminent(noteState()), false);
    assert.equal(await strict.runtime.vaultNullifierChallenged(nullifierFor(GENESIS_ANCHOR)), false);
});
