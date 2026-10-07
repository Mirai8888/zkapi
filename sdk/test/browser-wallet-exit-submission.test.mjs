// The client's exit submission (zkapiClient.performWithdrawal) over the real
// runtime and store: the E4.6 recovery pass right before broadcast, the
// advisory wallet simulation of E4.5 (a refusal warns; the exit is still
// submitted, through the exit RPC's estimate or a fixed gas limit), and the
// E4.1 re-proof from the vault's logs after UnknownRoot. The wallet provider,
// the protocol server, the pinned RPC and the proof worker are observed fakes.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DEPLOYMENT, DESTINATION, VAULT, createHarness, depositPath, derivedAnchor, memoryIndexedDb, noteState, nullifierFor,
    selectorOf, within
} from './helpers/request-archive-harness.mjs';

const storage = new Map();
globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: key => storage.delete(key)
};
globalThis.zkapiWallet = (await import('../wallet.js')).default;

const store = await import('../services/browserWalletStore.js');
const { default: runtime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { bufferedGasLimit } = await import('../services/zkapiGas.mjs');

const FROM = `0x${'77'.repeat(20)}`;
// The user closes MetaMask: the flow ends right after the send was offered.
const SEND_REFUSED = Object.freeze({ code: 4001, message: 'User rejected the request.' });
const FIXED_EXIT_GAS = '0xf4240';
const revert = selector => ({ code: -32603, message: 'Internal JSON-RPC error.',
    data: { code: 3, message: 'execution reverted', data: selector } });
const UNKNOWN_ROOT = selectorOf('UnknownRoot()');
const CHALLENGED = selectorOf('ChallengedNullifier()');
const LOG_ROOT = 0x6161n;

/** The vault's logs through an RPC: one NoteDeposited of note 7 at root 0x6161. */
const logsRpc = async ({ method }) => {
    if (method === 'eth_chainId') return '0xaa36a7';
    if (method === 'eth_getBlockByNumber') return { number: '0x64' };
    assert.equal(method, 'eth_getLogs');
    return [{ address: VAULT, blockNumber: '0x10', logIndex: '0x0', removed: false,
        topics: [globalThis.zkapiWallet.ABI.noteDeposited, `0x${'0'.repeat(63)}7`, `0x${'ab'.repeat(32)}`],
        data: `0x${[5_000_000, 2_000_000_000, LOG_ROOT].map(value => BigInt(value).toString(16).padStart(64, '0')).join('')}` }];
};

/** The shared runtime the client uses, under the harness, and a client over a scripted wallet. */
async function scenario({ state = noteState(), liveRequest = false } = {}) {
    indexedDB.clear();
    storage.clear();
    for (const name of ['exitRpc', 'pinnedRpc']) delete runtime[name];
    runtime.activeLease = null;
    const h = createHarness(function SharedRuntime() { return runtime; });
    // The encoder takes 256-byte Groth16 proofs.
    h.worker.mutate = plan => { plan.proof.proof = Buffer.alloc(256, h.worker.proofs).toString('base64'); };
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    await runtime.reload();
    if (liveRequest) {
        h.server.leasePost = body => h.activeLease(body);
        await runtime.issueLease('chat');
        await runtime.reload();
    }
    const wallet = { estimates: [], sent: [], estimate: () => '0x9c40', atSend: null };
    globalThis.ethereum = {
        async request({ method, params = [] }) {
            if (method === 'eth_chainId') return `0x${Number(h.funding.chain_id).toString(16)}`;
            if (method === 'eth_estimateGas') {
                wallet.estimates.push(params[0]);
                return wallet.estimate(params[0], wallet.estimates.length);
            }
            if (method === 'eth_getTransactionCount') return '0x5';
            if (method === 'eth_gasPrice' && wallet.gasPrice != null) return `0x${BigInt(wallet.gasPrice).toString(16)}`;
            if (method === 'eth_sendTransaction') {
                wallet.sent.push({ ...params[0], atSend: await wallet.atSend?.() });
                throw SEND_REFUSED;
            }
            throw new Error(`unexpected wallet RPC ${method}`);
        }
    };
    const client = new ZkapiClient();
    client.browserMode = true;
    client.config = runtime.config;
    client.wallet = { has_note: true, note: { note_id: state.note_id, current_balance: state.current_balance } };
    for (const name of ['assertBalanceNotClaimed', 'refresh', 'settleActiveLease']) client[name] = async () => {};
    client.connectWallet = async () => FROM;
    client.checkEscapeDestination = async () => ({ destination: DESTINATION, accepts: true, warning: null });
    client.recoverFailedWithdrawalSubmission = async () => null;
    client.submittedTransactionMetadata = async () => null;
    const statuses = [];
    const withdraw = mode => client.performWithdrawal(mode, message => statuses.push(message), { destination: DESTINATION });
    return { h, client, wallet, statuses, withdraw };
}

const escapeProofs = h => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === 'escape');
const refusedInWallet = error => error.code === 4001;

test('E4.6: a successor that arrives between proving and sending is archived late_successor before the wallet sees the escape', async () => {
    const { h, wallet, statuses, withdraw } = await scenario({ liveRequest: true });
    const saved = await store.readBrowserWallet();
    const { journal, state } = saved;
    // The server settles the request only once the escape proof exists.
    let proved = false;
    const mutate = h.worker.mutate;
    h.worker.mutate = (plan, payload) => {
        mutate(plan, payload);
        if (plan.mode === 'escape') proved = true;
    };
    h.server.nullifier = () => (proved
        ? { status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(journal,
            { charge: 25_000, nextAnchor: derivedAnchor(nullifierFor(state.current_anchor)) }) }
        : { status: 'not_found', nullifier_status: 'unknown' });
    wallet.atSend = async () => (await store.listBrowserRequestArchive(DEPLOYMENT)).map(record => record.disposition);
    await assert.rejects(withdraw('escape'), refusedInWallet);
    assert.equal(wallet.sent.length, 1);
    assert.deepEqual(wallet.sent[0].atSend, ['late_successor'], 'the pre-broadcast pass ran before eth_sendTransaction');
    assert.ok(statuses.some(message => /settled private request arrived after the exit proof was made/.test(message)));
    const after = await store.readBrowserWallet();
    assert.equal(after.state.current_anchor, state.current_anchor, 'a live exit proof keeps the successor archived (E6)');
    assert.deepEqual(after.exitLock.released.map(entry => entry.kind), [0]);
});

test('E4.5: a wallet simulation that refuses an escape only warns; the escape is still offered with a fixed gas limit', async () => {
    for (const refusal of [revert(CHALLENGED), { code: -32603, message: 'Internal JSON-RPC error.' },
        { code: -32000, message: 'header not found' }]) {
        const { h, wallet, statuses, withdraw } = await scenario();
        wallet.estimate = () => { throw refusal; };
        await assert.rejects(withdraw('escape'), refusedInWallet, JSON.stringify(refusal));
        assert.equal(wallet.sent.length, 1, 'the escape reached the wallet');
        assert.equal(wallet.sent[0].gas, FIXED_EXIT_GAS);
        assert.equal(wallet.sent[0].to, VAULT);
        assert.ok(statuses.some(message => /simulation refused this escape/.test(message)));
        assert.equal(escapeProofs(h).length, 1, 'a refusal no new proof can cure is not re-proved');
    }
    // A mutual close too: its simulation is advisory as well.
    const close = await scenario();
    close.h.server.clearance = body => ({ status: 'ok', withdrawal_nullifier: body.withdrawal_nullifier, signature: { r: '0x1', s: '0x2' } });
    close.client.readContractUint = async () => 0x77n;
    close.wallet.estimate = () => { throw revert(CHALLENGED); };
    await assert.rejects(close.withdraw('mutual'), refusedInWallet);
    assert.equal(close.wallet.sent.length, 1);
    assert.equal(close.wallet.sent[0].gas, FIXED_EXIT_GAS);
    assert.ok(close.statuses.some(message => /simulation refused this close/.test(message)));
});

test('E4.5: with an exit RPC set, its estimate replaces a refused wallet simulation', async () => {
    const { wallet, statuses, withdraw } = await scenario({ state: noteState({ deposit_path: depositPath('0x51') }) });
    wallet.estimate = () => { throw { code: -32000, message: 'header not found' }; };
    const estimates = [];
    runtime.exitRpc = () => async ({ method, params }) => {
        // E0 also reads effectiveExpiry through it.
        if (method === 'eth_call') return `0x${(2_000_000_000).toString(16).padStart(64, '0')}`;
        assert.equal(method, 'eth_estimateGas');
        estimates.push(params[0]);
        return '0x927c0';
    };
    await assert.rejects(withdraw('escape'), refusedInWallet);
    assert.equal(estimates.length, 1);
    assert.deepEqual(estimates[0], { from: FROM, to: VAULT, data: wallet.estimates[0].data });
    assert.equal(wallet.sent[0].gas, bufferedGasLimit(0x927c0n));
    assert.ok(statuses.some(message => /your exit RPC accepts it/.test(message)));
});

test('E4.1: an UnknownRoot simulation re-proves once at another root, and a second one only warns', async () => {
    for (const secondAnswer of ['accepts', 'refuses']) {
        const { h, wallet, withdraw } = await scenario({ state: noteState({ deposit_path: depositPath('0x51') }) });
        runtime.pinnedRpc = () => logsRpc;
        wallet.estimate = (_transaction, count) => {
            if (count === 1 || secondAnswer === 'refuses') throw revert(UNKNOWN_ROOT);
            return '0x9c40';
        };
        await assert.rejects(withdraw('escape'), refusedInWallet, secondAnswer);
        const [first, second, third] = escapeProofs(h);
        assert.equal(first.payload.args.active_root, '0x51', 'the saved deposit path first');
        assert.equal(second.payload.args.active_root, h.chain.root, 'then the indexer at the vault\'s current root');
        assert.equal(third, undefined, 'one re-proof per refusal');
        assert.equal(wallet.estimates.length, 2);
        assert.equal(wallet.sent.length, 1);
        assert.equal(wallet.sent[0].gas, secondAnswer === 'accepts' ? bufferedGasLimit(0x9c40n) : FIXED_EXIT_GAS);
    }
});

test('E4.1: after UnknownRoot the vault logs replace a missing indexer, the indexer replaces refused logs, and with neither the existing proof is still submitted', async () => {
    const refusingLogs = async ({ method }) => {
        if (method === 'eth_chainId') return '0xaa36a7';
        if (method === 'eth_getBlockByNumber') return { number: '0x64' };
        throw new Error('eth_getLogs is not supported');
    };
    for (const [label, indexerUp, logs, expected] of [
        ['indexer down, logs readable', false, logsRpc, 'logs'],
        ['logs refused, indexer up', true, refusingLogs, 'indexer'],
        ['both unavailable', false, refusingLogs, 'existing']
    ]) {
        const { h, wallet, statuses, withdraw } = await scenario({ state: noteState({ deposit_path: depositPath('0x51') }) });
        runtime.pinnedRpc = () => logs;
        if (!indexerUp) runtime.treePath = async () => { throw new Error('indexer down'); };
        // The wallet's RPC keeps refusing the root it does not know.
        wallet.estimate = (_transaction, count) => {
            if (count === 1 || expected === 'existing') throw revert(UNKNOWN_ROOT);
            return '0x9c40';
        };
        await assert.rejects(within(5_000, withdraw('escape'), label), refusedInWallet, label);
        const roots = escapeProofs(h).map(call => call.payload.args.active_root);
        assert.equal(roots[0], '0x51', label);
        if (expected === 'logs') assert.deepEqual(roots.slice(1).map(root => BigInt(root)), [LOG_ROOT], label);
        if (expected === 'indexer') assert.deepEqual(roots.slice(1), [h.chain.root], label);
        if (expected === 'existing') {
            assert.deepEqual(roots, ['0x51'], `${label}: no other proof`);
            assert.ok(statuses.some(message => /No Merkle path at another root was found/.test(message)), label);
            assert.equal(wallet.sent[0].gas, FIXED_EXIT_GAS, `${label}: the refusal only warns`);
        }
        assert.equal(wallet.sent.length, 1, `${label}: the escape reached the wallet`);
    }
});

test('G1: a withdrawal warns first when the balance returns less than three escape fees', async () => {
    for (const [gasPrice, warned] of [[10_000_000_000n, true], [1_000_000_000n, false], [null, false]]) {
        const { wallet, statuses, withdraw } = await scenario({ state: noteState({ deposit_path: depositPath('0x51') }) });
        wallet.gasPrice = gasPrice;
        await assert.rejects(withdraw('escape'), refusedInWallet);
        const index = statuses.findIndex(message => /less than three times the estimated network fee of an escape/.test(message));
        assert.equal(index >= 0, warned, `gas price ${gasPrice}`);
        if (warned) {
            assert.match(statuses[index], /as little as 0\.005 ETH.*\(0\.0062 ETH/);
            assert.ok(index < statuses.findIndex(message => /Confirm the escape-hatch start/.test(message)), 'before the wallet prompt');
        }
        assert.equal(wallet.sent.length, 1, 'the warning never blocks the exit');
    }
});
