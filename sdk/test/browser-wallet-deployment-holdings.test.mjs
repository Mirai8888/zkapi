import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DEPLOYMENT, DESTINATION, GENESIS_ANCHOR, VAULT, createHarness, memoryIndexedDb, noteState, nullifierFor
} from './helpers/request-archive-harness.mjs';

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };

const store = await import('../services/browserWalletStore.js');
const { BrowserWalletRuntime } = await import('../services/browserWalletRuntime.js');

// DEPLOYMENT plays the legacy deployment; the host then pins a hardened one.
const LEGACY = DEPLOYMENT;
const HARDENED = 'hardened-deployment';
const reserving = () => ({ phase: 'reserving', mode: 'mutual', operationId: 'close', noteId: 7, destination: DESTINATION,
    withdrawalNullifier: nullifierFor(GENESIS_ANCHOR), clearanceReserved: true, createdAt: 1 });

async function legacyWallet(runtimeValue = {}) {
    indexedDB.clear();
    const h = createHarness(BrowserWalletRuntime);
    await store.writeBrowserWallet({ deploymentId: LEGACY, billingAsset: 'native_eth', state: noteState(), ...runtimeValue });
    await h.runtime.reload();
    return h;
}

function hardenedRuntime() {
    const h = createHarness(BrowserWalletRuntime, { vaultRevision: 2 });
    h.runtime.manifest = { deployment_id: HARDENED };
    return h.runtime;
}

test('a set-aside legacy mutual close stays visible to a host and to a runtime pinned elsewhere', async () => {
    const h = await legacyWallet({ preparedWithdrawal: reserving() });
    await h.runtime.parkPreparedWithdrawal();
    const parked = await store.readBrowserWallet();
    assert.equal(parked.state, null, 'the runtime slot holds no note any more');
    assert.equal(store.browserRuntimeHoldsState(parked), false);

    assert.deepEqual(await store.readBrowserWalletHoldings(), [{
        deploymentId: LEGACY,
        runtime: false,
        withdrawals: [{ recordId: `${LEGACY}:11155111:${VAULT}:7`, noteId: 7, mode: 'mutual', phase: 'parked' }]
    }]);

    // A runtime pinned to the newer deployment loads, and says what it cannot reach.
    const runtime = hardenedRuntime();
    await runtime.reload();
    assert.deepEqual(runtime.withdrawals, []);
    const summary = runtime.snapshot();
    assert.deepEqual(summary.withdrawals, []);
    assert.deepEqual(summary.config.other_deployment_withdrawals, [{
        deployment_id: LEGACY, record_id: `${LEGACY}:11155111:${VAULT}:7`, note_id: 7, mode: 'mutual', phase: 'parked'
    }]);
    // The legacy runtime still owns it.
    await h.runtime.reload();
    assert.equal(h.runtime.snapshot().config.other_deployment_withdrawals.length, 0);
    assert.equal(h.runtime.snapshot().withdrawals.length, 1);
});

test('pending, challenged and closing legacy escapes count until a close is final and nothing is finalizing', async () => {
    const h = await legacyWallet();
    const escape = await h.runtime.detachEscapeWithdrawal({ noteId: 7, destination: DESTINATION, finalBalance: 5_000_000,
        challengeDeadline: 2_000_000_000, transactionHash: `0x${'aa'.repeat(32)}`, startBlockNumber: 10 });
    const listed = async () => (await store.readBrowserWalletHoldings())
        .flatMap(entry => entry.withdrawals.map(record => `${entry.deploymentId}:${record.phase}`));
    assert.deepEqual(await listed(), [`${LEGACY}:pending`]);
    for (const [changes, expected] of [
        [{ phase: 'challenged_unconfirmed' }, [`${LEGACY}:challenged_unconfirmed`]],
        [{ phase: 'restored' }, [`${LEGACY}:restored`]],
        [{ phase: 'finalizing' }, [`${LEGACY}:finalizing`]],
        [{ phase: 'closed_unconfirmed' }, [`${LEGACY}:closed_unconfirmed`]],
        [{ phase: 'closed', finalizeTransactionHash: `0x${'bb'.repeat(32)}` }, [`${LEGACY}:closed`]],
        [{ phase: 'closed', finalizeTransactionHash: null, finalizeSubmissionId: 'claim' }, [`${LEGACY}:closed`]],
        [{ phase: 'closed', finalizeTransactionHash: null, finalizeSubmissionId: null }, []]
    ]) {
        await store.putBrowserWithdrawal({ ...(await store.listBrowserWithdrawals())[0], ...changes });
        assert.deepEqual(await listed(), expected, JSON.stringify(changes));
    }
    assert.equal(escape.deploymentId, LEGACY);
});

test('when both deployments hold state the one in the runtime slot is the one that can load first', async () => {
    const h = await legacyWallet({ preparedWithdrawal: reserving() });
    await h.runtime.parkPreparedWithdrawal();
    // The user then funded a note on the newer deployment.
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), deploymentId: HARDENED,
        state: noteState({ note_id: 1, current_anchor: '0x4444' }) });
    const holdings = await store.readBrowserWalletHoldings();
    assert.deepEqual(holdings.map(entry => [entry.deploymentId, entry.runtime, entry.withdrawals.length]),
        [[HARDENED, true, 0], [LEGACY, false, 1]]);
    // The legacy profile cannot load until the newer note is withdrawn.
    await assert.rejects(h.runtime.reload(), /contains a wallet for hardened-deployment/);
    await hardenedRuntime().reload();
});

test('the runtime-state rule is the one the deployment guard applies', async () => {
    const quote = { operationId: 'draft', amount: 1 };
    for (const [value, holds] of [
        [{}, false],
        [{ lateWithdrawalAttempts: [{ status: 'closed' }], lateDepositAttempts: [{ status: 'confirmed' }] }, false],
        [{ state: noteState() }, true],
        [{ journal: { exists: true } }, true],
        [{ pendingDeposit: { operationId: 'p' } }, true],
        [{ depositQuote: quote }, true],
        [{ preparedWithdrawal: reserving() }, true],
        [{ lease: { sessionId: 's' } }, true],
        [{ lateWithdrawalAttempts: [{ status: 'submitted' }] }, true],
        [{ lateDepositAttempts: [{ status: 'submitted' }] }, true]
    ]) {
        indexedDB.clear();
        await store.writeBrowserWallet({ deploymentId: LEGACY, billingAsset: 'native_eth', ...value });
        assert.equal(store.browserRuntimeHoldsState(await store.readBrowserWallet()), holds, JSON.stringify(value));
        const holdings = await store.readBrowserWalletHoldings();
        assert.deepEqual(holdings, holds ? [{ deploymentId: LEGACY, runtime: true, withdrawals: [] }] : [],
            JSON.stringify(value));
        const other = hardenedRuntime();
        if (holds) await assert.rejects(other.reload(), /contains a wallet for/);
        else await other.reload();
    }
});
