// The client rules of the concession exit (design §6.1–§6.6) in the real
// runtime and store, over a transactional IndexedDB: C1–C5, the write order,
// E0–E7, the stale-device pre-check, the Merkle path without the operator and
// the exit kit. Only the protocol server, the pinned vault RPC and the proof
// worker are observed fakes (helpers/request-archive-harness.mjs).
import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DEPLOYMENT, DESTINATION, GENESIS_ANCHOR, HttpError, VAULT, createHarness, depositPath, derivedAnchor,
    memoryIndexedDb, noteState, nullifierFor, successorFor
} from './helpers/request-archive-harness.mjs';

// A crash can be injected into the one write that persists a request: the
// IndexedDB transaction then aborts as it would when the tab dies mid-write.
const control = { crash: null };
function crashable(idb) {
    const wrapStore = (transaction, store, name) => name !== 'runtime' ? store : {
        ...store,
        put(value, key) {
            if (control.crash?.(value)) {
                control.crash = null;
                transaction.abort();
                return {};
            }
            return store.put(value, key);
        }
    };
    const wrapDatabase = database => new Proxy(database, {
        get(target, property) {
            if (property !== 'transaction') return Reflect.get(target, property);
            return (...args) => {
                const transaction = target.transaction(...args);
                return new Proxy(transaction, {
                    get(inner, key) {
                        if (key === 'objectStore') return name => wrapStore(inner, inner.objectStore(name), name);
                        const value = Reflect.get(inner, key);
                        return typeof value === 'function' ? value.bind(inner) : value;
                    },
                    set(inner, key, value) { inner[key] = value; return true; }
                });
            };
        }
    });
    return {
        ...idb,
        open(name, version) {
            const request = idb.open(name, version);
            return new Proxy(request, {
                get(target, property) {
                    return property === 'result' && target.result ? wrapDatabase(target.result) : Reflect.get(target, property);
                },
                set(target, property, value) { target[property] = value; return true; }
            });
        }
    };
}

const storage = new Map();
globalThis.indexedDB = crashable(memoryIndexedDb());
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: key => storage.delete(key)
};

const store = await import('../services/browserWalletStore.js');
const { BrowserWalletRuntime } = await import('../services/browserWalletRuntime.js');
const { openExitKit } = await import('../services/zkapiExitKit.mjs');
const { ABI } = await import('../wallet.js');

const records = () => store.listBrowserRequestArchive(DEPLOYMENT);
const saved = () => store.readBrowserWallet();
const W = 21_905;
const now = () => Math.floor(Date.now() / 1_000);
const BOUND = 1_000_000;

async function freshWallet(options = {}, state = noteState()) {
    indexedDB.clear();
    storage.clear();
    control.crash = null;
    const h = createHarness(BrowserWalletRuntime, options);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    await h.runtime.reload();
    return h;
}

/** A wallet whose current state sent one request (bound BOUND) that is still live. */
async function walletWithLiveRequest(options, state) {
    const h = await freshWallet(options, state);
    h.server.leasePost = body => h.activeLease(body);
    await h.runtime.issueLease('chat');
    await h.runtime.reload();
    return h;
}

const proofsOf = (h, mode) => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === mode);
const requestProofs = h => h.workerOperations('prepareRequest').length;

test('C2 and the write order: the bound, the journal and its archive record land in one write before the request leaves', async () => {
    const h = await freshWallet();
    let atPost = null;
    h.server.leasePost = async body => {
        atPost = { saved: await saved(), archived: await records(), body };
        return h.activeLease(body);
    };
    await h.runtime.issueLease('chat');
    assert.ok(atPost, 'the request reached the server');
    assert.equal(atPost.saved.state.bound_at_state, atPost.body.public_inputs.solvency_bound,
        'the state records the request\'s bound before the proof leaves');
    assert.equal(atPost.saved.journal.client_request_id, atPost.body.client_request_id);
    assert.deepEqual(atPost.archived.map(record => record.disposition), ['pending']);

    // A crash during that one write leaves none of the three, and nothing is sent.
    const crashed = await freshWallet();
    crashed.server.leasePost = () => assert.fail('a request is never sent after a failed write');
    control.crash = value => Boolean(value?.journal);
    await assert.rejects(crashed.runtime.issueLease('chat'));
    const after = await saved();
    assert.equal(after.journal, null);
    assert.equal(after.state.bound_at_state ?? 0, 0, 'no bound without its journal');
    assert.deepEqual(await records(), []);
    assert.equal(crashed.serverCalls('POST', '/v2/openrouter/leases').length, 0);
});

test('C2: every request proof at a state carries the state\'s one bound, whatever tier is selected', async () => {
    const h = await freshWallet();
    h.server.leasePost = () => {
        h.chain.root = '0x78';
        throw new HttpError('The proof root is stale.', 409, 'stale_root');
    };
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    await assert.rejects(h.runtime.issueLease('chat', () => {}, null, 1), { code: 'stale_root' });
    const first = h.workerOperations('prepareRequest')[0].payload.config.request_charge_cap;
    assert.equal((await saved()).state.bound_at_state, first);
    // The next chat at the same state selects a larger tier: the proof keeps
    // the bound fixed at the state (the WebAssembly would refuse another).
    h.server.leasePost = body => h.activeLease(body);
    await h.runtime.reload();
    await h.runtime.prepareLeaseRequest(() => {}, null, 4.5);
    const second = h.workerOperations('prepareRequest')[1].payload.config.request_charge_cap;
    assert.equal(second, first);
});

test('C1: a request and an exit decision never interleave under the wallet lock', async () => {
    // Holds the wallet lock inside `operation` until `release` resolves.
    const inside = (h, operation) => {
        let entered;
        const reached = new Promise(resolve => { entered = resolve; });
        const call = h.runtime.worker.call;
        h.runtime.worker.call = async (name, payload) => {
            if (name === operation) {
                entered();
                await new Promise(resolve => setTimeout(resolve, 20));
            }
            return call(name, payload);
        };
        return reached;
    };
    // The exit first: the request waits for the lock and is refused (C3).
    const h = await freshWallet();
    h.server.leasePost = body => h.activeLease(body);
    const exitInside = inside(h, 'withdrawalNullifier');
    const exit = h.runtime.prepareWithdrawal('escape', DESTINATION);
    await exitInside;
    const request = h.runtime.issueLease('chat');
    const [plan, refused] = await Promise.allSettled([exit, request]);
    assert.equal(plan.status, 'fulfilled');
    assert.equal(plan.value.mode, 'escape');
    assert.equal(refused.status, 'rejected');
    assert.equal(refused.reason.code, 'exit_locked');
    assert.equal(requestProofs(h), 0, 'no request proof while the exit lock is held');

    // The request first: the exit sees it (an unresolved state, E3).
    const other = await freshWallet();
    other.server.leasePost = body => other.activeLease(body);
    const requestInside = inside(other, 'prepareRequest');
    const leasing = other.runtime.issueLease('chat');
    await requestInside;
    const [lease, waited] = await Promise.allSettled([leasing, other.runtime.prepareWithdrawal('mutual', DESTINATION)]);
    assert.equal(lease.status, 'fulfilled');
    assert.equal(waited.status, 'rejected');
    assert.equal(waited.reason.code, 'request_settlement_pending');
    assert.equal(waited.reason.data.bound_at_state, String(BOUND));
});

test('C3: a mutual lock allows one ownership proof and closes; after it falls back to an escape only escapes', async () => {
    const h = await freshWallet();
    let lockAtPost = null;
    h.server.clearance = async () => {
        lockAtPost = (await saved()).exitLock;
        throw new HttpError('Unavailable', 503, 'service_unavailable');
    };
    const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    // The ownership proof was journaled before it left (E4.4).
    assert.deepEqual(lockAtPost.released.map(entry => entry.kind), [2]);
    assert.equal(lockAtPost.mode, 'mutual');
    // E2.5: unreachable, so an escape conceding nothing.
    assert.equal(plan.mode, 'escape');
    assert.equal(plan.public_inputs.conceded, 0);
    assert.equal(plan.decision.rule, 'E2.fallback');
    const lock = (await saved()).exitLock;
    assert.equal(lock.mode, 'escape');
    assert.deepEqual(lock.released.map(entry => entry.kind), [2, 0]);

    // No request proof while the lock is held.
    h.server.leasePost = () => assert.fail('no request leaves a frozen note');
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'exit_locked' });
    assert.equal(requestProofs(h), 0);
    // A second mutual request neither proves ownership again nor asks the
    // server: the released escape is the exit.
    const again = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(again.mode, 'escape');
    assert.deepEqual(again.proof, plan.proof);
    assert.equal(proofsOf(h, 'ownership').length, 1);
    assert.equal(h.serverCalls('POST', '/v2/withdraw/clearance').length, 1);
    assert.equal(h.runtime.snapshot().config.exit.lock.exit_proofs_released, 1);
});

test('C4: no request when its settlement could run past must_initiate_by', async () => {
    const edge = now() + 43_200 + W + 900 + 3_600;
    const h = await freshWallet({}, noteState({ expiry_ts: edge - 60 }));
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'note_near_expiry' });
    assert.equal(requestProofs(h), 0);
    assert.equal(h.runtime.snapshot().config.exit.near_expiry, true);
    const later = await freshWallet({}, noteState({ expiry_ts: edge + 60 }));
    later.server.leasePost = body => later.activeLease(body);
    await later.runtime.issueLease('chat');
    assert.equal(requestProofs(later), 1);
    assert.equal(later.runtime.snapshot().config.exit.near_expiry, false);
});

test('E0: a hanging operator cannot hold an exit, and Retry-After is ignored', async () => {
    const h = await walletWithLiveRequest();
    h.runtime.exitTimingOverrides = { callTimeoutMs: 40, recoveryBudgetMs: 120 };
    const calls = [];
    h.runtime.remoteJson = url => {
        calls.push(url);
        return new Promise(() => {});
    };
    const started = Date.now();
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.ok(Date.now() - started < 2_000, 'every call ended at its timeout');
    assert.equal(plan.mode, 'escape');
    assert.equal(plan.decision.rule, 'E3.forced', 'nothing recovered: a forced escape before T');
    assert.equal(plan.public_inputs.conceded, 0);
    assert.ok(calls.length >= 3 && calls.length <= 6, `${calls.length} bounded calls`);

    // A 429 with a long Retry-After counts as unreachable at once.
    const t = await walletWithLiveRequest();
    let throttled = 0;
    t.runtime.remoteJson = async url => {
        throttled += 1;
        throw Object.assign(new Error('Too many requests'), { status: 429, code: 'rate_limited',
            data: { retry_after_seconds: 3_600 }, url });
    };
    const quick = Date.now();
    await t.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.ok(Date.now() - quick < 1_000);
    assert.ok(throttled <= 6, 'no retries');
});

test('E0: past must_initiate_by E1 is skipped and the escape concedes the bound; E_low comes from expiry_ts', async () => {
    // The request was sent long before; now must_initiate_by has passed.
    const h = await walletWithLiveRequest();
    h.server.calls.length = 0;
    const restore = Date.now;
    Date.now = () => (2_000_000_000 - 43_000) * 1_000;
    let plan;
    try {
        plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    } finally {
        Date.now = restore;
    }
    assert.equal(plan.mode, 'escape');
    assert.equal(plan.decision.rule, 'E3.T', 'T is never later than must_initiate_by');
    assert.equal(plan.public_inputs.conceded, BOUND);
    assert.equal(h.serverCalls('GET', '/v2/requests/').length, 0, 'E1 is skipped');
    assert.equal(h.serverCalls('POST', '/v2/openrouter/leases/').length, 0, 'no lease call either');
    assert.equal(h.server.calls.filter(call => /^\/v2\/nullifiers\/[^/]+$/.test(call.path)).length, 0);
    assert.equal(h.serverCalls('POST', '/v2/withdraw/clearance').length, 0);
});

test('E0: E_low is expiry_ts unless the exit RPC and the pinned RPC both report a later expiry', async () => {
    const h = await freshWallet();
    const state = noteState({ expiry_ts: 2_000_000_000 });
    const rpc = value => async ({ method, params }) => {
        assert.equal(method, 'eth_call');
        assert.equal(params[0].data.slice(0, 10), `0x${ABI.effectiveExpiry}`);
        return `0x${BigInt(value).toString(16).padStart(64, '0')}`;
    };
    assert.equal(await h.runtime.exitLowExpiry(state), 2_000_000_000, 'no exit RPC: the local expiry');
    h.runtime.exitRpc = () => rpc(2_100_000_000);
    h.runtime.pinnedRpc = () => rpc(2_050_000_000);
    assert.equal(await h.runtime.exitLowExpiry(state), 2_050_000_000);
    h.runtime.pinnedRpc = () => rpc(1_000);
    assert.equal(await h.runtime.exitLowExpiry(state), 2_000_000_000, 'one RPC alone never moves it');
    h.runtime.pinnedRpc = () => async () => { throw new Error('down'); };
    assert.equal(await h.runtime.exitLowExpiry(state), 2_000_000_000);
    // The snapshot's must_initiate_by uses only local data.
    await store.writeBrowserWallet({ ...(await saved()), state });
    await h.runtime.reload();
    assert.equal(h.runtime.snapshot().config.exit.must_initiate_by, (2_000_000_000 - 43_200) * 1_000);
    // The exit RPC setting is validated and persisted per origin.
    assert.throws(() => h.runtime.setExitRpcUrl('http://rpc.example'), { code: 'exit_rpc_invalid' });
    assert.equal(h.runtime.setExitRpcUrl('https://rpc.example/key'), 'https://rpc.example/key');
    assert.equal(storage.get('zkapi-exit-rpc-url'), 'https://rpc.example/key');
    assert.equal(h.runtime.snapshot().config.exit.exit_rpc_url, 'https://rpc.example/key');
});

/** A state that sent a request whose record a later read resolved (discarded_stale_root). */
async function walletWithResolvedRequest() {
    const h = await freshWallet();
    h.server.leasePost = () => {
        h.chain.root = '0x78';
        throw new HttpError('The proof root is stale.', 409, 'stale_root');
    };
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'stale_root' });
    await h.runtime.reload();
    return h;
}

test('E2: a clearance refused with nullifier_used decides as E3; unreachable or another refusal escapes with c = 0', async () => {
    const h = await walletWithResolvedRequest();
    const created = Math.floor((await records())[0].createdAt / 1_000);
    h.server.clearance = () => { throw new HttpError('The nullifier is used.', 409, 'nullifier_used'); };
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), error => {
        assert.equal(error.code, 'request_settlement_pending');
        assert.equal(error.data.clearance_error_code, 'nullifier_used');
        assert.equal(error.data.escape_at, (created + W + 900) * 1_000);
        return true;
    });
    assert.equal(proofsOf(h, 'escape').length, 0);
    // The ownership proof was sent, so the state stays withdrawal-only (C5).
    assert.deepEqual((await saved()).exitLock.released.map(entry => entry.kind), [2]);
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'exit_locked' });

    for (const refusal of [new HttpError('Unavailable', 503, 'service_unavailable'),
        new HttpError('Invalid ownership proof.', 400, 'invalid_ownership_proof'), new TypeError('Failed to fetch')]) {
        const other = await walletWithResolvedRequest();
        other.server.clearance = () => { throw refusal; };
        const plan = await other.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'escape', String(refusal));
        assert.equal(plan.public_inputs.conceded, 0);
        assert.equal(plan.decision.rule, 'E2.fallback');
    }
});

test('E2.4: a retry after nullifier_used still waits for T, asks no second clearance, and only an explicit escape escapes early', async () => {
    const h = await walletWithResolvedRequest();
    const created = Math.floor((await records())[0].createdAt / 1_000);
    let clearances = 0;
    h.server.clearance = () => {
        clearances += 1;
        throw new HttpError('The nullifier is used.', 409, 'nullifier_used');
    };
    const waitsForT = error => {
        assert.equal(error.code, 'request_settlement_pending');
        assert.equal(error.data.clearance_error_code, 'nullifier_used');
        assert.equal(error.data.escape_at, (created + W + 900) * 1_000);
        return true;
    };
    // Any UI retries after an error: every retry decides as the first did.
    for (let attempt = 0; attempt < 3; attempt += 1) {
        await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), waitsForT);
    }
    assert.equal(clearances, 1, 'one clearance request');
    assert.equal(proofsOf(h, 'ownership').length, 1, 'one ownership proof');
    assert.equal(proofsOf(h, 'escape').length, 0, 'no escape before T');
    assert.deepEqual((await saved()).exitLock.released.map(entry => [entry.kind, entry.outcome]), [[2, 'nullifier_used']]);
    // A cancel releases the lock; the withdrawal-only marker keeps the answer.
    await h.runtime.cancelExit();
    assert.equal((await saved()).preparedWithdrawal.clearanceOutcome, 'nullifier_used');
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), waitsForT);
    assert.equal(clearances, 1);
    assert.equal(proofsOf(h, 'ownership').length, 1);
    // Before T only an explicit escape escapes: the forced choice (E3).
    const forced = await h.runtime.prepareWithdrawal('escape', DESTINATION, { earlyConcession: 'bound' });
    assert.equal(forced.decision.rule, 'E3.forced');
    assert.equal(forced.public_inputs.conceded, BOUND);
    // At T the mutual request escapes conceding the bound (E3.T).
    const later = await walletWithResolvedRequest();
    later.server.clearance = () => { throw new HttpError('The nullifier is used.', 409, 'nullifier_used'); };
    await assert.rejects(later.runtime.prepareWithdrawal('mutual', DESTINATION), waitsForT);
    const restore = Date.now;
    Date.now = () => (created + W + 900) * 1_000 + 60_000;
    try {
        const plan = await later.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'escape');
        assert.equal(plan.decision.rule, 'E3.T');
        assert.equal(plan.public_inputs.conceded, BOUND);
    } finally {
        Date.now = restore;
    }
});

test('E2.5 on a retry: an ownership proof answered without a clearance escapes with c = 0, never a second proof', async () => {
    for (const [answer, outcome] of [[() => { throw new HttpError('Unavailable', 503, 'service_unavailable'); }, 'unreachable'],
        [() => { throw new HttpError('Invalid ownership proof.', 400, 'invalid_ownership_proof'); }, 'refused']]) {
        const h = await walletWithResolvedRequest();
        h.server.clearance = answer;
        // The first attempt fails after the answer (the escape proof cannot be made).
        h.worker.mutate = plan => { if (plan.mode === 'escape') throw new Error('proving failed'); };
        await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), /proving failed/);
        assert.deepEqual((await saved()).exitLock.released.map(entry => [entry.kind, entry.outcome]), [[2, outcome]]);
        h.worker.mutate = null;
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'escape', outcome);
        assert.equal(plan.decision.rule, 'E2.fallback');
        assert.equal(plan.decision.clearance_error_code, outcome);
        assert.equal(plan.public_inputs.conceded, 0);
        assert.equal(proofsOf(h, 'ownership').length, 1, 'one ownership proof per lock');
    }
});

test('E2: a fresh state closes cooperatively, journaling the close proof with its plan', async () => {
    const h = await freshWallet();
    h.server.clearance = body => ({ status: 'ok', withdrawal_nullifier: body.withdrawal_nullifier, signature: { r: '0x1', s: '0x2' } });
    const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(plan.mode, 'mutual');
    assert.equal(plan.public_inputs.kind, 1);
    assert.equal(plan.decision.rule, 'E2');
    assert.deepEqual((await saved()).exitLock.released.map(entry => entry.kind), [2, 1]);
    const [close] = proofsOf(h, 'mutual');
    const validity = close.payload.args.valid_until - now();
    assert.ok(validity > 10_700 && validity <= 10_800);
    // Within an hour of must_initiate_by a fresh state escapes instead.
    const late = await freshWallet({}, noteState({ expiry_ts: now() + 43_200 + 3_000 }));
    late.server.clearance = () => assert.fail('no clearance is asked so close to the deadline');
    const escape = await late.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(escape.mode, 'escape');
    assert.equal(escape.decision.rule, 'E2.deadline');
});

test('E3: before T an escape concedes 0 (or the bound on request), at T the bound, and lost ε min(charge, b)', async () => {
    const h = await walletWithLiveRequest();
    const journal = (await saved()).journal;
    const forced = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(forced.decision.rule, 'E3.forced');
    assert.equal(forced.public_inputs.conceded, 0);
    assert.equal(forced.boundAtState, String(BOUND));
    assert.equal(forced.stateBalance, String(5_000_000));
    // The live journal left the runtime only into the archive, still installable.
    const [record] = await records();
    assert.equal(record.disposition, 'abandoned_for_escape');
    assert.equal(record.journal.user_rerandomization, journal.user_rerandomization);
    assert.equal((await saved()).journal, null);

    const bound = await walletWithLiveRequest();
    const chosen = await bound.runtime.prepareWithdrawal('escape', DESTINATION, { earlyConcession: 'bound' });
    assert.equal(chosen.public_inputs.conceded, BOUND);
    assert.equal(chosen.public_inputs.final_balance, 5_000_000 - BOUND);

    // At T (the created_at + W + 900 of the newest request) the bound.
    const atT = await walletWithLiveRequest();
    // The server still reports the request reserved (an 'unknown' this late
    // would resolve it: the state would be fresh).
    atT.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
    const created = Math.floor(atT.runtime.runtime.journal.created_at_ms / 1_000);
    const restore = Date.now;
    Date.now = () => (created + W + 900) * 1_000 + 1_000;
    try {
        const plan = await atT.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'escape');
        assert.equal(plan.decision.rule, 'E3.T');
        assert.equal(plan.public_inputs.conceded, BOUND);
    } finally {
        Date.now = restore;
    }

    // Lost ε: a signed, derived-anchor response whose journal is gone.
    const lost = await walletWithLiveRequest();
    const state = (await saved()).state;
    const foreign = { ...(await saved()).journal, client_request_id: 'lost-journal', user_rerandomization: '0x1' };
    lost.server.requests = () => { throw new HttpError('Not found', 404, 'not_found'); };
    lost.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
        request_response: lost.receiptFor(foreign, { charge: 25_000, nextAnchor: derivedAnchor(nullifierFor(state.current_anchor)) }) });
    const plan = await lost.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(plan.decision.rule, 'E3.lost_epsilon');
    assert.equal(plan.public_inputs.conceded, 25_000);
    // The same response at a non-derived anchor is no lost-ε evidence.
    const notDerived = await walletWithLiveRequest();
    notDerived.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
        request_response: notDerived.receiptFor(foreign, { charge: 25_000, nextAnchor: '0x4242' }) });
    const withheld = await notDerived.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(withheld.decision.rule, 'E3.forced');
});

test('S1–S6: a signed successor at a non-derived anchor is archived invalid_successor and treated as withheld', async () => {
    const h = await walletWithLiveRequest();
    h.worker.deriveAnchors = true;
    const journal = (await saved()).journal;
    h.server.requests = () => ({ status: 'ok', request_response: h.receiptFor(journal, { nextAnchor: '0x4242' }) });
    await assert.rejects(h.runtime.installRecoveredResponse(journal.client_request_id), { code: 'invalid_successor' });
    const [record] = await records();
    assert.equal(record.disposition, 'invalid_successor');
    assert.equal(record.invalidCheck, 'S4');
    assert.equal(record.compacted, true, 'its private rerandomization is dropped');
    const after = await saved();
    assert.equal(after.state.current_anchor, GENESIS_ANCHOR, 'the state stays');
    assert.equal(after.journal, null);
    // The server finalized this state's nullifier: no new request from it.
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'invalid_successor' });
    // Exactly like a withheld successor (E3): an unresolved state.
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'request_settlement_pending' });

    // A successor at the derived anchor installs and resets the bound.
    const ok = await walletWithLiveRequest();
    ok.worker.deriveAnchors = true;
    const live = (await saved()).journal;
    ok.server.requests = () => ({ status: 'ok', request_response: ok.receiptFor(live, { nextAnchor: derivedAnchor(live.nullifier) }) });
    assert.equal(await ok.runtime.installRecoveredResponse(live.client_request_id), true);
    const next = (await saved()).state;
    assert.equal(next.current_anchor, derivedAnchor(live.nullifier));
    assert.equal(next.bound_at_state, 0);
    assert.equal((await saved()).stateSeq, 1);
});

test('E4.3: a successor that installs before any release moves the exit to the new state', async () => {
    const h = await walletWithLiveRequest();
    const journal = (await saved()).journal;
    let reads = 0;
    h.server.requests = () => {
        reads += 1;
        if (reads < 2) throw new HttpError('Not found', 404, 'not_found');
        return { status: 'ok', request_response: h.receiptFor(journal) };
    };
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor('0x9999'), 'the escape is from the new state');
    assert.equal(plan.public_inputs.conceded, 0, 'the new state is fresh');
    const lock = (await saved()).exitLock;
    assert.equal(lock.anchor, '0x9999');
    assert.deepEqual(lock.released.map(entry => entry.kind), [0]);
    assert.equal(proofsOf(h, 'escape').length, 1, 'nothing was proved at the old state');
});

test('E4.6 and E6: a successor after a release is archived, and installs once the released proof is dead', async () => {
    const h = await walletWithLiveRequest();
    const journal = (await saved()).journal;
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
    // The receipt arrives just before broadcast (E4.6).
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(journal) });
    const check = await h.runtime.exitBeforeBroadcast();
    assert.deepEqual(check, { checked: true, lateSuccessor: true });
    const [late] = await records();
    assert.equal(late.disposition, 'late_successor');
    assert.ok(late.lateResponse && late.journal.user_rerandomization, 'it keeps what an install needs');
    assert.equal((await saved()).state.current_anchor, GENESIS_ANCHOR, 'not installed while the proof can land');

    // The lock holds until valid_until + 900 at a finalized block.
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'exit_locked' });
    h.chain.finalizedTimestamp = plan.public_inputs.valid_until + 900;
    await assert.rejects(h.runtime.cancelExit(), error => error.code === 'exit_locked'
        && error.data.releasable_after === plan.public_inputs.valid_until + 900);
    h.chain.noteStatus = 'pending_withdrawal';
    h.chain.finalizedTimestamp = plan.public_inputs.valid_until + 901;
    await assert.rejects(h.runtime.cancelExit(), { code: 'exit_locked' });
    h.chain.noteStatus = 'active';
    const released = await h.runtime.cancelExit();
    assert.equal(released.released, true);
    assert.equal(released.installed, true);
    const after = await saved();
    assert.equal(after.exitLock, null);
    assert.equal(after.preparedWithdrawal, null);
    assert.equal(after.state.current_anchor, '0x9999', 'S1–S6 passed again and it installed');
    assert.equal(after.state.current_balance, 5_000_000 - 25_000);
    assert.equal((await records()).find(record => record.clientRequestId === journal.client_request_id).disposition, 'installed');
    // Requests resume from the new state.
    h.server.leasePost = body => h.activeLease(body);
    await h.runtime.issueLease('chat');
});

test('E6: a cancel releases a lock at once only while no escape or close proof was released', async () => {
    const h = await walletWithResolvedRequest();
    h.server.clearance = () => { throw new HttpError('The nullifier is used.', 409, 'nullifier_used'); };
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'request_settlement_pending' });
    const released = await h.runtime.cancelExit();
    assert.equal(released.reason, 'cancelled');
    const after = await saved();
    assert.equal(after.exitLock, null);
    // C5: the ownership proof was sent, so the state stays withdrawal-only.
    assert.equal(after.preparedWithdrawal.clearanceReserved, true);
    await assert.rejects(h.runtime.issueLease('chat'), /Finish the prepared withdrawal/);

    // A failed attempt that released nothing leaves no lock behind.
    const failed = await freshWallet();
    failed.worker.failWithdrawal = new Error('proving failed');
    await assert.rejects(failed.runtime.prepareWithdrawal('escape', DESTINATION), /proving failed/);
    assert.equal((await saved()).exitLock, null);
});

test('E4.2: verified evidence at N⁺ refuses with device_not_newest; anything else is ignored', async () => {
    const evidence = state => ({ public_inputs: { request_nullifier: successorFor(state.current_anchor) },
        proof: { backend: 'groth16_bn254', proof: 'cHJvb2Y=' } });
    const h = await freshWallet();
    h.server.evidence = () => evidence(noteState());
    h.worker.verify = payload => payload.proof === 'cHJvb2Y=';
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), { code: 'device_not_newest' });
    assert.equal(proofsOf(h, 'escape').length, 0);
    assert.equal(h.workerOperations('verifyRequest')[0].payload.verifyingKey, h.runtime.config.verifying_keys?.request);
    assert.equal((await saved()).exitLock, null, 'nothing was released');

    for (const [label, change] of [
        ['an answer that does not verify', other => { other.worker.verify = () => false; }],
        ['evidence for another nullifier', other => {
            other.server.evidence = () => ({ ...evidence(noteState()), public_inputs: { request_nullifier: '0x99' } });
            other.worker.verify = () => true;
        }],
        ['a failing server', other => { other.server.evidence = () => { throw new HttpError('down', 503, 'unavailable'); }; }],
        ['no evidence', () => {}]
    ]) {
        const other = await freshWallet();
        other.server.evidence = () => evidence(noteState());
        change(other);
        const plan = await other.runtime.prepareWithdrawal('escape', DESTINATION);
        assert.equal(plan.mode, 'escape', label);
    }
});

test('E4.1: an exit uses the deposit-time path, then the indexer checked against the vault, then the vault logs', async () => {
    const saved1 = await freshWallet({}, noteState({ deposit_path: depositPath('0x51') }));
    saved1.runtime.treePath = () => assert.fail('no indexer with a saved deposit path');
    const fromDeposit = await saved1.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(fromDeposit.pathSource, 'deposit');
    assert.equal(fromDeposit.public_inputs.active_root, '0x51');

    const indexed = await freshWallet();
    const fromIndexer = await indexed.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(fromIndexer.pathSource, 'indexer');
    assert.equal(fromIndexer.public_inputs.active_root, indexed.chain.root);

    // An indexer that lies about the root (or is down) gives way to the
    // vault's own logs, from the user's exit RPC when one is set.
    for (const exitRpc of [false, true]) {
        const rebuilt = await freshWallet();
        rebuilt.runtime.treePath = async () => ({ active_root: '0xbad', note_id: 7, siblings: [] });
        const calls = [];
        const rpc = source => async ({ method, params }) => {
            calls.push([source, method]);
            if (method === 'eth_chainId') return '0xaa36a7';
            if (method === 'eth_getBlockByNumber') return { number: '0x64' };
            assert.equal(method, 'eth_getLogs');
            return [{ address: VAULT, blockNumber: '0x10', logIndex: '0x0', removed: false,
                topics: [ABI.noteDeposited, `0x${'0'.repeat(63)}7`, `0x${'ab'.repeat(32)}`],
                data: `0x${[5_000_000, 2_000_000_000, 0x6161].map(value => BigInt(value).toString(16).padStart(64, '0')).join('')}` }];
        };
        rebuilt.runtime.pinnedRpc = () => rpc('pinned');
        if (exitRpc) rebuilt.runtime.exitRpc = () => rpc('exit');
        const plan = await rebuilt.runtime.prepareWithdrawal('escape', DESTINATION);
        assert.equal(plan.pathSource, 'rebuild');
        assert.equal(rebuilt.worker.rebuilds, 1);
        const rebuildCalls = calls.filter(([, method]) => ['eth_getLogs', 'eth_getBlockByNumber'].includes(method));
        assert.ok(rebuildCalls.length >= 2);
        assert.ok(rebuildCalls.every(([source]) => source === (exitRpc ? 'exit' : 'pinned')));
        assert.equal(BigInt(plan.public_inputs.active_root), 0x6161n);
    }
});

test('the deposit-time path is saved only when it leads to the root the deposit set (Amendment A1)', async () => {
    for (const matches of [true, false]) {
        indexedDB.clear();
        const h = createHarness(BrowserWalletRuntime);
        const pending = { operationId: 'deposit', phase: 'submitted', amount: 5_000_000, secret: '0x51',
            commitment: '0x52', next_note_id: 7, zero_path: Array.from({ length: 32 }, (_, index) => `0x${index}`),
            transactionHash: `0x${'aa'.repeat(32)}` };
        await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state: null, pendingDeposit: pending });
        await h.runtime.reload();
        h.worker.pathMatches = payload => {
            assert.equal(payload.path.active_root, `0x${'0'.repeat(60)}6161`);
            return matches;
        };
        const call = h.runtime.worker.call;
        h.runtime.worker.call = async (operation, payload) => operation === 'confirmDeposit'
            ? noteState({ note_id: 7 })
            : call(operation, payload);
        await h.runtime.confirmDeposit({ operationId: 'deposit', secret: '0x51', note_id: 7, amount: 5_000_000,
            commitment: '0x52', expiry_ts: 2_000_000_000, deposit_root: '0x6161' });
        const state = (await saved()).state;
        assert.equal(Boolean(state.deposit_path), matches);
        if (matches) assert.deepEqual(state.deposit_path.siblings, pending.zero_path);
        assert.equal((await saved()).stateSeq, 1);
        // Request proofs keep it through the WebAssembly's state.
        if (matches) {
            h.server.leasePost = body => h.activeLease(body);
            await h.runtime.issueLease('chat');
            assert.deepEqual((await saved()).state.deposit_path, state.deposit_path);
        }
    }
});

test('E7: the exit kit holds the state an escape needs and goes out of date after an install', async () => {
    const h = await walletWithLiveRequest({}, noteState({ secret_s: '0x5ec', deposit_path: depositPath('0x51') }));
    h.runtime.browserConfig.trusted_deployment = { ...h.runtime.browserConfig.trusted_deployment, deployment_id: 'kit-test' };
    const kit = await h.runtime.exportExitKit({ passphrase: 'correct horse battery' });
    const payload = await openExitKit(kit, 'correct horse battery');
    assert.equal(payload.format, 'zkapi-exit-kit-v1');
    assert.equal(payload.trusted_deployment.deployment_id, 'kit-test');
    assert.equal(payload.note.note_id, 7);
    assert.equal(payload.bound_at_state, String(BOUND));
    assert.deepEqual(payload.merkle_path, depositPath('0x51'));
    assert.equal(h.runtime.snapshot().config.exit.exit_kit.out_of_date, false);
    // An install makes the kit stale.
    const journal = (await saved()).journal;
    h.server.requests = () => ({ status: 'ok', request_response: h.receiptFor(journal) });
    await h.runtime.installRecoveredResponse(journal.client_request_id);
    assert.deepEqual(h.runtime.snapshot().config.exit.exit_kit, { state_seq: 1, exported_seq: 0, out_of_date: true });
    await assert.rejects(h.runtime.exportExitKit({ passphrase: 'short' }), { code: 'exit_kit_passphrase_weak' });
});
