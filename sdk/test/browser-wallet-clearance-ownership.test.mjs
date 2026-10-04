import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DEPLOYMENT, DESTINATION, GENESIS_ANCHOR, VAULT, HttpError,
    createHarness, destinationBytes, memoryIndexedDb, noteState, nullifierFor, selectorOf
} from './helpers/request-archive-harness.mjs';

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };

const store = await import('../services/browserWalletStore.js');
const { BrowserWalletRuntime, default: sharedRuntime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { contractEstimateError } = await import('../services/zkapiContractError.mjs');

const RECORD_ID = `${DEPLOYMENT}:11155111:${VAULT}:7`;
const SIGNATURE = Object.freeze({ r: '0x51', s: '0x52' });
const records = () => store.listBrowserRequestArchive(DEPLOYMENT);
const clearanceFor = body => ({ status: 'ok', withdrawal_nullifier: body.withdrawal_nullifier, signature: { ...SIGNATURE } });

async function freshWallet(options = {}, state = noteState()) {
    indexedDB.clear();
    const harness = createHarness(BrowserWalletRuntime, options);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    await harness.runtime.reload();
    return harness;
}

async function discardFirstRequest(h) {
    h.server.leasePost = () => {
        h.chain.root = '0x78';
        throw new HttpError('The proof root is stale.', 409, 'stale_root');
    };
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'stale_root' });
    return (await records())[0];
}

const escapeProofs = h => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === 'escape');
const mutualProofs = h => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === 'mutual');
const clearancePosts = h => h.serverCalls('POST', '/v2/withdraw/clearance');

test('mutual clearance sends an escape-form ownership proof for the same nullifier and destination', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' });
    let markerBeforeProof = 'not observed';
    const call = h.runtime.worker.call;
    h.runtime.worker.call = async (operation, payload) => {
        if (operation === 'prepareWithdrawal' && payload.args.mode === 'escape') {
            markerBeforeProof = (await store.readBrowserWallet()).preparedWithdrawal;
        }
        return call(operation, payload);
    };
    let atPost = null;
    h.server.clearance = async body => {
        atPost = { body, saved: await store.readBrowserWallet(), proofs: h.workerOperations('prepareWithdrawal').length };
        return clearanceFor(body);
    };
    const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);

    const [ownership] = escapeProofs(h);
    assert.equal(ownership.payload.args.clearance, null);
    assert.equal(ownership.payload.args.destination, DESTINATION, 'the ownership proof pays the real destination');
    assert.equal(markerBeforeProof, null, 'local proving precedes the withdrawal-only marker');
    const { body, saved } = atPost;
    assert.deepEqual(Object.keys(body).sort(), ['ownership_proof', 'withdrawal_nullifier']);
    assert.equal(body.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
    assert.deepEqual(Object.keys(body.ownership_proof).sort(), ['proof', 'public_inputs']);
    assert.equal(body.ownership_proof.public_inputs.has_clearance, false);
    assert.equal(body.ownership_proof.public_inputs.withdrawal_nullifier, body.withdrawal_nullifier);
    assert.deepEqual(body.ownership_proof.public_inputs.destination, destinationBytes(DESTINATION));
    assert.equal(body.ownership_proof.public_inputs.final_balance, 5_000_000);
    assert.equal(body.ownership_proof.proof.backend, 'groth16_bn254');
    assert.equal(atPost.proofs, 1, 'only the ownership proof exists when the server is asked');
    assert.equal(saved.preparedWithdrawal.phase, 'reserving', 'the marker is durable before the reservation');

    const [mutual] = mutualProofs(h);
    assert.deepEqual(mutual.payload.args.clearance, clearanceFor(body));
    assert.equal(plan.mode, 'mutual');
    assert.deepEqual(plan.clearance, clearanceFor(body));
    const persisted = await store.readBrowserWallet();
    assert.deepEqual(persisted.preparedWithdrawal.clearance, plan.clearance);
    assert.equal(JSON.stringify(persisted).includes(body.ownership_proof.proof.proof), false,
        'the ownership proof itself is never persisted');
});

test('a local ownership-proof failure never makes the note withdrawal-only', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' });
    h.worker.failWithdrawal = new Error('proof generation failed');
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), /proof generation failed/);
    assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null);
    assert.equal(clearancePosts(h).length, 0);
});

test('a mismatched ownership proof fails closed before any server reservation', async () => {
    const other = `0x${'56'.repeat(20)}`;
    for (const change of [{ chain_id: 1 }, { contract_address: other }, { state_signing_key_x: '0x1' },
        { clearance_signing_key_y: '0x1' }, { withdrawal_nullifier: '0x1' }, { note_id: 8 },
        { active_root: '0x1' }, { final_balance: 1 }, { destination: destinationBytes(other) },
        { has_clearance: true }, { protocol_version: 1 }, { request_nullifier: '0x1' },
        { authorization_tag: '0x1' }]) {
        const h = await freshWallet({ vaultRevision: 2 });
        h.worker.mutate = plan => { if (plan.mode === 'escape') Object.assign(plan.public_inputs, change); };
        h.server.clearance = body => clearanceFor(body);
        await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), /does not match/);
        assert.equal(clearancePosts(h).length, 0);
        assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null);
    }
});

test('a request proof is never sent as an ownership proof', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    const archived = await discardFirstRequest(h);
    h.server.clearance = body => clearanceFor(body);
    await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    const [{ body }] = clearancePosts(h);
    for (const field of ['request_nullifier', 'authorization_tag', 'anonymous_commitment_x', 'solvency_bound', 'request_time']) {
        assert.equal(field in body.ownership_proof.public_inputs, false);
    }
    assert.notEqual(body.ownership_proof.proof.proof, archived.journal.prepared_request.proof.proof);
    assert.equal(body.ownership_proof.public_inputs.withdrawal_nullifier, archived.journal.nullifier);
});

test('an ownership proof is generated at a transmitted state only after the server reports it unknown or clearance-reserved', async () => {
    for (const capability of [{ vaultRevision: 2 }, { clearanceOwnershipProof: 'required' }, {}]) {
        const h = await freshWallet(capability);
        await discardFirstRequest(h);
        h.server.clearance = body => {
            if (!body.ownership_proof) throw new HttpError('An ownership proof is required.', 400, 'clearance_ownership_required');
            return clearanceFor(body);
        };
        for (const [reply, code] of [
            [() => ({ status: 'ok', nullifier_status: 'reserved' }), 'request_settlement_pending'],
            [() => { throw new Error('network down'); }, 'transmitted_anchor_unconfirmed']
        ]) {
            h.server.nullifier = reply;
            await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), { code });
            assert.equal(escapeProofs(h).length, 0, 'no ownership proof is generated');
            assert.ok(clearancePosts(h).every(call => !call.body.ownership_proof));
        }
        await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), preparedWithdrawal: null });
        await h.runtime.reload();
        h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'clearance_reserved' });
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'mutual');
        assert.equal(escapeProofs(h).length, 1);
        assert.ok(clearancePosts(h).at(-1).body.ownership_proof);
    }
});

test('a legacy server is asked without a proof first and with one exactly once on clearance_ownership_required', async () => {
    const h = await freshWallet();
    h.server.clearance = body => {
        if (!body.ownership_proof) throw new HttpError('An ownership proof is required.', 400, 'clearance_ownership_required');
        return clearanceFor(body);
    };
    const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    const posts = clearancePosts(h);
    assert.equal(posts.length, 2);
    assert.deepEqual(posts[0].body, { withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) });
    assert.equal(posts[1].body.ownership_proof.public_inputs.has_clearance, false);
    assert.deepEqual(plan.clearance, clearanceFor(posts[1].body));

    const legacy = await freshWallet();
    legacy.server.clearance = body => clearanceFor(body);
    await legacy.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.deepEqual(clearancePosts(legacy).map(call => call.body), [{ withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }]);
    assert.equal(escapeProofs(legacy).length, 0, 'an accepting legacy server never receives a submittable escape');

    const refusing = await freshWallet();
    refusing.server.clearance = () => { throw new HttpError('An ownership proof is required.', 400, 'clearance_ownership_required'); };
    await assert.rejects(refusing.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'clearance_ownership_required' });
    assert.equal(clearancePosts(refusing).length, 2, 'the proof is sent once, never in a loop');
});

// An upgraded server refuses a proof-less request without reserving anything
// when it requires a proof or when its shared legacy budget is spent.
const proofOnlyServer = (h, status = 400, code = 'clearance_ownership_required') => {
    h.server.clearance = body => {
        if (!body.ownership_proof) throw new HttpError('Nothing was reserved.', status, code, { retriable: status === 503 });
        return clearanceFor(body);
    };
};
const LEGACY_REFUSALS = [[400, 'clearance_ownership_required'], [503, 'legacy_clearance_capacity']];

test('a legacy profile answers a spent legacy-clearance budget with its ownership proof', async () => {
    const h = await freshWallet();
    const sleeps = [];
    h.runtime.postClearance = (body, nullifier, signal) => BrowserWalletRuntime.prototype.postClearance.call(
        h.runtime, body, nullifier, signal, { delays: [1, 2, 4, 8], sleep: async milliseconds => { sleeps.push(milliseconds); } });
    let markerWhileProving = 'not observed';
    const call = h.runtime.worker.call;
    h.runtime.worker.call = async (operation, payload) => {
        if (operation === 'prepareWithdrawal' && payload.args.mode === 'escape') {
            markerWhileProving = (await store.readBrowserWallet()).preparedWithdrawal;
        }
        return call(operation, payload);
    };
    const markersAtPost = [];
    proofOnlyServer(h, 503, 'legacy_clearance_capacity');
    const answer = h.server.clearance;
    h.server.clearance = async body => {
        markersAtPost.push((await store.readBrowserWallet()).preparedWithdrawal?.phase ?? null);
        return answer(body);
    };
    const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);

    const posts = clearancePosts(h);
    assert.deepEqual(posts.map(post => Boolean(post.body.ownership_proof)), [false, true]);
    assert.deepEqual(sleeps, [], 'the proof-less body is never retried into a spent budget');
    assert.deepEqual(markersAtPost, ['reserving', 'reserving'], 'the marker is durable before every request that may reserve');
    assert.equal(markerWhileProving, null, 'the note stays usable while its ownership proof is generated');
    const { body } = posts[1];
    assert.equal(body.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
    assert.equal(body.ownership_proof.public_inputs.has_clearance, false);
    assert.deepEqual(body.ownership_proof.public_inputs.destination, destinationBytes(DESTINATION));
    assert.equal(plan.mode, 'mutual');
    assert.deepEqual(plan.clearance, clearanceFor(body));

    // Saturated verification is still retried with the same proof-less body.
    const saturated = await freshWallet();
    const delays = [];
    saturated.runtime.postClearance = (body, nullifier, signal) => BrowserWalletRuntime.prototype.postClearance.call(
        saturated.runtime, body, nullifier, signal, { delays: [1, 2, 4, 8], sleep: async milliseconds => { delays.push(milliseconds); } });
    let attempts = 0;
    saturated.server.clearance = body => {
        attempts += 1;
        if (attempts === 1) throw new HttpError('Verification is saturated.', 503, 'capacity_exhausted');
        return clearanceFor(body);
    };
    await saturated.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.deepEqual(clearancePosts(saturated).map(post => post.body), [
        { withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }, { withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }]);
    assert.deepEqual(delays, [1]);
    assert.equal(escapeProofs(saturated).length, 0);
});

test('a local ownership-proof failure never makes the note withdrawal-only on a legacy profile either', async () => {
    for (const [status, code] of LEGACY_REFUSALS) {
        const h = await freshWallet();
        proofOnlyServer(h, status, code);
        h.worker.failWithdrawal = new Error('proof generation failed');
        await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), /proof generation failed/);
        assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null, code);
        assert.deepEqual(clearancePosts(h).map(post => Boolean(post.body.ownership_proof)), [false], code);

        // A retry with a working prover completes the close.
        h.worker.failWithdrawal = null;
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'mutual', code);
        assert.deepEqual(clearancePosts(h).map(post => Boolean(post.body.ownership_proof)), [false, false, true], code);
    }
});

test('after a refused proof-less clearance a proving failure leaves inference available', async () => {
    const h = await freshWallet();
    proofOnlyServer(h);
    h.worker.failWithdrawal = new Error('out of memory');
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), /out of memory/);
    assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null);
    h.worker.failWithdrawal = null;
    const request = await h.runtime.prepareLeaseRequest(() => {});
    assert.equal(request.public_inputs.request_nullifier, nullifierFor(GENESIS_ANCHOR));
    assert.equal((await store.readBrowserWallet()).journal.client_request_id, request.client_request_id);
});

test('after a refused proof-less clearance a gate refusal leaves the note usable', async () => {
    const h = await freshWallet();
    await discardFirstRequest(h);
    proofOnlyServer(h);
    h.server.nullifier = () => { throw new Error('network down'); };
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'transmitted_anchor_unconfirmed' });
    assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null, 'not withdrawal-only');
    assert.equal(escapeProofs(h).length, 0, 'no ownership proof for an unconfirmed transmitted state');
    assert.ok(clearancePosts(h).every(post => !post.body.ownership_proof));
    const request = await h.runtime.prepareLeaseRequest(() => {});
    assert.equal(request.public_inputs.request_nullifier, nullifierFor(GENESIS_ANCHOR));

    // A settling request still gates inference, but not the withdrawal marker.
    const settling = await freshWallet();
    await discardFirstRequest(settling);
    proofOnlyServer(settling);
    settling.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
    await assert.rejects(settling.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'request_settlement_pending' });
    assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null, 'not withdrawal-only');
    assert.equal(escapeProofs(settling).length, 0);
    await assert.rejects(settling.runtime.prepareLeaseRequest(() => {}), { code: 'request_settlement_pending' });
});

test('a refused proof-less clearance restores, never drops, an earlier attempt’s marker', async () => {
    const h = await freshWallet();
    // An earlier proof-carrying request may have reserved before its answer was lost.
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), preparedWithdrawal: {
        phase: 'reserving', mode: 'mutual', operationId: 'earlier', noteId: 7, destination: DESTINATION,
        withdrawalNullifier: nullifierFor(GENESIS_ANCHOR), clearanceReserved: true, createdAt: 1 } });
    await h.runtime.reload();
    const earlier = (await store.readBrowserWallet()).preparedWithdrawal;
    proofOnlyServer(h);
    h.worker.failWithdrawal = new Error('proof generation failed');
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), /proof generation failed/);
    assert.deepEqual((await store.readBrowserWallet()).preparedWithdrawal, earlier);
    await assert.rejects(h.runtime.prepareLeaseRequest(() => {}), /Finish the prepared withdrawal/);
});

test('a legacy-profile background mutual answers a spent legacy-clearance budget with its ownership proof', async () => {
    const h = await freshWallet({}, noteState({ note_id: 8, current_anchor: '0x8888' }));
    const state = noteState();
    const nullifier = nullifierFor(state.current_anchor);
    await store.putBrowserWithdrawal({ recordId: RECORD_ID, deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT, noteId: 7, mode: 'mutual', destination: DESTINATION, phase: 'parked',
        clearanceReserved: true, state, finalBalance: state.current_balance, withdrawalNullifier: nullifier,
        preparedWithdrawal: { phase: 'reserving', mode: 'mutual', noteId: 7, operationId: 'old',
            destination: DESTINATION, clearanceReserved: true, withdrawalNullifier: nullifier } });
    await h.runtime.reload();
    proofOnlyServer(h, 503, 'legacy_clearance_capacity');
    const plan = await h.runtime.prepareBackgroundWithdrawal(RECORD_ID, { expectedActiveRoot: h.chain.root });
    const posts = clearancePosts(h);
    assert.deepEqual(posts.map(post => Boolean(post.body.ownership_proof)), [false, true]);
    assert.equal(posts[1].body.withdrawal_nullifier, nullifier);
    assert.equal(posts[1].body.ownership_proof.public_inputs.note_id, 7);
    assert.equal(plan.public_inputs.has_clearance, true);
});

// A server with legacy clearance on reserves a proof-less request, so only an
// error code that says nothing was reserved may roll the marker back. A bare
// 5xx or a lost connection can follow the reservation.
const LOST_ANSWERS = [
    ['a network error', () => new TypeError('Failed to fetch')],
    ['a 502 without an error code', () => new HttpError('Bad gateway', 502, undefined)],
    ['a 503 without an error code', () => new HttpError('Service unavailable', 503, undefined)],
    ['a 504 without an error code', () => new HttpError('Gateway timeout', 504, undefined)],
    ['500 internal_error', () => new HttpError('The server failed.', 500, 'internal_error')]
];
const markerOf = async () => {
    const marker = (await store.readBrowserWallet()).preparedWithdrawal;
    return marker && { phase: marker.phase, mode: marker.mode, clearanceReserved: marker.clearanceReserved,
        withdrawalNullifier: marker.withdrawalNullifier };
};
const RESERVING = Object.freeze({ phase: 'reserving', mode: 'mutual', clearanceReserved: true,
    withdrawalNullifier: nullifierFor(GENESIS_ANCHOR) });

test('an answer lost after a proof-less clearance keeps the note withdrawal-only until the close completes', async () => {
    for (const [label, lostAnswer] of LOST_ANSWERS) {
        const h = await freshWallet();
        const failure = lostAnswer();
        const reserved = [];
        h.server.clearance = body => {
            // The server reserves first; only the first answer is lost.
            reserved.push(body.withdrawal_nullifier);
            if (reserved.length === 1) throw failure;
            return clearanceFor(body);
        };
        await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), error => error === failure, label);
        assert.deepEqual(clearancePosts(h).map(post => post.body),
            [{ withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }], `${label}: sent once, without a proof`);
        assert.equal(escapeProofs(h).length, 0, `${label}: no ownership proof after an answer that may have reserved`);
        assert.deepEqual(await markerOf(), RESERVING, `${label}: the server may hold the reservation`);
        await assert.rejects(h.runtime.prepareLeaseRequest(() => {}), /Finish the prepared withdrawal/, label);

        // The server signs its reservation again, so a retry completes the close.
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'mutual', label);
        const posts = clearancePosts(h);
        assert.deepEqual(posts.map(post => post.body), [
            { withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }, { withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }], label);
        assert.deepEqual(plan.clearance, clearanceFor(posts[1].body), label);
        assert.equal(escapeProofs(h).length, 0, label);
    }
});

test('an answer lost after the proof-carrying clearance keeps the note withdrawal-only on every profile', async () => {
    for (const [profile, refusal] of [[{ clearanceOwnershipProof: 'required' }, null], [{}, LEGACY_REFUSALS[0]], [{}, LEGACY_REFUSALS[1]]]) {
        const label = refusal ? `legacy profile after ${refusal[1]}` : 'declared capability';
        const h = await freshWallet(profile);
        const failure = new TypeError('Failed to fetch');
        let proofAnswers = 0;
        h.server.clearance = body => {
            if (!body.ownership_proof) {
                if (!refusal) throw new Error('a declared capability never sends a proof-less clearance');
                throw new HttpError('Nothing was reserved.', refusal[0], refusal[1], { retriable: refusal[0] === 503 });
            }
            // The proof verified and the server reserved; only the first answer is lost.
            proofAnswers += 1;
            if (proofAnswers === 1) throw failure;
            return clearanceFor(body);
        };
        const phasesWhileProving = [];
        const call = h.runtime.worker.call;
        h.runtime.worker.call = async (operation, payload) => {
            if (operation === 'prepareWithdrawal' && payload.args.mode === 'escape') {
                phasesWhileProving.push((await store.readBrowserWallet()).preparedWithdrawal?.phase ?? null);
            }
            return call(operation, payload);
        };
        await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), error => error === failure, label);
        assert.deepEqual(clearancePosts(h).map(post => Boolean(post.body.ownership_proof)), refusal ? [false, true] : [true], label);
        assert.deepEqual(await markerOf(), RESERVING, `${label}: the server may hold the reservation`);
        await assert.rejects(h.runtime.prepareLeaseRequest(() => {}), /Finish the prepared withdrawal/, label);

        // The earlier proof may have reserved, so on the retry the note stays
        // withdrawal-only while proving, even after a refused proof-less request.
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'mutual', label);
        assert.deepEqual(phasesWhileProving, [null, 'reserving'], label);
        assert.deepEqual(clearancePosts(h).map(post => Boolean(post.body.ownership_proof)),
            refusal ? [false, true, false, true] : [true, true], label);
    }
});

test('a lagging clearance root retries the same ownership proof with backoff, then fails for the outer re-prove', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' });
    const sleeps = [];
    h.runtime.postClearance = (body, nullifier, signal) => BrowserWalletRuntime.prototype.postClearance.call(
        h.runtime, body, nullifier, signal, { delays: [1, 2, 4, 8], sleep: async milliseconds => { sleeps.push(milliseconds); } });
    let posts = 0;
    h.server.clearance = body => {
        posts += 1;
        if (posts === 1) throw new HttpError('Verification is saturated.', 503, 'capacity_exhausted');
        if (posts === 2) throw new HttpError('The ownership root is not known yet.', 409, 'stale_root', { latest_root: '0x76' });
        return clearanceFor(body);
    };
    await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    const bodies = clearancePosts(h).map(call => call.raw);
    assert.equal(bodies.length, 3);
    assert.ok(bodies.every(body => body === bodies[0]), 'the same proof is retried');
    assert.deepEqual(sleeps, [1, 2]);
    assert.equal(escapeProofs(h).length, 1);

    const stuck = await freshWallet({ clearanceOwnershipProof: 'required' });
    stuck.runtime.postClearance = (body, nullifier, signal) => BrowserWalletRuntime.prototype.postClearance.call(
        stuck.runtime, body, nullifier, signal, { delays: [1, 2, 4, 8], sleep: async () => {} });
    stuck.server.clearance = () => { throw new HttpError('The ownership root is not known yet.', 409, 'ownership_root_unknown'); };
    await assert.rejects(stuck.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'ownership_root_unknown' });
    assert.equal(clearancePosts(stuck).length, 5);
});

test('nullifier_used from the clearance endpoint is advisory and never becomes challenge evidence', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    h.server.clearance = () => { throw new HttpError('Nullifier already used.', 409, 'nullifier_used'); };
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'nullifier_used' });
    assert.deepEqual(await records(), []);
    h.server.calls.length = 0;
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), preparedWithdrawal: null });
    await h.runtime.reload();
    const escape = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(escape.mode, 'escape');
    assert.equal(h.server.calls.length, 0, 'the untransmitted state still escapes without the server');
});

test('a persisted clearance is reused without a second ownership proof or server request', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' });
    h.server.clearance = body => clearanceFor(body);
    const first = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    h.chain.root = '0x79';
    const second = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(second.public_inputs.active_root, '0x79');
    assert.deepEqual(second.clearance, first.clearance);
    const escape = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.deepEqual(escape.clearance, first.clearance, 'an escape carries the clearance for switching back');
    assert.equal(escapeProofs(h).at(-1).payload.args.clearance, null, 'the WASM never sees a clearance on an escape');
    const back = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(back.mode, 'mutual');
    assert.equal(clearancePosts(h).length, 1);
    assert.equal(escapeProofs(h).length, 2, 'one ownership proof and one real escape proof');

    const hardened = await freshWallet({ vaultRevision: 2 });
    hardened.server.clearance = body => clearanceFor(body);
    await hardened.runtime.prepareWithdrawal('mutual', DESTINATION);
    hardened.chain.root = '0x7a';
    const reproved = await hardened.runtime.prepareWithdrawal('mutual', DESTINATION, { reprove: true });
    assert.equal(reproved.public_inputs.active_root, '0x7a');
    assert.equal(clearancePosts(hardened).length, 1);
});

test('a persisted clearance is never reused after the note state changes', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' });
    const archived = await discardFirstRequest(h);
    h.server.clearance = body => clearanceFor(body);
    const first = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(first.clearance.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
        request_response: h.receiptFor(archived.journal) });
    const second = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(second.public_inputs.withdrawal_nullifier, nullifierFor('0x9999'));
    assert.equal(second.clearance.withdrawal_nullifier, nullifierFor('0x9999'));
    assert.equal(clearancePosts(h).at(-1).body.withdrawal_nullifier, nullifierFor('0x9999'));

    const stale = await freshWallet({ clearanceOwnershipProof: 'required' }, noteState({ current_anchor: '0x2222' }));
    const oldNullifier = nullifierFor(GENESIS_ANCHOR);
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), preparedWithdrawal: {
        phase: 'prepared', mode: 'mutual', operationId: 'legacy', noteId: 7, destination: DESTINATION,
        withdrawalNullifier: oldNullifier, clearanceReserved: true,
        clearance: { status: 'ok', withdrawal_nullifier: oldNullifier, signature: { ...SIGNATURE } } } });
    await stale.runtime.reload();
    stale.server.clearance = body => clearanceFor(body);
    const plan = await stale.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(clearancePosts(stale).length, 1, 'a clearance for an older state is ignored');
    assert.equal(plan.clearance.withdrawal_nullifier, nullifierFor('0x2222'));
});

test('background mutual sends the ownership proof and persists its clearance', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' }, noteState({ note_id: 8, current_anchor: '0x8888' }));
    const state = noteState();
    const nullifier = nullifierFor(state.current_anchor);
    await store.putBrowserWithdrawal({ recordId: RECORD_ID, deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT, noteId: 7, mode: 'mutual', destination: DESTINATION, phase: 'parked',
        clearanceReserved: true, state, finalBalance: state.current_balance, withdrawalNullifier: nullifier,
        preparedWithdrawal: { phase: 'reserving', mode: 'mutual', noteId: 7, operationId: 'old',
            destination: DESTINATION, clearanceReserved: true, withdrawalNullifier: nullifier } });
    await h.runtime.reload();
    h.server.clearance = body => clearanceFor(body);
    const plan = await h.runtime.prepareBackgroundWithdrawal(RECORD_ID, { expectedActiveRoot: h.chain.root });
    const [{ body }] = clearancePosts(h);
    assert.equal(body.withdrawal_nullifier, nullifier);
    assert.equal(body.ownership_proof.public_inputs.note_id, 7);
    assert.deepEqual(body.ownership_proof.public_inputs.destination, destinationBytes(DESTINATION));
    assert.equal(plan.public_inputs.has_clearance, true);
    const saved = (await store.listBrowserWithdrawals(DEPLOYMENT))[0];
    assert.deepEqual(saved.preparedWithdrawal.clearance, clearanceFor(body));
    assert.equal((await store.readBrowserWallet()).state.note_id, 8, 'the selected chat note is untouched');

    h.chain.root = '0x79';
    await h.runtime.prepareBackgroundWithdrawal(RECORD_ID, { expectedActiveRoot: '0x79' });
    assert.equal(clearancePosts(h).length, 1, 'the persisted clearance is reused');
    assert.equal(escapeProofs(h).length, 1);
    assert.equal(mutualProofs(h).length, 2);
});

test('a withdrawal proof is reused with refreshed siblings when a hardened vault root moved', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    const first = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    h.chain.root = '0x78';
    const refreshed = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(escapeProofs(h).length, 1, 'no new proof');
    assert.deepEqual(refreshed.proof, first.proof);
    assert.deepEqual(refreshed.public_inputs, first.public_inputs);
    assert.equal(refreshed.siblingsRoot, '0x78');
    assert.deepEqual(refreshed.siblings, (await h.runtime.treePath(7)).siblings);
    assert.deepEqual((await store.readBrowserWallet()).preparedWithdrawal.siblings, refreshed.siblings);
    assert.deepEqual(await h.runtime.prepareWithdrawal('escape', DESTINATION), refreshed);
    assert.equal(escapeProofs(h).length, 1);

    const reproved = await h.runtime.prepareWithdrawal('escape', DESTINATION, { reprove: true });
    assert.equal(escapeProofs(h).length, 2);
    assert.equal(reproved.public_inputs.active_root, '0x78');

    const strict = await freshWallet();
    await strict.runtime.prepareWithdrawal('escape', DESTINATION);
    strict.chain.root = '0x78';
    const strictPlan = await strict.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(escapeProofs(strict).length, 2, 'an older vault without root history always re-proves');
    assert.equal(strictPlan.public_inputs.active_root, '0x78');
});

test('withdrawal retries refresh siblings first, then re-prove after a repeated or explicit UnknownRoot rejection', async t => {
    const FROM = `0x${'11'.repeat(20)}`;
    const plan = { mode: 'escape', destination: DESTINATION, siblings: Array(32).fill('0x0'),
        proof: { backend: 'groth16_bn254', proof: Buffer.alloc(256).toString('base64') },
        public_inputs: { protocol_version: 2, chain_id: 11155111, contract_address: VAULT, active_root: '0x1',
            state_signing_key_x: '0x1', state_signing_key_y: '0x1', clearance_signing_key_x: '0x1',
            clearance_signing_key_y: '0x1', note_id: 7, final_balance: 5_000_000,
            destination: destinationBytes(DESTINATION), withdrawal_nullifier: '0x7', has_clearance: false,
            withdrawal_tag: '0x8' } };
    for (const [rejections, expected] of [
        [['stale_root', 'stale_root', 'stop'], [false, false, true]],
        [['unknown_root', 'stop'], [false, true]],
        [['stale_root', 'unknown_root', 'stale_root', 'stale_root'], [false, false, true, true]]
    ]) {
        const client = new ZkapiClient();
        client.config = { funding: { chain_id: 11155111, contract_address: VAULT } };
        client.wallet = { has_note: true, note: { note_id: 7, current_balance: 5_000_000 } };
        for (const name of ['assertBalanceNotClaimed', 'settleActiveLease', 'refresh', 'rememberWithdrawal']) {
            t.mock.method(client, name, async () => {});
        }
        t.mock.method(client, 'connectWallet', async () => FROM);
        t.mock.method(client, 'readContractUint', async () => 1n);
        t.mock.method(client, 'recoverFailedWithdrawalSubmission', async () => null);
        const reproveFlags = [];
        t.mock.method(sharedRuntime, 'currentPreparedWithdrawal', async () => null);
        t.mock.method(sharedRuntime, 'prepareWithdrawal', async (mode, destination, options) => {
            reproveFlags.push(options.reprove);
            return structuredClone(plan);
        });
        t.mock.method(sharedRuntime, 'claimPreparedWithdrawalSubmission', async () => ({}));
        t.mock.method(sharedRuntime, 'markPreparedWithdrawalRetryable', async () => null);
        const queue = [...rejections];
        t.mock.method(client, 'sendContractTransaction', async () => {
            const code = queue.shift();
            throw Object.assign(new Error(code), { code, broadcastPossible: false });
        });
        await assert.rejects(client.performWithdrawal('escape', () => {}, { destination: DESTINATION }));
        assert.deepEqual(reproveFlags, expected);
        t.mock.restoreAll();
    }
});

test('vault errors decode from selectors computed from their signatures', () => {
    for (const [signature, code] of [['UnknownRoot()', 'unknown_root'], ['ChallengedNullifier()', 'challenged_nullifier'],
        ['InvalidDestination()', 'invalid_destination'], ['Paused()', 'vault_paused'], ['StaleRoot()', 'stale_root']]) {
        const error = contractEstimateError({ message: 'execution reverted', data: { originalError: { data: selectorOf(signature) } } });
        assert.equal(error.code, code, signature);
        assert.equal(error.selector, selectorOf(signature));
    }
    assert.match(contractEstimateError({ data: selectorOf('Paused()') }).message, /paused/i);
});

test('withdraw keys the escape override separately and prompts for the Sepolia password only when the gate needs it', async t => {
    const client = new ZkapiClient();
    client.config = { funding: { chain_id: 11155111, contract_address: VAULT } };
    client.wallet = { has_note: true, note: { note_id: 7 } };
    const ensured = [];
    t.mock.method(client, 'ensureTestnetAccess', async options => { ensured.push(options); });
    const calls = [];
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    t.mock.method(client, 'performWithdrawal', async (mode, onStatus, options) => {
        calls.push(options);
        if (calls.length === 1) {
            await gate;
            throw Object.assign(new Error('Enter the Sepolia password.'), { code: 'testnet_password_required', status: 401 });
        }
        return { status: 'pending_withdrawal' };
    });
    const override = client.withdraw('escape', () => {}, { destination: DESTINATION, overrideUnsettledRequest: true });
    await assert.rejects(client.withdraw('escape', () => {}, { destination: DESTINATION }), /already running/);
    release();
    assert.deepEqual(await override, { status: 'pending_withdrawal' });
    assert.deepEqual(ensured, [{ interactive: true }], 'the password prompt follows a refused status read');
    assert.deepEqual(calls.map(options => options.overrideUnsettledRequest), [true, true]);

    t.mock.method(client, 'performWithdrawal', async () => {
        throw Object.assign(new Error('pending'), { code: 'request_settlement_pending', data: { escape_override_after: 5 } });
    });
    await assert.rejects(client.withdraw('escape', () => {}, { destination: DESTINATION }), error =>
        /still settling/.test(error.shortMessage) && error.data.escape_override_after === 5);
});
