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
// Kind-2 ownership proofs: no destination, no concession, never submittable.
const ownershipProofs = h => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === 'ownership');
const NO_DESTINATION = Array(20).fill(0);
const mutualProofs = h => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === 'mutual');
const clearancePosts = h => h.serverCalls('POST', '/v2/withdraw/clearance');
const markerOf = async () => {
    const marker = (await store.readBrowserWallet()).preparedWithdrawal;
    return marker && { phase: marker.phase, mode: marker.mode, clearanceReserved: marker.clearanceReserved,
        withdrawalNullifier: marker.withdrawalNullifier };
};
const RESERVING = Object.freeze({ phase: 'reserving', mode: 'mutual', clearanceReserved: true,
    withdrawalNullifier: nullifierFor(GENESIS_ANCHOR) });

test('mutual clearance sends a kind-2 ownership proof for the same nullifier and no destination', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' });
    let markerBeforeProof = 'not observed';
    const call = h.runtime.worker.call;
    h.runtime.worker.call = async (operation, payload) => {
        if (operation === 'prepareWithdrawal' && payload.args.mode === 'ownership') {
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

    const [ownership] = ownershipProofs(h);
    assert.equal(ownership.payload.args.clearance, undefined);
    assert.equal(ownership.payload.args.destination, undefined, 'the ownership proof names no destination');
    assert.equal(ownership.payload.args.conceded, undefined);
    const validity = ownership.payload.args.valid_until - Math.floor(Date.now() / 1000);
    assert.ok(validity > 3_500 && validity <= 3_600, 'an ownership proof is valid for one hour');
    assert.equal(markerBeforeProof, null, 'local proving precedes the withdrawal-only marker');
    const { body, saved } = atPost;
    assert.deepEqual(Object.keys(body).sort(), ['ownership_proof', 'withdrawal_nullifier']);
    assert.equal(body.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
    assert.deepEqual(Object.keys(body.ownership_proof).sort(), ['proof', 'public_inputs']);
    assert.equal(body.ownership_proof.public_inputs.kind, 2);
    assert.equal(body.ownership_proof.public_inputs.withdrawal_nullifier, body.withdrawal_nullifier);
    assert.deepEqual(body.ownership_proof.public_inputs.destination, NO_DESTINATION);
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
        { kind: 0 }, { kind: 1 }, { conceded: 1 }, { next_nullifier: '0x5' }, { valid_until: 1 },
        { valid_until: Math.floor(Date.now() / 1000) + 7_200 }, { destination: destinationBytes(DESTINATION) },
        { protocol_version: 1 }, { request_nullifier: '0x1' },
        { authorization_tag: '0x1' }]) {
        const h = await freshWallet({ vaultRevision: 2 });
        h.worker.mutate = plan => { if (plan.mode === 'ownership') Object.assign(plan.public_inputs, change); };
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
        const strict = capability.vaultRevision !== 2;
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
            assert.equal(ownershipProofs(h).length, 0, 'no ownership proof is generated');
            assert.ok(clearancePosts(h).every(call => !call.body.ownership_proof));
            assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null, 'a refused gate leaves the note usable');
        }
        h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'clearance_reserved' });
        if (strict) {
            // A vault that burns a challenged nullifier: the ownership proof is
            // a submittable escape, so the state gets only a proof-less request.
            await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION),
                { code: 'transmitted_anchor_ownership_unsafe', status: 409 });
            assert.equal(ownershipProofs(h).length, 0, 'a strict vault never proves ownership at a transmitted state');
            assert.ok(clearancePosts(h).every(call => !call.body.ownership_proof));
            assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null, 'nothing was reserved');
            continue;
        }
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'mutual');
        assert.equal(ownershipProofs(h).length, 1);
        assert.ok(clearancePosts(h).at(-1).body.ownership_proof);
    }
});

// The gateway that withheld a lease POST at this state holds a request proof
// for its nullifier. On a vault whose challenge burns the nullifier, it could
// submit an ownership proof as an escape and challenge it with that request.
test('a strict vault answers a forged or honest proof requirement at a transmitted state with a refusal, never a proof', async () => {
    for (const profile of [{}, { clearanceOwnershipProof: 'optional' }, { clearanceOwnershipProof: 'required' }]) {
        for (const [status, code] of LEGACY_REFUSALS) {
            const label = `${JSON.stringify(profile)} after ${code}`;
            const h = await freshWallet(profile);
            await discardFirstRequest(h);
            proofOnlyServer(h, status, code);
            for (const reading of ['unknown', 'clearance_reserved']) {
                h.server.nullifier = () => reading === 'unknown'
                    ? { status: 'not_found', nullifier_status: 'unknown' }
                    : { status: 'ok', nullifier_status: 'clearance_reserved' };
                await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), error => {
                    assert.equal(error.code, 'transmitted_anchor_ownership_unsafe', label);
                    assert.equal(error.status, 409, label);
                    assert.equal(error.data.transmitted, true, label);
                    assert.equal(error.data.clearance_error_code, code, label);
                    return true;
                });
            }
            assert.equal(ownershipProofs(h).length, 0, `${label}: no escape-form proof exists`);
            assert.deepEqual(clearancePosts(h).map(post => post.body),
                [{ withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }, { withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }],
                `${label}: only proof-less requests leave the device`);
            assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null, `${label}: the marker is rolled back`);
            // The note is not withdrawal-only: a chat from this state that
            // settles moves it to a new state, which closes normally.
            const request = await h.runtime.prepareLeaseRequest(() => {});
            assert.equal(request.public_inputs.request_nullifier, nullifierFor(GENESIS_ANCHOR), label);
        }
    }

    // The background exit of a set-aside balance follows the same rule.
    const h = await freshWallet({ clearanceOwnershipProof: 'optional' });
    await discardFirstRequest(h);
    const state = noteState();
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()),
        state: noteState({ note_id: 8, current_anchor: '0x8888' }) });
    await store.putBrowserWithdrawal({ recordId: RECORD_ID, deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT, noteId: 7, mode: 'mutual', destination: DESTINATION, phase: 'parked',
        clearanceReserved: true, state, finalBalance: state.current_balance, withdrawalNullifier: nullifierFor(GENESIS_ANCHOR),
        preparedWithdrawal: { phase: 'reserving', mode: 'mutual', noteId: 7, operationId: 'old',
            destination: DESTINATION, clearanceReserved: true, withdrawalNullifier: nullifierFor(GENESIS_ANCHOR) } });
    await h.runtime.reload();
    proofOnlyServer(h, 503, 'legacy_clearance_capacity');
    await assert.rejects(h.runtime.prepareBackgroundWithdrawal(RECORD_ID, { expectedActiveRoot: h.chain.root }),
        { code: 'transmitted_anchor_ownership_unsafe' });
    assert.equal(ownershipProofs(h).length, 0);
    assert.ok(clearancePosts(h).every(post => !post.body.ownership_proof));

    // The prover itself refuses such a state, whoever asks.
    await assert.rejects(h.runtime.generateOwnershipProof({ state, destination: DESTINATION,
        nullifier: nullifierFor(GENESIS_ANCHOR), path: await h.runtime.treePath(7) }),
    { code: 'transmitted_anchor_ownership_unsafe' });
    assert.equal(ownershipProofs(h).length, 0);
});

test('a strict vault closes a transmitted state through a proof-less clearance the server grants', async () => {
    for (const profile of [{}, { clearanceOwnershipProof: 'optional' }, { clearanceOwnershipProof: 'required' }]) {
        const h = await freshWallet(profile);
        await discardFirstRequest(h);
        h.server.clearance = body => clearanceFor(body);
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'mutual');
        assert.deepEqual(clearancePosts(h).map(post => post.body), [{ withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }]);
        assert.equal(ownershipProofs(h).length, 0);
        assert.deepEqual(plan.clearance, clearanceFor({ withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }));
    }
});

test('a strict vault still proves ownership at a state that never left the device', async () => {
    for (const [profile, expected] of [[{}, [false, true]], [{ clearanceOwnershipProof: 'optional' }, [true]],
        [{ clearanceOwnershipProof: 'required' }, [true]]]) {
        for (const [status, code] of LEGACY_REFUSALS) {
            const h = await freshWallet(profile);
            proofOnlyServer(h, status, code);
            const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
            assert.equal(plan.mode, 'mutual');
            assert.deepEqual(clearancePosts(h).map(post => Boolean(post.body.ownership_proof)), expected,
                `${JSON.stringify(profile)} after ${code}`);
            assert.equal(ownershipProofs(h).length, 1);
            assert.equal(h.server.calls.filter(call => call.path.startsWith('/v2/nullifiers/')).length, 0,
                'an untransmitted state needs no server reading');
        }
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
    assert.equal(posts[1].body.ownership_proof.public_inputs.kind, 2);
    assert.deepEqual(plan.clearance, clearanceFor(posts[1].body));

    const legacy = await freshWallet();
    legacy.server.clearance = body => clearanceFor(body);
    await legacy.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.deepEqual(clearancePosts(legacy).map(call => call.body), [{ withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }]);
    assert.equal(ownershipProofs(legacy).length, 0, 'an accepting legacy server never receives a submittable escape');

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
        if (operation === 'prepareWithdrawal' && payload.args.mode === 'ownership') {
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
    assert.equal(body.ownership_proof.public_inputs.kind, 2);
    assert.deepEqual(body.ownership_proof.public_inputs.destination, NO_DESTINATION);
    assert.equal(plan.mode, 'mutual');
    assert.deepEqual(plan.clearance, clearanceFor(body));

    // capacity_exhausted comes only from proof verification, so a proof-less
    // body answered with it is not retried, and nothing says it reserved nothing.
    const saturated = await freshWallet();
    const delays = [];
    saturated.runtime.postClearance = (body, nullifier, signal) => BrowserWalletRuntime.prototype.postClearance.call(
        saturated.runtime, body, nullifier, signal, { delays: [1, 2, 4, 8], sleep: async milliseconds => { delays.push(milliseconds); } });
    saturated.server.clearance = () => { throw new HttpError('Verification is saturated.', 503, 'capacity_exhausted'); };
    await assert.rejects(saturated.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'capacity_exhausted' });
    assert.deepEqual(clearancePosts(saturated).map(post => post.body), [{ withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }]);
    assert.deepEqual(delays, []);
    assert.deepEqual(await markerOf(), RESERVING);
});

// The reference gateway's own answer to a throttled POST, before the API.
const gatewayThrottle = () => new HttpError('Too many requests from this network source; retry the same request later.',
    429, 'gateway_rate_limited', { retriable: true, retry_after_seconds: 5 });
const withRecordedBackoff = h => {
    const sleeps = [];
    h.runtime.postClearance = (body, nullifier, signal) => BrowserWalletRuntime.prototype.postClearance.call(
        h.runtime, body, nullifier, signal, { sleep: async milliseconds => { sleeps.push(milliseconds); } });
    return sleeps;
};

test('a gateway 429 on the clearance is retried with the same body after its retry-after delay', async () => {
    for (const [profile, proofs] of [[{}, false], [{ clearanceOwnershipProof: 'required' }, true], [{ vaultRevision: 2 }, true]]) {
        const label = JSON.stringify(profile);
        const h = await freshWallet(profile);
        const sleeps = withRecordedBackoff(h);
        const markers = [];
        let posts = 0;
        h.server.clearance = async body => {
            markers.push((await store.readBrowserWallet()).preparedWithdrawal?.phase ?? null);
            posts += 1;
            if (posts <= 2) throw gatewayThrottle();
            return clearanceFor(body);
        };
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'mutual', label);
        const bodies = clearancePosts(h).map(post => post.raw);
        assert.equal(bodies.length, 3, label);
        assert.ok(bodies.every(body => body === bodies[0]), `${label}: the identical body is retried`);
        assert.equal(Boolean(JSON.parse(bodies[0]).ownership_proof), proofs, label);
        assert.deepEqual(sleeps, [5_000, 5_000], `${label}: Retry-After outranks the shorter backoff`);
        assert.deepEqual(markers, ['reserving', 'reserving', 'reserving'], label);
        assert.equal(ownershipProofs(h).length, proofs ? 1 : 0, `${label}: one ownership proof at most`);
    }
});

test('a gateway 429 that outlasts the backoff budget restores the note only when no proof could be captured', async () => {
    // [profile, ownership proof sent, note usable afterwards]
    for (const [profile, proofs, usable] of [[{}, false, true], [{ clearanceOwnershipProof: 'required' }, true, false],
        [{ clearanceOwnershipProof: 'optional' }, true, false], [{ vaultRevision: 2 }, true, true]]) {
        const label = JSON.stringify(profile);
        const h = await freshWallet(profile);
        const sleeps = withRecordedBackoff(h);
        h.server.clearance = () => { throw gatewayThrottle(); };
        await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), error => {
            assert.equal(error.code, 'gateway_rate_limited', label);
            assert.equal(error.status, 429, label);
            assert.equal(error.data.retry_after_seconds, 5, label);
            assert.equal(error.data.withdrawal_only === true, !usable, label);
            return true;
        });
        // 5 + 5 + 5 seconds fill the 15 second budget; the fourth wait would not fit.
        assert.deepEqual(sleeps, [5_000, 5_000, 5_000], label);
        assert.equal(clearancePosts(h).length, 4, label);
        assert.ok(clearancePosts(h).every(post => Boolean(post.body.ownership_proof) === proofs), label);
        if (usable) {
            // Nothing that could be submitted left the device, or the vault
            // restores a challenged note: the marker is rolled back.
            assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null, `${label}: the marker is rolled back`);
            const request = await h.runtime.prepareLeaseRequest(() => {});
            assert.equal(request.public_inputs.request_nullifier, nullifierFor(GENESIS_ANCHOR), `${label}: chat is still available`);
            continue;
        }
        // Whoever answered the 429 may hold the ownership proof, a submittable
        // escape at this nullifier; this vault burns a nullifier whose escape a
        // request proof challenges. No request proof is made from this state.
        assert.deepEqual(await markerOf(), RESERVING, `${label}: the note stays withdrawal-only`);
        await assert.rejects(h.runtime.prepareLeaseRequest(() => {}), /Finish the prepared withdrawal/, label);
        assert.equal(h.workerOperations('prepareRequest').length, 0, `${label}: no request proof exists`);
        await assert.rejects(h.runtime.clearPreparedWithdrawal(), /must remain withdrawal-only/, label);
        // Closing again completes the close.
        h.server.clearance = body => clearanceFor(body);
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'mutual', label);
        assert.deepEqual(plan.clearance, clearanceFor(clearancePosts(h).at(-1).body), label);
    }

    // A retry-after longer than the whole budget is not waited out.
    const slow = await freshWallet();
    const sleeps = withRecordedBackoff(slow);
    slow.server.clearance = () => {
        throw new HttpError('Throttled.', 429, 'gateway_rate_limited', { retriable: true, retry_after_seconds: 60 });
    };
    await assert.rejects(slow.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'gateway_rate_limited' });
    assert.deepEqual(sleeps, []);
    assert.equal(clearancePosts(slow).length, 1);
    assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null);

    // An earlier attempt's marker may stand for a reservation: it is restored, never dropped.
    const earlier = await freshWallet();
    withRecordedBackoff(earlier);
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), preparedWithdrawal: {
        phase: 'reserving', mode: 'mutual', operationId: 'earlier', noteId: 7, destination: DESTINATION,
        withdrawalNullifier: nullifierFor(GENESIS_ANCHOR), clearanceReserved: true, createdAt: 1 } });
    await earlier.runtime.reload();
    const saved = (await store.readBrowserWallet()).preparedWithdrawal;
    earlier.server.clearance = () => { throw gatewayThrottle(); };
    await assert.rejects(earlier.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'gateway_rate_limited' });
    assert.deepEqual(clearancePosts(earlier).map(post => Boolean(post.body.ownership_proof)), [false, false, false, false]);
    assert.deepEqual((await store.readBrowserWallet()).preparedWithdrawal, saved);
});

// The gateway that answers 429 may also read the body: it holds the ownership
// proof of a mutual close (an escape at nullifier N to the real destination).
// If the note then sent a request proof at N, that gateway could submit the
// escape on a strict vault and challenge it with the request, which burns N.
test('a strict vault keeps the note withdrawal-only after a throttled proof that followed a refused proof-less request', async () => {
    for (const [status, code] of LEGACY_REFUSALS) {
        const label = `after ${code}`;
        const h = await freshWallet();
        withRecordedBackoff(h);
        const captured = [];
        h.server.clearance = body => {
            if (!body.ownership_proof) throw new HttpError('Nothing was reserved.', status, code, { retriable: status === 503 });
            captured.push(body.ownership_proof.public_inputs);
            throw new HttpError('Throttled.', 429, 'gateway_rate_limited', { retriable: true, retry_after_seconds: 60 });
        };
        await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), error =>
            error.code === 'gateway_rate_limited' && error.data.withdrawal_only === true, label);
        assert.deepEqual(clearancePosts(h).map(post => Boolean(post.body.ownership_proof)), [false, true], label);
        assert.equal(captured[0].kind, 2, label);
        assert.equal(captured[0].withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR), label);
        assert.deepEqual(await markerOf(), RESERVING, `${label}: the note stays withdrawal-only`);
        await assert.rejects(h.runtime.issueLease('chat'), /Finish the prepared withdrawal/, label);
        assert.equal(h.serverCalls('POST', '/v2/openrouter/leases').length + h.workerOperations('prepareRequest').length, 0,
            `${label}: no request proof at the captured nullifier`);

        // A refused proof-less request on the next attempt keeps that marker.
        await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'gateway_rate_limited' }, label);
        assert.deepEqual(await markerOf(), RESERVING, label);
        // Escaping from the untransmitted state stays available.
        const escape = await h.runtime.prepareWithdrawal('escape', DESTINATION);
        assert.equal(escape.mode, 'escape', label);
        assert.equal(escape.clearanceReserved, true, `${label}: the escape plan stays withdrawal-only`);
    }

    // A hardened vault recovers a challenged nullifier, so the note is restored.
    const hardened = await freshWallet({ vaultRevision: 2 });
    withRecordedBackoff(hardened);
    hardened.server.clearance = () => {
        throw new HttpError('Throttled.', 429, 'gateway_rate_limited', { retriable: true, retry_after_seconds: 60 });
    };
    await assert.rejects(hardened.runtime.prepareWithdrawal('mutual', DESTINATION), error =>
        error.code === 'gateway_rate_limited' && !error.data.withdrawal_only);
    assert.ok(clearancePosts(hardened).every(post => post.body.ownership_proof));
    assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null);
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
    assert.equal(ownershipProofs(h).length, 0, 'no ownership proof for an unconfirmed transmitted state');
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
    assert.equal(ownershipProofs(settling).length, 0);
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
    assert.equal(plan.public_inputs.kind, 1);
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
        assert.equal(ownershipProofs(h).length, 0, `${label}: no ownership proof after an answer that may have reserved`);
        assert.deepEqual(await markerOf(), RESERVING, `${label}: the server may hold the reservation`);
        await assert.rejects(h.runtime.prepareLeaseRequest(() => {}), /Finish the prepared withdrawal/, label);

        // The server signs its reservation again, so a retry completes the close.
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'mutual', label);
        const posts = clearancePosts(h);
        assert.deepEqual(posts.map(post => post.body), [
            { withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }, { withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR) }], label);
        assert.deepEqual(plan.clearance, clearanceFor(posts[1].body), label);
        assert.equal(ownershipProofs(h).length, 0, label);
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
            if (operation === 'prepareWithdrawal' && payload.args.mode === 'ownership') {
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

test('a lagging clearance root retries the same ownership proof with backoff, then fails the close', async () => {
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
    assert.equal(ownershipProofs(h).length, 1);

    const stuck = await freshWallet({ clearanceOwnershipProof: 'required' });
    stuck.runtime.postClearance = (body, nullifier, signal) => BrowserWalletRuntime.prototype.postClearance.call(
        stuck.runtime, body, nullifier, signal, { delays: [1, 2, 4, 8], sleep: async () => {} });
    // The server rejects a clearance root it does not know with stale_root.
    stuck.server.clearance = () => {
        throw new HttpError('The ownership root is not known yet.', 409, 'stale_root', { latest_root: '0x76' });
    };
    await assert.rejects(stuck.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'stale_root' });
    assert.equal(clearancePosts(stuck).length, 5);
    assert.equal(ownershipProofs(stuck).length, 1, 'the runtime never re-proves on its own');

    // Codes the server never sends for a clearance are not retried.
    const invented = await freshWallet({ clearanceOwnershipProof: 'required' });
    invented.runtime.postClearance = (body, nullifier, signal) => BrowserWalletRuntime.prototype.postClearance.call(
        invented.runtime, body, nullifier, signal, { delays: [1, 2, 4, 8], sleep: async () => {} });
    invented.server.clearance = () => { throw new HttpError('Unknown root.', 409, 'ownership_root_unknown'); };
    await assert.rejects(invented.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'ownership_root_unknown' });
    assert.equal(clearancePosts(invented).length, 1);
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
    // The vault accepts any root it ever held: the close proof is reused.
    assert.equal(second.public_inputs.active_root, first.public_inputs.active_root);
    assert.deepEqual(second.proof, first.proof);
    assert.deepEqual(second.clearance, first.clearance);
    const escape = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.deepEqual(escape.clearance, first.clearance, 'an escape carries the clearance for switching back');
    assert.equal(escapeProofs(h).at(-1).payload.args.clearance, null, 'the WASM never sees a clearance on an escape');
    assert.equal(escapeProofs(h).at(-1).payload.args.conceded, 0);
    const back = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(back.mode, 'mutual');
    assert.equal(clearancePosts(h).length, 1);
    assert.equal(ownershipProofs(h).length, 1, 'one ownership proof');
    assert.equal(escapeProofs(h).length, 1, 'and one real escape proof');

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
    assert.deepEqual(body.ownership_proof.public_inputs.destination, NO_DESTINATION);
    assert.equal(plan.public_inputs.kind, 1);
    const saved = (await store.listBrowserWithdrawals(DEPLOYMENT))[0];
    assert.deepEqual(saved.preparedWithdrawal.clearance, clearanceFor(body));
    assert.equal((await store.readBrowserWallet()).state.note_id, 8, 'the selected chat note is untouched');

    h.chain.root = '0x79';
    await h.runtime.prepareBackgroundWithdrawal(RECORD_ID, { expectedActiveRoot: '0x79' });
    assert.equal(clearancePosts(h).length, 1, 'the persisted clearance is reused');
    assert.equal(ownershipProofs(h).length, 1);
    assert.equal(mutualProofs(h).length, 2);
});

test('a withdrawal proof is reused at any root until near its valid_until', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    const first = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    const validity = first.public_inputs.valid_until - Math.floor(Date.now() / 1000);
    assert.ok(validity > 10_700 && validity <= 10_800, 'an exit proof is valid for three hours');
    assert.equal(first.public_inputs.kind, 0);
    assert.equal(first.siblings, undefined, 'exits carry no Merkle path');
    h.chain.root = '0x78';
    const reused = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(escapeProofs(h).length, 1, 'no new proof');
    assert.deepEqual(reused, first);

    const reproved = await h.runtime.prepareWithdrawal('escape', DESTINATION, { reprove: true });
    assert.equal(escapeProofs(h).length, 2);
    assert.equal(reproved.public_inputs.active_root, '0x78');

    // A proof close to its valid_until is never handed out again.
    const saved = await store.readBrowserWallet();
    await store.writeBrowserWallet({ ...saved, preparedWithdrawal: { ...saved.preparedWithdrawal,
        public_inputs: { ...saved.preparedWithdrawal.public_inputs, valid_until: Math.floor(Date.now() / 1000) + 600 } } });
    await h.runtime.reload();
    const fresh = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(escapeProofs(h).length, 3);
    assert.ok(fresh.public_inputs.valid_until > Math.floor(Date.now() / 1000) + 10_000);
});

test('withdrawal retries refresh siblings first, then re-prove after a repeated or explicit UnknownRoot rejection', async t => {
    const FROM = `0x${'11'.repeat(20)}`;
    const plan = { mode: 'escape', destination: DESTINATION, siblings: Array(32).fill('0x0'),
        proof: { backend: 'groth16_bn254', proof: Buffer.alloc(256).toString('base64') },
        public_inputs: { protocol_version: 2, chain_id: 11155111, contract_address: VAULT, active_root: '0x1',
            state_signing_key_x: '0x1', state_signing_key_y: '0x1', clearance_signing_key_x: '0x1',
            clearance_signing_key_y: '0x1', note_id: 7, final_balance: 5_000_000,
            destination: destinationBytes(DESTINATION), withdrawal_nullifier: '0x7', kind: 0,
            next_nullifier: '0x8', conceded: 0, valid_until: 4_000_000_000 } };
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

test('withdraw explains a refused transmitted-state close and a throttled clearance', async t => {
    const client = new ZkapiClient();
    client.config = { funding: { chain_id: 11155111, contract_address: VAULT } };
    client.wallet = { has_note: true, note: { note_id: 7 } };
    t.mock.method(client, 'ensureTestnetAccess', async () => {});
    for (const [code, data, pattern] of [['transmitted_anchor_ownership_unsafe', { transmitted: true }, /cannot be closed from this state/],
        ['gateway_rate_limited', { retry_after_seconds: 5 }, /Nothing was reserved/],
        ['gateway_rate_limited', { retry_after_seconds: 5, withdrawal_only: true }, /stays withdrawal-only/]]) {
        t.mock.method(client, 'performWithdrawal', async () => {
            throw Object.assign(new Error(code), { code, data });
        });
        await assert.rejects(client.withdraw('mutual', () => {}, { destination: DESTINATION }), error =>
            pattern.test(error.shortMessage) && error.code === code
            && (data.withdrawal_only ? !/Nothing was reserved/.test(error.shortMessage) : true));
    }
});
