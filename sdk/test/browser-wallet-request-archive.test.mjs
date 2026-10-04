import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { nativeFunding, nativeQuote } from './helpers/native-fixtures.mjs';
import {
    DEPLOYMENT, DESTINATION, GENESIS_ANCHOR, VAULT, HttpError,
    createHarness, keccak256Hex, memoryIndexedDb, noteState, nullifierFor, word
} from './helpers/request-archive-harness.mjs';

// Real store and runtime over a transactional IndexedDB; only the protocol
// server, the pinned vault RPC and the proof worker are observed fakes.
globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };

const store = await import('../services/browserWalletStore.js');
const archive = await import('../services/zkapiRequestArchive.mjs');
const { BrowserWalletRuntime, default: sharedRuntime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { default: walletCodec } = await import('../wallet.js');

const records = () => store.listBrowserRequestArchive(DEPLOYMENT);
const RECORD_ID = `${DEPLOYMENT}:11155111:${VAULT}:7`;

async function freshWallet(options = {}, state = noteState()) {
    indexedDB.clear();
    const harness = createHarness(BrowserWalletRuntime, options);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    await harness.runtime.reload();
    return harness;
}

function journalFor(state, clientRequestId, { requestTime = Math.floor(Date.now() / 1000), createdAt = Date.now() } = {}) {
    const nullifier = nullifierFor(state.current_anchor);
    const request = {
        client_request_id: clientRequestId,
        payload: JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: nativeQuote() }),
        payload_hash: '0xabc',
        public_inputs: { request_nullifier: nullifier, request_time: requestTime, solvency_bound: 1_000_000 },
        proof: { backend: 'groth16_bn254', proof: `request-proof-${clientRequestId}` }
    };
    return { exists: true, client_request_id: clientRequestId, nullifier, payload_hash: '0xabc',
        user_rerandomization: '0xfeed', created_at_ms: createdAt, prepared_request: request };
}

const pendingRecord = (state, clientRequestId, options = {}) => archive.buildRequestJournalRecord({
    deploymentId: DEPLOYMENT, state, journal: journalFor(state, clientRequestId), ...options
});

// A transmitted request whose stale_root the chain and the server both corroborate.
async function discardFirstRequest(h) {
    h.server.leasePost = () => {
        h.chain.root = '0x78';
        throw new HttpError('The proof root is stale.', 409, 'stale_root', { latest_root: '0x78' });
    };
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'stale_root' });
    const [record] = await records();
    assert.equal(record.disposition, 'discarded_stale_root');
    return record;
}

// The override warning for receipt_journal_missing: the claim, what a genuine
// claim costs and what a false one leaves.
function assertJournalMissingWarning(warning) {
    assert.match(warning, /^The server claims a finalized receipt for this balance that this wallet cannot apply\./);
    assert.match(warning, /If that claim is genuine, the escape will be challenged, its gas is lost and the note then needs the operator’s help\./);
    assert.match(warning, /If it is false, the escape is the only exit\.$/);
    assert.doesNotMatch(warning, /withdrawable/, 'it never promises that the funds stay withdrawable');
}

// A refusal offering the override in the receipt_journal_missing case: that
// case's warning, and the acknowledgement that alone lets the override proceed.
function assertJournalMissingRefusal(error, overrideAfter) {
    assert.equal(error.code, 'receipt_journal_missing');
    assert.equal(error.message, 'The server reports a finalized private request for this balance that this browser cannot apply.');
    assert.equal(error.data.nullifier_status, 'finalized');
    assert.equal(error.data.escape_override_after, overrideAfter, 'the override is offered after the grace');
    assertJournalMissingWarning(error.data.escape_override_warning);
    assert.equal(error.data.escape_override_acknowledgement, 'receipt_journal_missing');
}

const withoutRetryDelays = runtime => {
    runtime.recoverStaleRootRequest = (request, error, onProgress, signal) =>
        BrowserWalletRuntime.prototype.recoverStaleRootRequest.call(runtime, request, error, onProgress, signal,
            { delays: [1, 1], sleep: async () => {} });
};

test('prepared request journal and its archive record commit atomically before transmission', async () => {
    const h = await freshWallet();
    let atPost = null;
    h.server.leasePost = async body => {
        atPost = { saved: await store.readBrowserWallet(), archived: await records(), body };
        return h.activeLease(body);
    };
    const lease = await h.runtime.issueLease('chat');
    assert.ok(atPost, 'the lease request reached the server');
    const { saved, archived, body } = atPost;
    assert.equal(saved.journal.client_request_id, lease.client_request_id);
    assert.deepEqual(saved.journal.prepared_request, body);
    assert.equal(archived.length, 1);
    assert.equal(archived[0].type, 'request_journal');
    assert.equal(archived[0].disposition, 'pending');
    assert.equal(archived[0].source, 'prepared');
    assert.deepEqual(archived[0].journal, saved.journal);
    assert.equal(archived[0].anchor, archive.feltKey(GENESIS_ANCHOR));
    assert.equal(archived[0].nullifier, archive.feltKey(nullifierFor(GENESIS_ANCHOR)));
    assert.equal(archived[0].createdAt, saved.journal.created_at_ms);
    assert.equal('state' in archived[0], false, 'archive records never hold the note state or secret');
});

test('stale_root is not trusted without server corroboration', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    h.server.leasePost = () => {
        h.chain.root = '0x78';
        throw new HttpError('The proof root is stale.', 409, 'stale_root', { latest_root: '0x78' });
    };
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
    await assert.rejects(h.runtime.issueLease('chat'), error => error.code === 'stale_root'
        && error.journalRetained === true && error.nullifierStatus === 'reserved');
    const saved = await store.readBrowserWallet();
    assert.ok(saved.journal, 'an unsigned error string never discards the transmitted journal');
    const [record] = await records();
    assert.equal(record.disposition, 'pending');
    assert.deepEqual(archive.lastObservation(record), { ...archive.lastObservation(record), status: 'reserved', context: 'stale_root' });

    h.server.leaseStatus = () => ({ status: 'revoking' });
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), { code: 'lease_pending' });
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
    assert.ok((await store.readBrowserWallet()).journal);
});

test('corroborated stale_root discards the journal but never the archive; honest retry still works', async () => {
    const h = await freshWallet();
    const discarded = await discardFirstRequest(h);
    assert.equal((await store.readBrowserWallet()).journal, null);
    assert.equal(archive.lastObservation(discarded).status, 'unknown');
    assert.equal(archive.lastObservation(discarded).context, 'stale_root');
    assert.ok(discarded.journal.user_rerandomization, 'a discarded record keeps its rerandomization for a later receipt');
    assert.ok(h.chain.reads.includes('0xfdab463d'), 'the pinned vault root was read first');

    h.server.leasePost = body => h.activeLease(body);
    const lease = await h.runtime.issueLease('chat');
    assert.notEqual(lease.client_request_id, discarded.clientRequestId);
    const after = await records();
    assert.deepEqual(after.map(record => record.disposition).sort(), ['discarded_stale_root', 'pending']);
    assert.equal(new Set(after.map(record => record.anchor)).size, 1, 'the honest retry proves at the same note state');
});

test('a stale_root the pinned vault contradicts keeps the journal and retries the identical request', async () => {
    const h = await freshWallet();
    withoutRetryDelays(h.runtime);
    const bodies = [];
    h.server.leasePost = (body, raw) => {
        bodies.push(raw);
        if (bodies.length < 3) throw new HttpError('The proof root is stale.', 409, 'stale_root');
        return h.activeLease(body);
    };
    const lease = await h.runtime.issueLease('chat');
    assert.equal(bodies.length, 3);
    assert.ok(bodies.every(body => body === bodies[0]), 'the byte-identical request is retried');
    assert.equal(lease.client_request_id, JSON.parse(bodies[0]).client_request_id);
    assert.equal(h.serverCalls('GET', '/v2/nullifiers/').length, 0, 'the chain witness needs no server corroboration');

    const lagging = await freshWallet();
    withoutRetryDelays(lagging.runtime);
    lagging.server.leasePost = () => { throw new HttpError('The proof root is stale.', 409, 'stale_root'); };
    await assert.rejects(lagging.runtime.issueLease('chat'), error => error.code === 'stale_root'
        && error.journalRetained === true);
    assert.ok((await store.readBrowserWallet()).journal);
    assert.equal((await records())[0].disposition, 'pending');
    assert.equal(lagging.serverCalls('GET', '/v2/nullifiers/').length, 0);
});

test('escape at a transmitted anchor requires corroboration on a hardened vault', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    await discardFirstRequest(h);
    for (const [reply, code] of [
        [() => ({ status: 'ok', nullifier_status: 'reserved' }), 'request_settlement_pending'],
        [() => { throw new Error('network down'); }, 'transmitted_anchor_unconfirmed']
    ]) {
        h.server.nullifier = reply;
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
            assert.equal(error.code, code);
            assert.equal(error.status, 409);
            assert.equal(error.data.transmitted, true);
            assert.ok(Number.isSafeInteger(error.data.escape_override_after));
            assert.match(error.data.escape_override_warning, /challenged/);
            return true;
        });
        assert.equal(h.workerOperations('prepareWithdrawal').length, 0, 'no escape proof is generated on refusal');
    }
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(plan.mode, 'escape');
    assert.equal(h.workerOperations('prepareWithdrawal').length, 1);
    assert.ok(h.chain.reads.some(read => read.startsWith('0x6cda756a')), 'the vault challenge flag is consulted');
    const summary = h.runtime.snapshot().config;
    assert.equal(summary.vault_revision, 2);
    assert.match(summary.escape_override.warning, /funds stay withdrawable/);
    assert.equal(summary.unresolved_requests[0].kind, 'request');
    assert.equal(summary.unresolved_requests[0].server_status, 'unknown');
});

test('a Sepolia 401 on the escape gate asks for the password instead of refusing as unconfirmed', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    await discardFirstRequest(h);
    h.server.nullifier = () => {
        throw Object.assign(new Error('Enter the Sepolia password to continue.'),
            { code: 'testnet_password_required', status: 401 });
    };
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), { code: 'testnet_password_required' });
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
});

test('a challenged nullifier is never escaped again, even when the server reports it unknown', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    await discardFirstRequest(h);
    h.chain.challenged.add(BigInt(nullifierFor(GENESIS_ANCHOR)));
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), { code: 'nullifier_challenged' });
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
});

test('strict legacy vaults never escape at a transmitted anchor, with or without the override', async () => {
    const h = await freshWallet();
    await discardFirstRequest(h);
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    for (const options of [{}, { overrideUnsettledRequest: true }]) {
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, options), error => {
            assert.equal(error.code, 'transmitted_anchor_escape_unsafe');
            assert.equal(error.data.escape_override_after, null);
            assert.equal(error.data.escape_override_warning, undefined);
            return true;
        });
    }
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
    assert.equal(h.runtime.snapshot().config.vault_revision, 1);
    assert.equal(h.runtime.snapshot().config.escape_override, null, 'no funds-safe override copy on a legacy vault');

    const clean = await freshWallet();
    const plan = await clean.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(plan.mode, 'escape');
    assert.equal(clean.server.calls.length, 0, 'an untransmitted note escapes with no server contact');
});

test('clearance_reserved discard is archived and leaves a withdrawal-only marker', async () => {
    const h = await freshWallet();
    await h.runtime.prepareLeaseRequest();
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'clearance_reserved' });
    assert.equal(await h.runtime.recoverPending({ retireLostKey: true }), true);
    const saved = await store.readBrowserWallet();
    assert.equal(saved.journal, null);
    assert.equal(saved.preparedWithdrawal.phase, 'reserving');
    assert.equal(saved.preparedWithdrawal.mode, 'mutual');
    assert.equal(saved.preparedWithdrawal.clearanceReserved, true);
    assert.equal(saved.preparedWithdrawal.withdrawalNullifier, nullifierFor(GENESIS_ANCHOR),
        'the marker carries the current state’s own nullifier');
    const [record] = await records();
    assert.equal(record.disposition, 'discarded_clearance_reserved');
    assert.equal(archive.lastObservation(record).status, 'clearance_reserved');
});

test('a later-finalized response completes from the archived rerandomization', async () => {
    const h = await freshWallet();
    const first = (await discardFirstRequest(h)).journal;
    h.server.leasePost = () => { throw new HttpError('Replay detected.', 409, 'replay'); };
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'replay' });
    const second = (await store.readBrowserWallet()).journal;
    assert.notEqual(second.client_request_id, first.client_request_id);

    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(first) });
    assert.equal(await h.runtime.recoverPending({ retireLostKey: true }), true);
    const [completion] = h.worker.completions;
    assert.equal(completion.journal.client_request_id, first.client_request_id);
    assert.equal(completion.journal.user_rerandomization, first.user_rerandomization);
    const saved = await store.readBrowserWallet();
    assert.equal(saved.journal, null);
    assert.equal(saved.state.current_anchor, '0x9999');
    assert.equal(saved.state.current_balance, 5_000_000 - 25_000);
    const byId = Object.fromEntries((await records()).map(record => [record.clientRequestId, record]));
    assert.equal(byId[first.client_request_id].disposition, 'installed');
    assert.equal(byId[first.client_request_id].installedNextAnchor, archive.feltKey('0x9999'));
    assert.equal(byId[second.client_request_id].disposition, 'superseded');
    for (const record of Object.values(byId)) {
        assert.equal(record.compacted, true);
        assert.equal(record.journal.prepared_request, undefined);
        assert.equal(record.journal.user_rerandomization, undefined);
    }
    assert.deepEqual(h.runtime.snapshot().config.unresolved_requests, []);
});

test('a receipt without a saved journal reports receipt_journal_missing instead of a replay', async () => {
    const h = await freshWallet();
    await discardFirstRequest(h);
    const foreign = journalFor(noteState(), 'request-from-another-device');
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(foreign) });
    h.server.leasePost = body => h.activeLease(body);
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'receipt_journal_missing',
        message: 'The server reports a finalized private request for this balance that this browser cannot apply.' });
    assert.equal(h.workerOperations('prepareRequest').length, 1, 'no new request proof is made at a finalized state');
});

test('a state the server reports reserved never receives another request proof', async () => {
    const h = await freshWallet();
    await discardFirstRequest(h);
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'request_settlement_pending' });
    assert.equal(h.workerOperations('prepareRequest').length, 1);
});

test('a failing archive sweep never blocks a new chat, and page load never sweeps', async () => {
    const h = await freshWallet();
    await discardFirstRequest(h);
    h.server.calls.length = 0;
    await h.runtime.recoverPending({ retireLostKey: true, quiet: true });
    assert.equal(h.server.calls.length, 0, 'startup recovery without a journal sends no nullifier to the server');
    h.server.nullifier = () => { throw new Error('network down'); };
    h.server.leasePost = body => h.activeLease(body);
    const lease = await h.runtime.issueLease('chat');
    assert.ok(lease.api_key);
    assert.equal(h.serverCalls('GET', '/v2/nullifiers/').length, 1, 'the user action swept once, quietly');
});

test('store refuses to drop an unarchived transmitted journal without a state install', async () => {
    const h = await freshWallet();
    await h.runtime.prepareLeaseRequest();
    const before = await store.readBrowserWallet();
    const { journal, state } = before;
    await assert.rejects(store.writeBrowserWallet({ ...before, journal: null }),
        error => error.code === 'request_journal_unarchived'
            && /archive records its outcome/.test(error.message));
    assert.deepEqual(await store.readBrowserWallet(), before, 'a rejected write changes nothing');
    await assert.rejects(store.writeBrowserWallet({ ...before,
        journal: { ...journal, client_request_id: 'replacement' } }), /archive records its outcome/);

    const discard = archive.buildRequestJournalRecord({ deploymentId: DEPLOYMENT, state, journal,
        disposition: 'discarded_stale_root', observations: [archive.requestObservation('unknown', 'stale_root')] });
    const committed = await store.commitBrowserWallet({ ...before, journal: null }, { requestArchive: [discard] });
    assert.equal(committed.runtime.journal, null);
    assert.equal(committed.requestArchive.find(record => record.archiveId === discard.archiveId).disposition,
        'discarded_stale_root', 'the merged records come back from the same transaction');

    indexedDB.clear();
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, state, journal });
    await assert.rejects(store.writeBrowserWallet({ deploymentId: DEPLOYMENT, state, journal: null }),
        /archive records its outcome/);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, state: { ...state, current_anchor: '0x9999' }, journal: null });
    assert.equal((await store.readBrowserWallet()).journal, null, 'a verified install advances the state');
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, state, journal: { signedTransaction: 'legacy-shape' } });
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, state, journal: null });
});

test('an existing runtime journal migrates into the archive on first read, exempt from the bound', async () => {
    indexedDB.clear();
    const state = noteState();
    await store.putBrowserRequestArchive(Array.from({ length: 16 }, (_, index) =>
        pendingRecord(state, `filler-${index}`)));
    const journal = journalFor(state, 'old-build-request');
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state, journal });
    const before = await store.readBrowserWallet();
    const snapshot = await store.readBrowserWalletSnapshot(DEPLOYMENT);
    const migrated = snapshot.requestArchive.find(record => record.clientRequestId === 'old-build-request');
    assert.equal(migrated.source, 'migrated_runtime_journal');
    assert.equal(migrated.disposition, 'pending');
    assert.deepEqual(migrated.journal, journal);
    assert.equal(snapshot.requestArchive.filter(archive.isUnresolved).length, 17);
    assert.deepEqual(await store.readBrowserWallet(), before, 'the runtime slot is untouched');
    const h = createHarness(BrowserWalletRuntime);
    await h.runtime.reload();
    assert.equal(h.runtime.requestArchive.length, 17, 'reload never fails on the migration');
    assert.equal((await records()).length, 17, 'the migration is idempotent');
});

test('the per-state bound fails closed before proving, and eviction only sets expired corroborated discards aside', async () => {
    const h = await freshWallet();
    const state = noteState();
    await store.putBrowserRequestArchive(Array.from({ length: 16 }, (_, index) => pendingRecord(state, `pending-${index}`)));
    await assert.rejects(store.putBrowserRequestArchive([pendingRecord(state, 'one-too-many')]),
        { code: 'request_archive_limit' });
    await h.runtime.reload();
    await assert.rejects(h.runtime.prepareLeaseRequest(), { code: 'request_archive_limit' });
    assert.equal(h.workerOperations('prepareRequest').length, 0, 'the bound is checked before proving');
    await store.putBrowserRequestArchive([pendingRecord(noteState({ current_anchor: '0x4321' }), 'other-state')]);

    indexedDB.clear();
    const requestTime = Math.floor(Date.now() / 1000) - 7_200;
    const late = requestTime * 1000 + 1_300_000;
    const discarded = (index, observedAt, {
        status = 'unknown', context = 'stale_root', disposition = 'discarded_stale_root'
    } = {}) => archive.buildRequestJournalRecord({
        deploymentId: DEPLOYMENT, state,
        journal: journalFor(state, `stale-${index}`, { requestTime, createdAt: requestTime * 1000 + index }),
        disposition,
        observations: [archive.requestObservation(status, context, observedAt)]
    });
    await store.putBrowserRequestArchive([
        ...Array.from({ length: 15 }, (_, index) => discarded(index, requestTime * 1000 + 60_000)),
        discarded(15, late)
    ]);
    const merged = await store.putBrowserRequestArchive([pendingRecord(state, 'fresh')], { deploymentId: DEPLOYMENT });
    const evicted = merged.find(record => record.clientRequestId === 'stale-15');
    assert.equal(evicted.disposition, 'evicted');
    assert.ok(archive.isUnresolved(evicted) && !evicted.compacted && evicted.journal.user_rerandomization
        && evicted.journal.prepared_request, 'an evicted record keeps its full journal');
    assert.equal(merged.find(record => record.clientRequestId === 'stale-0').disposition, 'discarded_stale_root',
        'a discard observed inside the acceptance window is never evicted');
    assert.equal(merged.find(record => record.clientRequestId === 'fresh').disposition, 'pending');
    await assert.rejects(store.putBrowserRequestArchive([pendingRecord(state, 'again')]), { code: 'request_archive_limit' });

    // An /expire answer only echoes the request, so it never qualifies a
    // record for eviction, however late it was saved.
    indexedDB.clear();
    await store.putBrowserRequestArchive(Array.from({ length: 16 }, (_, index) => discarded(index, late,
        { status: 'unaccepted', context: 'recovery', disposition: 'discarded_expired_unaccepted' })));
    await assert.rejects(store.putBrowserRequestArchive([pendingRecord(state, 'after-unaccepted')]),
        { code: 'request_archive_limit' });

    // The hard ceiling counts evicted records: at 64 retained records nothing
    // more is set aside, and the next request is refused before proving.
    indexedDB.clear();
    await store.putBrowserRequestArchive([
        ...Array.from({ length: 47 }, (_, index) => discarded(100 + index, late, { disposition: 'evicted' })),
        ...Array.from({ length: 16 }, (_, index) => discarded(index, late))
    ]);
    const full = await store.putBrowserRequestArchive([pendingRecord(state, 'last-slot')], { deploymentId: DEPLOYMENT });
    assert.equal(full.length, archive.REQUEST_ARCHIVE_LIMITS.retainedPerAnchor);
    assert.equal(full.filter(record => record.disposition === 'evicted').length, 48);
    // Waiting helps only if the server settles one of them, and the refusal
    // says so instead of asking the user to wait.
    const atCeiling = error => {
        assert.equal(error.code, 'request_archive_limit');
        assert.match(error.message, /no new chat can start from it\. Chats resume only if the server settles one of them; otherwise withdraw this balance\./);
        assert.doesNotMatch(error.message, /Wait/);
        return true;
    };
    await assert.rejects(store.putBrowserRequestArchive([pendingRecord(state, 'beyond')]), atCeiling);
    assert.deepEqual(await records(), full, 'nothing is evicted or discarded at the ceiling');
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    await h.runtime.reload();
    await assert.rejects(h.runtime.prepareLeaseRequest(), atCeiling);
    assert.equal(h.workerOperations('prepareRequest').length, 0);
});

test('an /expire answer is saved as unaccepted, never as a nullifier reading', async () => {
    const h = await freshWallet();
    h.server.leasePost = () => { throw new HttpError('Quote expired.', 409, 'native_quote_expired'); };
    h.server.expire = body => ({ status: 'expired_unaccepted', client_request_id: body.client_request_id,
        request_nullifier: body.public_inputs.request_nullifier, payload_hash: body.payload_hash });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'native_quote_expired' });
    const [record] = await records();
    assert.equal(record.disposition, 'discarded_expired_unaccepted');
    assert.ok(record.journal.user_rerandomization);
    assert.deepEqual(record.serverObservations.map(({ status, context }) => ({ status, context })),
        [{ status: 'unaccepted', context: 'recovery' }], 'the echo is not an unknown nullifier reading');
    assert.equal(archive.lastDefinitiveObservation(record), null);
    assert.equal(h.serverCalls('GET', '/v2/nullifiers/').length, 0, 'no nullifier was read on this path');
});

// The gateway rewriter of the journal-discard review: the honest server
// reserves the first request it sees at this state (J1) and later finalizes
// it, while every lease POST is rewritten to native_quote_expired, every
// /expire echoes the client's own identifiers and every nullifier read says
// unknown. Eviction must never cost J1 its private rerandomization.
for (const vaultRevision of [null, 2]) {
    test(`forged discards past the per-state cap never cost a reserved request its receipt (vault_revision ${vaultRevision ?? 'absent'})`, async t => {
        const h = await freshWallet(vaultRevision == null ? {} : { vaultRevision });
        const realNow = Date.now;
        let elapsed = 0;
        t.mock.method(Date, 'now', () => realNow() + elapsed);
        let reserved = null;
        let rewriting = true;
        h.server.leasePost = body => {
            reserved ??= body;
            if (rewriting) throw new HttpError('Quote expired.', 409, 'native_quote_expired');
            return h.activeLease(body);
        };
        h.server.expire = body => ({ status: 'expired_unaccepted', client_request_id: body.client_request_id,
            request_nullifier: body.public_inputs.request_nullifier, payload_hash: body.payload_hash });
        h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
        const forgedDiscards = async count => {
            for (let chat = 0; chat < count; chat += 1) {
                await assert.rejects(h.runtime.issueLease('chat'), { code: 'native_quote_expired' });
            }
        };
        const dispositions = async () => Object.fromEntries((await records())
            .map(record => [record.clientRequestId, record.disposition]));

        await forgedDiscards(16);
        // 21 minutes later every discard looks expired and corroborated, so
        // the next chat evicts J1 from the per-state cap, not from the archive.
        elapsed = 21 * 60_000;
        await forgedDiscards(1);
        const evicted = (await records()).find(record => record.clientRequestId === reserved.client_request_id);
        assert.equal(evicted.disposition, 'evicted');
        assert.ok(archive.isUnresolved(evicted) && evicted.journal.user_rerandomization != null
            && evicted.journal.prepared_request, 'eviction keeps the full journal of a request at the current state');

        // Keep forging, 21 minutes apart, up to the hard per-state ceiling.
        await forgedDiscards(15);
        for (const minutes of [42, 63]) {
            elapsed = minutes * 60_000;
            await forgedDiscards(16);
        }
        const retained = await records();
        assert.equal(retained.length, archive.REQUEST_ARCHIVE_LIMITS.retainedPerAnchor);
        assert.equal(retained.filter(record => record.disposition === 'evicted').length, 48);
        assert.ok(retained.every(record => archive.isUnresolved(record)
            && record.journal.user_rerandomization != null && record.journal.prepared_request));
        const before = await dispositions();
        elapsed = 84 * 60_000;
        const proofs = h.workerOperations('prepareRequest').length;
        await assert.rejects(h.runtime.issueLease('chat'), { code: 'request_archive_limit' });
        assert.equal(h.workerOperations('prepareRequest').length, proofs, 'the ceiling refuses before proving');
        assert.deepEqual(await dispositions(), before, 'nothing is evicted or discarded at the ceiling');
        if (vaultRevision == null) {
            await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION),
                { code: 'transmitted_anchor_escape_unsafe' });
        }

        // The rewriter stops; the honest server finalizes J1 and reports it.
        rewriting = false;
        h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
            request_response: h.receiptFor({ client_request_id: reserved.client_request_id,
                nullifier: reserved.public_inputs.request_nullifier, prepared_request: reserved }) });
        const lease = await h.runtime.issueLease('chat');
        assert.deepEqual(h.worker.completions.map(completion => completion.journal.client_request_id),
            [reserved.client_request_id], 'the reserved request’s receipt installs from its evicted journal');
        const saved = await store.readBrowserWallet();
        assert.equal(saved.state.current_anchor, '0x9999');
        assert.equal(saved.state.current_balance, 5_000_000 - 25_000);
        assert.equal(saved.journal.client_request_id, lease.client_request_id, 'the next chat proves at the signed next state');
        const settled = (await records()).filter(record => record.anchor === archive.feltKey(GENESIS_ANCHOR));
        assert.equal(settled.length, 64);
        assert.ok(settled.every(record => record.compacted && !archive.isUnresolved(record)));
        assert.equal(settled.find(record => record.clientRequestId === reserved.client_request_id).disposition, 'installed');
    });
}

test('an evicted request still marks its state transmitted and installs its later receipt', async () => {
    for (const vaultRevision of [null, 2]) {
        const h = await freshWallet(vaultRevision == null ? {} : { vaultRevision });
        const state = noteState();
        const journal = journalFor(state, `evicted-${vaultRevision ?? 'strict'}`);
        await store.putBrowserRequestArchive([archive.buildRequestJournalRecord({ deploymentId: DEPLOYMENT, state,
            journal, disposition: 'evicted' })]);
        await h.runtime.reload();
        h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION),
            { code: vaultRevision == null ? 'transmitted_anchor_escape_unsafe' : 'request_settlement_pending' });
        assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
        assert.deepEqual(h.runtime.snapshot().config.unresolved_requests.map(entry => entry.disposition), ['evicted']);

        h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(journal) });
        const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION);
        assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor('0x9999'), 'the escape is at the signed next state');
        assert.equal(h.worker.completions[0].journal.user_rerandomization, journal.user_rerandomization);
        assert.equal((await records())[0].disposition, 'installed');
    }
});

test('terminal records are compacted and pruned to 256 per deployment without touching note archives', async () => {
    indexedDB.clear();
    const state = noteState();
    indexedDB.stores.get('archives').set('note-archive', { archiveId: 'note-archive', reason: 'closed',
        deploymentId: DEPLOYMENT, state, archivedAt: 1 });
    await store.putBrowserRequestArchive([pendingRecord(state, 'unresolved')]);
    await store.putBrowserRequestArchive(Array.from({ length: 300 }, (_, index) => {
        const done = noteState({ current_anchor: `0x${(0x10000 + index).toString(16)}` });
        return archive.buildRequestJournalRecord({ deploymentId: DEPLOYMENT, state: done,
            journal: journalFor(done, `done-${index}`), disposition: 'superseded' });
    }));
    const all = await records();
    const done = all.filter(record => record.clientRequestId?.startsWith('done-'));
    assert.equal(done.length, 256);
    assert.ok(done.every(record => record.compacted && record.journal.prepared_request === undefined
        && record.journal.user_rerandomization === undefined));
    assert.equal(all.filter(archive.isUnresolved).length, 1, 'unresolved records are never pruned');
    assert.ok(indexedDB.stores.get('archives').has('note-archive'));
});

test('repeated evidence and a discarded migrated journal merge as partial patches', () => {
    const state = noteState();
    const evidence = archive.buildRequestEvidenceRecord({ deploymentId: DEPLOYMENT, noteId: 7,
        anchor: state.current_anchor, nullifier: nullifierFor(state.current_anchor),
        evidence: { transactionHash: `0x${'ab'.repeat(32)}`, blockNumber: 10 }, now: 100 });
    const again = archive.buildRequestEvidenceRecord({ deploymentId: DEPLOYMENT, noteId: 7,
        anchor: state.current_anchor, nullifier: nullifierFor(state.current_anchor), now: 200 });
    const merged = archive.mergeRequestArchiveRecord(evidence, again, 300);
    assert.equal(merged.createdAt, 100, 'the original createdAt is kept');
    assert.deepEqual(merged.sources, ['escape_challenged']);
    assert.equal(merged.evidence.blockNumber, 10);

    const migrated = archive.buildRequestJournalRecord({ deploymentId: DEPLOYMENT, state,
        journal: journalFor(state, 'migrated'), source: 'migrated_runtime_journal', now: 100 });
    const discard = archive.buildRequestJournalRecord({ deploymentId: DEPLOYMENT, state,
        journal: journalFor(state, 'migrated'), disposition: 'discarded_stale_root', now: 200 });
    const discarded = archive.mergeRequestArchiveRecord(migrated, discard, 300);
    assert.equal(discarded.source, 'migrated_runtime_journal');
    assert.equal(discarded.disposition, 'discarded_stale_root');
    const installed = archive.mergeRequestArchiveRecord(discarded,
        { archiveId: discarded.archiveId, disposition: 'installed', installedNextAnchor: word(9) }, 400);
    assert.equal(installed.disposition, 'installed');
    assert.equal(installed.journal.user_rerandomization, undefined, 'terminal compaction is exempt from identity rules');
    const late = archive.mergeRequestArchiveRecord(installed, { archiveId: installed.archiveId, disposition: 'pending' }, 500);
    assert.equal(late.disposition, 'installed', 'a disposition only moves forward');
    assert.throws(() => archive.mergeRequestArchiveRecord(migrated, { ...discard, nullifier: '0x1' }, 600),
        { code: 'request_archive_conflict' });
    const observations = Array.from({ length: 12 }, (_, index) => archive.requestObservation('unavailable', 'recovery', 1_000 + index));
    const bounded = archive.mergeRequestArchiveRecord(migrated, { archiveId: migrated.archiveId, serverObservations: observations }, 700);
    assert.equal(bounded.serverObservations.length, 8);
    assert.equal(bounded.serverObservations.at(-1).at, 1_011);
});

test('the escape override is time-gated and archive-covered', async t => {
    const h = await freshWallet({ vaultRevision: 2, graceSeconds: 3_600 });
    await h.runtime.prepareLeaseRequest();
    const journal = (await store.readBrowserWallet()).journal;
    h.server.leaseStatus = () => ({ status: 'revoking' });
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), { code: 'lease_pending' });
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }), error => {
        assert.equal(error.code, 'request_settlement_pending');
        assert.equal(error.data.escape_override_after, journal.created_at_ms + 3_600_000);
        assert.match(error.data.escape_override_warning, /challenged/);
        return true;
    });
    assert.ok((await store.readBrowserWallet()).journal, 'a refused override keeps the journal');

    const realNow = Date.now;
    t.mock.method(Date, 'now', () => realNow() + 3_700_000);
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true });
    assert.equal(plan.mode, 'escape');
    const saved = await store.readBrowserWallet();
    assert.equal(saved.journal, null);
    assert.equal(saved.lease, null);
    const [record] = await records();
    assert.equal(record.disposition, 'abandoned_for_escape');
    assert.equal(archive.lastObservation(record).context, 'override');
    assert.ok(record.journal.user_rerandomization, 'an abandoned request can still install a later receipt');
});

test('the escape override opens early only when the note would otherwise expire', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    await h.runtime.prepareLeaseRequest();
    h.server.leaseStatus = () => ({ status: 'revoking' });
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
    h.chain.effectiveExpiry = BigInt(Math.floor(Date.now() / 1000) + 30 * 86_400);
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }),
        { code: 'request_settlement_pending' });
    h.chain.effectiveExpiry = BigInt(Math.floor(Date.now() / 1000) + 86_400 + 3_600);
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true });
    assert.equal(plan.mode, 'escape');
    assert.ok(h.chain.reads.some(read => read.startsWith('0x7cb4a03c')), 'the pause-aware expiry is read');
    assert.equal((await records())[0].disposition, 'abandoned_for_escape');
});

test('a verified finalized receipt installs instead of the escape override', async () => {
    const h = await freshWallet({ vaultRevision: 2, graceSeconds: 3_600 });
    await h.runtime.prepareLeaseRequest();
    const journal = (await store.readBrowserWallet()).journal;
    h.server.leaseStatus = () => ({ status: 'revoking' });
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(journal) });
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true });
    assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor('0x9999'), 'the escape is at the signed next state');
    assert.equal(plan.public_inputs.final_balance, 5_000_000 - 25_000);
    assert.equal((await records())[0].disposition, 'installed');
});

test('a finalized receipt this browser cannot apply keeps the time-gated override behind its own warning and acknowledgement', async t => {
    const h = await freshWallet({ vaultRevision: 2 });
    const discarded = await discardFirstRequest(h);
    const realNow = Date.now;
    let elapsed = 0;
    t.mock.method(Date, 'now', () => realNow() + elapsed);
    const overrideAfter = discarded.journal.created_at_ms + 43_200_000;
    const otherReadings = [
        [() => ({ status: 'ok', nullifier_status: 'reserved' }), 'request_settlement_pending'],
        [() => { throw new Error('network down'); }, 'transmitted_anchor_unconfirmed'],
        [() => ({ status: 'ok', nullifier_status: 'finalized' }), 'receipt_response_missing']
    ];
    // Before any receipt claim, the other override codes keep the existing
    // warning and the general acknowledgement, in the refusal and in the
    // snapshot.
    for (const [reply, code] of otherReadings) {
        h.server.nullifier = reply;
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
            assert.equal(error.code, code);
            assert.equal(error.data.escape_override_after, overrideAfter);
            assert.match(error.data.escape_override_warning, /funds stay withdrawable from the next state/);
            assert.equal(error.data.escape_override_acknowledgement, true);
            return true;
        });
        assert.match(h.runtime.snapshot().config.escape_override.warning, /funds stay withdrawable from the next state/);
        assert.equal(h.runtime.snapshot().config.escape_override.acknowledgement, true);
    }

    // The server reports a finalized transcript for a request whose journal
    // this browser does not have. Genuine or not, only a receipt that
    // verifies may veto the override.
    const foreign = journalFor(noteState(), 'request-from-another-device');
    const finalizedForeign = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(foreign) });
    h.server.nullifier = finalizedForeign;
    for (const options of [{}, { overrideUnsettledRequest: true }, { overrideUnsettledRequest: 'receipt_journal_missing' }]) {
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, options), error => {
            assertJournalMissingRefusal(error, overrideAfter);
            assert.doesNotMatch(error.message, /would be challenged|operator/);
            return true;
        });
    }
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0, 'no escape is proved before the grace');
    const summary = h.runtime.snapshot().config;
    assertJournalMissingWarning(summary.escape_override.warning);
    assert.equal(summary.escape_override.acknowledgement, 'receipt_journal_missing');
    assert.equal(summary.unresolved_requests[0].escape_override_after, overrideAfter);

    // The claim stands through the same readings: each is refused with its
    // own code, but the override it offers, like the snapshot, keeps this
    // case's warning and acknowledgement.
    for (const [reply, code] of otherReadings) {
        h.server.nullifier = reply;
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
            assert.equal(error.code, code);
            assert.equal(error.data.escape_override_after, overrideAfter);
            assertJournalMissingWarning(error.data.escape_override_warning);
            assert.equal(error.data.escape_override_acknowledgement, 'receipt_journal_missing');
            return true;
        });
        assertJournalMissingWarning(h.runtime.snapshot().config.escape_override.warning);
        assert.equal(h.runtime.snapshot().config.escape_override.acknowledgement, 'receipt_journal_missing');
    }

    h.server.nullifier = finalizedForeign;
    elapsed = 13 * 3_600_000;
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), { code: 'receipt_journal_missing' },
        'only the explicit override escapes');
    // The general acknowledgement never escapes in this case, also after the
    // grace: the refusal carries this case's warning and acknowledgement.
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }), error => {
        assertJournalMissingRefusal(error, overrideAfter);
        return true;
    });
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: 'receipt_journal_missing' });
    assert.equal(plan.mode, 'escape');
    assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR), 'the override escapes at the current state');
    assert.equal(h.workerOperations('prepareWithdrawal').length, 1);
    assert.equal(h.workerOperations('completeResponse').length, 0, 'the receipt names no journal this browser holds');
    const [kept] = await records();
    assert.ok(archive.isUnresolved(kept) && kept.journal.user_rerandomization, 'the archived journal still installs a later receipt');

    // Once ready, every refusal is overridable; a receipt that verifies is
    // installed by the gate before this decision is ever made. Only
    // receipt_journal_missing needs its own acknowledgement, which also
    // covers the general case.
    const entries = [pendingRecord(noteState(), 'transmitted')];
    const decide = (observed, {
        overrideReady = true, journalMissingAcknowledged = false, journalMissingClaimed = false
    } = {}) => archive.transmittedAnchorDecision({ entries, observed, purpose: 'escape', hardened: true, override: true,
        overrideReady, journalMissingAcknowledged, journalMissingClaimed });
    for (const observed of [{ status: 'reserved' }, { status: 'unavailable' }, { status: 'finalized', response: null }]) {
        assert.deepEqual(decide(observed), { allowed: true, reason: 'overridden' });
        assert.deepEqual(decide(observed, { journalMissingAcknowledged: true }), { allowed: true, reason: 'overridden' });
        // A claim saved earlier that this reading does not contradict.
        assert.deepEqual(decide(observed, { journalMissingClaimed: true }), { allowed: false, code: 'receipt_journal_missing' });
        assert.deepEqual(decide(observed, { journalMissingClaimed: true, journalMissingAcknowledged: true }),
            { allowed: true, reason: 'overridden' });
    }
    assert.deepEqual(decide({ status: 'unavailable' }, { overrideReady: false, journalMissingClaimed: true }),
        { allowed: false, code: 'transmitted_anchor_unconfirmed' }, 'before it is ready the code follows the reading');
    for (const status of ['unknown', 'clearance_reserved']) {
        assert.deepEqual(decide({ status }, { journalMissingClaimed: true }), { allowed: true, reason: 'corroborated' },
            'a reading that contradicts the claim is corroborated');
    }
    const unapplied = { status: 'finalized', response: h.receiptFor(foreign) };
    assert.deepEqual(decide(unapplied), { allowed: false, code: 'receipt_journal_missing' });
    assert.deepEqual(decide(unapplied, { journalMissingAcknowledged: true }), { allowed: true, reason: 'overridden' });
    assert.deepEqual(decide(unapplied, { overrideReady: false, journalMissingAcknowledged: true }),
        { allowed: false, code: 'receipt_journal_missing' });
});

// The refutation of completeness #3: a server or gateway that lies 'finalized'
// produces the same receipt_journal_missing code. Without the override, the
// escape would stay refused after the grace and near expiry, and the note
// would be left to claimExpired.
for (const variant of ['invented request', 'forged signature']) {
    test(`a fabricated finalized claim (${variant}) never blocks the escape override after the grace or near expiry`, async t => {
        const realNow = Date.now;
        let elapsed = 0;
        t.mock.method(Date, 'now', () => realNow() + elapsed);
        for (const trigger of ['grace', 'expiry']) {
            elapsed = 0;
            const h = await freshWallet({ vaultRevision: 2 });
            let own;
            let fabricated;
            if (variant === 'invented request') {
                // A gateway answers the lease POST itself and echoes /expire,
                // so the honest server never sees a request at this state.
                h.server.leasePost = () => { throw new HttpError('Quote expired.', 409, 'native_quote_expired'); };
                h.server.expire = body => ({ status: 'expired_unaccepted', client_request_id: body.client_request_id,
                    request_nullifier: body.public_inputs.request_nullifier, payload_hash: body.payload_hash });
                await assert.rejects(h.runtime.issueLease('chat'), { code: 'native_quote_expired' });
                [own] = await records();
                assert.equal(own.disposition, 'discarded_expired_unaccepted');
                fabricated = { status: 'ok', client_request_id: 'invented-by-the-server',
                    request_nullifier: nullifierFor(GENESIS_ANCHOR), response_payload: 'garbage' };
            } else {
                // 'unknown' corroborated this discard: the server never
                // reserved the nullifier, so a later 'finalized' is false.
                own = await discardFirstRequest(h);
                fabricated = { ...h.receiptFor(own.journal), next_state_signature: 'forged-signature' };
            }
            h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: fabricated });

            // A host following the refusal shows its warning and passes back
            // its acknowledgement.
            let acknowledgement = null;
            await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }), error => {
                assertJournalMissingRefusal(error, own.journal.created_at_ms + 43_200_000);
                acknowledgement = error.data.escape_override_acknowledgement;
                return true;
            });
            assert.equal(h.workerOperations('prepareWithdrawal').length, 0, 'refused before the grace');

            if (trigger === 'grace') elapsed = 13 * 3_600_000;
            else h.chain.effectiveExpiry = BigInt(Math.floor(Date.now() / 1_000)) + h.chain.challengePeriod + 3_600n;
            // Ready now, yet the general acknowledgement still never escapes
            // here; the refusal says that the override is available now.
            await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }), error => {
                assert.equal(error.code, 'receipt_journal_missing');
                assert.ok(error.data.escape_override_after <= Date.now(), `available now (${trigger})`);
                assert.equal(error.data.escape_override_acknowledgement, 'receipt_journal_missing');
                return true;
            });
            assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
            const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: acknowledgement });
            assert.equal(plan.mode, 'escape', `the override opens (${trigger})`);
            assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
            assert.equal(h.workerOperations('completeResponse').length > 0, variant === 'forged signature',
                'an invented request never reaches completeResponse; a forged signature fails it');
            assert.equal((await store.readBrowserWallet()).state.current_anchor, GENESIS_ANCHOR, 'nothing was installed');
        }
    });
}

// The same lie while this browser still holds the live journal: the server
// reports the lease revoking, unknown, or active and then retired with a
// receipt by request id, and the nullifier 'finalized', always for an invented
// request. Quiet recovery (initialization, the override) must not fail on it,
// and the override's own time gate warns about this case.
for (const leaseStatus of ['revoking', 'not_found', 'active']) {
    test(`a fabricated finalized claim never blocks initialization or the override of a live journal (lease ${leaseStatus})`, async t => {
        const h = await freshWallet({ vaultRevision: 2, graceSeconds: 3_600 });
        await h.runtime.prepareLeaseRequest();
        const journal = (await store.readBrowserWallet()).journal;
        h.server.leaseStatus = () => {
            if (leaseStatus === 'not_found') throw new HttpError('Not found', 404, 'not_found');
            return { status: leaseStatus };
        };
        const invented = { status: 'ok', client_request_id: 'invented-by-the-server',
            request_nullifier: nullifierFor(GENESIS_ANCHOR), response_payload: 'garbage' };
        h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: invented });
        h.server.requests = () => ({ request_response: invented });
        assert.equal(await h.runtime.recoverPendingLocked({ retireLostKey: true, quiet: true }), false,
            'the quiet recovery that initialization runs does not fail');
        // The snapshot follows the reading that this recovery saved.
        assertJournalMissingWarning(h.runtime.snapshot().config.escape_override.warning);
        await assert.rejects(h.runtime.recoverPending({ retireLostKey: true }), { code: 'receipt_journal_missing' },
            'a caller that is not quiet still sees the refusal');
        assert.ok((await store.readBrowserWallet()).journal);

        const overrideAfter = journal.created_at_ms + 3_600_000;
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }), error => {
            assertJournalMissingRefusal(error, overrideAfter);
            assert.equal(error.data.client_request_id, journal.client_request_id);
            return true;
        });
        assert.ok((await store.readBrowserWallet()).journal, 'a refused override keeps the journal');
        assertJournalMissingWarning(h.runtime.snapshot().config.escape_override.warning);

        const realNow = Date.now;
        t.mock.method(Date, 'now', () => realNow() + 3_700_000);
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }), error => {
            assertJournalMissingRefusal(error, overrideAfter);
            return true;
        }, 'the general acknowledgement never abandons the journal in this case');
        assert.ok((await store.readBrowserWallet()).journal);
        assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
        const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: 'receipt_journal_missing' });
        assert.equal(plan.mode, 'escape');
        assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
        assert.equal(h.workerOperations('completeResponse').length, 0);
        const [record] = await records();
        assert.equal(record.disposition, 'abandoned_for_escape');
        assert.ok(record.journal.user_rerandomization, 'the abandoned journal still installs a later receipt');
    });
}

// The README's genuine receipt_journal_missing, end to end. An older build
// discarded J0, which the honest server reserved and later finalized. After
// the upgrade no archive record exists for that state, so the next chat proves
// J1 there. The server answers 409 replay (J0 holds the nullifier), keeps no
// lease for J1 (404) and reports the nullifier finalized with J0's genuine
// receipt, so an escape at this state will be challenged. No escape may be
// proved before this case's own warning was offered and acknowledged.
test('a genuine finalized receipt for a request an older build discarded never escapes without its own acknowledgement', async t => {
    const h = await freshWallet({ vaultRevision: 2 });
    const j0 = journalFor(noteState(), 'discarded-by-an-older-build',
        { requestTime: Math.floor(Date.now() / 1000) - 86_400, createdAt: Date.now() - 86_400_000 });
    h.server.leasePost = () => { throw new HttpError('This request replays an earlier one.', 409, 'replay'); };
    h.server.leaseStatus = () => { throw new HttpError('Not found', 404, 'not_found'); };
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(j0) });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'replay' });
    const j1 = (await store.readBrowserWallet()).journal;
    assert.ok(j1, 'the replayed request stays live');
    const overrideAfter = j1.created_at_ms + 43_200_000;

    const realNow = Date.now;
    let elapsed = 0;
    t.mock.method(Date, 'now', () => realNow() + elapsed);
    for (const hours of [0, 13]) {
        elapsed = hours * 3_600_000;
        // A plain escape offers the override with this case's warning, and
        // the snapshot shows the same from the reading recovery saved.
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
            assertJournalMissingRefusal(error, overrideAfter);
            return true;
        });
        const summary = h.runtime.snapshot().config;
        assertJournalMissingWarning(summary.escape_override.warning);
        assert.equal(summary.escape_override.acknowledgement, 'receipt_journal_missing');
        assert.equal(summary.unresolved_requests[0].server_status, 'finalized');
        assert.equal(summary.unresolved_requests[0].escape_override_after, overrideAfter);
    }
    // Past the grace, the general acknowledgement is refused again and the
    // live journal stays where it is.
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }), error => {
        assertJournalMissingRefusal(error, overrideAfter);
        assert.equal(error.data.client_request_id, j1.client_request_id);
        return true;
    });
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0, 'no escape before this case is acknowledged');
    assert.equal((await store.readBrowserWallet()).journal.client_request_id, j1.client_request_id);

    // The user accepted that a genuine claim makes the challenge certain.
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: 'receipt_journal_missing' });
    assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
    assert.equal(h.workerOperations('completeResponse').length, 0);
    const [record] = await records();
    assert.equal(record.disposition, 'abandoned_for_escape');
    assert.ok(record.journal.user_rerandomization, 'the abandoned journal still installs a later receipt');
});

// The first 'finalized' reading can arrive inside an override past the grace,
// after the snapshot or an earlier refusal offered only the general warning.
for (const earlier of ['unknown', 'reserved']) {
    test(`a finalized claim first read inside the override is refused with its own warning (earlier reading ${earlier})`, async t => {
        const h = await freshWallet({ vaultRevision: 2 });
        const discarded = await discardFirstRequest(h);
        const overrideAfter = discarded.journal.created_at_ms + 43_200_000;
        if (earlier === 'reserved') {
            h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
            await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
                assert.equal(error.code, 'request_settlement_pending');
                assert.match(error.data.escape_override_warning, /funds stay withdrawable/);
                assert.equal(error.data.escape_override_acknowledgement, true);
                return true;
            });
        }
        const realNow = Date.now;
        t.mock.method(Date, 'now', () => realNow() + 13 * 3_600_000);
        const shown = h.runtime.snapshot().config.escape_override;
        assert.match(shown.warning, /funds stay withdrawable/);
        assert.equal(shown.acknowledgement, true);

        // The server's answer changes before the user overrides with the
        // general acknowledgement that was offered.
        h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
            request_response: h.receiptFor(journalFor(noteState(), 'not-held-by-this-browser')) });
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: shown.acknowledgement }),
            error => {
                assertJournalMissingRefusal(error, overrideAfter);
                return true;
            });
        assert.equal(h.workerOperations('prepareWithdrawal').length, 0, 'no escape on the first finalized reading');
        const updated = h.runtime.snapshot().config.escape_override;
        assertJournalMissingWarning(updated.warning);
        const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: updated.acknowledgement });
        assert.equal(plan.mode, 'escape');
        assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
    });
}

// Round-2 review: once a reading saved the claim, a later read that fails,
// says 'reserved' or says 'finalized' without a receipt must neither offer the
// general warning nor let `true` escape. Each variant runs with the request
// archived (a corroborated discard) and with the journal still live (the
// README's older-build path).
const LATER_READINGS = [
    ['a failed read', () => { throw new HttpError('Service unavailable', 503, 'service_unavailable'); },
        'unavailable', 'transmitted_anchor_unconfirmed'],
    ['reserved', () => ({ status: 'ok', nullifier_status: 'reserved' }), 'reserved', 'request_settlement_pending'],
    ['finalized without a receipt', () => ({ status: 'ok', nullifier_status: 'finalized' }),
        'finalized', 'receipt_response_missing']
];

// The override refused as receipt_journal_missing on a claim an earlier read
// saved: ready, so available now, and this case's own acknowledgement.
function assertSavedClaimRefusal(error, nullifierStatus) {
    assert.equal(error.code, 'receipt_journal_missing');
    assert.equal(error.message, 'The server earlier reported a finalized private request for this balance that this browser cannot apply.');
    assert.equal(error.data.nullifier_status, nullifierStatus, 'the data reports this read');
    assert.ok(error.data.escape_override_after <= Date.now(), 'available now');
    assertJournalMissingWarning(error.data.escape_override_warning);
    assert.equal(error.data.escape_override_acknowledgement, 'receipt_journal_missing');
}

for (const [later, reply, nullifierStatus, code] of LATER_READINGS) {
    test(`a saved receipt_journal_missing claim keeps its own acknowledgement after ${later} (archived request)`, async t => {
        const h = await freshWallet({ vaultRevision: 2 });
        const discarded = await discardFirstRequest(h);
        const overrideAfter = discarded.journal.created_at_ms + 43_200_000;
        h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
            request_response: h.receiptFor(journalFor(noteState(), 'discarded-by-an-older-build')) });
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
            assertJournalMissingRefusal(error, overrideAfter);
            return true;
        });

        const realNow = Date.now;
        t.mock.method(Date, 'now', () => realNow() + 13 * 3_600_000);
        h.server.nullifier = reply;
        // The plain escape is refused for this read and offers the override
        // with the claim's warning and acknowledgement, as the snapshot does.
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
            assert.equal(error.code, code);
            assert.equal(error.data.nullifier_status, nullifierStatus);
            assert.equal(error.data.escape_override_after, overrideAfter);
            assertJournalMissingWarning(error.data.escape_override_warning);
            assert.equal(error.data.escape_override_acknowledgement, 'receipt_journal_missing');
            return true;
        });
        const shown = h.runtime.snapshot().config.escape_override;
        assertJournalMissingWarning(shown.warning);
        assert.equal(shown.acknowledgement, 'receipt_journal_missing');

        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }),
            error => {
                assertSavedClaimRefusal(error, nullifierStatus);
                return true;
            });
        assert.equal(h.workerOperations('prepareWithdrawal').length, 0, 'the general acknowledgement never escapes here');
        // The claim never vetoes: its own acknowledgement escapes.
        const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: shown.acknowledgement });
        assert.equal(plan.mode, 'escape');
        assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
        assert.equal(h.workerOperations('prepareWithdrawal').length, 1);
    });

    test(`a saved receipt_journal_missing claim keeps its own acknowledgement after ${later} (live journal)`, async t => {
        const h = await freshWallet({ vaultRevision: 2 });
        h.server.leasePost = () => { throw new HttpError('This request replays an earlier one.', 409, 'replay'); };
        h.server.leaseStatus = () => { throw new HttpError('Not found', 404, 'not_found'); };
        h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
            request_response: h.receiptFor(journalFor(noteState(), 'discarded-by-an-older-build')) });
        await assert.rejects(h.runtime.issueLease('chat'), { code: 'replay' });
        const j1 = (await store.readBrowserWallet()).journal;
        const overrideAfter = j1.created_at_ms + 43_200_000;
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
            assertJournalMissingRefusal(error, overrideAfter);
            return true;
        });

        const realNow = Date.now;
        let elapsed = 3_600_000;
        t.mock.method(Date, 'now', () => realNow() + elapsed);
        h.server.nullifier = reply;
        // Before the grace the override waits like any other, and already
        // shows this case's warning and acknowledgement.
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }),
            error => {
                assert.equal(error.code, 'request_settlement_pending');
                assert.equal(error.data.nullifier_status, nullifierStatus);
                assert.equal(error.data.escape_override_after, overrideAfter);
                assertJournalMissingWarning(error.data.escape_override_warning);
                assert.equal(error.data.escape_override_acknowledgement, 'receipt_journal_missing');
                return true;
            });

        elapsed = 13 * 3_600_000;
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }),
            error => {
                assertSavedClaimRefusal(error, nullifierStatus);
                assert.equal(error.data.client_request_id, j1.client_request_id);
                return true;
            });
        assert.equal((await store.readBrowserWallet()).journal.client_request_id, j1.client_request_id,
            'the general acknowledgement never abandons the journal here');
        assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
        const shown = h.runtime.snapshot().config.escape_override;
        assertJournalMissingWarning(shown.warning);
        const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: shown.acknowledgement });
        assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
        const [record] = await records();
        assert.equal(record.disposition, 'abandoned_for_escape');
        assert.ok(record.journal.user_rerandomization, 'the abandoned journal still installs a later receipt');
    });
}

test('a standing receipt claim survives repeated failed reads, and a reading that contradicts it ends it', async t => {
    const h = await freshWallet({ vaultRevision: 2 });
    await discardFirstRequest(h);
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
        request_response: h.receiptFor(journalFor(noteState(), 'not-held-by-this-browser')) });
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), { code: 'receipt_journal_missing' });
    const realNow = Date.now;
    t.mock.method(Date, 'now', () => realNow() + 13 * 3_600_000);
    h.server.nullifier = () => { throw new Error('network down'); };
    // Each attempt saves two failed reads (the sweep and the gate), well past
    // the newest eight observations a record keeps.
    for (let attempt = 0; attempt < 6; attempt += 1) {
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
            assert.equal(error.code, 'transmitted_anchor_unconfirmed');
            assert.equal(error.data.escape_override_acknowledgement, 'receipt_journal_missing');
            return true;
        });
    }
    const [record] = await records();
    assert.equal(record.serverObservations.length, archive.REQUEST_ARCHIVE_LIMITS.observationsPerRecord + 1);
    assert.ok(archive.isReceiptClaim(record.serverObservations[0]), 'the standing claim is kept ahead of the newest eight');
    assert.ok(record.serverObservations.slice(1).every(observation => observation.status === 'unavailable'));
    assert.equal(h.runtime.snapshot().config.escape_override.acknowledgement, 'receipt_journal_missing');
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }), error => {
        assertSavedClaimRefusal(error, 'unavailable');
        return true;
    });
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0);

    // The server now reports the nullifier unknown: the claim no longer
    // stands, so the general warning applies again, even after a failed read.
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    assert.equal(await h.runtime.recoverPending({ retireLostKey: true, sweep: true }), false);
    assert.match(h.runtime.snapshot().config.escape_override.warning, /funds stay withdrawable from the next state/);
    assert.equal(h.runtime.snapshot().config.escape_override.acknowledgement, true);
    h.server.nullifier = () => { throw new Error('network down'); };
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
        assert.equal(error.code, 'transmitted_anchor_unconfirmed');
        assert.match(error.data.escape_override_warning, /funds stay withdrawable from the next state/);
        assert.equal(error.data.escape_override_acknowledgement, true);
        return true;
    });
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true });
    assert.equal(plan.mode, 'escape');
});

test('a receipt claim stands until a later unknown or clearance_reserved reading, and is never trimmed', () => {
    const state = noteState();
    const claim = (at, extra = { receipt: true }) => archive.requestObservation('finalized', 'escape', at, extra);
    const reading = (status, at) => archive.requestObservation(status, 'escape', at);
    const recordWith = (serverObservations, id = 'r') => ({ ...pendingRecord(state, id), serverObservations });
    const standing = (...records) => archive.standingReceiptClaim(records);

    assert.equal(standing(), null);
    assert.equal(standing(recordWith([reading('finalized', 1), reading('reserved', 2)])), null,
        'finalized without a receipt is no claim');
    assert.deepEqual(standing(recordWith([claim(1), reading('reserved', 2), reading('unavailable', 3),
        reading('finalized', 4), reading('unaccepted', 5)])), claim(1));
    assert.deepEqual(standing(recordWith([claim(1, { clientRequestId: 'named' })])), claim(1, { clientRequestId: 'named' }));
    for (const status of ['unknown', 'clearance_reserved']) {
        assert.equal(standing(recordWith([claim(1), reading(status, 2)])), null, `${status} contradicts the claim`);
        assert.deepEqual(standing(recordWith([reading(status, 1), claim(2)])), claim(2));
    }
    // Across the records of one state, by time.
    assert.equal(standing(recordWith([claim(1)], 'a'), recordWith([reading('unknown', 2)], 'b')), null);
    assert.deepEqual(standing(recordWith([reading('unknown', 1)], 'a'), recordWith([claim(2)], 'b')), claim(2));

    // Trimming keeps the newest eight observations and, ahead of them, the
    // newest claim or contradicting reading: a standing claim is never trimmed.
    const base = recordWith([]);
    const failures = from => Array.from({ length: 12 }, (_, index) => reading('unavailable', from + index));
    const kept = archive.mergeRequestArchiveRecord(base,
        { archiveId: base.archiveId, serverObservations: [reading('unknown', 1), claim(2), ...failures(10)] }, 100);
    assert.equal(kept.serverObservations.length, 9);
    assert.deepEqual(kept.serverObservations[0], claim(2));
    assert.deepEqual(kept.serverObservations.slice(1).map(observation => observation.at), [14, 15, 16, 17, 18, 19, 20, 21]);
    const again = archive.mergeRequestArchiveRecord(kept, { archiveId: kept.archiveId, serverObservations: failures(30) }, 200);
    assert.deepEqual(again.serverObservations[0], claim(2), 'the claim keeps its place through later merges');
    assert.deepEqual(again.serverObservations.slice(1).map(observation => observation.at), [34, 35, 36, 37, 38, 39, 40, 41]);
    const ended = archive.mergeRequestArchiveRecord(base,
        { archiveId: base.archiveId, serverObservations: [claim(1), reading('unknown', 2), ...failures(10)] }, 300);
    assert.deepEqual(ended.serverObservations.map(observation => observation.at), [2, 14, 15, 16, 17, 18, 19, 20, 21],
        'a contradicted claim is trimmed, and the reading that contradicted it is kept');
    assert.equal(ended.serverObservations[0].status, 'unknown');
    assert.equal(archive.standingReceiptClaim([ended]), null);
});

// Round-3 review: the contradicting reading may be saved on one record only
// (the override's refusal, a stale_root or clearance_reserved discard). It
// must outlive trimming exactly as long as a claim on another record does.
test('a reading that ends a receipt claim on one record keeps it ended when both records are trimmed', () => {
    const state = noteState();
    const claim = at => archive.requestObservation('finalized', 'escape', at,
        { receipt: true, clientRequestId: 'not-held-by-this-browser' });
    const reading = (status, at) => archive.requestObservation(status, 'override', at);
    const merge = (record, serverObservations, at) =>
        archive.mergeRequestArchiveRecord(record, { archiveId: record.archiveId, serverObservations }, at);
    for (const status of ['unknown', 'clearance_reserved']) {
        let a = merge(pendingRecord(state, 'archived'), [claim(2_000)], 2_000);
        let b = merge(pendingRecord(state, 'live'), [claim(2_000), reading(status, 3_000)], 3_000);
        assert.equal(archive.standingReceiptClaim([a, b]), null);
        for (let index = 0; index < 12; index += 1) {
            const failed = [reading('unavailable', 4_000 + index)];
            a = merge(a, failed, 4_000 + index);
            b = merge(b, failed, 4_000 + index);
        }
        assert.deepEqual(a.serverObservations[0], claim(2_000), 'the claim still stands on its own record');
        assert.deepEqual(b.serverObservations[0], reading(status, 3_000), `the ${status} reading is kept`);
        assert.equal(archive.standingReceiptClaim([a, b]), null, `${status} still ends the claim`);
        assert.equal(archive.standingReceiptClaim([b, a]), null, 'in either record order');
        // A later claim on either record stands again.
        a = merge(a, [claim(5_000)], 5_000);
        assert.deepEqual(archive.standingReceiptClaim([a, b]), claim(5_000));
    }
});

test('trimming never changes the standing claim, the newest eight observations or the newest reading in them', () => {
    const state = noteState();
    const limit = archive.REQUEST_ARCHIVE_LIMITS.observationsPerRecord;
    // Deterministic pseudo-random sequences (a linear congruential generator).
    let seed = 0x5eed;
    const random = bound => {
        seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
        return seed % bound;
    };
    const kinds = [
        ['unavailable'], ['unavailable'], ['unavailable'], ['unaccepted'], ['reserved'],
        ['finalized'], ['finalized', { receipt: true }], ['finalized', { clientRequestId: 'foreign' }],
        ['unknown'], ['clearance_reserved']
    ];
    const sameReading = (left, right) => assert.deepEqual(left ?? null, right ?? null);
    for (let sequence = 0; sequence < 300; sequence += 1) {
        const ids = ['a', 'b', 'c'].slice(0, 1 + random(3));
        const trimmed = ids.map(id => pendingRecord(state, id));
        const full = ids.map(() => []);
        let at = 1_000;
        for (let step = 0; step < 40; step += 1) {
            // Mostly later, sometimes the same millisecond, rarely an earlier clock.
            at = Math.max(1, at + [1, 1, 1, 0, -3][random(5)] * (1 + random(50)));
            const [status, extra = {}] = kinds[random(kinds.length)];
            const observation = archive.requestObservation(status, 'escape', at, extra);
            // Saved on every record (a sweep or a gate) or on one (a refusal or a discard).
            const targets = random(2) ? ids.map((_, index) => index) : [random(ids.length)];
            for (const index of targets) {
                trimmed[index] = archive.mergeRequestArchiveRecord(trimmed[index],
                    { archiveId: trimmed[index].archiveId, serverObservations: [observation] }, at);
                full[index].push(observation);
            }
            sameReading(archive.standingReceiptClaim(trimmed),
                archive.standingReceiptClaim(full.map(serverObservations => ({ serverObservations }))));
            trimmed.forEach((record, index) => {
                const kept = record.serverObservations;
                const all = full[index];
                assert.ok(kept.length <= limit + 1);
                assert.deepEqual(kept.slice(-limit), all.slice(-limit), 'the newest eight are never displaced');
                let cursor = 0;
                for (const observation of kept) {
                    while (cursor < all.length && JSON.stringify(all[cursor]) !== JSON.stringify(observation)) cursor += 1;
                    assert.ok(cursor < all.length, 'kept observations stay in order');
                    cursor += 1;
                }
                // The newest nullifier reading among the newest eight, else
                // only the kept claim or contradicting reading.
                const window = archive.lastDefinitiveObservation({ serverObservations: all.slice(-limit) });
                const newestReading = archive.lastDefinitiveObservation(record);
                if (window) sameReading(newestReading, window);
                else assert.ok(newestReading == null || newestReading === kept[0]);
            });
        }
    }
});

test('an unknown reading saved on the live journal alone keeps a receipt claim ended through later failed reads', async t => {
    const h = await freshWallet({ vaultRevision: 2 });
    const discarded = await discardFirstRequest(h);
    // A second chat is refused with 'replay' and its journal stays live.
    h.server.leasePost = () => { throw new HttpError('This request replays an earlier one.', 409, 'replay'); };
    h.server.leaseStatus = () => { throw new HttpError('Not found', 404, 'not_found'); };
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'replay' });
    const live = (await store.readBrowserWallet()).journal;
    const overrideAfter = live.created_at_ms + 43_200_000;
    // One lying answer: recovery saves the claim on both records.
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
        request_response: h.receiptFor(journalFor(noteState(), 'not-held-by-this-browser')) });
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), { code: 'receipt_journal_missing' });
    assert.ok((await records()).every(record => record.serverObservations.some(archive.isReceiptClaim)));
    assert.equal(h.runtime.snapshot().config.escape_override.acknowledgement, 'receipt_journal_missing');

    const realNow = Date.now;
    let elapsed = 3_600_000;
    t.mock.method(Date, 'now', () => realNow() + elapsed);
    // The server reports the nullifier unknown while its lease status fails:
    // the override's refusal before the grace saves that on the live record only.
    h.server.leaseStatus = () => { throw new HttpError('Service unavailable', 503, 'service_unavailable'); };
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }), error => {
        assert.equal(error.code, 'request_settlement_pending');
        assert.equal(error.data.nullifier_status, 'unknown');
        assert.equal(error.data.escape_override_acknowledgement, true);
        return true;
    });
    const byId = async id => (await records()).find(record => record.clientRequestId === id);
    assert.ok(!(await byId(discarded.clientRequestId)).serverObservations.some(observation => observation.context === 'override'),
        'the archived record never received that reading');
    assert.equal(archive.standingReceiptClaim(await records()), null);

    // Eight more attempts before the grace while the server is unreachable.
    h.server.nullifier = () => { throw new HttpError('Service unavailable', 503, 'service_unavailable'); };
    for (let attempt = 0; attempt < 8; attempt += 1) {
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }),
            error => {
                assert.equal(error.code, 'request_settlement_pending');
                assert.equal(error.data.nullifier_status, 'unavailable');
                assert.equal(error.data.escape_override_after, overrideAfter);
                assert.match(error.data.escape_override_warning, /funds stay withdrawable from the next state/);
                assert.equal(error.data.escape_override_acknowledgement, true);
                return true;
            });
    }
    const liveRecord = await byId(live.client_request_id);
    assert.equal(liveRecord.serverObservations[0].status, 'unknown', 'the reading that ended the claim is kept');
    assert.ok(liveRecord.serverObservations.slice(1).every(observation => observation.status === 'unavailable'));
    assert.ok(archive.isReceiptClaim(archive.lastDefinitiveObservation(await byId(discarded.clientRequestId))),
        'the archived record still holds the claim as its newest reading');
    assert.equal(archive.standingReceiptClaim(await records()), null);
    const shown = h.runtime.snapshot().config.escape_override;
    assert.match(shown.warning, /funds stay withdrawable from the next state/);
    assert.equal(shown.acknowledgement, true);

    // Past the grace the general acknowledgement escapes.
    elapsed = 13 * 3_600_000;
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: shown.acknowledgement });
    assert.equal(plan.mode, 'escape');
    assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
    assert.equal(h.workerOperations('prepareWithdrawal').length, 1);
    assert.equal((await byId(live.client_request_id)).disposition, 'abandoned_for_escape');
});

test('a clearance_reserved discard of the live journal keeps a receipt claim ended through later failed reads', async t => {
    const h = await freshWallet({ vaultRevision: 2 });
    const discarded = await discardFirstRequest(h);
    h.server.leasePost = () => { throw new HttpError('This request replays an earlier one.', 409, 'replay'); };
    h.server.leaseStatus = () => { throw new HttpError('Not found', 404, 'not_found'); };
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'replay' });
    const live = (await store.readBrowserWallet()).journal;
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
        request_response: h.receiptFor(journalFor(noteState(), 'not-held-by-this-browser')) });
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), { code: 'receipt_journal_missing' });
    assert.ok((await records()).every(record => record.serverObservations.some(archive.isReceiptClaim)));

    const realNow = Date.now;
    let elapsed = 3_600_000;
    t.mock.method(Date, 'now', () => realNow() + elapsed);
    // Operator remediation: recovery reads 'clearance_reserved' once and
    // discards the live journal, saving that reading on its record only.
    // Then the server is unreachable.
    let answers = 0;
    h.server.nullifier = () => {
        answers += 1;
        if (answers === 1) return { status: 'ok', nullifier_status: 'clearance_reserved' };
        throw new HttpError('Service unavailable', 503, 'service_unavailable');
    };
    assert.equal(await h.runtime.recoverPending({ retireLostKey: true }), true);
    const byId = async id => (await records()).find(record => record.clientRequestId === id);
    assert.equal((await byId(live.client_request_id)).disposition, 'discarded_clearance_reserved');
    assert.ok(!(await byId(discarded.clientRequestId)).serverObservations.some(observation =>
        observation.status === 'clearance_reserved'), 'the archived record never received that reading');
    assert.equal(archive.standingReceiptClaim(await records()), null);

    // Each attempt saves two failed reads on both records (the sweep and the gate).
    for (let attempt = 0; attempt < 5; attempt += 1) {
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
            assert.equal(error.code, 'transmitted_anchor_unconfirmed');
            assert.match(error.data.escape_override_warning, /funds stay withdrawable from the next state/);
            assert.equal(error.data.escape_override_acknowledgement, true);
            return true;
        });
    }
    assert.equal((await byId(live.client_request_id)).serverObservations[0].status, 'clearance_reserved',
        'the reading that ended the claim is kept');
    assert.equal(archive.standingReceiptClaim(await records()), null);
    const shown = h.runtime.snapshot().config.escape_override;
    assert.match(shown.warning, /funds stay withdrawable from the next state/);
    assert.equal(shown.acknowledgement, true);

    elapsed = 13 * 3_600_000;
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: shown.acknowledgement });
    assert.equal(plan.mode, 'escape');
    assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
    assert.equal(h.workerOperations('prepareWithdrawal').length, 1);
});

test('near expiry, a live request’s receipt_journal_missing refusal offers the override now', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    await h.runtime.prepareLeaseRequest();
    const journal = (await store.readBrowserWallet()).journal;
    h.server.leaseStatus = () => { throw new HttpError('Not found', 404, 'not_found'); };
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
        request_response: h.receiptFor(journalFor(noteState(), 'not-held-by-this-browser')) });
    // Well before the grace; only the note's expiry makes the override ready.
    h.chain.effectiveExpiry = BigInt(Math.floor(Date.now() / 1_000)) + h.chain.challengePeriod + 3_600n;
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }), error => {
        assert.equal(error.code, 'receipt_journal_missing');
        assert.ok(error.data.escape_override_after <= Date.now(), 'available now, not after the grace');
        assert.ok(journal.created_at_ms + 43_200_000 > Date.now());
        assertJournalMissingWarning(error.data.escape_override_warning);
        assert.equal(error.data.escape_override_acknowledgement, 'receipt_journal_missing');
        return true;
    });
    assert.ok((await store.readBrowserWallet()).journal, 'the general acknowledgement keeps the journal');
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: 'receipt_journal_missing' });
    assert.equal(plan.mode, 'escape');
    assert.equal((await records())[0].disposition, 'abandoned_for_escape');
});

test('the snapshot advertises the override time that binds, and none at a challenged state', async t => {
    const h = await freshWallet({ vaultRevision: 2 });
    const discarded = await discardFirstRequest(h);
    const realNow = Date.now;
    t.mock.method(Date, 'now', () => realNow() + 3_600_000);
    // An hour later a second request at the same state stays live.
    h.server.leasePost = () => { throw new HttpError('This request replays an earlier one.', 409, 'replay'); };
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'replay' });
    const live = (await store.readBrowserWallet()).journal;
    assert.ok(live.created_at_ms > discarded.journal.created_at_ms);
    const advertised = () => h.runtime.snapshot().config.unresolved_requests.map(entry => entry.escape_override_after);
    // The live request's own time gate binds first.
    assert.deepEqual(advertised(), [live.created_at_ms + 43_200_000, live.created_at_ms + 43_200_000]);

    await store.putBrowserRequestArchive([archive.buildRequestEvidenceRecord({ deploymentId: DEPLOYMENT, noteId: 7,
        anchor: GENESIS_ANCHOR, nullifier: nullifierFor(GENESIS_ANCHOR) })]);
    await h.runtime.reload();
    assert.deepEqual(advertised(), [null, null, null], 'a challenged state is never escaped again');
});

test('a finalized receipt without a client request id selects the same warning in the snapshot and the refusal', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    const discarded = await discardFirstRequest(h);
    const { client_request_id: _unnamed, ...receipt } = h.receiptFor(journalFor(noteState(), 'unnamed'));
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: receipt });
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION), error => {
        assertJournalMissingRefusal(error, discarded.journal.created_at_ms + 43_200_000);
        return true;
    });
    const observed = archive.lastDefinitiveObservation((await records())[0]);
    assert.deepEqual({ status: observed.status, receipt: observed.receipt, named: 'clientRequestId' in observed },
        { status: 'finalized', receipt: true, named: false });
    assertJournalMissingWarning(h.runtime.snapshot().config.escape_override.warning);
    assert.equal(h.runtime.snapshot().config.escape_override.acknowledgement, 'receipt_journal_missing');
    // A finalized reading without any receipt stays receipt_response_missing.
    assert.deepEqual(archive.requestObservation('finalized', 'escape', 1, { receipt: false }),
        { status: 'finalized', context: 'escape', at: 1 });
    assert.deepEqual(archive.requestObservation('reserved', 'escape', 1, { receipt: true, clientRequestId: 'x' }),
        { status: 'reserved', context: 'escape', at: 1 }, 'only a finalized reading carries a receipt');
});

test('client.withdraw offers the override for a plain escape and passes each acknowledgement through', async t => {
    // The genuine older-build case above, through the client's own settle step.
    const h = await freshWallet({ vaultRevision: 2 });
    h.server.leasePost = () => { throw new HttpError('This request replays an earlier one.', 409, 'replay'); };
    h.server.leaseStatus = () => { throw new HttpError('Not found', 404, 'not_found'); };
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
        request_response: h.receiptFor(journalFor(noteState(), 'discarded-by-an-older-build')) });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'replay' });
    const j1 = (await store.readBrowserWallet()).journal;

    const client = new ZkapiClient();
    client.config = { funding: { chain_id: 11155111, contract_address: VAULT } };
    client.wallet = { has_note: true, note: { note_id: 7, current_balance: 5_000_000 } };
    t.mock.method(client, 'assertBalanceNotClaimed', async () => {});
    t.mock.method(client, 'settleActiveLease', async () => h.runtime.settleActiveLease());
    t.mock.method(sharedRuntime, 'withEscapeOverrideData', error => h.runtime.withEscapeOverrideData(error));
    await assert.rejects(client.withdraw('escape', () => {}, { destination: DESTINATION }), error => {
        assertJournalMissingRefusal(error, j1.created_at_ms + 43_200_000);
        assert.match(error.shortMessage, /read its warning before using it/);
        return true;
    });

    // Only `true` and 'receipt_journal_missing' request the override, and
    // each reaches the runtime unchanged.
    t.mock.method(client, 'settleActiveLease', async () => {});
    t.mock.method(client, 'connectWallet', async () => DESTINATION);
    t.mock.method(client, 'readContractUint', async () => 1n);
    t.mock.method(client, 'recoverFailedWithdrawalSubmission', async () => null);
    t.mock.method(sharedRuntime, 'currentPreparedWithdrawal', async () => null);
    const seen = [];
    t.mock.method(sharedRuntime, 'prepareWithdrawal', async (_mode, _destination, options) => {
        seen.push(options.overrideUnsettledRequest);
        throw Object.assign(new Error('refused'), { code: 'request_settlement_pending' });
    });
    for (const value of ['receipt_journal_missing', true, 'yes', false]) {
        await assert.rejects(client.withdraw('escape', () => {}, { destination: DESTINATION, overrideUnsettledRequest: value }),
            { code: 'request_settlement_pending' });
    }
    assert.deepEqual(seen, ['receipt_journal_missing', true, undefined, undefined]);
});

test('an escape override never abandons another tab’s live key', async t => {
    const h = await freshWallet({ vaultRevision: 2, graceSeconds: 3_600 });
    await h.runtime.prepareLeaseRequest();
    const saved = await store.readBrowserWallet();
    const realNow = Date.now;
    const future = realNow() + 3_700_000;
    await store.writeBrowserWallet({ ...saved, lease: { ownerId: 'other-tab', sessionId: 'chat',
        client_request_id: saved.journal.client_request_id, expires_at: Math.floor(future / 1000) + 300,
        settle_after: Math.floor(future / 1000) + 600 } });
    h.server.leaseStatus = () => ({ status: 'active' });
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
    t.mock.method(Date, 'now', () => future);
    await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, { overrideUnsettledRequest: true }),
        { code: 'lease_tab_conflict' });
    assert.ok((await store.readBrowserWallet()).journal);
    assert.equal((await records())[0].disposition, 'pending');
});

test('worst-case and clamped receipts install with their proof-bound quote after a manifest pin change', async () => {
    for (const basis of ['worst_case', 'clamped']) {
        const h = await freshWallet();
        await h.runtime.prepareLeaseRequest();
        const journal = (await store.readBrowserWallet()).journal;
        const bound = journal.prepared_request.public_inputs.solvency_bound;
        h.runtime.config.funding = { ...h.runtime.config.funding, native_price_max_age_seconds: 4_500 };
        h.server.leaseStatus = () => ({ status: 'finalized' });
        h.server.requests = () => ({ request_response: h.receiptFor(journal, {
            billingQuote: { ...h.quote, answer: '200000000000' } }) });
        await assert.rejects(h.runtime.recoverPending({ retireLostKey: true }), /changed the authorized/);
        const charge = basis === 'worst_case' ? bound : bound - 1;
        h.server.requests = () => ({ request_response: h.receiptFor(journal, { charge,
            payload: { charge_basis: basis, ...(basis === 'worst_case' ? { settlement_reason: 'settlement_deadline' } : {}) } }) });
        assert.equal(await h.runtime.recoverPending({ retireLostKey: true }), true);
        assert.equal((await store.readBrowserWallet()).state.current_balance, 5_000_000 - charge);
        const settlement = h.runtime.snapshot().config.last_settlement;
        assert.equal(settlement.charge_basis, basis);
        assert.equal(settlement.charge_applied, charge);
        assert.equal(settlement.settlement_reason, basis === 'worst_case' ? 'settlement_deadline' : null);
    }
});

test('a journaled request made under older price pins settles unused instead of failing', async () => {
    const h = await freshWallet();
    await h.runtime.prepareLeaseRequest();
    const journal = (await store.readBrowserWallet()).journal;
    const newFunding = { ...h.runtime.config.funding, native_price_max_age_seconds: 4_500 };
    h.runtime.config.funding = newFunding;
    h.runtime.nativeBillingQuote = async () => nativeQuote(newFunding);
    const verified = [];
    h.runtime.verifyLease = async (...args) => { verified.push(args); };
    h.server.leasePost = body => h.activeLease(body);
    h.server.leaseStatus = () => { throw new HttpError('Not found', 404, 'not_found'); };
    h.server.requests = id => {
        assert.equal(id, journal.client_request_id);
        return { request_response: h.receiptFor(journal, { charge: 0 }) };
    };
    const lease = await h.runtime.issueLease('chat');
    assert.notEqual(lease.client_request_id, journal.client_request_id, 'the old-pin key is never exposed');
    assert.deepEqual(verified[0][6], { proofBoundQuote: true });
    assert.equal(verified[0][2], journal.client_request_id);
    assert.equal(h.runtime.activeLease.client_request_id, lease.client_request_id);
});

test('restored challenged escape records evidence; a repeat escape needs the server receipt', async () => {
    const h = await freshWallet({ vaultRevision: 2, clearanceOwnershipProof: 'required' });
    const first = (await discardFirstRequest(h)).journal;
    const state = (await store.readBrowserWallet()).state;
    const nullifier = nullifierFor(state.current_anchor);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state: null });
    await store.putBrowserWithdrawal({ recordId: RECORD_ID, deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT, noteId: 7, mode: 'escape', phase: 'restored', chainStatus: 'active',
        destination: DESTINATION, finalBalance: state.current_balance, state, withdrawalNullifier: nullifier,
        startBlockNumber: 100, challengeEvidence: { noteId: 7, nullifier: word(nullifier),
            transactionHash: `0x${'cd'.repeat(32)}`, blockNumber: 120, finalizedBlock: 200, observedAt: 1 } });
    const background = (await store.listBrowserWithdrawals(DEPLOYMENT))[0];
    await store.restoreBrowserWithdrawal(RECORD_ID, { deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT }, background.revision);
    const evidence = (await records()).find(record => record.type === 'request_evidence');
    assert.equal(evidence.anchor, archive.feltKey(state.current_anchor));
    assert.deepEqual(evidence.sources, ['escape_challenged']);
    assert.equal(evidence.evidence.transactionHash, `0x${'cd'.repeat(32)}`);

    await h.runtime.reload();
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    for (const options of [{}, { overrideUnsettledRequest: true }]) {
        await assert.rejects(h.runtime.prepareWithdrawal('escape', DESTINATION, options), { code: 'anchor_challenged' });
    }
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0);

    h.server.clearance = body => ({ status: 'ok', withdrawal_nullifier: body.withdrawal_nullifier,
        signature: { r: '0x1', s: '0x2' } });
    const mutual = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(mutual.mode, 'mutual', 'evidence never blocks a mutual close the server reports unknown');
    assert.equal(h.serverCalls('POST', '/v2/withdraw/clearance')[0].body.ownership_proof.public_inputs.has_clearance, false);
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), preparedWithdrawal: null });
    await h.runtime.reload();

    h.server.calls.length = 0;
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(first) });
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor('0x9999'));
    assert.equal(h.serverCalls('GET', '/v2/nullifiers/').length, 1, 'the next state escapes without a server gate');
    assert.equal((await records()).find(record => record.type === 'request_evidence').disposition, 'superseded');
});

test('challenge evidence is never inferred from a reorged-out start, another nullifier or a canceled transaction', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    const state = (await store.readBrowserWallet()).state;
    const nullifier = nullifierFor(state.current_anchor);
    for (const challengeEvidence of [undefined, { noteId: 7, nullifier: word('0x1'), blockNumber: 120 },
        { noteId: 8, nullifier: word(nullifier), blockNumber: 120 }]) {
        await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state: null });
        await store.putBrowserWithdrawal({ recordId: RECORD_ID, deploymentId: DEPLOYMENT, chainId: 11155111,
            contractAddress: VAULT, noteId: 7, mode: 'escape', phase: 'restored', chainStatus: 'active',
            destination: DESTINATION, finalBalance: state.current_balance, state, withdrawalNullifier: nullifier,
            startBlockNumber: 100, ...(challengeEvidence ? { challengeEvidence } : {}) });
        const background = (await store.listBrowserWithdrawals(DEPLOYMENT))[0];
        await store.restoreBrowserWithdrawal(RECORD_ID, { deploymentId: DEPLOYMENT, chainId: 11155111,
            contractAddress: VAULT }, background.revision);
        assert.equal((await records()).length, 0);
    }

    await h.runtime.reload();
    const attempt = { operationId: 'late', transactionHash: `0x${'ef'.repeat(32)}`, noteId: 7, mode: 'escape',
        clearanceReserved: true, withdrawalNullifier: nullifier, deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT, destination: DESTINATION, status: 'submitted_late', observedAt: 1 };
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), lateWithdrawalAttempts: [attempt] });
    await h.runtime.resolveLateChallengedWithdrawalAttempt(attempt);
    assert.equal((await records()).length, 0, 'a replaced or canceled late transaction is not challenge evidence');

    const client = new ZkapiClient();
    client.config = { funding: { contract_address: VAULT, chain_id: 11155111 } };
    const topic = keccak256Hex('EscapeWithdrawalChallenged(uint32,uint256,uint256)');
    assert.equal(walletCodec.ABI.escapeChallengedEvent, topic);
    const challenged = { address: VAULT, topics: [topic, word(7)], data: `${word(nullifier)}${word(1).slice(2)}`,
        blockNumber: '0x78', transactionHash: `0x${'cd'.repeat(32)}`, removed: false };
    let logs = [challenged];
    const queries = [];
    client.setWalletProvider({ request: async ({ method, params }) => {
        assert.equal(method, 'eth_getLogs');
        queries.push(params[0]);
        return logs;
    } });
    const record = { mode: 'escape', noteId: 7, withdrawalNullifier: nullifier, startBlockNumber: 100 };
    const found = await client.finalizedEscapeChallenge(record, 200);
    assert.deepEqual({ ...found, observedAt: 0 }, { noteId: 7, nullifier: word(nullifier),
        transactionHash: `0x${'cd'.repeat(32)}`, blockNumber: 120, finalizedBlock: 200, observedAt: 0 });
    assert.deepEqual(queries[0], { address: VAULT, topics: [topic, word(7)], fromBlock: '0x64', toBlock: '0xc8' });
    for (const variant of [[], [{ ...challenged, data: `${word('0x1')}${word(1).slice(2)}` }],
        [{ ...challenged, removed: true }], [{ ...challenged, blockNumber: '0x12c' }],
        [{ ...challenged, address: `0x${'99'.repeat(20)}` }], [{ ...challenged, topics: [topic, word(8)] }]]) {
        logs = variant;
        assert.equal(await client.finalizedEscapeChallenge(record, 200), null);
    }
    client.setWalletProvider({ request: async () => { throw new Error('log range too large'); } });
    assert.equal(await client.finalizedEscapeChallenge(record, 200), null);
    assert.equal(await client.finalizedEscapeChallenge({ ...record, mode: 'mutual' }, 200), null);
});

test('closing or sanitizing a note supersedes its transmitted requests', async () => {
    const h = await freshWallet();
    await discardFirstRequest(h);
    await store.archiveBrowserWallet('withdrawn', 7);
    const [closed] = await records();
    assert.equal(closed.disposition, 'superseded');
    assert.equal(closed.journal.user_rerandomization, undefined);

    indexedDB.clear();
    const state = noteState();
    await store.putBrowserRequestArchive([pendingRecord(state, 'background-note'),
        pendingRecord(noteState({ note_id: 8 }), 'another-note')]);
    await store.putBrowserWithdrawal({ recordId: RECORD_ID, deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT, noteId: 7, mode: 'mutual', phase: 'closed_unconfirmed', destination: DESTINATION,
        state, finalBalance: 1 });
    await store.updateBrowserWithdrawal(RECORD_ID, { phase: 'closed', chainStatus: 'closed' }, { sanitize: true });
    const byId = Object.fromEntries((await records()).map(record => [record.clientRequestId, record]));
    assert.equal(byId['background-note'].disposition, 'superseded');
    assert.equal(byId['another-note'].disposition, 'pending');
});

// Byte-for-byte copies of sdk/services/browserWalletStore.js at 045b444 (the
// last build without the request archive) and of the one module it imports,
// vendored so this check never depends on git history.
const LEGACY_STORE_FIXTURE = new URL('./fixtures/legacy-store-045b444/', import.meta.url);
const LEGACY_STORE_SHA256 = Object.freeze({
    'browserWalletStore.js': 'c27189f8d0ff66c00a6bf10b1c743c2449eeae0a2ead8ef513556026527cb3a9',
    'zkapiWithdrawalRecovery.mjs': '4d54c9f44d9674631edf8e84a7db7e266d23492f6302820322ef8fbd21151d05'
});

test('old-build compatibility: request records leave deposit history and note archives unchanged', async () => {
    indexedDB.clear();
    const state = noteState();
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    assert.ok(indexedDB.versions.length > 0 && indexedDB.versions.every(version => version === 3),
        'the shared database version is never bumped');
    const baseline = (await store.readBrowserWalletSnapshot(DEPLOYMENT)).deposits;
    const evidence = archive.buildRequestEvidenceRecord({ deploymentId: DEPLOYMENT, noteId: 9,
        anchor: '0x99', nullifier: nullifierFor('0x99') });
    await store.putBrowserRequestArchive([pendingRecord(state, 'compat-request'), evidence]);
    assert.deepEqual((await store.readBrowserWalletSnapshot(DEPLOYMENT)).deposits, baseline);
    assert.equal(indexedDB.stores.get('deposits').size, baseline.length);

    // A missing or edited fixture fails here; it is never skipped.
    for (const [file, sha256] of Object.entries(LEGACY_STORE_SHA256)) {
        const bytes = await readFile(new URL(file, LEGACY_STORE_FIXTURE));
        assert.equal(createHash('sha256').update(bytes).digest('hex'), sha256, `${file} is the frozen 045b444 copy`);
    }
    const legacy = await import(new URL('browserWalletStore.js', LEGACY_STORE_FIXTURE).href);
    assert.deepEqual((await legacy.readBrowserWalletSnapshot(DEPLOYMENT)).deposits, baseline);
    await legacy.archiveBrowserWallet('closed', 7);
    const after = await records();
    assert.equal(after.length, 2, 'an older build never rewrites or drops request records');
    assert.ok(after.every(record => archive.isUnresolved(record)));
    assert.deepEqual((await legacy.readBrowserWalletSnapshot(DEPLOYMENT)).deposits.map(row => row.noteId),
        baseline.map(row => row.noteId));
});

test('a failing automatic settlement backs off instead of polling every two seconds', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const runtime = new BrowserWalletRuntime();
    runtime.activeLease = { settle_after: 0, inFlight: 0 };
    const delays = [];
    const schedule = runtime.scheduleSettlement.bind(runtime);
    runtime.scheduleSettlement = delay => { delays.push(delay); return schedule(delay); };
    runtime.retireActiveLease = async () => { throw new Error('settlement unavailable'); };
    runtime.scheduleSettlement(0);
    for (let round = 0; round < 7; round += 1) {
        t.mock.timers.tick(delays.at(-1));
        await new Promise(resolve => setImmediate(resolve));
    }
    assert.deepEqual(delays, [0, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000]);
    runtime.activeLease = null;
    t.mock.timers.tick(60_000);
});

test('capabilities come only from the build-pinned trust anchor', async () => {
    const runtime = new BrowserWalletRuntime();
    runtime.manifest = { vault_revision: 2, clearance_ownership_proof: 'required' };
    runtime.browserConfig = { trusted_deployment: {} };
    assert.deepEqual(runtime.vaultCapabilities(), { vaultRevision: 1, hardenedVault: false,
        clearanceOwnershipProof: null, sendOwnershipProof: false });
    runtime.browserConfig = { trusted_deployment: { vault_revision: 2 } };
    assert.deepEqual(runtime.vaultCapabilities(), { vaultRevision: 2, hardenedVault: true,
        clearanceOwnershipProof: null, sendOwnershipProof: true });
    runtime.browserConfig = { trusted_deployment: { clearance_ownership_proof: 'optional' } };
    assert.equal(runtime.vaultCapabilities().hardenedVault, false);
    assert.equal(runtime.vaultCapabilities().sendOwnershipProof, true);
    for (const [seconds, expected] of [[undefined, 43_200], [60, 3_600], [10_000_000, 604_800], [7_200, 7_200], ['7200', 43_200]]) {
        runtime.browserConfig = { unsettled_request_escape_after_seconds: seconds };
        assert.equal(runtime.unsettledRequestEscapeGraceMs(), expected * 1_000);
    }

    const config = JSON.parse(await readFile(new URL('../assets/config/sepolia.json', import.meta.url), 'utf8'));
    const funding = nativeFunding();
    const trusted = { ...config.trusted_deployment, ...funding, rpc_url: funding.demo_rpc_url, billing_token_address: null };
    const manifest = { ...trusted, protocol_version: 2, proof_backend: 'groth16_bn254',
        proof_setup: { circuit_id: trusted.circuit_id, request_proving_key_sha256: trusted.request_proving_key_sha256,
            withdrawal_proving_key_sha256: trusted.withdrawal_proving_key_sha256 },
        privacy_mode: { openrouter_inference_base: trusted.openrouter_inference_base, verifier_url: trusted.verifier_url } };
    runtime.browserConfig = { ...config, trusted_deployment: trusted };
    assert.doesNotThrow(() => runtime.validateManifestTrust(manifest));
    for (const change of [{ vault_revision: 0 }, { vault_revision: '2' }, { vault_revision: 1.5 },
        { clearance_ownership_proof: 'always' }]) {
        runtime.browserConfig = { ...config, trusted_deployment: { ...trusted, ...change } };
        assert.throws(() => runtime.validateManifestTrust(manifest), /invalid trusted/);
    }
    runtime.browserConfig = { ...config, trusted_deployment: { ...trusted, vault_revision: 2, clearance_ownership_proof: 'required' } };
    assert.doesNotThrow(() => runtime.validateManifestTrust(manifest));
});
