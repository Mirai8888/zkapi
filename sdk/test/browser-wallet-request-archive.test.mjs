import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
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
const { BrowserWalletRuntime } = await import('../services/browserWalletRuntime.js');
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
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'receipt_journal_missing' });
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

test('the per-state bound fails closed before proving, and only expired corroborated discards are evicted', async () => {
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
    const discarded = (index, observedAt) => archive.buildRequestJournalRecord({
        deploymentId: DEPLOYMENT, state,
        journal: journalFor(state, `stale-${index}`, { requestTime, createdAt: requestTime * 1000 + index }),
        disposition: 'discarded_stale_root',
        observations: [archive.requestObservation('unknown', 'stale_root', observedAt)]
    });
    await store.putBrowserRequestArchive([
        ...Array.from({ length: 15 }, (_, index) => discarded(index, requestTime * 1000 + 60_000)),
        discarded(15, requestTime * 1000 + 1_300_000)
    ]);
    const merged = await store.putBrowserRequestArchive([pendingRecord(state, 'fresh')], { deploymentId: DEPLOYMENT });
    assert.equal(merged.find(record => record.clientRequestId === 'stale-15').disposition, 'superseded');
    assert.equal(merged.find(record => record.clientRequestId === 'stale-0').disposition, 'discarded_stale_root',
        'a discard observed inside the acceptance window is never evicted');
    assert.equal(merged.find(record => record.clientRequestId === 'fresh').disposition, 'pending');
    await assert.rejects(store.putBrowserRequestArchive([pendingRecord(state, 'again')]), { code: 'request_archive_limit' });
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

test('old-build compatibility: request records leave deposit history and note archives unchanged', async t => {
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

    let legacy = null;
    try {
        const repository = fileURLToPath(new URL('../..', import.meta.url));
        const source = execFileSync('git', ['show', '045b444:sdk/services/browserWalletStore.js'],
            { cwd: repository, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
        const recovery = pathToFileURL(fileURLToPath(new URL('../services/zkapiWithdrawalRecovery.mjs', import.meta.url))).href;
        legacy = await import(`data:text/javascript,${encodeURIComponent(
            source.replace("'./zkapiWithdrawalRecovery.mjs'", JSON.stringify(recovery)))}`);
    } catch {
        // A shallow clone has no base revision; the current-store checks above still apply.
    }
    if (!legacy) {
        t.diagnostic('base revision 045b444 unavailable; skipped the legacy store module check');
        return;
    }
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
