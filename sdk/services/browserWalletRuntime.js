import { browserSdkOptions, beginBrowserSdkInitialization, browserSdkTransport } from '../configure.js';
import { assertHardenedVault, assertNativeVault, validateNativeFunding, validateNativeQuote, validateProofBoundQuote, readNativeQuote, readVaultWord, nativeUnitsForUsd, nativeUsdMicros, sameNativeQuote, requestBillingQuote, vaultRevisionMismatch, vaultViewMissing } from './zkapiNativeEth.mjs';
import { CHAT_SPENDING_TIER_USD } from './zkapiRequestCompat.mjs';
import { TestnetPasswordAuth, testnetPasswordRequired } from './testnetPasswordAuth.mjs';
import { sameFelt, waitForExpectedActiveRoot } from './zkapiWithdrawalRoot.mjs';
import { isUnsubmittedParkedMutualWithdrawal } from './zkapiWithdrawalRecovery.mjs';
import {
    REQUEST_EVIDENCE_TYPE,
    REQUEST_JOURNAL_TYPE,
    anchorArchiveCapacity,
    buildRequestJournalRecord,
    earliestLocalTransmission,
    feltKey,
    isReceiptClaim,
    journalClientRequestId,
    lastDefinitiveObservation,
    lastObservation,
    requestObservation,
    standingReceiptClaim,
    transmittedAnchorDecision,
    unresolvedRequestArchiveAt
} from './zkapiRequestArchive.mjs';
import {
    archiveBrowserWallet,
    assertBrowserBackgroundWithdrawalAvailable,
    browserRuntimeHoldsState,
    authorizeBrowserWithdrawalFinalizationRetry,
    claimBrowserWithdrawalStartReplacement,
    claimBrowserBackgroundWithdrawalSubmission,
    claimBrowserWithdrawalFinalization,
    claimBrowserWithdrawalFinalizationReplacement,
    commitBrowserWallet,
    createWalletChannel,
    detachBrowserClosedWithdrawal,
    detachBrowserEscapeWithdrawal,
    listBrowserWithdrawals,
    isBrowserBackgroundWithdrawalPreparationCancelable,
    markBrowserWithdrawalFinalizationAmbiguous,
    markBrowserBackgroundWithdrawalAmbiguous,
    markBrowserWithdrawalFinalizationMissingReceipts,
    parkBrowserWithdrawal,
    projectBrowserDeposits,
    putBrowserRequestArchive,
    readBrowserWalletSnapshot,
    recordBrowserExpiryClaims,
    releaseBrowserWithdrawalFinalization,
    releaseBrowserWithdrawalFinalizationReplacementClaim,
    releaseBrowserWithdrawalStartSubmission,
    releaseBrowserBackgroundWithdrawalSubmission,
    rememberBrowserBackgroundWithdrawalMetadata,
    rememberBrowserBackgroundWithdrawalTransaction,
    rememberBrowserWithdrawalFinalization,
    rememberBrowserWithdrawalFinalizationSubmissionMetadata,
    requestPersistentStorage,
    repairBrowserUnsubmittedBackgroundWithdrawal,
    resolveBrowserBackgroundWithdrawalForRetry,
    resolveBrowserChallengedFinalization,
    restoreBrowserWithdrawal,
    saveBrowserBackgroundWithdrawalPlan,
    transferBrowserLateWithdrawalAttempt,
    updateBrowserWithdrawal,
    withBrowserWalletLock,
    writeBrowserWallet
} from './browserWalletStore.js';

// Escape override for an unsettled transmitted request (hardened vaults only):
// the default grace must exceed the server's maximum settlement deadline, so
// an honest operator has finalized (and an honest watcher challenged) first.
const UNSETTLED_REQUEST_ESCAPE_AFTER_SECONDS = Object.freeze({
    default: 43_200,
    minimum: 3_600,
    maximum: 604_800
});
// Allow the override early when waiting for the grace could let the note
// expire: a challenged escape still needs a full challenge period plus margin.
const ESCAPE_OVERRIDE_EXPIRY_MARGIN_SECONDS = 6 * 3_600;
const ESCAPE_OVERRIDE_WARNING = 'An escape while a private request is unsettled can be challenged if the server later finalizes that request. On this vault a challenge only costs the escape gas and delay: the note becomes active again and the wallet applies the finalized receipt, so the funds stay withdrawable from the next state.';
// receipt_journal_missing keeps the override: only a receipt that verifies may
// veto it, because a lying server or gateway can claim 'finalized' with a
// receipt this wallet cannot apply. A genuine claim makes the challenge
// certain, so that case has its own warning, and the override proceeds there
// only with that case's own acknowledgement (overrideUnsettledRequest:
// 'receipt_journal_missing'), never with the general `true`. A saved claim
// stands until the server reports the nullifier unknown or clearance_reserved,
// so a failed or different later read never brings back the general case.
const RECEIPT_JOURNAL_MISSING_OVERRIDE_WARNING = 'The server claims a finalized receipt for this balance that this wallet cannot apply. If that claim is genuine, the escape will be challenged, its gas is lost and the note then needs the operator’s help. If it is false, the escape is the only exit.';
const RECEIPT_JOURNAL_MISSING_ACKNOWLEDGEMENT = 'receipt_journal_missing';
const RECEIPT_JOURNAL_MISSING_MESSAGE = 'The server reports a finalized private request for this balance that this browser cannot apply.';
// The same refusal when it rests on a claim that an earlier read saved.
const RECEIPT_JOURNAL_MISSING_EARLIER_MESSAGE = 'The server earlier reported a finalized private request for this balance that this browser cannot apply.';
const DEPOSITS_CLOSED_MESSAGE = 'This deployment no longer accepts new deposits. Existing balances and deposits already started can still be completed, recovered and withdrawn.';
const REQUEST_ARCHIVE_LIMIT_MESSAGE = 'Too many unsettled private requests are recorded for this balance state, so no new chat can start from it. Chats resume only if the server settles one of them; otherwise withdraw this balance.';
const STALE_ROOT_RETRY_DELAYS_MS = Object.freeze([2_000, 4_000, 8_000, 16_000]);
const CLEARANCE_RETRY_DELAYS_MS = Object.freeze([1_000, 2_000, 4_000, 8_000]);
// The reference gateway's own 429: the request never reached the API.
const CLEARANCE_GATEWAY_THROTTLED = 'gateway_rate_limited';
// Server refusals of a proof-less clearance that reserved nothing.
const CLEARANCE_NOTHING_RESERVED = new Set(['clearance_ownership_required', 'legacy_clearance_capacity']);
const CLEARANCE_THROTTLED_WITHDRAWAL_ONLY_MESSAGE = 'The service is receiving too many requests and did not grant this mutual close. Its ownership proof was already sent, and on this vault a private request from this balance could let that proof burn the balance, so the balance stays withdrawal-only. Try the withdrawal again in a moment, or escape.';
const TRANSMITTED_OWNERSHIP_MESSAGE = 'This balance’s current state was already sent with a private request, and this vault can permanently burn a challenged escape. The server asks for an ownership proof, which works as such an escape, so this wallet does not send one from this state. A private chat that settles moves the balance to a new state that can be withdrawn; otherwise wait for the pending request to settle or ask the operator.';
const SETTLEMENT_RETRY_MIN_MS = 2_000;
const SETTLEMENT_RETRY_MAX_MS = 60_000;
const VAULT_SELECTORS = Object.freeze({
    currentRoot: '0xfdab463d',
    challengePeriod: '0xf3f480d9',
    effectiveExpiry: '0x7cb4a03c',
    challengedNullifiers: '0x6cda756a'
});
const WITHDRAWAL_RESTART = Symbol('withdrawal-restart');
const REQUEST_PUBLIC_INPUT_FIELDS = Object.freeze([
    'request_nullifier', 'authorization_tag', 'anonymous_commitment_x', 'anonymous_commitment_y',
    'solvency_bound', 'request_time'
]);

/** The warning that goes with an escape override offered for a refusal code. */
function escapeOverrideWarning(code) {
    return code === 'receipt_journal_missing' ? RECEIPT_JOURNAL_MISSING_OVERRIDE_WARNING : ESCAPE_OVERRIDE_WARNING;
}

/** The overrideUnsettledRequest value that acknowledges that code's warning. */
function escapeOverrideAcknowledgement(code) {
    return code === 'receipt_journal_missing' ? RECEIPT_JOURNAL_MISSING_ACKNOWLEDGEMENT : true;
}

/** The escape override fields of a refusal that offers it. */
function escapeOverrideData(code, overrideAfter) {
    return {
        escape_override_after: overrideAfter,
        escape_override_warning: escapeOverrideWarning(code),
        escape_override_acknowledgement: escapeOverrideAcknowledgement(code)
    };
}

/**
 * The override code of a nullifier reading, fresh ({ status, response }) or
 * saved ({ status, receipt, clientRequestId }), taken after the receipt it
 * carried was offered for install. 'finalized' with a receipt that did not
 * install, so the note state is still current, is receipt_journal_missing.
 */
function readingOverrideCode(observed) {
    return isReceiptClaim(observed) ? 'receipt_journal_missing' : null;
}

/**
 * Whether the receipt_journal_missing case applies after a fresh reading: the
 * reading is such a claim, or a claim saved before it stands and the reading
 * does not contradict it ('unknown' or 'clearance_reserved').
 */
function journalMissingAfter(observed, savedClaim) {
    return readingOverrideCode(observed) === 'receipt_journal_missing'
        || (Boolean(savedClaim) && !['unknown', 'clearance_reserved'].includes(observed?.status));
}

/** A saved observation of a nullifier reading, marking and naming the receipt it carried. */
function readingObservation(observed, context) {
    return requestObservation(observed.status, context, Date.now(), {
        clientRequestId: observed.response?.client_request_id
            ? String(observed.response.client_request_id) : null,
        receipt: Boolean(observed.response)
    });
}

/**
 * A GET /v2/nullifiers answer as a reading: only 'unknown', 'reserved',
 * 'finalized' (with its response) and 'clearance_reserved' are readings;
 * anything else is 'unavailable'.
 */
function nullifierReading(recovery) {
    if (recovery?.status === 'not_found' && recovery.nullifier_status === 'unknown' && !recovery.request_response) {
        return { status: 'unknown', response: null };
    }
    if (recovery?.status === 'ok'
        && ['reserved', 'finalized', 'clearance_reserved'].includes(recovery.nullifier_status)) {
        return {
            status: recovery.nullifier_status,
            response: recovery.nullifier_status === 'finalized' ? recovery.request_response || null : null
        };
    }
    return { status: 'unavailable', response: null };
}

function browserConfigUrl() {
    const configured = browserSdkOptions().configUrl;
    if (!configured) throw new Error('Configure a trusted configUrl before initializing the zkAPI browser SDK.');
    return configured;
}
const REQUIRED_CIRCUIT_ID = 'zkapi-v2-concession-v1';
// Setups a bundle can be built for; the build-pinned profile names one, and
// the proof worker must run a bundle of exactly that setup.
const BUNDLE_SETUP_IDS = Object.freeze(['dev', 'mpc-1']);
// valid_until of kind 0 and 1 proofs (checked by the vault) and of kind 2
// ownership proofs (checked by the server), design §6.4 E0.
const WITHDRAWAL_PROOF_VALIDITY_SECONDS = 10_800;
const OWNERSHIP_PROOF_VALIDITY_SECONDS = 3_600;
// A saved withdrawal proof is reused only while this much of its validity
// remains, so a reused proof can still be signed and included in time.
const WITHDRAWAL_PROOF_REUSE_MARGIN_SECONDS = 1_800;
const MAX_RECOVERY_WAIT_MS = 45_000;
// OA may briefly throttle child-key creation. Keep retrying the same durable,
// idempotent lease request long enough to cross a one-minute limiter without
// ever reproving, waiting indefinitely, or amplifying the limiter with a tight
// retry loop. The production schedule is 5s, 10s, 20s, then 30s.
const LEASE_ISSUE_MAX_WAIT_MS = 75_000;
const LEASE_ISSUE_MAX_ATTEMPTS = 5;
const LEASE_ISSUE_INITIAL_RETRY_MS = 5_000;
const LEASE_ISSUE_MAX_RETRY_MS = 30_000;
// Never begin a potentially long frontier-model stream on a key that is near
// the server's independent settlement boundary. A follow-up inside this
// window transparently closes the old key and obtains a fresh key at the selected model tier.
const MIN_REQUEST_LEASE_REMAINING_SECONDS = 90;
const TAB_OWNER_STORAGE_KEY = 'zkapi-browser-tab-owner-v1';
const LATE_WITHDRAWAL_TERMINAL_STATUSES = new Set([
    'closed',
    'detached',
    'reverted',
    'challenged',
    'superseded',
    'quarantined'
]);
const LATE_DEPOSIT_TERMINAL_STATUSES = new Set(['confirmed', 'reverted', 'superseded']);

class BrowserWalletHttpError extends Error {
    constructor(message, status, code, data = null) {
        super(message);
        this.name = 'BrowserWalletHttpError';
        this.status = status;
        this.code = code;
        this.data = data;
    }
}

/** A 429's retry_after_seconds (body or Retry-After header) in milliseconds, else 0. */
function retryAfterMilliseconds(error) {
    const seconds = Number(error?.data?.retry_after_seconds);
    return Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds * 1_000) : 0;
}

/**
 * The refusal of a mutual close at a transmitted state of a vault without
 * non-destructive challenges, when the server will not grant a proof-less
 * clearance: `error` is that answer (null when refused before asking).
 */
function transmittedOwnershipRefusal(error) {
    return new BrowserWalletHttpError(TRANSMITTED_OWNERSHIP_MESSAGE, 409, 'transmitted_anchor_ownership_unsafe', {
        transmitted: true,
        clearance_error_code: error?.code || null
    });
}

/**
 * A gateway 429 that outlasted the retries of a clearance carrying an
 * ownership proof, on a vault whose challenge burns the nullifier: the same
 * code and retry hint, with `withdrawal_only` because the note keeps its
 * withdrawal-only marker.
 */
function clearanceThrottledAfterOwnershipProof(error) {
    const throttled = new BrowserWalletHttpError(CLEARANCE_THROTTLED_WITHDRAWAL_ONLY_MESSAGE,
        error?.status ?? 429, CLEARANCE_GATEWAY_THROTTLED, {
            ...(error?.data && typeof error.data === 'object' ? error.data : {}),
            withdrawal_only: true
        });
    throttled.cause = error;
    return throttled;
}

class WorkerBridge {
    constructor() {
        this.worker = new Worker(browserSdkOptions().workerUrl || new URL('./zkapiWasmWorker.js', import.meta.url), { type: 'module' });
        this.pending = new Map();
        this.sequence = 0;
        this.worker.addEventListener('message', (event) => {
            const entry = this.pending.get(event.data?.id);
            if (!entry) return;
            this.pending.delete(event.data.id);
            if (event.data.error) entry.reject(new Error(event.data.error));
            else entry.resolve(event.data.result);
        });
        this.worker.addEventListener('error', (event) => {
            const error = new Error(event.message || 'The zkAPI proof worker crashed.');
            for (const entry of this.pending.values()) entry.reject(error);
            this.pending.clear();
        });
    }

    call(operation, payload = {}) {
        const id = ++this.sequence;
        return new Promise((resolve, reject) => {
            this.pending.set(id, { resolve, reject });
            this.worker.postMessage({ id, operation, payload });
        });
    }
}

function normalizeUrl(value) {
    return String(value || '').replace(/\/+$/, '');
}

function throwIfAborted(signal) {
    if (!signal?.aborted) return;
    const error = new DOMException('The operation was aborted.', 'AbortError');
    error.isCancelled = true;
    throw error;
}

function exactTrustedUrl(supplied, expected, label) {
    if (!expected?.startsWith('https://') && !expected?.startsWith('http://127.0.0.1:')
        && !expected?.startsWith('http://localhost:')) {
        throw new Error(`${label} is not a secure or loopback URL.`);
    }
    if (normalizeUrl(supplied) !== normalizeUrl(expected)) {
        throw new Error(`${label} did not match the deployment trust anchor.`);
    }
}

function delay(milliseconds, signal) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, milliseconds);
        signal?.addEventListener('abort', () => {
            clearTimeout(timer);
            const error = new Error('Request aborted');
            error.name = 'AbortError';
            reject(error);
        }, { once: true });
    });
}

function isExplicitlyRetriableLeaseError(error) {
    const explicitlyRetriable = error?.data?.retriable === true
        || error?.data?.error?.retriable === true;
    // These responses require a new proof or local lost-key reconciliation;
    // repeatedly sending the same lease request cannot resolve either state.
    return explicitlyRetriable
        && !['stale_root', 'native_quote_expired', 'native_quote_superseded', 'lease_pending', 'lease_settlement_pending'].includes(error?.code);
}

function isExplicitlyRetriableLeaseRetirementError(error) {
    const explicitlyRetriable = error?.data?.retriable === true
        || error?.data?.error?.retriable === true;
    return isExplicitlyRetriableLeaseError(error)
        || (explicitlyRetriable
            && ['lease_pending', 'lease_settlement_pending'].includes(error?.code));
}

function isLeaseRateLimit(error) {
    return error?.status === 429
        || /^oa_(?:minute_request_limit|hourly_issuance_budget|rate_limited)$/.test(error?.code || '')
        || /(?:\b429\b|too many requests|rate[ -]?limit)/i.test(error?.message || '');
}

function leaseRetryAfterMilliseconds(error) {
    const candidates = [
        error?.data?.retry_after_seconds,
        error?.data?.error?.retry_after_seconds,
        error?.data?.detail?.retry_after_seconds,
        error?.data?.error?.detail?.retry_after_seconds
    ];
    for (const candidate of candidates) {
        const seconds = Number(candidate);
        if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds * 1_000);
    }
    return null;
}

function describeRetryDelay(milliseconds) {
    const seconds = Math.max(1, Math.ceil(milliseconds / 1_000));
    if (seconds < 60) return seconds === 1 ? '1 second' : `${seconds} seconds`;
    const minutes = Math.ceil(seconds / 60);
    if (minutes < 60) return minutes === 1 ? 'about 1 minute' : `about ${minutes} minutes`;
    const hours = Math.ceil(minutes / 60);
    return hours === 1 ? 'about 1 hour' : `about ${hours} hours`;
}

function makeLeaseRateLimitActionable(error, retryAfterMs = null) {
    if (!isLeaseRateLimit(error)) return error;
    error.shortMessage = retryAfterMs != null
        ? `Temporary-key capacity is full. Your message is saved and was not sent. Try again in ${describeRetryDelay(retryAfterMs)}.`
        : 'The temporary-key service is still busy. Your message is saved and was not sent; use Retry in a moment.';
    return error;
}

function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function browserTabOwnerId() {
    try {
        const existing = sessionStorage.getItem(TAB_OWNER_STORAGE_KEY);
        if (existing && /^[0-9a-f-]{36}$/i.test(existing)) return existing;
        const created = uuid();
        sessionStorage.setItem(TAB_OWNER_STORAGE_KEY, created);
        return created;
    } catch {
        return uuid();
    }
}

function retainAttemptHistory(attempts, terminalStatuses, terminalLimit = 32) {
    const unresolved = attempts.filter(attempt => !terminalStatuses.has(attempt.status));
    const terminal = attempts
        .filter(attempt => terminalStatuses.has(attempt.status))
        .slice(-terminalLimit);
    // An unresolved transaction is a recovery capability, not log history. It
    // must never be evicted merely because more wallet attempts were made.
    return [...terminal, ...unresolved];
}

function unresolvedLateWithdrawalForNote(runtime, noteId) {
    return (runtime?.lateWithdrawalAttempts || []).find(attempt =>
        Number(attempt.noteId) === Number(noteId)
        && !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt.status)) || null;
}

async function responsePayload(response) {
    const text = await response.text();
    try {
        return text ? JSON.parse(text) : {};
    } catch {
        return { raw: text };
    }
}

function isAbortError(error, signal = null) {
    return Boolean(signal?.aborted || error?.name === 'AbortError' || error?.isCancelled);
}

function abiWordHex(value) {
    return BigInt(value).toString(16).padStart(64, '0');
}

function withdrawalDestinationHex(value) {
    if (typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value)) return value.toLowerCase();
    if (!Array.isArray(value) || value.length !== 20
        || value.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) return null;
    return `0x${value.map(byte => byte.toString(16).padStart(2, '0')).join('')}`;
}

function preparedWithdrawalHashes(prepared) {
    return Array.isArray(prepared?.transactionHashes)
        ? prepared.transactionHashes
        : prepared?.transactionHash ? [prepared.transactionHash] : [];
}

function preparedWithdrawalHasSubmission(prepared) {
    return Boolean(prepared?.submissionId || preparedWithdrawalHashes(prepared).length);
}

function preparedWithdrawalNullifier(prepared) {
    return prepared?.withdrawalNullifier ?? prepared?.public_inputs?.withdrawal_nullifier ?? null;
}

/** A persisted server clearance is reusable only for the exact state nullifier. */
function validClearance(prepared, nullifier) {
    const clearance = prepared?.clearance;
    return Boolean(clearance?.signature && clearance.withdrawal_nullifier != null && nullifier != null
        && sameFelt(clearance.withdrawal_nullifier, nullifier));
}

// Everything of a note state except its bound (bound_at_state), which the
// prover sets on the state a request proof is made at.
const STATE_IDENTITY_FIELDS = Object.freeze(['protocol_version', 'chain_id', 'contract_address', 'note_id',
    'secret_s', 'deposit_amount', 'expiry_ts', 'current_balance', 'balance_blinding', 'current_commitment_x',
    'current_commitment_y', 'current_anchor', 'is_genesis', 'state_signature', 'prev_anchor']);

function sameStateExceptBound(next, current) {
    if (!next || typeof next !== 'object' || !current) return false;
    return STATE_IDENTITY_FIELDS.every(field => JSON.stringify(next[field] ?? null) === JSON.stringify(current[field] ?? null));
}

function nowSeconds() {
    return Math.floor(Date.now() / 1000);
}

/** A saved kind-0/1 proof is reused only while enough of its validity remains. */
function withdrawalProofStillValid(inputs) {
    const validUntil = Number(inputs?.valid_until);
    return Number.isSafeInteger(validUntil) && validUntil - nowSeconds() >= WITHDRAWAL_PROOF_REUSE_MARGIN_SECONDS;
}

class BrowserWalletRuntime extends EventTarget {
    constructor() {
        super();
        this.worker = null;
        this.browserConfig = null;
        this.manifest = null;
        this.config = null;
        this.runtime = null;
        this.withdrawals = [];
        this.deposits = [];
        this.otherDeploymentWithdrawals = [];
        this.otherDeploymentCredits = [];
        // Transmitted-request archive cache. Decisions use it only after
        // reload() under the global wallet lock.
        this.requestArchive = [];
        this.settlementFailures = 0;
        this.activeLease = null;
        this.initialized = false;
        this.initPromise = null;
        this.leasePromise = null;
        this.leasePromiseSession = null;
        this.leasePromiseSpendingLimitUsd = null;
        this.leaseAbortController = null;
        this.leaseWaiterCount = 0;
        this.leaseProgressListeners = new Set();
        this.lastLeaseProgress = null;
        this.retirementPromise = null;
        this.requestProverWarmup = null;
        this.settlementTimer = null;
        this.legacyMigrationInProgress = false;
        this.channel = null;
        // sessionStorage survives a reload in this tab but is isolated from an
        // independently opened browser tab. That lets crash recovery retire a
        // lost in-memory key without allowing another live tab to take it.
        this.ownerId = browserTabOwnerId();
    }

    async init() {
        beginBrowserSdkInitialization();
        if (this.initPromise) return this.initPromise;
        this.initPromise = this.initialize();
        return this.initPromise;
    }

    async initialize() {
        this.browserConfig = await this.loadBrowserConfig();
        const allowedManifests = (this.browserConfig.allowed_deployment_manifest_urls
            || [this.browserConfig.deployment_manifest_url])
            .filter(Boolean)
            .map(value => new URL(value, location.href).href);
        const requestedManifest = new URLSearchParams(location.search).get('zkapiDeployment');
        const storedManifest = localStorage.getItem('zkapi-browser-deployment');
        if (requestedManifest
            && !allowedManifests.includes(new URL(requestedManifest, location.href).href)) {
            throw new Error('The selected deployment manifest is not trusted by this application build.');
        }
        if (storedManifest
            && !allowedManifests.includes(new URL(storedManifest, location.href).href)) {
            localStorage.removeItem('zkapi-browser-deployment');
        }
        const configuredManifest = requestedManifest
            || (storedManifest && allowedManifests.includes(new URL(storedManifest, location.href).href)
                ? storedManifest
                : null)
            || this.browserConfig.deployment_manifest_url;
        if (!configuredManifest) throw new Error('The website has no zkAPI deployment manifest configured.');
        const manifestUrl = new URL(configuredManifest, location.href).href;
        if (!allowedManifests.includes(manifestUrl)) {
            throw new Error('The selected deployment manifest is not trusted by this application build.');
        }
        this.manifest = await this.directJson(manifestUrl);
        this.validateManifest(this.manifest);
        this.validateManifestTrust(this.manifest);
        localStorage.setItem('zkapi-browser-deployment', manifestUrl);
        this.config = this.buildClientConfig(this.manifest, this.browserConfig);
        this.testnetAuth = new TestnetPasswordAuth({
            funding: this.config.funding,
            fetch: (url, init) => this.remoteFetchRaw(url, init),
            requestPassword: browserSdkOptions().requestTestnetPassword
        });
        await assertNativeVault(this.config.funding);
        // A build-pinned vault_revision 2 enables the escape override and
        // proof reuse, which are safe only on a vault whose challenge does not
        // burn the nullifier. Require the hardened interface on chain first.
        if (this.vaultCapabilities().hardenedVault) await assertHardenedVault(this.config.funding);
        this.worker = new WorkerBridge();
        await this.assertWorkerBundle();
        // Initialization participates in the same global lock as every later
        // mutation. This prevents two same-origin deployment tabs from both
        // rebinding the singleton runtime and committing stale snapshots.
        await withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.deploymentId !== this.manifest.deployment_id) {
                this.runtime = await writeBrowserWallet({
                    ...this.runtime,
                    deploymentId: this.manifest.deployment_id,
                    billingAsset: 'native_eth'
                });
            }
            await this.discardClosedDepositDraftLocked();
            await this.recoverPendingLocked({ retireLostKey: true, quiet: true });
        });
        this.channel = createWalletChannel(this.manifest.deployment_id, () => {
            // A channel notification can arrive while this tab is awaiting a
            // proof or server response inside a wallet mutation. Reading the
            // singleton IndexedDB snapshot outside the global lock can then
            // install an older in-memory value which the mutation later
            // spreads into a commit. Queue the refresh behind mutations.
            void withBrowserWalletLock(this.manifest.deployment_id, () => this.reload())
                .then(() => this.dispatchEvent(new Event('change')))
                .catch(error => this.dispatchEvent(new CustomEvent('runtime-error', { detail: error })));
        });
        await requestPersistentStorage();
        this.initialized = true;
        return this.snapshot();
    }

    async loadBrowserConfig() {
        const response = await fetch(browserConfigUrl(), { cache: 'no-store', credentials: 'omit' });
        if (!response.ok) throw new Error(`Unable to load browser-config.json (${response.status}).`);
        return response.json();
    }

    deploymentProxyUrl(url) {
        const proxyPath = this.browserConfig?.deployment_api_proxy_path;
        if (!proxyPath) return null;
        const proxyBase = new URL(proxyPath, location.origin);
        if (proxyBase.origin !== location.origin || !proxyBase.pathname.endsWith('/')) {
            throw new Error('browser-config.json contains an invalid deployment API proxy path.');
        }
        const target = new URL(url, location.href);
        const trusted = this.browserConfig?.trusted_deployment;
        const trustedOrigins = new Set([
            trusted?.protocol_server_url,
            trusted?.indexer_url,
            this.browserConfig?.deployment_manifest_url,
            ...(this.browserConfig?.allowed_deployment_manifest_urls || [])
        ].filter(Boolean).map(value => new URL(value, location.href).origin));
        if (!trustedOrigins.has(target.origin)) return null;
        return new URL(`${target.pathname.replace(/^\/+/, '')}${target.search}`, proxyBase).href;
    }

    async directJson(url) {
        const proxyUrl = this.deploymentProxyUrl(url);
        let response = proxyUrl
            ? await fetch(proxyUrl, { cache: 'no-store', credentials: 'omit' })
            : null;
        // Local static development servers do not necessarily provide the
        // production rewrite. Fall back to the deployment URL only for that
        // unambiguous case; Vercel serves the trusted target at the proxy URL.
        if (!response || response.status === 404) {
            response = await fetch(url, { cache: 'no-store', credentials: 'omit' });
        }
        if (!response.ok) throw new Error(`Unable to load ${url} (${response.status}).`);
        return response.json();
    }

    validateManifest(manifest) {
        if (Number(manifest.protocol_version) !== 2 || manifest.proof_backend !== 'groth16_bn254') {
            throw new Error('The selected deployment is not a zkAPI v2 Groth16 deployment.');
        }
        if (manifest.proof_setup?.circuit_id !== REQUIRED_CIRCUIT_ID) {
            const error = new Error('This deployment uses an incompatible legacy proof circuit. Funding is unavailable until the operator publishes a new vault and concession-exit proof setup. Keep existing funds and recovery data with the legacy deployment.');
            error.code = 'incompatible_proof_circuit';
            throw error;
        }
        for (const field of ['deployment_id', 'contract_address', 'protocol_server_url', 'indexer_url']) {
            if (!manifest[field]) throw new Error(`The deployment manifest omitted ${field}.`);
        }
        if (!/^0x[0-9a-fA-F]{40}$/.test(manifest.contract_address)) {
            throw new Error('The deployment manifest contains an invalid contract address.');
        }
        validateNativeFunding(manifest);
        for (const field of ['protocol_server_url', 'indexer_url']) {
            const url = new URL(manifest[field]);
            if (url.protocol !== 'https:' && !['127.0.0.1', 'localhost'].includes(url.hostname)) {
                throw new Error(`The deployment ${field} is not HTTPS or loopback.`);
            }
        }
        if (!manifest.state_signing_key?.x || !manifest.clearance_signing_key?.x) {
            throw new Error('The deployment manifest omitted its pinned server signing keys.');
        }
        if (!manifest.privacy_mode?.openrouter_inference_base) {
            throw new Error('The deployment does not advertise prompt-private OpenRouter leases.');
        }
    }

    validateManifestTrust(manifest) {
        if (this.browserConfig.deployment_status === 'migration_required') {
            throw new Error('This application still pins a legacy vault. Configure a newly deployed note-bound vault before funding.');
        }
        const trusted = this.browserConfig.trusted_deployment;
        if (!trusted) {
            throw new Error('browser-config.json omitted its trusted deployment pins.');
        }
        if (trusted.deployment_status === 'not_deployed') {
            throw new BrowserWalletHttpError('This application pins a placeholder profile: no vault for this proof setup is deployed on this network yet.',
                409, 'deployment_not_deployed');
        }
        // Vault revision 3 only: the concession exit is not a monotone
        // upgrade of revision 2, so its own capability must be pinned.
        if (trusted.exit_concession !== 1) {
            throw new BrowserWalletHttpError('This application build supports only vaults with the concession exit (exit_concession 1).',
                409, 'exit_concession_required');
        }
        if (!BUNDLE_SETUP_IDS.includes(trusted.setup_id)) {
            throw new Error('browser-config.json contains an invalid trusted setup_id.');
        }
        const requireEqual = (actual, expected, label, normalize = value => String(value)) => {
            if (expected == null || normalize(actual) !== normalize(expected)) {
                throw new Error(`The deployment manifest changed its pinned ${label}.`);
            }
        };
        const lowercase = value => String(value || '').toLowerCase();
        const normalizedUrl = value => normalizeUrl(new URL(value).href);
        requireEqual(manifest.proof_setup?.circuit_id, trusted.circuit_id, 'proof circuit');
        requireEqual(manifest.deployment_id, trusted.deployment_id, 'deployment id');
        requireEqual(manifest.chain_id, trusted.chain_id, 'chain id', Number);
        requireEqual(manifest.contract_address, trusted.contract_address, 'vault address', lowercase);
        validateNativeFunding(manifest);
        validateNativeFunding(trusted);
        requireEqual(manifest.billing_asset, trusted.billing_asset, 'billing asset');
        requireEqual(manifest.billing_unit, trusted.billing_unit, 'billing unit');
        requireEqual(manifest.native_asset_wei_per_unit, trusted.native_asset_wei_per_unit, 'native asset scale');
        requireEqual(manifest.native_price_feed_address, trusted.native_price_feed_address, 'ETH price feed', lowercase);
        requireEqual(manifest.native_price_feed_decimals, trusted.native_price_feed_decimals, 'ETH price decimals', Number);
        requireEqual(manifest.native_price_max_age_seconds, trusted.native_price_max_age_seconds, 'ETH price freshness', Number);
        requireEqual(manifest.rpc_url, trusted.rpc_url, 'native asset RPC', normalizedUrl);
        requireEqual(manifest.protocol_server_url, trusted.protocol_server_url, 'protocol server', normalizedUrl);
        requireEqual(manifest.indexer_url, trusted.indexer_url, 'indexer', normalizedUrl);
        requireEqual(manifest.request_charge_cap, trusted.request_charge_cap, 'request charge cap', Number);
        for (const keyName of ['state_signing_key', 'clearance_signing_key']) {
            for (const coordinate of ['x', 'y']) {
                requireEqual(
                    manifest[keyName]?.[coordinate],
                    trusted[keyName]?.[coordinate],
                    `${keyName}.${coordinate}`,
                    lowercase
                );
            }
        }
        requireEqual(
            manifest.proof_setup?.request_proving_key_sha256,
            trusted.request_proving_key_sha256,
            'request proving key hash',
            lowercase
        );
        requireEqual(
            manifest.proof_setup?.withdrawal_proving_key_sha256,
            trusted.withdrawal_proving_key_sha256,
            'withdrawal proving key hash',
            lowercase
        );
        requireEqual(
            manifest.privacy_mode?.openrouter_inference_base,
            trusted.openrouter_inference_base,
            'OpenRouter origin',
            normalizedUrl
        );
        requireEqual(
            manifest.privacy_mode?.verifier_url,
            trusted.verifier_url,
            'OA verifier',
            normalizedUrl
        );
        // Escape and clearance capabilities come only from the build-pinned
        // trust anchor, never from the served manifest: a server claiming a
        // hardened vault must not unlock the escape override on an old one.
        if (trusted.vault_revision != null
            && (!Number.isSafeInteger(trusted.vault_revision) || trusted.vault_revision < 1)) {
            throw new Error('browser-config.json contains an invalid trusted vault_revision.');
        }
        if (trusted.clearance_ownership_proof != null
            && !['required', 'optional'].includes(trusted.clearance_ownership_proof)) {
            throw new Error('browser-config.json contains an invalid trusted clearance_ownership_proof.');
        }
        // The deposit cutoff of a deployment being drained, also from the
        // build-pinned profile only.
        if (trusted.deposits != null && !['open', 'closed'].includes(trusted.deposits)) {
            throw new Error('browser-config.json contains an invalid trusted deposits setting.');
        }
    }

    /**
     * Whether the build-pinned profile closed this deployment to new deposits
     * (trusted_deployment.deposits "closed"). Deposits already started stay
     * tracked, completable and recoverable; nothing new can be quoted or
     * prepared.
     */
    depositsClosed() {
        return this.browserConfig?.trusted_deployment?.deposits === 'closed';
    }

    depositsClosedError() {
        return new BrowserWalletHttpError(DEPOSITS_CLOSED_MESSAGE, 409, 'deposits_closed');
    }

    /**
     * On a closed deployment an unused deposit draft can never be promoted or
     * sent, so drop it: it would otherwise count as this deployment's wallet
     * state. A draft is never signed and holds no funds. Call under the lock.
     */
    async discardClosedDepositDraftLocked() {
        if (!this.depositsClosed() || !this.runtime?.depositQuote) return false;
        await this.commit({ ...this.runtime, depositQuote: null });
        return true;
    }

    /**
     * Deployment capabilities from the trusted (build-pinned) deployment.
     * vault_revision >= 2 is the hardened vault whose challenge is
     * non-destructive; absent means the currently deployed vaults (strict).
     */
    vaultCapabilities() {
        const trusted = this.browserConfig?.trusted_deployment || {};
        const vaultRevision = Number.isSafeInteger(trusted.vault_revision) && trusted.vault_revision >= 1
            ? trusted.vault_revision
            : 1;
        const clearanceOwnershipProof = ['required', 'optional'].includes(trusted.clearance_ownership_proof)
            ? trusted.clearance_ownership_proof
            : null;
        return {
            vaultRevision,
            hardenedVault: vaultRevision >= 2,
            clearanceOwnershipProof,
            sendOwnershipProof: clearanceOwnershipProof != null || vaultRevision >= 2
        };
    }

    unsettledRequestEscapeGraceMs() {
        const configured = this.browserConfig?.unsettled_request_escape_after_seconds;
        const seconds = Number.isSafeInteger(configured)
            ? Math.min(Math.max(configured, UNSETTLED_REQUEST_ESCAPE_AFTER_SECONDS.minimum),
                UNSETTLED_REQUEST_ESCAPE_AFTER_SECONDS.maximum)
            : UNSETTLED_REQUEST_ESCAPE_AFTER_SECONDS.default;
        return seconds * 1_000;
    }

    /**
     * The proof worker must run a bundle of the pinned circuit and setup: a
     * development bundle never proves for a ceremony profile, nor the reverse.
     */
    async assertWorkerBundle() {
        const trusted = this.browserConfig?.trusted_deployment || {};
        const identity = await this.worker.call('identity', {});
        if (identity?.circuit_id !== REQUIRED_CIRCUIT_ID || identity?.circuit_id !== trusted.circuit_id
            || identity?.setup_id !== trusted.setup_id) {
            throw new BrowserWalletHttpError(`The proof worker runs ${identity?.circuit_id}/${identity?.setup_id}, `
                + `but this deployment pins ${trusted.circuit_id}/${trusted.setup_id}.`, 409, 'setup_mismatch');
        }
    }

    buildClientConfig(manifest, browserConfig) {
        const keyBase = new URL(browserConfig.proving_keys_base_url || './proofs/', browserConfigUrl());
        const requestKey = new URL('request.pk', keyBase).href;
        const withdrawalKey = new URL('withdrawal.pk', keyBase).href;
        const requestVerifyingKey = new URL('request.vk', keyBase).href;
        const requestCap = Number(manifest.request_charge_cap);
        validateNativeFunding(manifest);
        return {
            ux_proposal: String(browserConfig.ux_proposal || 'quiet'),
            credits_per_usd: null,
            request_charge_cap: requestCap,
            request_charge_cap_usd: null,
            policy_charge_cap: Number(manifest.policy_charge_cap || requestCap),
            policy_enabled: Boolean(manifest.policy_enabled),
            upstream_kind: 'openrouter',
            direct_openrouter_available: true,
            request_mode: 'direct_openrouter',
            browser_wallet: true,
            active_lease: null,
            prepared_withdrawal: null,
            wallet_core: {
                protocol_version: Number(manifest.protocol_version),
                chain_id: Number(manifest.chain_id),
                contract_address: manifest.contract_address,
                request_charge_cap: requestCap,
                policy_charge_cap: Number(manifest.policy_charge_cap || requestCap),
                policy_enabled: Boolean(manifest.policy_enabled),
                state_signing_key: manifest.state_signing_key,
                clearance_signing_key: manifest.clearance_signing_key
            },
            proving_keys: {
                request: {
                    url: requestKey,
                    sha256: manifest.proof_setup?.request_proving_key_sha256
                },
                withdrawal: {
                    url: withdrawalKey,
                    sha256: manifest.proof_setup?.withdrawal_proving_key_sha256
                }
            },
            // The stale-device pre-check verifies operator evidence with the
            // build-pinned request.vk only.
            verifying_keys: {
                request: {
                    url: requestVerifyingKey,
                    sha256: browserConfig.trusted_deployment?.request_verifying_key_sha256
                }
            },
            openrouter: {
                inference_base: normalizeUrl(manifest.privacy_mode.openrouter_inference_base),
                verifier_url: normalizeUrl(manifest.privacy_mode.verifier_url),
                require_oa_key_source: browserConfig.require_oa_key_source !== false
            },
            funding: {
                contract_address: manifest.contract_address,
                chain_id: Number(manifest.chain_id),
                indexer_url: normalizeUrl(manifest.indexer_url),
                protocol_server_url: normalizeUrl(manifest.protocol_server_url),
                models: manifest.models || [],
                suggested_deposit_amount: Number(browserConfig.suggested_deposit_amount || requestCap * 100),
                demo_rpc_url: manifest.rpc_url || null,
                billing_token_symbol: 'ETH',
                billing_token_decimals: 9,
                billing_asset: manifest.billing_asset,
                billing_unit: manifest.billing_unit,
                native_asset_wei_per_unit: manifest.native_asset_wei_per_unit,
                native_price_feed_address: manifest.native_price_feed_address,
                native_price_feed_decimals: manifest.native_price_feed_decimals,
                native_price_max_age_seconds: manifest.native_price_max_age_seconds,
                demo_note_ttl_seconds: Number(manifest.note_ttl_seconds || 0) || null
            }
        };
    }

    snapshot() {
        const active = this.activeLease && this.activeLease.expires_at > Math.floor(Date.now() / 1000)
            ? {
                session_id: this.activeLease.sessionId,
                client_request_id: this.activeLease.client_request_id,
                expires_at: this.activeLease.expires_at,
                settle_after: this.activeLease.settle_after,
                spending_limit_usd: Number(this.activeLease.spending_limit_usd),
                station_id: this.activeLease.verification?.station_id || null
            }
            : null;
        const prepared = this.runtime?.preparedWithdrawal;
        const pendingDeposit = this.runtime?.pendingDeposit;
        const preparedHashes = new Set((Array.isArray(prepared?.transactionHashes)
            ? prepared.transactionHashes
            : prepared?.transactionHash ? [prepared.transactionHash] : [])
            .map(hash => String(hash).toLowerCase()));
        const replacementIdentities = new Set((prepared?.transactionAttempts || [])
            .filter(attempt => preparedHashes.has(String(attempt.hash || '').toLowerCase())
                && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                && Number.isSafeInteger(Number(attempt.nonce))
                && Number(attempt.nonce) >= 0)
            .map(attempt => `${attempt.from.toLowerCase()}:${Number(attempt.nonce)}`));
        const pendingDepositHashes = new Set((Array.isArray(pendingDeposit?.transactionHashes)
            ? pendingDeposit.transactionHashes
            : pendingDeposit?.transactionHash ? [pendingDeposit.transactionHash] : [])
            .map(hash => String(hash).toLowerCase()));
        const depositReplacementIdentities = new Set((pendingDeposit?.transactionAttempts || [])
            .filter(attempt => pendingDepositHashes.has(String(attempt.hash || '').toLowerCase())
                && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                && Number.isSafeInteger(Number(attempt.nonce))
                && Number(attempt.nonce) >= 0)
            .map(attempt => `${attempt.from.toLowerCase()}:${Number(attempt.nonce)}`));
        const config = this.config ? {
            ...this.config,
            deposits: this.depositsClosed() ? 'closed' : 'open',
            other_deployment_withdrawals: (this.otherDeploymentWithdrawals || []).map(record => ({
                deployment_id: record.deploymentId,
                record_id: record.recordId,
                note_id: record.noteId,
                mode: record.mode,
                phase: record.phase
            })),
            // Escape payouts another deployment's vault only credited. They
            // do not block a deposit here; the claim needs that profile.
            other_deployment_credits: (this.otherDeploymentCredits || []).map(credit => ({
                deployment_id: credit.deploymentId,
                record_id: credit.recordId,
                note_id: credit.noteId,
                chain_id: credit.chainId,
                contract_address: credit.contractAddress,
                destination: credit.destination,
                credited_amount: credit.creditedAmount
            })),
            active_lease: active,
            late_withdrawal_attempts: (this.runtime?.lateWithdrawalAttempts || [])
                .filter(attempt => !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(attempt.status))
                .map(attempt => ({
                    operation_id: attempt.operationId,
                    note_id: Number(attempt.noteId),
                    mode: attempt.mode,
                    destination: attempt.destination,
                    transaction_hash: attempt.transactionHash,
                    status: attempt.status,
                    error: attempt.error || null
                })),
            late_deposit_attempts: (this.runtime?.lateDepositAttempts || [])
                .filter(attempt => !LATE_DEPOSIT_TERMINAL_STATUSES.has(attempt.status))
                .map(attempt => ({
                    operation_id: attempt.operationId,
                    note_id: Number(attempt.noteId),
                    amount: Number(attempt.amount),
                    transaction_hash: attempt.transactionHash,
                    status: attempt.status
                })),
            pending_deposit: pendingDeposit ? {
                operation_id: pendingDeposit.operationId || null,
                phase: pendingDeposit.phase || (pendingDeposit.transactionHash ? 'submitted' : 'ambiguous'),
                amount: Number(pendingDeposit.amount),
                funding_quote_available: Boolean(this.config?.funding)
                    && this.canQuotePendingDeposit(pendingDeposit),
                next_note_id: Number(pendingDeposit.next_note_id),
                transaction_hash: pendingDeposit.transactionHash || null,
                transaction_hashes: Array.isArray(pendingDeposit.transactionHashes)
                    ? [...pendingDeposit.transactionHashes]
                    : pendingDeposit.transactionHash ? [pendingDeposit.transactionHash] : [],
                replacement_available: pendingDeposit.phase === 'dropped_or_pending'
                    && depositReplacementIdentities.size === 1
            } : null,
            prepared_withdrawal: prepared ? {
                mode: prepared.mode,
                phase: prepared.phase || (prepared.transactionHash ? 'submitted' : 'prepared'),
                note_id: prepared.public_inputs?.note_id ?? prepared.noteId ?? prepared.note_id,
                destination: Array.isArray(prepared.public_inputs?.destination)
                    ? `0x${prepared.public_inputs.destination.map(byte => Number(byte).toString(16).padStart(2, '0')).join('')}`
                    : prepared.destination,
                transaction_hash: prepared.transactionHash || null,
                clearance_reserved: prepared.clearanceReserved === true || prepared.mode === 'mutual',
                replacement_available: prepared.phase === 'dropped_or_pending'
                    && replacementIdentities.size === 1
            } : null,
            ...this.requestArchiveSummary()
        } : null;
        return {
            config,
            runtime: this.runtime,
            activeLease: active,
            deposits: this.deposits.map(record => ({ ...record,
                ...(record.expiryClaim ? { expiryClaim: { ...record.expiryClaim } } : {}) })),
            withdrawals: this.withdrawals.map(record => {
                const {
                    state: _state,
                    preparedWithdrawal: _prepared,
                    proof: _proof,
                    withdrawalNullifier: _nullifier,
                    challengeEvidence,
                    ...summary
                } = record;
                return { ...summary, challengeObserved: Boolean(challengeEvidence),
                    backgroundWithdrawalReady: isUnsubmittedParkedMutualWithdrawal(
                    record, this.runtime?.lateWithdrawalAttempts || []
                ), backgroundPreparationCancelable: Boolean(this.config && this.manifest)
                    && isBrowserBackgroundWithdrawalPreparationCancelable(
                        record, this.runtime, this.backgroundWithdrawalIdentity(record)
                    ) };
            })
        };
    }

    /** Public, proof-free view of transmitted requests at the selected note state. */
    requestArchiveSummary() {
        const { vaultRevision, hardenedVault } = this.vaultCapabilities();
        const graceMs = this.unsettledRequestEscapeGraceMs();
        const entries = this.archivedRequestsAt(this.runtime?.state);
        const overrideAfter = this.escapeOverrideAfter(this.runtime?.state, entries);
        // The warning and its acknowledgement follow the state's standing
        // receipt claim, as every refusal that offers the override does.
        const claimCode = standingReceiptClaim(entries) ? 'receipt_journal_missing' : null;
        const installed = (this.requestArchive || [])
            .filter(record => record.type === REQUEST_JOURNAL_TYPE && record.disposition === 'installed'
                && record.deploymentId === this.manifest?.deployment_id
                && Number(record.noteId) === Number(this.runtime?.state?.note_id))
            .sort((left, right) => Number(right.installedAt || right.updatedAt || 0)
                - Number(left.installedAt || left.updatedAt || 0))[0];
        return {
            vault_revision: vaultRevision,
            escape_override: hardenedVault
                ? {
                    grace_seconds: graceMs / 1_000,
                    warning: escapeOverrideWarning(claimCode),
                    acknowledgement: escapeOverrideAcknowledgement(claimCode)
                }
                : null,
            unresolved_requests: entries.map(entry => {
                const observed = lastObservation(entry);
                return {
                    client_request_id: entry.clientRequestId || null,
                    kind: entry.type === REQUEST_JOURNAL_TYPE ? 'request' : 'evidence',
                    disposition: entry.disposition,
                    created_at: Number(entry.createdAt) || null,
                    server_status: observed?.status || null,
                    server_status_at: observed?.at || null,
                    escape_override_after: overrideAfter
                };
            }),
            last_settlement: installed ? {
                client_request_id: installed.clientRequestId,
                charge_applied: installed.chargeApplied ?? null,
                charge_basis: installed.chargeBasis ?? null,
                settlement_reason: installed.settlementReason ?? null,
                installed_at: installed.installedAt ?? installed.updatedAt ?? null
            } : null
        };
    }

    archiveKey(state = this.runtime?.state) {
        const deploymentId = this.manifest?.deployment_id;
        if (!deploymentId || state?.note_id == null || state.current_anchor == null) return null;
        return { deploymentId, noteId: Number(state.note_id), anchor: state.current_anchor };
    }

    /** Unresolved transmitted requests and challenge evidence at a note state. */
    archivedRequestsAt(state = this.runtime?.state) {
        const key = this.archiveKey(state);
        return key ? unresolvedRequestArchiveAt(this.requestArchive, key) : [];
    }

    /**
     * When the escape override opens at a transmitted state on a hardened
     * vault, absent an imminent expiry: the grace after the live request's
     * transmission while one exists (its own time gate binds first), else
     * after the earliest archived one. Null where no override applies.
     */
    escapeOverrideAfter(state = this.runtime?.state, entries = this.archivedRequestsAt(state)) {
        if (!this.vaultCapabilities().hardenedVault
            || entries.some(entry => entry.type === REQUEST_EVIDENCE_TYPE)) return null;
        const earliest = earliestLocalTransmission(entries);
        if (earliest == null) return null;
        const live = state && state === this.runtime?.state ? Number(this.runtime?.journal?.created_at_ms) : NaN;
        return (Number.isSafeInteger(live) && live > earliest ? live : earliest) + this.unsettledRequestEscapeGraceMs();
    }

    /** A complete archive record for a journal at a state, or null when incomplete. */
    tryRequestJournalRecord(journal, state = this.runtime?.state, options = {}) {
        try {
            return buildRequestJournalRecord({
                deploymentId: this.manifest?.deployment_id,
                state,
                journal,
                ...options
            });
        } catch {
            return null;
        }
    }

    async saveRequestObservations(entries, observed, context) {
        if (!entries?.length || !observed?.status) return;
        try {
            const observation = readingObservation(observed, context);
            this.requestArchive = await putBrowserRequestArchive(entries.map(entry => ({
                archiveId: entry.archiveId,
                type: entry.type,
                serverObservations: [observation]
            })), { deploymentId: this.manifest.deployment_id });
        } catch (error) {
            // The decision already used the fresh observation in memory.
            console.warn('Unable to save a private request status observation.', error);
        }
    }

    async reload() {
        const deploymentId = this.manifest?.deployment_id || this.runtime?.deploymentId || null;
        const snapshot = await readBrowserWalletSnapshot(deploymentId);
        const storedRuntime = snapshot.runtime;
        const hasDurableState = browserRuntimeHoldsState(storedRuntime);
        if (this.manifest && hasDurableState
            && (!storedRuntime.deploymentId || storedRuntime.deploymentId !== this.manifest.deployment_id
                || (storedRuntime.billingAsset != null && storedRuntime.billingAsset !== 'native_eth'))) {
            throw new Error(`This browser contains a wallet for ${storedRuntime.deploymentId || 'an unidentified legacy deployment'}. Switch back to that deployment before using or withdrawing it.`);
        }
        this.runtime = storedRuntime.deploymentId
            && this.manifest
            && storedRuntime.deploymentId !== this.manifest.deployment_id
            ? { ...storedRuntime, deploymentId: this.manifest.deployment_id }
            : storedRuntime;
        this.withdrawals = snapshot.withdrawals;
        // Only another deployment's runtime can finish these; the snapshot
        // reports them so a host can switch profiles before funding here.
        this.otherDeploymentWithdrawals = snapshot.otherDeploymentWithdrawals || [];
        this.otherDeploymentCredits = snapshot.otherDeploymentCredits || [];
        this.deposits = snapshot.deposits;
        this.requestArchive = snapshot.requestArchive || [];
        return this.runtime;
    }

    notify() {
        this.channel?.postMessage({ updatedAt: this.runtime.updatedAt });
        this.dispatchEvent(new Event('change'));
    }

    async commit(next, options = {}) {
        const committed = await commitBrowserWallet({ ...next, deploymentId: this.manifest.deployment_id, billingAsset: 'native_eth' }, options);
        this.runtime = committed.runtime;
        // The same transaction returned the merged archive; no fallible read follows.
        if (committed.requestArchive) this.requestArchive = committed.requestArchive;
        this.deposits = projectBrowserDeposits(this.runtime, this.deposits,
            this.manifest.deployment_id, options.depositConfirmation);
        this.notify();
        return this.runtime;
    }

    async getDepositHistory() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.snapshot().deposits;
        });
    }

    async rememberExpiryClaims(claims) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const updated = await recordBrowserExpiryClaims(this.manifest.deployment_id, claims);
            await this.reload();
            if (updated.length) this.notify();
            return updated;
        });
    }

    async walletStatus() {
        await this.init();
        const status = await this.worker.call('walletStatus', {
            state: this.runtime.state,
            journal: this.runtime.journal
        });
        // Let the lightweight status needed for the first paint leave the
        // worker before beginning the CPU-heavy decode. The warm-up then runs
        // while a funded user reads or types, without delaying page readiness.
        if (this.runtime.state || this.runtime.pendingDeposit) {
            void this.prewarmRequestProver();
        }
        return status;
    }

    prewarmRequestProver() {
        if (!this.worker || !this.config?.proving_keys?.request) {
            return Promise.resolve(false);
        }
        if (this.requestProverWarmup) return this.requestProverWarmup;
        const warmup = this.worker.call('preloadRequestProver', {
            provingKey: this.config.proving_keys.request
        }).then(() => true).catch(error => {
            // Pre-warming is an optimization. A failed fetch/decode must stay
            // silent here and be retried by the normal Send path later.
            if (this.requestProverWarmup === warmup) this.requestProverWarmup = null;
            console.warn('Unable to pre-warm the zkAPI request prover.', error);
            return false;
        });
        this.requestProverWarmup = warmup;
        return warmup;
    }

    async hasPendingLease() {
        await this.init();
        await this.reload();
        return Boolean(this.activeLease || this.runtime?.journal);
    }

    async getPendingLeaseOwner() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.runtime?.lease?.sessionId || this.activeLease?.sessionId || null;
        });
    }

    async remoteFetch(url, init = {}) {
        return this.testnetAuth ? this.testnetAuth.fetch(url, init) : this.remoteFetchRaw(url, init);
    }

    async remoteFetchRaw(url, init = {}) {
        const proxyUrl = this.deploymentProxyUrl(url);
        if (proxyUrl) {
            try {
                const response = await fetch(proxyUrl, {
                    ...init,
                    credentials: 'omit'
                });
                if (response.status !== 404) return response;
            } catch {
                // A local static development server may not implement the
                // production rewrite. Keep the existing privacy-proxy/direct
                // fallback available there.
            }
        }
        return browserSdkTransport(url, init, { preferProxy: true });
    }

    async remoteJson(url, init = {}) {
        const response = await this.remoteFetch(url, init);
        if (response.status === 401 && this.testnetAuth?.protects(url)) throw testnetPasswordRequired();
        let payload = await responsePayload(response);
        if (!response.ok) {
            const retryAfterHeader = response.headers.get('retry-after');
            const retryAfter = retryAfterHeader == null || retryAfterHeader.trim() === ''
                ? Number.NaN
                : Number(retryAfterHeader);
            if (Number.isFinite(retryAfter) && retryAfter >= 0
                && payload?.retry_after_seconds == null) {
                payload = { ...payload, retry_after_seconds: retryAfter };
            }
            const details = payload?.error && typeof payload.error === 'object'
                ? payload.error
                : {};
            throw new BrowserWalletHttpError(
                details.error_message
                    || details.message
                    || payload.error_message
                    || payload.message
                    || `HTTP ${response.status}`,
                response.status,
                details.error_code
                    || details.code
                    || payload.error_code
                    || payload.code,
                payload
            );
        }
        return payload;
    }

    async treePath(noteId, requireExisting = true, expectedActiveRoot = null) {
        return waitForExpectedActiveRoot(async () => {
            const snapshot = await this.remoteJson(`${this.config.funding.indexer_url}/v1/tree/snapshot`);
            return this.worker.call('treePath', { snapshot, noteId, requireExisting });
        }, expectedActiveRoot, { sleep: milliseconds => delay(milliseconds) });
    }

    async nextDepositPath(expectedActiveRoot = null) {
        return waitForExpectedActiveRoot(async () => {
            const snapshot = await this.remoteJson(`${this.config.funding.indexer_url}/v1/tree/snapshot`);
            return this.worker.call('treePath', {
                snapshot,
                noteId: Number(snapshot.next_note_id),
                requireExisting: false
            });
        }, expectedActiveRoot, { sleep: milliseconds => delay(milliseconds) });
    }

    canQuotePendingDeposit(pending = this.runtime?.pendingDeposit) {
        const noActiveAttempt = pending && typeof pending.operationId === 'string' && pending.operationId
            && !pending.submissionId && !pending.transactionHash
            && !pending.transactionHashes?.length && !pending.transactionAttempts?.length
            && !pending.submissionFrom && pending.submissionNonce == null
            && !(this.runtime?.lateDepositAttempts || []).some(attempt =>
                attempt.operationId === pending.operationId
                && !LATE_DEPOSIT_TERMINAL_STATUSES.has(attempt.status));
        if (!noActiveAttempt) return false;
        if (pending.phase === 'retry_exact') {
            return pending.fundingQuoteRetryAuthorized === true && Boolean(pending.ambiguousSubmissions?.length);
        }
        return pending.phase === 'prepared' && !pending.legacyRecovery
            && !(pending.ambiguousSubmissions || []).some(attempt =>
                !(pending.resolvedAmbiguousSubmissionIds || []).includes(attempt.submissionId));
    }

    async prepareDepositQuote(amount, expectedActiveRoot) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending && this.depositsClosed()) {
                // Only a deposit already started may still be quoted.
                await this.discardClosedDepositDraftLocked();
                throw this.depositsClosedError();
            }
            if (this.runtime.state || (pending && !this.canQuotePendingDeposit(pending))) {
                throw new Error('Recover the existing private balance or deposit before preparing another quote.');
            }
            if (!Number.isSafeInteger(amount) || amount <= 0) throw new Error('Invalid deposit amount.');
            if (pending && pending.amount !== amount) {
                throw new Error('The prepared deposit amount is fixed. Refresh its existing funding quote.');
            }
            if (pending?.phase === 'retry_exact') {
                // An explicit retry may coexist with an unknown old send. Its
                // exact calldata must remain fixed until chain recovery proves
                // the old slot cannot execute; quoting never rebases it.
                return { ...pending };
            }
            const previous = pending || this.runtime.depositQuote;
            const params = previous?.amount === amount ? previous
                : await this.worker.call('generateDeposit');
            const path = await this.nextDepositPath(expectedActiveRoot);
            const draft = {
                ...(pending || {}),
                operationId: previous?.amount === amount ? previous.operationId : uuid(),
                createdAt: previous?.amount === amount ? previous.createdAt : Date.now(),
                amount,
                secret: params.secret,
                commitment: params.commitment || params.registration_commitment,
                next_note_id: path.note_id,
                active_root: path.active_root,
                zero_path: path.siblings
            };
            // A new quote is only a draft. A rejected-before-broadcast pending
            // plan can be requoted, but only for its original amount and identity.
            // Neither path creates a claim, history entry or transaction.
            await this.commit(pending
                ? { ...this.runtime, depositQuote: null, pendingDeposit: draft }
                : { ...this.runtime, depositQuote: draft });
            return draft;
        });
    }

    async prepareDeposit(amount, { preparedOperationId = null } = {}) {
        await this.init();
        const plan = await withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.state) throw new Error('This browser already has an active private note.');
            if (preparedOperationId && this.runtime.pendingDeposit?.operationId === preparedOperationId
                && this.runtime.pendingDeposit.amount !== amount) {
                throw new Error('The prepared deposit amount does not match the selected quote.');
            }
            if (preparedOperationId && this.runtime.pendingDeposit?.operationId !== preparedOperationId) {
                const draft = this.runtime.depositQuote;
                if (this.runtime.pendingDeposit || !draft || draft.operationId !== preparedOperationId
                    || draft.amount !== amount) {
                    throw new Error('The deposit quote changed in another tab. Refresh the quote before continuing.');
                }
                if (this.depositsClosed()) {
                    await this.discardClosedDepositDraftLocked();
                    throw this.depositsClosedError();
                }
                const promoted = { ...draft, phase: 'prepared' };
                // Promotion is the explicit deposit action, atomic with the
                // stale-quote check under the same cross-tab wallet lock.
                await this.commit({ ...this.runtime, depositQuote: null, pendingDeposit: promoted });
                return promoted;
            }
            if (this.runtime.pendingDeposit) {
                let pending = this.runtime.pendingDeposit;
                if (!pending.operationId || !pending.phase) {
                    // Legacy clients opened MetaMask without a durable claim.
                    // A missing hash is not proof that nothing was broadcast.
                    pending = {
                        ...pending,
                        operationId: pending.operationId || uuid(),
                        phase: pending.transactionHash ? 'submitted' : 'ambiguous',
                        legacyRecovery: true
                    };
                    await this.commit({ ...this.runtime, pendingDeposit: pending });
                }
                if (Number(pending.amount) !== Number(amount)) {
                    if (pending.phase !== 'prepared' || pending.submissionId
                        || pending.transactionHash || pending.transactionHashes?.length) {
                        throw new Error('A previous deposit may already be in MetaMask. Recover it before changing the amount.');
                    }
                    // Replacing it would start a new deposit; it stays as it is.
                    if (this.depositsClosed()) throw this.depositsClosedError();
                    await this.commit({ ...this.runtime, pendingDeposit: null });
                    await this.reload();
                } else {
                    return pending;
                }
            }
            if (this.depositsClosed()) {
                await this.discardClosedDepositDraftLocked();
                throw this.depositsClosedError();
            }
            const params = await this.worker.call('generateDeposit');
            const path = await this.nextDepositPath();
            const plan = {
                operationId: uuid(),
                createdAt: Date.now(),
                phase: 'prepared',
                amount: Number(amount),
                secret: params.secret,
                commitment: params.registration_commitment,
                next_note_id: path.note_id,
                active_root: path.active_root,
                zero_path: path.siblings
            };
            // Persist the note secret before MetaMask is opened. If the tab is
            // closed after the transaction is submitted, the deposit can still
            // be confirmed from its on-chain receipt without losing funds.
            await this.commit({ ...this.runtime, depositQuote: null, pendingDeposit: plan });
            return plan;
        });
        // Start only after deposit preparation's small WASM calls have left the
        // worker. MetaMask/on-chain confirmation normally outlasts the decode,
        // hiding it without creating a lease or disposable inference request.
        void this.prewarmRequestProver();
        return plan;
    }

    async refreshPendingDeposit(amount, expectedActiveRoot = null, { expectedOperationId = null } = {}) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.state) throw new Error('This browser already has an active private note.');
            const pending = this.runtime.pendingDeposit;
            if (!pending) throw new Error('The durable pending deposit is missing.');
            if (expectedOperationId && pending.operationId !== expectedOperationId) {
                throw new Error('The pending deposit changed in another tab. Check its status before continuing.');
            }
            if (Number(pending.amount) !== Number(amount)) {
                throw new Error('The prepared private note has a different deposit amount.');
            }
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (pending.phase !== 'prepared' || pending.submissionId || hashes.length) {
                throw new Error('This deposit already has a wallet attempt. Check it before refreshing the vault path.');
            }
            const path = await this.nextDepositPath(expectedActiveRoot);
            const refreshed = {
                ...pending,
                next_note_id: path.note_id,
                active_root: path.active_root,
                zero_path: path.siblings
            };
            // Keep the durable secret and commitment, but rebase their unused
            // note onto the latest append position before the wallet prompt.
            await this.commit({ ...this.runtime, pendingDeposit: refreshed });
            return refreshed;
        });
    }

    async pendingDeposit() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.runtime.pendingDeposit ? { ...this.runtime.pendingDeposit } : null;
        });
    }

    async claimPendingDepositSubmission(expectedOperationId = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) throw new Error('The durable pending deposit is missing.');
            if (expectedOperationId && pending.operationId !== expectedOperationId) {
                throw new Error('The pending deposit changed in another tab. Check its status before continuing.');
            }
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (hashes.length) {
                return {
                    status: 'submitted',
                    transactionHash: hashes[0],
                    operationId: pending.operationId,
                    submissionId: pending.submissionId || null,
                    noteId: Number(pending.next_note_id),
                    amount: Number(pending.amount),
                    commitment: pending.commitment,
                    secret: pending.secret,
                    deploymentId: this.manifest.deployment_id,
                    chainId: Number(this.config.funding.chain_id),
                    contractAddress: this.config.funding.contract_address
                };
            }
            if (pending.phase === 'ambiguous') {
                throw new BrowserWalletHttpError(
                    'The previous deposit has an unknown result. Check it before explicitly retrying.',
                    409,
                    'deposit_submission_ambiguous'
                );
            }
            if (pending.submissionId) {
                throw new BrowserWalletHttpError(
                    'This deposit is already awaiting MetaMask in this or another tab.',
                    409,
                    'deposit_wallet_pending'
                );
            }
            if (!['prepared', 'retry_exact'].includes(pending.phase)) {
                throw new Error('This deposit is not ready for a wallet request.');
            }
            const submissionId = uuid();
            const next = {
                ...pending,
                phase: 'awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return {
                status: 'claimed',
                plan: { ...next },
                transactionHash: null,
                operationId: next.operationId,
                submissionId,
                noteId: Number(next.next_note_id),
                amount: Number(next.amount),
                commitment: next.commitment,
                secret: next.secret,
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address
            };
        });
    }

    async claimPendingDepositReplacement(expectedFrom) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending || pending.phase !== 'dropped_or_pending') {
                throw new Error('Check the submitted deposit before replacing it.');
            }
            if (pending.submissionId) {
                throw new Error('A deposit replacement request is already open in MetaMask.');
            }
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            const hashSet = new Set(hashes.map(hash => String(hash).toLowerCase()));
            const identities = [...new Map((pending.transactionAttempts || [])
                .filter(attempt => hashSet.has(String(attempt.hash || '').toLowerCase())
                    && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                    && Number.isSafeInteger(Number(attempt.nonce))
                    && Number(attempt.nonce) >= 0)
                .map(attempt => {
                    const identity = {
                        from: attempt.from.toLowerCase(),
                        nonce: Number(attempt.nonce)
                    };
                    return [`${identity.from}:${identity.nonce}`, identity];
                })).values()];
            if (identities.length !== 1) {
                throw new Error(identities.length
                    ? 'The saved deposit has more than one wallet nonce. Use MetaMask to cancel or speed up the pending transactions, then check again.'
                    : 'The saved deposit has no replacement nonce. Use MetaMask to cancel or speed up the pending transaction, then check again.');
            }
            const [{ from, nonce }] = identities;
            if (!/^0x[0-9a-fA-F]{40}$/.test(expectedFrom || '')
                || from !== expectedFrom.toLowerCase()) {
                throw new Error(`Connect the MetaMask account ${from} that submitted this deposit.`);
            }
            const submissionId = uuid();
            const next = {
                ...pending,
                phase: 'awaiting_wallet',
                submissionOutcome: 'replacement_awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: Date.now(),
                submissionFrom: from,
                submissionNonce: nonce,
                replacementOf: [...hashSet]
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return {
                status: 'claimed',
                submissionId,
                transactionHash: null,
                operationId: next.operationId,
                noteId: Number(next.next_note_id),
                amount: Number(next.amount),
                commitment: next.commitment,
                secret: next.secret,
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                replacementFrom: from,
                replacementNonce: nonce,
                plan: structuredClone(next)
            };
        });
    }

    async rememberPendingDepositSubmissionMetadata(submission, metadata) {
        await this.init();
        const from = metadata?.from;
        const nonce = Number(metadata?.nonce);
        if (!/^0x[0-9a-fA-F]{40}$/.test(from || '')
            || !Number.isSafeInteger(nonce) || nonce < 0) {
            throw new Error('The deposit transaction metadata is invalid.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!this.depositSubmissionMatches(pending, submission)
                || pending.submissionId !== submission.submissionId) {
                throw new Error('The deposit wallet claim changed before its nonce was saved.');
            }
            const next = {
                ...pending,
                submissionFrom: from.toLowerCase(),
                submissionNonce: nonce
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    depositSubmissionMatches(pending, reference) {
        return Boolean(reference?.operationId && reference?.submissionId
            && pending?.operationId === reference.operationId
            && Number(pending.next_note_id) === Number(reference.noteId)
            && Number(pending.amount) === Number(reference.amount)
            && sameFelt(pending.commitment, reference.commitment)
            && reference.deploymentId === this.manifest.deployment_id
            && Number(reference.chainId) === Number(this.config.funding.chain_id)
            && String(reference.contractAddress || '').toLowerCase()
                === String(this.config.funding.contract_address || '').toLowerCase());
    }

    async rememberPendingDepositTransaction(
        transactionHash,
        submission,
        transactionMetadata = null
    ) {
        await this.init();
        if (!/^0x[0-9a-fA-F]{64}$/.test(transactionHash || '')) {
            throw new Error('MetaMask returned an invalid deposit transaction hash.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) {
                throw new Error('The durable pending deposit is missing.');
            }
            if (!this.depositSubmissionMatches(pending, submission)) {
                const attempts = Array.isArray(this.runtime.lateDepositAttempts)
                    ? this.runtime.lateDepositAttempts
                    : [];
                const lateAttempt = {
                    operationId: submission?.operationId || null,
                    submissionId: submission?.submissionId || null,
                    noteId: Number(submission?.noteId),
                    amount: Number(submission?.amount),
                    commitment: submission?.commitment || null,
                    secret: submission?.secret || null,
                    deploymentId: submission?.deploymentId || null,
                    chainId: Number(submission?.chainId),
                    contractAddress: submission?.contractAddress || null,
                    transactionHash: transactionHash.toLowerCase(),
                    from: /^0x[0-9a-fA-F]{40}$/.test(transactionMetadata?.from || '')
                        ? transactionMetadata.from.toLowerCase()
                        : null,
                    nonce: Number.isSafeInteger(Number(transactionMetadata?.nonce))
                        ? Number(transactionMetadata.nonce)
                        : null,
                    status: 'submitted_late',
                    observedAt: Date.now()
                };
                await this.commit({
                    ...this.runtime,
                    lateDepositAttempts: retainAttemptHistory([...attempts.filter(attempt => !(
                        attempt.operationId === lateAttempt.operationId
                        && attempt.transactionHash === lateAttempt.transactionHash
                    )), lateAttempt], new Set(['confirmed', 'reverted', 'superseded']))
                });
                return { late: true, ...lateAttempt };
            }
            const normalizedHash = transactionHash.toLowerCase();
            const hashes = [...new Set([
                ...(Array.isArray(pending.transactionHashes)
                    ? pending.transactionHashes
                    : pending.transactionHash ? [pending.transactionHash] : []),
                normalizedHash
            ].map(value => value.toLowerCase()))];
            const pendingDeposit = {
                ...pending,
                phase: 'submitted',
                transactionHash: hashes[0],
                transactionHashes: hashes,
                transactionAttempts: [
                    ...(Array.isArray(pending.transactionAttempts)
                        ? pending.transactionAttempts.filter(attempt => attempt.hash !== normalizedHash)
                        : []),
                    {
                        hash: normalizedHash,
                        submissionId: submission.submissionId,
                        operationId: submission.operationId,
                        from: /^0x[0-9a-fA-F]{40}$/.test(
                            transactionMetadata?.from || pending.submissionFrom || ''
                        )
                            ? (transactionMetadata?.from || pending.submissionFrom).toLowerCase()
                            : null,
                        nonce: Number.isSafeInteger(Number(
                            transactionMetadata?.nonce ?? pending.submissionNonce
                        ))
                            ? Number(transactionMetadata?.nonce ?? pending.submissionNonce)
                            : null,
                        observedAt: Date.now()
                    }
                ]
            };
            if (pending.submissionId === submission.submissionId) {
                delete pendingDeposit.submissionId;
                delete pendingDeposit.submissionOwner;
                delete pendingDeposit.submissionStartedAt;
                delete pendingDeposit.submissionFrom;
                delete pendingDeposit.submissionNonce;
            }
            await this.commit({ ...this.runtime, pendingDeposit });
            return { ...pendingDeposit };
        });
    }

    async markPendingDepositRetryable(expectedTransactionHash = null, submission = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) return null;
            if (!expectedTransactionHash && !this.depositSubmissionMatches(pending, submission)) {
                throw new Error('The deposit operation changed while MetaMask was open.');
            }
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (expectedTransactionHash
                && !hashes.some(hash => hash.toLowerCase() === expectedTransactionHash.toLowerCase())) {
                throw new Error('The deposit transaction changed while its receipt was checked.');
            }
            const remaining = expectedTransactionHash
                ? hashes.filter(hash => hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                : hashes;
            const releasesClaim = !expectedTransactionHash
                && pending.submissionId === submission?.submissionId;
            const next = {
                ...pending,
                phase: remaining.length
                    ? 'submitted'
                    : pending.submissionId && !releasesClaim
                        ? (pending.phase === 'ambiguous' ? 'ambiguous' : 'awaiting_wallet')
                        : pending.fundingQuoteRetryAuthorized === true && pending.ambiguousSubmissions?.length
                            ? 'retry_exact' : 'prepared',
                transactionHashes: remaining,
                transactionAttempts: Array.isArray(pending.transactionAttempts)
                    ? pending.transactionAttempts.filter(attempt => !expectedTransactionHash
                        || attempt.hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                    : []
            };
            if (remaining.length) next.transactionHash = remaining[0];
            else {
                delete next.transactionHash;
                delete next.transactionHashes;
            }
            if (releasesClaim) {
                delete next.submissionId;
                delete next.submissionOwner;
                delete next.submissionStartedAt;
                delete next.submissionFrom;
                delete next.submissionNonce;
            }
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async markPendingDepositMissingReceipts(expectedTransactionHashes) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) return null;
            const normalize = values => [...values]
                .map(value => String(value).toLowerCase())
                .sort();
            const hashes = Array.isArray(pending.transactionHashes)
                ? pending.transactionHashes
                : pending.transactionHash ? [pending.transactionHash] : [];
            if (JSON.stringify(normalize(hashes))
                !== JSON.stringify(normalize(expectedTransactionHashes || []))) {
                throw new Error('The deposit transactions changed while their receipts were checked.');
            }
            if (pending.submissionId) return pending;
            if (pending.phase === 'dropped_or_pending') return pending;
            const next = {
                ...pending,
                phase: 'dropped_or_pending',
                submissionOutcome: 'receipt_missing',
                missingReceiptCheckedAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async releasePendingDepositReplacementClaim(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending || pending.submissionId !== submission?.submissionId
                || pending.operationId !== submission?.operationId
                || !Number.isSafeInteger(Number(submission?.replacementNonce))) {
                throw new Error('The deposit replacement request changed before it could be released.');
            }
            const history = Array.isArray(pending.ambiguousReplacements)
                ? pending.ambiguousReplacements
                : [];
            const next = {
                ...pending,
                phase: 'dropped_or_pending',
                submissionOutcome: 'replacement_result_unknown',
                ambiguousReplacements: [...history, {
                    submissionId: pending.submissionId,
                    nonce: Number(submission.replacementNonce),
                    startedAt: pending.submissionStartedAt,
                    releasedAt: Date.now(),
                    message: message || 'The wallet did not return a deposit replacement transaction ID.'
                }].slice(-8),
                missingReceiptCheckedAt: Date.now()
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionError;
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async markPendingDepositAmbiguous(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!this.depositSubmissionMatches(pending, submission)
                || pending.submissionId !== submission.submissionId) {
                throw new Error('The deposit operation changed before its unknown result could be saved.');
            }
            const next = {
                ...pending,
                phase: 'ambiguous',
                submissionError: message || 'MetaMask did not return a transaction ID.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async markPendingDepositUnknown() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending?.submissionId) throw new Error('There is no deposit wallet prompt to recover.');
            if (pending.phase === 'ambiguous') return pending;
            const next = {
                ...pending,
                phase: 'ambiguous',
                submissionError: 'The wallet prompt was closed before a transaction ID was saved.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async authorizePendingDepositRetry({ forFundingQuote = false } = {}) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            const hashes = Array.isArray(pending?.transactionHashes)
                ? pending.transactionHashes
                : pending?.transactionHash ? [pending.transactionHash] : [];
            if (forFundingQuote && pending?.phase === 'retry_exact' && !pending.submissionId
                && !hashes.length && !pending.transactionAttempts?.length && pending.ambiguousSubmissions?.length) {
                const authorized = { ...pending, fundingQuoteRetryAuthorized: true };
                if (!this.canQuotePendingDeposit(authorized)) {
                    throw new Error('Check the unresolved deposit transaction before reviewing retry fees.');
                }
                await this.commit({ ...this.runtime, pendingDeposit: authorized });
                return authorized;
            }
            if (!pending || pending.phase !== 'ambiguous' || !pending.submissionId || hashes.length) {
                throw new Error('There is no unknown deposit request to retry.');
            }
            const history = Array.isArray(pending.ambiguousSubmissions)
                ? pending.ambiguousSubmissions
                : [];
            const next = {
                ...pending,
                phase: 'retry_exact',
                fundingQuoteRetryAuthorized: forFundingQuote,
                ambiguousSubmissions: [...history, {
                    submissionId: pending.submissionId,
                    startedAt: pending.submissionStartedAt,
                    authorizedAt: Date.now()
                }].slice(-8)
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionError;
            if (forFundingQuote && !this.canQuotePendingDeposit(next)) {
                throw new Error('Check the unresolved deposit transaction before reviewing retry fees.');
            }
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async resolvePendingDepositSlotConflict(expected) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const pending = this.runtime.pendingDeposit;
            if (!pending) return null;
            const normalizeHashes = value => [...new Set((Array.isArray(value)
                ? value
                : value ? [value] : [])
                .map(hash => String(hash).toLowerCase()))].sort();
            const pendingHashes = normalizeHashes(
                pending.transactionHashes || pending.transactionHash
            );
            const expectedHashes = normalizeHashes(
                expected?.transactionHashes || expected?.transactionHash
            );
            if (!expected?.operationId
                || pending.operationId !== expected.operationId
                || Number(pending.next_note_id) !== Number(expected.noteId)
                || Number(pending.amount) !== Number(expected.amount)
                || !sameFelt(pending.commitment, expected.commitment)
                || (pending.phase || null) !== (expected.phase || null)
                || (pending.submissionId || null) !== (expected.submissionId || null)
                || JSON.stringify(pendingHashes) !== JSON.stringify(expectedHashes)) {
                throw new Error('The pending deposit changed while its vault slot was being checked. Check it again before retrying.');
            }
            const next = {
                ...pending,
                phase: 'prepared',
                previousSlot: Number(pending.next_note_id),
                // Finalized occupation by another commitment proves every old
                // ambiguous call for this append slot can no longer succeed.
                // Retain those claims for late recovery, while recording exactly
                // which ambiguity was resolved before allowing a fresh quote.
                resolvedAmbiguousSubmissionIds: (pending.ambiguousSubmissions || []).map(attempt => attempt.submissionId),
                legacyRecovery: false,
                fundingQuoteRetryAuthorized: false
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.transactionHash;
            delete next.transactionHashes;
            delete next.transactionAttempts;
            await this.commit({ ...this.runtime, pendingDeposit: next });
            return next;
        });
    }

    async confirmDeposit(args) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            if (this.runtime.state) throw new Error('This browser already has an active private note.');
            const pending = this.runtime.pendingDeposit;
            if (!pending || pending.secret !== args.secret
                || (args.operationId && pending.operationId !== args.operationId)
                || Number(pending.next_note_id) !== Number(args.note_id)
                || Number(pending.amount) !== Number(args.amount)
                || (args.commitment && !sameFelt(pending.commitment, args.commitment))) {
                throw new Error('The deposit secret does not match this browser’s durable pending deposit.');
            }
            const state = await this.worker.call('confirmDeposit', {
                config: this.config.wallet_core,
                args: {
                    secret: args.secret,
                    note_id: Number(args.note_id),
                    amount: Number(args.amount),
                    expiry_ts: Number(args.expiry_ts)
                }
            });
            await this.commit({
                ...this.runtime,
                state,
                journal: null,
                pendingDeposit: null,
                preparedWithdrawal: null
            }, {
                depositConfirmation: {
                    operationId: pending.operationId,
                    createdAt: pending.createdAt || pending.submissionStartedAt || null,
                    confirmedAt: Date.now(),
                    // A saved attempt may have been replaced. Only the receipt
                    // caller identifies the actual mined transaction; recovery
                    // from the vault alone intentionally leaves it unknown.
                    transactionHash: args.transactionHash || null,
                    ...(args.receiptMetadata || {})
                }
            });
            // The atomic note/history write is the confirmation boundary.
            // A later worker status refresh must not turn this exact committed
            // deposit into a reported funding failure or authorize resubmission.
            return {
                status: 'confirmed',
                operationId: pending.operationId,
                noteId: Number(args.note_id),
                amount: Number(args.amount),
                transactionHash: args.transactionHash || null
            };
        });
    }

    async nativeBillingQuote(signal) {
        const funding = this.config.funding;
        const quoted = await this.remoteJson(`${funding.protocol_server_url}/v2/billing/quote`, { signal });
        validateNativeQuote(quoted, funding);
        const verified = await readNativeQuote(funding, { expected: quoted, signal });
        this.ethUsdQuote = verified;
        return verified;
    }

    leaseBudget(spendingLimitUsd, quote = null, { checkBalance = false } = {}) {
        if (!CHAT_SPENDING_TIER_USD.includes(Number(spendingLimitUsd))) throw new Error('Invalid private-balance model budget configuration.');
        validateNativeQuote(quote, this.config.funding, { allowExpired: true });
        const amount = Number(nativeUnitsForUsd(spendingLimitUsd, quote));
        if (checkBalance) {
            const balance = Number(this.runtime.state.current_balance);
            if (!Number.isSafeInteger(balance) || balance < 0) throw new Error('Invalid native ETH wallet balance.');
            if (amount < Number(this.config.request_charge_cap)) throw new Error('This model budget is below the deployment’s minimum private-chat budget.');
            if (balance < amount) {
                const error = new Error(`This model requires at least $${Number(spendingLimitUsd).toFixed(2)} in private balance for a new key. Choose a lower-cap model, or fund a larger balance.`);
                error.code = 'insufficient_chat_balance';
                error.required_credits = amount;
                error.required_balance_usd = Number(spendingLimitUsd);
                throw error;
            }
        }
        return amount;
    }

    async prepareLeaseRequest(onProgress = () => {}, signal = null, spendingLimitUsd = 1) {
        throwIfAborted(signal);
        if (!this.runtime.state) throw new Error('Fund a private balance before starting a chat.');
        if (unresolvedLateWithdrawalForNote(this.runtime, this.runtime.state.note_id)) {
            throw new BrowserWalletHttpError(
                'A withdrawal from another tab may already be on-chain. Check its status before using this balance.',
                409,
                'late_withdrawal_pending'
            );
        }
        if (this.runtime.journal) return this.runtime.journal.prepared_request;
        if (this.runtime.preparedWithdrawal) throw new Error('Finish the prepared withdrawal before sending another message.');
        // Fail closed before proving: every transmitted request needs an
        // archive identity, is never sent at a state the server is already
        // settling, and keeps the archive bounded.
        if (!this.archiveKey(this.runtime.state)) {
            throw new Error('The prepared request journal is incomplete.');
        }
        this.assertAnchorAcceptsRequest(this.runtime.state);
        onProgress('syncing', 'Checking your private balance…');
        const path = await this.treePath(this.runtime.state.note_id, true);
        throwIfAborted(signal);
        const now = Date.now();
        const quote = await this.nativeBillingQuote(signal);
        throwIfAborted(signal);
        // C2: every request proof at a state carries the state's one bound.
        // Once a request at this state left the device, a later one reuses
        // its bound (a different bound would be refused by the prover).
        const selectedLimitCredits = this.leaseBudget(spendingLimitUsd, quote, { checkBalance: true });
        const boundAtState = Number(this.runtime.state.bound_at_state || 0);
        const spendingLimitCredits = boundAtState > 0 ? boundAtState : selectedLimitCredits;
        onProgress('proving', 'Proving this chat is funded…');
        const prepared = await this.worker.call('prepareRequest', {
            config: {
                ...this.config.wallet_core,
                request_charge_cap: spendingLimitCredits,
                policy_charge_cap: this.config.policy_enabled
                    ? spendingLimitCredits
                    : this.config.wallet_core.policy_charge_cap
            },
            state: this.runtime.state,
            args: {
                payload: JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: quote }),
                active_root: path.active_root,
                merkle_siblings: path.siblings,
                client_request_id: uuid(),
                request_time: Math.floor(now / 1000),
                created_at_ms: now
            },
            provingKey: this.config.proving_keys.request
        });
        throwIfAborted(signal);
        const requestNullifier = prepared.request?.public_inputs?.request_nullifier;
        const record = this.tryRequestJournalRecord(prepared.journal, this.runtime.state);
        if (!record || (requestNullifier != null && !sameFelt(requestNullifier, prepared.journal.nullifier))
            || !sameStateExceptBound(prepared.state, this.runtime.state)
            || Number(prepared.state.bound_at_state) !== Number(prepared.request?.public_inputs?.solvency_bound)) {
            throw new Error('The prepared request journal is incomplete.');
        }
        // The state with its bound, the journal and its append-only archive
        // record land in ONE durable write before any POST can carry the
        // proof off this device (design §6.2).
        await this.commit({ ...this.runtime, state: prepared.state, journal: prepared.journal },
            { requestArchive: [record] });
        return prepared.request;
    }

    assertAnchorAcceptsRequest(state) {
        const journals = this.archivedRequestsAt(state)
            .filter(entry => entry.type === REQUEST_JOURNAL_TYPE);
        const finalized = journals.map(lastDefinitiveObservation)
            .find(observed => observed?.status === 'finalized');
        if (finalized) {
            const installable = journals.some(entry => entry.clientRequestId === finalized.clientRequestId
                && entry.journal?.user_rerandomization != null && entry.journal?.prepared_request);
            throw new BrowserWalletHttpError(installable
                ? 'A settled private request receipt must be applied to this balance first. Try again in a moment.'
                : RECEIPT_JOURNAL_MISSING_MESSAGE,
            409, installable ? 'receipt_pending_install' : 'receipt_journal_missing',
            { nullifier_status: 'finalized' });
        }
        // Every request at one state shares its nullifier, so a new proof would
        // only be a replay of a reservation the server already holds.
        if (journals.some(entry => lastDefinitiveObservation(entry)?.status === 'reserved')) {
            throw new BrowserWalletHttpError(
                'The server is still settling an earlier private request for this balance. Try again after it settles.',
                409,
                'request_settlement_pending',
                { nullifier_status: 'reserved' }
            );
        }
        const key = this.archiveKey(state);
        if (key && !anchorArchiveCapacity(this.requestArchive, key).available) {
            throw new BrowserWalletHttpError(REQUEST_ARCHIVE_LIMIT_MESSAGE, 409, 'request_archive_limit');
        }
    }

    async verifyLease(lease, expectedLimitCredits, expectedRequestId, onProgress = () => {}, signal = null, expectedQuote = null, {
        proofBoundQuote = false
    } = {}) {
        throwIfAborted(signal);
        if (lease.status !== 'active'
            || lease.client_request_id !== expectedRequestId
            || !lease.api_key
            || Number(lease.expires_at) <= Math.floor(Date.now() / 1000)) {
            throw new Error('The zkAPI server returned an unusable OpenRouter lease.');
        }
        // A durable proof made under older price-feed pins keeps its own quote;
        // it is never re-validated against the current pins, only matched.
        if (proofBoundQuote) validateProofBoundQuote(expectedQuote, this.config.funding);
        else validateNativeQuote(expectedQuote, this.config.funding, { allowExpired: true });
        if (!sameNativeQuote(lease.billing_quote, expectedQuote)
            || Number(lease.spending_limit_usd) !== Number(nativeUsdMicros(expectedLimitCredits, expectedQuote)) / 1_000_000) {
            throw new Error('The zkAPI server returned a child key with the wrong native ETH spending cap or quote.');
        }
        exactTrustedUrl(lease.openrouter_api_base, this.config.openrouter.inference_base, 'OpenRouter inference origin');
        if (this.config.openrouter.require_oa_key_source && lease.key_source !== 'oa_org') {
            throw new Error('Client policy requires an OA verifier-backed ephemeral key.');
        }
        if (lease.key_source === 'oa_org') {
            onProgress('verifying', 'Verifying the new private key with OA…');
            const evidence = lease.verification;
            if (!evidence?.station_id || !evidence.station_signature || !evidence.org_signature) {
                throw new Error('The OA lease omitted its verification evidence.');
            }
            exactTrustedUrl(evidence.verifier_url, this.config.openrouter.verifier_url, 'OA verifier');
            if (Number(evidence.key_valid_till) < Number(lease.expires_at)
                || Number(evidence.key_valid_till) - Number(lease.expires_at) > 60) {
                throw new Error('The OA evidence expiry does not safely cover the lease.');
            }
            const verification = await this.remoteJson(`${this.config.openrouter.verifier_url}/submit_key`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                signal,
                body: JSON.stringify({
                    station_id: evidence.station_id,
                    api_key: lease.api_key,
                    key_valid_till: evidence.key_valid_till,
                    station_signature: evidence.station_signature,
                    org_signature: evidence.org_signature
                })
            });
            if (verification.status !== 'verified') throw new Error('The trusted OA verifier rejected the ephemeral key.');
        }
    }

    async requestLeaseWithRetry(request, onProgress = () => {}, signal = null, retryOptions = {}) {
        const maxWaitMs = retryOptions.maxWaitMs ?? LEASE_ISSUE_MAX_WAIT_MS;
        const maxAttempts = retryOptions.maxAttempts ?? LEASE_ISSUE_MAX_ATTEMPTS;
        const initialRetryMs = retryOptions.initialRetryMs ?? LEASE_ISSUE_INITIAL_RETRY_MS;
        const maxRetryMs = retryOptions.maxRetryMs ?? LEASE_ISSUE_MAX_RETRY_MS;
        const now = retryOptions.now || Date.now;
        const sleep = retryOptions.sleep || delay;
        const deadline = now() + maxWaitMs;
        const body = JSON.stringify(request);
        let attempt = 1;

        while (true) {
            throwIfAborted(signal);
            onProgress(
                'requesting',
                attempt === 1
                    ? 'Creating a temporary key for this chat…'
                    : 'Retrying temporary key creation…'
            );
            try {
                return await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    signal,
                    body
                });
            } catch (error) {
                throwIfAborted(signal);
                const backoffDelayMs = Math.min(
                    initialRetryMs * (2 ** Math.max(0, attempt - 1)),
                    maxRetryMs
                );
                const advertisedRetryMs = leaseRetryAfterMilliseconds(error);
                const retryDelayMs = Math.max(backoffDelayMs, advertisedRetryMs || 0);
                if (!isExplicitlyRetriableLeaseError(error)
                    || attempt >= maxAttempts
                    || now() + retryDelayMs > deadline) {
                    makeLeaseRateLimitActionable(error, advertisedRetryMs);
                    throw error;
                }

                const waitLabel = retryDelayMs < 1_000 ? 'a moment' : describeRetryDelay(retryDelayMs);
                onProgress(
                    'waiting',
                    isLeaseRateLimit(error)
                        ? `OA is briefly limiting new temporary keys. Retrying in ${waitLabel}…`
                        : `The temporary-key service is briefly unavailable. Retrying in ${waitLabel}…`
                );
                throwIfAborted(signal);
                await sleep(retryDelayMs, signal);
                attempt += 1;
            }
        }
    }

    async requestLeaseWithQuoteRecovery(request, onProgress, signal) {
        try {
            return await this.requestLeaseWithRetry(request, onProgress, signal);
        } catch (error) {
            if (['native_quote_expired', 'native_quote_superseded'].includes(error?.code)) {
                await this.recoverUnacceptedNativeQuote(request, signal);
            } else if (error?.code === 'stale_root') {
                return this.recoverStaleRootRequest(request, error, onProgress, signal);
            }
            throw error;
        }
    }

    /** One word of the pinned vault, read over the trusted deployment RPC. */
    async vaultWord(data, signal = null) {
        const timeout = AbortSignal.timeout(20_000);
        return readVaultWord(this.config.funding, data, {
            signal: signal ? AbortSignal.any([signal, timeout]) : timeout
        });
    }

    /**
     * An unsigned stale_root reply alone never discards a transmitted journal.
     * The pinned chain is the first witness: while the vault still has this
     * proof's root, the server lags (or misreports), so the byte-identical
     * request is retried. Only when the chain confirms the root moved (or
     * cannot be read) is the server's own nullifier record consulted, and only
     * an "unknown" reading discards the journal, into the archive.
     */
    async recoverStaleRootRequest(request, error, onProgress = () => {}, signal = null, {
        delays = STALE_ROOT_RETRY_DELAYS_MS,
        sleep = delay
    } = {}) {
        const journal = this.runtime?.journal;
        if (!journal || JSON.stringify(request) !== JSON.stringify(journal.prepared_request)) throw error;
        let failure = error;
        for (const wait of [...delays, null]) {
            let chainRoot = null;
            try {
                chainRoot = await this.vaultWord(VAULT_SELECTORS.currentRoot, signal);
            } catch (readError) {
                if (isAbortError(readError, signal)) throw readError;
            }
            if (chainRoot == null || !sameFelt(chainRoot, request.public_inputs?.active_root)) break;
            if (wait == null) {
                failure.journalRetained = true;
                throw failure;
            }
            onProgress('waiting', 'The private service is catching up with the vault. Retrying the same request…');
            await sleep(wait, signal);
            try {
                return await this.requestLeaseWithRetry(request, onProgress, signal);
            } catch (retryError) {
                if (['native_quote_expired', 'native_quote_superseded'].includes(retryError?.code)) {
                    await this.recoverUnacceptedNativeQuote(request, signal);
                }
                if (retryError?.code !== 'stale_root') throw retryError;
                failure = retryError;
            }
        }
        const state = this.runtime.state;
        const observed = await this.nullifierServerStatus(journal.nullifier, signal);
        const record = this.tryRequestJournalRecord(journal, state);
        if (observed.status === 'finalized' && observed.response) {
            // Install the verified receipt; the caller then proves at the new state.
            await this.saveRequestObservations(this.archivedRequestsAt(state), observed, 'stale_root');
            failure.receiptInstalled = await this.installRecoveredResponse(
                observed.response.client_request_id || journalClientRequestId(journal),
                onProgress,
                { response: observed.response }
            );
            throw failure;
        }
        if (observed.status === 'unknown' && record) {
            await this.commit({ ...this.runtime, journal: null }, { requestArchive: [{
                ...record,
                disposition: 'discarded_stale_root',
                serverObservations: [requestObservation('unknown', 'stale_root')]
            }] });
            throw failure;
        }
        await this.saveRequestObservations(this.archivedRequestsAt(state), observed, 'stale_root');
        failure.journalRetained = true;
        failure.nullifierStatus = observed.status;
        throw failure;
    }

    /**
     * The server's own record for a nullifier. Only 'unknown', 'reserved',
     * 'finalized' (with its response) and 'clearance_reserved' are readings;
     * every failure is 'unavailable'. A 401 maps to testnet_password_required
     * when the caller can prompt for the password.
     */
    async nullifierServerStatus(nullifier, signal = null, { propagateAuth = false } = {}) {
        let recovery;
        try {
            recovery = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/nullifiers/${encodeURIComponent(nullifier)}`, { signal });
        } catch (error) {
            if (isAbortError(error, signal)) throw error;
            if (propagateAuth && (error?.code === 'testnet_password_required'
                || (error?.status === 401 && this.testnetAuth?.enabled))) {
                throw error?.code === 'testnet_password_required' ? error : testnetPasswordRequired();
            }
            return { status: 'unavailable', response: null };
        }
        return nullifierReading(recovery);
    }

    async issueLease(sessionId, onProgress = () => {}, signal = null, spendingLimitUsd = 1) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            throwIfAborted(signal);
            await this.reload();
            throwIfAborted(signal);
            onProgress('checking', 'Checking for unfinished private activity…');
            const reportRecovery = (phase, message) => onProgress(phase, message, 'recovery');
            await this.recoverPendingLocked({
                retireLostKey: true,
                onProgress: reportRecovery,
                signal,
                sweep: true
            });
            let request = await this.prepareLeaseRequest(onProgress, signal, spendingLimitUsd);

            // A browser can restart with a durable proof made under an older
            // spending policy or older price-feed pins. Finish that
            // byte-identical request safely, but never expose its key to the
            // host application. Settle it unused, install the signed receipt,
            // then prove the selected budget.
            let desiredLimitCredits = null;
            try {
                desiredLimitCredits = this.leaseBudget(spendingLimitUsd, requestBillingQuote(request));
            } catch {
                // Its proof-bound quote predates the current pins.
            }
            if (desiredLimitCredits == null
                || Number(request.public_inputs.solvency_bound) !== desiredLimitCredits) {
                try {
                    this.legacyMigrationInProgress = true;
                    reportRecovery('settling', 'Updating an unfinished temporary key…');
                    const legacyLease = await this.requestLeaseWithQuoteRecovery(request, reportRecovery, signal);
                    await this.verifyLease(
                        legacyLease,
                        request.public_inputs.solvency_bound,
                        request.client_request_id,
                        reportRecovery,
                        signal,
                        requestBillingQuote(request),
                        { proofBoundQuote: true }
                    );
                    // Persist recovery metadata, but deliberately never assign
                    // this legacy-cap key to activeLease. It cannot be returned
                    // to inference even if settlement needs a later retry.
                    await this.commit({
                        ...this.runtime,
                        lease: {
                            ownerId: this.ownerId,
                            sessionId,
                            client_request_id: legacyLease.client_request_id,
                            expires_at: Number(legacyLease.expires_at),
                            settle_after: Number(legacyLease.settle_after),
                            spending_limit_usd: Number(legacyLease.spending_limit_usd)
                        }
                    });
                    reportRecovery('usage', 'Closing the unfinished temporary key…');
                    const status = await this.retireRequest(
                        legacyLease.client_request_id,
                        request,
                        signal
                    );
                    if (status.status !== 'finalized') {
                        throw new Error(`Lease is still ${status.status}.`);
                    }
                    const installed = await this.installRecoveredResponse(
                        legacyLease.client_request_id,
                        reportRecovery
                    );
                    if (!installed) throw new Error('The legacy private-key receipt is not ready yet.');
                } finally {
                    this.legacyMigrationInProgress = false;
                }
                await this.reload();
                request = await this.prepareLeaseRequest(onProgress, signal, spendingLimitUsd);
            }
            // stale_root is reconciled inside (chain witness, then corroboration);
            // a server error string alone never clears the transmitted journal.
            const lease = await this.requestLeaseWithQuoteRecovery(request, onProgress, signal);
            await this.verifyLease(
                lease,
                request.public_inputs.solvency_bound,
                request.client_request_id,
                onProgress,
                signal,
                requestBillingQuote(request)
            );
            throwIfAborted(signal);
            const activeLease = {
                ...lease,
                sessionId,
                selectedSpendingLimitUsd: Number(spendingLimitUsd),
                inFlight: 0
            };
            await this.commit({
                ...this.runtime,
                lease: {
                    ownerId: this.ownerId,
                    sessionId,
                    client_request_id: lease.client_request_id,
                    expires_at: Number(lease.expires_at),
                    settle_after: Number(lease.settle_after),
                    spending_limit_usd: Number(lease.spending_limit_usd)
                }
            });
            this.activeLease = activeLease;
            this.settlementFailures = 0;
            this.dispatchEvent(new Event('change'));
            this.scheduleSettlement();
            onProgress('ready', 'Private chat ready.');
            return this.activeLease;
        });
    }

    addLeaseProgressListener(listener, { replay = true } = {}) {
        if (typeof listener !== 'function') return () => {};
        // Each registration gets a distinct token so two callers that happen
        // to pass the same callback can unsubscribe independently.
        const registration = (phase, message, kind) => listener(phase, message, kind);
        this.leaseProgressListeners.add(registration);
        if (replay && this.lastLeaseProgress) {
            const { phase, message, kind } = this.lastLeaseProgress;
            try {
                registration(phase, message, kind);
            } catch (error) {
                console.warn('A private-access progress listener failed.', error);
            }
        }
        return () => this.leaseProgressListeners.delete(registration);
    }

    reportLeaseProgress(phase, message, kind = 'access') {
        this.lastLeaseProgress = { phase, message, kind };
        for (const listener of this.leaseProgressListeners) {
            try {
                listener(phase, message, kind);
            } catch (error) {
                console.warn('A private-access progress listener failed.', error);
            }
        }
    }

    async waitForLeasePromise(normalizedSessionId, onProgress, signal, spendingLimitUsd = 1) {
        const leasePromise = this.leasePromise;
        if (!leasePromise) return null;
        if (this.leasePromiseSession !== normalizedSessionId) {
            throw new BrowserWalletHttpError(
                `Chat ${this.leasePromiseSession} is creating the current private key.`,
                409,
                'lease_session_conflict'
            );
        }

        if (this.leasePromiseSpendingLimitUsd !== spendingLimitUsd) {
            throw new BrowserWalletHttpError(
                'A different model budget is being prepared. Retry when the current request finishes.',
                409,
                'lease_budget_conflict'
            );
        }

        throwIfAborted(signal);
        const unsubscribe = this.addLeaseProgressListener(onProgress);
        this.leaseWaiterCount += 1;
        let abortHandler = null;
        try {
            if (!signal) return await leasePromise;
            const canceled = new Promise((_, reject) => {
                abortHandler = () => {
                    try {
                        throwIfAborted(signal);
                    } catch (error) {
                        reject(error);
                    }
                };
                signal.addEventListener('abort', abortHandler, { once: true });
            });
            return await Promise.race([leasePromise, canceled]);
        } finally {
            if (signal && abortHandler) signal.removeEventListener('abort', abortHandler);
            unsubscribe();
            this.leaseWaiterCount = Math.max(0, this.leaseWaiterCount - 1);
            if (signal?.aborted
                && this.leasePromise === leasePromise
                && this.leaseWaiterCount === 0) {
                this.leaseAbortController?.abort();
            }
        }
    }

    async ensureLease(sessionId, onProgress = () => {}, signal = null, spendingLimitUsd = 1) {
        throwIfAborted(signal);
        await this.init();
        throwIfAborted(signal);
        const normalized = String(sessionId || 'default').slice(0, 160);
        spendingLimitUsd = Number(spendingLimitUsd);
        if (!CHAT_SPENDING_TIER_USD.includes(spendingLimitUsd)) throw new Error('Invalid private-balance model budget configuration.');
        if (this.leasePromise) {
            return this.waitForLeasePromise(normalized, onProgress, signal, spendingLimitUsd);
        }
        const now = Math.floor(Date.now() / 1000);
        const isSafeForNewRequest = this.activeLease
            && Number(this.activeLease.expires_at) > now + MIN_REQUEST_LEASE_REMAINING_SECONDS;
        const activeLeaseMatchesPolicy = this.activeLease?.selectedSpendingLimitUsd === spendingLimitUsd;
        if (this.activeLease
            && isSafeForNewRequest
            && activeLeaseMatchesPolicy
            && !this.activeLease.retiring
            && !this.activeLease.retired) {
            if (this.activeLease.sessionId !== normalized) {
                throw new BrowserWalletHttpError(
                    `Chat ${this.activeLease.sessionId} owns the current private key until it settles.`,
                    409,
                    'lease_session_conflict'
                );
            }
            onProgress('ready', 'Private chat ready.', 'access');
            return this.activeLease;
        }
        if (this.activeLease?.inFlight > 0) {
            throw new BrowserWalletHttpError(
                'Wait for the current requests to finish before renewing or changing the private key budget.',
                409,
                'lease_requests_in_flight'
            );
        }
        await this.reload();
        if (this.runtime.lease
            && Number(this.runtime.lease.settle_after || this.runtime.lease.expires_at) > now
            && this.runtime.lease.ownerId !== this.ownerId) {
            throw new BrowserWalletHttpError(
                `Another browser tab owns the current private key until ${new Date(Number(this.runtime.lease.settle_after || this.runtime.lease.expires_at) * 1000).toLocaleTimeString()}.`,
                409,
                'lease_tab_conflict'
            );
        }
        if (this.leasePromise) {
            return this.waitForLeasePromise(normalized, onProgress, signal, spendingLimitUsd);
        }
        this.leasePromiseSession = normalized;
        this.leasePromiseSpendingLimitUsd = spendingLimitUsd;
        this.lastLeaseProgress = null;
        const jobKind = this.activeLease ? 'renewal' : 'access';
        const controller = new AbortController();
        this.leaseAbortController = controller;
        let leasePromise;
        leasePromise = (async () => {
            if (this.activeLease) {
                await this.retireActiveLease(
                    (phase, message) => this.reportLeaseProgress(phase, message, 'renewal')
                );
            }
            return this.issueLease(
                normalized,
                (phase, message, kind = 'access') => this.reportLeaseProgress(
                    phase,
                    message,
                    kind === 'access' ? jobKind : kind
                ),
                controller.signal,
                spendingLimitUsd
            );
        })().finally(() => {
            if (this.leasePromise === leasePromise) {
                this.leasePromise = null;
                this.leasePromiseSession = null;
                this.leasePromiseSpendingLimitUsd = null;
                this.leaseAbortController = null;
                this.lastLeaseProgress = null;
            }
        });
        this.leasePromise = leasePromise;
        return this.waitForLeasePromise(normalized, onProgress, signal, spendingLimitUsd);
    }

    scheduleSettlement(delayOverrideMs = null) {
        if (!this.activeLease) return;
        if (this.settlementTimer) clearTimeout(this.settlementTimer);
        const delayMs = delayOverrideMs ?? Math.max(
            0,
            Number(this.activeLease.settle_after) * 1000 - Date.now() + 250
        );
        this.settlementTimer = setTimeout(() => {
            this.settlementTimer = null;
            if (!this.activeLease) return;
            if (this.activeLease.inFlight > 0) {
                this.scheduleSettlement(500);
                return;
            }
            void this.retireActiveLease().then(() => {
                this.settlementFailures = 0;
            }, () => {
                // A settlement that keeps failing backs off instead of
                // polling the server every two seconds forever.
                this.settlementFailures += 1;
                if (this.activeLease) {
                    this.scheduleSettlement(Math.min(SETTLEMENT_RETRY_MAX_MS,
                        SETTLEMENT_RETRY_MIN_MS * (2 ** Math.min(this.settlementFailures - 1, 5))));
                }
            });
        }, Math.min(delayMs, 2_147_000_000));
    }

    async retireRequest(clientRequestId, request, signal, retryOptions = {}) {
        const now = retryOptions.now || Date.now;
        const sleep = retryOptions.sleep || delay;
        const maxWaitMs = retryOptions.maxWaitMs ?? MAX_RECOVERY_WAIT_MS;
        const deadline = now() + maxWaitMs;
        const body = JSON.stringify(request);
        let attempt = 1;
        while (true) {
            try {
                return await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases/${encodeURIComponent(clientRequestId)}`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body,
                    signal
                });
            } catch (error) {
                const backoffDelayMs = Math.min(1_000 * (2 ** Math.max(0, attempt - 1)), 10_000);
                const advertisedRetryMs = leaseRetryAfterMilliseconds(error);
                const retryDelayMs = Math.max(backoffDelayMs, advertisedRetryMs || 0);
                if (!isExplicitlyRetriableLeaseRetirementError(error)
                    || now() + retryDelayMs > deadline) {
                    throw error;
                }
                await sleep(retryDelayMs, signal);
                attempt += 1;
            }
        }
    }

    async retireActiveLease(onProgress = () => {}) {
        if (this.retirementPromise) return this.retirementPromise;
        if (!this.activeLease || !this.runtime?.journal) return;
        if (this.activeLease.inFlight > 0) {
            throw new BrowserWalletHttpError(
                'Wait for the active model requests to finish before settling the private key.',
                409,
                'lease_requests_in_flight'
            );
        }
        const lease = this.activeLease;
        lease.retiring = true;
        onProgress('settling', 'Closing the temporary key from the previous chat…');
        const retireWithinLock = async () => {
            await this.reload();
            const request = this.runtime.journal?.prepared_request;
            if (!request || request.client_request_id !== lease.client_request_id) return;
            onProgress('usage', 'Confirming the previous chat’s usage…');
            const status = await this.retireRequest(lease.client_request_id, request);
            if (status.status !== 'finalized') throw new Error(`Lease is still ${status.status}.`);
            // The remote key is now disabled. Make that transition
            // irreversible locally before receipt installation, which can
            // still fail independently and be retried from the durable journal.
            lease.retired = true;
            if (this.activeLease === lease) this.activeLease = null;
            if (this.settlementTimer) clearTimeout(this.settlementTimer);
            this.settlementTimer = null;
            this.dispatchEvent(new Event('change'));
            return this.installRecoveredResponse(lease.client_request_id, onProgress);
        };
        const retirement = (async () => {
            const installed = await withBrowserWalletLock(
                this.manifest.deployment_id,
                retireWithinLock
            );
            this.activeLease = null;
            if (this.settlementTimer) clearTimeout(this.settlementTimer);
            this.settlementTimer = null;
            // installRecoveredResponse commits and notifies. Only publish here
            // when there was no recovered response (and therefore no commit).
            if (!installed) this.dispatchEvent(new Event('change'));
            return installed;
        })();
        this.retirementPromise = retirement;
        try {
            return await retirement;
        } finally {
            if (this.activeLease === lease) lease.retiring = false;
            if (this.retirementPromise === retirement) this.retirementPromise = null;
        }
    }

    async settleActiveLease(onProgress = () => {}) {
        await this.init();
        if (this.retirementPromise) {
            try {
                await this.retirementPromise;
            } catch {
                // The durable journal remains recoverable below even if the
                // first receipt-installation attempt failed.
            }
        }
        if (this.legacyMigrationInProgress) {
            throw new BrowserWalletHttpError(
                'An unfinished private key is already being updated. Try settling again in a moment.',
                409,
                'lease_pending'
            );
        }
        if (this.activeLease?.inFlight > 0) {
            throw new BrowserWalletHttpError(
                'Wait for the active model requests to finish before settling the private key.',
                409,
                'lease_requests_in_flight'
            );
        }
        if (this.activeLease) {
            await this.retireActiveLease(onProgress);
        } else {
            await this.reload();
            await this.recoverPending({ retireLostKey: true, onProgress });
        }
        await this.reload();
        if (this.runtime.journal) {
            throw new BrowserWalletHttpError(
                'The private key usage receipt is still being finalized. Try settling again shortly.',
                409,
                'lease_pending'
            );
        }
        this.activeLease = null;
        return this.walletStatus();
    }

    async settleSessionLease(sessionId, onProgress = () => {}) {
        await this.init();
        if (this.activeLease?.sessionId === sessionId) {
            // retireActiveLease captures the exact request and checks it again
            // under the wallet lock before publishing its settlement.
            await this.retireActiveLease(onProgress);
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            // A different tab may have opened a key after our first owner read.
            // Recovery must never retire that tab's new lease.
            if (this.runtime?.lease?.sessionId !== sessionId) return;
            await this.recoverPendingLocked({ retireLostKey: true, onProgress });
            if (this.runtime?.journal && this.runtime?.lease?.sessionId === sessionId) {
                throw new BrowserWalletHttpError('This chat’s private key is still being finalized. Try again shortly.',
                    409, 'lease_pending');
            }
        });
    }

    /**
     * Install a finalized, signed receipt. The response selects its journal:
     * the live one, or an archived one at this state that still holds its
     * private rerandomization (a discarded, evicted or abandoned request the
     * server finalized later). completeResponse verifies the commitment
     * algebra, the charge bound (a worst-case charge equal to the proven
     * solvency bound is valid) and the state signature before the ONE commit
     * that installs it.
     */
    async installRecoveredResponse(clientRequestId, onProgress = () => {}, { response = null } = {}) {
        onProgress('applying', 'Updating your private balance…');
        let receipt = response;
        const fetched = !receipt;
        if (fetched) {
            const recovery = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/requests/${encodeURIComponent(clientRequestId)}`);
            if (!recovery.request_response) return false;
            receipt = recovery.request_response;
        }
        const state = this.runtime.state;
        const current = this.runtime.journal;
        const responseId = typeof receipt.client_request_id === 'string' && receipt.client_request_id
            ? receipt.client_request_id
            : null;
        let journal = null;
        if (current && (!responseId || journalClientRequestId(current) === responseId)) {
            journal = current;
        } else if (responseId) {
            journal = this.archivedRequestsAt(state).find(entry => entry.type === REQUEST_JOURNAL_TYPE
                && entry.clientRequestId === responseId && entry.journal?.user_rerandomization != null
                && entry.journal?.prepared_request)?.journal || null;
        }
        if (!journal) {
            // A caller that passed the receipt saved the nullifier reading it
            // came with. One fetched by request id is saved here, so the
            // snapshot's override warning follows this claim too.
            if (fetched) {
                await this.saveRequestObservations(this.archivedRequestsAt(state),
                    { status: 'finalized', response: receipt }, 'recovery');
            }
            throw new BrowserWalletHttpError(RECEIPT_JOURNAL_MISSING_MESSAGE, 409, 'receipt_journal_missing',
                { nullifier_status: 'finalized' });
        }
        // The quote was validated against the pins when the proof was made; a
        // receipt only has to carry exactly that proof-bound quote.
        const quote = requestBillingQuote(journal.prepared_request);
        validateProofBoundQuote(quote, this.config.funding);
        let payload;
        try { payload = JSON.parse(receipt.response_payload); } catch { /* Reject below. */ }
        if (!sameNativeQuote(payload?.billing_quote, quote)) throw new Error('The settlement receipt changed the authorized ETH/USD quote.');
        const prepared = this.runtime.preparedWithdrawal;
        if (preparedWithdrawalHasSubmission(prepared)
            || (state && unresolvedLateWithdrawalForNote(this.runtime, state.note_id))) {
            throw new BrowserWalletHttpError(
                'A withdrawal transaction for this balance is still unresolved. Check it before applying a settled private request.',
                409,
                'withdrawal_submission_pending'
            );
        }
        const next = await this.worker.call('completeResponse', {
            config: this.config.wallet_core,
            args: {
                state,
                journal,
                response: receipt
            }
        });
        // An unsubmitted withdrawal plan or clearance marker was bound to the
        // consumed state's nullifier; the next state starts clean.
        await this.commit({ ...this.runtime, state: next, journal: null, lease: null, preparedWithdrawal: null }, {
            requestArchive: this.installArchiveUpdates({ state, journal, current, next, receipt, payload })
        });
        return true;
    }

    installArchiveUpdates({ state, journal, current, next, receipt, payload }) {
        if (!this.archiveKey(state)) return [];
        const installedId = journalClientRequestId(journal);
        const now = Date.now();
        const updates = [];
        const installed = this.tryRequestJournalRecord(journal, state, { disposition: 'installed' });
        if (installed) {
            let nextAnchor = null;
            try { nextAnchor = feltKey(next?.current_anchor); } catch { /* Keep the audit field empty. */ }
            updates.push({
                ...installed,
                installedNextAnchor: nextAnchor,
                chargeApplied: Number.isSafeInteger(Number(receipt?.charge_applied)) ? Number(receipt.charge_applied) : null,
                chargeBasis: typeof payload?.charge_basis === 'string' ? payload.charge_basis : null,
                settlementReason: typeof payload?.settlement_reason === 'string' ? payload.settlement_reason : null,
                installedAt: now
            });
        }
        if (current && journalClientRequestId(current) !== installedId) {
            const superseded = this.tryRequestJournalRecord(current, state, { disposition: 'superseded' });
            if (superseded) updates.push(superseded);
        }
        // Every request at the consumed state shares its nullifier, which the
        // server has now finalized: none of them can install any more.
        for (const entry of this.archivedRequestsAt(state)) {
            if (!updates.some(update => update.archiveId === entry.archiveId)) {
                updates.push({ archiveId: entry.archiveId, disposition: 'superseded' });
            }
        }
        return updates;
    }

    async recoverPending(options = {}) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.recoverPendingLocked(options);
        });
    }

    async recoverUnacceptedNativeQuote(request, signal = null) {
        const journal = this.runtime?.journal;
        const body = JSON.stringify(request);
        if (!request?.client_request_id || request.payload_hash == null
            || request.public_inputs?.request_nullifier == null
            || !sameFelt(journal?.nullifier, request.public_inputs.request_nullifier)
            || body !== JSON.stringify(journal?.prepared_request)) return false;
        validateProofBoundQuote(requestBillingQuote(request), this.config.funding);
        // This endpoint only observes quote validity and acceptance under the server's
        // issuance lock. Neither local time nor an unknown nullifier proves an
        // older in-flight request can no longer reserve the note.
        let recovery;
        try {
            recovery = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases/${encodeURIComponent(request.client_request_id)}/expire`, {
                method: 'POST', headers: { 'content-type': 'application/json' }, signal, body
            });
        } catch (error) {
            if (error?.code === 'lease_pending') return false;
            throw error;
        }
        if (!['expired_unaccepted', 'superseded_unaccepted'].includes(recovery?.status)) return false;
        if (recovery.client_request_id !== request.client_request_id
            || recovery.request_nullifier == null || recovery.payload_hash == null
            || !sameFelt(recovery.request_nullifier, request.public_inputs.request_nullifier)
            || !sameFelt(recovery.payload_hash, request.payload_hash)) {
            throw new Error('The quote recovery response does not match the saved private request.');
        }
        if (body !== JSON.stringify(this.runtime?.journal?.prepared_request)
            || !sameFelt(this.runtime.journal.nullifier, request.public_inputs.request_nullifier)) return false;
        // The dedicated endpoint attested non-acceptance under the issuance
        // lock; the archive still remembers that this state was transmitted.
        // The answer only echoes this request's own identifiers, so it is
        // saved as 'unaccepted', never as a nullifier reading.
        const record = this.tryRequestJournalRecord(this.runtime.journal, this.runtime.state, {
            disposition: 'discarded_expired_unaccepted',
            observations: [requestObservation('unaccepted', 'recovery')]
        });
        await this.commit({ ...this.runtime, journal: null, lease: null },
            record ? { requestArchive: [record] } : {});
        return true;
    }

    /**
     * Recover an interrupted request journal. A quiet caller (initialization,
     * the escape override) never fails here, also when a receipt does not
     * install: its own gates decide again from a fresh reading, so an
     * unverifiable 'finalized' claim can neither break initialization nor
     * veto the override.
     */
    async recoverPendingLocked(options = {}) {
        try {
            return await this.recoverPendingJournalLocked(options);
        } catch (error) {
            if (!options?.quiet || isAbortError(error, options?.signal)) throw error;
            return false;
        }
    }

    async recoverPendingJournalLocked({
        retireLostKey = false,
        quiet = false,
        onProgress = () => {},
        signal = null,
        sweep = false
    } = {}) {
        throwIfAborted(signal);
        if (this.activeLease) return false;
        if (!this.runtime?.journal) {
            // User actions also look for a later-finalized receipt of a request
            // whose journal was discarded or abandoned. Never on page load.
            return sweep ? this.recoverArchivedRequestsLocked({ onProgress, signal }) : false;
        }
        const request = this.runtime.journal.prepared_request;
        try {
            const status = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/openrouter/leases/${encodeURIComponent(request.client_request_id)}`, { signal });
            if (status.status === 'active') {
                if (!retireLostKey) return false;
                const ownershipDeadline = Number(
                    this.runtime.lease?.settle_after || this.runtime.lease?.expires_at
                );
                if (this.runtime.lease && ownershipDeadline > Math.floor(Date.now() / 1000)
                    && this.runtime.lease.ownerId !== this.ownerId) {
                    return false;
                }
                onProgress('settling', 'Finishing an interrupted private chat…');
                const retired = await this.retireRequest(request.client_request_id, request, signal);
                if (retired.status !== 'finalized') return false;
            } else if (status.status !== 'finalized') {
                // Revoking, disabled, cancelled or a future status: the nullifier
                // record is authoritative for a finalized receipt.
                return this.installFinalizedNullifierLocked(this.runtime.journal.nullifier, {
                    onProgress, signal, context: 'recovery'
                });
            }
            return this.installRecoveredResponse(request.client_request_id, onProgress);
        } catch (error) {
            if (error.status === 404) {
                const recovery = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/nullifiers/${encodeURIComponent(this.runtime.journal.nullifier)}`, { signal });
                const observed = nullifierReading(recovery);
                // Saved with every request at this state, so the snapshot's
                // override warning follows any receipt claim it carries. A
                // clearance reservation is saved below, with its discard.
                if (observed.status !== 'clearance_reserved') {
                    await this.saveRequestObservations(this.archivedRequestsAt(this.runtime.state), observed, 'recovery');
                }
                if (recovery.request_response) {
                    // A replayed request may have been finalized under an
                    // earlier, archived client request id.
                    return this.installRecoveredResponse(
                        recovery.request_response.client_request_id || request.client_request_id,
                        onProgress,
                        { response: recovery.request_response }
                    );
                }
                if (recovery.status === 'not_found'
                    && recovery.nullifier_status === 'unknown' && !recovery.request_response) {
                    try { return await this.recoverUnacceptedNativeQuote(request, signal); }
                    catch (recoveryError) {
                        if (!quiet) throw recoveryError;
                        return false;
                    }
                }
                if (recovery.nullifier_status === 'clearance_reserved') {
                    // Mutual-close preparation owns this deterministic state
                    // nullifier. The lease was never accepted, so discard only
                    // its orphaned request journal (into the archive) and keep
                    // the withdrawal-only note/intent intact.
                    const record = this.tryRequestJournalRecord(this.runtime.journal, this.runtime.state, {
                        disposition: 'discarded_clearance_reserved',
                        observations: [requestObservation('clearance_reserved', 'recovery')]
                    });
                    // The marker is bound to the current state's own nullifier.
                    const withdrawalNullifier = this.runtime.preparedWithdrawal || !this.runtime.state
                        ? null
                        : await this.worker.call('withdrawalNullifier', { state: this.runtime.state });
                    await this.commit({
                        ...this.runtime,
                        journal: null,
                        lease: null,
                        preparedWithdrawal: this.runtime.preparedWithdrawal || {
                            phase: 'reserving',
                            mode: 'mutual',
                            noteId: Number(this.runtime.state?.note_id),
                            destination: null,
                            withdrawalNullifier: withdrawalNullifier ?? this.runtime.journal.nullifier,
                            clearanceReserved: true,
                            createdAt: Date.now()
                        }
                    }, record ? { requestArchive: [record] } : {});
                    return true;
                }
            }
            if (!quiet) throw error;
            return false;
        }
    }

    /** Consult the server's nullifier record and install a finalized receipt. */
    async installFinalizedNullifierLocked(nullifier, { onProgress = () => {}, signal = null, context = 'recovery' } = {}) {
        const observed = await this.nullifierServerStatus(nullifier, signal);
        await this.saveRequestObservations(this.archivedRequestsAt(this.runtime.state), observed, context);
        if (observed.status !== 'finalized' || !observed.response) return false;
        return this.installRecoveredResponse(
            observed.response.client_request_id || journalClientRequestId(this.runtime.journal),
            onProgress,
            { response: observed.response }
        );
    }

    /**
     * Quiet sweep of archived requests at the selected state: one nullifier
     * read, then install if the server finalized one of them. It never
     * blocks the user's action and never runs on page load.
     */
    async recoverArchivedRequestsLocked({ onProgress = () => {}, signal = null } = {}) {
        const entries = this.archivedRequestsAt(this.runtime?.state);
        if (!entries.length) return false;
        try {
            return await this.installFinalizedNullifierLocked(entries[0].nullifier, {
                onProgress, signal, context: 'recovery'
            });
        } catch (error) {
            if (isAbortError(error, signal)) throw error;
            return false;
        }
    }

    async acquireEphemeralKey(sessionId, onProgress = () => {}, options = {}) {
        const signal = options.signal || null;
        const lease = await this.ensureLease(sessionId, onProgress, signal, options.spendingLimitUsd);
        throwIfAborted(signal);
        // Rotation may have started between ensureLease resolving and this
        // continuation. Retirement marks the old key synchronously, so check
        // ownership before checking it out and exposing its credential.
        if (this.activeLease !== lease || lease.retiring || lease.retired) {
            throw new BrowserWalletHttpError(
                'The previous private key is closing. Retry when its balance update finishes.',
                409,
                'lease_pending'
            );
        }
        lease.inFlight += 1;
        let released = false;
        return {
            mode: 'ephemeral-key',
            apiKey: lease.api_key,
            baseUrl: normalizeUrl(lease.openrouter_api_base),
            spendingLimitUsd: Number(lease.spending_limit_usd),
            headers: {
                authorization: `Bearer ${lease.api_key}`,
                'content-type': 'application/json',
                'http-referer': location.origin,
                'x-title': 'zkAPI'
            },
            release: () => {
                if (released) return;
                released = true;
                // A fetch resolves when headers arrive, not when an SSE body is
                // finished. Keep the lease checked out for the entire stream.
                lease.inFlight = Math.max(0, lease.inFlight - 1);
                if (lease.inFlight === 0
                    && Number(lease.settle_after) * 1000 <= Date.now()) {
                    this.scheduleSettlement(0);
                }
                this.dispatchEvent(new Event('change'));
            }
        };
    }

    async prepareWithdrawal(mode, destination, {
        expectedActiveRoot = null,
        reprove = false,
        overrideUnsettledRequest = false
    } = {}) {
        await this.init();
        // The override exists only where a wrongly challenged escape is
        // non-destructive (hardened vault). Strict mode ignores it entirely.
        // `true` acknowledges the general warning; 'receipt_journal_missing'
        // acknowledges that case's own warning, and covers the general one.
        const override = (overrideUnsettledRequest === true
            || overrideUnsettledRequest === RECEIPT_JOURNAL_MISSING_ACKNOWLEDGEMENT)
            && mode === 'escape' && this.vaultCapabilities().hardenedVault;
        const journalMissingAcknowledged = override
            && overrideUnsettledRequest === RECEIPT_JOURNAL_MISSING_ACKNOWLEDGEMENT;
        try {
            try {
                await this.settleActiveLease();
            } catch (error) {
                // An unsettleable lease must not block the escape hatch forever; the
                // override below archives its journal under the same time gate.
                if (!override || error?.code === 'lease_requests_in_flight' || isAbortError(error)
                    || error?.code === 'testnet_password_required') throw error;
            }
            return await withBrowserWalletLock(this.manifest.deployment_id, async () => {
                // A verified receipt install advances the note to an untransmitted
                // state, after which preparation restarts from a fresh reload.
                for (let pass = 0; pass < 3; pass += 1) {
                    const plan = await this.prepareWithdrawalLocked(mode, destination, {
                        expectedActiveRoot, reprove, override, journalMissingAcknowledged
                    });
                    if (plan !== WITHDRAWAL_RESTART) return plan;
                }
                throw new Error('The private balance changed repeatedly while the withdrawal was being prepared. Try again.');
            });
        } catch (error) {
            throw mode === 'escape' ? this.withEscapeOverrideData(error) : error;
        }
    }

    /**
     * A plain escape that recovery refused with receipt_journal_missing (a
     * finalized receipt for a live request that this browser cannot apply)
     * offers the override like the escape gate does. Strict vaults and
     * challenged states offer none.
     */
    withEscapeOverrideData(error) {
        if (error?.code !== 'receipt_journal_missing' || error.data?.escape_override_warning) return error;
        const overrideAfter = this.escapeOverrideAfter(this.runtime?.state);
        if (overrideAfter == null) return error;
        error.data = {
            ...(error.data || {}),
            nullifier_status: 'finalized',
            transmitted: true,
            ...escapeOverrideData('receipt_journal_missing', overrideAfter)
        };
        return error;
    }

    async prepareWithdrawalLocked(mode, destination, { expectedActiveRoot, reprove, override, journalMissingAcknowledged = false }) {
        await this.reload();
        if (!this.runtime.state) throw new Error('There is no active private note to withdraw.');
        if (unresolvedLateWithdrawalForNote(this.runtime, this.runtime.state.note_id)) {
            throw new BrowserWalletHttpError(
                'A withdrawal from another tab may already be on-chain. Check its status before starting another withdrawal.',
                409,
                'late_withdrawal_pending'
            );
        }
        const validateExisting = (prepared) => {
            if (!prepared) return;
            if (Number(prepared.noteId ?? prepared.note_id ?? prepared.public_inputs?.note_id)
                !== Number(this.runtime.state.note_id)) {
                throw new Error('The prepared withdrawal belongs to a different private balance.');
            }
            const existingDestination = prepared.destination?.toLowerCase();
            const existingHashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            const hasSubmission = Boolean(prepared.submissionId || existingHashes.length);
            const safeModeSwitch = !hasSubmission && (
                (prepared.mode === 'mutual' && mode === 'escape')
                || (prepared.mode === 'escape' && mode === 'mutual'
                    && prepared.clearanceReserved === true)
            );
            if (existingDestination
                && (prepared.mode !== mode || existingDestination !== destination.toLowerCase())
                && !(safeModeSwitch && existingDestination === destination.toLowerCase())) {
                throw new Error('A different withdrawal is already prepared in this browser.');
            }
        };
        let existing = this.runtime.preparedWithdrawal;
        validateExisting(existing);
        await this.recoverPendingLocked({ retireLostKey: true, quiet: override, sweep: true });
        await this.reload();
        if (!this.runtime.state) throw new Error('There is no active private note to withdraw.');
        // Recovery can discover that a pre-crash request nullifier was
        // already reserved for mutual close. Re-read that marker before
        // choosing whether this note is still usable.
        existing = this.runtime.preparedWithdrawal;
        validateExisting(existing);
        if (this.runtime.journal || this.runtime.lease) {
            if (!override) {
                throw new BrowserWalletHttpError(
                    'A private chat started in another tab while withdrawal was opening. Finish that chat and try again.',
                    409,
                    'lease_pending'
                );
            }
            if (await this.abandonUnsettledRequestLocked({ journalMissingAcknowledged }) === WITHDRAWAL_RESTART) {
                return WITHDRAWAL_RESTART;
            }
            existing = this.runtime.preparedWithdrawal;
        }
        const existingHashes = Array.isArray(existing?.transactionHashes)
            ? existing.transactionHashes
            : existing?.transactionHash ? [existing.transactionHash] : [];
        if (existing?.submissionId && !existingHashes.length) {
            throw new BrowserWalletHttpError(
                existing.phase === 'ambiguous'
                    ? 'MetaMask did not return a transaction ID. Check the chain, then explicitly retry if this balance is still active.'
                    : 'This withdrawal is awaiting MetaMask in this or another tab.',
                409,
                existing.phase === 'ambiguous'
                    ? 'withdrawal_submission_ambiguous'
                    : 'withdrawal_wallet_pending'
            );
        }
        if (existingHashes.length) {
            // A broadcast is never gated or re-proved.
            if (!existing.public_inputs || !existing.proof) {
                throw new Error('The submitted withdrawal proof is missing from this browser.');
            }
            return existing;
        }
        const state = this.runtime.state;
        // Always derive the nullifier from the current state. A plan or marker
        // left over from an older state must not steer the gate, clearance or
        // proof reuse.
        const withdrawalNullifier = await this.worker.call('withdrawalNullifier', { state });
        const savedNullifier = preparedWithdrawalNullifier(existing);
        if (existing && savedNullifier != null && !sameFelt(savedNullifier, withdrawalNullifier)) {
            existing = null;
        }
        const path = await this.treePath(state.note_id, true, expectedActiveRoot);
        const persistedClearance = validClearance(existing, withdrawalNullifier) ? existing.clearance : null;
        if (mode === 'escape') {
            const gate = await this.transmittedAnchorGate({
                state, nullifier: withdrawalNullifier, purpose: 'escape', override, journalMissingAcknowledged
            });
            if (gate.advanced) return WITHDRAWAL_RESTART;
        }
        const provenForState = existing?.mode === mode
            && existing.destination?.toLowerCase() === destination.toLowerCase()
            && existing.proof && existing.public_inputs
            && Number(existing.public_inputs.kind) === (mode === 'escape' ? 0 : 1)
            && Number(existing.public_inputs.note_id) === Number(state.note_id)
            && sameFelt(existing.public_inputs.withdrawal_nullifier, withdrawalNullifier)
            && sameFelt(existing.public_inputs.final_balance, state.current_balance)
            && Number(existing.public_inputs.conceded) === 0
            && withdrawalProofStillValid(existing.public_inputs);
        // The vault accepts any root it ever held and exits do no Merkle
        // work, so a durable plan stays usable until its valid_until. An
        // UnknownRoot() or a repeated rejection asks for a fresh proof.
        if (!reprove && provenForState) return existing;
        const clearanceReserved = existing?.clearanceReserved === true
            || existing?.mode === 'mutual';
        let clearance = persistedClearance;
        if (mode === 'mutual' && !clearance) {
            const replacedMarker = this.runtime.preparedWithdrawal ?? null;
            clearance = await this.obtainClearance({
                state,
                destination,
                nullifier: withdrawalNullifier,
                path,
                selected: true,
                // The server's mutual-close clearance reservation is
                // deliberately irreversible for this note state. Persist the
                // intent before crossing that boundary so closing the tab can
                // never leave an apparently usable but server-rejected note.
                commitMarker: () => this.commit({
                    ...this.runtime,
                    preparedWithdrawal: {
                        phase: 'reserving',
                        mode,
                        operationId: existing?.operationId || uuid(),
                        noteId: Number(state.note_id),
                        destination,
                        withdrawalNullifier,
                        clearanceReserved: true,
                        createdAt: Number(existing?.createdAt || Date.now())
                    }
                }),
                // A refusal that reserved nothing restores exactly what this
                // attempt replaced: an earlier attempt's marker may still
                // stand for a reservation, so it is never dropped.
                rollbackMarker: () => this.commit({ ...this.runtime, preparedWithdrawal: replacedMarker })
            });
            if (clearance === WITHDRAWAL_RESTART) return WITHDRAWAL_RESTART;
        }
        const plan = await this.worker.call('prepareWithdrawal', {
            config: this.config.wallet_core,
            state,
            args: {
                mode,
                destination,
                // Nothing is conceded here: an escape at a fresh state, or the
                // override, pays the whole balance (design §6.4 E2, E3).
                ...(mode === 'escape' ? { conceded: 0 } : {}),
                valid_until: nowSeconds() + WITHDRAWAL_PROOF_VALIDITY_SECONDS,
                active_root: path.active_root,
                merkle_siblings: path.siblings,
                // The WASM rejects any clearance on an escape.
                clearance: mode === 'mutual' ? clearance : null
            },
            provingKey: this.config.proving_keys.withdrawal
        });
        if (Number(plan?.public_inputs?.kind) !== (mode === 'escape' ? 0 : 1)) {
            throw new Error('The generated withdrawal proof is of another kind.');
        }
        plan.destination = destination;
        plan.phase = 'prepared';
        plan.operationId = existing?.operationId || uuid();
        plan.noteId = Number(state.note_id);
        plan.withdrawalNullifier = withdrawalNullifier
            || plan.public_inputs?.withdrawal_nullifier
            || null;
        plan.clearanceReserved = mode === 'mutual' || clearanceReserved;
        plan.createdAt = Number(existing?.createdAt || Date.now());
        // Persist the server clearance with the plan: re-proving at a new
        // root (or switching back from an escape) needs no second request.
        const carriedClearance = clearance || persistedClearance;
        if (carriedClearance?.signature) plan.clearance = carriedClearance;
        await this.commit({ ...this.runtime, preparedWithdrawal: plan });
        return plan;
    }

    /**
     * Explicit, time-gated escape override for an unsettled transmitted
     * request (hardened vault only). The journal leaves the runtime only into
     * the archive ('abandoned_for_escape'), so a later-finalized receipt still
     * installs from its saved rerandomization. A finalized claim whose receipt
     * does not install is the receipt_journal_missing case: abandoned only
     * with that case's own acknowledgement, also when the claim was saved by
     * an earlier read and this one failed or did not repeat it.
     */
    async abandonUnsettledRequestLocked({ onProgress = () => {}, signal = null, journalMissingAcknowledged = false } = {}) {
        if (this.activeLease?.inFlight > 0) {
            throw new BrowserWalletHttpError(
                'Wait for the active model requests to finish before overriding the private key settlement.',
                409,
                'lease_requests_in_flight'
            );
        }
        const nowMs = Date.now();
        const lease = this.runtime.lease;
        if (lease && lease.ownerId !== this.ownerId
            && Number(lease.settle_after || lease.expires_at) * 1_000 > nowMs) {
            throw new BrowserWalletHttpError(
                `Another browser tab owns the current private key until ${new Date(Number(lease.settle_after || lease.expires_at) * 1000).toLocaleTimeString()}.`,
                409,
                'lease_tab_conflict'
            );
        }
        const journal = this.runtime.journal;
        const state = this.runtime.state;
        const dropActiveLease = () => {
            this.activeLease = null;
            if (this.settlementTimer) clearTimeout(this.settlementTimer);
            this.settlementTimer = null;
        };
        if (!journal) {
            // A lease row without a request journal carries no transmitted proof.
            await this.commit({ ...this.runtime, lease: null });
            dropActiveLease();
            return 'abandoned';
        }
        const record = this.tryRequestJournalRecord(journal, state);
        if (!record) throw new Error('The unsettled private request journal is incomplete.');
        // Saved before this read; only a contradicting reading or an installed
        // receipt ends it.
        const savedClaim = standingReceiptClaim(this.archivedRequestsAt(state));
        const observed = await this.nullifierServerStatus(journal.nullifier, signal, { propagateAuth: true });
        if (observed.status === 'finalized' && observed.response) {
            try {
                if (await this.installRecoveredResponse(
                    observed.response.client_request_id || journalClientRequestId(journal),
                    onProgress,
                    { response: observed.response }
                )) return WITHDRAWAL_RESTART;
            } catch (error) {
                // Only a receipt that verifies can veto the override.
                if (isAbortError(error, signal)) throw error;
            }
        }
        const overrideAfter = Number(record.createdAt) + this.unsettledRequestEscapeGraceMs();
        // A finalized receipt that did not install above, or a claim saved
        // earlier that this reading does not contradict.
        const freshClaim = readingOverrideCode(observed) === 'receipt_journal_missing';
        const journalMissing = journalMissingAfter(observed, savedClaim);
        const ready = nowMs >= overrideAfter || await this.escapeExpiryImminent(state, signal);
        if (!ready || (journalMissing && !journalMissingAcknowledged)) {
            await putBrowserRequestArchive([{
                ...record,
                serverObservations: [readingObservation(observed, 'override')]
            }], { deploymentId: this.manifest.deployment_id }).then(records => {
                this.requestArchive = records;
            }, error => console.warn('Unable to save a private request status observation.', error));
            // The code follows this reading, except that a ready override
            // missing only this case's acknowledgement is refused as this case.
            const code = freshClaim || (journalMissing && ready) ? 'receipt_journal_missing' : 'request_settlement_pending';
            throw new BrowserWalletHttpError(
                code === 'request_settlement_pending'
                    ? 'The server may still settle this private request. The escape override becomes available after its safety window.'
                    : freshClaim ? RECEIPT_JOURNAL_MISSING_MESSAGE : RECEIPT_JOURNAL_MISSING_EARLIER_MESSAGE,
                409,
                code,
                {
                    client_request_id: record.clientRequestId,
                    nullifier_status: observed.status,
                    created_at: record.createdAt,
                    // Ready but unacknowledged (also near expiry): available now.
                    ...escapeOverrideData(journalMissing ? 'receipt_journal_missing' : null,
                        ready ? Math.min(overrideAfter, nowMs) : overrideAfter)
                }
            );
        }
        await this.commit({ ...this.runtime, journal: null, lease: null }, { requestArchive: [{
            ...record,
            disposition: 'abandoned_for_escape',
            serverObservations: [readingObservation(observed, 'override')]
        }] });
        dropActiveLease();
        return 'abandoned';
    }

    /** now + challenge period + margin >= the vault's pause-aware expiry. */
    async escapeExpiryImminent(state, signal = null) {
        try {
            const [expiry, period] = await Promise.all([
                this.vaultWord(`${VAULT_SELECTORS.effectiveExpiry}${abiWordHex(state.note_id)}`, signal),
                this.vaultWord(VAULT_SELECTORS.challengePeriod, signal)
            ]);
            if (expiry <= 0n) return false;
            return BigInt(Math.floor(Date.now() / 1_000)) + period
                + BigInt(ESCAPE_OVERRIDE_EXPIRY_MARGIN_SECONDS) >= expiry;
        } catch (error) {
            if (isAbortError(error, signal)) throw error;
            this.assertHardenedViewRead(error);
            // An unreadable expiry only waits for the grace.
            return false;
        }
    }

    async vaultNullifierChallenged(nullifier, signal = null) {
        try {
            return await this.vaultWord(`${VAULT_SELECTORS.challengedNullifiers}${abiWordHex(nullifier)}`, signal) !== 0n;
        } catch (error) {
            if (isAbortError(error, signal)) throw error;
            this.assertHardenedViewRead(error);
            // The gas estimate still reverts ChallengedNullifier() if it was.
            return false;
        }
    }

    /**
     * Under a vault_revision 2 profile, a hardened-only view that reverts (or
     * returns no word) means the pinned vault is not hardened: a configuration
     * error, never a "false" that would open the escape override.
     */
    assertHardenedViewRead(error) {
        if (this.vaultCapabilities().hardenedVault && vaultViewMissing(error)) throw vaultRevisionMismatch();
    }

    /**
     * Escape/clearance gate for a state whose request proof may have left this
     * device. Untransmitted states pass without any server contact, so the
     * escape hatch stays operator-independent in the normal case.
     */
    async transmittedAnchorGate({
        state, nullifier, purpose, override = false, journalMissingAcknowledged = false, selected = true, signal = null
    }) {
        const entries = this.archivedRequestsAt(state);
        if (!entries.length) return { allowed: true, transmitted: false };
        const { hardenedVault } = this.vaultCapabilities();
        const graceMs = this.unsettledRequestEscapeGraceMs();
        const transmittedAt = earliestLocalTransmission(entries);
        // A receipt claim saved before this gate's own read.
        const savedClaim = standingReceiptClaim(entries);
        // `ready`: the override was requested and is available now (by the
        // grace or an imminent expiry); only its acknowledgement was missing.
        const refuse = (decision, observed, ready = false) => {
            const messages = {
                transmitted_anchor_escape_unsafe: 'This balance’s current private state was already sent with a private request. This vault can permanently burn a challenged escape, so the escape hatch stays closed until the server settles that request. Wait for settlement, or withdraw by mutual close.',
                request_settlement_pending: 'The server is still settling a private request for this balance. Try again after it settles.',
                transmitted_anchor_unconfirmed: 'This balance’s current state was sent with a private request, and the server’s status could not be confirmed. Try again shortly.',
                anchor_challenged: 'An escape at this balance state was already challenged on-chain. Withdraw from the server-signed next state instead.',
                receipt_journal_missing: RECEIPT_JOURNAL_MISSING_MESSAGE,
                receipt_response_missing: 'The server reports this private request as finalized but returned no receipt. Try again shortly.',
                receipt_pending_install: 'A finalized private request receipt must be applied to this balance before it can be withdrawn.'
            };
            const escapeOverride = purpose === 'escape' && hardenedVault
                && ['request_settlement_pending', 'transmitted_anchor_unconfirmed', 'receipt_journal_missing', 'receipt_response_missing'].includes(decision.code);
            // The override's warning and acknowledgement follow the claim that
            // stands after this reading, as the snapshot's do.
            const overrideCode = journalMissingAfter(observed, savedClaim) ? 'receipt_journal_missing' : decision.code;
            const message = decision.code === 'receipt_journal_missing' && !readingOverrideCode(observed)
                ? RECEIPT_JOURNAL_MISSING_EARLIER_MESSAGE
                : messages[decision.code] || 'This withdrawal is not safe at the current balance state.';
            return new BrowserWalletHttpError(message, 409, decision.code, {
                nullifier_status: observed?.status || null,
                transmitted: true,
                escape_override_after: escapeOverride && transmittedAt != null
                    ? (ready ? Math.min(transmittedAt + graceMs, Date.now()) : transmittedAt + graceMs)
                    : null,
                ...(escapeOverride ? {
                    escape_override_warning: escapeOverrideWarning(overrideCode),
                    escape_override_acknowledgement: escapeOverrideAcknowledgement(overrideCode)
                } : {})
            });
        };
        // STRICT (no hardened vault): never escape at a transmitted state, and
        // never let a server answer decide otherwise.
        if (purpose === 'escape' && !hardenedVault) {
            throw refuse({ code: 'transmitted_anchor_escape_unsafe' }, null);
        }
        const observed = await this.nullifierServerStatus(nullifier ?? entries[0].nullifier, signal, { propagateAuth: true });
        await this.saveRequestObservations(entries, observed, override ? 'override' : purpose);
        if (observed.status === 'finalized' && observed.response && selected) {
            try {
                if (await this.installRecoveredResponse(observed.response.client_request_id, () => {},
                    { response: observed.response })) return { advanced: true };
            } catch (error) {
                // An unverifiable "finalized" claim neither installs nor vetoes.
                if (isAbortError(error, signal)) throw error;
            }
        }
        let overrideReady = false;
        if (purpose === 'escape' && override) {
            overrideReady = (transmittedAt != null && Date.now() >= transmittedAt + graceMs)
                || await this.escapeExpiryImminent(state, signal);
        }
        // Past the grace, a receipt_journal_missing reading, or such a claim
        // saved earlier that this reading does not contradict, is refused
        // again without its own acknowledgement, with that code's warning.
        const decision = transmittedAnchorDecision({
            entries, observed, purpose, hardened: hardenedVault, override, overrideReady,
            journalMissingAcknowledged, journalMissingClaimed: Boolean(savedClaim), selected
        });
        if (!decision.allowed) throw refuse(decision, observed, overrideReady);
        if (purpose === 'escape' && await this.vaultNullifierChallenged(nullifier, signal)) {
            throw new BrowserWalletHttpError(
                'The vault already challenged an escape at this balance state, so it cannot escape again. Withdraw from the server-signed next state instead.',
                409,
                'nullifier_challenged',
                { nullifier_status: observed.status, transmitted: true }
            );
        }
        return { allowed: true, transmitted: true, reason: decision.reason };
    }

    /**
     * Assert that a locally generated ownership proof is a kind-2 withdrawal
     * proof for exactly this state, vault, keys, root and balance: no
     * destination, no concession, no successor nullifier, and a fresh
     * valid_until. The vault rejects kind 2 at every entry point, so it can
     * never be submitted as an exit. Never a request proof.
     */
    assertOwnershipProof(plan, { state, nullifier, activeRoot }) {
        const inputs = plan?.public_inputs;
        const core = this.config.wallet_core || {};
        const funding = this.config.funding || {};
        const validUntil = Number(inputs?.valid_until);
        const valid = Boolean(inputs) && typeof inputs === 'object'
            && plan.mode === 'ownership'
            && plan.proof?.backend === 'groth16_bn254'
            && typeof plan.proof.proof === 'string' && plan.proof.proof.length > 0
            && inputs.kind === 2
            && Number(inputs.conceded) === 0
            && sameFelt(inputs.next_nullifier, 0)
            && Number.isSafeInteger(validUntil) && validUntil > nowSeconds()
            && validUntil <= nowSeconds() + OWNERSHIP_PROOF_VALIDITY_SECONDS
            && Number(inputs.protocol_version) === 2
            && Number(inputs.chain_id) === Number(funding.chain_id)
            && sameFelt(inputs.contract_address, funding.contract_address)
            && sameFelt(inputs.state_signing_key_x, core.state_signing_key?.x)
            && sameFelt(inputs.state_signing_key_y, core.state_signing_key?.y)
            && sameFelt(inputs.clearance_signing_key_x, core.clearance_signing_key?.x)
            && sameFelt(inputs.clearance_signing_key_y, core.clearance_signing_key?.y)
            && Number(inputs.note_id) === Number(state.note_id)
            && sameFelt(inputs.withdrawal_nullifier, nullifier)
            && sameFelt(inputs.active_root, activeRoot)
            && sameFelt(inputs.final_balance, state.current_balance)
            && withdrawalDestinationHex(inputs.destination) === `0x${'0'.repeat(40)}`
            && !REQUEST_PUBLIC_INPUT_FIELDS.some(field => field in inputs);
        if (!valid) throw new Error('The generated ownership proof does not match its saved balance and vault.');
    }

    async generateOwnershipProof({ state, nullifier, path }) {
        // A kind-2 ownership proof at the current balance: it names no
        // destination and no successor nullifier, and every vault entry point
        // rejects it, so the server cannot submit it as an exit. It is valid
        // for one hour (the server's freshness window).
        if (!this.vaultCapabilities().hardenedVault && this.archivedRequestsAt(state).length) {
            throw transmittedOwnershipRefusal(null);
        }
        const ownership = await this.worker.call('prepareWithdrawal', {
            config: this.config.wallet_core,
            state,
            args: {
                mode: 'ownership',
                valid_until: nowSeconds() + OWNERSHIP_PROOF_VALIDITY_SECONDS,
                active_root: path.active_root,
                merkle_siblings: path.siblings
            },
            provingKey: this.config.proving_keys.withdrawal
        });
        this.assertOwnershipProof(ownership, { state, nullifier, activeRoot: path.active_root });
        // Only the public inputs and proof travel; nothing is persisted.
        return { public_inputs: ownership.public_inputs, proof: ownership.proof };
    }

    /**
     * POST one clearance body, retrying the same bytes only for answers that
     * reserved nothing and may pass on their own: the gateway's 429
     * gateway_rate_limited (the request never reached the API; its
     * retry_after_seconds is honoured), and for a proof the server's
     * stale_root (its root lags the vault) or capacity_exhausted (proof
     * verification is saturated). The server sends neither of the last two
     * for a proof-less request. All waits share one backoff budget; a wait the
     * budget cannot hold ends the retries. The caller does not re-prove: a
     * stale_root that outlasts the budget fails the close, which a retry
     * prepares again at the then-current root.
     */
    async postClearance(body, nullifier, signal = null, {
        delays = CLEARANCE_RETRY_DELAYS_MS,
        sleep = delay
    } = {}) {
        const serialized = JSON.stringify(body);
        const budget = delays.reduce((total, value) => total + value, 0);
        let waited = 0;
        for (let attempt = 0; ; attempt += 1) {
            try {
                const clearance = await this.remoteJson(`${this.config.funding.protocol_server_url}/v2/withdraw/clearance`, {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: serialized,
                    signal
                });
                // The WASM verifies the signature; here only the identity.
                if (clearance?.withdrawal_nullifier != null && !sameFelt(clearance.withdrawal_nullifier, nullifier)) {
                    throw new Error('The server returned a clearance for a different private balance state.');
                }
                return clearance;
            } catch (error) {
                const throttled = error?.code === CLEARANCE_GATEWAY_THROTTLED;
                const retriable = throttled || (Boolean(body.ownership_proof)
                    && ['stale_root', 'capacity_exhausted'].includes(error?.code));
                if (!retriable || attempt >= delays.length) throw error;
                const wait = Math.max(delays[attempt], throttled ? retryAfterMilliseconds(error) : 0);
                if (waited + wait > budget) throw error;
                waited += wait;
                await sleep(wait, signal);
            }
        }
    }

    /**
     * Obtain the server clearance for a mutual close (G6 client half). With a
     * declared capability the request always carries an escape-form ownership
     * proof; otherwise it is proof-less first. A refusal that reserved nothing
     * (400 clearance_ownership_required, or 503 legacy_clearance_capacity from
     * an upgraded server whose shared proof-less budget is spent) rolls the
     * withdrawal-only marker back, then the proof is generated and sent once
     * exactly as with the capability. A gateway 429 that outlasts the retries
     * fails the close; it rolls the marker back for a proof-less body or on a
     * hardened vault, but after an ownership proof was sent to a vault that
     * burns a challenged nullifier the note stays withdrawal-only, since the
     * 429 is unsigned and its sender may hold that proof. An ownership proof is
     * never generated for a transmitted state unless the vault is hardened
     * (vault_revision 2) and the server reports that nullifier unknown or
     * clearance_reserved. On any other vault such a state, once its gate
     * passes, gets only the proof-less request; a refusal that asks for a
     * proof is answered with transmitted_anchor_ownership_unsafe.
     */
    async obtainClearance({
        state, destination, nullifier, path, selected = true, signal = null,
        commitMarker = null, rollbackMarker = null
    }) {
        const { hardenedVault, sendOwnershipProof } = this.vaultCapabilities();
        // On a vault that burns a challenged nullifier the ownership proof is
        // a submittable escape at this nullifier, and whoever holds a request
        // proof sent from this state can challenge it there. Neither a server
        // reading nor a server refusal is signed, so neither may decide that.
        const strictTransmitted = !hardenedVault && this.archivedRequestsAt(state).length > 0;
        const send = async body => {
            if (commitMarker) await commitMarker();
            try {
                return await this.postClearance(body, nullifier, signal);
            } catch (error) {
                if (error?.code !== CLEARANCE_GATEWAY_THROTTLED) throw error;
                // An honest gateway answered before the API, so the server
                // reserved nothing. A proof-less body gave whoever answered
                // nothing, so the note may be usable again.
                if (!body.ownership_proof || hardenedVault) {
                    if (rollbackMarker) await rollbackMarker();
                    throw error;
                }
                // The 429 is unsigned, and whoever answered it now holds an
                // ownership proof: a submittable escape at this nullifier. On
                // a vault whose challenge burns the nullifier, a request proof
                // from this state would let that holder escape and challenge,
                // so the note stays withdrawal-only (closing again or an
                // escape still works) and no request proof is ever made here.
                throw clearanceThrottledAfterOwnershipProof(error);
            }
        };
        if (strictTransmitted) {
            // Settle, install or refuse as for any transmitted state before
            // the note is marked withdrawal-only.
            const gate = await this.transmittedAnchorGate({ state, nullifier, purpose: 'clearance', selected, signal });
            if (gate.advanced) return WITHDRAWAL_RESTART;
        }
        if (!sendOwnershipProof || strictTransmitted) {
            // A server with legacy clearance on may reserve on this request,
            // so the marker is committed before it is sent.
            try {
                return await send({ withdrawal_nullifier: nullifier });
            } catch (error) {
                if (!CLEARANCE_NOTHING_RESERVED.has(error?.code)) throw error;
                // This request reserved nothing: until the proof is ready, a gate
                // refusal, a proving failure or a closed tab leaves the note as it was.
                if (rollbackMarker) await rollbackMarker();
                if (strictTransmitted) throw transmittedOwnershipRefusal(error);
            }
        }
        const gate = await this.transmittedAnchorGate({ state, nullifier, purpose: 'clearance', selected, signal });
        if (gate.advanced) return WITHDRAWAL_RESTART;
        const ownership = await this.generateOwnershipProof({ state, nullifier, path });
        // Commit the withdrawal-only marker only after local proving, so a
        // proving failure never makes the note withdrawal-only.
        return send({ withdrawal_nullifier: nullifier, ownership_proof: ownership });
    }

    async claimPreparedWithdrawalSubmission() {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            let prepared = this.runtime.preparedWithdrawal;
            if (!prepared) throw new Error('The durable prepared withdrawal is missing.');
            if (!prepared.operationId) {
                prepared = { ...prepared, operationId: uuid() };
                await this.commit({ ...this.runtime, preparedWithdrawal: prepared });
            }
            const knownHashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (knownHashes.length) {
                return {
                    status: 'submitted',
                    transactionHash: knownHashes[0],
                    submissionId: prepared.submissionId || null,
                    operationId: prepared.operationId,
                    noteId: Number(prepared.noteId ?? prepared.public_inputs?.note_id),
                    mode: prepared.mode,
                    destination: prepared.destination,
                    finalBalance: Number(prepared.public_inputs?.final_balance
                        ?? this.runtime.state?.current_balance),
                    clearanceReserved: prepared.clearanceReserved === true
                        || prepared.mode === 'mutual',
                    withdrawalNullifier: prepared.withdrawalNullifier
                        || prepared.public_inputs?.withdrawal_nullifier
                        || null,
                    deploymentId: this.manifest.deployment_id,
                    chainId: Number(this.config.funding.chain_id),
                    contractAddress: this.config.funding.contract_address
                };
            }
            if (prepared.submissionId) {
                throw new BrowserWalletHttpError(
                    prepared.phase === 'ambiguous'
                        ? 'The previous wallet request has no transaction ID. Check its status before retrying.'
                        : 'This withdrawal is already awaiting MetaMask in this or another tab.',
                    409,
                    prepared.phase === 'ambiguous'
                        ? 'withdrawal_submission_ambiguous'
                        : 'withdrawal_wallet_pending'
                );
            }
            const now = Date.now();
            const submissionId = uuid();
            const next = {
                ...prepared,
                phase: 'awaiting_wallet',
                submissionOutcome: 'awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: now,
                submissionNonceJournalRequired: true
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return {
                status: 'claimed',
                submissionId,
                transactionHash: null,
                operationId: next.operationId,
                noteId: Number(next.noteId ?? next.public_inputs?.note_id),
                mode: next.mode,
                destination: next.destination,
                finalBalance: Number(next.public_inputs?.final_balance
                    ?? this.runtime.state?.current_balance),
                clearanceReserved: next.clearanceReserved === true
                    || next.mode === 'mutual',
                withdrawalNullifier: next.withdrawalNullifier
                    || next.public_inputs?.withdrawal_nullifier
                    || null,
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address
            };
        });
    }

    async rememberPreparedWithdrawalSubmissionMetadata(submission, metadata) {
        const from = metadata?.from;
        const nonce = Number(metadata?.nonce);
        if (!/^0x[0-9a-fA-F]{40}$/.test(from || '')
            || !Number.isSafeInteger(nonce) || nonce < 0) {
            throw new Error('The withdrawal transaction metadata is invalid.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const reference = submission && typeof submission === 'object' ? submission : null;
            const matches = prepared
                && reference?.operationId === prepared.operationId
                && reference?.submissionId === prepared.submissionId
                && Number(reference.noteId) === Number(
                    prepared.noteId ?? prepared.public_inputs?.note_id
                )
                && reference.mode === prepared.mode
                && String(reference.destination || '').toLowerCase()
                    === String(prepared.destination || '').toLowerCase()
                && reference.deploymentId === this.manifest.deployment_id
                && Number(reference.chainId) === Number(this.config.funding.chain_id)
                && String(reference.contractAddress || '').toLowerCase()
                    === String(this.config.funding.contract_address || '').toLowerCase();
            if (!matches) {
                throw new Error('The withdrawal wallet claim changed before its nonce was saved.');
            }
            const next = {
                ...prepared,
                submissionFrom: from.toLowerCase(),
                submissionNonce: nonce
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async claimPreparedWithdrawalReplacement(expectedFrom) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.phase !== 'dropped_or_pending') {
                throw new Error('Check the submitted withdrawal before replacing it.');
            }
            if (prepared.submissionId) {
                throw new Error('A replacement request is already open in MetaMask.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            const hashSet = new Set(hashes.map(hash => String(hash).toLowerCase()));
            const identities = [...new Map((prepared.transactionAttempts || [])
                .filter(attempt => hashSet.has(String(attempt.hash || '').toLowerCase())
                    && /^0x[0-9a-fA-F]{40}$/.test(attempt.from || '')
                    && Number.isSafeInteger(Number(attempt.nonce))
                    && Number(attempt.nonce) >= 0)
                .map(attempt => {
                    const identity = {
                        from: attempt.from.toLowerCase(),
                        nonce: Number(attempt.nonce)
                    };
                    return [`${identity.from}:${identity.nonce}`, identity];
                })).values()];
            if (identities.length !== 1) {
                throw new Error(identities.length
                    ? 'The saved withdrawal has more than one wallet nonce. Use MetaMask to cancel or speed up the pending transactions, then check again.'
                    : 'The saved withdrawal has no replacement nonce. Use MetaMask to cancel or speed up the pending transaction, then check again.');
            }
            const [{ from, nonce }] = identities;
            if (!/^0x[0-9a-fA-F]{40}$/.test(expectedFrom || '')
                || from !== expectedFrom.toLowerCase()) {
                throw new Error(`Connect the MetaMask account ${from} that submitted this withdrawal.`);
            }
            const submissionId = uuid();
            const next = {
                ...prepared,
                phase: 'awaiting_wallet',
                submissionOutcome: 'replacement_awaiting_wallet',
                submissionId,
                submissionOwner: this.ownerId,
                submissionStartedAt: Date.now(),
                submissionFrom: from,
                submissionNonce: nonce,
                submissionNonceJournalRequired: true,
                replacementOf: [...hashSet]
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return {
                status: 'claimed',
                submissionId,
                transactionHash: null,
                operationId: next.operationId,
                noteId: Number(next.noteId ?? next.public_inputs?.note_id),
                mode: next.mode,
                destination: next.destination,
                finalBalance: Number(next.public_inputs?.final_balance
                    ?? this.runtime.state?.current_balance),
                clearanceReserved: next.clearanceReserved === true
                    || next.mode === 'mutual',
                withdrawalNullifier: next.withdrawalNullifier
                    || next.public_inputs?.withdrawal_nullifier
                    || null,
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                replacementFrom: from,
                replacementNonce: nonce,
                plan: structuredClone(next)
            };
        });
    }

    async rememberPreparedWithdrawalTransaction(
        transactionHash,
        submission = null,
        transactionMetadata = null
    ) {
        if (!/^0x[0-9a-fA-F]{64}$/.test(transactionHash || '')) {
            throw new Error('MetaMask returned an invalid withdrawal transaction hash.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const reference = submission && typeof submission === 'object' ? submission : null;
            if (!reference?.operationId || !reference.submissionId
                || reference.deploymentId !== this.manifest.deployment_id
                || Number(reference.chainId) !== Number(this.config.funding.chain_id)
                || String(reference.contractAddress || '').toLowerCase()
                    !== String(this.config.funding.contract_address || '').toLowerCase()) {
                throw new Error('The withdrawal transaction is missing its durable operation identity.');
            }
            const sameOperation = prepared && (
                prepared.operationId === reference.operationId
                    && Number(prepared.noteId ?? prepared.public_inputs?.note_id) === Number(reference.noteId)
                    && prepared.mode === reference.mode
                    && prepared.destination?.toLowerCase() === reference.destination?.toLowerCase()
            );
            if (!sameOperation) {
                const attempts = Array.isArray(this.runtime.lateWithdrawalAttempts)
                    ? this.runtime.lateWithdrawalAttempts
                    : [];
                const lateAttempt = {
                    operationId: reference.operationId || null,
                    submissionId: reference.submissionId || null,
                    noteId: Number(reference.noteId),
                    mode: reference.mode || null,
                    destination: reference.destination || null,
                    finalBalance: Number(reference.finalBalance),
                    clearanceReserved: reference.clearanceReserved === true
                        || reference.mode === 'mutual',
                    withdrawalNullifier: reference.withdrawalNullifier || null,
                    deploymentId: reference.deploymentId,
                    chainId: Number(reference.chainId),
                    contractAddress: reference.contractAddress,
                    transactionHash: transactionHash.toLowerCase(),
                    from: /^0x[0-9a-fA-F]{40}$/.test(
                        transactionMetadata?.from || prepared?.submissionFrom || ''
                    )
                        ? (transactionMetadata?.from || prepared?.submissionFrom).toLowerCase()
                        : null,
                    nonce: Number.isSafeInteger(Number(
                        transactionMetadata?.nonce ?? prepared?.submissionNonce
                    ))
                        ? Number(transactionMetadata?.nonce ?? prepared?.submissionNonce)
                        : null,
                    observedAt: Date.now(),
                    status: 'submitted_late'
                };
                const deduplicated = attempts.filter(attempt => !(
                    attempt.operationId === lateAttempt.operationId
                    && attempt.transactionHash === lateAttempt.transactionHash
                ));
                await this.commit({
                    ...this.runtime,
                    lateWithdrawalAttempts: retainAttemptHistory(
                        [...deduplicated, lateAttempt],
                        LATE_WITHDRAWAL_TERMINAL_STATUSES
                    )
                });
                return { late: true, ...lateAttempt };
            }
            // A wallet prompt can outlive its cross-tab ownership claim. Never
            // reject a late valid hash: retaining every broadcast is the only
            // safe way to reconcile a takeover without losing an on-chain tx.
            const transactionHashes = [...new Set([
                ...(Array.isArray(prepared.transactionHashes)
                    ? prepared.transactionHashes
                    : prepared.transactionHash ? [prepared.transactionHash] : []),
                transactionHash
            ].map(value => value.toLowerCase()))];
            const transactionAttempts = [
                ...(Array.isArray(prepared.transactionAttempts)
                    ? prepared.transactionAttempts.filter(attempt => attempt.hash !== transactionHash.toLowerCase())
                    : []),
                {
                    hash: transactionHash.toLowerCase(),
                    submissionId: reference.submissionId || null,
                    operationId: prepared.operationId,
                    from: /^0x[0-9a-fA-F]{40}$/.test(
                        transactionMetadata?.from || prepared.submissionFrom || ''
                    )
                        ? (transactionMetadata?.from || prepared.submissionFrom).toLowerCase()
                        : null,
                    nonce: Number.isSafeInteger(Number(
                        transactionMetadata?.nonce ?? prepared.submissionNonce
                    ))
                        ? Number(transactionMetadata?.nonce ?? prepared.submissionNonce)
                        : null,
                    observedAt: Date.now()
                }
            ];
            const next = {
                ...prepared,
                phase: 'submitted',
                transactionHash: transactionHashes[0],
                transactionHashes,
                transactionAttempts,
                submissionOutcome: 'submitted',
                ...(reference.submissionId && prepared.submissionId !== reference.submissionId
                    ? { concurrentSubmissionObserved: true }
                    : {})
            };
            if (reference.submissionId && prepared.submissionId === reference.submissionId) {
                delete next.submissionId;
                delete next.submissionOwner;
                delete next.submissionStartedAt;
                delete next.submissionFrom;
                delete next.submissionNonce;
                delete next.submissionNonceJournalRequired;
            }
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async currentLateWithdrawalAttempts() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return (this.runtime.lateWithdrawalAttempts || []).map(attempt => ({ ...attempt }));
        });
    }

    async updateLateWithdrawalAttempt(operationId, transactionHash, changes = {}, {
        expectedStatus = null
    } = {}) {
        await this.init();
        const normalizedHash = String(transactionHash || '').toLowerCase();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const attempts = Array.isArray(this.runtime.lateWithdrawalAttempts)
                ? this.runtime.lateWithdrawalAttempts
                : [];
            const index = attempts.findIndex(attempt =>
                attempt.operationId === operationId
                && String(attempt.transactionHash || '').toLowerCase() === normalizedHash);
            if (index < 0) return null;
            const current = attempts[index];
            if (expectedStatus != null && current.status !== expectedStatus) {
                throw new Error('The late withdrawal attempt changed while its receipt was being checked.');
            }
            if (LATE_WITHDRAWAL_TERMINAL_STATUSES.has(current.status)
                && changes.status && changes.status !== current.status) {
                return { ...current };
            }
            const nextAttempt = {
                ...current,
                ...changes,
                updatedAt: Date.now()
            };
            const nextAttempts = [...attempts];
            nextAttempts[index] = nextAttempt;
            await this.commit({
                ...this.runtime,
                lateWithdrawalAttempts: retainAttemptHistory(
                    nextAttempts,
                    LATE_WITHDRAWAL_TERMINAL_STATUSES
                )
            });
            return { ...nextAttempt };
        });
    }

    async transferLateWithdrawalAttempt(attempt, record) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const detachesSelectedNote = this.runtime.deploymentId === attempt.deploymentId
                && this.runtime.state
                && Number(this.runtime.state.note_id) === Number(attempt.noteId);
            const result = await transferBrowserLateWithdrawalAttempt({
                operationId: attempt.operationId,
                transactionHash: attempt.transactionHash,
                deploymentId: attempt.deploymentId,
                chainId: Number(attempt.chainId),
                contractAddress: attempt.contractAddress,
                noteId: Number(attempt.noteId)
            }, record);
            this.runtime = result.runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            if (detachesSelectedNote) this.activeLease = null;
            this.notify();
            return result;
        });
    }

    async releaseBackgroundWithdrawalStartSubmission(submission, options = {}) {
        await this.init();
        const recordId = this.withdrawalRecordId(submission?.noteId);
        let result = await releaseBrowserWithdrawalStartSubmission(
            recordId,
            submission,
            options
        );
        // Test adapters and older embedders may provide a runtime persistence
        // layer without the shared IndexedDB stores. The production path above
        // atomically checks both owners; this fallback preserves that adapter
        // contract without creating a gap between production ownership checks.
        if (!result) {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (prepared?.submissionId === submission?.submissionId
                && prepared.operationId === submission?.operationId) {
                const released = options.replacementUnknown
                    ? await this.releasePreparedWithdrawalReplacementClaim(
                        submission,
                        options.message || null
                    )
                    : await this.markPreparedWithdrawalRetryable(null, submission);
                result = released ? { location: 'selected', runtime: this.runtime } : null;
            }
        }
        await this.reload();
        this.notify();
        return result;
    }

    async resolveLateChallengedWithdrawalAttempt(attempt) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const attempts = Array.isArray(this.runtime.lateWithdrawalAttempts)
                ? this.runtime.lateWithdrawalAttempts
                : [];
            const index = attempts.findIndex(entry =>
                entry.operationId === attempt.operationId
                && String(entry.transactionHash || '').toLowerCase()
                    === String(attempt.transactionHash || '').toLowerCase()
                && Number(entry.noteId) === Number(attempt.noteId));
            if (index < 0) throw new Error('The challenged withdrawal attempt is no longer available.');
            const currentAttempt = attempts[index];
            if (LATE_WITHDRAWAL_TERMINAL_STATUSES.has(currentAttempt.status)) {
                return { ...currentAttempt };
            }
            const selectedOwns = Number(this.runtime.state?.note_id) === Number(attempt.noteId);
            const backgroundOwns = this.withdrawals.some(record =>
                Number(record.noteId) === Number(attempt.noteId) && record.state);
            if (!selectedOwns && !backgroundOwns) {
                throw new Error('The challenged withdrawal has no recoverable private note.');
            }
            const clearanceReserved = currentAttempt.clearanceReserved === true
                || currentAttempt.mode === 'mutual';
            const preparedWithdrawal = selectedOwns && clearanceReserved
                ? this.runtime.preparedWithdrawal || {
                    phase: 'prepared',
                    mode: currentAttempt.mode === 'mutual' ? 'mutual' : 'escape',
                    operationId: currentAttempt.operationId,
                    noteId: Number(currentAttempt.noteId),
                    destination: currentAttempt.destination,
                    withdrawalNullifier: currentAttempt.withdrawalNullifier || null,
                    clearanceReserved: true,
                    submissionOutcome: 'challenged',
                    createdAt: Number(currentAttempt.observedAt || Date.now())
                }
                : this.runtime.preparedWithdrawal;
            const nextAttempt = {
                ...currentAttempt,
                status: 'challenged',
                resolvedAt: Date.now(),
                error: null
            };
            const nextAttempts = attempts.map((entry, entryIndex) => {
                if (entryIndex === index) return nextAttempt;
                return Number(entry.noteId) === Number(currentAttempt.noteId)
                    && entry.deploymentId === currentAttempt.deploymentId
                    && !LATE_WITHDRAWAL_TERMINAL_STATUSES.has(entry.status)
                    ? {
                        ...entry,
                        status: 'superseded',
                        supersededBy: currentAttempt.transactionHash,
                        resolvedAt: Date.now(),
                        error: null
                    }
                    : entry;
            });
            await this.commit({
                ...this.runtime,
                preparedWithdrawal,
                lateWithdrawalAttempts: retainAttemptHistory(
                    nextAttempts,
                    LATE_WITHDRAWAL_TERMINAL_STATUSES
                )
            });
            return { ...nextAttempt };
        });
    }

    async markPreparedWithdrawalRetryable(expectedTransactionHash = null, submission = null) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared) return null;
            const reference = submission && typeof submission === 'object' ? submission : null;
            if (!expectedTransactionHash && (!reference?.operationId || !reference.submissionId)) {
                throw new Error('The withdrawal retry is missing its durable operation identity.');
            }
            if (reference?.operationId && prepared.operationId !== reference.operationId) {
                throw new Error('The withdrawal operation changed while MetaMask was open.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (expectedTransactionHash
                && !hashes.some(hash => hash.toLowerCase() === expectedTransactionHash.toLowerCase())) {
                throw new Error('The withdrawal transaction changed while its receipt was being checked.');
            }
            if (!expectedTransactionHash && reference.submissionId
                && prepared.submissionId !== reference.submissionId) {
                throw new Error('The withdrawal submission changed while MetaMask was open.');
            }
            const remainingHashes = expectedTransactionHash
                ? hashes.filter(hash => hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                : hashes;
            const remainingAttempts = Array.isArray(prepared.transactionAttempts)
                ? prepared.transactionAttempts.filter(attempt => !expectedTransactionHash
                    || attempt.hash.toLowerCase() !== expectedTransactionHash.toLowerCase())
                : [];
            const releasesClaim = !expectedTransactionHash
                && reference?.submissionId
                && prepared.submissionId === reference.submissionId;
            const survivingClaimPhase = prepared.submissionId && !releasesClaim
                ? (prepared.submissionOutcome === 'ambiguous' || prepared.phase === 'ambiguous'
                    ? 'ambiguous'
                    : 'awaiting_wallet')
                : 'prepared';
            const next = {
                ...prepared,
                phase: remainingHashes.length
                    ? 'submitted'
                    : survivingClaimPhase,
                transactionHashes: remainingHashes,
                transactionAttempts: remainingAttempts,
                submissionOutcome: remainingHashes.length
                    ? 'submitted'
                    : releasesClaim
                        ? 'explicitly_rejected'
                        : prepared.submissionId
                            ? prepared.submissionOutcome
                            : expectedTransactionHash ? 'reverted' : prepared.submissionOutcome
            };
            if (remainingHashes.length) {
                next.transactionHash = remainingHashes[0];
            } else {
                delete next.transactionHash;
                delete next.transactionHashes;
            }
            if (releasesClaim) {
                delete next.submissionId;
                delete next.submissionOwner;
                delete next.submissionStartedAt;
                delete next.submissionFrom;
                delete next.submissionNonce;
                delete next.submissionNonceJournalRequired;
            }
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async markPreparedWithdrawalMissingReceipts(expectedTransactionHashes) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared) return null;
            const normalize = values => [...values]
                .map(value => String(value).toLowerCase())
                .sort();
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (JSON.stringify(normalize(hashes))
                !== JSON.stringify(normalize(expectedTransactionHashes || []))) {
                throw new Error('The withdrawal transactions changed while their receipts were checked.');
            }
            // A second tab may already be replacing this transaction. Preserve
            // that live claim rather than regressing its UI/state phase.
            if (prepared.submissionId) return prepared;
            const next = {
                ...prepared,
                phase: 'dropped_or_pending',
                submissionOutcome: 'receipt_missing',
                missingReceiptCheckedAt: Date.now()
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async markPreparedWithdrawalAmbiguous(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const reference = submission && typeof submission === 'object' ? submission : null;
            if (!prepared || !reference?.submissionId || !reference.operationId
                || prepared.submissionId !== reference.submissionId
                || prepared.operationId !== reference.operationId) {
                throw new Error('The withdrawal operation changed before its ambiguous result could be saved.');
            }
            const next = {
                ...prepared,
                phase: 'ambiguous',
                submissionOutcome: 'ambiguous',
                submissionError: message || 'MetaMask did not return a transaction ID.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async releasePreparedWithdrawalReplacementClaim(submission, message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.submissionId !== submission?.submissionId
                || prepared.operationId !== submission?.operationId
                || !Number.isSafeInteger(Number(submission?.replacementNonce))) {
                throw new Error('The replacement wallet request changed before it could be released.');
            }
            const history = Array.isArray(prepared.ambiguousReplacements)
                ? prepared.ambiguousReplacements
                : [];
            const next = {
                ...prepared,
                phase: 'dropped_or_pending',
                submissionOutcome: 'replacement_result_unknown',
                ambiguousReplacements: [...history, {
                    submissionId: prepared.submissionId,
                    nonce: Number(submission.replacementNonce),
                    startedAt: prepared.submissionStartedAt,
                    releasedAt: Date.now(),
                    message: message || 'The wallet did not return a replacement transaction ID.'
                }].slice(-8),
                missingReceiptCheckedAt: Date.now()
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionNonceJournalRequired;
            delete next.submissionError;
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async authorizePreparedWithdrawalRetry() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.phase !== 'ambiguous' || !prepared.submissionId) {
                throw new Error('There is no ambiguous wallet request to retry.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (hashes.length) throw new Error('Check the submitted transaction before retrying.');
            const history = Array.isArray(prepared.ambiguousSubmissions)
                ? prepared.ambiguousSubmissions
                : [];
            const next = {
                ...prepared,
                phase: 'prepared',
                submissionOutcome: 'retry_authorized',
                ambiguousSubmissions: [...history, {
                    submissionId: prepared.submissionId,
                    startedAt: prepared.submissionStartedAt,
                    authorizedAt: Date.now()
                }].slice(-8)
            };
            delete next.submissionId;
            delete next.submissionOwner;
            delete next.submissionStartedAt;
            delete next.submissionFrom;
            delete next.submissionNonce;
            delete next.submissionNonceJournalRequired;
            delete next.submissionError;
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async clearPreparedWithdrawal({
        force = false,
        expectedNoteId = null,
        expectedTransactionHashes = null
    } = {}) {
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared) return null;
            if (expectedNoteId != null
                && Number(prepared.noteId ?? prepared.public_inputs?.note_id) !== Number(expectedNoteId)) {
                throw new Error('The selected withdrawal changed before it could be cleared.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (expectedTransactionHashes) {
                const normalize = values => [...values].map(value => value.toLowerCase()).sort();
                if (JSON.stringify(normalize(hashes))
                    !== JSON.stringify(normalize(expectedTransactionHashes))) {
                    throw new Error('The withdrawal transactions changed before recovery completed.');
                }
            }
            if (!force && (prepared.mode === 'mutual' || prepared.clearanceReserved === true)) {
                throw new Error('This balance already has a mutual-close authorization and must remain withdrawal-only.');
            }
            // Even force recovery must preserve a hashless MetaMask claim: its
            // delayed callback still needs a durable owner in this exact note.
            if (prepared.submissionId) {
                throw new Error('A MetaMask withdrawal request is still unresolved. Close or finish that prompt before clearing this balance.');
            }
            if (!force && hashes.length) {
                throw new Error('This withdrawal may already be in MetaMask. Check its transaction status before canceling it.');
            }
            await this.commit({ ...this.runtime, preparedWithdrawal: null });
            return null;
        });
    }

    async recoverPreparedWithdrawalSubmissionClaim() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared?.submissionId) return prepared || null;
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (hashes.length) return prepared;
            // A reload cannot prove whether another tab still has MetaMask
            // open. Preserve the claim until the provider returns a definite
            // rejection or the user explicitly starts recovery.
            return prepared;
        });
    }

    async markPreparedWithdrawalUnknown(message = null) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared?.submissionId) {
                throw new Error('There is no wallet request waiting to be recovered.');
            }
            if (prepared.phase === 'ambiguous') return prepared;
            const next = {
                ...prepared,
                phase: 'ambiguous',
                submissionOutcome: 'ambiguous',
                submissionError: message || 'The wallet prompt was closed before a transaction ID was saved.',
                ambiguousAt: Date.now()
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    async resolveChallengedPreparedEscape(noteId, expectedTransactionHashes = []) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            if (!prepared || prepared.mode !== 'escape' || prepared.clearanceReserved !== true
                || Number(prepared.noteId ?? prepared.public_inputs?.note_id) !== Number(noteId)) {
                throw new Error('The challenged escape no longer matches the selected balance.');
            }
            if (prepared.submissionId) {
                throw new Error('A wallet request is still unresolved for this balance.');
            }
            const normalize = values => [...values].map(value => value.toLowerCase()).sort();
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (JSON.stringify(normalize(hashes)) !== JSON.stringify(normalize(expectedTransactionHashes))) {
                throw new Error('The withdrawal transactions changed while the challenge was being checked.');
            }
            const next = {
                phase: 'prepared',
                mode: 'escape',
                operationId: prepared.operationId,
                noteId: Number(noteId),
                destination: prepared.destination,
                withdrawalNullifier: prepared.withdrawalNullifier
                    || prepared.public_inputs?.withdrawal_nullifier
                    || null,
                clearanceReserved: true,
                submissionOutcome: 'challenged',
                createdAt: Number(prepared.createdAt || Date.now())
            };
            await this.commit({ ...this.runtime, preparedWithdrawal: next });
            return next;
        });
    }

    withdrawalRecordId(noteId) {
        return [
            this.manifest.deployment_id,
            Number(this.config?.funding?.chain_id),
            String(this.config?.funding?.contract_address || '').toLowerCase(),
            Number(noteId)
        ].join(':');
    }

    async detachEscapeWithdrawal(details) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const noteId = Number(details.noteId);
            const phase = details.phase === 'challenged_unconfirmed'
                ? 'challenged_unconfirmed'
                : 'pending';
            const result = await detachBrowserEscapeWithdrawal({
                recordId: this.withdrawalRecordId(noteId),
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                mode: 'escape',
                phase,
                chainStatus: details.chainStatus
                    || (phase === 'challenged_unconfirmed' ? 'active' : 'pending_withdrawal'),
                noteId,
                destination: details.destination,
                finalBalance: Number(details.finalBalance),
                challengeDeadline: Number(details.challengeDeadline),
                transactionHash: details.transactionHash || null,
                startBlockNumber: Number(details.startBlockNumber || 0),
                challengeObservedBlock: Number(details.challengeObservedBlock || 0),
                lastObservedBlock: Number(details.lastObservedBlock || 0),
                createdAt: Number(details.createdAt || Date.now())
            });
            this.runtime = result.runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            this.activeLease = null;
            this.notify();
            return result.withdrawal;
        });
    }

    async detachClosedWithdrawal(details) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const noteId = Number(details.noteId);
            const result = await detachBrowserClosedWithdrawal({
                recordId: this.withdrawalRecordId(noteId),
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                mode: details.mode,
                noteId,
                destination: details.destination,
                finalBalance: Number(details.finalBalance),
                transactionHash: details.transactionHash || null,
                closeBlockNumber: Number(details.closeBlockNumber || 0),
                payoutVerified: details.payoutVerified === true,
                lastObservedBlock: Number(details.lastObservedBlock || 0),
                clearanceReserved: details.clearanceReserved === true,
                createdAt: Number(details.createdAt || Date.now()),
                closedAt: Date.now()
            });
            this.runtime = result.runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            this.activeLease = null;
            this.notify();
            return result.withdrawal;
        });
    }

    backgroundWithdrawalIdentity(record) {
        return { recordId: record?.recordId, deploymentId: this.manifest.deployment_id,
            chainId: Number(this.config.funding.chain_id), contractAddress: this.config.funding.contract_address,
            noteId: Number(record?.noteId), mode: record?.mode, destination: record?.destination };
    }

    async repairUnsubmittedBackgroundWithdrawal(recordId, observedBlock, expectedRevision) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record) return null;
        const result = await repairBrowserUnsubmittedBackgroundWithdrawal(
            this.backgroundWithdrawalIdentity(record), Number(observedBlock), expectedRevision);
        await this.reload();
        if (result && Number(result.revision) !== Number(expectedRevision)) this.notify();
        return result;
    }

    async resolveBackgroundWithdrawalForRetry(recordId, evidence) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        const result = await resolveBrowserBackgroundWithdrawalForRetry(
            this.backgroundWithdrawalIdentity(record), evidence);
        await this.reload();
        this.notify();
        return result;
    }

    async prepareBackgroundWithdrawal(recordId, { expectedActiveRoot } = {}) {
        await this.init();
        await this.reload();
        const record = structuredClone(this.withdrawals.find(entry => entry.recordId === recordId));
        const identity = this.backgroundWithdrawalIdentity(record);
        assertBrowserBackgroundWithdrawalAvailable(record, this.runtime, identity);
        if (expectedActiveRoot == null) throw new Error('A current vault root is required to prepare this withdrawal.');
        const state = record.state;
        const config = this.config;
        if (Number(state.chain_id) !== identity.chainId || !sameFelt(state.contract_address, identity.contractAddress)) {
            throw new Error('The saved private state belongs to a different vault.');
        }
        const nullifier = await this.worker.call('withdrawalNullifier', { state });
        const savedNullifiers = [record.withdrawalNullifier, record.preparedWithdrawal?.withdrawalNullifier,
            record.preparedWithdrawal?.public_inputs?.withdrawal_nullifier].filter(value => value != null);
        if (savedNullifiers.some(value => !sameFelt(value, nullifier))) {
            throw new Error('The saved withdrawal authorization does not match its private balance.');
        }
        // Deliberately outside the global wallet lock: a proof or indexer wait
        // must not stall unrelated deposits, requests, or settlement in another tab.
        const path = await this.treePath(identity.noteId, true, expectedActiveRoot);
        // A persisted clearance for this exact nullifier needs no second
        // ownership proof or server request when only the root moved.
        let clearance = validClearance(record.preparedWithdrawal, nullifier)
            ? record.preparedWithdrawal.clearance
            : null;
        if (!clearance) {
            clearance = await this.obtainClearance({
                state, destination: identity.destination, nullifier, path, selected: false
            });
            if (clearance === WITHDRAWAL_RESTART) {
                throw new Error('The saved balance changed while its withdrawal was being prepared. Try again.');
            }
        }
        const plan = await this.worker.call('prepareWithdrawal', {
            config: config.wallet_core, state,
            args: { mode: 'mutual', destination: identity.destination,
                valid_until: nowSeconds() + WITHDRAWAL_PROOF_VALIDITY_SECONDS, active_root: path.active_root,
                merkle_siblings: path.siblings, clearance }, provingKey: config.proving_keys.withdrawal
        });
        const inputs = plan.public_inputs;
        const encodedDestination = Array.isArray(inputs?.destination)
            ? `0x${inputs.destination.map(value => Number(value).toString(16).padStart(2, '0')).join('')}`
            : inputs?.destination;
        if (!plan.proof || Number(inputs?.note_id) !== identity.noteId
            || Number(inputs?.chain_id) !== identity.chainId
            || !sameFelt(inputs?.contract_address, identity.contractAddress)
            || !sameFelt(inputs?.active_root, expectedActiveRoot)
            || !sameFelt(inputs?.withdrawal_nullifier, nullifier)
            || !sameFelt(inputs?.final_balance, state.current_balance)
            || String(encodedDestination || '').toLowerCase() !== identity.destination.toLowerCase()
            || inputs?.kind !== 1 || Number(inputs?.conceded) !== 0 || !sameFelt(inputs?.next_nullifier, 0)) {
            throw new Error('The generated withdrawal proof does not match its saved balance and vault.');
        }
        Object.assign(plan, { destination: identity.destination, mode: 'mutual', phase: 'prepared',
            operationId: uuid(), noteId: identity.noteId, withdrawalNullifier: nullifier,
            clearanceReserved: true, createdAt: Number(record.createdAt || Date.now()),
            ...(clearance?.signature ? { clearance } : {}) });
        await saveBrowserBackgroundWithdrawalPlan(identity, record, plan);
        await this.reload();
        this.notify();
        return plan;
    }

    async claimBackgroundWithdrawalSubmission(recordId, expectedOperationId) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        const result = await claimBrowserBackgroundWithdrawalSubmission(
            this.backgroundWithdrawalIdentity(record), expectedOperationId, this.ownerId);
        await this.reload();
        this.notify();
        return result;
    }

    async rememberBackgroundWithdrawalSubmissionMetadata(submission, metadata) {
        const result = await rememberBrowserBackgroundWithdrawalMetadata(submission, metadata);
        await this.reload();
        this.notify();
        return result;
    }

    async markBackgroundWithdrawalAmbiguous(submission, message) {
        const result = await markBrowserBackgroundWithdrawalAmbiguous(submission, message);
        await this.reload();
        this.notify();
        return result;
    }

    async releaseBackgroundWithdrawalSubmission(submission) {
        const result = await releaseBrowserBackgroundWithdrawalSubmission(submission);
        await this.reload();
        this.notify();
        return result;
    }

    async cancelBackgroundWithdrawalPreparation(recordId) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record) throw new Error('This saved withdrawal is no longer available.');
        const submission = { ...this.backgroundWithdrawalIdentity(record),
            submissionId: record.startSubmissionId, operationId: record.startOperationId };
        const result = await releaseBrowserBackgroundWithdrawalSubmission(submission, { requireNoNonce: true });
        await this.reload();
        this.notify();
        return result;
    }

    async rememberBackgroundWithdrawalTransaction(hash, submission, metadata = null) {
        const result = await rememberBrowserBackgroundWithdrawalTransaction(hash, submission, metadata);
        await this.reload();
        this.notify();
        return result;
    }

    async parkPreparedWithdrawal() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const prepared = this.runtime.preparedWithdrawal;
            const noteId = Number(this.runtime.state?.note_id);
            if (!prepared || (prepared.mode !== 'mutual' && prepared.clearanceReserved !== true)
                || !Number.isFinite(noteId)) {
                throw new Error('There is no withdrawal-only balance to set aside.');
            }
            const hashes = Array.isArray(prepared.transactionHashes)
                ? prepared.transactionHashes
                : prepared.transactionHash ? [prepared.transactionHash] : [];
            if (!['reserving', 'prepared'].includes(prepared.phase || 'prepared')
                || prepared.submissionId || hashes.length) {
                throw new Error('Check the submitted withdrawal before setting this balance aside.');
            }
            const result = await parkBrowserWithdrawal({
                recordId: this.withdrawalRecordId(noteId),
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address,
                mode: prepared.mode,
                phase: 'parked',
                noteId,
                destination: prepared.destination,
                finalBalance: Number(prepared.public_inputs?.final_balance
                    ?? this.runtime.state.current_balance),
                createdAt: Number(prepared.createdAt || Date.now())
            });
            this.runtime = result.runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            this.activeLease = null;
            this.notify();
            return result.withdrawal;
        });
    }

    async updateWithdrawal(recordId, changes = {}, options = {}) {
        await this.init();
        const updated = await updateBrowserWithdrawal(recordId, changes, options);
        await this.reload();
        this.notify();
        return updated;
    }

    async currentPreparedWithdrawal() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return this.runtime.preparedWithdrawal
                ? structuredClone(this.runtime.preparedWithdrawal)
                : null;
        });
    }

    async currentWithdrawal(recordId) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const record = this.withdrawals.find(entry => entry.recordId === recordId);
            return record ? structuredClone(record) : null;
        });
    }

    /** Every withdrawal record of this deployment, re-read under the wallet lock. */
    async currentWithdrawals() {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            return structuredClone(this.withdrawals);
        });
    }

    async claimBackgroundWithdrawalStartReplacement(recordId, expectedFrom) {
        await this.init();
        const result = await claimBrowserWithdrawalStartReplacement(
            recordId,
            this.ownerId,
            expectedFrom
        );
        await this.reload();
        this.notify();
        return result;
    }

    async claimWithdrawalFinalization(recordId) {
        await this.init();
        const result = await claimBrowserWithdrawalFinalization(
            recordId,
            this.ownerId
        );
        await this.reload();
        this.notify();
        return result;
    }

    async claimWithdrawalFinalizationReplacement(recordId, expectedFrom) {
        await this.init();
        const result = await claimBrowserWithdrawalFinalizationReplacement(
            recordId,
            this.ownerId,
            expectedFrom
        );
        await this.reload();
        this.notify();
        return result;
    }

    async rememberWithdrawalFinalization(
        recordId,
        transactionHash,
        submission = null,
        transactionMetadata = null
    ) {
        await this.init();
        const result = await rememberBrowserWithdrawalFinalization(
            recordId,
            transactionHash,
            submission,
            transactionMetadata
        );
        await this.reload();
        this.notify();
        return result;
    }

    async rememberWithdrawalFinalizationSubmissionMetadata(
        recordId,
        submission,
        transactionMetadata
    ) {
        await this.init();
        const result = await rememberBrowserWithdrawalFinalizationSubmissionMetadata(
            recordId,
            submission,
            transactionMetadata
        );
        await this.reload();
        this.notify();
        return result;
    }

    async releaseWithdrawalFinalization(recordId, options = {}) {
        await this.init();
        const result = await releaseBrowserWithdrawalFinalization(recordId, options);
        await this.reload();
        this.notify();
        return result;
    }

    async markWithdrawalFinalizationMissingReceipts(recordId, expectedTransactionHashes) {
        await this.init();
        const result = await markBrowserWithdrawalFinalizationMissingReceipts(
            recordId,
            expectedTransactionHashes
        );
        await this.reload();
        this.notify();
        return result;
    }

    async releaseWithdrawalFinalizationReplacementClaim(
        recordId,
        submission,
        message = null
    ) {
        await this.init();
        const result = await releaseBrowserWithdrawalFinalizationReplacementClaim(
            recordId,
            submission,
            message
        );
        await this.reload();
        this.notify();
        return result;
    }

    async markWithdrawalFinalizationAmbiguous(recordId, submission, message = null) {
        await this.init();
        const result = await markBrowserWithdrawalFinalizationAmbiguous(
            recordId,
            submission,
            message
        );
        await this.reload();
        this.notify();
        return result;
    }

    async markWithdrawalFinalizationUnknown(recordId) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record?.finalizeSubmissionId || !record.finalizeOperationId) {
            throw new Error('There is no finalization wallet request waiting to be recovered.');
        }
        if (record.phase === 'ambiguous') return record;
        return this.markWithdrawalFinalizationAmbiguous(recordId, {
            recordId,
            submissionId: record.finalizeSubmissionId,
            operationId: record.finalizeOperationId,
            generation: Number(record.finalizeGeneration || 0),
            deploymentId: record.deploymentId,
            chainId: Number(record.chainId),
            contractAddress: record.contractAddress,
            noteId: Number(record.noteId),
            destination: record.destination
        }, 'The wallet prompt was closed before a transaction ID was saved.');
    }

    async resolveChallengedWithdrawalFinalization(recordId, {
        expectedRevision = null,
        observedBlock = null
    } = {}) {
        await this.init();
        await this.reload();
        const record = this.withdrawals.find(entry => entry.recordId === recordId);
        if (!record?.finalizeSubmissionId || !record.finalizeOperationId) {
            throw new Error('There is no challenged wallet prompt to release.');
        }
        const result = await resolveBrowserChallengedFinalization(recordId, {
            recordId,
            submissionId: record.finalizeSubmissionId,
            operationId: record.finalizeOperationId,
            generation: Number(record.finalizeGeneration || 0),
            deploymentId: record.deploymentId,
            chainId: Number(record.chainId),
            contractAddress: record.contractAddress,
            noteId: Number(record.noteId),
            destination: record.destination
        }, { expectedRevision, observedBlock });
        await this.reload();
        this.notify();
        return result;
    }

    async authorizeWithdrawalFinalizationRetry(recordId) {
        await this.init();
        const result = await authorizeBrowserWithdrawalFinalizationRetry(recordId);
        await this.reload();
        this.notify();
        return result;
    }

    async restoreWithdrawal(recordId, {
        expectedRevision = null,
        observedBlock = null
    } = {}) {
        await this.init();
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const record = this.withdrawals.find(entry => entry.recordId === recordId);
            if (!record) throw new Error('The recoverable private balance is no longer available.');
            if (expectedRevision == null || Number(record.revision) !== Number(expectedRevision)) {
                throw new Error('The withdrawal changed after its on-chain status was checked. Check it again before selecting this balance.');
            }
            const chainFloor = Math.max(
                Number(record.startBlockNumber || 0),
                Number(record.lastObservedBlock || 0)
            );
            if (observedBlock == null || Number(observedBlock) < chainFloor) {
                throw new Error('The connected RPC has not caught up to this withdrawal. Check it again before selecting this balance.');
            }
            const runtime = await restoreBrowserWithdrawal(recordId, {
                deploymentId: this.manifest.deployment_id,
                chainId: Number(this.config.funding.chain_id),
                contractAddress: this.config.funding.contract_address
            }, expectedRevision);
            this.runtime = runtime;
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            this.notify();
            return this.walletStatus();
        });
    }

    async archiveNote(reason = 'closed', expectedNoteId = null) {
        await this.init();
        if (expectedNoteId == null) {
            throw new Error('Archiving a private note requires its exact note identity.');
        }
        return withBrowserWalletLock(this.manifest.deployment_id, async () => {
            await this.reload();
            const noteId = expectedNoteId ?? this.runtime.state?.note_id;
            if (reason === 'expiry-claimed' && this.activeLease?.inFlight > 0) {
                throw new Error('Finish the current response before starting a new private balance.');
            }
            this.runtime = await archiveBrowserWallet(reason, noteId);
            this.withdrawals = await listBrowserWithdrawals(this.manifest.deployment_id);
            if (reason === 'expiry-claimed' && this.settlementTimer) {
                clearTimeout(this.settlementTimer);
                this.settlementTimer = null;
            }
            this.activeLease = null;
            this.notify();
            return this.walletStatus();
        });
    }
}

const browserWalletRuntime = new BrowserWalletRuntime();
export { BrowserWalletHttpError, BrowserWalletRuntime };
export default browserWalletRuntime;
