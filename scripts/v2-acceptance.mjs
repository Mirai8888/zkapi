#!/usr/bin/env node
// Entirely local end-to-end acceptance of circuit zkapi-v2-concession-v1
// (vault revision 3), the §10.7 Phase B drill scenarios that run on a local
// chain, and a gas measurement (docs/v2-acceptance.md).
//
// Real: the contracts (deployed by demo/contracts/script/Deploy.s.sol and
// finalized by scripts/expected-codehashes.mjs), the dev setup's Groth16
// proofs, `zkapi serverd` (a drill build with --adversary modes),
// zkapi-indexerd, zkapi-challenged, the challenge signer sidecar
// (docker/aws/signer), the browser SDK (sdk/, its WebAssembly in Node), the
// clientd companion (zkapi-walletd) and the in-memory wallet driver
// (examples/v2_acceptance_wallet.rs, the browser wallet core natively).
// Mocks: the OpenRouter-style provider and the ETH/USD price feed, both on
// loopback. Anvil runs with Sepolia's chain ID, because the signer signs only
// for 1 and 11155111; nothing leaves loopback.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SETUP_DIR = path.join(ROOT, 'protocol/setup/v2-concession-dev');
// Anvil with Sepolia's chain ID: the signer sidecar refuses any other chain
// but mainnet's. Deploy.s.sol treats it as off a local chain, so the drill
// vault's dev setup needs ALLOW_DEV_SETUP=1 there, as on Sepolia.
export const CHAIN_ID = 11155111;
const GWEI = 1_000_000_000n;
const DEPOSIT = 1_000_000; // gwei: 0.001 ETH per note
const CAP = 50_000; // request_charge_cap: every request's solvency bound
const MOCK_USAGE_MICRO_USD = 1_000;
const MOCK_PRICE = 250_000_000_000n; // $2,500 / ETH, eight decimal places.
// One accepted inference ($0.001 at $2,500) costs ceil(1e3 µUSD → gwei) = 400.
export const INFERENCE_CHARGE = Number((BigInt(MOCK_USAGE_MICRO_USD) * GWEI * 100_000_000n + MOCK_PRICE * 1_000_000n - 1n)
    / (MOCK_PRICE * 1_000_000n));
const MODEL = 'local/mock-model';
const PROMPT = 'Reply with the word OK.';
// Drill timing, scaled down so a challenge period is skipped with
// evm_increaseTime. Both daemons' startup checks must hold (drillTiming).
export const TIMING = Object.freeze({
    challengePeriod: 3_600,
    maxPauseDuration: 7_200,
    noteTtl: 30 * 86_400,
    leaseTtl: 60,
    settlementGrace: 1,
    settlementDeadline: 901,
    settlementPoll: 1,
    raiseLead: 1_200,
});
// Skipping a challenge period moves only block time; the daemons' and
// clients' clocks stay on the wall clock. The chain starts this far behind
// it, so that block time and the wall clock meet when the bounded pause ends
// (two skipped periods), before the missed-defeat drill: the challenger
// counts a miss only for server evidence written (wall clock) before the
// escape's deadline (block time). From there block time runs at most one
// challenge period ahead, well within the 3 h validity of every exit proof
// (which clients bound by the wall clock); an SDK judging a deadline then
// gets its device clock moved to block time.
const CHAIN_LAG_SECONDS = 2 * TIMING.challengePeriod;
const MAX_CHAIN_LEAD_SECONDS = 2 * TIMING.challengePeriod;
const INDEXER_CONFIRMATIONS = 2;
// Challenger fee policy: the daemon proposes both EIP-1559 fees within these
// caps; the signer enforces its own copy of them.
const CHALLENGE_MAX_FEE_PER_GAS = 100n * GWEI;
const CHALLENGE_MAX_PRIORITY_FEE_PER_GAS = 10n * GWEI;
const CHALLENGE_PRIORITY_FEE_PER_GAS = 2n * GWEI;
// Anvil's mnemonic: public test keys, funded only on a disposable chain.
const MNEMONIC = 'test test test test test test test test test test test junk';
const ANVIL_KEYS = Object.freeze([
    '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
    '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
]);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const json = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2);
const hex = value => `0x${BigInt(value).toString(16)}`;
const word = value => BigInt(value).toString(16).padStart(64, '0');
const felt = value => `0x${word(value)}`;
// Explicit agents bypass Node's optional global environment-proxy support.
const localAgent = new http.Agent({ keepAlive: false, proxyEnv: {} });

function loopback(url) {
    const parsed = new URL(url);
    assert.equal(parsed.protocol, 'http:', 'this test permits only loopback HTTP');
    assert.equal(parsed.hostname, '127.0.0.1', 'this test never calls public networks');
    assert.equal(parsed.username + parsed.password, '');
    return parsed;
}

async function body(req) {
    const chunks = [];
    let bytes = 0;
    for await (const chunk of req) {
        bytes += chunk.length;
        assert.ok(bytes < 4_194_304, 'oversized local HTTP request');
        chunks.push(chunk);
    }
    return JSON.parse(Buffer.concat(chunks).toString() || '{}');
}

function respond(res, status, value) {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(value));
}

export async function localJSON(url, { method = 'GET', value, headers = {}, timeoutMs = 60_000 } = {}) {
    const parsed = loopback(url);
    return new Promise((resolve, reject) => {
        const outgoing = http.request(parsed, { method, agent: localAgent,
            headers: { 'content-type': 'application/json', ...headers } }, incoming => {
            const chunks = [];
            incoming.on('data', chunk => chunks.push(chunk));
            incoming.on('error', reject);
            incoming.on('end', () => {
                const text = Buffer.concat(chunks).toString();
                try { resolve({ status: incoming.statusCode, headers: incoming.headers, value: text ? JSON.parse(text) : null }); }
                catch { resolve({ status: incoming.statusCode, headers: incoming.headers, value: null, text }); }
            });
        });
        outgoing.setTimeout(timeoutMs, () => outgoing.destroy(new Error('Local HTTP request timed out')));
        outgoing.on('error', reject);
        outgoing.end(value === undefined ? undefined : JSON.stringify(value));
    });
}

// Forwards one JSON-RPC call and relays an upstream error unchanged, so the
// caller sees the node's own {code, message, data} (for example revert data).
export async function proxyJsonRpc(url, call) {
    const upstream = await localJSON(url, { method: 'POST',
        value: { jsonrpc: '2.0', id: call.id, method: call.method, params: call.params ?? [] } });
    assert.equal(upstream.status, 200, `upstream JSON-RPC answered HTTP ${upstream.status}`);
    if (upstream.value.error) {
        const { code, message, data } = upstream.value.error;
        return { jsonrpc: '2.0', id: call.id, error: data === undefined ? { code, message } : { code, message, data } };
    }
    return { jsonrpc: '2.0', id: call.id, result: upstream.value.result };
}

export const CHALLENGE_TRANSACTION_FIELDS = Object.freeze(
    ['data', 'from', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce', 'to']);

// The challenger proposes both EIP-1559 fees within its caps and nothing else:
// no gasPrice, type, value, chainId or access list.
export function challengeFees(tx, maxFeePerGasCap) {
    assert.deepEqual(Object.keys(tx).sort(), CHALLENGE_TRANSACTION_FIELDS,
        'a challenge transaction carries exactly the EIP-1559 send fields');
    for (const field of ['gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce']) {
        assert.match(tx[field], /^0x(0|[1-9a-f][0-9a-f]*)$/, `${field} must be a canonical hex quantity`);
    }
    const maxFeePerGas = BigInt(tx.maxFeePerGas);
    const maxPriorityFeePerGas = BigInt(tx.maxPriorityFeePerGas);
    assert.ok(maxPriorityFeePerGas > 0n && maxPriorityFeePerGas <= maxFeePerGas && maxFeePerGas <= maxFeePerGasCap,
        'challenge fees must satisfy 0 < maxPriorityFeePerGas <= maxFeePerGas <= the cap');
    return { maxFeePerGas, maxPriorityFeePerGas };
}

// The startup checks of serverd (settlement within half the challenge
// period) and zkapi-challenged (G5 and the raise timing), for TIMING.
export function drillTiming(timing = TIMING) {
    const window = timing.leaseTtl + timing.settlementGrace + timing.settlementDeadline;
    const poll = Math.max(1, timing.settlementPoll);
    const checks = {
        settlement_window_seconds: window,
        deadline_leaves_retries: timing.settlementDeadline >= timing.settlementGrace + 900,
        server_settlement: window + 2 * poll + 600 <= Math.floor(timing.challengePeriod / 2),
        challenger_g5: window + 2 * poll + 600 <= Math.floor(timing.challengePeriod / 2),
        challenger_raise: window + timing.raiseLead + 4 * poll + 1_200 <= timing.challengePeriod,
        bounded_pause: timing.maxPauseDuration >= 2 * timing.challengePeriod,
    };
    return { ...checks, ok: Object.entries(checks).every(([key, value]) => key === 'settlement_window_seconds' || value) };
}

// The deployment profile (§10.3 `trusted_deployment`) of a finalized
// Deploy.s.sol manifest, as serverd, zkapi-challenged, the SDK and the
// companion read it. Only a finalized manifest is a deployment.
export function trustedDeployment(finalized, services) {
    assert.equal(finalized.deploymentStatus, 'deployed', 'profiles come only from a finalized manifest');
    assert.ok(Number.isSafeInteger(finalized.deployBlock) && finalized.deployBlock > 0, 'finalized manifests carry deployBlock');
    assert.equal(finalized.vaultRevision, 3);
    assert.equal(finalized.concessionEscapeVersion, 1);
    const key = (x, y) => ({ x: felt(x), y: felt(y) });
    return {
        deployment_status: 'deployed',
        deployment_id: services.deploymentId,
        chain_id: finalized.chainId,
        contract_address: finalized.vault.toLowerCase(),
        deploy_block: finalized.deployBlock,
        billing_token_address: null,
        protocol_server_url: services.protocolServerUrl,
        indexer_url: services.indexerUrl,
        request_charge_cap: finalized.requestChargeCap,
        state_signing_key: key(finalized.stateSigningKeyX, finalized.stateSigningKeyY),
        clearance_signing_key: key(finalized.clearanceSigningKeyX, finalized.clearanceSigningKeyY),
        rpc_url: services.rpcUrl,
        billing_asset: finalized.billing_asset,
        billing_unit: finalized.billing_unit,
        native_asset_wei_per_unit: String(finalized.nativeAssetWeiPerUnit),
        native_price_feed_address: services.priceFeed,
        native_price_feed_decimals: 8,
        native_price_max_age_seconds: 4_500,
        circuit_id: finalized.circuitId,
        setup_id: finalized.setupId,
        request_proving_key_sha256: services.keyHashes.requestPk,
        withdrawal_proving_key_sha256: services.keyHashes.withdrawalPk,
        request_verifying_key_sha256: services.keyHashes.requestVk,
        request_vk_keccak256: finalized.requestVkKeccak256,
        withdrawal_vk_keccak256: finalized.withdrawalVkKeccak256,
        vault_runtime_codehash: finalized.vaultRuntimeCodehash,
        proof_adapter_address: finalized.proofAdapter.toLowerCase(),
        adapter_runtime_codehash: finalized.adapterRuntimeCodehash,
        poseidon_library_address: finalized.poseidonLibrary.toLowerCase(),
        poseidon_runtime_codehash: finalized.poseidonRuntimeCodehash,
        challenge_period: finalized.challengePeriod,
        note_ttl: finalized.noteTtl,
        max_pause_duration: finalized.maxPauseDuration,
        settlement_window_seconds: services.settlementWindowSeconds,
        vault_revision: 3,
        exit_concession: 1,
        clearance_ownership_proof: 'required',
        allow_dev_setup: finalized.allowDevSetup,
        canary: null,
        // Never contacted: the drill server issues direct provider keys,
        // not OA-verifier-backed ones, but the profile pins a verifier origin.
        verifier_url: services.verifierUrl,
        openrouter_inference_base: services.inferenceBase,
    };
}

// The forward proxy a packaged companion must use (OA_ZKAPI_BRIDGE_TOKEN set):
// only requests carrying the proxy's own basic credentials pass.
export function proxyAuthorized(header, user, password) {
    if (typeof header !== 'string' || !header.startsWith('Basic ')) return false;
    const expected = Buffer.from(`${user}:${password}`).toString('base64');
    const actual = header.slice(6).trim();
    return actual.length === expected.length && Buffer.compare(Buffer.from(actual), Buffer.from(expected)) === 0;
}

// Exported so the accounting mock itself can be tested without starting the chain.
export function mockProvider(managementKey = 'local-only-management-key') {
    const keys = new Map();
    const events = [];
    let pendingCreateFailures = 0;
    const handler = async (req, res) => {
        try {
            const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
            if (pathname === '/v1/chat/completions' && req.method === 'POST') {
                const key = [...keys.values()].find(k => req.headers.authorization === `Bearer ${k.key}`);
                if (!key || key.disabled || key.deleted || Date.parse(key.expires_at) <= Date.now()) {
                    return respond(res, 401, { error: 'invalid or retired local runtime key' });
                }
                const request = await body(req);
                if (request.model !== MODEL || request.stream === true
                    || !Array.isArray(request.messages) || request.messages.length !== 1 || request.messages[0].role !== 'user'
                    || request.messages[0].content !== PROMPT) {
                    return respond(res, 400, { error: 'unexpected acceptance-test inference request' });
                }
                if (key.usage_micro_usd + MOCK_USAGE_MICRO_USD > Math.floor(key.limit * 1_000_000)) {
                    return respond(res, 402, { error: 'local runtime key spending limit reached' });
                }
                key.usage_micro_usd += MOCK_USAGE_MICRO_USD;
                key.calls += 1;
                events.push({ type: 'inference', hash: key.hash, usage_micro_usd: key.usage_micro_usd });
                return respond(res, 200, { id: `local-${key.calls}`, object: 'chat.completion', model: MODEL,
                    choices: [{ index: 0, message: { role: 'assistant', content: 'OK' }, finish_reason: 'stop' }],
                    usage: { prompt_tokens: 6, completion_tokens: 1, total_tokens: 7, cost: MOCK_USAGE_MICRO_USD / 1_000_000 } });
            }
            if (req.headers.authorization !== `Bearer ${managementKey}`) {
                return respond(res, 401, { error: 'local management authentication required' });
            }
            if (pathname === '/v1/keys' && req.method === 'POST') {
                const value = await body(req);
                assert.ok(value.limit > 0 && value.limit <= 1, 'bounded local key limit required');
                assert.equal(value.include_byok_in_limit, true);
                assert.ok(Date.parse(value.expires_at) > Date.now());
                if (pendingCreateFailures > 0) {
                    pendingCreateFailures--;
                    events.push({ type: 'create_failed', name: value.name });
                    return respond(res, 503, { error: 'injected local key creation failure' });
                }
                const hash = randomUUID();
                const key = { ...value, hash, key: `local-runtime-${randomUUID()}`, disabled: false,
                    deleted: false, usage_micro_usd: 0, calls: 0 };
                keys.set(hash, key);
                events.push({ type: 'issued', hash, limit_usd: key.limit });
                return respond(res, 200, { key: key.key, data: { ...value, hash } });
            }
            const match = /^\/v1\/keys\/([0-9a-f-]+)$/.exec(pathname);
            const key = match && keys.get(match[1]);
            if (!key || key.deleted) return respond(res, 404, { error: 'unknown local key' });
            if (req.method === 'PATCH') {
                assert.deepEqual(await body(req), { disabled: true });
                key.disabled = true;
                events.push({ type: 'disabled', hash: key.hash });
            } else if (req.method === 'DELETE') {
                assert.equal(key.disabled, true, 'production settlement must disable before deleting');
                key.deleted = true;
                events.push({ type: 'deleted', hash: key.hash });
                return respond(res, 200, { deleted: true });
            } else if (req.method === 'GET') {
                events.push({ type: 'usage_read', hash: key.hash, usage_micro_usd: key.usage_micro_usd, disabled: key.disabled });
            } else {
                return respond(res, 405, { error: 'unsupported local mock operation' });
            }
            return respond(res, 200, { data: { hash: key.hash, usage: key.usage_micro_usd / 1_000_000,
                byok_usage: 0, disabled: key.disabled } });
        } catch (error) {
            respond(res, 400, { error: error.message });
        }
    };
    return { handler, keys, events, failNextCreate: () => { pendingCreateFailures++; } };
}

// The OA org (station-issued keys) and its verifier, for the clientd
// companion, which accepts only OA org keys: the org mints each key at the
// provider mock and reports its usage once the key has expired (an OA key is
// never revoked early), and the verifier binds the key it is shown.
export function mockOaOrg(provider, options) {
    const issued = new Map();
    const signature = () => randomBytes(64).toString('hex');
    const now = () => Math.floor(Date.now() / 1000);
    const org = async (req, res) => {
        const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
        if (req.headers.authorization !== `Bearer ${options.sharedSecret}`) return respond(res, 401, { detail: 'unauthorized' });
        const value = await body(req);
        if (pathname === '/api/zkapi/request_key') {
            const expiresAt = now() + value.duration_minutes * 60;
            const hash = randomUUID();
            const key = { name: value.client_request_id, limit: value.credit_limit, include_byok_in_limit: true,
                expires_at: new Date(expiresAt * 1000).toISOString(), hash, key: `local-oa-${randomUUID()}`, disabled: false,
                deleted: false, usage_micro_usd: 0, calls: 0 };
            provider.keys.set(hash, key);
            provider.events.push({ type: 'issued', hash, limit_usd: key.limit, source: 'oa_org' });
            issued.set(hash, { expiresAt, limitCredits: value.credit_limit_credits });
            return respond(res, 200, { source: 'oa_org', replayed: false, key: key.key, key_hash: hash, credit_limit: value.credit_limit,
                duration_minutes: value.duration_minutes, expires_at_unix: expiresAt, station_id: 'local-oa-station',
                station_recently_attested: true, station_signature: signature(), org_signature: signature(),
                verifier_url: options.verifierUrl, openrouter_api_base: options.inferenceBase });
        }
        if (pathname === '/api/zkapi/key_usage') {
            const lease = issued.get(value.key_hash);
            const key = provider.keys.get(value.key_hash);
            if (!lease || !key) return respond(res, 404, { detail: 'unknown key' });
            const common = { source: 'oa_org', version: 1, client_request_id: value.client_request_id, key_hash: value.key_hash,
                station_request_id: createHash('sha256').update(value.key_hash).digest('hex') };
            if (now() < lease.expiresAt) return respond(res, 200, { ...common, status: 'pending', retry_after_seconds: 1 });
            provider.events.push({ type: 'usage_read', hash: key.hash, usage_micro_usd: key.usage_micro_usd, source: 'oa_org' });
            return respond(res, 200, { ...common, status: 'finalized', usage_credits: key.usage_micro_usd,
                credit_limit_credits: value.credit_limit_credits, expires_at_unix: lease.expiresAt, closed_at_unix: lease.expiresAt,
                finalized_at_unix: now(), station_id: 'local-oa-station', station_signature: signature(), org_signature: signature() });
        }
        respond(res, 404, { detail: 'not found' });
    };
    const verifier = async (req, res) => {
        const value = await body(req);
        const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
        if (pathname !== '/submit_key' || !value.api_key) return respond(res, 404, { detail: 'not found' });
        return respond(res, 200, { status: 'verified', station_id: value.station_id,
            key_hash: createHash('sha256').update(value.api_key).digest('hex') });
    };
    return { org, verifier, issued };
}

// Collects every receipt's gas by operation (gas.json).
export function gasLedger() {
    const entries = [];
    return {
        entries,
        record(operation, receipt, extra = {}) {
            assert.ok(receipt?.gasUsed, `no receipt for ${operation}`);
            entries.push({ operation, gas_used: Number(BigInt(receipt.gasUsed)), status: Number(BigInt(receipt.status)),
                transaction: receipt.transactionHash, block: Number(BigInt(receipt.blockNumber)), ...extra });
        },
        summary() {
            const byOperation = {};
            for (const entry of entries) {
                const item = byOperation[entry.operation] ??= { count: 0, min: Infinity, max: 0, total: 0 };
                item.count++;
                item.min = Math.min(item.min, entry.gas_used);
                item.max = Math.max(item.max, entry.gas_used);
                item.total += entry.gas_used;
            }
            for (const item of Object.values(byOperation)) item.mean = Math.round(item.total / item.count);
            return byOperation;
        },
    };
}

function options(args) {
    const parsed = { binDir: path.join(ROOT, 'target/acceptance/release'), outputDir: path.join(ROOT, '.zkapi/acceptance'),
        stopAfter: null };
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--help') return { help: true };
        const key = { '--bin-dir': 'binDir', '--output-dir': 'outputDir', '--stop-after': 'stopAfter' }[args[i]];
        assert.ok(key && args[i + 1], `Unknown or incomplete option: ${args[i]}`);
        parsed[key] = key === 'stopAfter' ? args[++i] : path.resolve(args[++i]);
    }
    return parsed;
}

// A per-run operator seed: 31 random bytes, below the subgroup order and far
// from zero, as the server's seed policy requires.
const randomSeed = () => `0x${randomBytes(31).toString('hex')}`;

// Revert data of a JSON-RPC error, wherever the node put it.
const revertData = error => [error?.data, error?.data?.data, error?.error?.data]
    .find(data => typeof data === 'string' && data.startsWith('0x'));

class RpcCallError extends Error {
    constructor(method, error) {
        super(`${method}: ${JSON.stringify(error)}`);
        this.rpcError = error;
        this.data = revertData(error);
    }
}

async function main() {
    const opts = options(process.argv.slice(2));
    if (opts.help) {
        console.log('Usage: node scripts/v2-acceptance.mjs [--bin-dir target/acceptance/release] [--output-dir .zkapi/acceptance] [--stop-after STEP]\n'
            + 'Runs only disposable loopback services, with mock provider, OA org and price feed. See docs/v2-acceptance.md.\n'
            + '--stop-after ends a development run early, after one of: deploy, stack, honest, stale, clients, mismatch, sdk-honest,\n'
            + 'raise, companion, pause, pause-max, anchors, lie-expired, withhold, missed.');
        return;
    }
    const { AbiCoder, Interface } = await import(
        pathToFileURL(path.join(ROOT, 'docker/aws/signer/node_modules/ethers/lib.esm/index.js')).href);
    const coder = AbiCoder.defaultAbiCoder();
    const started = Date.now();
    const runId = `${new Date().toISOString().replaceAll(':', '-')}-${randomUUID().slice(0, 8)}`;
    const runDir = path.join(opts.outputDir, runId);
    await fs.mkdir(runDir, { recursive: true, mode: 0o700 });
    await fs.chmod(runDir, 0o700);
    const readJSON = async p => JSON.parse(await fs.readFile(p, 'utf8'));
    const save = (name, value) => fs.writeFile(path.join(runDir, name), json(value), { mode: 0o600 });
    // Fresh operator seeds for this run. They reach only the environment of
    // `zkapi signing-keys` and `zkapi serverd`; nothing writes them to the run
    // directory, and the run fails if any saved file contains one.
    const seedEnv = { ZKAPI_STATE_SEED: randomSeed(), ZKAPI_CLEAR_SEED: randomSeed() };
    const children = new Set();
    const servers = new Set();
    const scenarios = [];
    const gas = gasLedger();
    const evidence = {};
    let interrupted = false;
    // The first assertion failure inside a loopback mock or proxy; it fails
    // the run instead of surfacing to a daemon as a transport error.
    let fatal;
    let miner = null;
    const onSignal = () => {
        interrupted = true;
        for (const child of children) child.kill('SIGINT');
    };
    process.on('SIGINT', onSignal);
    process.on('SIGTERM', onSignal);
    const check = () => {
        if (interrupted) throw new Error('Local acceptance test interrupted');
        if (fatal) throw fatal;
    };
    const log = message => console.log(`[${((Date.now() - started) / 1000).toFixed(0).padStart(4)} s] ${message}`);
    async function waitFor(label, fn, timeout = 60_000, interval = 200) {
        const end = Date.now() + timeout;
        let last;
        while (Date.now() < end) {
            check();
            try { const value = await fn(); if (value) return value; } catch (error) { last = error; }
            await delay(interval);
        }
        check();
        throw new Error(`Timeout: ${label}${last ? ` (${last.message})` : ''}`);
    }
    // Each scenario's outcome: PASS with its evidence, or FAIL (which ends the
    // run: later scenarios build on the chain the earlier ones left).
    async function scenario(name, fn) {
        check();
        log(`scenario: ${name}`);
        const begin = Date.now();
        try {
            const result = await fn();
            scenarios.push({ name, status: 'PASS', seconds: (Date.now() - begin) / 1000, ...result });
            await save('scenarios.json', scenarios);
            return result;
        } catch (error) {
            scenarios.push({ name, status: 'FAIL', seconds: (Date.now() - begin) / 1000, error: error.message });
            await save('scenarios.json', scenarios);
            throw error;
        }
    }
    const stopAfter = step => {
        if (opts.stopAfter === step) throw Object.assign(new Error(`stopped after ${step}`), { stopped: true });
    };
    function launch(command, args, logName, { interactive = false, env = {}, cwd = ROOT } = {}) {
        check();
        const out = createWriteStream(path.join(runDir, logName), { flags: 'a', mode: 0o600 });
        // No inherited credentials, network proxies, HOME, or provider settings.
        const child = spawn(command, args, { cwd, env: { PATH: process.env.PATH,
            RUST_LOG: 'warn,zkapi=info,zkapi_serverd=info,zkapi_indexerd=info,zkapi_companion=info,zkapi_walletd=info,r1cs=warn',
            ...env }, stdio: [interactive ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
        if (!interactive) child.stdout.pipe(out);
        child.stderr.pipe(out);
        child.once('error', error => out.write(error.message));
        child.once('close', () => { children.delete(child); out.end(); });
        children.add(child);
        return child;
    }
    // Runs a process that must exit by itself and returns its exit status and
    // output. The event loop keeps serving the loopback mocks meanwhile.
    async function runToExit(command, args, logName, env = {}, { timeout = 300_000, cwd = ROOT } = {}) {
        const child = launch(command, args, logName, { env, cwd });
        let output = '';
        child.stdout.on('data', chunk => { output += chunk; });
        child.stderr.on('data', chunk => { output += chunk; });
        const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
        const [code, signal] = await new Promise((resolve, reject) => {
            child.once('error', reject);
            child.once('close', (exitCode, exitSignal) => resolve([exitCode, exitSignal]));
        });
        clearTimeout(timer);
        return { code, signal, output };
    }
    async function stop(child) {
        if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
        const done = new Promise(resolve => child.once('exit', resolve));
        child.kill('SIGINT');
        await Promise.race([done, delay(3000)]);
        if (child.exitCode === null && child.signalCode === null) {
            child.kill('SIGKILL');
            await Promise.race([done, delay(3000)]);
        }
    }
    async function freePort() {
        const server = net.createServer();
        await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
        const port = server.address().port;
        await new Promise(resolve => server.close(resolve));
        return port;
    }
    async function serve(handler, server = http.createServer()) {
        server.on('request', (req, res) => Promise.resolve(handler(req, res)).catch(error => {
            if (!res.headersSent) respond(res, 500, { error: error.message });
            else res.destroy();
        }));
        await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
        servers.add(server);
        return `http://127.0.0.1:${server.address().port}`;
    }
    async function request(url, { method = 'GET', value, headers = {}, timeoutMs } = {}) {
        check();
        return localJSON(url, { method, value, headers, timeoutMs });
    }
    async function get(url) {
        const result = await request(url);
        assert.equal(result.status, 200, `${new URL(url).pathname}: ${result.value?.error_code ?? result.status} ${JSON.stringify(result.value)}`);
        return result.value;
    }
    let rpcId = 0;
    async function rpcRaw(url, method, params = []) {
        const result = await request(url, { method: 'POST', value: { jsonrpc: '2.0', id: ++rpcId, method, params } });
        assert.equal(result.status, 200, `${method}: HTTP ${result.status}`);
        return result.value;
    }
    async function rpcAt(url, method, params = []) {
        const reply = await rpcRaw(url, method, params);
        if (reply.error) throw new RpcCallError(method, reply.error);
        return reply.result;
    }
    function sha256File(file) {
        return fs.readFile(file).then(bytes => createHash('sha256').update(bytes).digest('hex'));
    }
    const toolEnv = () => Object.fromEntries(['HOME', 'SVM_HOME', 'FOUNDRY_DIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME']
        .filter(name => process.env[name]).map(name => [name, process.env[name]]));

    const companions = [];
    const sdkAgents = [];
    try {
        log('Starting the local concession-exit acceptance: real contracts, proofs, daemons, signer, SDK and companion; mock provider and price feed.');
        const timing = drillTiming();
        assert.ok(timing.ok, `drill timing fails a daemon startup check: ${json(timing)}`);
        const W = timing.settlement_window_seconds;

        // ---------------------------------------------------------------- keys
        const signingKeysFor = env => spawnSync(path.join(opts.binDir, 'zkapi'), ['signing-keys'], { cwd: ROOT, encoding: 'utf8',
            env: { PATH: process.env.PATH, RUST_LOG: 'warn', ...env } });
        const derived = signingKeysFor(seedEnv);
        assert.equal(derived.status, 0, `zkapi signing-keys failed: ${derived.stderr}`);
        const signingKeys = JSON.parse(derived.stdout);
        const development = signingKeysFor({ ZKAPI_STATE_SEED: '0x1', ZKAPI_CLEAR_SEED: '0x2' });
        assert.notEqual(development.status, 0, 'signing-keys must refuse the published development seeds');
        assert.match(development.stderr, /published development key/);

        // ---------------------------------------------------------------- chain
        const anvilPort = await freePort();
        const rpcUrl = `http://127.0.0.1:${anvilPort}`;
        const genesisTimestamp = Math.floor(Date.now() / 1000) - CHAIN_LAG_SECONDS;
        launch('anvil', ['--host', '127.0.0.1', '--port', String(anvilPort), '--chain-id', String(CHAIN_ID),
            '--mnemonic', MNEMONIC, '--timestamp', String(genesisTimestamp), '--slots-in-an-epoch', '1', '--silent'],
            'anvil.log', { env: toolEnv() });
        await waitFor('Anvil startup', async () => await rpcAt(rpcUrl, 'eth_chainId') === hex(CHAIN_ID));
        const rpc = (method, params) => rpcAt(rpcUrl, method, params);
        const accounts = await rpc('eth_accounts');
        const [owner, challengerAccount, treasury] = accounts;
        // Each client and destination has its own account.
        const account = Object.fromEntries(['driver', 'companion', 'sdk', 'destination', 'thirdParty', 'sdkDestination', 'companionDestination']
            .map((name, index) => [name, accounts[3 + index]]));
        // Mines a block every second, so block time follows the wall clock
        // (CHAIN_LAG_SECONDS behind it) and confirmations and the finalized
        // tag (two blocks with --slots-in-an-epoch 1) keep advancing.
        miner = setInterval(() => { void rpc('evm_mine', []).catch(() => {}); }, 1_000);
        const chainNow = async () => Number(BigInt((await rpc('eth_getBlockByNumber', ['latest', false])).timestamp));
        async function skipChain(seconds, label) {
            const before = await chainNow();
            await rpc('evm_increaseTime', [seconds]);
            await rpc('evm_mine', []);
            const after = await chainNow();
            assert.ok(after >= before + seconds, 'the chain clock advanced');
            assert.ok(after <= Math.floor(Date.now() / 1000) + MAX_CHAIN_LEAD_SECONDS, 'block time stays within the exit proofs\' validity');
            (evidence.time_skips ??= []).push({ label, seconds, chain_before: before, chain_after: after,
                wall: Math.floor(Date.now() / 1000) });
            return after;
        }
        async function waitReceipt(hash, timeout = 60_000) {
            return waitFor(`receipt ${hash}`, () => rpc('eth_getTransactionReceipt', [hash]), timeout, 100);
        }
        async function sendTx({ from, to, data, value = 0n, gasLimit }) {
            const tx = { from, to, data, value: hex(value) };
            if (gasLimit) tx.gas = hex(gasLimit);
            return waitReceipt(await rpc('eth_sendTransaction', [tx]));
        }
        const balance = address => rpc('eth_getBalance', [address, 'latest']).then(BigInt);

        // ---------------------------------------------------------------- deployment
        log('Deploying with demo/contracts/script/Deploy.s.sol and finalizing its manifest on chain.');
        const deployDir = path.join(ROOT, '.demo', `acceptance-${runId}`);
        await fs.mkdir(deployDir, { recursive: true });
        const broadcastDir = path.join(runDir, 'broadcast');
        const deployEnv = {
            ...toolEnv(), FOUNDRY_BROADCAST: broadcastDir,
            PRIVATE_KEY: ANVIL_KEYS[0], OWNER: owner, TREASURY: treasury, CHAIN_ID: String(CHAIN_ID),
            OUTPUT_PATH: path.join(deployDir, 'deployment.json'), SETUP_MANIFEST: path.join(SETUP_DIR, 'manifest.json'),
            STATE_SIGNING_KEY_X: signingKeys.state_signing_key.x, STATE_SIGNING_KEY_Y: signingKeys.state_signing_key.y,
            CLEARANCE_SIGNING_KEY_X: signingKeys.clearance_signing_key.x, CLEARANCE_SIGNING_KEY_Y: signingKeys.clearance_signing_key.y,
            CHALLENGE_PERIOD_SECONDS: String(TIMING.challengePeriod), NOTE_TTL_SECONDS: String(TIMING.noteTtl),
            MAX_PAUSE_DURATION_SECONDS: String(TIMING.maxPauseDuration), REQUEST_CHARGE_CAP: String(CAP),
            // Off a local chain (this Anvil has Sepolia's ID) the single-party
            // dev setup deploys only as a drill vault.
            ALLOW_DEV_SETUP: '1',
        };
        const deployed = await runToExit('forge', ['script', 'script/Deploy.s.sol', '--rpc-url', rpcUrl, '--broadcast'],
            'deploy.log', deployEnv, { cwd: path.join(ROOT, 'demo/contracts') });
        assert.equal(deployed.code, 0, `Deploy.s.sol failed:\n${deployed.output.slice(-3000)}`);
        const pending = await readJSON(path.join(deployDir, 'deployment.json.pending'));
        assert.equal(pending.deploymentStatus, 'pending');
        assert.equal(pending.allowDevSetup, true);
        assert.ok(!('deployBlock' in pending), 'a provisional manifest has no deployBlock');
        const finalizedPath = path.join(deployDir, 'deployment.json');
        const finalizing = await runToExit(process.execPath, [path.join(ROOT, 'scripts/expected-codehashes.mjs'),
            '--deployment', path.join(deployDir, 'deployment.json.pending'), '--rpc', rpcUrl, '--finalize', finalizedPath,
            '--broadcast-log', path.join(broadcastDir, 'Deploy.s.sol', String(CHAIN_ID), 'run-latest.json')], 'finalize.log');
        assert.equal(finalizing.code, 0, `finalize failed:\n${finalizing.output}`);
        const finalized = await readJSON(finalizedPath);
        assert.equal(finalized.deploymentStatus, 'deployed');
        await fs.copyFile(path.join(deployDir, 'deployment.json.pending'), path.join(runDir, 'deployment.json.pending'));
        await fs.copyFile(finalizedPath, path.join(runDir, 'deployment.json'));
        await fs.rm(deployDir, { recursive: true, force: true });
        const vaultAddress = finalized.vault.toLowerCase();
        const deployBlock = finalized.deployBlock;
        assert.equal(await rpc('eth_getCode', [vaultAddress, hex(deployBlock - 1)]), '0x', 'deployBlock is the vault\'s creation block');
        for (const [key, coordinate] of [['state_signing_key', 'x'], ['state_signing_key', 'y'], ['clearance_signing_key', 'x'], ['clearance_signing_key', 'y']]) {
            const field = `${key === 'state_signing_key' ? 'state' : 'clearance'}SigningKey${coordinate.toUpperCase()}`;
            assert.equal(BigInt(finalized[field]), BigInt(signingKeys[key][coordinate]), `${field} pins this run's key`);
        }
        const vaultArtifact = await readJSON(path.join(ROOT, 'protocol/contracts/out/ZkApiVault.sol/ZkApiVault.json'));
        const vault = new Interface(vaultArtifact.abi);
        async function vaultRead(name, args = [], tag = 'latest') {
            const result = vault.decodeFunctionResult(name, await rpc('eth_call', [{ to: vaultAddress, data: vault.encodeFunctionData(name, args) }, tag]));
            return result.length === 1 ? result[0] : result;
        }
        // The custom error a call reverts with, or null when it succeeds.
        async function revertName(data, from = account.thirdParty, to = vaultAddress) {
            try {
                await rpc('eth_call', [{ from, to, data }, 'latest']);
                return null;
            } catch (error) {
                assert.ok(error instanceof RpcCallError && error.data, `no revert data: ${error.message}`);
                return vault.parseError(error.data)?.name ?? error.data.slice(0, 10);
            }
        }
        const vaultEvents = receipt => receipt.logs.filter(entry => entry.address.toLowerCase() === vaultAddress)
            .map(entry => vault.parseLog(entry)).filter(Boolean);
        const eventOf = (receipt, name) => vaultEvents(receipt).find(event => event.name === name);
        async function vaultSend(from, name, args, { value = 0n, gasLimit, operation } = {}) {
            const receipt = await sendTx({ from, to: vaultAddress, data: vault.encodeFunctionData(name, args), value, gasLimit });
            if (operation) gas.record(operation, receipt);
            return receipt;
        }
        async function noteView(noteId) {
            const [commitment, amount, expiry, status] = await vaultRead('notes', [noteId]);
            return { commitment, amount, expiry: Number(expiry), status: Number(status) };
        }
        const NOTE = Object.freeze({ Active: 1, PendingWithdrawal: 2, Closed: 3 });
        assert.equal(await vaultRead('CONCESSION_ESCAPE_VERSION'), 1n);
        assert.equal(await vaultRead('challengePeriod'), BigInt(TIMING.challengePeriod));
        assert.equal(await vaultRead('maxPauseDuration'), BigInt(TIMING.maxPauseDuration));
        assert.equal((await vaultRead('owner')).toLowerCase(), owner.toLowerCase());
        evidence.deployment = { script: 'demo/contracts/script/Deploy.s.sol', finalized_by: 'scripts/expected-codehashes.mjs --finalize',
            vault: vaultAddress, deploy_block: deployBlock, deploy_block_lower_bound: pending.deployBlockLowerBound,
            setup_id: finalized.setupId, allow_dev_setup: finalized.allowDevSetup, circuit_id: finalized.circuitId,
            codehashes: { vault: finalized.vaultRuntimeCodehash, adapter: finalized.adapterRuntimeCodehash,
                poseidon: finalized.poseidonRuntimeCodehash }, deploy_transactions: finalized.deployTransactions };
        stopAfter('deploy');

        // ---------------------------------------------------------------- mocks and profiles
        const keyHashes = { requestPk: await sha256File(path.join(SETUP_DIR, 'request.pk')),
            withdrawalPk: await sha256File(path.join(SETUP_DIR, 'withdrawal.pk')), requestVk: await sha256File(path.join(SETUP_DIR, 'request.vk')) };
        const sdkManifest = await readJSON(path.join(ROOT, 'sdk/assets/manifest.json'));
        assert.equal(sdkManifest.setupId, 'dev', 'the shipped WebAssembly is the dev setup\'s');
        for (const [file, hash] of [['request.pk', keyHashes.requestPk], ['withdrawal.pk', keyHashes.withdrawalPk], ['request.vk', keyHashes.requestVk]]) {
            assert.equal(sdkManifest.files[`assets/proofs/${file}`], hash, `sdk/assets/proofs/${file} is the dev setup's`);
        }
        const mock = mockProvider();
        const providerUrl = await serve(mock.handler);
        const feed = '0x0000000000000000000000000000000000001234';
        const quoteTimestamp = Math.floor(Date.now() / 1000) - 1;
        // The pinned RPC of the server (native billing) and of the clients:
        // the ETH/USD feed is mocked, everything else is the actual chain.
        const pinnedRpcMethods = new Map();
        const pinnedRpcUrl = await serve(async (req, res) => {
            const call = await body(req);
            pinnedRpcMethods.set(call.method, (pinnedRpcMethods.get(call.method) ?? 0) + 1);
            const target = call.params?.[0];
            if (call.method === 'eth_call' && target?.to?.toLowerCase() === feed) {
                let result;
                if (target.data === '0x313ce567') result = coder.encode(['uint256'], [8]);
                else if (target.data === '0xfeaf968c' || target.data === `0x9a6fc8f5${word(123)}`) {
                    result = coder.encode(['uint80', 'int256', 'uint256', 'uint256', 'uint80'], [123, MOCK_PRICE, quoteTimestamp, quoteTimestamp, 123]);
                } else {
                    fatal ??= new Error(`unexpected price feed read ${target.data}`);
                    return respond(res, 200, { jsonrpc: '2.0', id: call.id, error: { code: -32000, message: 'unsupported feed read' } });
                }
                return respond(res, 200, { jsonrpc: '2.0', id: call.id, result });
            }
            respond(res, 200, await proxyJsonRpc(rpcUrl, call));
        });

        // The operator's public endpoint in front of serverd: clients only
        // ever see this URL, so serverd can restart (in another adversary
        // mode) behind it, be taken unreachable, or have its answers replaced.
        const gate = { target: null, mode: 'pass', intercept: null, log: [] };
        const gateUrl = await serve(async (req, res) => {
            const chunks = [];
            for await (const chunk of req) chunks.push(chunk);
            const payload = Buffer.concat(chunks);
            gate.log.push({ method: req.method, path: req.url, mode: gate.mode, at: Date.now() });
            if (gate.mode === 'down' || !gate.target) {
                res.writeHead(503, { 'content-type': 'application/json' });
                return res.end(JSON.stringify({ error_code: 'service_unavailable', error: 'local operator outage' }));
            }
            const upstream = await new Promise((resolve, reject) => {
                const outgoing = http.request(new URL(req.url, gate.target), { method: req.method, agent: localAgent,
                    headers: { ...req.headers, host: new URL(gate.target).host } }, incoming => {
                    const parts = [];
                    incoming.on('data', chunk => parts.push(chunk));
                    incoming.on('error', reject);
                    incoming.on('end', () => resolve({ status: incoming.statusCode, headers: incoming.headers, body: Buffer.concat(parts) }));
                });
                outgoing.setTimeout(120_000, () => outgoing.destroy(new Error('gate upstream timed out')));
                outgoing.on('error', reject);
                outgoing.end(payload);
            });
            const answer = gate.intercept ? await gate.intercept({ method: req.method, path: req.url, payload, upstream }) : upstream;
            const headers = { ...answer.headers };
            delete headers['content-length'];
            delete headers['transfer-encoding'];
            res.writeHead(answer.status, headers);
            res.end(answer.body);
        });
        const indexerPort = await freePort();
        const indexerUrl = `http://127.0.0.1:${indexerPort}`;
        const services = { deploymentId: `acceptance-${CHAIN_ID}-${runId.slice(-8)}`, protocolServerUrl: gateUrl, indexerUrl,
            rpcUrl: pinnedRpcUrl, priceFeed: feed, keyHashes, settlementWindowSeconds: W, inferenceBase: `${providerUrl}/v1`,
            verifierUrl: `${providerUrl}/verifier` };
        const trusted = trustedDeployment(finalized, services);
        assert.deepEqual(trusted.state_signing_key, { x: felt(signingKeys.state_signing_key.x), y: felt(signingKeys.state_signing_key.y) });
        const manifestPath = path.join(runDir, 'trusted-deployment.json');
        await save('trusted-deployment.json', { trusted_deployment: trusted });

        // ---------------------------------------------------------------- daemons
        log('Daemon order: indexer, zkapi db init, signer, challenger, serverd.');
        const indexerArgs = ['--listen', `127.0.0.1:${indexerPort}`, '--rpc-url', rpcUrl, '--contract-address', vaultAddress,
            '--from-block', String(deployBlock), '--poll-interval-ms', '100', '--chain-id', String(CHAIN_ID),
            '--confirmations', String(INDEXER_CONFIRMATIONS), '--max-head-age-secs', '0', '--cursor-path', path.join(runDir, 'indexer.json')];
        let indexer = launch(path.join(opts.binDir, 'zkapi-indexerd'), indexerArgs, 'indexer.log');
        async function synchronizedTree() {
            const chainRoot = await vaultRead('currentRoot');
            return waitFor('indexer root matches the chain', async () => {
                const snapshot = await get(`${indexerUrl}/v1/tree/snapshot`);
                return BigInt(snapshot.root) === chainRoot && snapshot;
            });
        }
        await synchronizedTree();
        const dbPath = path.join(runDir, 'server.db');
        const zkapi = path.join(opts.binDir, 'zkapi');
        const dbInit = await runToExit(zkapi, ['--proof-setup-dir', SETUP_DIR, 'db', 'init', '--deployment', manifestPath, '--db', dbPath], 'db-init.log');
        assert.equal(dbInit.code, 0, `zkapi db init failed: ${dbInit.output}`);
        assert.equal(JSON.parse(dbInit.output.slice(dbInit.output.indexOf('{'))).result, 'bound');
        // A profile whose vault codehash is not the deployed code: db init binds
        // it (it reads no chain), and serverd refuses to start on it.
        const tamperedManifest = path.join(runDir, 'trusted-deployment-wrong-codehash.json');
        await save(path.basename(tamperedManifest), { trusted_deployment: { ...trusted, vault_runtime_codehash: `0x${'ab'.repeat(32)}` } });

        const signerPort = await freePort();
        const signerUrl = `http://127.0.0.1:${signerPort}`;
        const signer = launch(process.execPath, [path.join(ROOT, 'docker/aws/signer/server.mjs')], 'signer.log', { env: {
            ZKAPI_CHALLENGE_CHAIN_ID: String(CHAIN_ID), ZKAPI_CHALLENGE_PRIVATE_KEY: ANVIL_KEYS[1], ZKAPI_CHALLENGE_VAULT: vaultAddress,
            ZKAPI_CHALLENGE_RPC_URL: rpcUrl, ZKAPI_CHALLENGE_PORT: String(signerPort),
            ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: String(CHALLENGE_MAX_FEE_PER_GAS),
            ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI: String(CHALLENGE_MAX_PRIORITY_FEE_PER_GAS),
            ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI: String(CHALLENGE_PRIORITY_FEE_PER_GAS),
            ZKAPI_CHALLENGE_RETIRE_ON_MISS: 'true', ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY: '2' } });
        const signerHealth = await waitFor('signer health', async () => {
            const health = await request(`${signerUrl}/health`);
            return health.status === 200 && health.value;
        });
        assert.equal(signerHealth.sender.toLowerCase(), challengerAccount.toLowerCase());
        assert.equal(signerHealth.vault.toLowerCase(), vaultAddress);

        // Every call the challenger makes reaches the signer through this
        // recorder: each send's fees, decoded call and outcome.
        const challengeSends = [];
        const challengerRpcUrl = await serve(async (req, res) => {
            const call = await body(req);
            let send;
            if (call.method === 'eth_sendTransaction') {
                try {
                    const tx = call.params[0];
                    const parsed = vault.parseTransaction({ data: tx.data });
                    send = { tx, call: parsed?.name, note_id: Number(parsed?.args?.noteId ?? -1),
                        fees: challengeFees(tx, CHALLENGE_MAX_FEE_PER_GAS), at: Date.now() };
                    assert.equal(tx.from.toLowerCase(), challengerAccount.toLowerCase());
                    assert.equal(tx.to.toLowerCase(), vaultAddress);
                    assert.ok(['challengeEscapeWithdrawal', 'raiseEscapeConcession', 'retireClosedLeaf'].includes(send.call), send.call);
                    challengeSends.push(send);
                } catch (error) {
                    fatal ??= error;
                    throw error;
                }
            }
            const reply = await proxyJsonRpc(signerUrl, call);
            if (send) Object.assign(send, reply.error ? { error: reply.error } : { hash: reply.result });
            respond(res, 200, reply);
        });
        const challengerStatusPort = await freePort();
        const challengerStatusUrl = `http://127.0.0.1:${challengerStatusPort}`;
        const challengerCheckpoint = path.join(runDir, 'challenger.json');
        const challengerArgs = ['--rpc-url', challengerRpcUrl, '--indexer-url', indexerUrl, '--sender', challengerAccount,
            '--deployment', manifestPath, '--from-block', String(deployBlock), '--confirmations', '2', '--db-path', dbPath,
            '--checkpoint', challengerCheckpoint, '--proof-setup-dir', SETUP_DIR, '--poll-interval-ms', '200',
            '--max-fee-per-gas-wei', String(CHALLENGE_MAX_FEE_PER_GAS), '--max-priority-fee-per-gas-wei', String(CHALLENGE_MAX_PRIORITY_FEE_PER_GAS),
            '--priority-fee-per-gas-wei', String(CHALLENGE_PRIORITY_FEE_PER_GAS), '--status-listen', `127.0.0.1:${challengerStatusPort}`,
            '--observe-interval-seconds', '1', '--raise-lead-seconds', String(TIMING.raiseLead),
            '--settlement-window-seconds', String(W), '--settlement-poll-seconds', String(TIMING.settlementPoll), '--retire-on-miss', 'true'];
        let challenger = null;
        let challengerStarts = 0;
        async function startChallenger() {
            challenger = launch(path.join(opts.binDir, 'zkapi-challenged'), challengerArgs, `challenger-${++challengerStarts}.log`);
            return waitFor('challenger status', async () => {
                const status = await get(`${challengerStatusUrl}/status`);
                return status.chain?.latest_block != null && status;
            }, 60_000);
        }
        const challengerReady = await startChallenger();
        assert.equal(challengerReady.schema, 'zkapi-challenged-status/v2');
        const challengerStatus = () => get(`${challengerStatusUrl}/status`);

        const serverPort = await freePort();
        const serverUrl = `http://127.0.0.1:${serverPort}`;
        // The OA org and verifier the companion phase uses (the companion
        // accepts only OA org keys); serverd switches to it for that phase.
        const oaSecret = randomBytes(24).toString('hex');
        const oaOptions = { sharedSecret: oaSecret, verifierUrl: null, inferenceBase: `${providerUrl}/v1` };
        const oaOrgMock = mockOaOrg(mock, oaOptions);
        oaOptions.verifierUrl = await serve(oaOrgMock.verifier);
        const oaOrgUrl = await serve(oaOrgMock.org);
        const serverArgs = (listenPort, db, { adversary = null, manifest = manifestPath, keySource = 'openrouter' } = {}) => [
            '--chain-id', String(CHAIN_ID), '--contract-address', vaultAddress, '--request-charge-cap', String(CAP),
            '--proof-setup-dir', SETUP_DIR, ...(adversary ? ['--adversary', adversary] : []), 'serverd',
            '--listen', `127.0.0.1:${listenPort}`, '--openrouter-api-base', providerUrl,
            ...(keySource === 'oa_org' ? ['--oa-org-url', oaOrgUrl] : ['--openrouter-management-key', 'local-only-management-key']),
            '--openrouter-lease-ttl-seconds', String(TIMING.leaseTtl),
            '--openrouter-settlement-grace-seconds', String(TIMING.settlementGrace),
            '--openrouter-settlement-poll-seconds', String(TIMING.settlementPoll),
            '--openrouter-settlement-deadline-seconds', String(TIMING.settlementDeadline),
            '--deployment', manifest, '--native-billing-rpc-url', pinnedRpcUrl, '--native-price-feed-address', feed,
            '--db-path', db, '--indexer-url', indexerUrl, '--root-poll-interval-ms', '100'];
        // Each refused start uses its own database path and must exit non-zero.
        async function refusedStart(label, env, refusal, argsFor = (port, db) => serverArgs(port, db)) {
            const db = path.join(runDir, `refused-${label}.db`);
            const result = await runToExit(zkapi, argsFor(await freePort(), db), `refused-${label}.log`, env, { timeout: 120_000 });
            assert.ok(result.code !== null && result.code !== 0, `${label}: serverd must refuse to start (exit ${result.code}, ${result.signal})`);
            assert.match(result.output, refusal, `${label}: unexpected refusal:\n${result.output.slice(-2000)}`);
            return { exit_code: result.code, refusal: refusal.source };
        }
        const refusedStarts = {
            development_seeds: await refusedStart('development-seeds', { ZKAPI_STATE_SEED: '0x1', ZKAPI_CLEAR_SEED: '0x2' }, /published development key/),
            unpinned_seeds: await refusedStart('unpinned-seeds', { ZKAPI_STATE_SEED: randomSeed(), ZKAPI_CLEAR_SEED: randomSeed() },
                /do not derive the keys the deployment manifest pins/),
            missing_seeds: await refusedStart('missing-seeds', {}, /ZKAPI_STATE_SEED \(or --state-seed\) is required/),
        };
        // The codehash-mismatch profile: bound by db init, refused by serverd.
        const tamperedDb = path.join(runDir, 'refused-codehash.db');
        const tamperedInit = await runToExit(zkapi, ['--proof-setup-dir', SETUP_DIR, 'db', 'init', '--deployment', tamperedManifest, '--db', tamperedDb], 'db-init-codehash.log');
        assert.equal(tamperedInit.code, 0, tamperedInit.output);
        refusedStarts.vault_codehash_mismatch = await refusedStart('codehash', seedEnv, /codehash/i,
            port => serverArgs(port, tamperedDb, { manifest: tamperedManifest }));
        let server = null;
        let serverStarts = 0;
        async function startServer(adversary = null, { keySource = 'openrouter' } = {}) {
            if (server) await stop(server);
            server = launch(zkapi, serverArgs(serverPort, dbPath, { adversary, keySource }),
                `server-${++serverStarts}-${adversary ?? 'honest'}${keySource === 'oa_org' ? '-oa-org' : ''}.log`,
                { env: { ...seedEnv, ...(keySource === 'oa_org' ? { ZKAPI_OA_ORG_SHARED_SECRET: oaSecret } : {}) } });
            gate.target = serverUrl;
            await waitFor('serverd ready at the chain root', async () => {
                const health = await get(`${serverUrl}/health`);
                return BigInt(health.current_root) === await vaultRead('currentRoot') && health;
            }, 90_000);
            const health = await get(`${serverUrl}/health`);
            assert.equal(health.circuit_id, 'zkapi-v2-concession-v1');
            assert.equal(health.exit_concession, 1);
            return health;
        }
        const serverHealth = await startServer();
        const attestation = await get(`${serverUrl}/v1/attestation`);
        assert.equal(BigInt(attestation.state_signing_key.x), BigInt(signingKeys.state_signing_key.x));
        assert.equal(BigInt(attestation.clearance_signing_key.y), BigInt(signingKeys.clearance_signing_key.y));
        evidence.stack = { signer_health: signerHealth, server_health: serverHealth, refused_server_starts: refusedStarts,
            db_init: 'bound', timing: { ...TIMING, ...timing } };
        stopAfter('stack');

        // ---------------------------------------------------------------- client drivers
        const config = { protocol_version: 2, chain_id: CHAIN_ID, contract_address: vaultAddress, request_charge_cap: CAP,
            policy_charge_cap: 0, policy_enabled: false, state_signing_key: signingKeys.state_signing_key,
            clearance_signing_key: signingKeys.clearance_signing_key };
        const driverBinary = path.join(opts.binDir, 'examples/v2_acceptance_wallet');
        // The browser wallet core (zkapi-browser, natively) behind a JSONL
        // driver: one in-memory wallet per process.
        async function wallet(name) {
            const child = launch(driverBinary, [SETUP_DIR], `wallet-${name}.log`, { interactive: true });
            const lines = readline.createInterface({ input: child.stdout });
            let nextId = 0;
            const pending = new Map();
            const rejectAll = error => { for (const item of pending.values()) item.reject(error); pending.clear(); };
            lines.on('line', line => {
                try {
                    const response = JSON.parse(line);
                    const item = pending.get(response.id);
                    assert.ok(item, 'unexpected wallet response');
                    pending.delete(response.id);
                    if (response.ok) item.resolve(response.result);
                    else item.reject(new Error(`Wallet ${item.command}: ${response.error}`));
                } catch (error) { rejectAll(error); }
            });
            child.once('error', rejectAll);
            child.once('close', code => rejectAll(new Error(`Wallet helper exited (${code})`)));
            const call = async (command, data = {}) => {
                check();
                const id = ++nextId;
                return new Promise((resolve, reject) => {
                    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Wallet ${command} timed out`)); }, 180_000);
                    pending.set(id, { command, resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
                    child.stdin.write(JSON.stringify({ id, command, ...data }) + '\n');
                });
            };
            assert.equal((await call('circuit')).circuit_id, 'zkapi-v2-concession-v1');
            await call('init', { config });
            return call;
        }
        const WITHDRAWAL_TUPLE = 'tuple(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,uint8,uint256,uint128,uint64)';
        const wallNow = () => Math.floor(Date.now() / 1000);
        async function treePath(client, noteId) {
            const snapshot = await synchronizedTree();
            return client('tree_path', { args: { snapshot, note_id: noteId, require_existing: true } });
        }
        async function driverDeposit(client, amount = DEPOSIT, from = account.driver) {
            const snapshot = await synchronizedTree();
            const params = await client('deposit_params');
            const merkle = await client('tree_path', { args: { snapshot, note_id: snapshot.next_note_id, require_existing: false } });
            const receipt = await vaultSend(from, 'deposit', [felt(params.registration_commitment), amount, merkle.siblings],
                { value: BigInt(amount) * GWEI, operation: 'deposit' });
            assert.equal(receipt.status, '0x1');
            const deposited = eventOf(receipt, 'NoteDeposited');
            const noteId = Number(deposited.args.noteId);
            const note = await noteView(noteId);
            assert.equal(note.amount, BigInt(amount));
            assert.equal(note.status, NOTE.Active);
            const status = await client('confirm_deposit', { args: { note_id: noteId, amount, expiry_ts: note.expiry } });
            assert.equal(status.state.note.is_genesis, true);
            // Amendment A1: the deposit's own root and siblings prove the note
            // for good; exits need no indexer.
            const depositPath = { active_root: felt(deposited.args.newRoot), siblings: merkle.siblings };
            assert.equal((await client('note_path_matches', { args: { active_root: depositPath.active_root, siblings: depositPath.siblings } })).matches, true);
            return { noteId, receipt, depositPath, expiry: note.expiry };
        }
        const quotePayload = async () => JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1,
            billing_quote: await get(`${gateUrl}/v2/billing/quote`) });
        async function inference(lease) {
            const answer = await request(`${lease.openrouter_api_base}/chat/completions`, { method: 'POST',
                headers: { authorization: `Bearer ${lease.api_key}` },
                value: { model: MODEL, messages: [{ role: 'user', content: PROMPT }], max_tokens: 8, stream: false } });
            assert.equal(answer.status, 200, `inference: ${JSON.stringify(answer.value)}`);
            assert.equal(answer.value.choices[0].message.content, 'OK');
        }
        async function retireLease(id, preparedRequest) {
            const retired = await request(`${gateUrl}/v2/openrouter/leases/${id}`, { method: 'POST', value: preparedRequest });
            assert.ok(retired.status === 200 || (retired.status === 409 && retired.value?.error_code === 'lease_settlement_pending'),
                `retirement failed: ${retired.status}/${retired.value?.error_code}`);
        }
        // A request through the operator: proved by the wallet, leased over
        // HTTP, one inference at the provider mock with the issued key.
        async function driverRequest(client, noteId, label, { retire = true, infer = true } = {}) {
            const merkle = await treePath(client, noteId);
            const id = `acceptance-${label}-${randomUUID()}`;
            const prepared = await client('prepare_request', { args: { payload: await quotePayload(), active_root: merkle.active_root,
                merkle_siblings: merkle.siblings, client_request_id: id, request_time: wallNow(), created_at_ms: Date.now() } });
            assert.equal(prepared.bound_at_state, CAP, 'C2: the request fixes the state\'s bound');
            const issued = await request(`${gateUrl}/v2/openrouter/leases`, { method: 'POST', value: prepared.request });
            assert.equal(issued.status, 201, `lease rejected: ${issued.value?.error_code ?? issued.status}`);
            if (infer) await inference(issued.value);
            if (retire) await retireLease(id, prepared.request);
            return { id, request: prepared.request, lease: issued.value, nullifier: prepared.request.public_inputs.request_nullifier, merkle };
        }
        async function settledResponse(id, timeout = 60_000) {
            return waitFor(`settlement of ${id}`, async () => {
                const found = await get(`${gateUrl}/v2/requests/${id}`);
                return found.request_response;
            }, timeout);
        }
        async function honestRequest(client, noteId, label) {
            const sent = await driverRequest(client, noteId, label);
            const response = await settledResponse(sent.id);
            assert.equal(response.charge_applied, INFERENCE_CHARGE);
            const status = await client('complete_response', { response });
            assert.equal(status.pending_request, false);
            return { ...sent, response, status };
        }
        async function driverEscape(client, noteId, { snapshot, conceded = 0, destination = account.destination, validUntil, path: merkle,
            from = account.driver, send = true, operation = 'escape' } = {}) {
            const plan = await client('prepare_withdrawal', { ...(snapshot ? { snapshot } : {}), args: { mode: 'escape', destination,
                conceded, valid_until: validUntil ?? (await chainNow()) + 10_800, active_root: merkle.active_root, merkle_siblings: merkle.siblings } });
            assert.equal(plan.public_inputs.kind, 0);
            assert.ok(plan.calldata.startsWith('0xa38d62aa') && plan.calldata.length === 2 + 836 * 2, 'escape calldata layout');
            if (!send) return { plan };
            const receipt = await sendTx({ from, to: vaultAddress, data: plan.calldata });
            assert.equal(receipt.status, '0x1', 'the escape reverted');
            if (operation) gas.record(operation, receipt, { note_id: noteId, conceded });
            const initiated = eventOf(receipt, 'EscapeWithdrawalInitiated');
            const recorded = eventOf(receipt, 'EscapeConcessionRecorded');
            assert.equal(BigInt(recorded.args.nextNullifier), BigInt(plan.public_inputs.next_nullifier));
            assert.equal(recorded.args.conceded, BigInt(conceded));
            return { plan, receipt, initiated, recorded, deadline: Number(initiated.args.challengeDeadline) };
        }
        async function clearance(client, merkle) {
            const ownership = await client('prepare_withdrawal', { args: { mode: 'ownership', valid_until: wallNow() + 3_000,
                active_root: merkle.active_root, merkle_siblings: merkle.siblings } });
            assert.equal(ownership.public_inputs.kind, 2);
            const granted = await request(`${gateUrl}/v2/withdraw/clearance`, { method: 'POST', value: ownership.clearance_request });
            return { ownership, granted };
        }
        async function driverMutualClose(client, noteId, merkle, destination = account.destination) {
            const { ownership, granted } = await clearance(client, merkle);
            assert.equal(granted.status, 200, `clearance refused: ${JSON.stringify(granted.value)}`);
            const close = await client('prepare_withdrawal', { args: { mode: 'mutual', destination, valid_until: (await chainNow()) + 10_800,
                active_root: merkle.active_root, merkle_siblings: merkle.siblings, clearance: granted.value } });
            assert.ok(close.calldata.startsWith('0x72cd2e44') && close.calldata.length === 2 + 836 * 2, 'close calldata layout');
            const receipt = await sendTx({ from: account.driver, to: vaultAddress, data: close.calldata });
            assert.equal(receipt.status, '0x1', 'the mutual close reverted');
            gas.record('mutual_close', receipt, { note_id: noteId });
            return { ownership, clearance: granted.value, close, receipt };
        }
        async function vaultEventsSince(name, noteId, fromBlock) {
            const topic = vault.getEvent(name).topicHash;
            const logs = await rpc('eth_getLogs', [{ address: vaultAddress, fromBlock: hex(fromBlock), toBlock: 'latest',
                topics: [topic, felt(noteId)] }]);
            return logs.map(entry => ({ ...vault.parseLog(entry), transactionHash: entry.transactionHash,
                blockNumber: Number(BigInt(entry.blockNumber)) }));
        }
        async function waitEvent(name, noteId, fromBlock, timeout = 90_000) {
            const found = await waitFor(`${name} for note ${noteId}`, async () => (await vaultEventsSince(name, noteId, fromBlock))[0], timeout, 300);
            return { event: found, receipt: await rpc('eth_getTransactionReceipt', [found.transactionHash]) };
        }
        // Waits for the challenger to settle every obligation it has.
        async function challengerQuiet(timeout = 90_000) {
            return waitFor('challenger has no unresolved obligation', async () => {
                const status = await challengerStatus();
                return status.obligations.every(item => ['nothing_due', 'expired_nothing_due', 'resolved_unconfirmed'].includes(item.state)
                    || item.state === 'raised') && status;
            }, timeout);
        }
        const balances = async (...addresses) => Object.fromEntries(await Promise.all(addresses.map(async a => [a, await balance(a)])));
        const pendingEscapes = [];
        let expiryNote = null;

        // ================================================================ Phase H: an honest operator
        await scenario('honest flow: deposit, two requests, settle, mutual close', async () => {
            const client = await wallet('honest');
            const note = await driverDeposit(client);
            const before = await balances(vaultAddress, treasury, account.destination);
            const first = await honestRequest(client, note.noteId, 'honest-1');
            const second = await honestRequest(client, note.noteId, 'honest-2');
            const state = second.status.state.note;
            assert.equal(state.current_balance, DEPOSIT - 2 * INFERENCE_CHARGE);
            assert.equal(state.is_genesis, false);
            assert.equal(state.bound_at_state, 0, 'an installed successor resets the bound');
            assert.equal((await get(`${gateUrl}/v2/requests/${first.id}`)).nullifier_status, 'finalized');
            // An ownership proof (kind 2) never lands on chain.
            const { ownership, granted } = await clearance(client, note.depositPath);
            assert.equal(granted.status, 200, `clearance refused: ${JSON.stringify(granted.value)}`);
            const tuple = coder.decode([WITHDRAWAL_TUPLE], ownership.inputs_abi)[0];
            const asEscape = vault.encodeFunctionData('initiateEscapeWithdrawal', [tuple, ownership.proof_hex]);
            const asClose = vault.encodeFunctionData('mutualClose', [tuple, ownership.proof_hex]);
            assert.equal(await revertName(asEscape), 'WrongWithdrawalKind');
            assert.equal(await revertName(asClose), 'WrongWithdrawalKind');
            const rejected = await sendTx({ from: account.thirdParty, to: vaultAddress, data: asEscape, gasLimit: 1_000_000 });
            assert.equal(rejected.status, '0x0');
            gas.record('ownership_proof_on_chain_reverts', rejected);
            const nullifier = ownership.public_inputs.withdrawal_nullifier;
            assert.equal((await get(`${gateUrl}/v2/nullifiers/${nullifier}`)).nullifier_status, 'clearance_reserved');
            // The close proves at the deposit's root (Amendment A1).
            const close = await client('prepare_withdrawal', { args: { mode: 'mutual', destination: account.destination,
                valid_until: (await chainNow()) + 10_800, active_root: note.depositPath.active_root, merkle_siblings: note.depositPath.siblings,
                clearance: granted.value } });
            const receipt = await sendTx({ from: account.driver, to: vaultAddress, data: close.calldata });
            assert.equal(receipt.status, '0x1');
            gas.record('mutual_close', receipt, { note_id: note.noteId });
            const closed = eventOf(receipt, 'MutualClose');
            const payout = DEPOSIT - 2 * INFERENCE_CHARGE;
            assert.equal(closed.args.finalBalance, BigInt(payout));
            const after = await balances(vaultAddress, treasury, account.destination);
            assert.equal((await noteView(note.noteId)).status, NOTE.Closed);
            assert.equal(after[account.destination] - before[account.destination], BigInt(payout) * GWEI);
            assert.equal(after[treasury] - before[treasury], BigInt(2 * INFERENCE_CHARGE) * GWEI);
            assert.equal(before[vaultAddress] - after[vaultAddress], BigInt(DEPOSIT) * GWEI);
            assert.equal(await vaultRead('usedNullifiers', [nullifier]), true);
            const final = await client('status');
            assert.equal(final.state.note.current_balance, payout, 'the wallet\'s balance is what the close paid');
            return { note_id: note.noteId, charges: [first.response.charge_applied, second.response.charge_applied],
                payout_gwei: payout, treasury_gwei: 2 * INFERENCE_CHARGE, close_transaction: receipt.transactionHash,
                ownership_proof_on_chain: 'WrongWithdrawalKind (escape and close)', client_final_balance: final.state.note.current_balance };
        });
        stopAfter('honest');

        await scenario('stale exit after spending: defeat, SupersededState, re-escape from an older state and defeat', async () => {
            const client = await wallet('stale');
            const note = await driverDeposit(client);
            const snapshots = [await client('snapshot', { name: 'S0' })];
            const requests = [];
            for (let k = 0; k < 4; k++) {
                requests.push(await honestRequest(client, note.noteId, `stale-${k}`));
                if (k < 3) snapshots.push(await client('snapshot', { name: `S${k + 1}` }));
            }
            // S_k's successor nullifier is S_{k+1}'s nullifier.
            for (let k = 0; k < 3; k++) assert.equal(BigInt(snapshots[k].successor_nullifier), BigInt(snapshots[k + 1].withdrawal_nullifier));
            const before = await balances(vaultAddress, treasury, account.destination);
            // Stale-device pre-check (E4.2): the operator serves the request at
            // S2's successor, which verifies: another device is newer.
            const served = await get(`${gateUrl}/v2/nullifiers/${snapshots[2].successor_nullifier}/evidence`);
            assert.equal((await client('verify_request', { args: { public_inputs: served.public_inputs, proof: served.proof.proof } })).valid, true,
                'device_not_newest: the evidence at the successor verifies');
            // 1. Escape from S2 after spending S3: defeated by the request at N3.
            const merkle = await treePath(client, note.noteId);
            const fromS2 = await driverEscape(client, note.noteId, { snapshot: 'S2', path: merkle });
            const defeat = await waitEvent('EscapeWithdrawalChallenged', note.noteId, fromS2.receipt.blockNumber);
            gas.record('defeat', defeat.receipt, { note_id: note.noteId });
            assert.equal(BigInt(defeat.event.args.nullifier), BigInt(snapshots[2].withdrawal_nullifier));
            assert.equal((await rpc('eth_getTransactionByHash', [defeat.event.transactionHash])).from.toLowerCase(), challengerAccount.toLowerCase());
            assert.equal((await noteView(note.noteId)).status, NOTE.Active);
            assert.equal(await vaultRead('challengedNullifiers', [snapshots[2].withdrawal_nullifier]), true);
            assert.equal(await vaultRead('usedNullifiers', [snapshots[2].withdrawal_nullifier]), false);
            assert.equal(await vaultRead('usedNullifiers', [snapshots[2].successor_nullifier]), false);
            const sends = challengeSends.filter(send => send.note_id === note.noteId);
            assert.ok(sends.some(send => send.call === 'challengeEscapeWithdrawal' && send.hash === defeat.event.transactionHash),
                'the challenger\'s defeat went through the signer');
            const defeatCall = vault.parseTransaction({ data: (await rpc('eth_getTransactionByHash', [defeat.event.transactionHash])).input });
            assert.equal(BigInt(defeatCall.args.inputs.requestNullifier), BigInt(snapshots[3].withdrawal_nullifier), 'evidence at N3 = N2⁺');
            // The defeat cleared both used flags, so only the indexer's
            // published-nullifier table (the escape's EscapeConcessionRecorded
            // named N3) still tells serverd that N3 is public: the evidence
            // endpoint now refuses it.
            const published = await waitFor('serverd learns from the indexer that N3 is published', async () => {
                const answer = await request(`${gateUrl}/v2/nullifiers/${snapshots[2].successor_nullifier}/evidence`);
                return answer.status === 410 && answer;
            });
            assert.equal(published.value.error_code, 'published');
            const indexerPublished = await get(`${indexerUrl}/v1/nullifiers/${snapshots[2].successor_nullifier}/published`);
            assert.equal(indexerPublished.published, true);
            // 2. From S1: its successor N2 is challenged, so SupersededState.
            const fromS1 = await driverEscape(client, note.noteId, { snapshot: 'S1', path: merkle, send: false });
            assert.equal(await revertName(fromS1.plan.calldata), 'SupersededState');
            const superseded = await sendTx({ from: account.driver, to: vaultAddress, data: fromS1.plan.calldata, gasLimit: 1_000_000 });
            assert.equal(superseded.status, '0x0');
            gas.record('escape_superseded_state_reverts', superseded);
            // 3. From S0 (two states older): recorded, then defeated by the request at N1.
            const fromS0 = await driverEscape(client, note.noteId, { snapshot: 'S0', path: note.depositPath });
            const second = await waitEvent('EscapeWithdrawalChallenged', note.noteId, fromS0.receipt.blockNumber);
            gas.record('defeat', second.receipt, { note_id: note.noteId });
            assert.equal(BigInt(second.event.args.nullifier), BigInt(snapshots[0].withdrawal_nullifier));
            assert.equal(await vaultRead('challengedNullifiers', [snapshots[0].withdrawal_nullifier]), true);
            // 4. S2 again: ChallengedNullifier.
            const again = await driverEscape(client, note.noteId, { snapshot: 'S2', path: merkle, send: false });
            assert.equal(await revertName(again.plan.calldata), 'ChallengedNullifier');
            // Defeats move no funds; the newest state then closes mutually.
            const mid = await balances(vaultAddress, treasury, account.destination);
            assert.equal(mid[vaultAddress], before[vaultAddress]);
            assert.equal(mid[account.destination], before[account.destination]);
            const close = await driverMutualClose(client, note.noteId, await treePath(client, note.noteId));
            const payout = DEPOSIT - 4 * INFERENCE_CHARGE;
            assert.equal(eventOf(close.receipt, 'MutualClose').args.finalBalance, BigInt(payout));
            const after = await balances(vaultAddress, treasury, account.destination);
            assert.equal(after[account.destination] - before[account.destination], BigInt(payout) * GWEI);
            assert.equal(after[treasury] - before[treasury], BigInt(4 * INFERENCE_CHARGE) * GWEI);
            assert.equal((await noteView(note.noteId)).status, NOTE.Closed);
            const final = await client('status');
            assert.equal(final.state.note.current_balance, payout);
            return { note_id: note.noteId, stale_device_precheck: 'device_not_newest (evidence at S2⁺ verifies)',
                evidence_after_publication: '410 published (indexer published-nullifier table)',
                defeats: [defeat.event.transactionHash, second.event.transactionHash], superseded_revert: 'SupersededState',
                replay_after_defeat: 'ChallengedNullifier', newest_state_close: close.receipt.transactionHash, payout_gwei: payout,
                client_final_balance: final.state.note.current_balance };
        });
        stopAfter('stale');

        // ---------------------------------------------------------------- the browser SDK
        // The host: browser-config.json (the build-pinned profile), the proof
        // keys the SDK fetches by SHA-256 pin, and the operator's manifest.
        const operatorManifest = { protocol_version: 2, proof_backend: 'groth16_bn254',
            proof_setup: { circuit_id: trusted.circuit_id, setup_id: trusted.setup_id,
                request_proving_key_sha256: trusted.request_proving_key_sha256,
                withdrawal_proving_key_sha256: trusted.withdrawal_proving_key_sha256 },
            deployment_id: trusted.deployment_id, contract_address: trusted.contract_address, chain_id: trusted.chain_id,
            protocol_server_url: trusted.protocol_server_url, indexer_url: trusted.indexer_url, rpc_url: trusted.rpc_url,
            billing_asset: trusted.billing_asset, billing_unit: trusted.billing_unit, billing_token_address: null,
            native_asset_wei_per_unit: trusted.native_asset_wei_per_unit, native_price_feed_address: trusted.native_price_feed_address,
            native_price_feed_decimals: trusted.native_price_feed_decimals, native_price_max_age_seconds: trusted.native_price_max_age_seconds,
            request_charge_cap: trusted.request_charge_cap, state_signing_key: trusted.state_signing_key,
            clearance_signing_key: trusted.clearance_signing_key, models: [MODEL],
            privacy_mode: { openrouter_inference_base: trusted.openrouter_inference_base, verifier_url: trusted.verifier_url } };
        const hostConfigs = new Map();
        const proofFiles = { 'request.pk': 'request.pk', 'withdrawal.pk': 'withdrawal.pk', 'request.vk': 'request.vk' };
        const hostUrl = await serve(async (req, res) => {
            const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
            if (pathname === '/operator/config.json') return respond(res, 200, operatorManifest);
            const configured = /^\/zkapi\/([a-z0-9-]+)\/browser-config\.json$/.exec(pathname);
            if (configured && hostConfigs.has(configured[1])) return respond(res, 200, hostConfigs.get(configured[1]));
            const key = /^\/zkapi\/([a-z0-9-]+)\/proofs\/([a-z.]+)$/.exec(pathname);
            if (key && proofFiles[key[2]]) {
                res.writeHead(200, { 'content-type': 'application/octet-stream' });
                return res.end(await fs.readFile(path.join(ROOT, 'sdk/assets/proofs', proofFiles[key[2]])));
            }
            respond(res, 404, { error: 'not found' });
        });
        const browserConfig = profile => ({ deployment_manifest_url: `${hostUrl}/operator/config.json`,
            allowed_deployment_manifest_urls: [`${hostUrl}/operator/config.json`], trusted_deployment: profile,
            proving_keys_base_url: './proofs/', credits_per_usd: null, billing_token_symbol: 'ETH', billing_token_decimals: 9,
            require_oa_key_source: false });
        hostConfigs.set('v2c', browserConfig(trusted));
        // A build whose profile pins another vault codehash (§10.7 B: the
        // codehash-mismatch profile refuses deposits).
        hostConfigs.set('v2c-mismatch', browserConfig({ ...trusted, vault_runtime_codehash: `0x${'ab'.repeat(32)}` }));
        await save('browser-config.json', hostConfigs.get('v2c'));
        async function sdkAgent(name, { build = 'v2c', walletAccount }) {
            const child = launch(process.execPath, [path.join(ROOT, 'scripts/acceptance/sdk-agent.mjs')], `sdk-${name}.log`, { interactive: true });
            const lines = readline.createInterface({ input: child.stdout });
            let nextId = 0;
            const pending = new Map();
            const rejectAll = error => { for (const item of pending.values()) item.reject(error); pending.clear(); };
            lines.on('line', line => {
                let response;
                try { response = JSON.parse(line); } catch { return; }
                const item = pending.get(response.id);
                if (!item) return;
                pending.delete(response.id);
                if (response.ok) item.resolve(response.result);
                else item.reject(Object.assign(new Error(`SDK ${item.command}: ${response.error.message}`), { sdk: response.error }));
            });
            child.once('error', rejectAll);
            child.once('close', code => rejectAll(new Error(`SDK agent exited (${code})`)));
            const call = async (command, data = {}, timeout = 300_000) => {
                check();
                const id = ++nextId;
                return new Promise((resolve, reject) => {
                    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`SDK ${command} timed out`)); }, timeout);
                    pending.set(id, { command, resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
                    child.stdin.write(JSON.stringify({ id, command, ...data }) + '\n');
                });
            };
            call.close = async () => { await call('close', {}, 5_000).catch(() => {}); await stop(child); };
            sdkAgents.push(call);
            await call('start', { hostUrl, configUrl: `${hostUrl}/zkapi/${build}/browser-config.json`, walletRpcUrl: rpcUrl, account: walletAccount });
            return call;
        }
        // The SDK's refusal, as an object (its code and data).
        const sdkRefusal = promise => promise.then(value => assert.fail(`expected a refusal, got ${json(value)}`), error => {
            assert.ok(error.sdk, error.message);
            return error.sdk;
        });

        // ---------------------------------------------------------------- the clientd companion
        // zkapi-walletd as zkapi-clientd runs it: a bridge token, and every
        // outbound connection through an authenticated loopback proxy.
        async function forwardProxy(name) {
            const user = 'clientd';
            const password = randomBytes(24).toString('hex');
            const record = { requests: 0, refused: 0, hosts: new Set() };
            const proxy = http.createServer();
            proxy.on('connect', (req, socket) => {
                const [host, port] = req.url.split(':');
                if (!proxyAuthorized(req.headers['proxy-authorization'], user, password) || host !== '127.0.0.1') {
                    record.refused++;
                    socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
                    return;
                }
                const upstream = net.connect(Number(port), host, () => {
                    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                    upstream.pipe(socket);
                    socket.pipe(upstream);
                });
                upstream.on('error', () => socket.destroy());
                socket.on('error', () => upstream.destroy());
            });
            const url = await serve(async (req, res) => {
                const target = new URL(req.url);
                if (!proxyAuthorized(req.headers['proxy-authorization'], user, password) || target.hostname !== '127.0.0.1') {
                    record.refused++;
                    return respond(res, 403, { error: 'refused by the local proxy' });
                }
                record.requests++;
                record.hosts.add(target.host);
                const headers = { ...req.headers };
                delete headers['proxy-authorization'];
                delete headers['proxy-connection'];
                await new Promise((resolve, reject) => {
                    const outgoing = http.request(target, { method: req.method, headers, agent: localAgent }, incoming => {
                        res.writeHead(incoming.statusCode, incoming.headers);
                        incoming.pipe(res);
                        incoming.on('end', resolve);
                        incoming.on('error', reject);
                    });
                    outgoing.on('error', error => { if (!res.headersSent) respond(res, 502, { error: error.message }); else res.destroy(); resolve(); });
                    req.pipe(outgoing);
                });
            }, proxy);
            const parsed = new URL(url);
            parsed.username = user;
            parsed.password = password;
            return { url: parsed.href, record, name };
        }
        const companionManifest = { deployment_id: trusted.deployment_id, protocol_version: 2, chain_id: CHAIN_ID,
            rpc_url: trusted.rpc_url, contract_address: vaultAddress, billing_token_address: null, billing_asset: 'native_eth',
            billing_unit: 'gwei', native_asset_wei_per_unit: trusted.native_asset_wei_per_unit, native_price_feed_address: feed,
            native_price_feed_decimals: 8, native_price_max_age_seconds: 4_500, vault_revision: 3, deployment_status: 'deployed',
            exit_concession: 1, settlement_window_seconds: W, deploy_block: deployBlock, protocol_server_url: gateUrl,
            indexer_url: indexerUrl, request_charge_cap: CAP, proof_backend: 'groth16_bn254',
            proof_setup: { circuit_id: trusted.circuit_id, setup_id: trusted.setup_id },
            state_signing_key: trusted.state_signing_key, clearance_signing_key: trusted.clearance_signing_key,
            models: [{ id: MODEL, owned_by: 'local', tags: ['chat'] }] };
        const companionManifestPath = path.join(runDir, 'companion-deployment.json');
        await save('companion-deployment.json', companionManifest);
        async function startCompanion(name) {
            const token = randomBytes(24).toString('hex');
            const proxy = await forwardProxy(name);
            const port = await freePort();
            const stateDir = path.join(runDir, `companion-${name}`);
            const proxyEnv = Object.fromEntries(['HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'https_proxy', 'http_proxy', 'all_proxy']
                .map(key => [key, proxy.url]));
            // The arguments zkapi-clientd passes (CompanionCommand), with the
            // user's own exit RPC (here the Anvil node itself).
            const child = launch(path.join(opts.binDir, 'zkapi-walletd'), ['--require-oa-org-key-source', '--oa-verifier-url', oaOptions.verifierUrl,
                '--openrouter-inference-base', `${providerUrl}/v1`, '--exit-rpc-url', rpcUrl, 'client', '--deployment', companionManifestPath,
                '--mode', 'direct-openrouter', '--no-fund', '--listen', `127.0.0.1:${port}`, '--state-dir', stateDir],
            `companion-${name}.log`, { env: { OA_ZKAPI_BRIDGE_TOKEN: token, OA_ZKAPI_CHAIN_ID: String(CHAIN_ID),
                ZKAPI_PROOF_SETUP_DIR: SETUP_DIR, NO_PROXY: '', no_proxy: '', RAYON_NUM_THREADS: '4', ...proxyEnv } });
            const base = `http://127.0.0.1:${port}`;
            const call = async (method, pathname, value, timeoutMs = 300_000) =>
                request(`${base}${pathname}`, { method, value, headers: { authorization: `Bearer ${token}` }, timeoutMs });
            await waitFor('companion ready', async () => (await call('GET', '/health')).status === 200, 60_000);
            const unauthenticated = await request(`${base}/oa/v1/status`);
            assert.equal(unauthenticated.status, 401, 'the companion answers only its bridge token');
            const companion = { child, call, stateDir, proxy, name };
            companions.push(companion);
            return companion;
        }
        stopAfter('clients');

        await scenario('codehash-mismatch profile refuses deposits (SDK); serverd refuses the same profile', async () => {
            const sdk = await sdkAgent('mismatch', { build: 'v2c-mismatch', walletAccount: account.sdk });
            const initialized = await sdk('init');
            assert.equal(initialized.service?.available, true, 'the operator\'s manifest matches the build\'s pins');
            const vaultBefore = await balance(vaultAddress);
            const refusal = await sdkRefusal(sdk('deposit', { amount: '0.001' }));
            assert.equal(refusal.code, 'deployment_mismatch', json(refusal));
            const mismatches = refusal.data?.mismatches ?? [];
            assert.ok(mismatches.some(item => item.field === 'vault_runtime_codehash'), json(refusal.data));
            assert.equal(await balance(vaultAddress), vaultBefore, 'nothing was deposited');
            const after = await sdk('snapshot');
            assert.equal(after.note, null, 'the SDK holds no note');
            assert.equal(after.sent.length, 0, 'the wallet signed nothing');
            await sdk.close();
            return { sdk_refusal: refusal.code, mismatched_fields: mismatches.map(item => `${item.field} (${item.source})`),
                serverd_refusal: refusedStarts.vault_codehash_mismatch.refusal, client_final_state: 'no note, no transaction' };
        });
        stopAfter('mismatch');

        await scenario('SDK: deposit with deployment checks, request, settle; indexer down, escape with the deposit-time path', async () => {
            const sdk = await sdkAgent('honest', { walletAccount: account.sdk });
            await sdk('init');
            const deposited = await sdk('deposit', { amount: '0.001' });
            const note = deposited.note;
            assert.ok(note, `no note after the deposit: ${json(deposited)}`);
            assert.equal(Number(note.current_balance), DEPOSIT);
            const noteId = Number(note.note_id);
            assert.equal((await noteView(noteId)).status, NOTE.Active);
            const depositTx = deposited.sent.find(item => item.data === vault.getFunction('deposit').selector);
            assert.ok(depositTx, 'the wallet sent the deposit');
            gas.record('deposit', await rpc('eth_getTransactionReceipt', [depositTx.hash]), { client: 'sdk' });
            const chat = await sdk('chat', { sessionId: 'acceptance-sdk', model: MODEL, prompt: PROMPT });
            assert.equal(chat.status, 200, json(chat));
            const settled = await sdk('settle');
            assert.equal(Number(settled.note.current_balance), DEPOSIT - INFERENCE_CHARGE, json(settled.note));
            // Another deposit moves the root past this note's deposit root.
            // It is the note claimExpired sweeps at the end of the run.
            expiryNote = { client: await wallet('expiry') };
            Object.assign(expiryNote, await driverDeposit(expiryNote.client));
            const depositRoot = (await vaultEventsSince('NoteDeposited', noteId, deployBlock))[0].args.newRoot;
            assert.notEqual(await vaultRead('currentRoot'), depositRoot);
            // The operator's indexer goes down; the escape needs no indexer
            // (Amendment A1: the deposit's root is a known root for good).
            await stop(indexer);
            const before = await balances(vaultAddress, account.sdkDestination);
            const escaped = await sdk('withdraw', { mode: 'escape', destination: account.sdkDestination });
            const record = escaped.withdrawals.find(item => Number(item.noteId) === noteId) ?? escaped.withdrawal;
            assert.ok(record, json(escaped));
            const escapeTx = escaped.sent.find(item => item.data === vault.getFunction('initiateEscapeWithdrawal').selector);
            assert.ok(escapeTx, 'the wallet sent the escape');
            const receipt = await waitReceipt(escapeTx.hash);
            assert.equal(receipt.status, '0x1');
            gas.record('escape', receipt, { client: 'sdk', conceded: 0 });
            const recorded = eventOf(receipt, 'EscapeConcessionRecorded');
            assert.equal(recorded.args.conceded, 0n, 'a fresh state escapes conceding nothing');
            assert.equal(recorded.args.stateBalance, BigInt(DEPOSIT - INFERENCE_CHARGE));
            const pending = await vaultRead('pendingWithdrawals', [noteId]);
            assert.equal(pending[0], true);
            const root = pending[1];
            assert.equal(root, depositRoot, 'the escape proves at the note\'s deposit root, not the current one');
            assert.equal(await vaultRead('isKnownRoot', [root]), true);
            await save('sdk-honest-escape.json', escaped);
            const pathSource = escaped.prepared?.pathSource ?? record.pathSource ?? record.preparedWithdrawal?.pathSource ?? null;
            if (pathSource !== null) assert.equal(pathSource, 'deposit');
            // Restart the indexer from its checkpoint.
            indexer = launch(path.join(opts.binDir, 'zkapi-indexerd'), indexerArgs, 'indexer-2.log');
            await synchronizedTree();
            pendingEscapes.push({ name: 'sdk-honest', client: 'sdk', sdk, noteId, destination: account.sdkDestination,
                payout: DEPOSIT - INFERENCE_CHARGE, before });
            return { note_id: noteId, deposit: depositTx.hash, escape: escapeTx.hash, path_source: pathSource,
                decision: escaped.result?.decision ?? null, sdk_statuses: escaped.statuses,
                proof_root: felt(root), proof_root_is_the_deposit_root: true, deposit_root_is_not_current: true, conceded: 0,
                indexer_down_during_escape: true, sdk_settled_balance: Number(settled.note.current_balance) };
        });
        stopAfter('sdk-honest');

        // A destination whose receive() needs more than ESCAPE_PAYOUT_GAS
        // (five fresh SSTOREs): finalization credits it, claimEscapePayout
        // (all gas) pays it.
        const slowReceiver = '0x00000000000000000000000000000000005104e5';
        await rpc('anvil_setCode', [slowReceiver, '0x346000553460015534600255346003553460045500']);
        await scenario('under-concession escape, raised to the settled charge (exit_deferred)', async () => {
            const client = await wallet('raise');
            const note = await driverDeposit(client);
            // A served request: the provider was used, the lease still runs.
            const sent = await driverRequest(client, note.noteId, 'raise', { retire: false });
            const abandoned = await client('abandon_request');
            assert.equal(abandoned.bound_at_state, CAP);
            // The owner concedes less than the request will cost.
            const conceded = 100;
            assert.ok(conceded < INFERENCE_CHARGE);
            const escape = await driverEscape(client, note.noteId, { conceded, destination: slowReceiver, path: note.depositPath });
            assert.equal(escape.recorded.args.stateBalance, BigInt(DEPOSIT));
            // The lease retires; the server settles its charge, but the
            // nullifier is consumed on chain, so it signs no successor (O7).
            await retireLease(sent.id, sent.request);
            const deferred = await waitFor('the request settles as exit_deferred', async () => {
                const found = await get(`${gateUrl}/v2/requests/${sent.id}`);
                return found.nullifier_status === 'exit_deferred' && found;
            }, 60_000);
            assert.equal(deferred.request_response, undefined, 'no successor once the nullifier is published');
            // The challenger raises to the charge (Ω = the settled charge).
            const raised = await waitEvent('EscapeConcessionRaised', note.noteId, escape.receipt.blockNumber);
            gas.record('raise', raised.receipt, { note_id: note.noteId });
            assert.equal(raised.event.args.conceded, BigInt(INFERENCE_CHARGE));
            assert.equal(raised.event.args.finalBalance, BigInt(DEPOSIT - INFERENCE_CHARGE));
            assert.equal((await rpc('eth_getTransactionByHash', [raised.event.transactionHash])).from.toLowerCase(), challengerAccount.toLowerCase());
            const raiseCall = vault.parseTransaction({ data: (await rpc('eth_getTransactionByHash', [raised.event.transactionHash])).input });
            assert.equal(BigInt(raiseCall.args.inputs.requestNullifier), BigInt(sent.nullifier), 'raised with the request at the escaped nullifier');
            const concession = await vaultRead('pendingConcessions', [note.noteId]);
            assert.equal(concession[2], BigInt(INFERENCE_CHARGE));
            assert.equal((await vaultRead('pendingWithdrawals', [note.noteId]))[3], BigInt(DEPOSIT - INFERENCE_CHARGE));
            const status = await client('status');
            assert.equal(status.state.note.bound_at_state, CAP);
            assert.equal(status.archived.at(-1).disposition, 'abandoned_for_escape');
            pendingEscapes.push({ name: 'driver-raise', client: 'driver', noteId: note.noteId, destination: slowReceiver,
                payout: DEPOSIT - INFERENCE_CHARGE, deferred: true, before: await balances(slowReceiver) });
            return { note_id: note.noteId, conceded_at_init: conceded, raised_to: INFERENCE_CHARGE, raise: raised.event.transactionHash,
                server_status: deferred.nullifier_status };
        });
        stopAfter('raise');

        await scenario('companion: forced early exit conceding 0 while the operator is unreachable, raised to the real charge', async () => {
            // The companion takes only OA org keys: serverd switches its key
            // source (every direct-provider lease has settled).
            await startServer(null, { keySource: 'oa_org' });
            const companion = await startCompanion('forced');
            const bridge = await companion.call('GET', '/oa/v1/status');
            assert.equal(bridge.status, 200);
            assert.equal(bridge.value.exit_concession, 1);
            const plan = await companion.call('POST', '/deposit/prepare', { amount: DEPOSIT });
            assert.equal(plan.status, 200, json(plan.value));
            const receipt = await vaultSend(account.companion, 'deposit', [felt(plan.value.commitment), DEPOSIT, plan.value.zero_path],
                { value: BigInt(DEPOSIT) * GWEI, operation: 'deposit' });
            const deposited = eventOf(receipt, 'NoteDeposited');
            const noteId = Number(deposited.args.noteId);
            assert.equal(noteId, plan.value.next_note_id);
            const note = await noteView(noteId);
            const confirmed = await companion.call('POST', '/deposit/confirm', { secret: plan.value.secret, note_id: noteId, amount: DEPOSIT,
                expiry_ts: note.expiry, deposit_root: felt(deposited.args.newRoot), deposit_siblings: plan.value.zero_path });
            assert.equal(confirmed.status, 200, json(confirmed.value));
            await synchronizedTree();
            // One request, as clientd makes it: an OA bridge lease (the
            // companion proves the request; the verifier binds the key), then
            // the inference with that key.
            const lease = await companion.call('POST', '/oa/v1/lease', { request_limit_micro_usd: 1_000_000 });
            assert.equal(lease.status, 200, json(lease.value));
            assert.equal(lease.value.verified, true, json(lease.value));
            await inference({ openrouter_api_base: lease.value.base_url, api_key: lease.value.api_key });
            // The operator becomes unreachable; the owner exits before T.
            gate.mode = 'down';
            let prepared;
            try {
                const decision = await companion.call('POST', '/oa/v1/withdraw/escape/prepare',
                    { destination: account.companionDestination, early_exit: 'concede_nothing' });
                assert.equal(decision.status, 200, json(decision.value));
                prepared = decision.value.status === 'prepared' ? decision.value : (await companion.call('POST', '/oa/v1/withdraw/escape/prepare',
                    { destination: account.companionDestination, conceded: String(decision.value.conceded ?? '0'), early_exit: 'concede_nothing' })).value;
                assert.equal(prepared.status, 'prepared', json(prepared));
                assert.equal(String(prepared.conceded), '0');
            } finally {
                gate.mode = 'pass';
            }
            const escapeReceipt = await sendTx({ from: account.companion, to: vaultAddress, data: prepared.calldata });
            assert.equal(escapeReceipt.status, '0x1');
            gas.record('escape', escapeReceipt, { client: 'companion', conceded: 0 });
            const submitted = await companion.call('POST', '/oa/v1/withdraw/escape/submit', { transaction_hash: escapeReceipt.transactionHash });
            assert.equal(submitted.status, 200, json(submitted.value));
            // The lease expires and settles at its measured usage; its
            // nullifier is spent, so the challenger raises to that charge.
            const raised = await waitEvent('EscapeConcessionRaised', noteId, Number(BigInt(escapeReceipt.blockNumber)),
                (TIMING.leaseTtl + 120) * 1000);
            gas.record('raise', raised.receipt, { note_id: noteId });
            assert.equal(raised.event.args.conceded, BigInt(INFERENCE_CHARGE));
            assert.equal(raised.event.args.finalBalance, BigInt(DEPOSIT - INFERENCE_CHARGE));
            const status = await companion.call('GET', '/oa/v1/withdraw/escape/status');
            assert.equal(status.status, 200, json(status.value));
            // The OA lease settled: serverd returns to direct provider keys.
            await startServer();
            pendingEscapes.push({ name: 'companion-forced', client: 'companion', companion, noteId, destination: account.companionDestination,
                payout: DEPOSIT - INFERENCE_CHARGE, before: await balances(account.companionDestination) });
            return { note_id: noteId, decision: { rule: prepared.reason ?? null, conceded: prepared.conceded, bound: prepared.bound_at_state },
                path_source: prepared.path_source ?? null, escape: escapeReceipt.transactionHash, raise: raised.event.transactionHash,
                proxied_requests: companion.proxy.record.requests, escape_status_phase: status.value.phase ?? status.value.record?.phase ?? null };
        });
        stopAfter('companion');

        // Prepared now, abandoned, replayed after its valid_until.
        const replay = { client: await wallet('replay') };
        Object.assign(replay, await driverDeposit(replay.client));
        replay.abandoned = await driverEscape(replay.client, replay.noteId, { validUntil: (await chainNow()) + 600, path: replay.depositPath, send: false });
        assert.equal(await revertName(replay.abandoned.plan.calldata), null, 'the abandoned proof would still land now');
        // The missed-defeat note: two settled requests, so a request at the
        // genesis state's successor exists.
        const missed = { client: await wallet('missed') };
        Object.assign(missed, await driverDeposit(missed.client));
        missed.genesis = await missed.client('snapshot', { name: 'S0' });
        missed.requests = [await honestRequest(missed.client, missed.noteId, 'missed-0'), await honestRequest(missed.client, missed.noteId, 'missed-1')];

        // ---------------------------------------------------------------- pause
        async function finalizePending(entry) {
            const before = await balances(entry.destination, treasury);
            let receipt;
            if (entry.client === 'sdk') {
                // Skipping time moved only block time: the device clock
                // catches up with it before the SDK judges the deadline.
                const lead = await chainNow() - wallNow();
                const offset = (await entry.sdk('snapshot')).device_clock_offset_seconds;
                if (lead + 60 > offset) await entry.sdk('clock', { offsetSeconds: lead + 60 });
                const finalized = await entry.sdk('finalize', { recordId: null });
                const tx = finalized.sent.find(item => item.data === vault.getFunction('finalizeEscapeWithdrawal').selector);
                assert.ok(tx, `the SDK sent no finalization: ${json(finalized)}`);
                receipt = await waitReceipt(tx.hash);
            } else {
                receipt = await vaultSend(account.thirdParty, 'finalizeEscapeWithdrawal', [entry.noteId]);
            }
            assert.equal(receipt.status, '0x1');
            const finalizedEvent = eventOf(receipt, 'EscapeWithdrawalFinalized');
            const deferredEvent = eventOf(receipt, 'EscapePayoutDeferred');
            gas.record(deferredEvent ? 'finalize_deferred' : 'finalize', receipt, { note_id: entry.noteId });
            assert.equal(finalizedEvent.args.finalBalance, BigInt(entry.payout), `${entry.name}: payout`);
            assert.equal((await noteView(entry.noteId)).status, NOTE.Closed);
            const after = await balances(entry.destination, treasury);
            assert.equal(after[treasury] - before[treasury], BigInt(DEPOSIT - entry.payout) * GWEI, `${entry.name}: treasury share`);
            if (entry.deferred) {
                assert.ok(deferredEvent, `${entry.name}: the push must fail and be credited`);
                assert.equal(after[entry.destination], before[entry.destination]);
                assert.equal(await vaultRead('escapePayoutCredits', [entry.destination]), BigInt(entry.payout) * 1n);
            } else {
                assert.equal(after[entry.destination] - before[entry.destination], BigInt(entry.payout) * GWEI, `${entry.name}: destination`);
            }
            return { receipt, deferred: Boolean(deferredEvent) };
        }
        await scenario('pause with escapes pending, then finalize while paused (deferred credit and claim; SDK and companion close)', async () => {
            await challengerQuiet();
            const paused = await vaultSend(owner, 'pause', [], { operation: 'pause' });
            assert.equal(paused.status, '0x1');
            assert.equal(await vaultRead('paused'), true);
            // New exits are blocked while paused (until maxPauseDuration).
            const blocked = await driverEscape(replay.client, replay.noteId, { path: replay.depositPath, send: false });
            assert.equal(await revertName(blocked.plan.calldata), 'Paused');
            const deadlines = await Promise.all(pendingEscapes.map(async entry => Number((await vaultRead('pendingWithdrawals', [entry.noteId]))[5])));
            await skipChain(Math.max(...deadlines) - await chainNow() + 5, 'challenge period, while paused');
            const results = {};
            for (const entry of pendingEscapes.splice(0)) {
                const { receipt, deferred } = await finalizePending(entry);
                results[entry.name] = { finalize: receipt.transactionHash, payout_gwei: entry.payout, deferred };
                if (entry.deferred) {
                    const claimed = await vaultSend(account.thirdParty, 'claimEscapePayout', [entry.destination], { operation: 'claim_escape_payout' });
                    assert.equal(claimed.status, '0x1');
                    assert.equal(await vaultRead('escapePayoutCredits', [entry.destination]), 0n);
                    assert.equal((await balances(entry.destination))[entry.destination] - entry.before[entry.destination], BigInt(entry.payout) * GWEI);
                    results[entry.name].claim = claimed.transactionHash;
                }
                if (entry.client === 'companion') {
                    const closed = await waitFor('the companion records the finalized escape', async () => {
                        const answer = await entry.companion.call('POST', '/oa/v1/withdraw/escape/finalize', { transaction_hash: receipt.transactionHash });
                        return answer.status === 200 && answer.value.status === 'complete' && answer.value;
                    }, 60_000, 1_000);
                    assert.equal(closed.payout, String(entry.payout));
                    assert.equal(closed.conceded_final, String(DEPOSIT - entry.payout));
                    const wallet = await entry.companion.call('GET', '/status');
                    assert.equal(wallet.status, 200);
                    assert.ok(!wallet.value.note && wallet.value.active !== true, `the companion still holds the note: ${json(wallet.value)}`);
                    results[entry.name].client_final_state = { phase: closed.record?.phase ?? closed.status, payout: closed.payout,
                        conceded_final: closed.conceded_final, note: wallet.value.note ?? null };
                }
                if (entry.client === 'sdk') {
                    const after = await waitFor('the SDK closes the escape record', async () => {
                        const state = await entry.sdk('sync');
                        const record = state.withdrawals.find(item => Number(item.noteId) === entry.noteId);
                        return record?.phase === 'closed' && { state, record };
                    }, 90_000, 2_000);
                    assert.equal(after.state.note, null, 'the SDK holds no note after the payout');
                    results[entry.name].client_final_state = { phase: after.record.phase, conceded_final: after.record.concededFinal ?? null,
                        payout_alert: after.record.payoutAlert ?? null };
                }
            }
            assert.equal(await vaultRead('paused'), true, 'every finalization ran while paused');
            return { paused: paused.transactionHash, escapes: results };
        });
        stopAfter('pause');

        await scenario('pause past maxPauseDuration: exits reopen while paused; re-pause cooldown; abandoned proof replay after valid_until', async () => {
            const pausedAt = Number(await vaultRead('pausedAt'));
            await skipChain(pausedAt + TIMING.maxPauseDuration - await chainNow() + 1, 'past maxPauseDuration');
            assert.equal(await vaultRead('paused'), true);
            // The abandoned proof is past its valid_until: nobody can land it.
            assert.equal(await revertName(replay.abandoned.plan.calldata), 'ProofExpired');
            const replayed = await sendTx({ from: account.thirdParty, to: vaultAddress, data: replay.abandoned.plan.calldata, gasLimit: 1_000_000 });
            assert.equal(replayed.status, '0x0');
            gas.record('escape_expired_proof_reverts', replayed);
            // A fresh escape lands although the vault is still paused.
            const escape = await driverEscape(replay.client, replay.noteId, { path: replay.depositPath });
            pendingEscapes.push({ name: 'driver-escape-after-pause', client: 'driver', noteId: replay.noteId, destination: account.destination, payout: DEPOSIT });
            const unpaused = await vaultSend(owner, 'unpause', [], { operation: 'unpause' });
            assert.equal(unpaused.status, '0x1');
            assert.equal(await revertName(vault.encodeFunctionData('pause', []), owner), 'PauseCooldown');
            return { paused_at: pausedAt, escape_while_paused: escape.receipt.transactionHash, abandoned_proof: 'ProofExpired',
                repause: 'PauseCooldown' };
        });
        stopAfter('pause-max');

        // ================================================================ adversarial operators (drill build)
        // A signed successor at a non-derived anchor (S4) or above the bound
        // (S3): the wallet refuses it, the request circuit cannot spend it,
        // and the owner escapes conceding min(charge, bound) (lost response).
        async function refusedSuccessor(mode, check) {
            await startServer(mode);
            const client = await wallet(mode);
            const note = await driverDeposit(client);
            let first = null;
            if (mode === 'reuse-anchor') {
                // The first successor this server signs is the honest one; it
                // then signs every later successor at that same anchor.
                first = await honestRequest(client, note.noteId, `${mode}-first`);
            }
            const sent = await driverRequest(client, note.noteId, mode);
            const response = await settledResponse(sent.id);
            const before = await client('status');
            await assert.rejects(client('complete_response', { response }), new RegExp(`invalid_successor: ${check}`));
            const after = await client('status');
            assert.deepEqual(after.state.note, before.state.note, 'a refused successor changes no state');
            assert.equal(after.archived.at(-1).disposition, 'invalid_successor');
            let spend = null;
            if (check === 'S4') {
                const merkle = await treePath(client, note.noteId);
                spend = await client('spend_refused_successor', { args: { response, active_root: merkle.active_root,
                    merkle_siblings: merkle.siblings, request_time: wallNow() } });
                assert.equal(spend.server_signed, true, 'the drill server signed it');
                assert.equal(spend.circuit_satisfied, false, 'the request circuit cannot spend it (Q6a)');
                assert.notEqual(BigInt(spend.next_anchor), BigInt(spend.derived_anchor));
                if (mode === 'born-spent') {
                    assert.equal(BigInt(spend.next_anchor), 1n);
                    assert.equal(BigInt(spend.forced_nullifier), BigInt(spend.genesis_nullifier), 'anchor 1 names the genesis nullifier: born spent');
                }
                if (mode === 'reuse-anchor') assert.equal(BigInt(spend.next_anchor), BigInt(before.state.note.current_anchor));
            }
            const charge = Number(response.charge_applied);
            const bound = Number(after.state.note.bound_at_state);
            if (check === 'S3') assert.equal(charge, bound + 1, 'overcharge: one unit above the bound');
            const conceded = Math.min(charge, bound);
            const balanceBefore = Number(after.state.note.current_balance);
            const escape = await driverEscape(client, note.noteId, { conceded, path: note.depositPath });
            pendingEscapes.push({ name: mode, client: 'driver', noteId: note.noteId, destination: account.destination,
                payout: balanceBefore - conceded });
            return { note_id: note.noteId, server_mode: mode, refused_check: check, charge, bound, conceded,
                wallet_refusal: spend?.wallet_refusal ?? `invalid_successor: ${check}`, circuit_satisfied: spend?.circuit_satisfied ?? null,
                next_anchor: response.next_anchor, escape: escape.receipt.transactionHash, client_state: 'unchanged; record invalid_successor' };
        }
        await scenario('born-spent successor (anchor 1): client refuses (S4), circuit cannot spend it, escape concedes min(charge, bound)',
            () => refusedSuccessor('born-spent', 'S4'));
        await scenario('reused-anchor successor: client refuses (S4), circuit cannot spend it, escape concedes min(charge, bound)',
            () => refusedSuccessor('reuse-anchor', 'S4'));
        await scenario('random-anchor successor: client refuses (S4), circuit cannot spend it, escape concedes min(charge, bound)',
            () => refusedSuccessor('random-anchor', 'S4'));
        await scenario('overcharged successor: client refuses (S3), escape concedes the bound and no raise exceeds it',
            () => refusedSuccessor('overcharge', 'S3'));
        stopAfter('anchors');

        await scenario('lying expired_unaccepted: the SDK discards a request the operator reserved and spent; clearance reveals it; escape raised to the real charge', async () => {
            await startServer('lie-expired');
            const sdk = await sdkAgent('lie-expired', { walletAccount: account.sdk });
            await sdk('init');
            const deposited = await sdk('deposit', { amount: '0.001' });
            const noteId = Number(deposited.note.note_id);
            // The lease reaches serverd, which reserves it and issues a key;
            // the operator keeps the key, spends it, and tells the SDK that its
            // quote expired before acceptance.
            let stolen = null;
            gate.intercept = async ({ method, path: target, upstream }) => {
                if (method === 'POST' && target === '/v2/openrouter/leases' && upstream.status === 201 && !stolen) {
                    stolen = JSON.parse(upstream.body.toString());
                    return { status: 409, headers: { 'content-type': 'application/json' },
                        body: Buffer.from(JSON.stringify({ error_code: 'native_quote_expired', error: 'The ETH/USD quote expired before acceptance.',
                            retriable: false })) };
                }
                return upstream;
            };
            let chat;
            try {
                chat = await sdkRefusal(sdk('chat', { sessionId: 'acceptance-lie', model: MODEL, prompt: PROMPT }));
            } finally {
                gate.intercept = null;
            }
            assert.equal(chat.code, 'native_quote_expired', json(chat));
            assert.ok(stolen?.api_key, 'serverd issued the key');
            await inference(stolen);
            const lied = await sdk('snapshot');
            const record = lied.request_archive.at(-1);
            assert.equal(record?.disposition, 'discarded_expired_unaccepted', json(lied.request_archive));
            assert.equal(lied.wallet?.pending_request, false, 'the lie discarded the journal');
            // The state looks fresh, so the SDK asks for a clearance: the
            // reservation answers nullifier_used, and the state is unresolved.
            const mutual = await sdkRefusal(sdk('withdraw', { mode: 'mutual', destination: account.sdkDestination }));
            assert.equal(mutual.code, 'request_settlement_pending', json(mutual));
            // A forced early escape concedes nothing; the operator's raise
            // takes its real charge, never more than the bound.
            const escaped = await sdk('withdraw', { mode: 'escape', destination: account.sdkDestination });
            const escapeTx = escaped.sent.find(item => item.data === vault.getFunction('initiateEscapeWithdrawal').selector);
            const receipt = await waitReceipt(escapeTx.hash);
            assert.equal(receipt.status, '0x1');
            gas.record('escape', receipt, { client: 'sdk', conceded: 0 });
            assert.equal(eventOf(receipt, 'EscapeConcessionRecorded').args.conceded, 0n);
            const raised = await waitEvent('EscapeConcessionRaised', noteId, Number(BigInt(receipt.blockNumber)), (TIMING.leaseTtl + 120) * 1000);
            gas.record('raise', raised.receipt, { note_id: noteId });
            assert.equal(raised.event.args.conceded, BigInt(INFERENCE_CHARGE));
            const status = await get(`${gateUrl}/v2/requests/${stolen.client_request_id}`);
            assert.equal(status.nullifier_status, 'exit_deferred');
            pendingEscapes.push({ name: 'sdk-lie-expired', client: 'sdk', sdk, noteId, destination: account.sdkDestination,
                payout: DEPOSIT - INFERENCE_CHARGE });
            return { note_id: noteId, sdk_chat: chat.code, archived: record.disposition, archived_observations: record.observations, mutual: mutual.code,
                escape_at_ms: mutual.data?.escape_at ?? null, escape: escapeTx.hash, decision: escaped.result?.decision ?? null,
                raised_to: INFERENCE_CHARGE, server_status: status.nullifier_status };
        });
        stopAfter('lie-expired');

        await scenario('withholding operator: the SDK waits for T, then escapes conceding its bound; no defeat; payout B - b', async () => {
            await startServer('withhold');
            const sdk = await sdkAgent('withhold', { walletAccount: account.sdk });
            await sdk('init');
            const deposited = await sdk('deposit', { amount: '0.001' });
            const noteId = Number(deposited.note.note_id);
            const chat = await sdk('chat', { sessionId: 'acceptance-withhold', model: MODEL, prompt: PROMPT });
            assert.equal(chat.status, 200);
            // The server settles the request but never signs its successor.
            const settle = await sdk('settle').then(() => null, error => error.sdk);
            assert.ok(settle, 'a withheld successor never settles the chat');
            const waiting = await sdkRefusal(sdk('withdraw', { mode: 'mutual', destination: account.sdkDestination }));
            assert.equal(waiting.code, 'request_settlement_pending', json(waiting));
            const escapeAt = Number(waiting.data.escape_at);
            assert.ok(escapeAt > Date.now(), 'T is ahead');
            // The device clock reaches T (W + 900 s after the request) at once.
            await sdk('clock', { offsetSeconds: Math.ceil((escapeAt - Date.now()) / 1000) + 5 });
            const escaped = await sdk('withdraw', { mode: 'mutual', destination: account.sdkDestination });
            const escapeTx = escaped.sent.find(item => item.data === vault.getFunction('initiateEscapeWithdrawal').selector);
            assert.ok(escapeTx, json(escaped.statuses));
            const receipt = await waitReceipt(escapeTx.hash);
            assert.equal(receipt.status, '0x1');
            gas.record('escape', receipt, { client: 'sdk', conceded: 'bound' });
            const recorded = eventOf(receipt, 'EscapeConcessionRecorded');
            const bound = BigInt(escaped.result?.decision?.conceded ?? recorded.args.conceded);
            assert.equal(recorded.args.conceded, bound);
            assert.ok(bound >= BigInt(CAP), 'at T the escape concedes the state\'s bound');
            const stateBalance = Number(recorded.args.stateBalance);
            assert.equal(stateBalance, DEPOSIT);
            // The challenger owes nothing more (Ω = the settled charge ≤ c) and
            // has no successor evidence to defeat with.
            // ("raised" is the status of a concession that covers what is
            // owed, whether or not a raise was ever sent.)
            let seen = null;
            const obligation = await waitFor('the challenger finds the concession covers the withheld request', async () => {
                seen = (await challengerStatus()).obligations.find(item => item.note_id === noteId) ?? null;
                return ['nothing_due', 'raised'].includes(seen?.state) && seen?.evidence === 'settled' && seen;
            }, 120_000).catch(error => { throw new Error(`${error.message}; last seen ${json(seen)}`); });
            assert.equal(obligation.owed, INFERENCE_CHARGE);
            assert.equal(BigInt(obligation.conceded), bound);
            assert.equal(obligation.transaction_hash, null, 'nothing was sent for it');
            // Settled, never signed: the lease row reads 'finalized' between
            // settle and sign, then 'exit_deferred' once the exit is seen.
            assert.ok(['finalized', 'exit_deferred'].includes(obligation.settlement?.lease_status), json(obligation.settlement));
            pendingEscapes.push({ name: 'sdk-withhold', client: 'sdk', sdk, noteId, destination: account.sdkDestination,
                payout: stateBalance - Number(bound), noDefeatFrom: Number(BigInt(receipt.blockNumber)) });
            return { note_id: noteId, refusal_before_t: waiting.code, escape_at_ms: escapeAt, device_clock_advanced_s: Math.ceil((escapeAt - Date.now()) / 1000),
                decision: escaped.result?.decision ?? null, conceded: bound.toString(), escape: escapeTx.hash,
                challenger: { state: obligation.state, evidence: obligation.evidence, owed: obligation.owed, detail: obligation.detail } };
        });
        stopAfter('withhold');

        // ================================================================ a missed defeat
        await startServer();
        await scenario('missed defeat (challenger stopped), finalization, then retire-on-miss: retireClosedLeaf through the signer', async () => {
            await challengerQuiet();
            await stop(challenger);
            // A stale escape from the genesis state, whose successor's request
            // is in the server's evidence: a defeat is due, and nobody sends it.
            const escape = await driverEscape(missed.client, missed.noteId, { snapshot: 'S0', path: missed.depositPath });
            assert.equal(BigInt(escape.recorded.args.nextNullifier), BigInt(missed.requests[1].nullifier), 'evidence at N⁺ exists');
            pendingEscapes.push({ name: 'missed-defeat', client: 'driver', noteId: missed.noteId, destination: account.destination,
                payout: DEPOSIT, missed: true, escapeBlock: Number(BigInt(escape.receipt.blockNumber)) });
            return { note_id: missed.noteId, escape: escape.receipt.transactionHash, challenger: 'stopped' };
        });

        await scenario('finalize every pending escape; payouts, treasury shares and client states', async () => {
            const deadlines = await Promise.all(pendingEscapes.map(async entry => Number((await vaultRead('pendingWithdrawals', [entry.noteId]))[5])));
            await skipChain(Math.max(...deadlines) - await chainNow() + 5, 'challenge period');
            const results = {};
            for (const entry of pendingEscapes.splice(0)) {
                const raises = await vaultEventsSince('EscapeConcessionRaised', entry.noteId, deployBlock);
                const { receipt } = await finalizePending(entry);
                const defeats = await vaultEventsSince('EscapeWithdrawalChallenged', entry.noteId, deployBlock);
                results[entry.name] = { finalize: receipt.transactionHash, payout_gwei: entry.payout, treasury_gwei: DEPOSIT - entry.payout,
                    raises: raises.map(event => Number(event.args.conceded)), defeats: defeats.length };
                if (entry.name === 'sdk-withhold' || entry.name === 'missed-defeat') assert.equal(defeats.length, 0, `${entry.name}: never defeated`);
                if (entry.client === 'sdk') {
                    const after = await waitFor('the SDK closes the escape record', async () => {
                        const state = await entry.sdk('sync');
                        const record = state.withdrawals.find(item => Number(item.noteId) === entry.noteId);
                        return record?.phase === 'closed' && { state, record };
                    }, 90_000, 2_000);
                    assert.equal(after.state.note, null, `${entry.name}: the SDK holds no note after the payout`);
                    assert.equal(String(after.record.concededFinal ?? DEPOSIT - entry.payout), String(DEPOSIT - entry.payout));
                    results[entry.name].client_final_state = { phase: after.record.phase, conceded_final: after.record.concededFinal ?? null,
                        payout_alert: after.record.payoutAlert ?? null };
                }
                if (entry.client === 'driver') {
                    results[entry.name].client_final_state = 'the wallet holds the exited state; the note is Closed on chain';
                }
            }
            return { escapes: results };
        });

        await scenario('retire-on-miss: the restarted challenger reports the missed defeat and retires the closed leaf', async () => {
            const rootBefore = await vaultRead('currentRoot');
            const restartBlock = Number(await rpc('eth_blockNumber'));
            await startChallenger();
            const retired = await waitEvent('ClosedLeafRetired', missed.noteId, restartBlock, 120_000);
            gas.record('retire_closed_leaf', retired.receipt, { note_id: missed.noteId });
            assert.equal((await rpc('eth_getTransactionByHash', [retired.event.transactionHash])).from.toLowerCase(), challengerAccount.toLowerCase());
            assert.ok(challengeSends.some(send => send.call === 'retireClosedLeaf' && send.hash === retired.event.transactionHash),
                'the retirement went through the signer');
            const rootAfter = await vaultRead('currentRoot');
            assert.notEqual(rootAfter, rootBefore);
            assert.equal(BigInt(retired.event.args.newRoot), rootAfter);
            assert.equal(await vaultRead('isKnownRoot', [rootAfter]), true);
            const status = await waitFor('the challenger counts the missed defeat', async () => {
                const current = await challengerStatus();
                return current.escapes_finalized_with_successor_evidence_total >= 1 && current;
            }, 60_000);
            const logs = await Promise.all([...Array(challengerStarts).keys()].map(index =>
                fs.readFile(path.join(runDir, `challenger-${index + 1}.log`), 'utf8').catch(() => '')));
            assert.ok(logs.some(text => text.includes('MISSED escape deadline')), 'the challenger logs the miss');
            // The retired leaf is gone from the tree: the newest state of the
            // note can no longer prove membership at the current root.
            const snapshot = await synchronizedTree();
            assert.equal(BigInt(snapshot.leaves[missed.noteId]), 0n);
            const atCurrentRoot = await missed.client('tree_path', { args: { snapshot, note_id: missed.noteId, require_existing: true } });
            assert.equal((await missed.client('note_path_matches', { args: { active_root: atCurrentRoot.active_root,
                siblings: atCurrentRoot.siblings } })).matches, false, 'the note\'s leaf is not under the current root');
            const signer = await get(`${signerUrl}/health`);
            assert.equal(signer.retirements_last_24h, 1);
            return { note_id: missed.noteId, retirement: retired.event.transactionHash, new_root: felt(rootAfter),
                missed_defeats_counted: status.escapes_finalized_with_successor_evidence_total, signer_retirements_last_24h: signer.retirements_last_24h,
                last_missed: status.last_missed ?? null };
        });
        stopAfter('missed');

        await scenario('expiry sweep and pause cooldown end: claimExpired after effectiveExpiry; a pause after PAUSE_COOLDOWN', async () => {
            // Stop the daemons first: block time now runs ahead of the wall clock.
            await stop(challenger);
            await stop(server);
            gate.target = null;
            const expiry = Number(await vaultRead('effectiveExpiry', [expiryNote.noteId]));
            const now = await chainNow();
            await rpc('evm_increaseTime', [expiry - now + 1]);
            await rpc('evm_mine', []);
            const before = await balances(treasury, vaultAddress);
            const claimed = await vaultSend(account.thirdParty, 'claimExpired', [expiryNote.noteId], { operation: 'claim_expired' });
            assert.equal(claimed.status, '0x1');
            assert.ok(eventOf(claimed, 'ExpiredClaimed'));
            assert.equal((await noteView(expiryNote.noteId)).status, NOTE.Closed);
            const after = await balances(treasury, vaultAddress);
            assert.equal(after[treasury] - before[treasury], BigInt(DEPOSIT) * GWEI);
            const paused = await vaultSend(owner, 'pause', [], { operation: 'pause' });
            assert.equal(paused.status, '0x1', 'PAUSE_COOLDOWN has passed');
            await vaultSend(owner, 'unpause', [], { operation: 'unpause' });
            return { note_id: expiryNote.noteId, claim: claimed.transactionHash, treasury_gwei: DEPOSIT, repause_after_cooldown: paused.transactionHash };
        });

        // Every note of the run is closed; the vault holds only what the
        // ledger says it owes.
        assert.equal(await balance(vaultAddress), 0n, 'the vault holds nothing once every note closed and every credit was claimed');
        assert.equal(await vaultRead('treasuryArrears'), 0n);

        evidence.pinned_rpc_methods = Object.fromEntries(pinnedRpcMethods);
        evidence.operator_gate = { requests: gate.log.length, while_down: gate.log.filter(entry => entry.mode === 'down').length };
        evidence.mock_provider = { keys: mock.keys.size, events: mock.events.length,
            oa_org_keys: mock.events.filter(event => event.source === 'oa_org' && event.type === 'issued').length };
        evidence.challenger_sends = challengeSends.map(send => ({ call: send.call, note_id: send.note_id, hash: send.hash ?? null,
            error: send.error ?? null, ...send.fees }));
        const hashes = {};
        for (const file of [fileURLToPath(import.meta.url), path.join(ROOT, 'crates/zkapi-serverd/examples/v2_acceptance_wallet.rs'),
            path.join(ROOT, 'scripts/acceptance/sdk-agent.mjs'),
            ...['zkapi', 'zkapi-indexerd', 'zkapi-challenged', 'zkapi-walletd', 'examples/v2_acceptance_wallet'].map(file => path.join(opts.binDir, file)),
            ...['request.pk', 'request.vk', 'withdrawal.pk', 'withdrawal.vk'].map(file => path.join(SETUP_DIR, file)),
            path.join(ROOT, 'sdk/wasm/zkapi_browser_bg.wasm')]) {
            hashes[path.relative(ROOT, file)] = await sha256File(file).catch(() => null);
        }
        const gitOutput = args => {
            const result = spawnSync('git', args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
            assert.equal(result.status, 0, `git ${args.join(' ')} failed: ${result.error?.message ?? result.stderr}`);
            return result.stdout;
        };
        const gasReport = { schema: 'zkapi-acceptance-gas/v1', circuit_id: 'zkapi-v2-concession-v1', setup_id: finalized.setupId,
            chain: 'anvil', chain_id: CHAIN_ID, note: 'transaction gasUsed of real calls on a fresh Anvil vault (receipt gas, refunds applied)',
            snapshot: await readJSON(path.join(ROOT, 'protocol/contracts/snapshots/concession-exit-gas.json')).catch(() => null),
            summary: gas.summary(), transactions: gas.entries };
        await save('gas.json', gasReport);
        const result = { passed: true, timestamp: new Date().toISOString(), elapsed_wall_seconds: (Date.now() - started) / 1000,
            source_commit: gitOutput(['rev-parse', 'HEAD']).trim(),
            source_dirty: gitOutput(['status', '--porcelain']).trim().length > 0,
            tracked_source_diff_sha256: createHash('sha256').update(gitOutput(['diff', '--binary', 'HEAD'])).digest('hex'),
            artifact_sha256: hashes,
            network: { chain_id: CHAIN_ID, kind: 'disposable loopback Anvil with Sepolia\'s chain ID', fork: false, public_rpc: false,
                chain_lag_seconds_at_start: CHAIN_LAG_SECONDS },
            coverage: {
                contracts: 'protocol/contracts via demo/contracts/script/Deploy.s.sol, finalized by scripts/expected-codehashes.mjs',
                proof_system: 'protocol/setup/v2-concession-dev (single-party dev setup, drill vault only)',
                server: 'zkapi serverd (drill build: --adversary withhold, born-spent, reuse-anchor, random-anchor, overcharge, lie-expired), SQLite archive bound by zkapi db init',
                indexer: `zkapi-indexerd at ${INDEXER_CONFIRMATIONS} confirmations, stopped and restarted from its checkpoint`,
                challenger: 'zkapi-challenged: defeats, raises and retire-on-miss through the signer sidecar',
                signer: 'docker/aws/signer (EIP-1559, allowlisted calls, retirement budget)',
                clients: { wallet_core: 'examples/v2_acceptance_wallet (zkapi-browser natively)', sdk: 'sdk/ (zkapiClient + browserWalletRuntime) with sdk/wasm in Node',
                    companion: 'zkapi-walletd routes the Go clientd calls (the harness signs and sends its transactions)' },
                provider: 'loopback mock management and inference HTTP service',
                oracle: 'loopback mock ETH/USD feed; every other read is the actual chain',
                external_provider_verified: false, live_network_verified: false, go_clientd_verified: false },
            scenarios, evidence, gas: gasReport.summary };
        await save('result.json', result);
        // The per-run seeds must not appear in any saved evidence or log.
        const secrets = Object.values(seedEnv).flatMap(seed => [seed, seed.slice(2)]);
        for (const name of await fs.readdir(runDir, { recursive: true })) {
            const file = path.join(runDir, name);
            if (!(await fs.stat(file)).isFile()) continue;
            const content = await fs.readFile(file);
            assert.ok(secrets.every(secret => !content.includes(secret)), `${name} contains an operator seed`);
        }
        for (const item of scenarios) console.log(`${item.status}  ${item.name}`);
        console.log(`PASS: ${scenarios.length} scenarios.\nEvidence: ${runDir}`);
    } catch (error) {
        if (error?.stopped) {
            for (const item of scenarios) console.log(`${item.status}  ${item.name}`);
            console.log(`${error.message}.\nEvidence: ${runDir}`);
        } else {
            await save('failure.json', { passed: false, error: error.message, stack: error.stack, scenarios, evidence });
            for (const item of scenarios) console.log(`${item.status}  ${item.name}`);
            console.error(`FAIL: ${error.message}\nEvidence: ${runDir}`);
            process.exitCode = 1;
        }
    } finally {
        if (miner) clearInterval(miner);
        for (const agent of sdkAgents) await agent.close?.().catch(() => {});
        for (const child of [...children]) await stop(child);
        for (const server of servers) {
            server.closeAllConnections?.();
            await new Promise(resolve => server.close(resolve));
        }
        process.off('SIGINT', onSignal);
        process.off('SIGTERM', onSignal);
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    await main();
}
