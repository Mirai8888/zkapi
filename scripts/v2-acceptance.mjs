#!/usr/bin/env node
// Entirely local acceptance test. The provider and price feed are explicit mocks;
// wallet cryptography, HTTP server, SQLite archive, indexer, vault and challenger are real.
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
const CHAIN_ID = 31337;
const GWEI = 1_000_000_000n;
const DEPOSIT = 1_000_000;
const EXTRA_DEPOSIT = 10_000;
const CAP = 50_000;
const MOCK_USAGE_MICRO_USD = 1_000;
const MOCK_PRICE = 250_000_000_000n; // $2,500 / ETH, eight decimal places.
const WITHDRAWAL_TUPLE = 'tuple(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,bool,uint256)';
// Challenger fee policy: the daemon must stay within these caps and keep a
// tip cap of at least twice its first tip for same-nonce replacements.
const CHALLENGE_MAX_FEE_PER_GAS = 100n * GWEI;
const CHALLENGE_MAX_PRIORITY_FEE_PER_GAS = 10n * GWEI;
const CHALLENGE_PRIORITY_FEE_PER_GAS = 2n * GWEI;
const INDEXER_CONFIRMATIONS = 2;
// Vault getters the API server may read over its native-billing RPC, all at
// "latest": the deposit unit, the pinned signing keys and challenge period
// (startup binding), and the live root (ownership-proof clearance).
const SERVER_VAULT_GETTERS = Object.freeze({
    '0x4d1352fd': 'nativeAssetWeiPerUnit',
    '0x15fa2a9a': 'stateSigningKeyX',
    '0x230e2a24': 'stateSigningKeyY',
    '0xdc41d636': 'clearanceSigningKeyX',
    '0x112cd6bc': 'clearanceSigningKeyY',
    '0xf3f480d9': 'challengePeriod',
    '0xfdab463d': 'currentRoot',
});
const CHALLENGED_NULLIFIER_ERROR = '0x2845df70'; // ChallengedNullifier()
// The indexer's constant public body while it has no verified view.
const INDEXER_UNAVAILABLE = Object.freeze({ status: 'unavailable', error_code: 'indexer_unavailable',
    error_message: 'the indexer has no verified view of the vault state; retry later', retriable: true,
    retry_after_seconds: 5 });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const json = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2);
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
        assert.ok(bytes < 1_048_576, 'oversized local HTTP request');
        chunks.push(chunk);
    }
    return JSON.parse(Buffer.concat(chunks).toString() || '{}');
}

function respond(res, status, value) {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(value));
}

export async function localJSON(url, { method = 'GET', value, headers = {} } = {}) {
    const parsed = loopback(url);
    return new Promise((resolve, reject) => {
        const outgoing = http.request(parsed, { method, agent: localAgent,
            headers: { 'content-type': 'application/json', ...headers } }, incoming => {
            const chunks = [];
            incoming.on('data', chunk => chunks.push(chunk));
            incoming.on('error', reject);
            incoming.on('end', () => {
                try { resolve({ status: incoming.statusCode, value: JSON.parse(Buffer.concat(chunks).toString()) }); }
                catch (error) { reject(error); }
            });
        });
        outgoing.setTimeout(30_000, () => outgoing.destroy(new Error('Local HTTP request timed out')));
        outgoing.on('error', reject);
        outgoing.end(value === undefined ? undefined : JSON.stringify(value));
    });
}

// Forwards one JSON-RPC call and relays an upstream error unchanged, so the
// challenger sees the node's own {code, message, data} (for example revert data).
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
                if (request.model !== 'local/mock-model' || request.max_tokens !== 8 || request.stream !== false
                    || request.messages?.length !== 1 || request.messages[0].role !== 'user'
                    || request.messages[0].content !== 'Reply with the word OK.') {
                    return respond(res, 400, { error: 'unexpected acceptance-test inference request' });
                }
                if (key.usage_micro_usd + MOCK_USAGE_MICRO_USD > Math.floor(key.limit * 1_000_000)) {
                    return respond(res, 402, { error: 'local runtime key spending limit reached' });
                }
                key.usage_micro_usd += MOCK_USAGE_MICRO_USD;
                key.calls += 1;
                events.push({ type: 'inference', hash: key.hash, usage_micro_usd: key.usage_micro_usd });
                return respond(res, 200, { id: `local-${key.calls}`, object: 'chat.completion',
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

function options(args) {
    const parsed = { binDir: path.join(ROOT, 'target/release'), outputDir: path.join(ROOT, '.zkapi/acceptance') };
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--help') return { help: true };
        const key = { '--bin-dir': 'binDir', '--output-dir': 'outputDir' }[args[i]];
        assert.ok(key && args[i + 1], `Unknown or incomplete option: ${args[i]}`);
        parsed[key] = path.resolve(args[++i]);
    }
    return parsed;
}

function linkBytecode(artifact, addresses) {
    let bytecode = artifact.bytecode.object;
    for (const [source, libraries] of Object.entries(artifact.bytecode.linkReferences ?? {})) {
        for (const [name, references] of Object.entries(libraries)) {
            const address = addresses[`${source}:${name}`];
            assert.match(address ?? '', /^0x[0-9a-fA-F]{40}$/);
            for (const ref of references) {
                assert.equal(ref.length, 20);
                const offset = 2 + ref.start * 2;
                bytecode = bytecode.slice(0, offset) + address.slice(2).toLowerCase() + bytecode.slice(offset + 40);
            }
        }
    }
    assert.match(bytecode, /^0x[0-9a-fA-F]+$/, 'unlinked Solidity library');
    return bytecode;
}

// A per-run operator seed: 31 random bytes, below the subgroup order and far
// from zero, as the server's seed policy requires.
const randomSeed = () => `0x${randomBytes(31).toString('hex')}`;

// Revert data of an ethers v6 call exception, wherever the provider put it.
const revertData = error => [error?.data, error?.info?.error?.data, error?.error?.data]
    .find(data => typeof data === 'string' && data.startsWith('0x'));

async function main() {
    const opts = options(process.argv.slice(2));
    if (opts.help) {
        console.log('Usage: node scripts/v2-acceptance.mjs [--bin-dir target/release] [--output-dir .zkapi/acceptance]\nRuns only disposable loopback services, with mock provider and oracle. See docs/v2-acceptance.md.');
        return;
    }
    const { AbiCoder, Contract, ContractFactory, FetchRequest, JsonRpcProvider } = await import(
        pathToFileURL(path.join(ROOT, 'docker/aws/signer/node_modules/ethers/lib.esm/index.js')).href);
    const coder = AbiCoder.defaultAbiCoder();
    const started = Date.now();
    const runDir = path.join(opts.outputDir, `${new Date().toISOString().replaceAll(':', '-')}-${randomUUID().slice(0, 8)}`);
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
    let provider;
    let interrupted = false;
    // The first assertion failure inside a loopback mock; it fails the run
    // instead of surfacing to a daemon as a transport error.
    let fatal;
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
    async function waitFor(label, fn, timeout = 30_000) {
        const end = Date.now() + timeout;
        let last;
        while (Date.now() < end) {
            check();
            try { const value = await fn(); if (value) return value; } catch (error) { last = error; }
            await delay(100);
        }
        check();
        throw new Error(`Timeout: ${label}${last ? ` (${last.message})` : ''}`);
    }
    function launch(command, args, log, { interactive = false, env = {} } = {}) {
        check();
        const out = createWriteStream(path.join(runDir, log), { flags: 'a', mode: 0o600 });
        // No inherited credentials, network proxies, HOME, or provider settings.
        const child = spawn(command, args, { cwd: ROOT, env: { PATH: process.env.PATH,
            RUST_LOG: 'warn,zkapi=info,zkapi_serverd=info,zkapi_indexerd=info,r1cs=warn', ...env },
            stdio: [interactive ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
        if (!interactive) child.stdout.pipe(out);
        child.stderr.pipe(out);
        child.once('error', error => out.write(error.message));
        child.once('close', () => { children.delete(child); out.end(); });
        children.add(child);
        return child;
    }
    // Runs a process that must exit by itself and returns its exit status and
    // output. The event loop keeps serving the loopback mocks meanwhile.
    async function runToExit(command, args, log, env, timeout = 180_000) {
        const child = launch(command, args, log, { env });
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
        await Promise.race([done, delay(2000)]);
        if (child.exitCode === null && child.signalCode === null) {
            child.kill('SIGKILL');
            await Promise.race([done, delay(2000)]);
        }
    }
    async function freePort() {
        const server = net.createServer();
        await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
        const port = server.address().port;
        await new Promise(resolve => server.close(resolve));
        return port;
    }
    async function serve(handler) {
        const server = http.createServer((req, res) => Promise.resolve(handler(req, res)).catch(error => respond(res, 500, { error: error.message })));
        await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
        servers.add(server);
        return `http://127.0.0.1:${server.address().port}`;
    }
    async function request(url, { method = 'GET', value, headers = {} } = {}) {
        check();
        return localJSON(url, { method, value, headers });
    }
    async function get(url) {
        const result = await request(url);
        assert.equal(result.status, 200, `${new URL(url).pathname}: ${result.value.error_code ?? result.status}`);
        return result.value;
    }
    let rpcId = 0;
    async function rpc(url, method, params = []) {
        const result = await request(url, { method: 'POST', value: { jsonrpc: '2.0', id: ++rpcId, method, params } });
        assert.equal(result.status, 200);
        if (result.value.error) throw new Error(`${method}: ${JSON.stringify(result.value.error)}`);
        return result.value.result;
    }
    function wallet(name) {
        const child = launch(path.join(opts.binDir, 'examples/v2_acceptance_wallet'), [path.join(ROOT, 'protocol/setup/v2')], `${name}-wallet.log`, { interactive: true });
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
        return async (command, data = {}) => {
            check();
            const id = ++nextId;
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Wallet ${command} timed out`)); }, 120_000);
                pending.set(id, { command, resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
                child.stdin.write(JSON.stringify({ id, command, ...data }) + '\n');
            });
        };
    }
    // Derives the public signing keys from seeds passed in the environment.
    function signingKeysFor(env) {
        return spawnSync(path.join(opts.binDir, 'zkapi'), ['signing-keys'], { cwd: ROOT, encoding: 'utf8',
            env: { PATH: process.env.PATH, RUST_LOG: 'warn', ...env } });
    }

    try {
        console.log('Starting local v2 acceptance: real proofs and services, mock provider and oracle.');
        const client = wallet('primary');
        assert.equal((await client('circuit')).circuit_id, 'zkapi-v2-note-bound-v1');
        const derived = signingKeysFor(seedEnv);
        assert.equal(derived.status, 0, `zkapi signing-keys failed: ${derived.stderr}`);
        const signingKeys = JSON.parse(derived.stdout);
        const development = signingKeysFor({ ZKAPI_STATE_SEED: '0x1', ZKAPI_CLEAR_SEED: '0x2' });
        assert.notEqual(development.status, 0, 'signing-keys must refuse the published development seeds');
        assert.match(development.stderr, /published development key/);
        const port = await freePort();
        const rpcUrl = `http://127.0.0.1:${port}`;
        launch('anvil', ['--host', '127.0.0.1', '--port', String(port), '--chain-id', String(CHAIN_ID),
            '--mnemonic', 'test test test test test test test test test test test junk', '--silent'], 'anvil.log');
        await waitFor('Anvil startup', async () => await rpc(rpcUrl, 'eth_chainId') === '0x7a69');
        const ethersRpc = new FetchRequest(rpcUrl);
        const getLocalUrl = FetchRequest.createGetUrlFunc({ agent: localAgent });
        ethersRpc.getUrlFunc = (req, signal) => { loopback(req.url); return getLocalUrl(req, signal); };
        provider = new JsonRpcProvider(ethersRpc, CHAIN_ID, { staticNetwork: true, cacheTimeout: -1 });
        const accounts = await rpc(rpcUrl, 'eth_accounts');
        const signer = await provider.getSigner(accounts[0]);
        const challengerAccount = accounts[1];
        const destination = accounts[2];
        const treasury = accounts[3];
        const artifact = name => readJSON(path.join(ROOT, `protocol/contracts/out/${name}.sol/${name}.json`));
        const poseidonArtifact = await artifact('Bn254Poseidon');
        const adapterArtifact = await artifact('Groth16ProofAdapter');
        const vaultArtifact = await artifact('ZkApiVault');
        const poseidon = await new ContractFactory(poseidonArtifact.abi, linkBytecode(poseidonArtifact, {}), signer).deploy();
        await poseidon.waitForDeployment();
        const adapter = await new ContractFactory(adapterArtifact.abi, linkBytecode(adapterArtifact, {}), signer).deploy();
        await adapter.waitForDeployment();
        const deployed = await new ContractFactory(vaultArtifact.abi, linkBytecode(vaultArtifact,
            { 'src/libraries/Bn254Poseidon.sol:Bn254Poseidon': await poseidon.getAddress() }), signer).deploy(
            treasury, 30 * 86400, 86400, CAP, await adapter.getAddress(), signingKeys.state_signing_key.x,
            signingKeys.state_signing_key.y, signingKeys.clearance_signing_key.x, signingKeys.clearance_signing_key.y, accounts[0]);
        const deployment = await deployed.deploymentTransaction().wait();
        const vaultAddress = await deployed.getAddress();
        const vault = new Contract(vaultAddress, vaultArtifact.abi, signer);
        for (const [selector, name] of Object.entries(SERVER_VAULT_GETTERS)) {
            assert.equal(vault.interface.getFunction(name).selector, selector, `${name} selector`);
        }
        const usedNullifierCall = new RegExp(`^${vault.interface.getFunction('usedNullifiers').selector}[0-9a-fA-F]{64}$`);
        assert.equal(await vault.challengePeriod(), 86400n);
        const vaultKeys = {
            state: { x: await vault.stateSigningKeyX(), y: await vault.stateSigningKeyY() },
            clearance: { x: await vault.clearanceSigningKeyX(), y: await vault.clearanceSigningKeyY() },
        };
        const sameKey = (wire, pinned) => BigInt(wire.x) === pinned.x && BigInt(wire.y) === pinned.y;
        assert.ok(sameKey(signingKeys.state_signing_key, vaultKeys.state) && sameKey(signingKeys.clearance_signing_key, vaultKeys.clearance),
            'the vault pins the keys derived from this run\'s seeds');
        const config = { protocol_version: 2, chain_id: CHAIN_ID, contract_address: vaultAddress,
            request_charge_cap: CAP, policy_charge_cap: 0, policy_enabled: false,
            state_signing_key: signingKeys.state_signing_key, clearance_signing_key: signingKeys.clearance_signing_key };
        await client('init', { config });
        const indexerPort = await freePort();
        const indexerUrl = `http://127.0.0.1:${indexerPort}`;
        // Anvil mines on demand, so the head-age check is disabled.
        launch(path.join(opts.binDir, 'zkapi-indexerd'), ['--listen', `127.0.0.1:${indexerPort}`, '--rpc-url', rpcUrl,
            '--contract-address', vaultAddress, '--from-block', String(deployment.blockNumber), '--poll-interval-ms', '100',
            '--chain-id', String(CHAIN_ID), '--confirmations', String(INDEXER_CONFIRMATIONS), '--max-head-age-secs', '0',
            '--cursor-path', path.join(runDir, 'indexer.json')], 'indexer.log');
        async function synchronizedTree() {
            const chainRoot = await vault.currentRoot();
            return waitFor('indexer root matches actual chain', async () => {
                const snapshot = await get(`${indexerUrl}/v1/tree/snapshot`);
                return BigInt(snapshot.root) === chainRoot && snapshot;
            });
        }
        async function treePath(walletClient, noteId, requireExisting = true) {
            return walletClient('tree_path', { args: { snapshot: await synchronizedTree(), note_id: noteId, require_existing: requireExisting } });
        }
        async function deposit(walletClient, amount) {
            const snapshot = await synchronizedTree();
            const params = await walletClient('deposit_params');
            const merkle = await walletClient('tree_path', { args: { snapshot, note_id: snapshot.next_note_id, require_existing: false } });
            const commitment = `0x${BigInt(params.registration_commitment).toString(16).padStart(64, '0')}`;
            const receipt = await (await vault.deposit(commitment, amount, merkle.siblings, { value: BigInt(amount) * GWEI })).wait();
            const noteId = snapshot.next_note_id;
            const note = await vault.notes(noteId);
            assert.equal(note[1], BigInt(amount)); assert.equal(note[3], 1n);
            const status = await walletClient('confirm_deposit', { args: { note_id: noteId, amount, expiry_ts: Number(note[2]) } });
            await synchronizedTree();
            return { noteId, receipt, status };
        }
        const primary = await deposit(client, DEPOSIT);
        assert.equal(primary.noteId, 0);
        assert.equal(primary.status.state.note.is_genesis, true);
        assert.equal(primary.status.state.note.current_balance, DEPOSIT);
        await save('deposit-receipt.json', primary.receipt);
        console.log('Deposited a fresh genesis note; checking that the actual HTTP protocol server binds to the vault keys.');
        const mock = mockProvider();
        const providerUrl = await serve(mock.handler);
        const feed = '0x0000000000000000000000000000000000001234';
        const quoteTimestamp = Math.floor(Date.now() / 1000) - 1;
        const oracleVaultReads = new Set();
        // While set, the native-billing RPC answers every call with an error.
        const oracleOutage = { active: false, refused: 0 };
        const oracleUrl = await serve(async (req, res) => {
            const call = await body(req);
            const target = call.params?.[0];
            if (oracleOutage.active) {
                oracleOutage.refused++;
                return respond(res, 200, { jsonrpc: '2.0', id: call.id, error: { code: -32000, message: 'local RPC outage' } });
            }
            let result;
            try {
                if (call.method === 'eth_call' && target?.to?.toLowerCase() === feed) {
                    if (target.data === '0x313ce567') result = coder.encode(['uint256'], [8]);
                    else {
                        assert.equal(call.params[1], 'finalized', 'oracle rounds must use finalized reads');
                        assert.ok(target.data === '0xfeaf968c' || target.data === `0x9a6fc8f5${(123n).toString(16).padStart(64, '0')}`);
                        result = coder.encode(['uint80', 'int256', 'uint256', 'uint256', 'uint80'], [123, MOCK_PRICE, quoteTimestamp, quoteTimestamp, 123]);
                    }
                } else {
                    const getter = call.method === 'eth_call' && target?.to?.toLowerCase() === vaultAddress.toLowerCase()
                        && (SERVER_VAULT_GETTERS[target.data] ?? (usedNullifierCall.test(target.data) ? 'usedNullifiers' : undefined));
                    assert.ok(call.method === 'eth_chainId' || getter, `unexpected oracle RPC read: ${call.method} ${target?.data?.slice(0, 10) ?? ''}`);
                    if (getter) {
                        assert.equal(call.params[1], 'latest', 'vault authorization must use the current chain state');
                        oracleVaultReads.add(getter);
                    }
                    result = await rpc(rpcUrl, call.method, call.params);
                }
            } catch (error) {
                fatal ??= error;
                throw error;
            }
            respond(res, 200, { jsonrpc: '2.0', id: call.id, result });
        });
        const dbPath = path.join(runDir, 'server.db');
        const serverCommand = path.join(opts.binDir, 'zkapi');
        const serverArgs = (listenPort, db, contract = vaultAddress) => ['--chain-id', String(CHAIN_ID), '--contract-address', contract,
            '--request-charge-cap', String(CAP), '--proof-setup-dir', path.join(ROOT, 'protocol/setup/v2'), 'serverd',
            '--listen', `127.0.0.1:${listenPort}`, '--openrouter-api-base', providerUrl,
            '--openrouter-management-key', 'local-only-management-key', '--openrouter-lease-ttl-seconds', '300',
            '--openrouter-settlement-grace-seconds', '1', '--openrouter-settlement-poll-seconds', '1',
            '--native-billing-rpc-url', oracleUrl, '--native-price-feed-address', feed,
            '--db-path', db, '--indexer-url', indexerUrl, '--root-poll-interval-ms', '100'];
        // Each refused start uses its own database path and must exit non-zero
        // before creating anything at that path.
        async function refusedStartWith(label, env, refusal, args, fresh = true) {
            const db = args[args.indexOf('--db-path') + 1];
            const before = fresh ? [] : await fs.readdir(runDir);
            const result = await runToExit(serverCommand, args, `refused-${label}.log`, env);
            assert.ok(result.code !== null && result.code !== 0, `${label}: serverd must refuse to start (exit ${result.code}, ${result.signal})`);
            assert.match(result.output, refusal, `${label}: unexpected refusal`);
            const files = (await fs.readdir(runDir)).filter(name => name.startsWith(path.basename(db)));
            assert.deepEqual(files, before.filter(name => name.startsWith(path.basename(db))),
                `${label}: a refused start must not create database files`);
            return { exit_code: result.code, refusal: refusal.source, database_created: false };
        }
        const refusedStart = async (label, env, refusal) =>
            refusedStartWith(label, env, refusal, serverArgs(await freePort(), path.join(runDir, `refused-${label}.db`)));
        const refusedStarts = {
            development_seeds: await refusedStart('development-seeds', { ZKAPI_STATE_SEED: '0x1', ZKAPI_CLEAR_SEED: '0x2' },
                /published development key/),
            unpinned_seeds: await refusedStart('unpinned-seeds', { ZKAPI_STATE_SEED: randomSeed(), ZKAPI_CLEAR_SEED: randomSeed() },
                /do not match the vault's immutable keys/),
            missing_seeds: await refusedStart('missing-seeds', {}, /ZKAPI_STATE_SEED \(or --state-seed\) is required/),
        };
        console.log('Refused development, unpinned and missing seeds; starting the actual HTTP protocol server.');
        const serverPort = await freePort();
        const serverUrl = `http://127.0.0.1:${serverPort}`;
        oracleVaultReads.clear();
        const server = launch(serverCommand, serverArgs(serverPort, dbPath), 'server.log', { env: seedEnv });
        await waitFor('actual server ready at chain root', async () => BigInt((await get(`${serverUrl}/health`)).current_root) === await vault.currentRoot());
        const attestation = await get(`${serverUrl}/v1/attestation`);
        assert.deepEqual(attestation.state_signing_key, signingKeys.state_signing_key);
        assert.deepEqual(attestation.clearance_signing_key, signingKeys.clearance_signing_key);
        assert.ok(sameKey(attestation.state_signing_key, vaultKeys.state) && sameKey(attestation.clearance_signing_key, vaultKeys.clearance),
            'served signing keys must equal the vault getters');
        await waitFor('server log confirms the vault key binding', async () =>
            (await fs.readFile(path.join(runDir, 'server.log'), 'utf8')).includes("server signing keys match the vault's immutable keys"));
        for (const getter of ['stateSigningKeyX', 'stateSigningKeyY', 'clearanceSigningKeyX', 'clearanceSigningKeyY', 'challengePeriod']) {
            assert.ok(oracleVaultReads.has(getter), `startup did not read ${getter}() from the vault`);
        }
        const startupKeyBinding = { seeds: 'per-run random 31-byte seeds, passed only by environment',
            derived_with: 'zkapi signing-keys', vault_constructor_keys: 'derived keys', attestation_equals_vault_getters: true,
            startup_vault_reads: [...oracleVaultReads].sort(), binding_log_line: true,
            signing_keys_refuses_development_seeds: true, refused_starts: refusedStarts };
        const settlements = [];
        async function inferenceAndSettlement(label) {
            const merkle = await treePath(client, primary.noteId);
            const quote = await get(`${serverUrl}/v2/billing/quote`);
            const payload = JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: quote });
            const id = `acceptance-${label}-${randomUUID()}`;
            const prepared = await client('prepare_request', { args: { payload, active_root: merkle.active_root,
                merkle_siblings: merkle.siblings, client_request_id: id, request_time: Math.floor(Date.now() / 1000), created_at_ms: Date.now() } });
            const issued = await request(`${serverUrl}/v2/openrouter/leases`, { method: 'POST', value: prepared.request });
            assert.equal(issued.status, 201, `lease rejected: ${issued.value.error_code ?? issued.status}`);
            const lease = issued.value;
            assert.equal(lease.openrouter_api_base, `${providerUrl}/v1`);
            assert.equal(lease.key_source, 'openrouter');
            const key = [...mock.keys.values()].find(k => k.key === lease.api_key);
            assert.ok(key); assert.equal(key.usage_micro_usd, 0);
            const issuedCount = mock.keys.size;
            const replay = await request(`${serverUrl}/v2/openrouter/leases`, { method: 'POST', value: prepared.request });
            assert.equal(replay.status, 409, 'active lease replay must not mint another runtime key');
            assert.equal(mock.keys.size, issuedCount);
            const inference = await request(`${lease.openrouter_api_base}/chat/completions`, { method: 'POST',
                headers: { authorization: `Bearer ${lease.api_key}` }, value: { model: 'local/mock-model',
                    messages: [{ role: 'user', content: 'Reply with the word OK.' }], max_tokens: 8, stream: false } });
            assert.equal(inference.status, 200); assert.equal(inference.value.choices[0].message.content, 'OK');
            assert.equal(key.calls, 1); assert.equal(key.usage_micro_usd, MOCK_USAGE_MICRO_USD);
            const retired = await request(`${serverUrl}/v2/openrouter/leases/${id}`, { method: 'POST', value: prepared.request });
            assert.ok(retired.status === 200 || (retired.status === 409 && retired.value.error_code === 'lease_settlement_pending'),
                `retirement failed: ${retired.status}/${retired.value.error_code}`);
            const recovery = await waitFor('cryptographic usage settlement from HTTP recovery', async () => {
                const found = await get(`${serverUrl}/v2/requests/${id}`);
                return found.request_response && found;
            });
            const response = recovery.request_response;
            const expectedCharge = Number((BigInt(MOCK_USAGE_MICRO_USD) * 1_000_000_000n * 100_000_000n + MOCK_PRICE * 1_000_000n - 1n)
                / (MOCK_PRICE * 1_000_000n));
            assert.equal(response.charge_applied, expectedCharge);
            const settledPayload = JSON.parse(response.response_payload);
            assert.equal(settledPayload.usage_usd, MOCK_USAGE_MICRO_USD / 1_000_000);
            assert.equal(settledPayload.charge_basis, 'measured');
            assert.equal(key.disabled, true); assert.equal(key.deleted, true);
            assert.deepEqual(mock.events.filter(event => event.hash === key.hash).map(event => event.type),
                ['issued', 'inference', 'disabled', 'usage_read', 'deleted']);
            const beforeTamper = await client('status');
            const tampered = structuredClone(response);
            tampered.next_state_signature.s = `0x${(BigInt(tampered.next_state_signature.s) ^ 1n).toString(16)}`;
            await assert.rejects(client('complete_response', { response: tampered }), /signature/i,
                'client must reject a forged state signature');
            assert.deepEqual(await client('status'), beforeTamper, 'failed completion must preserve wallet and pending journal');
            const completed = await client('complete_response', { response });
            assert.equal(completed.pending_request, false);
            assert.equal(completed.state.note.is_genesis, false);
            const record = { label, client_request_id: id, request_nullifier: prepared.request.public_inputs.request_nullifier,
                archived_root: prepared.request.public_inputs.active_root, provider_calls: key.calls,
                provider_usage_micro_usd: key.usage_micro_usd, charge_gwei: expectedCharge, charge_basis: settledPayload.charge_basis,
                state: completed, verified_signed_settlement: true, tampered_signature_rejected_without_state_change: true,
                active_lease_replay_did_not_mint_key: true, runtime_key_revoked: key.deleted };
            settlements.push(record);
            await save(`${label}-settlement.json`, { ...record, response });
            return { request: prepared.request, response, record };
        }
        const first = await inferenceAndSettlement('first');
        await client('snapshot', { name: 'settled-before-second-request' });
        console.log('First real HTTP settlement verified; spending the signed state again.');
        const second = await inferenceAndSettlement('second');
        assert.notEqual(first.request.public_inputs.request_nullifier, second.request.public_inputs.request_nullifier);
        const totalCharge = settlements.reduce((sum, item) => sum + item.charge_gwei, 0);
        const extraClient = wallet('unrelated');
        await extraClient('init', { config });
        const unrelated = await deposit(extraClient, EXTRA_DEPOSIT);
        const restoredRoot = await vault.currentRoot();
        assert.notEqual(BigInt(second.request.public_inputs.active_root), restoredRoot);
        const merkle = await treePath(client, primary.noteId);
        const stale = await client('prepare_withdrawal', { snapshot: 'settled-before-second-request', args: {
            mode: 'escape', destination, active_root: merkle.active_root, merkle_siblings: merkle.siblings } });
        const staleInputs = [...coder.decode([WITHDRAWAL_TUPLE], stale.inputs_abi)[0]];
        assert.equal(staleInputs[9], BigInt(DEPOSIT - first.record.charge_gwei));
        assert.equal(staleInputs[11], BigInt(second.request.public_inputs.request_nullifier));
        const balance = address => rpc(rpcUrl, 'eth_getBalance', [address, 'latest']).then(BigInt);
        const balances = { vault: await balance(vaultAddress), destination: await balance(destination), treasury: await balance(treasury) };
        const initiated = await (await vault.initiateEscapeWithdrawal(staleInputs, stale.proof_hex, stale.siblings)).wait();
        await save('escape-initiation-receipt.json', initiated);
        const initiationBlock = await rpc(rpcUrl, 'eth_getBlockByNumber', [`0x${initiated.blockNumber.toString(16)}`, false]);
        const pending = await vault.pendingWithdrawals(primary.noteId);
        assert.equal(pending[0], true);
        assert.equal(pending[5] - BigInt(initiationBlock.timestamp), 86400n);
        await assert.rejects(vault.finalizeEscapeWithdrawal.staticCall(primary.noteId), 'unchallenged escape must still wait 24 hours');
        await rpc(rpcUrl, 'anvil_mine', ['0x2']);
        await synchronizedTree();
        console.log('Real stale-state escape initiated; starting the challenger while its indexer view is withheld.');
        // Every eth_sendTransaction of the daemon, with its fees and outcome.
        const challengeSends = [];
        const simulated = new Set();
        const challengerRpc = await serve(async (req, res) => {
            const call = await body(req);
            let send;
            if (call.method === 'eth_sendTransaction') {
                try {
                    const tx = call.params[0];
                    send = { tx, fees: challengeFees(tx, CHALLENGE_MAX_FEE_PER_GAS) };
                    assert.equal(tx.from.toLowerCase(), challengerAccount.toLowerCase());
                    assert.equal(tx.to.toLowerCase(), vaultAddress.toLowerCase());
                    assert.equal(vault.interface.parseTransaction(tx).name, 'challengeEscapeWithdrawal');
                    challengeSends.push(send);
                } catch (error) {
                    fatal ??= error;
                    throw error;
                }
            }
            if (call.method === 'eth_call') simulated.add(call.params[0].data?.toLowerCase());
            const reply = await proxyJsonRpc(rpcUrl, call);
            if (send) Object.assign(send, reply.error ? { error: reply.error } : { hash: reply.result });
            respond(res, 200, reply);
        });
        // The challenger reads the actual indexer through a gate that first
        // answers with the indexer's own unavailable response: the daemon must
        // keep the obligation and challenge once the indexer recovers.
        const indexerGate = { open: false, withheld: 0 };
        const challengerIndexerUrl = await serve(async (req, res) => {
            assert.equal(req.method, 'GET');
            if (!indexerGate.open) {
                indexerGate.withheld++;
                res.writeHead(503, { 'content-type': 'application/json', 'retry-after': '5' });
                return res.end(JSON.stringify(INDEXER_UNAVAILABLE));
            }
            const upstream = await request(`${indexerUrl}${req.url}`);
            respond(res, upstream.status, upstream.value);
        });
        const checkpoint = path.join(runDir, 'challenger.json');
        const statusPort = await freePort();
        const statusUrl = `http://127.0.0.1:${statusPort}`;
        const challenger = launch(path.join(opts.binDir, 'zkapi-challenged'), ['--rpc-url', challengerRpc,
            '--indexer-url', challengerIndexerUrl, '--sender', challengerAccount, '--chain-id', String(CHAIN_ID),
            '--contract-address', vaultAddress, '--from-block', String(deployment.blockNumber), '--confirmations', '2',
            '--db-path', dbPath, '--checkpoint', checkpoint, '--proof-setup-dir', path.join(ROOT, 'protocol/setup/v2'),
            '--poll-interval-ms', '100', '--max-fee-per-gas-wei', String(CHALLENGE_MAX_FEE_PER_GAS),
            '--max-priority-fee-per-gas-wei', String(CHALLENGE_MAX_PRIORITY_FEE_PER_GAS),
            '--priority-fee-per-gas-wei', String(CHALLENGE_PRIORITY_FEE_PER_GAS),
            '--status-listen', `127.0.0.1:${statusPort}`, '--observe-interval-seconds', '1'], 'challenger.log');
        const withheld = await waitFor('challenger reports the withheld indexer for the escaped note', async () => {
            const status = await get(`${statusUrl}/status`);
            const obligation = status.obligations.find(item => item.note_id === primary.noteId);
            return obligation?.blocked_reason === 'indexer_unavailable' && { state: obligation.state,
                evidence: obligation.evidence, blocked_reason: obligation.blocked_reason, indexer_state: status.indexer.state };
        }, 60_000);
        assert.equal(withheld.evidence, 'finalized');
        assert.equal(challengeSends.length, 0, 'no challenge can be built without an indexer path');

        console.log('Reorganizing a confirmed unrelated deposit out of the chain below the indexer checkpoint.');
        const indexerBefore = await get(`${indexerUrl}/health`);
        assert.equal(indexerBefore.status, 'ok');
        assert.equal(indexerBefore.confirmations, INDEXER_CONFIRMATIONS);
        const reorgSnapshot = await synchronizedTree();
        const reorgNoteId = reorgSnapshot.next_note_id;
        const reorgPath = await client('tree_path', { args: { snapshot: reorgSnapshot, note_id: reorgNoteId, require_existing: false } });
        // Any field element works as the commitment of this throwaway note.
        const reorgCommitment = `0x${randomBytes(31).toString('hex').padStart(64, '0')}`;
        const reorgDeposit = await (await vault.deposit(reorgCommitment, EXTRA_DEPOSIT, reorgPath.siblings,
            { value: BigInt(EXTRA_DEPOSIT) * GWEI })).wait();
        await rpc(rpcUrl, 'anvil_mine', [`0x${INDEXER_CONFIRMATIONS.toString(16)}`]);
        const committed = await waitFor('indexer checkpoint commits the deposit at its confirmation depth', async () => {
            const health = await get(`${indexerUrl}/health`);
            return health.confirmed_block >= reorgDeposit.blockNumber && health.confirmed_next_note_id === reorgNoteId + 1 && health;
        });
        const reorgHead = Number(await rpc(rpcUrl, 'eth_blockNumber'));
        const reorgDepth = reorgHead - reorgDeposit.blockNumber + 1;
        assert.ok(reorgDepth > INDEXER_CONFIRMATIONS, 'the reorg must be deeper than the indexer confirmations');
        assert.ok(initiated.blockNumber < reorgDeposit.blockNumber, 'the escape initiation must survive the reorg');
        await rpc(rpcUrl, 'anvil_reorg', [reorgDepth, []]);
        assert.equal(await rpc(rpcUrl, 'eth_getTransactionReceipt', [reorgDeposit.hash]), null);
        assert.equal((await vault.notes(reorgNoteId))[3], 0n, 'the reorganized deposit no longer exists');
        assert.equal((await vault.pendingWithdrawals(primary.noteId))[0], true, 'the escape is still pending');
        const rebuilt = await waitFor('indexer rebuilds after the reorg below its checkpoint', async () => {
            const health = await request(`${indexerUrl}/health`);
            return health.status === 200 && health.value.status === 'ok' && health.value.rebuild_count > indexerBefore.rebuild_count
                && health.value;
        }, 120_000);
        const convergedTree = await synchronizedTree();
        assert.equal(convergedTree.next_note_id, reorgNoteId, 'the indexer dropped the reorganized deposit');
        const indexerReorg = { confirmations: INDEXER_CONFIRMATIONS, reorged_deposit_transaction: reorgDeposit.hash,
            reorged_deposit_block: reorgDeposit.blockNumber, committed_block_before_reorg: committed.confirmed_block,
            reorg_depth: reorgDepth, rebuild_count_before: indexerBefore.rebuild_count, rebuild_count_after: rebuilt.rebuild_count,
            health_after: rebuilt.status, converged_root: convergedTree.root, escape_survived: true };
        await save('indexer-reorg.json', { ...indexerReorg, health_before: indexerBefore, health_committed: committed, health_after: rebuilt });
        // Pause block production so the first bid stays pending, then price
        // it out with a base-fee spike above its max fee. The daemon must bid
        // again on the same nonce with a max fee that covers the new base fee:
        // Anvil drops the priced-out bid from its pool, so this is a fresh
        // send; a node that kept it would receive a replacement instead.
        await rpc(rpcUrl, 'evm_setAutomine', [false]);
        indexerGate.open = true;
        console.log('Indexer rebuilt and converged; releasing it to the challenger with block production paused.');
        const firstBid = await waitFor('daemon challenge broadcast after the indexer recovered',
            async () => challengeSends.find(send => send.hash), 60_000);
        assert.equal(challengeSends.indexOf(firstBid), 0, `refused challenge send: ${JSON.stringify(challengeSends[0]?.error)}`);
        const raisedBaseFee = 20n * GWEI;
        assert.ok(raisedBaseFee > firstBid.fees.maxFeePerGas, 'the raised base fee must exclude the first bid');
        await rpc(rpcUrl, 'anvil_setNextBlockBaseFeePerGas', [`0x${raisedBaseFee.toString(16)}`]);
        await rpc(rpcUrl, 'anvil_mine', ['0x1']);
        assert.equal(await rpc(rpcUrl, 'eth_getTransactionReceipt', [firstBid.hash]), null, 'a bid below the base fee is not mined');
        const firstBidDropped = await rpc(rpcUrl, 'eth_getTransactionByHash', [firstBid.hash]) === null;
        const rebid = await waitFor('daemon bids again on the same nonce above the raised base fee',
            async () => challengeSends.slice(1).find(send => send.hash), 60_000);
        const refusedBeforeBroadcast = challengeSends.slice(1, challengeSends.indexOf(rebid));
        assert.ok(refusedBeforeBroadcast.every(send => send.error), 'only refused sends may precede the new bid');
        assert.equal(rebid.tx.nonce, firstBid.tx.nonce, 'the new bid reuses the challenge nonce');
        assert.equal(rebid.tx.data, firstBid.tx.data, 'the new bid changes only the fees');
        assert.ok(rebid.fees.maxFeePerGas >= raisedBaseFee, 'the new bid covers the raised base fee');
        assert.ok(rebid.fees.maxPriorityFeePerGas >= firstBid.fees.maxPriorityFeePerGas, 'the tip never falls');
        await rpc(rpcUrl, 'anvil_mine', ['0x1']);
        await rpc(rpcUrl, 'evm_setAutomine', [true]);
        const challengeHash = rebid.hash;
        const challengeReceipt = await waitFor('mined challenge', () => rpc(rpcUrl, 'eth_getTransactionReceipt', [challengeHash]));
        assert.equal(await rpc(rpcUrl, 'eth_getTransactionReceipt', [firstBid.hash]), null, 'the priced-out bid never mines');
        assert.equal(challengeReceipt.status, '0x1');
        const transaction = await rpc(rpcUrl, 'eth_getTransactionByHash', [challengeHash]);
        assert.equal(transaction.type, '0x2', 'the challenge is an EIP-1559 transaction');
        const decoded = vault.interface.parseTransaction({ data: transaction.input });
        assert.equal(decoded.name, 'challengeEscapeWithdrawal');
        const publicInputs = second.request.public_inputs;
        const expectedRequest = [publicInputs.protocol_version, publicInputs.chain_id,
            publicInputs.contract_address, publicInputs.active_root, publicInputs.state_signing_key_x,
            publicInputs.state_signing_key_y, publicInputs.request_time, publicInputs.solvency_bound,
            publicInputs.request_nullifier, publicInputs.authorization_tag, publicInputs.anonymous_commitment_x,
            publicInputs.anonymous_commitment_y].map(BigInt);
        assert.deepEqual([...decoded.args[1]].map(BigInt), expectedRequest, 'daemon must preserve every archived public input');
        assert.equal(decoded.args[2].toLowerCase(), `0x${Buffer.from(second.request.proof.proof, 'base64').toString('hex')}`,
            'daemon must preserve the exact archived Groth16 proof bytes');
        assert.deepEqual([...decoded.args[3]], merkle.siblings.map(BigInt), 'daemon must supply the current restoration path');
        const challengeEvents = challengeReceipt.logs.map(log => {
            try { return vault.interface.parseLog(log); } catch { return null; }
        }).filter(event => event?.name === 'EscapeWithdrawalChallenged');
        assert.equal(challengeEvents.length, 1);
        assert.equal(challengeEvents[0].args.noteId, BigInt(primary.noteId));
        assert.equal(challengeEvents[0].args.nullifier, BigInt(publicInputs.request_nullifier));
        assert.equal(challengeEvents[0].args.restoredRoot, restoredRoot);
        assert.equal(simulated.has(transaction.input.toLowerCase()), true, 'daemon simulated exact submitted calldata');
        assert.equal((await vault.notes(primary.noteId))[3], 1n);
        assert.equal((await vault.pendingWithdrawals(primary.noteId))[0], false);
        // A challenge restores the note without burning the nullifier, and
        // marks it so the stale escape can never be replayed.
        assert.equal(await vault.usedNullifiers(publicInputs.request_nullifier), false);
        assert.equal(await vault.challengedNullifiers(publicInputs.request_nullifier), true);
        assert.equal(await vault.currentRoot(), restoredRoot);
        assert.equal(await balance(vaultAddress), balances.vault);
        assert.equal(await balance(destination), balances.destination);
        assert.equal(await balance(treasury), balances.treasury);
        const challengeBlock = await rpc(rpcUrl, 'eth_getBlockByNumber', [challengeReceipt.blockNumber, false]);
        const elapsed = Number(BigInt(challengeBlock.timestamp) - BigInt(initiationBlock.timestamp));
        assert.ok(elapsed >= 0 && elapsed < 86400);
        assert.equal(await vault.challengePeriod(), 86400n);
        const replayPath = await treePath(client, primary.noteId);
        const replay = await vault.initiateEscapeWithdrawal.staticCall(staleInputs, stale.proof_hex, replayPath.siblings)
            .then(() => null, error => error);
        assert.ok(replay, 'the challenged stale escape must not be accepted again');
        assert.equal(revertData(replay)?.slice(0, 10), CHALLENGED_NULLIFIER_ERROR, `stale escape replay: ${replay?.shortMessage ?? replay?.message}`);
        await rpc(rpcUrl, 'anvil_mine', ['0x2']);
        await waitFor('challenge checkpoint retired after real confirmations', async () => {
            const saved = await readJSON(checkpoint);
            return Object.keys(saved.pending).length === 0;
        });
        const challengerStatus = await waitFor('challenger status has no obligations', async () => {
            const status = await get(`${statusUrl}/status`);
            return status.obligations.length === 0 && status;
        });
        assert.notEqual(challengerStatus.status, 'critical', JSON.stringify(challengerStatus.alarms));
        const livez = await request(`${statusUrl}/livez`);
        assert.equal(livez.status, 200);
        const challengerHealth = await request(`${statusUrl}/health`);
        assert.equal(challengerHealth.status, 200, JSON.stringify(challengerHealth.value));
        await save('challenger-status.json', challengerStatus);
        await stop(challenger);
        assert.equal(challengeSends.filter(send => send.hash).length, 2, 'one priced-out bid and one mined bid');
        await save('challenge-receipt.json', challengeReceipt);
        await save('challenge-transaction.json', transaction);
        await synchronizedTree();
        console.log('Challenge restored the note. Closing its latest settled state with ownership-proof clearance.');
        const current = await client('status');
        const closePath = await treePath(client, primary.noteId);
        assert.equal((await get(`${serverUrl}/health`)).clearance_ownership_proof_required, true);
        const proofless = await request(`${serverUrl}/v2/withdraw/clearance`, { method: 'POST',
            value: { withdrawal_nullifier: current.withdrawal_nullifier } });
        assert.equal(proofless.status, 400);
        assert.equal(proofless.value.error_code, 'clearance_ownership_required');
        assert.equal(proofless.value.retriable, false);
        assert.equal((await get(`${serverUrl}/v2/nullifiers/${current.withdrawal_nullifier}`)).nullifier_status, 'unknown',
            'a refused clearance reserves nothing');
        // The ownership proof is an escape-form proof of the same state, to the
        // real destination at the current balance.
        const ownership = await client('prepare_withdrawal', { args: { mode: 'escape', destination,
            active_root: closePath.active_root, merkle_siblings: closePath.siblings } });
        assert.equal(ownership.public_inputs.has_clearance, false);
        assert.equal(BigInt(ownership.public_inputs.withdrawal_nullifier), BigInt(current.withdrawal_nullifier));
        assert.equal(BigInt(ownership.public_inputs.final_balance), BigInt(DEPOSIT - totalCharge));
        const clearance = await request(`${serverUrl}/v2/withdraw/clearance`, { method: 'POST', value: {
            withdrawal_nullifier: current.withdrawal_nullifier,
            ownership_proof: { public_inputs: ownership.public_inputs, proof: ownership.proof } } });
        assert.equal(clearance.status, 200, `clearance rejected: ${clearance.value.error_code ?? clearance.status}`);
        assert.equal((await get(`${serverUrl}/v2/nullifiers/${current.withdrawal_nullifier}`)).nullifier_status, 'clearance_reserved');
        const close = await client('prepare_withdrawal', { args: { mode: 'mutual', destination,
            active_root: closePath.active_root, merkle_siblings: closePath.siblings, clearance: clearance.value } });
        const closeInputs = [...coder.decode([WITHDRAWAL_TUPLE], close.inputs_abi)[0]];
        assert.equal(closeInputs[9], BigInt(DEPOSIT - totalCharge));
        assert.equal(closeInputs[12], true);
        assert.notEqual(closeInputs[11], staleInputs[11]);
        const closeReceipt = await (await vault.mutualClose(closeInputs, close.proof_hex, close.siblings)).wait();
        assert.equal(closeReceipt.status, 1);
        assert.equal((await vault.notes(primary.noteId))[3], 3n);
        assert.equal((await vault.notes(unrelated.noteId))[3], 1n);
        assert.equal(await balance(destination) - balances.destination, BigInt(DEPOSIT - totalCharge) * GWEI);
        assert.equal(await balance(treasury) - balances.treasury, BigInt(totalCharge) * GWEI);
        assert.equal(await balance(vaultAddress), BigInt(EXTRA_DEPOSIT) * GWEI);
        assert.equal(await vault.usedNullifiers(closeInputs[11]), true);
        await synchronizedTree();
        assert.equal(mock.keys.size, 2);
        assert.ok([...mock.keys.values()].every(key => key.deleted && key.calls === 1));

        console.log('Testing failed issuance recovery after escape initiation and finalization on the local chain.');
        const retryClient = wallet('failed-issuance');
        await retryClient('init', { config });
        const retryNote = await deposit(retryClient, DEPOSIT);
        await waitFor('server observes regression deposit root', async () =>
            BigInt((await get(`${serverUrl}/health`)).current_root) === await vault.currentRoot());
        const retryPath = await treePath(retryClient, retryNote.noteId);
        // Prepare the genuine genesis exit before the request journal exists.
        // This models retaining the original wallet state, without inventing a signature.
        const retryEscape = await retryClient('prepare_withdrawal', { args: { mode: 'escape', destination,
            active_root: retryPath.active_root, merkle_siblings: retryPath.siblings } });
        const retryEscapeInputs = [...coder.decode([WITHDRAWAL_TUPLE], retryEscape.inputs_abi)[0]];
        const retryQuote = await get(`${serverUrl}/v2/billing/quote`);
        const retryId = `acceptance-failed-issuance-${randomUUID()}`;
        const failedRequest = await retryClient('prepare_request', { args: {
            payload: JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: retryQuote }),
            active_root: retryPath.active_root, merkle_siblings: retryPath.siblings, client_request_id: retryId,
            request_time: Math.floor(Date.now() / 1000), created_at_ms: Date.now() } });
        const retryNullifier = failedRequest.request.public_inputs.request_nullifier;
        assert.equal(retryEscapeInputs[11], BigInt(retryNullifier), 'request and escape must consume the same genuine state');
        assert.equal(retryEscapeInputs[9], BigInt(DEPOSIT));
        assert.equal(await vault.usedNullifiers(retryNullifier), false);
        const keysBeforeFailure = mock.keys.size;
        mock.failNextCreate();
        const failedAt = Date.now();
        const failedIssue = await request(`${serverUrl}/v2/openrouter/leases`, { method: 'POST', value: failedRequest.request });
        assert.equal(failedIssue.status, 500);
        assert.equal(failedIssue.value.error_code, 'internal_error');
        assert.equal(mock.events.filter(event => event.type === 'create_failed').length, 1,
            'the failure must occur at the mock provider, after request reservation');
        assert.equal(mock.keys.size, keysBeforeFailure);
        const failedRecovery = await get(`${serverUrl}/v2/requests/${retryId}`);
        assert.equal(failedRecovery.nullifier_status, 'reserved');
        assert.equal(failedRecovery.request_response, undefined);
        const attemptsBeforeRetry = mock.events.filter(event => event.type === 'issued' || event.type === 'create_failed').length;
        const retryBalances = { vault: await balance(vaultAddress), destination: await balance(destination), treasury: await balance(treasury) };
        const retryInitiated = await (await vault.initiateEscapeWithdrawal(retryEscapeInputs, retryEscape.proof_hex, retryEscape.siblings)).wait();
        assert.equal(await vault.usedNullifiers(retryNullifier), true);
        assert.equal((await vault.pendingWithdrawals(retryNote.noteId))[0], true);
        async function rejectedSpentRetry() {
            const retried = await request(`${serverUrl}/v2/openrouter/leases`, { method: 'POST', value: failedRequest.request });
            assert.equal(retried.status, 409);
            assert.equal(retried.value.error_code, 'nullifier_used');
            assert.equal(mock.keys.size, keysBeforeFailure, 'spent retry must never create another provider key');
            assert.equal(mock.events.filter(event => event.type === 'issued' || event.type === 'create_failed').length,
                attemptsBeforeRetry, 'spent retry must be rejected before provider creation');
            return { http_status: retried.status, error_code: retried.value.error_code };
        }
        const pendingRetry = await rejectedSpentRetry();
        await assert.rejects(vault.finalizeEscapeWithdrawal.staticCall(retryNote.noteId), 'the honest escape still has its full challenge window');
        // Only this separate regression advances the disposable chain clock.
        // The earlier daemon challenge runs within the unchanged 24-hour window.
        await rpc(rpcUrl, 'evm_increaseTime', [86401]);
        await rpc(rpcUrl, 'anvil_mine', ['0x1']);
        const retryFinalized = await (await vault.finalizeEscapeWithdrawal(retryNote.noteId)).wait();
        assert.equal(retryFinalized.status, 1);
        assert.equal((await vault.notes(retryNote.noteId))[3], 3n);
        assert.equal((await vault.pendingWithdrawals(retryNote.noteId))[0], false);
        assert.equal(await balance(destination) - retryBalances.destination, BigInt(DEPOSIT) * GWEI);
        assert.equal(await balance(treasury), retryBalances.treasury);
        assert.equal(retryBalances.vault - await balance(vaultAddress), BigInt(DEPOSIT) * GWEI);
        assert.equal(await balance(vaultAddress), BigInt(EXTRA_DEPOSIT) * GWEI);
        const finalizedRetry = await rejectedSpentRetry();
        assert.equal((await get(`${serverUrl}/v2/requests/${retryId}`)).nullifier_status, 'reserved');
        // A never-delivered lease settles at zero only after its TTL and grace
        // (wall clock, 301 s here); these checks ran well before that.
        const wallSecondsAfterFailure = (Date.now() - failedAt) / 1000;
        assert.ok(wallSecondsAfterFailure < 300, 'the reserved-lease checks must run before its settlement is due');
        const failedIssuance = { note_id: retryNote.noteId, client_request_id: retryId, request_nullifier: retryNullifier,
            deposit_transaction: retryNote.receipt.hash, initiation_transaction: retryInitiated.hash,
            finalization_transaction: retryFinalized.hash, failed_create_left_reserved_request: true,
            exact_saved_request_replayed: true, rejected_while_pending: pendingRetry, rejected_after_finalization: finalizedRetry,
            provider_create_attempts_before_retry: attemptsBeforeRetry, provider_create_attempts_after_retry: attemptsBeforeRetry,
            additional_provider_keys: mock.keys.size - keysBeforeFailure, user_payout_gwei: DEPOSIT,
            real_escape_proof: true, challenge_period_seconds: 86400, local_time_jump_seconds: 86401,
            wall_seconds_after_failed_create: wallSecondsAfterFailure, lease_ttl_plus_grace_seconds: 301 };
        await save('failed-issuance-regression.json', failedIssuance);
        await save('failed-issuance-request.json', failedRequest.request);
        await save('failed-issuance-escape-initiation-receipt.json', retryInitiated);
        await save('failed-issuance-escape-finalization-receipt.json', retryFinalized);

        console.log('Restarting the API server from its recorded deployment binding while its vault RPC is down.');
        await stop(server);
        const otherVault = await refusedStartWith('other-vault', seedEnv, /is bound to vault .* use a separate database/,
            serverArgs(await freePort(), dbPath, await adapter.getAddress()), false);
        oracleOutage.active = true;
        const restartPort = await freePort();
        const restartUrl = `http://127.0.0.1:${restartPort}`;
        const restarted = launch(serverCommand, serverArgs(restartPort, dbPath), 'server-restart.log', { env: seedEnv });
        await waitFor('restarted server serves without its vault RPC', async () =>
            BigInt((await get(`${restartUrl}/health`)).current_root) === await vault.currentRoot());
        const restartAttestation = await get(`${restartUrl}/v1/attestation`);
        assert.ok(sameKey(restartAttestation.state_signing_key, vaultKeys.state)
            && sameKey(restartAttestation.clearance_signing_key, vaultKeys.clearance));
        const restartLog = () => fs.readFile(path.join(runDir, 'server-restart.log'), 'utf8');
        await waitFor('restart starts from the recorded binding', async () =>
            (await restartLog()).includes('starting from the recorded vault signing-key binding'));
        assert.ok(oracleOutage.refused > 0, 'the restarted server tried its vault RPC during the outage');
        const refusedDuringOutage = oracleOutage.refused;
        oracleOutage.active = false;
        await waitFor('restarted server re-verifies the recorded binding once its RPC returns', async () =>
            (await restartLog()).includes('re-verified the recorded vault signing-key binding'), 90_000);
        await stop(restarted);
        startupKeyBinding.restart_from_recorded_binding = { vault_rpc_down_during_restart: true,
            rpc_calls_refused_during_outage: refusedDuringOutage, served_vault_keys: true, background_reverified: true };
        startupKeyBinding.refused_starts.database_bound_to_another_vault = otherVault;
        const hashes = {};
        for (const file of [fileURLToPath(import.meta.url), path.join(ROOT, 'crates/zkapi-serverd/examples/v2_acceptance_wallet.rs'),
            ...['zkapi', 'zkapi-indexerd', 'zkapi-challenged', 'examples/v2_acceptance_wallet'].map(file => path.join(opts.binDir, file)),
            ...['request.pk', 'request.vk', 'withdrawal.pk', 'withdrawal.vk'].map(file => path.join(ROOT, 'protocol/setup/v2', file))]) {
            hashes[path.relative(ROOT, file)] = createHash('sha256').update(await fs.readFile(file)).digest('hex');
        }
        const gitOutput = args => {
            const result = spawnSync('git', args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
            assert.equal(result.status, 0, `git ${args.join(' ')} failed: ${result.error?.message ?? result.stderr}`);
            return result.stdout;
        };
        const result = { passed: true, timestamp: new Date().toISOString(), elapsed_wall_seconds: (Date.now() - started) / 1000,
            source_commit: gitOutput(['rev-parse', 'HEAD']).trim(),
            source_dirty: gitOutput(['status', '--porcelain']).trim().length > 0,
            tracked_source_diff_sha256: createHash('sha256').update(gitOutput(['diff', '--binary', 'HEAD'])).digest('hex'),
            artifact_sha256: hashes,
            network: { chain_id: CHAIN_ID, kind: 'disposable loopback Anvil', fork: false, public_rpc: false },
            coverage: { wallet: 'production browser wallet Rust APIs; fresh random genesis note',
                proof_system: 'real checked-in Groth16 proving keys and deployed verifier',
                server: 'actual zkapi serverd HTTP routes and SQLite archive, bound to per-run vault keys',
                indexer: `actual zkapi-indexerd at ${INDEXER_CONFIRMATIONS} confirmations, rebuilt after a reorg below its checkpoint`,
                challenger: 'actual zkapi-challenged daemon (EIP-1559 fees, status endpoints)',
                provider: 'loopback mock management and inference HTTP service',
                oracle: 'loopback mock price feed; chain, vault keys, root and live nullifiers checked against actual Anvil',
                external_provider_verified: false, oa_station_verified: false, live_network_verified: false,
                aws_signer_verified: false },
            startup_key_binding: startupKeyBinding,
            deposit: { transaction: primary.receipt.hash, note_id: primary.noteId, amount_gwei: DEPOSIT, genuine_genesis: true },
            settlements, mock_provider_events: mock.events,
            challenge: { transaction: challengeHash, note_id: primary.noteId, challenge_period_seconds: 86400,
                elapsed_chain_seconds: elapsed, proof_from_genuine_settled_state: true, historical_request_root_preserved: true,
                archived_inputs_preserved: true, archived_proof_preserved: true, restoration_path_verified: true,
                challenge_event_verified: true, no_time_jump: true, daemon_simulation_and_submission: true,
                restored_active: true, pending_cleared: true, no_payout: true, confirmations_observed: 2,
                eip1559_fields_only: true,
                fee_caps_wei: { max_fee_per_gas: CHALLENGE_MAX_FEE_PER_GAS, max_priority_fee_per_gas: CHALLENGE_MAX_PRIORITY_FEE_PER_GAS },
                base_fee_spike: { nonce: rebid.tx.nonce, raised_base_fee_wei: raisedBaseFee,
                    first_bid: { transaction: firstBid.hash, ...firstBid.fees }, first_bid_dropped_by_node: firstBidDropped,
                    sends_refused_before_broadcast: refusedBeforeBroadcast.map(send => ({ ...send.fees, error: send.error })),
                    mined_bid: { transaction: rebid.hash, ...rebid.fees }, first_bid_mined: false },
                used_nullifier_cleared: true, challenged_nullifier_marked: true,
                stale_escape_replay_revert: 'ChallengedNullifier()',
                indexer_withheld_before_challenge: { responses: indexerGate.withheld, reported: withheld },
                status_after: { livez: livez.status, health: challengerHealth.status, status: challengerStatus.status,
                    obligations: challengerStatus.obligations.length } },
            indexer_reorg: indexerReorg,
            withdrawal: { transaction: closeReceipt.hash, real_proof: true, signed_clearance: true,
                clearance_ownership_proof_required: true, proofless_clearance_refused: proofless.value.error_code,
                proofless_clearance_reserved_nothing: true, ownership_proof_clearance: 'escape-form proof to the real destination',
                user_payout_gwei: DEPOSIT - totalCharge, treasury_payout_gwei: totalCharge, closed: true },
            failed_issuance_retry: failedIssuance,
            unrelated_note: { note_id: unrelated.noteId, retained_local_balance_gwei: EXTRA_DEPOSIT },
            all_runtime_keys_revoked: true };
        await save('mutual-close-receipt.json', closeReceipt);
        await save('result.json', result);
        // The per-run seeds must not appear in any saved evidence or log.
        const secrets = Object.values(seedEnv).flatMap(seed => [seed, seed.slice(2)]);
        for (const name of await fs.readdir(runDir, { recursive: true })) {
            const file = path.join(runDir, name);
            if (!(await fs.stat(file)).isFile()) continue;
            const content = await fs.readFile(file);
            assert.ok(secrets.every(secret => !content.includes(secret)), `${name} contains an operator seed`);
        }
        console.log(`PASS: deposit → two provider calls → signed settlements → stale escape → indexer reorg rebuild → daemon challenge → ownership-proof clearance → mutual withdrawal; failed issuance cannot mint access after escape.\nEvidence: ${runDir}`);
    } catch (error) {
        await save('failure.json', { passed: false, error: error.message, stack: error.stack });
        console.error(`FAIL: ${error.message}\nEvidence: ${runDir}`);
        process.exitCode = 1;
    } finally {
        provider?.destroy();
        for (const child of [...children]) await stop(child);
        for (const server of servers) {
            server.closeAllConnections();
            await new Promise(resolve => server.close(resolve));
        }
        process.off('SIGINT', onSignal);
        process.off('SIGTERM', onSignal);
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    await main();
}
