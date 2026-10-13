import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { createHash } from 'node:crypto';
import {
    CHAIN_ID, INFERENCE_CHARGE, SDK_REQUEST_BOUND, TIMING, challengeFees, drillTiming, gasLedger, gaslessProfile, localJSON, mockOaOrg,
    mockProvider, proxyAuthorized, proxyJsonRpc, trustedDeployment,
} from './v2-acceptance.mjs';
import { CANONICAL_ENTRY_POINT, ENTRY_POINT_V070_CODEHASH, GAS_POLICY_SCALARS, SENDER_CREATOR, SENDER_CREATOR_V070_CODEHASH,
    accountCreationCode, hexToBytes, keccak256 } from './expected-codehashes.mjs';

test('provider mock accounts only accepted calls against the issued child key', async () => {
    const mock = mockProvider('test-management');
    const server = http.createServer(mock.handler);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const call = (pathname, method, token, body) => localJSON(`${base}${pathname}`, { method, headers: {
            authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        value: body });
    try {
        const issued = await call('/v1/keys', 'POST', 'test-management', {
            name: 'test', limit: 0.001, expires_at: new Date(Date.now() + 60_000).toISOString(), include_byok_in_limit: true,
        });
        assert.equal(issued.status, 200);
        const { key, data: { hash } } = issued.value;
        const prompt = { model: 'local/mock-model', max_tokens: 8, stream: false,
            messages: [{ role: 'user', content: 'Reply with the word OK.' }] };
        assert.equal((await call('/v1/chat/completions', 'POST', 'unissued-key', prompt)).status, 401);
        assert.equal((await call('/v1/chat/completions', 'POST', key, { ...prompt, model: 'wrong-model' })).status, 400);
        assert.equal(mock.keys.get(hash).usage_micro_usd, 0);
        assert.equal((await call('/v1/chat/completions', 'POST', key, prompt)).status, 200);
        assert.equal((await call('/v1/chat/completions', 'POST', key, prompt)).status, 402);
        assert.equal(mock.keys.get(hash).usage_micro_usd, 1000);
        const usage = await call(`/v1/keys/${hash}`, 'GET', 'test-management');
        assert.equal(usage.value.data.usage, 0.001);
        assert.equal(usage.value.data.byok_usage, 0);
        await call(`/v1/keys/${hash}`, 'PATCH', 'test-management', { disabled: true });
        assert.equal((await call('/v1/chat/completions', 'POST', key, prompt)).status, 401);
        await call(`/v1/keys/${hash}`, 'DELETE', 'test-management');
        assert.equal((await call('/v1/chat/completions', 'POST', key, prompt)).status, 401);
        assert.equal(mock.keys.get(hash).calls, 1);
        assert.equal(mock.keys.get(hash).usage_micro_usd, 1000);
    } finally {
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
    }
});

test('loopback transport ignores inherited proxy environment and rejects public URLs', async () => {
    let direct = 0;
    let proxied = 0;
    const target = http.createServer((req, res) => { direct++; res.end('{"direct":true}'); });
    const proxy = http.createServer((req, res) => { proxied++; res.end('{"direct":false}'); });
    await Promise.all([target, proxy].map(server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve))));
    try {
        const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
        const targetUrl = `http://127.0.0.1:${target.address().port}`;
        const script = `import { localJSON } from ${JSON.stringify(new URL('./v2-acceptance.mjs', import.meta.url).href)};
            const result = await localJSON(${JSON.stringify(targetUrl)});
            if (result.value.direct !== true) process.exitCode = 1;`;
        const child = spawn(process.execPath, ['--input-type=module', '-e', script], { env: {
            PATH: process.env.PATH, NODE_USE_ENV_PROXY: '1', HTTP_PROXY: proxyUrl,
            HTTPS_PROXY: proxyUrl, ALL_PROXY: proxyUrl, NO_PROXY: '',
        }, stdio: 'ignore' });
        const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
        assert.equal(code, 0);
        assert.equal(direct, 1);
        assert.equal(proxied, 0);
        await assert.rejects(localJSON('https://example.invalid/'), /loopback HTTP/);
        await assert.rejects(localJSON('http://192.0.2.1/'), /never calls public/);
    } finally {
        for (const server of [target, proxy]) {
            server.closeAllConnections();
            await new Promise(resolve => server.close(resolve));
        }
    }
});

test('provider mock fails one creation before creating any key, then recovers', async () => {
    const mock = mockProvider('test-management');
    const server = http.createServer(mock.handler);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const create = () => localJSON(`${base}/v1/keys`, { method: 'POST',
        headers: { authorization: 'Bearer test-management' }, value: {
            name: 'failure-regression', limit: 0.001, expires_at: new Date(Date.now() + 60_000).toISOString(),
            include_byok_in_limit: true,
        } });
    try {
        mock.failNextCreate();
        assert.equal((await create()).status, 503);
        assert.equal(mock.keys.size, 0);
        assert.deepEqual(mock.events, [{ type: 'create_failed', name: 'failure-regression' }]);
        assert.equal((await create()).status, 200);
        assert.equal(mock.keys.size, 1);
        assert.deepEqual(mock.events.map(event => event.type), ['create_failed', 'issued']);
    } finally {
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
    }
});

test('challenge transactions admit only bounded EIP-1559 fees', () => {
    const cap = 100_000_000_000n;
    const tx = { from: '0x70997970c51812dc3a010c7d01b50e0d17dc79c8', to: '0x5fbdb2315678afecb367f032d93f642f64180aa3',
        data: '0x1234', gas: '0x72f840', nonce: '0x0', maxFeePerGas: '0xee6b2800', maxPriorityFeePerGas: '0x77359400' };
    assert.deepEqual(challengeFees(tx, cap), { maxFeePerGas: 4_000_000_000n, maxPriorityFeePerGas: 2_000_000_000n });
    assert.deepEqual(challengeFees({ ...tx, maxFeePerGas: '0x174876e800', maxPriorityFeePerGas: '0x174876e800' }, cap),
        { maxFeePerGas: cap, maxPriorityFeePerGas: cap });
    for (const extra of [{ gasPrice: '0x1' }, { type: '0x2' }, { value: '0x0' }, { chainId: '0x7a69' }, { accessList: [] }]) {
        assert.throws(() => challengeFees({ ...tx, ...extra }, cap), /EIP-1559 send fields/, JSON.stringify(extra));
    }
    for (const field of ['maxFeePerGas', 'maxPriorityFeePerGas', 'nonce']) {
        const missing = { ...tx };
        delete missing[field];
        assert.throws(() => challengeFees(missing, cap), /EIP-1559 send fields/, field);
    }
    for (const [field, value] of [['nonce', '0x00'], ['gas', '0X72F840'], ['maxFeePerGas', '4000000000']]) {
        assert.throws(() => challengeFees({ ...tx, [field]: value }, cap), /canonical hex quantity/, `${field}=${value}`);
    }
    assert.throws(() => challengeFees({ ...tx, maxPriorityFeePerGas: '0x0' }, cap), /0 < maxPriorityFeePerGas/);
    assert.throws(() => challengeFees({ ...tx, maxPriorityFeePerGas: '0xee6b2801' }, cap), /0 < maxPriorityFeePerGas/);
    assert.throws(() => challengeFees({ ...tx, maxFeePerGas: '0x174876e801' }, cap), /0 < maxPriorityFeePerGas/);
});

test('challenger RPC proxy relays upstream errors with their revert data', async () => {
    const calls = [];
    const upstream = http.createServer(async (req, res) => {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const call = JSON.parse(Buffer.concat(chunks).toString());
        calls.push(call);
        const reply = call.method === 'eth_call'
            ? { error: { code: 3, message: 'execution reverted', data: '0x607447de' } }
            : call.method === 'eth_estimateGas' ? { error: { code: -32000, message: 'gas required exceeds allowance' } }
                : { result: '0x7a69' };
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: call.id, ...reply }));
    });
    await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${upstream.address().port}`;
    try {
        assert.deepEqual(await proxyJsonRpc(url, { id: 7, method: 'eth_call', params: [{ to: '0x1', data: '0x' }, 'latest'] }),
            { jsonrpc: '2.0', id: 7, error: { code: 3, message: 'execution reverted', data: '0x607447de' } });
        assert.deepEqual(await proxyJsonRpc(url, { id: 8, method: 'eth_estimateGas', params: [] }),
            { jsonrpc: '2.0', id: 8, error: { code: -32000, message: 'gas required exceeds allowance' } });
        assert.deepEqual(await proxyJsonRpc(url, { id: 9, method: 'eth_chainId' }), { jsonrpc: '2.0', id: 9, result: '0x7a69' });
        assert.deepEqual(calls.map(call => [call.id, call.method, call.params]),
            [[7, 'eth_call', [{ to: '0x1', data: '0x' }, 'latest']], [8, 'eth_estimateGas', []], [9, 'eth_chainId', []]]);
    } finally {
        upstream.closeAllConnections();
        await new Promise(resolve => upstream.close(resolve));
    }
});

test('drill timing passes serverd\'s and zkapi-challenged\'s startup checks, and a shorter period would not', () => {
    const timing = drillTiming();
    assert.equal(timing.ok, true, JSON.stringify(timing));
    assert.equal(timing.settlement_window_seconds, TIMING.leaseTtl + TIMING.settlementGrace + TIMING.settlementDeadline);
    assert.equal(TIMING.leaseTtl % 60, 0, 'OA org keys last whole minutes');
    assert.equal(drillTiming({ ...TIMING, challengePeriod: 3_000 }).ok, false, 'G5 needs W + 2 poll + 600 <= cp / 2');
    assert.equal(drillTiming({ ...TIMING, raiseLead: 2_000 }).ok, false, 'the raise must land within the period');
    assert.equal(drillTiming({ ...TIMING, maxPauseDuration: TIMING.challengePeriod }).ok, false, 'maxPauseDuration >= 2 cp');
    assert.equal(drillTiming({ ...TIMING, settlementDeadline: 900 }).ok, false, 'the deadline leaves 900 s of retries');
    // One accepted inference ($0.001 at $2,500/ETH) costs 400 gwei, and an
    // SDK request ($1 limit) fixes a bound of 400,000 gwei.
    assert.equal(INFERENCE_CHARGE, 400);
    assert.equal(SDK_REQUEST_BOUND, 400_000);
});

test('profiles come only from a finalized Deploy.s.sol manifest', () => {
    const finalized = {
        deploymentStatus: 'deployed', deployBlock: 7, chainId: CHAIN_ID, vaultRevision: 3, concessionEscapeVersion: 1,
        vault: '0xAbCd000000000000000000000000000000000001', proofAdapter: '0xAbCd000000000000000000000000000000000002',
        poseidonLibrary: '0xAbCd000000000000000000000000000000000003', requestChargeCap: 50_000, nativeAssetWeiPerUnit: 1_000_000_000,
        billing_asset: 'native_eth', billing_unit: 'gwei', circuitId: 'zkapi-v2-concession-v1', setupId: 'dev', allowDevSetup: true,
        requestVkKeccak256: `0x${'11'.repeat(32)}`, withdrawalVkKeccak256: `0x${'22'.repeat(32)}`,
        vaultRuntimeCodehash: `0x${'33'.repeat(32)}`, adapterRuntimeCodehash: `0x${'44'.repeat(32)}`, poseidonRuntimeCodehash: `0x${'55'.repeat(32)}`,
        challengePeriod: 3_600, noteTtl: 2_592_000, maxPauseDuration: 7_200,
        // Deploy.s.sol writes the key coordinates as decimal strings.
        stateSigningKeyX: '1', stateSigningKeyY: '2', clearanceSigningKeyX: '3', clearanceSigningKeyY: '18446744073709551617',
    };
    const services = { deploymentId: 'acceptance', protocolServerUrl: 'http://127.0.0.1:1', indexerUrl: 'http://127.0.0.1:2',
        rpcUrl: 'http://127.0.0.1:3', priceFeed: '0x0000000000000000000000000000000000001234', settlementWindowSeconds: 962,
        inferenceBase: 'http://127.0.0.1:4/v1', verifierUrl: 'http://127.0.0.1:4/verifier',
        keyHashes: { requestPk: 'a', withdrawalPk: 'b', requestVk: 'c' } };
    const profile = trustedDeployment(finalized, services);
    assert.equal(profile.deployment_status, 'deployed');
    assert.equal(profile.deploy_block, 7);
    assert.equal(profile.contract_address, '0xabcd000000000000000000000000000000000001');
    assert.equal(profile.clearance_signing_key.y, `0x${(2n ** 64n + 1n).toString(16).padStart(64, '0')}`);
    assert.equal(profile.exit_concession, 1);
    assert.equal(profile.vault_revision, 3);
    assert.equal(profile.settlement_window_seconds, 962);
    assert.equal(profile.allow_dev_setup, true);
    for (const status of ['pending', 'simulated']) {
        assert.throws(() => trustedDeployment({ ...finalized, deploymentStatus: status }, services), /finalized manifest/);
    }
    assert.throws(() => trustedDeployment({ ...finalized, deployBlock: undefined }, services), /deployBlock/);
});

test('the companion\'s proxy admits only its own basic credentials', () => {
    const header = `Basic ${Buffer.from('clientd:secret').toString('base64')}`;
    assert.equal(proxyAuthorized(header, 'clientd', 'secret'), true);
    assert.equal(proxyAuthorized(header, 'clientd', 'other'), false);
    assert.equal(proxyAuthorized(undefined, 'clientd', 'secret'), false);
    assert.equal(proxyAuthorized(`Bearer ${Buffer.from('clientd:secret').toString('base64')}`, 'clientd', 'secret'), false);
});

test('the OA org mock reports usage only once its key expired, and the verifier binds the key it is shown', async () => {
    const provider = mockProvider();
    const options = { sharedSecret: 'org-secret', verifierUrl: 'http://127.0.0.1:9/verifier', inferenceBase: 'http://127.0.0.1:9/v1' };
    const oa = mockOaOrg(provider, options);
    const servers = [http.createServer(oa.org), http.createServer(oa.verifier)];
    await Promise.all(servers.map(server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve))));
    const [org, verifier] = servers.map(server => `http://127.0.0.1:${server.address().port}`);
    const post = (url, value, token = 'org-secret') => localJSON(url, { method: 'POST', value, headers: { authorization: `Bearer ${token}` } });
    try {
        assert.equal((await post(`${org}/api/zkapi/request_key`, {}, 'wrong')).status, 401);
        const issued = await post(`${org}/api/zkapi/request_key`, { client_request_id: 'r1', credit_limit: 1, credit_limit_credits: 1_000_000,
            duration_minutes: 1 });
        assert.equal(issued.status, 200);
        assert.equal(issued.value.source, 'oa_org');
        assert.match(issued.value.station_signature, /^[0-9a-f]{128}$/);
        assert.equal(issued.value.verifier_url, options.verifierUrl);
        assert.ok(provider.keys.has(issued.value.key_hash), 'the key works at the provider mock');
        const usage = await post(`${org}/api/zkapi/key_usage`, { client_request_id: 'r1', key_hash: issued.value.key_hash,
            credit_limit_credits: 1_000_000 });
        assert.equal(usage.value.status, 'pending', 'an OA key is never revoked early');
        assert.match(usage.value.station_request_id, /^[0-9a-f]{64}$/);
        const verified = await localJSON(`${verifier}/submit_key`, { method: 'POST', value: { station_id: issued.value.station_id,
            api_key: issued.value.key } });
        assert.deepEqual(verified.value, { status: 'verified', station_id: issued.value.station_id,
            key_hash: createHash('sha256').update(issued.value.key).digest('hex') });
    } finally {
        for (const server of servers) {
            server.closeAllConnections();
            await new Promise(resolve => server.close(resolve));
        }
    }
});

test('the gas ledger summarizes receipts by operation', () => {
    const ledger = gasLedger();
    const receipt = (gas, status = '0x1') => ({ gasUsed: `0x${gas.toString(16)}`, status, transactionHash: '0x01', blockNumber: '0x2' });
    ledger.record('escape', receipt(574_000));
    ledger.record('escape', receipt(575_000));
    ledger.record('superseded', receipt(45_000, '0x0'));
    assert.deepEqual(ledger.summary(), {
        escape: { count: 2, min: 574_000, max: 575_000, total: 1_149_000, mean: 574_500 },
        superseded: { count: 1, min: 45_000, max: 45_000, total: 45_000, mean: 45_000 },
    });
    assert.equal(ledger.entries[2].status, 0);
    assert.throws(() => ledger.record('escape', null), /no receipt/);
});

// scripts/deployment-profile.mjs: every consumer's profile from one finalized
// manifest (migration runbook B2, step 5).
test('deployment profiles: hex keys, a new deployment ID, the vault\'s setup, and clientd\'s own names', async () => {
    const { clientdProfile, deploymentProfile, setupPins } = await import('./deployment-profile.mjs');
    const fs = await import('node:fs');
    const os = await import('node:os');
    const path = await import('node:path');
    const { spawnSync } = await import('node:child_process');
    const root = new URL('..', import.meta.url).pathname;
    const setupDir = path.join(root, 'protocol/setup/v2-concession-dev');
    const setup = JSON.parse(fs.readFileSync(path.join(setupDir, 'manifest.json'), 'utf8'));
    const finalized = {
        deploymentStatus: 'deployed', deployBlock: 9_100_000, chainId: 11_155_111, vaultRevision: 3, concessionEscapeVersion: 1,
        vault: '0xAbCd000000000000000000000000000000000001', proofAdapter: '0xAbCd000000000000000000000000000000000002',
        poseidonLibrary: '0xAbCd000000000000000000000000000000000003', requestChargeCap: 50_000, nativeAssetWeiPerUnit: 1_000_000_000,
        billing_asset: 'native_eth', billing_unit: 'gwei', circuitId: 'zkapi-v2-concession-v1', setupId: 'dev', allowDevSetup: true,
        requestVkKeccak256: setup.vk_keccak256.request, withdrawalVkKeccak256: setup.vk_keccak256.withdrawal,
        vaultRuntimeCodehash: `0x${'33'.repeat(32)}`, adapterRuntimeCodehash: `0x${'44'.repeat(32)}`, poseidonRuntimeCodehash: `0x${'55'.repeat(32)}`,
        challengePeriod: 43_200, noteTtl: 2_592_000, maxPauseDuration: 604_800,
        // Deploy.s.sol writes decimal coordinates; a 77-digit one would not
        // parse as the hex every consumer reads.
        stateSigningKeyX: (2n ** 252n + 7n).toString(), stateSigningKeyY: '2', clearanceSigningKeyX: '3', clearanceSigningKeyY: '4',
    };
    const keyHashes = setupPins(setupDir, finalized);
    assert.equal(keyHashes.requestVk, setup.files['request.vk']);
    assert.throws(() => setupPins(setupDir, { ...finalized, withdrawalVkKeccak256: `0x${'00'.repeat(32)}` }), /withdrawal verifying key/);
    assert.throws(() => setupPins(setupDir, { ...finalized, setupId: 'mpc-1' }), /setup dev/);
    const services = { protocolServerUrl: 'https://api.example', indexerUrl: 'https://indexer.example', rpcUrl: 'https://rpc.example',
        verifierUrl: 'https://verifier.example', priceFeed: '0x694AA1769357215DE4FAC081bf1f309aDC325306', settlementWindowSeconds: 14_705, keyHashes };
    assert.throws(() => deploymentProfile(finalized, services), /new deployment ID/);
    assert.throws(() => deploymentProfile(finalized, { ...services, deploymentId: 'zkapi-native-eth-sepolia-note-bound-v1-fresh-20260930' }),
        /legacy vault/);
    const profile = deploymentProfile(finalized, { ...services, deploymentId: 'zkapi-native-eth-sepolia-concession-v1' });
    assert.equal(profile.state_signing_key.x, `0x${(2n ** 252n + 7n).toString(16).padStart(64, '0')}`);
    assert.match(profile.clearance_signing_key.y, /^0x0{63}4$/);
    assert.equal(profile.deploy_block, 9_100_000);
    const placeholder = JSON.parse(fs.readFileSync(path.join(root, 'zkapi-clientd/internal/zkapi/deployments/sepolia.json'), 'utf8'));
    const clientd = clientdProfile(placeholder, profile, finalized, keyHashes);
    assert.equal(clientd.deployment_status, 'deployed');
    assert.equal(clientd.deployment_id, 'zkapi-native-eth-sepolia-concession-v1');
    assert.equal(clientd.challenge_period_seconds, 43_200);
    assert.equal(clientd.note_ttl_seconds, 2_592_000);
    assert.equal(clientd.max_pause_duration_seconds, 604_800);
    assert.equal(clientd.deployment_evidence.adapter_runtime_keccak256, finalized.adapterRuntimeCodehash);
    assert.equal(clientd.proof_setup.withdrawal_verifying_key_sha256, setup.files['withdrawal.vk']);
    assert.deepEqual(clientd.state_signing_key, profile.state_signing_key);
    assert.ok(!clientd.limitations.some(text => text.startsWith('Placeholder:')));
    // Without the paymaster: gasless null in both shapes, the evidence pins null, and clientd says so.
    assert.equal(profile.gasless, null);
    assert.equal(clientd.gasless, null);
    for (const key of GASLESS_EVIDENCE_KEYS) assert.equal(clientd.deployment_evidence[key], null, key);
    assert.ok(clientd.limitations.includes(
        'The gasless withdrawal paymaster (ERC-4337) is not deployed with this vault; a withdrawal pays its own network fee from the signing address.'));
    assert.throws(() => deploymentProfile(finalized, { ...services, deploymentId: 'zkapi-native-eth-sepolia-concession-v1',
        bundlerUrl: 'https://bundler.example/rpc' }), /without the paymaster/);
    // The command line, in each format.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkapi-profile-'));
    const file = path.join(dir, 'deployment.json');
    fs.writeFileSync(file, JSON.stringify(finalized));
    const run = (...args) => spawnSync(process.execPath, [path.join(root, 'scripts/deployment-profile.mjs'), '--finalized', file,
        '--deployment-id', 'zkapi-native-eth-sepolia-concession-v1', '--protocol-server-url', services.protocolServerUrl,
        '--indexer-url', services.indexerUrl, '--verifier-url', services.verifierUrl, ...args], { encoding: 'utf8' });
    const trusted = run('--rpc-url', services.rpcUrl, '--price-feed', services.priceFeed, '--settlement-window-seconds', '14705');
    assert.equal(trusted.status, 0, trusted.stderr);
    assert.deepEqual(JSON.parse(trusted.stdout).trusted_deployment, { ...profile, rpc_url: services.rpcUrl });
    const clientdOut = run('--format', 'clientd', '--base', path.join(root, 'zkapi-clientd/internal/zkapi/deployments/sepolia.json'));
    assert.equal(clientdOut.status, 0, clientdOut.stderr);
    assert.equal(JSON.parse(clientdOut.stdout).rpc_url, placeholder.rpc_url);
    const sdkOut = run('--format', 'sdk', '--base', path.join(root, 'sdk/assets/config/sepolia.json'));
    assert.equal(sdkOut.status, 0, sdkOut.stderr);
    const sdk = JSON.parse(sdkOut.stdout);
    assert.equal(sdk.trusted_deployment.deployment_status, 'deployed');
    assert.ok(sdk.deployment_manifest_url !== undefined, 'the browser fields stay');
    const pending = path.join(dir, 'pending.json');
    fs.writeFileSync(pending, JSON.stringify({ ...finalized, deploymentStatus: 'pending' }));
    const refused = spawnSync(process.execPath, [path.join(root, 'scripts/deployment-profile.mjs'), '--finalized', pending,
        '--deployment-id', 'zkapi-x', '--protocol-server-url', 'https://a', '--indexer-url', 'https://b', '--verifier-url', 'https://c',
        '--rpc-url', 'https://d', '--price-feed', '0x1', '--settlement-window-seconds', '1'], { encoding: 'utf8' });
    assert.notEqual(refused.status, 0);
    assert.match(refused.stderr, /finalized manifest/);
    fs.rmSync(dir, { recursive: true, force: true });
});

const GASLESS_KEYS = ['entry_point_address', 'entry_point_runtime_codehash', 'sender_creator_address', 'sender_creator_runtime_codehash',
    'withdrawal_paymaster_address', 'withdrawal_paymaster_runtime_codehash', 'withdrawal_account_factory_address',
    'withdrawal_account_factory_runtime_codehash', 'withdrawal_account_implementation_address',
    'withdrawal_account_implementation_runtime_codehash', 'account_creation_code', 'account_creation_code_keccak256', 'bundler_url',
    'gas_policy', 'policy', 'fee_ceilings', 'uneconomic_fraction_percent'];
const GASLESS_EVIDENCE_KEYS = ['entry_point_runtime_keccak256', 'sender_creator_runtime_keccak256', 'paymaster_runtime_keccak256',
    'factory_runtime_keccak256', 'account_implementation_runtime_keccak256'];

// The gasless object (design §4.3) in both profile shapes, from a Sepolia-chain
// manifest deployed with the paymaster.
test('deployment profiles: the gasless object of a paymaster deployment, in the trusted and clientd shapes', async () => {
    const { clientdProfile, deploymentProfile, setupPins } = await import('./deployment-profile.mjs');
    const fs = await import('node:fs');
    const os = await import('node:os');
    const path = await import('node:path');
    const { spawnSync } = await import('node:child_process');
    const root = new URL('..', import.meta.url).pathname;
    const setupDir = path.join(root, 'protocol/setup/v2-concession-dev');
    const setup = JSON.parse(fs.readFileSync(path.join(setupDir, 'manifest.json'), 'utf8'));
    const vectors = JSON.parse(fs.readFileSync(path.join(root, 'protocol/contracts/test/fixtures/transit-vectors.json'), 'utf8'));
    const snake = name => name.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
    const gasPolicy = { callFloor: vectors.gas_policy.call_floor.map(Number), callCap: vectors.gas_policy.call_hard_cap.map(Number) };
    for (const name of GAS_POLICY_SCALARS) gasPolicy[name] = Number(vectors.gas_policy[snake(name)]);
    const implementation = '0xAbCd000000000000000000000000000000000006';
    const creation = accountCreationCode(implementation);
    const finalized = {
        deploymentStatus: 'deployed', deployBlock: 9_100_000, chainId: 11_155_111, vaultRevision: 3, concessionEscapeVersion: 1,
        vault: '0xAbCd000000000000000000000000000000000001', proofAdapter: '0xAbCd000000000000000000000000000000000002',
        poseidonLibrary: '0xAbCd000000000000000000000000000000000003', requestChargeCap: 50_000, nativeAssetWeiPerUnit: 1_000_000_000,
        billing_asset: 'native_eth', billing_unit: 'gwei', circuitId: 'zkapi-v2-concession-v1', setupId: 'dev', allowDevSetup: true,
        requestVkKeccak256: setup.vk_keccak256.request, withdrawalVkKeccak256: setup.vk_keccak256.withdrawal,
        vaultRuntimeCodehash: `0x${'33'.repeat(32)}`, adapterRuntimeCodehash: `0x${'44'.repeat(32)}`, poseidonRuntimeCodehash: `0x${'55'.repeat(32)}`,
        challengePeriod: 43_200, noteTtl: 2_592_000, maxPauseDuration: 604_800,
        stateSigningKeyX: '1', stateSigningKeyY: '2', clearanceSigningKeyX: '3', clearanceSigningKeyY: '4',
        // The gasless block, as Deploy.s.sol writes it (checksummed addresses, wei as decimal strings).
        entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032', entryPointRuntimeCodehash: ENTRY_POINT_V070_CODEHASH,
        senderCreator: '0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C', senderCreatorRuntimeCodehash: SENDER_CREATOR_V070_CODEHASH,
        withdrawalPaymaster: '0xAbCd000000000000000000000000000000000004', withdrawalAccountFactory: '0xAbCd000000000000000000000000000000000005',
        withdrawalAccountImplementation: implementation,
        paymasterRuntimeCodehash: `0x${'66'.repeat(32)}`, factoryRuntimeCodehash: `0x${'77'.repeat(32)}`,
        accountImplementationRuntimeCodehash: `0x${'88'.repeat(32)}`,
        accountCreationCode: creation, accountCreationCodeKeccak256: keccak256(hexToBytes(creation)),
        paymasterOwner: '0xAbCd000000000000000000000000000000000009', paymasterOwnershipTransferPending: false,
        paymasterDeployer: '0xAbCd000000000000000000000000000000000009', paymasterFeeKeeper: `0x${'0'.repeat(40)}`,
        paymasterStakeWei: '100000000000000000', factoryStakeWei: '100000000000000000', paymasterUnstakeDelaySeconds: 86_400,
        paymasterInitialDepositWei: '500000000000000000',
        paymasterPolicy: { maxSponsoredCostWei: '50000000000000000', flatFeeWei: '0', minEscapeNetWei: '10000000000000000', escapesEnabled: false },
        paymasterFeeCeilings: { maxFeeWei: '200000000000', priorityFeeWei: '3000000000' },
        paymasterGasPolicy: gasPolicy,
    };
    const keyHashes = setupPins(setupDir, finalized);
    const services = { deploymentId: 'zkapi-native-eth-sepolia-concession-v1', protocolServerUrl: 'https://api.example',
        indexerUrl: 'https://indexer.example', rpcUrl: 'https://rpc.example', verifierUrl: 'https://verifier.example',
        priceFeed: '0x694AA1769357215DE4FAC081bf1f309aDC325306', settlementWindowSeconds: 14_705, keyHashes };
    const profile = deploymentProfile(finalized, { ...services, bundlerUrl: 'https://bundler.example/rpc' });
    const gasless = profile.gasless;
    assert.deepEqual(Object.keys(gasless), GASLESS_KEYS);
    assert.equal(gasless.entry_point_address, CANONICAL_ENTRY_POINT);
    assert.equal(gasless.sender_creator_address, SENDER_CREATOR);
    assert.equal(gasless.entry_point_runtime_codehash, ENTRY_POINT_V070_CODEHASH);
    assert.equal(gasless.sender_creator_runtime_codehash, SENDER_CREATOR_V070_CODEHASH);
    assert.equal(gasless.withdrawal_paymaster_address, '0xabcd000000000000000000000000000000000004');
    assert.equal(gasless.withdrawal_paymaster_runtime_codehash, finalized.paymasterRuntimeCodehash);
    assert.equal(gasless.withdrawal_account_factory_address, '0xabcd000000000000000000000000000000000005');
    assert.equal(gasless.withdrawal_account_factory_runtime_codehash, finalized.factoryRuntimeCodehash);
    assert.equal(gasless.withdrawal_account_implementation_address, implementation.toLowerCase());
    assert.equal(gasless.withdrawal_account_implementation_runtime_codehash, finalized.accountImplementationRuntimeCodehash);
    assert.equal(gasless.account_creation_code, creation);
    assert.match(gasless.account_creation_code, /^0x[0-9a-f]{148}$/);
    assert.equal(gasless.account_creation_code_keccak256, finalized.accountCreationCodeKeccak256);
    assert.equal(gasless.bundler_url, 'https://bundler.example/rpc');
    const gp = gasless.gas_policy;
    assert.deepEqual(gp.call_floor, gasPolicy.callFloor);
    assert.deepEqual(gp.call_cap, gasPolicy.callCap);
    for (let kind = 0; kind < 4; kind++) {
        assert.ok(gp.call_floor[kind] <= gp.call_default[kind] && gp.call_default[kind] <= gp.call_cap[kind], `call_default[${kind}]`);
    }
    for (const [name, floor, cap] of [['postop_default', 'postop_floor', 'postop_cap'],
        ['verification_default', 'verification_floor', 'verification_cap'],
        ['verification_default_init', 'verification_floor_init', 'verification_cap'],
        ['pm_verification_default', 'pm_verification_floor', 'pm_verification_cap']]) {
        assert.ok(gp[floor] <= gp[name] && gp[name] <= gp[cap], `${name} ${gp[name]} is outside [${gp[floor]}, ${gp[cap]}]`);
    }
    for (const name of GAS_POLICY_SCALARS) assert.equal(gp[snake(name).replace(/post_op/g, 'postop')], gasPolicy[name], name);
    assert.equal(gp.max_attempts, 3);
    assert.deepEqual(gasless.policy, { max_sponsored_cost_wei: '50000000000000000', flat_fee_wei: '0', min_escape_net_wei: '10000000000000000',
        escapes_enabled: false });
    assert.deepEqual(gasless.fee_ceilings, { max_fee_wei: '200000000000', priority_fee_wei: '3000000000' });
    assert.equal(gasless.uneconomic_fraction_percent, 25);
    // bundler_url: null when none is published, https or loopback http only.
    assert.equal(deploymentProfile(finalized, services).gasless.bundler_url, null);
    assert.equal(deploymentProfile(finalized, { ...services, bundlerUrl: 'http://127.0.0.1:4337' }).gasless.bundler_url, 'http://127.0.0.1:4337');
    assert.throws(() => deploymentProfile(finalized, { ...services, bundlerUrl: 'http://bundler.example/rpc' }), /https URL/);
    assert.throws(() => deploymentProfile(finalized, { ...services, bundlerUrl: 'ftp://bundler.example' }), /https URL/);
    // A pin that is missing or malformed fails by name instead of reaching a profile.
    for (const name of ['entryPoint', 'senderCreator', 'withdrawalAccountFactory', 'paymasterRuntimeCodehash', 'factoryRuntimeCodehash',
        'accountImplementationRuntimeCodehash', 'accountCreationCode', 'accountCreationCodeKeccak256']) {
        const missing = { ...finalized };
        delete missing[name];
        assert.throws(() => gaslessProfile(missing), new RegExp(name), `${name} missing`);
        assert.throws(() => gaslessProfile({ ...finalized, [name]: '0x1234' }), new RegExp(name), `${name} malformed`);
    }
    assert.throws(() => gaslessProfile({ ...finalized, accountCreationCode: accountCreationCode(finalized.vault) }), /creation code for the account logic/);
    assert.throws(() => gaslessProfile({ ...finalized, accountCreationCodeKeccak256: `0x${'11'.repeat(32)}` }), /keccak256 of the creation code/);
    // clientd's shape: the same object, and the evidence pins beside the vault's.
    const placeholder = JSON.parse(fs.readFileSync(path.join(root, 'zkapi-clientd/internal/zkapi/deployments/sepolia.json'), 'utf8'));
    const clientd = clientdProfile(placeholder, profile, finalized, keyHashes);
    assert.deepEqual(clientd.gasless, gasless);
    assert.deepEqual(Object.keys(clientd.deployment_evidence),
        ['vault_runtime_keccak256', 'adapter_runtime_keccak256', 'poseidon_runtime_keccak256', ...GASLESS_EVIDENCE_KEYS]);
    assert.deepEqual(clientd.deployment_evidence, {
        vault_runtime_keccak256: finalized.vaultRuntimeCodehash,
        adapter_runtime_keccak256: finalized.adapterRuntimeCodehash,
        poseidon_runtime_keccak256: finalized.poseidonRuntimeCodehash,
        entry_point_runtime_keccak256: ENTRY_POINT_V070_CODEHASH,
        sender_creator_runtime_keccak256: SENDER_CREATOR_V070_CODEHASH,
        paymaster_runtime_keccak256: finalized.paymasterRuntimeCodehash,
        factory_runtime_keccak256: finalized.factoryRuntimeCodehash,
        account_implementation_runtime_keccak256: finalized.accountImplementationRuntimeCodehash,
    });
    assert.ok(!clientd.limitations.some(text => /paymaster .* is not deployed/.test(text)));
    // The command line writes the same objects in the clientd and SDK formats.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkapi-profile-gasless-'));
    const file = path.join(dir, 'deployment.json');
    fs.writeFileSync(file, JSON.stringify(finalized));
    const run = (...args) => spawnSync(process.execPath, [path.join(root, 'scripts/deployment-profile.mjs'), '--finalized', file,
        '--deployment-id', services.deploymentId, '--protocol-server-url', services.protocolServerUrl, '--indexer-url', services.indexerUrl,
        '--verifier-url', services.verifierUrl, '--bundler-url', 'https://bundler.example/rpc', ...args], { encoding: 'utf8' });
    const clientdOut = run('--format', 'clientd', '--base', path.join(root, 'zkapi-clientd/internal/zkapi/deployments/sepolia.json'));
    assert.equal(clientdOut.status, 0, clientdOut.stderr);
    assert.deepEqual(JSON.parse(clientdOut.stdout).gasless, gasless);
    assert.deepEqual(JSON.parse(clientdOut.stdout).deployment_evidence, clientd.deployment_evidence);
    const sdkOut = run('--format', 'sdk', '--base', path.join(root, 'sdk/assets/config/sepolia.json'));
    assert.equal(sdkOut.status, 0, sdkOut.stderr);
    assert.deepEqual(JSON.parse(sdkOut.stdout).trusted_deployment.gasless, gasless);
    fs.rmSync(dir, { recursive: true, force: true });
});
