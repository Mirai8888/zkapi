import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { createHash } from 'node:crypto';
import {
    CHAIN_ID, INFERENCE_CHARGE, SDK_REQUEST_BOUND, TIMING, challengeFees, drillTiming, gasLedger, localJSON, mockOaOrg, mockProvider,
    proxyAuthorized, proxyJsonRpc, trustedDeployment,
} from './v2-acceptance.mjs';

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
