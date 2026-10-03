import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

// Exercise the real launcher with the documented environment and harmless
// executables. This catches shell startup failures without RPCs or credentials.
// Each fake binary prints its arguments, one per line, on stdout and reports
// on stderr the settings it received through its environment.
const REPORTED_ENV = [
    'ZKAPI_STATE_SEED',
    'ZKAPI_CLEAR_SEED',
    'ZKAPI_ALLOW_LEGACY_CLEARANCE',
    'ZKAPI_LEGACY_CLEARANCE_MAX_PER_MINUTE',
    'ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS',
    'ZKAPI_CHALLENGE_RPC_URL',
    'ZKAPI_CHALLENGE_SENDER',
    'ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI',
    'ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI',
    'ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI',
];

const BASE_ENV = {
    CHAIN_ID: '11155111',
    VAULT_ADDRESS: '0x0000000000000000000000000000000000000001',
    DEPLOY_BLOCK: '1',
    CIRCUIT_ID: 'zkapi-v2-note-bound-v1',
    REQUEST_CHARGE_CAP: '50000',
    ZKAPI_NATIVE_BILLING_RPC_URL: 'https://rpc.example',
    ZKAPI_NATIVE_PRICE_FEED_ADDRESS: '0x0000000000000000000000000000000000000003',
    ZKAPI_STATE_SEED: 'test-state-seed',
    ZKAPI_CLEAR_SEED: 'test-clear-seed',
    RPC_URL: 'https://indexer-rpc.example',
    ZKAPI_CHALLENGE_RPC_URL: 'http://signer:8547',
    ZKAPI_CHALLENGE_SENDER: '0x0000000000000000000000000000000000000002',
    ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '100000000000',
    ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI: '10000000000',
};

async function launch(role, { set = {}, unset = [], exitCode = 0, refusal = '' } = {}) {
    const bin = await mkdtemp(join(tmpdir(), 'zkapi-launcher-'));
    try {
        const fake = [
            '#!/bin/sh',
            `printf '%s\\n' "$@"`,
            `for name in ${REPORTED_ENV.join(' ')}; do`,
            `    if value=$(printenv "$name"); then printf 'env %s=%s\\n' "$name" "$value" >&2; fi`,
            'done',
            refusal ? `printf '%s\\n' '${refusal}' >&2` : '',
            `exit ${exitCode}`,
            '',
        ].join('\n');
        for (const name of ['zkapi', 'zkapi-indexerd', 'zkapi-challenged']) {
            await writeFile(join(bin, name), fake, { mode: 0o755 });
        }
        const env = { PATH: `${bin}:/usr/bin:/bin`, ...BASE_ENV, ...set };
        for (const name of unset) delete env[name];
        const result = spawnSync('/bin/sh', [resolve('docker/aws/run-daemon.sh'), role], {
            env, encoding: 'utf8', timeout: 5000,
        });
        const args = result.stdout ? result.stdout.trimEnd().split('\n') : [];
        const received = {};
        for (const line of result.stderr.split('\n')) {
            const match = /^env ([A-Z0-9_]+)=(.*)$/.exec(line);
            if (match) received[match[1]] = match[2];
        }
        return { ...result, args, received };
    } finally {
        await rm(bin, { recursive: true, force: true });
    }
}

function flag(args, name) {
    const index = args.indexOf(name);
    assert.ok(index >= 0, `missing ${name} in ${args.join(' ')}`);
    return args[index + 1];
}

for (const role of ['server', 'challenger']) {
    for (const override of [null, '/custom/proofs']) {
        test(`${role} launches with ${override ? 'explicit' : 'default'} proof artifacts`, async () => {
            const result = await launch(role, { set: override ? { ZKAPI_PROOF_SETUP_DIR: override } : {} });
            assert.equal(result.status, 0, result.stderr);
            assert.equal(flag(result.args, '--proof-setup-dir'), override || '/srv/zkapi/protocol/setup/v2');
            if (role === 'server') {
                assert.equal(flag(result.args, '--native-billing-rpc-url'), BASE_ENV.ZKAPI_NATIVE_BILLING_RPC_URL);
                assert.equal(flag(result.args, '--native-price-feed-address'), BASE_ENV.ZKAPI_NATIVE_PRICE_FEED_ADDRESS);
            }
            assert.ok(!result.stdout.includes('test-state-seed'));
            assert.ok(!result.stdout.includes('test-clear-seed'));
        });
    }
}

test('server forwards the settlement deadline and native price policy defaults', async () => {
    const result = await launch('server');
    assert.equal(result.status, 0, result.stderr);
    assert.equal(flag(result.args, '--openrouter-settlement-deadline-seconds'), '21600');
    assert.equal(flag(result.args, '--native-price-max-age-seconds'), '4500');
    assert.equal(flag(result.args, '--native-price-feed-decimals'), '8');
    assert.equal(flag(result.args, '--openrouter-lease-ttl-seconds'), '300');
    assert.equal(flag(result.args, '--openrouter-settlement-grace-seconds'), '5');
    assert.equal(flag(result.args, '--indexer-url'), 'http://indexer:3001');
    assert.equal(flag(result.args, '--db-path'), '/data/server.db');
    assert.equal(flag(result.args, '--chain-id'), BASE_ENV.CHAIN_ID);
    assert.equal(flag(result.args, '--contract-address'), BASE_ENV.VAULT_ADDRESS);
    assert.ok(!result.args.includes('--oa-org-url'));
});

test('server forwards explicit settlement and native price overrides', async () => {
    const result = await launch('server', {
        set: {
            ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS: '7200',
            ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS: '3600',
            ZKAPI_NATIVE_PRICE_FEED_DECIMALS: '18',
            LEASE_TTL_SECONDS: '600',
            SETTLEMENT_GRACE_SECONDS: '10',
            OA_ORG_URL: 'https://org.example',
        },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(flag(result.args, '--openrouter-settlement-deadline-seconds'), '7200');
    assert.equal(flag(result.args, '--native-price-max-age-seconds'), '3600');
    assert.equal(flag(result.args, '--native-price-feed-decimals'), '18');
    assert.equal(flag(result.args, '--openrouter-lease-ttl-seconds'), '600');
    assert.equal(flag(result.args, '--openrouter-settlement-grace-seconds'), '10');
    assert.equal(flag(result.args, '--oa-org-url'), 'https://org.example');
});

test('server leaves seed validation to zkapi serverd and keeps seeds out of argv', async () => {
    // The removed shell guard compared strings and missed 0X1, 0x0002 and every
    // other spelling. serverd now refuses development keys by derived public key.
    for (const [state, clear] of [['0x1', '0x2'], ['0X1', '0x0002'], ['0x5eed01', '0x5eed02']]) {
        const result = await launch('server', { set: { ZKAPI_STATE_SEED: state, ZKAPI_CLEAR_SEED: clear } });
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.received.ZKAPI_STATE_SEED, state);
        assert.equal(result.received.ZKAPI_CLEAR_SEED, clear);
        assert.ok(!result.args.includes('--state-seed'));
        assert.ok(!result.args.includes('--clear-seed'));
        assert.ok(!result.args.includes(state) && !result.args.includes(clear));
        assert.ok(!result.stderr.includes('Refusing the development signing seeds'));
    }
});

test('a refusal by zkapi serverd propagates its exit status and message', async () => {
    const refusal = 'refusing to start: invalid signing seeds (ZKAPI_STATE_SEED / ZKAPI_CLEAR_SEED)';
    const result = await launch('server', { exitCode: 3, refusal });
    assert.equal(result.status, 3);
    assert.ok(result.stderr.includes(refusal));
    assert.ok(!result.stderr.includes('Missing required environment variable'));
});

test('server requires both signing seeds and starts nothing without them', async () => {
    for (const name of ['ZKAPI_STATE_SEED', 'ZKAPI_CLEAR_SEED']) {
        for (const options of [{ unset: [name] }, { set: { [name]: '' } }]) {
            const result = await launch('server', options);
            assert.equal(result.status, 1);
            assert.equal(result.stderr.trim(), `Missing required environment variable: ${name}`);
            assert.deepEqual(result.args, []);
        }
    }
});

test('server passes legacy clearance settings only through the environment', async () => {
    const legacyFlags = ['--allow-legacy-clearance', '--legacy-clearance-max-per-minute', '--clearance-root-window-seconds'];
    const defaults = await launch('server');
    assert.equal(defaults.status, 0, defaults.stderr);
    for (const name of legacyFlags) assert.ok(!defaults.args.includes(name), name);
    assert.equal(defaults.received.ZKAPI_ALLOW_LEGACY_CLEARANCE, undefined);

    const settings = {
        ZKAPI_ALLOW_LEGACY_CLEARANCE: 'true',
        ZKAPI_LEGACY_CLEARANCE_MAX_PER_MINUTE: '30',
        ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS: '600',
    };
    const legacy = await launch('server', { set: settings });
    assert.equal(legacy.status, 0, legacy.stderr);
    for (const name of legacyFlags) assert.ok(!legacy.args.includes(name), name);
    for (const [name, value] of Object.entries(settings)) assert.equal(legacy.received[name], value);
});

test('indexer launches with the deployment chain, confirmations and head-age limit', async () => {
    const result = await launch('indexer');
    assert.equal(result.status, 0, result.stderr);
    assert.equal(flag(result.args, '--listen'), '0.0.0.0:3001');
    assert.equal(flag(result.args, '--rpc-url'), BASE_ENV.RPC_URL);
    assert.equal(flag(result.args, '--contract-address'), BASE_ENV.VAULT_ADDRESS);
    assert.equal(flag(result.args, '--from-block'), '1');
    assert.equal(flag(result.args, '--chain-id'), '11155111');
    assert.equal(flag(result.args, '--confirmations'), '12');
    assert.equal(flag(result.args, '--max-head-age-secs'), '180');
    assert.equal(flag(result.args, '--cursor-path'), '/data/indexer.cursor');
    assert.ok(!result.args.includes('--resync'));
});

test('indexer forwards explicit confirmation and head-age overrides', async () => {
    const result = await launch('indexer', { set: { INDEXER_CONFIRMATIONS: '3', INDEXER_MAX_HEAD_AGE_SECS: '0' } });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(flag(result.args, '--confirmations'), '3');
    assert.equal(flag(result.args, '--max-head-age-secs'), '0');
});

test('indexer requires its RPC endpoint', async () => {
    for (const options of [{ unset: ['RPC_URL'] }, { set: { RPC_URL: '' } }]) {
        const result = await launch('indexer', options);
        assert.equal(result.status, 1);
        assert.equal(result.stderr.trim(), 'Missing required environment variable: RPC_URL');
        assert.deepEqual(result.args, []);
    }
});

test('challenger requires its signer RPC, sender and both fee caps', async () => {
    for (const name of [
        'ZKAPI_CHALLENGE_RPC_URL',
        'ZKAPI_CHALLENGE_SENDER',
        'ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI',
        'ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI',
    ]) {
        for (const options of [{ unset: [name] }, { set: { [name]: '' } }]) {
            const result = await launch('challenger', options);
            assert.equal(result.status, 1);
            assert.equal(result.stderr.trim(), `Missing required environment variable: ${name}`);
            assert.deepEqual(result.args, []);
        }
    }
});

test('challenger serves status on loopback and takes its fees from the environment', async () => {
    const result = await launch('challenger', { set: { ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI: '2000000000' } });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(flag(result.args, '--status-listen'), '127.0.0.1:3002');
    assert.equal(flag(result.args, '--indexer-url'), 'http://indexer:3001');
    assert.equal(flag(result.args, '--chain-id'), '11155111');
    assert.equal(flag(result.args, '--contract-address'), BASE_ENV.VAULT_ADDRESS);
    assert.equal(flag(result.args, '--from-block'), '1');
    assert.equal(flag(result.args, '--confirmations'), '2');
    assert.equal(flag(result.args, '--db-path'), '/data/server.db');
    assert.equal(flag(result.args, '--checkpoint'), '/data/challenges.json');
    for (const name of ['--max-fee-per-gas-wei', '--max-priority-fee-per-gas-wei', '--priority-fee-per-gas-wei', '--rpc-url', '--sender']) {
        assert.ok(!result.args.includes(name), name);
    }
    assert.equal(result.received.ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI, '100000000000');
    assert.equal(result.received.ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI, '10000000000');
    assert.equal(result.received.ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI, '2000000000');
    assert.equal(result.received.ZKAPI_CHALLENGE_RPC_URL, 'http://signer:8547');
});

test('unknown roles print the usage and exit 2', async () => {
    const result = await launch('indexer-resync');
    assert.equal(result.status, 2);
    assert.equal(result.stderr.trim(), 'Usage: zkapi-run server|indexer|challenger');
    assert.deepEqual(result.args, []);
});
