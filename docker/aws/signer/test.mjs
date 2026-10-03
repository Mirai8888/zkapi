import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { spawn, spawnSync } from 'node:child_process';
import { dirname } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { Transaction, Wallet, keccak256 } from 'ethers';
import {
  ABSOLUTE_FEE_CEILING, ConfigError, GWEI, RpcError, UPSTREAM_TIMEOUT_MS, createSigner, createUpstream,
  parseChainId, parseSignerConfig, vaultInterface,
} from './signer.mjs';
import { createHttpServer } from './server.mjs';

const CHAIN_ID = 11155111n;
const here = dirname(fileURLToPath(import.meta.url));

// Public test key; never used or funded outside these offline tests.
const key = `0x${'1'.padStart(64, '0')}`;
const sender = new Wallet(key).address;
const vault = '0x0000000000000000000000000000000000001234';
const proof = `0x${'00'.repeat(256)}`;
const inputs = [2, CHAIN_ID, vault, 0, 1, 2, 0, 1, 0, 0, 0, 0];
const data = vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, inputs, proof, Array(32).fill(0)]);
const validTx = { from: sender, to: vault, data, gas: '0x7a1200', nonce: '0x4' };
const ONE_ETH = '0xde0b6b3a7640000';
const wei = value => `0x${value.toString(16)}`;
const fees = (maxFee, tip) => ({ maxFeePerGas: wei(maxFee), maxPriorityFeePerGas: wei(tip) });
const configError = message => error => error instanceof ConfigError && error.message === message;

function fixture(overrides = {}, options = {}) {
  const calls = [];
  const answers = {
    eth_chainId: `0x${CHAIN_ID.toString(16)}`,
    eth_call: '0x', eth_estimateGas: '0x6acfc0',
    eth_getBlockByNumber: { number: '0x10', baseFeePerGas: '0x3b9aca00' },
    eth_getBalance: ONE_ETH, eth_getTransactionByHash: null,
    eth_sendRawTransaction: raw => keccak256(raw), eth_blockNumber: '0x1',
    ...overrides,
  };
  // Unexpected methods fail the test, which proves eth_gasPrice is never read.
  const rpc = async (method, params) => {
    calls.push({ method, params });
    assert.ok(Object.hasOwn(answers, method), `Unexpected RPC method ${method}`);
    if (answers[method] instanceof Error) throw answers[method];
    return typeof answers[method] === 'function' ? answers[method](...params) : answers[method];
  };
  const logs = [];
  return { calls, logs, signer: createSigner({ privateKey: key, vault, rpc, chainId: CHAIN_ID, log: line => logs.push(line), ...options }) };
}
const broadcasts = calls => calls.filter(call => call.method === 'eth_sendRawTransaction');

test('signs only the bounded Sepolia challenge as EIP-1559 at the default bid, preserving caller nonce', async () => {
  const { signer, calls } = fixture();
  const hash = await signer.handle('eth_sendTransaction', [validTx]);
  assert.deepEqual(calls.map(c => c.method), ['eth_chainId', 'eth_call', 'eth_estimateGas', 'eth_getBlockByNumber', 'eth_getBalance', 'eth_sendRawTransaction']);
  const raw = calls.at(-1).params[0];
  const signed = Transaction.from(raw);
  assert.equal(hash, keccak256(raw));
  assert.equal(signed.hash, hash);
  assert.equal(signed.type, 2);
  assert.equal(signed.gasPrice, null);
  assert.equal(signed.maxFeePerGas, 10n * GWEI);
  assert.equal(signed.maxPriorityFeePerGas, 1n * GWEI);
  assert.deepEqual(signed.accessList, []);
  assert.equal(signed.from, sender);
  assert.equal(signed.chainId, CHAIN_ID);
  assert.equal(signed.to.toLowerCase(), vault);
  assert.equal(signed.value, 0n);
  assert.equal(signed.nonce, 4);
  assert.equal(signed.data, data);
  assert.equal(signed.gasLimit, 8_000_000n);
  assert.deepEqual(calls[1].params, [{ from: sender.toLowerCase(), to: vault, data, value: '0x0' }, 'latest']);
  assert.deepEqual(calls[3].params, ['latest', false]);
  assert.deepEqual(calls[4].params, [sender.toLowerCase(), 'latest']);
});

test('signs daemon-proposed fees exactly and checks the balance against gas limit x proposed max fee', async () => {
  // The balance covers 8M gas at 3 gwei but not at the 10 gwei cap.
  const { signer, calls } = fixture({ eth_getBalance: wei(8_000_000n * 3n * GWEI) });
  const hash = await signer.handle('eth_sendTransaction', [{ ...validTx, ...fees(3n * GWEI, 2n * GWEI) }]);
  const signed = Transaction.from(calls.at(-1).params[0]);
  assert.equal(signed.hash, hash);
  assert.equal(signed.type, 2);
  assert.equal(signed.maxFeePerGas, 3n * GWEI);
  assert.equal(signed.maxPriorityFeePerGas, 2n * GWEI);
  // Bounds are inclusive: tip == max fee == cap == tip cap, and base fee == max fee.
  for (const [maxFee, tip] of [[10n * GWEI, 10n * GWEI], [GWEI, GWEI]]) {
    const inclusive = fixture();
    await inclusive.signer.handle('eth_sendTransaction', [{ ...validTx, ...fees(maxFee, tip) }]);
    const bid = Transaction.from(inclusive.calls.at(-1).params[0]);
    assert.deepEqual([bid.maxFeePerGas, bid.maxPriorityFeePerGas], [maxFee, tip]);
  }
});

test('rejects unauthorized transaction changes before any RPC or signature', async () => {
  const modifications = [
    { from: vault }, { to: sender }, { to: null }, { value: '0x1' }, { chainId: '0x1' },
    { data: '0xdeadbeef' }, { data: `${data}00` }, { gas: '0xffffffff' }, { gas: '0x0' },
    { nonce: undefined }, { nonce: '0xffffffffffffffff' }, { nonce: '0x04' },
    { gasPrice: '0x1' }, { accessList: [] }, { authorizationList: [] }, { type: '0x2' }, { type: '0x0' }, { input: data },
    { maxFeePerBlobGas: '0x1' }, { blobVersionedHashes: [] }, { blobs: [] },
    { maxFeePerGas: '0x2540be400', maxPriorityFeePerGas: '0x03b9aca00' }, { maxFeePerGas: '0x02540be400', maxPriorityFeePerGas: '0x3b9aca00' },
    { maxFeePerGas: 10_000_000_000, maxPriorityFeePerGas: 1_000_000_000 }, { maxFeePerGas: null, maxPriorityFeePerGas: null },
    { maxFeePerGas: '0x', maxPriorityFeePerGas: '0x1' },
    { data: vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, [2, 1, vault, ...inputs.slice(3)], proof, Array(32).fill(0)]) },
    { data: vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, [2, CHAIN_ID, sender, ...inputs.slice(3)], proof, Array(32).fill(0)]) },
    { data: vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, inputs, '0x00', Array(32).fill(0)]) },
  ];
  for (const modification of modifications) {
    const { signer, calls } = fixture();
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...validTx, ...modification }]), error => error instanceof RpcError && error.code === -32602, JSON.stringify(modification));
    assert.equal(calls.length, 0);
  }
});

test('fee proposals outside 0 < tip <= max fee <= cap and tip <= tip cap are refused before any RPC', async () => {
  const options = { maxFeePerGas: 50n * GWEI, maxPriorityFeePerGas: 5n * GWEI };
  const bounds = { reason: 'fee_out_of_bounds', max_fee_per_gas: wei(50n * GWEI), max_priority_fee_per_gas: wei(5n * GWEI) };
  for (const [proposal, message] of [
    [fees(10n * GWEI, 0n), 'Requested fees are outside the configured bounds'],
    [fees(0n, 0n), 'Requested fees are outside the configured bounds'],
    [fees(2n * GWEI, 3n * GWEI), 'Requested fees are outside the configured bounds'],
    [fees(50n * GWEI + 1n, GWEI), 'Requested fees are outside the configured bounds'],
    [fees(50n * GWEI, 5n * GWEI + 1n), 'Requested fees are outside the configured bounds'],
    [{ maxFeePerGas: wei(10n * GWEI) }, 'maxFeePerGas and maxPriorityFeePerGas must be supplied together'],
    [{ maxPriorityFeePerGas: wei(GWEI) }, 'maxFeePerGas and maxPriorityFeePerGas must be supplied together'],
  ]) {
    const { signer, calls } = fixture({}, options);
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...validTx, ...proposal }]), { code: -32602, message, data: bounds }, JSON.stringify(proposal));
    assert.equal(calls.length, 0);
  }
});

test('upstream wrong chain, failed simulation, base fee above the max fee, missing base fee, low balance and changed estimate never broadcast', async () => {
  const proposed = { ...validTx, ...fees(3n * GWEI, GWEI) };
  for (const [overrides, transaction, expected] of [
    [{ eth_chainId: '0x1' }, validTx, { code: -32000, message: 'Upstream RPC does not match the configured chain', data: { reason: 'upstream_chain_mismatch' } }],
    [{ eth_chainId: '0x01' }, validTx, { code: -32000, message: 'Upstream RPC returned an invalid chain ID', data: { reason: 'upstream_unavailable' } }],
    [{ eth_call: new RpcError(-32000, 'reverted', 'upstream_rejected') }, validTx, { code: -32000, message: 'Challenge simulation failed', data: { reason: 'simulation_failed' } }],
    [{ eth_estimateGas: new RpcError(-32000, 'rate limited', 'upstream_rejected') }, validTx, { code: -32000, message: 'Challenge simulation failed', data: { reason: 'simulation_failed' } }],
    [{ eth_call: new RpcError(-32000, 'down', 'upstream_unavailable') }, validTx, { code: -32000, message: 'down', data: { reason: 'upstream_unavailable' } }],
    [{ eth_estimateGas: '0xffffff' }, validTx, { code: -32602, message: 'Gas limit is below current estimate', data: { reason: 'gas_estimate_exceeds_limit', estimate: '0xffffff' } }],
    [{ eth_estimateGas: '0x' }, validTx, { code: -32000, message: 'Upstream RPC returned an invalid gas estimate', data: { reason: 'upstream_unavailable' } }],
    [{ eth_getBlockByNumber: { number: '0x10', baseFeePerGas: '0x2540be401' } }, validTx, { code: -32003, message: 'Base fee exceeds the transaction max fee per gas', data: { reason: 'base_fee_above_max_fee', base_fee_per_gas: '0x2540be401', max_fee_per_gas: '0x2540be400' } }],
    [{ eth_getBlockByNumber: { number: '0x10', baseFeePerGas: wei(3n * GWEI + 1n) } }, proposed, { code: -32003, message: 'Base fee exceeds the transaction max fee per gas', data: { reason: 'base_fee_above_max_fee', base_fee_per_gas: wei(3n * GWEI + 1n), max_fee_per_gas: wei(3n * GWEI) } }],
    [{ eth_getBlockByNumber: { number: '0x10' } }, validTx, { code: -32000, message: 'Upstream block lacks a base fee', data: { reason: 'base_fee_unavailable' } }],
    [{ eth_getBlockByNumber: null }, validTx, { code: -32000, message: 'Upstream block lacks a base fee', data: { reason: 'base_fee_unavailable' } }],
    [{ eth_getBlockByNumber: { number: '0x10', baseFeePerGas: '0x01' } }, validTx, { code: -32000, message: 'Upstream block lacks a base fee', data: { reason: 'base_fee_unavailable' } }],
    [{ eth_getBalance: '0x0' }, validTx, { code: -32003, message: 'Sender balance cannot cover gas limit times max fee per gas', data: { reason: 'insufficient_balance', balance: '0x0', required_balance: wei(8_000_000n * 10n * GWEI) } }],
    [{ eth_getBalance: wei(8_000_000n * 3n * GWEI - 1n) }, proposed, { code: -32003, message: 'Sender balance cannot cover gas limit times max fee per gas', data: { reason: 'insufficient_balance', balance: wei(8_000_000n * 3n * GWEI - 1n), required_balance: wei(8_000_000n * 3n * GWEI) } }],
    [{ eth_getBalance: '1000' }, validTx, { code: -32000, message: 'Upstream RPC returned an invalid balance', data: { reason: 'upstream_unavailable' } }],
  ]) {
    const { signer, calls } = fixture(overrides);
    await assert.rejects(signer.handle('eth_sendTransaction', [transaction]), expected, JSON.stringify(overrides));
    assert.equal(broadcasts(calls).length, 0);
  }
});

test('every failure is either a definite non-broadcast or broadcast_ambiguous carrying the candidate hash', async () => {
  const methods = ['eth_chainId', 'eth_call', 'eth_estimateGas', 'eth_getBlockByNumber', 'eth_getBalance', 'eth_sendRawTransaction', 'eth_getTransactionByHash'];
  const faults = [
    new RpcError(-32000, 'Upstream RPC request failed', 'upstream_unavailable'),
    new RpcError(-32000, 'Upstream RPC rejected the request', 'upstream_rejected'),
    new Error('unexpected failure'), 'malformed', null, {}, `0x${'cd'.repeat(32)}`,
  ];
  for (const method of methods) {
    for (const fault of faults) {
      const overrides = { [method]: fault };
      if (method === 'eth_getTransactionByHash') overrides.eth_sendRawTransaction = new RpcError(-32000, 'already known', 'upstream_rejected');
      const { signer, calls } = fixture(overrides);
      const outcome = await signer.handle('eth_sendTransaction', [validTx]).then(hash => ({ hash }), error => ({ error }));
      const sent = broadcasts(calls);
      const label = `${method} -> ${fault instanceof Error ? fault.message : JSON.stringify(fault)}`;
      if (outcome.error?.data?.reason === 'broadcast_ambiguous') {
        assert.equal(outcome.error.code, -32000, label);
        assert.equal(sent.length, 1, label);
        assert.equal(outcome.error.data.transaction_hash, keccak256(sent[0].params[0]), label);
        assert.equal(calls.at(-1).method === 'eth_sendRawTransaction' || calls.at(-1).method === 'eth_getTransactionByHash', true, label);
      } else if (outcome.error) {
        assert.equal(sent.length, 0, label);
      } else {
        assert.equal(sent.length, 1, label);
        assert.equal(outcome.hash, keccak256(sent[0].params[0]), label);
      }
    }
  }
});

test('base fee at the max fee still signs; the effective tip shrinks, the bid does not change', async () => {
  const { signer, calls } = fixture({ eth_getBlockByNumber: { number: '0x10', baseFeePerGas: '0x2540be400' } });
  await signer.handle('eth_sendTransaction', [validTx]);
  const signed = Transaction.from(calls.at(-1).params[0]);
  assert.equal(signed.maxFeePerGas, 10n * GWEI);
  assert.equal(signed.maxPriorityFeePerGas, 1n * GWEI);
});

test('daemon replacement on the same nonce changes only the proposed fees', async () => {
  const { signer, calls } = fixture({}, { maxFeePerGas: 50n * GWEI, maxPriorityFeePerGas: 20n * GWEI });
  const first = await signer.handle('eth_sendTransaction', [{ ...validTx, ...fees(4n * GWEI, GWEI) }]);
  const bump = fees(9n * GWEI / 2n, 9n * GWEI / 8n);
  const bumped = await signer.handle('eth_sendTransaction', [{ ...validTx, ...bump }]);
  const raws = broadcasts(calls).map(c => Transaction.from(c.params[0]));
  assert.equal(raws.length, 2);
  assert.notEqual(first, bumped);
  for (const field of ['type', 'nonce', 'to', 'data', 'value', 'chainId', 'gasLimit', 'from', 'accessList']) {
    assert.deepEqual(raws[1][field], raws[0][field], field);
  }
  assert.deepEqual([raws[0].maxFeePerGas, raws[0].maxPriorityFeePerGas], [4n * GWEI, GWEI]);
  assert.deepEqual([raws[1].maxFeePerGas, raws[1].maxPriorityFeePerGas], [9n * GWEI / 2n, 9n * GWEI / 8n]);
  const before = calls.length;
  for (const change of [{ to: sender }, { value: '0x1' }, { data: '0xdeadbeef' }, { gasPrice: '0x1' }, { type: '0x2' }, fees(50n * GWEI + 1n, 2n * GWEI), fees(30n * GWEI, 20n * GWEI + 1n)]) {
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...validTx, ...bump, ...change }]), RpcError, JSON.stringify(change));
  }
  assert.equal(calls.length, before);
});

test('ambiguous sends retain the caller nonce, report the candidate hash, and the retry queue remains usable', async () => {
  const { signer, calls } = fixture({ eth_sendRawTransaction: new RpcError(-32000, 'Unavailable', 'upstream_unavailable') });
  const first = await signer.handle('eth_sendTransaction', [validTx]).catch(error => error);
  const second = await signer.handle('eth_sendTransaction', [validTx]).catch(error => error);
  const sends = broadcasts(calls);
  assert.equal(sends.length, 2);
  assert.equal(sends[0].params[0], sends[1].params[0]);
  const decoded = Transaction.from(sends[1].params[0]);
  assert.equal(decoded.nonce, 4);
  for (const error of [first, second]) {
    assert.ok(error instanceof RpcError);
    assert.equal(error.code, -32000);
    assert.equal(error.message, 'Transaction broadcast outcome is unknown');
    assert.deepEqual(error.data, { reason: 'broadcast_ambiguous', transaction_hash: keccak256(sends[0].params[0]) });
    assert.equal(error.data.transaction_hash, decoded.hash);
  }
  assert.equal(calls.filter(call => call.method === 'eth_getTransactionByHash').length, 2);
});

test('an already-known identical rebroadcast returns the locally computed hash', async () => {
  let known;
  const { signer, calls } = fixture({
    eth_sendRawTransaction: raw => { known = keccak256(raw); throw new RpcError(-32000, 'already known', 'upstream_rejected'); },
    eth_getTransactionByHash: hash => (hash === known ? { hash: known.toUpperCase().replace('0X', '0x'), blockNumber: null } : null),
  });
  assert.equal(await signer.handle('eth_sendTransaction', [validTx]), known);
  assert.equal(calls.at(-1).method, 'eth_getTransactionByHash');
  assert.deepEqual(calls.at(-1).params, [known]);
});

test('an invalid or mismatched upstream transaction hash remains an ambiguous send error', async () => {
  for (const returned of ['0x', `0x${'ab'.repeat(32)}`, null]) {
    const { signer, calls } = fixture({ eth_sendRawTransaction: returned });
    const error = await signer.handle('eth_sendTransaction', [validTx]).catch(failure => failure);
    assert.ok(error instanceof RpcError);
    assert.deepEqual([error.code, error.message, error.data], [-32000, 'Transaction broadcast outcome is unknown',
      { reason: 'broadcast_ambiguous', transaction_hash: keccak256(broadcasts(calls)[0].params[0]) }]);
    assert.equal(calls.at(-1).method, 'eth_sendRawTransaction');
  }
});

test('audit logging can never change the RPC outcome', async () => {
  const unhandled = [];
  const onUnhandled = reason => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    for (const log of [() => { throw new Error('log sink failed'); }, async () => { throw new Error('async log sink failed'); }, () => ({ then() { throw new Error('bad thenable'); } })]) {
      const ok = fixture({}, { log });
      assert.equal(await ok.signer.handle('eth_sendTransaction', [validTx]), keccak256(ok.calls.at(-1).params[0]));
      const lost = fixture({ eth_sendRawTransaction: new RpcError(-32000, 'down', 'upstream_unavailable') }, { log });
      const ambiguous = await lost.signer.handle('eth_sendTransaction', [validTx]).catch(error => error);
      assert.deepEqual(ambiguous.data, { reason: 'broadcast_ambiguous', transaction_hash: keccak256(broadcasts(lost.calls)[0].params[0]) });
      const refused = fixture({ eth_getBalance: '0x0' }, { log });
      await assert.rejects(refused.signer.handle('eth_sendTransaction', [validTx]), { code: -32003, data: { reason: 'insufficient_balance', balance: '0x0', required_balance: wei(8_000_000n * 10n * GWEI) } });
    }
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(unhandled, []);
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});

test('RPC method allowlist excludes generic signing, account management, fee oracles and raw broadcasts', async () => {
  const feeHistory = { oldestBlock: '0xf', baseFeePerGas: ['0x3b9aca00', '0x3b9aca00'], gasUsedRatio: [0.5], reward: [['0x3b9aca00']] };
  const { signer, calls } = fixture({ eth_feeHistory: feeHistory });
  for (const method of ['eth_sendRawTransaction', 'eth_sign', 'personal_sign', 'eth_signTypedData_v4', 'personal_unlockAccount', 'admin_peers', 'debug_traceCall', 'eth_signTransaction', 'eth_accounts', 'eth_gasPrice', 'eth_maxPriorityFeePerGas']) {
    await assert.rejects(signer.handle(method, []), { code: -32601 });
  }
  assert.equal(calls.length, 0);
  assert.equal(await signer.handle('eth_blockNumber', []), '0x1');
  assert.equal(await signer.handle('eth_getBalance', [sender, 'latest']), ONE_ETH);
  assert.deepEqual(await signer.handle('eth_feeHistory', ['0x1', 'latest', [50]]), feeHistory);
  assert.deepEqual(calls.map(c => [c.method, c.params]), [['eth_blockNumber', []], ['eth_getBalance', [sender, 'latest']], ['eth_feeHistory', ['0x1', 'latest', [50]]]]);
});

test('signer status reports policy, base fee, balance coverage and warnings', async () => {
  const healthy = await fixture().signer.handle('zkapi_signerStatus', []);
  assert.deepEqual(healthy, {
    chain_id: '0xaa36a7', sender: sender.toLowerCase(), vault, transaction_type: '0x2', fee_cap_source: 'default',
    max_fee_per_gas: '0x2540be400', priority_fee_per_gas: '0x3b9aca00', max_priority_fee_per_gas: '0x2540be400',
    fee_ceiling: '0x9184e72a000', max_gas: '0xb71b00', required_balance: '0x1aa535d3d0c0000',
    block_number: '0x10', base_fee_per_gas: '0x3b9aca00', balance: ONE_ETH, warnings: [],
  });
  const warnings = async (baseFee, balance = ONE_ETH) => (await fixture({
    eth_getBlockByNumber: { number: '0x11', baseFeePerGas: wei(baseFee) }, eth_getBalance: wei(BigInt(balance)),
  }).signer.handle('zkapi_signerStatus', [])).warnings;
  // Near the cap once baseFee x 1.125 + default tip (1 gwei) exceeds the 10 gwei cap.
  assert.deepEqual(await warnings(8n * GWEI), []);
  assert.deepEqual(await warnings(8n * GWEI + 1n), ['base_fee_near_cap']);
  assert.deepEqual(await warnings(10n * GWEI), ['base_fee_near_cap']);
  assert.deepEqual(await warnings(10n * GWEI + 1n), ['base_fee_above_cap', 'base_fee_near_cap']);
  assert.deepEqual(await warnings(GWEI, 12_000_000n * 10n * GWEI), []);
  assert.deepEqual(await warnings(GWEI, 12_000_000n * 10n * GWEI - 1n), ['balance_below_required']);
  assert.deepEqual(await warnings(10n * GWEI + 1n, 1n), ['base_fee_above_cap', 'base_fee_near_cap', 'balance_below_required']);
  await assert.rejects(fixture().signer.handle('zkapi_signerStatus', [1]), { code: -32602, message: 'Expected no parameters' });
  await assert.rejects(fixture({ eth_chainId: '0x1' }).signer.handle('zkapi_signerStatus', []), { code: -32000, message: 'Upstream RPC does not match the configured chain', data: { reason: 'upstream_chain_mismatch' } });
  await assert.rejects(fixture({ eth_getBlockByNumber: { number: '0x11' } }).signer.handle('zkapi_signerStatus', []), { code: -32000, message: 'Upstream block lacks a base fee', data: { reason: 'base_fee_unavailable' } });
});

test('base-fee and balance reads run in parallel when signing and in status', async () => {
  // Each read resolves only after both were requested; sequential reads time out.
  const gate = () => {
    let arrived = 0;
    let release;
    const both = new Promise(resolve => { release = resolve; });
    return value => async () => {
      if (++arrived === 2) release();
      await Promise.race([both, sleep(2_000, undefined, { ref: false }).then(() => { throw new Error('reads were sequential'); })]);
      return value;
    };
  };
  for (const run of [signer => signer.handle('eth_sendTransaction', [validTx]), signer => signer.handle('zkapi_signerStatus', [])]) {
    const reads = gate();
    const { signer } = fixture({ eth_getBlockByNumber: reads({ number: '0x10', baseFeePerGas: '0x3b9aca00' }), eth_getBalance: reads(ONE_ETH) });
    await run(signer);
  }
});

test('HTTP errors suppress provider details, carry structured refusal reasons, and health reports the fee policy', async t => {
  const secret = 'https://provider.invalid/private-key-material';
  const { signer } = fixture({ eth_blockNumber: new Error(secret) });
  const server = createHttpServer(signer).listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = value => fetch(base, { method: 'POST', body: JSON.stringify(value) }).then(r => r.json());
  const health = await fetch(`${base}/health`).then(r => r.json());
  assert.deepEqual(health, {
    status: 'ok', chain_id: Number(CHAIN_ID), sender: sender.toLowerCase(), vault, transaction_type: '0x2', fee_cap_source: 'default',
    max_fee_per_gas: '0x2540be400', priority_fee_per_gas: '0x3b9aca00', max_priority_fee_per_gas: '0x2540be400',
    fee_ceiling: '0x9184e72a000', max_gas: '0xb71b00', required_balance: '0x1aa535d3d0c0000',
  });
  const failed = await post({ jsonrpc: '2.0', id: 8, method: 'eth_blockNumber', params: [] });
  assert.deepEqual(failed, { jsonrpc: '2.0', id: 8, error: { code: -32603, message: 'Signer request failed' } });
  assert.ok(!JSON.stringify(failed).includes(secret));
  assert.equal((await post([])).error.code, -32600);
  assert.equal((await post({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: {} })).error.code, -32602);
  const outOfBounds = await post({ jsonrpc: '2.0', id: 3, method: 'eth_sendTransaction', params: [{ ...validTx, ...fees(10n * GWEI + 1n, GWEI) }] });
  assert.deepEqual(outOfBounds, { jsonrpc: '2.0', id: 3, error: { code: -32602, message: 'Requested fees are outside the configured bounds', data: { reason: 'fee_out_of_bounds', max_fee_per_gas: '0x2540be400', max_priority_fee_per_gas: '0x2540be400' } } });
  const spiking = createHttpServer(fixture({ eth_getBlockByNumber: { number: '0x10', baseFeePerGas: '0x2540be401' } }).signer).listen(0, '127.0.0.1');
  await once(spiking, 'listening');
  t.after(() => spiking.close());
  const refused = await fetch(`http://127.0.0.1:${spiking.address().port}`, { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'eth_sendTransaction', params: [validTx] }) }).then(r => r.json());
  assert.deepEqual(refused, { jsonrpc: '2.0', id: 2, error: { code: -32003, message: 'Base fee exceeds the transaction max fee per gas', data: { reason: 'base_fee_above_max_fee', base_fee_per_gas: '0x2540be401', max_fee_per_gas: '0x2540be400' } } });
  const wrong = createHttpServer(fixture({ eth_chainId: '0x1' }).signer).listen(0, '127.0.0.1');
  await once(wrong, 'listening');
  t.after(() => wrong.close());
  const unavailable = await fetch(`http://127.0.0.1:${wrong.address().port}/health`);
  assert.equal(unavailable.status, 503);
  assert.deepEqual(await unavailable.json(), { status: 'unavailable' });
});

test('upstream enforces encrypted remote transport, bounds every call by a timeout and sanitizes errors', async t => {
  assert.equal(UPSTREAM_TIMEOUT_MS, 8_000);
  assert.throws(() => createUpstream('http://remote.invalid/private-api-key'), configError('Upstream RPC must use HTTPS or loopback HTTP'));
  for (const invalid of [undefined, '', 'not a url private-api-key']) assert.throws(() => createUpstream(invalid), configError('Upstream RPC URL is invalid'));
  const unavailable = { code: -32000, message: 'Upstream RPC request failed', data: { reason: 'upstream_unavailable' } };
  await assert.rejects(createUpstream('http://127.0.0.1:1/private-api-key')('eth_chainId', []), unavailable);
  const sockets = new Set();
  const upstream = createServer(async (request, response) => {
    for await (const _chunk of request) { /* drain */ }
    const route = {
      '/ok': () => response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0xaa36a7' })),
      '/rejected': () => response.end(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code: 3, message: 'execution reverted: private-api-key', data: '0xdead' } })),
      '/http-error': () => { response.statusCode = 500; response.end('private-api-key'); },
      '/no-result': () => response.end(JSON.stringify({ jsonrpc: '2.0', id: 1 })),
      '/not-json': () => response.end('private-api-key'),
      '/hang': () => {},
    }[request.url];
    route();
  }).listen(0, '127.0.0.1');
  upstream.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await once(upstream, 'listening');
  t.after(() => { for (const socket of sockets) socket.destroy(); upstream.close(); });
  const at = (path, options) => createUpstream(`http://127.0.0.1:${upstream.address().port}${path}`, options);
  assert.equal(await at('/ok')('eth_chainId', []), '0xaa36a7');
  for (const path of ['/http-error', '/no-result', '/not-json']) await assert.rejects(at(path)('eth_chainId', []), unavailable, path);
  const rejected = await at('/rejected')('eth_call', []).catch(error => error);
  assert.deepEqual({ code: rejected.code, message: rejected.message, data: rejected.data }, { code: -32000, message: 'Upstream RPC rejected the request', data: { reason: 'upstream_rejected' } });
  const started = Date.now();
  await assert.rejects(at('/hang', { timeoutMs: 200 })('eth_chainId', []), unavailable);
  assert.ok(Date.now() - started < 5_000, 'a hung upstream call is abandoned at its timeout');
});

test('requires an explicit supported chain without a Sepolia fallback', () => {
  for (const value of [undefined, null, '', '01', '0x1', '11155111 ', '137', 1]) assert.throws(() => parseChainId(value), configError('Explicit challenge chain ID must be 1 or 11155111'));
  assert.equal(parseChainId('1'), 1n);
  assert.equal(parseChainId('11155111'), 11155111n);
  for (const chainId of [undefined, 1, '1', 0n, 137n]) assert.throws(() => fixture({}, { chainId }), RpcError);
});

test('Mainnet refuses to start without an explicit fee cap; Sepolia uses a reported default', () => {
  for (const maxFeePerGas of [undefined, null]) {
    assert.throws(() => fixture({ eth_chainId: '0x1' }, { chainId: 1n, maxFeePerGas }), { message: 'Mainnet requires an explicit ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI' });
    const { policy } = fixture({}, { maxFeePerGas }).signer;
    assert.deepEqual([policy.fee_cap_source, policy.max_fee_per_gas], ['default', '0x2540be400']);
  }
  assert.throws(() => fixture({}, { maxGasPrice: 50n * GWEI }), { message: 'Unsupported signer option' });
  assert.equal(fixture({ eth_chainId: '0x1' }, { chainId: 1n, maxFeePerGas: 10n * GWEI }).signer.policy.fee_cap_source, 'explicit');
  const env = { ZKAPI_CHALLENGE_CHAIN_ID: '1', ZKAPI_CHALLENGE_PRIVATE_KEY: key, ZKAPI_CHALLENGE_VAULT: vault, ZKAPI_CHALLENGE_RPC_URL: 'https://rpc.invalid' };
  const { rpcUrl, listenHost, port, ...options } = parseSignerConfig(env);
  assert.deepEqual([rpcUrl, listenHost, port, options.maxFeePerGas], ['https://rpc.invalid', '127.0.0.1', 8547, undefined]);
  assert.throws(() => createSigner({ ...options, rpc: async () => assert.fail('no RPC expected') }), { message: 'Mainnet requires an explicit ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI' });
  assert.equal(parseSignerConfig({ ...env, ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '' }).maxFeePerGas, undefined);
  assert.equal(parseSignerConfig({ ...env, ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '50000000000' }).maxFeePerGas, 50n * GWEI);
  const configured = parseSignerConfig({
    ...env, ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '300000000000', ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI: '2000000000',
    ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI: '20000000000', ZKAPI_CHALLENGE_FEE_CEILING_WEI: '1000000000000',
    ZKAPI_CHALLENGE_MAX_GAS: '9000000', ZKAPI_CHALLENGE_PORT: '65535', ZKAPI_CHALLENGE_LISTEN_HOST: '',
  });
  assert.deepEqual(configured, {
    chainId: 1n, privateKey: key, vault, rpcUrl: 'https://rpc.invalid', listenHost: '127.0.0.1', port: 65535, maxGas: 9_000_000n,
    maxFeePerGas: 300n * GWEI, priorityFeePerGas: 2n * GWEI, maxPriorityFeePerGas: 20n * GWEI, feeCeiling: 1_000n * GWEI,
  });
  for (const legacy of ['50000000000', '']) {
    assert.throws(() => parseSignerConfig({ ...env, ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '50000000000', ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI: legacy }),
      configError('ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI is no longer supported; remove it and set ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI (the EIP-1559 fee cap in wei)'));
  }
  for (const name of ['ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI', 'ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI', 'ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI', 'ZKAPI_CHALLENGE_FEE_CEILING_WEI', 'ZKAPI_CHALLENGE_MAX_GAS', 'ZKAPI_CHALLENGE_PORT']) {
    for (const bad of ['0', '0x10', '1e9', ' 5', '5 ', '-1', '10.5', '+5', '05', '1_000', 'REPLACE_WITH_FEE_CAP_WEI', '9'.repeat(32)]) {
      assert.throws(() => parseSignerConfig({ ...env, [name]: bad }), configError(`${name} must be a positive decimal integer`), `${name}=${bad}`);
    }
  }
  assert.throws(() => parseSignerConfig({ ...env, ZKAPI_CHALLENGE_PORT: '65536' }), configError('ZKAPI_CHALLENGE_PORT must be between 1 and 65535'));
});

test('fee cap, priority fees and the configurable ceiling are mutually bounded', () => {
  const policy = options => fixture({}, options).signer.policy;
  assert.throws(() => policy({ maxFeePerGas: 10_001n * GWEI }), { message: 'Fee cap is invalid or exceeds the fee ceiling' });
  assert.equal(policy({ maxFeePerGas: 20_000n * GWEI, feeCeiling: 20_000n * GWEI }).max_fee_per_gas, wei(20_000n * GWEI));
  assert.equal(policy({ maxFeePerGas: ABSOLUTE_FEE_CEILING, feeCeiling: ABSOLUTE_FEE_CEILING }).fee_ceiling, wei(ABSOLUTE_FEE_CEILING));
  assert.throws(() => policy({ feeCeiling: ABSOLUTE_FEE_CEILING + 1n }), { message: 'Fee ceiling is invalid' });
  for (const feeCeiling of [0n, 10_000, null]) assert.throws(() => policy({ feeCeiling }), { message: 'Fee ceiling is invalid' });
  for (const maxFeePerGas of [0n, -1n, 10, '10000000000']) assert.throws(() => policy({ maxFeePerGas }), { message: 'Fee cap is invalid or exceeds the fee ceiling' });
  for (const maxGas of [0n, 16_777_217n, 1_000, null]) assert.throws(() => policy({ maxGas }), { message: 'Gas limit cap is invalid' });
  // Defaults: tip = min(1 gwei, tip cap); tip cap = min(fee cap, 10 x default tip).
  const tips = options => { const p = policy(options); return [p.priority_fee_per_gas, p.max_priority_fee_per_gas]; };
  assert.deepEqual(tips({ maxFeePerGas: 50n * GWEI }), [wei(GWEI), wei(10n * GWEI)]);
  assert.deepEqual(tips({ maxFeePerGas: 5n * GWEI }), [wei(GWEI), wei(5n * GWEI)]);
  assert.deepEqual(tips({ maxFeePerGas: GWEI / 2n }), [wei(GWEI / 2n), wei(GWEI / 2n)]);
  assert.deepEqual(tips({ maxFeePerGas: 50n * GWEI, priorityFeePerGas: 2n * GWEI }), [wei(2n * GWEI), wei(20n * GWEI)]);
  assert.deepEqual(tips({ maxFeePerGas: 50n * GWEI, maxPriorityFeePerGas: GWEI / 2n }), [wei(GWEI / 2n), wei(GWEI / 2n)]);
  assert.deepEqual(tips({ maxFeePerGas: 50n * GWEI, maxPriorityFeePerGas: 50n * GWEI }), [wei(GWEI), wei(50n * GWEI)]);
  assert.deepEqual(tips({ maxFeePerGas: 50n * GWEI, priorityFeePerGas: null, maxPriorityFeePerGas: null }), [wei(GWEI), wei(10n * GWEI)]);
  for (const maxPriorityFeePerGas of [10n * GWEI + 1n, 0n, 1]) {
    assert.throws(() => policy({ maxFeePerGas: 10n * GWEI, maxPriorityFeePerGas }), { message: 'Priority fee cap is invalid or exceeds the fee cap' });
  }
  for (const options of [{ maxPriorityFeePerGas: 2n * GWEI, priorityFeePerGas: 3n * GWEI }, { priorityFeePerGas: 11n * GWEI }, { priorityFeePerGas: 0n }, { priorityFeePerGas: 1 }]) {
    assert.throws(() => policy({ maxFeePerGas: 10n * GWEI, ...options }), { message: 'Default priority fee is invalid or exceeds the priority fee cap' });
  }
  assert.throws(() => fixture({}, { privateKey: '0x1234' }), { message: 'Signer private key is invalid' });
});

test('Mainnet and Sepolia preserve chain-specific signatures, proof bindings and fee bounds', async () => {
  for (const chainId of [1n, 11155111n]) {
    const other = chainId === 1n ? 11155111n : 1n;
    const chainHex = `0x${chainId.toString(16)}`;
    const selectedData = vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, [2, chainId, vault, ...inputs.slice(3)], proof, Array(32).fill(0)]);
    const transaction = { ...validTx, data: selectedData, chainId: chainHex };
    const options = { chainId, maxFeePerGas: 30n * GWEI };
    const { signer, calls } = fixture({ eth_chainId: chainHex }, options);
    await signer.handle('eth_sendTransaction', [transaction]);
    assert.equal(signer.chainId, chainId);
    const signed = Transaction.from(calls.at(-1).params[0]);
    assert.equal(signed.chainId, chainId);
    assert.equal(signed.type, 2);
    assert.equal(signed.maxFeePerGas, 30n * GWEI);
    const baseline = calls.length;
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...transaction, chainId: `0x${other.toString(16)}` }]), RpcError);
    const wrongData = vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, [2, other, vault, ...inputs.slice(3)], proof, Array(32).fill(0)]);
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...transaction, data: wrongData }]), RpcError);
    await assert.rejects(signer.handle('eth_sendTransaction', [{ ...transaction, ...fees(30n * GWEI + 1n, GWEI) }]), RpcError);
    assert.equal(calls.length, baseline);
    for (const overrides of [{ eth_chainId: `0x${other.toString(16)}` }, { eth_getBlockByNumber: { number: '0x1', baseFeePerGas: wei(30n * GWEI + 1n) } }, { eth_estimateGas: '0xffffff' }]) {
      const denied = fixture({ eth_chainId: chainHex, ...overrides }, options);
      await assert.rejects(denied.signer.handle('eth_sendTransaction', [transaction]), RpcError);
      assert.equal(broadcasts(denied.calls).length, 0);
    }
  }
});

test('Mainnet health advertises only its explicitly configured chain', async t => {
  const { signer } = fixture({ eth_chainId: '0x1' }, { chainId: 1n, maxFeePerGas: 30n * GWEI });
  const server = createHttpServer(signer).listen(0, '127.0.0.1');
  await once(server, 'listening'); t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address().port}/health`).then(r => r.json());
  assert.equal(response.chain_id, 1);
  assert.equal(response.fee_cap_source, 'explicit');
  assert.equal(response.max_fee_per_gas, wei(30n * GWEI));
});

test('server process refuses unsafe fee configuration and prints only the safe reason', () => {
  const base = { PATH: process.env.PATH, ZKAPI_CHALLENGE_PRIVATE_KEY: key, ZKAPI_CHALLENGE_VAULT: vault, ZKAPI_CHALLENGE_RPC_URL: 'http://127.0.0.1:1/private-api-key' };
  for (const [env, reason] of [
    [{ ZKAPI_CHALLENGE_CHAIN_ID: '1' }, 'Mainnet requires an explicit ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI'],
    [{ ZKAPI_CHALLENGE_CHAIN_ID: '1', ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: 'REPLACE_WITH_FEE_CAP_WEI' }, 'ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI must be a positive decimal integer'],
    [{ ZKAPI_CHALLENGE_CHAIN_ID: '11155111', ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI: '50000000000' }, 'ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI is no longer supported'],
    [{ ZKAPI_CHALLENGE_CHAIN_ID: '11155111' }, 'Upstream RPC request failed (upstream_unavailable)'],
  ]) {
    const result = spawnSync(process.execPath, ['server.mjs'], { cwd: here, encoding: 'utf8', timeout: 30_000, env: { ...base, ...env } });
    assert.equal(result.status, 1, reason);
    assert.ok(result.stderr.startsWith(`Challenge signer startup failed: ${reason}`), result.stderr);
    for (const secret of [key.slice(2), 'private-api-key']) assert.ok(!result.stderr.includes(secret) && !result.stdout.includes(secret));
  }
});

test('server process starts from strict configuration and prints its fee policy without key material', async t => {
  const upstream = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    const { id, method } = JSON.parse(body);
    const results = { eth_chainId: '0xaa36a7', eth_getBlockByNumber: { number: '0x10', baseFeePerGas: wei(9n * GWEI) }, eth_getBalance: '0x1' };
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(Object.hasOwn(results, method) ? { jsonrpc: '2.0', id, result: results[method] } : { jsonrpc: '2.0', id, error: { code: -32601, message: 'not found' } }));
  }).listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  t.after(() => upstream.close());
  const probe = createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: here, stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH, ZKAPI_CHALLENGE_CHAIN_ID: '11155111', ZKAPI_CHALLENGE_PRIVATE_KEY: key, ZKAPI_CHALLENGE_VAULT: vault,
      ZKAPI_CHALLENGE_RPC_URL: `http://127.0.0.1:${upstream.address().port}/private-api-key`, ZKAPI_CHALLENGE_PORT: String(port),
      ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: '10000000000', ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI: '',
    },
  });
  t.after(() => child.kill());
  let stdout = '';
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  const line = await new Promise((resolve, reject) => {
    child.stdout.on('data', chunk => { stdout += chunk; if (stdout.includes('\n')) resolve(JSON.parse(stdout.split('\n')[0])); });
    child.on('exit', code => reject(new Error(`signer exited with ${code}: ${stderr}`)));
  });
  assert.deepEqual(line, {
    status: 'listening', chain_id: 11155111, sender: sender.toLowerCase(), vault, fee_model: 'eip1559', fee_cap_source: 'explicit',
    max_fee_per_gas_wei: '10000000000', priority_fee_per_gas_wei: '1000000000', max_priority_fee_per_gas_wei: '10000000000',
    fee_ceiling_wei: '10000000000000', max_gas: '12000000', required_balance_wei: '120000000000000000', balance_wei: '1',
    base_fee_per_gas_wei: '9000000000', warnings: ['base_fee_near_cap', 'balance_below_required'],
  });
  const health = await fetch(`http://127.0.0.1:${port}/health`).then(r => r.json());
  assert.equal(health.status, 'ok');
  assert.equal(health.max_fee_per_gas, wei(10n * GWEI));
  for (const secret of [key.slice(2), 'private-api-key']) assert.ok(!stdout.includes(secret) && !stderr.includes(secret));
});

test('refusals and signatures are logged once per transition without provider details', async () => {
  let baseFee = '0x2540be401';
  const { signer, logs } = fixture({ eth_getBlockByNumber: () => ({ number: '0x10', baseFeePerGas: baseFee }) });
  await assert.rejects(signer.handle('eth_sendTransaction', [validTx]));
  await assert.rejects(signer.handle('eth_sendTransaction', [validTx]));
  assert.deepEqual(logs, [{ event: 'challenge_refused', nonce: 4, code: -32003, reason: 'base_fee_above_max_fee', message: 'Base fee exceeds the transaction max fee per gas', base_fee_per_gas_wei: '10000000001', max_fee_per_gas_wei: '10000000000' }]);
  await assert.rejects(signer.handle('eth_sendTransaction', [{ ...validTx, ...fees(GWEI, 2n * GWEI) }]));
  await assert.rejects(signer.handle('eth_sendTransaction', [{ ...validTx, to: sender }]));
  assert.deepEqual(logs.slice(1), [
    { event: 'challenge_refused', nonce: 4, code: -32602, reason: 'fee_out_of_bounds', message: 'Requested fees are outside the configured bounds', max_fee_per_gas_wei: '10000000000', max_priority_fee_per_gas_wei: '10000000000' },
    { event: 'challenge_refused', nonce: 4, code: -32602, reason: 'invalid_request', message: 'Destination is not authorized' },
  ]);
  baseFee = '0x3b9aca00';
  const hash = await signer.handle('eth_sendTransaction', [validTx]);
  await signer.handle('eth_sendTransaction', [validTx]);
  assert.equal(logs.length, 4);
  assert.deepEqual(logs[3], { event: 'challenge_signed', nonce: 4, transaction_hash: hash, max_fee_per_gas_wei: '10000000000', max_priority_fee_per_gas_wei: '1000000000' });
  baseFee = '0x2540be401';
  await assert.rejects(signer.handle('eth_sendTransaction', [validTx]));
  assert.equal(logs.length, 5, 'a refusal after a signature is a new transition');
  const lost = fixture({ eth_sendRawTransaction: new RpcError(-32000, 'https://provider.invalid/private-api-key', 'upstream_unavailable') });
  await assert.rejects(lost.signer.handle('eth_sendTransaction', [validTx]));
  assert.deepEqual(lost.logs, [{ event: 'challenge_refused', nonce: 4, code: -32000, reason: 'broadcast_ambiguous', message: 'Transaction broadcast outcome is unknown', transaction_hash: keccak256(broadcasts(lost.calls)[0].params[0]) }]);
  const text = JSON.stringify([...logs, ...lost.logs]);
  for (const secret of [key.slice(2), 'private-api-key', broadcasts(lost.calls)[0].params[0].slice(2, 66), data.slice(2, 10)]) assert.ok(!text.includes(secret));
});
