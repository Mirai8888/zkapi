// Real-node checks of the type-2 signer against a disposable anvil. Skipped when
// anvil is not installed unless ZKAPI_REQUIRE_ANVIL=1, which makes that a failure.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { Transaction, Wallet } from 'ethers';
import { GWEI, createSigner, createUpstream, vaultInterface } from './signer.mjs';

const CHAIN_ID = 11155111n;
const haveAnvil = spawnSync('anvil', ['--version'], { stdio: 'ignore' }).status === 0;
const skip = !haveAnvil && process.env.ZKAPI_REQUIRE_ANVIL !== '1' && 'anvil is not installed (ZKAPI_REQUIRE_ANVIL=1 makes this a failure)';
// Anvil's first default account: a public test key, only ever funded on a disposable anvil.
const key = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const sender = new Wallet(key).address;
const vault = '0x0000000000000000000000000000000000001234';
const data = vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', [0, [2, CHAIN_ID, vault, 0, 1, 2, 0, 1, 0, 0, 0, 0], `0x${'00'.repeat(256)}`, Array(32).fill(0)]);
const GAS = 200_000n;
const wei = value => `0x${value.toString(16)}`;
const fees = (maxFee, tip) => ({ maxFeePerGas: wei(maxFee), maxPriorityFeePerGas: wei(tip) });
const tx = (nonce, extra = {}) => ({ from: sender, to: vault, data, gas: wei(GAS), nonce: wei(BigInt(nonce)), ...extra });

// Port 0 lets the OS choose a free port, which anvil reports on stdout, so
// parallel runs cannot collide; startup is still retried. Automine is off and
// every test mines explicitly, so no receipt is read before its block exists.
async function startAnvil(t) {
  assert.ok(haveAnvil, 'ZKAPI_REQUIRE_ANVIL=1 but anvil is not on PATH');
  for (let attempt = 1; attempt <= 3; attempt++) {
    const child = spawn('anvil', ['--port', '0', '--chain-id', String(CHAIN_ID), '--no-mining'], { stdio: ['ignore', 'pipe', 'ignore'] });
    t.after(() => child.kill());
    const port = await new Promise(resolve => {
      let output = '';
      const timer = setTimeout(() => resolve(null), 20_000);
      const onData = chunk => {
        output += chunk;
        const match = output.match(/Listening on \S+:(\d+)/);
        if (!match) return;
        clearTimeout(timer);
        child.stdout.off('data', onData);
        child.stdout.resume(); // Keep draining anvil's request log.
        resolve(Number(match[1]));
      };
      child.stdout.on('data', onData);
      child.on('exit', () => { clearTimeout(timer); resolve(null); });
    });
    if (port) {
      const rpc = createUpstream(`http://127.0.0.1:${port}`);
      // A STOP contract: every challenge call simulates successfully.
      await rpc('anvil_setCode', [vault, '0x00']);
      return rpc;
    }
    child.kill();
  }
  assert.fail('anvil did not start');
}
const signerFor = (rpc, options) => createSigner({ privateKey: key, vault, rpc, chainId: CHAIN_ID, log: () => {}, ...options });
const nonceOf = async (rpc, tag) => Number(BigInt(await rpc('eth_getTransactionCount', [sender, tag])));
const poolSize = async rpc => Number(BigInt((await rpc('txpool_status', [])).pending));
async function receipt(rpc, hash) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const value = await rpc('eth_getTransactionReceipt', [hash]);
    if (value) return value;
    await sleep(50);
  }
  return assert.fail(`no receipt for ${hash}`);
}
async function mine(rpc, nextBaseFee) {
  if (nextBaseFee !== undefined) await rpc('anvil_setNextBlockBaseFeePerGas', [wei(nextBaseFee)]);
  await rpc('evm_mine', []);
}
const balanceOf = async (rpc, block = 'latest') => BigInt(await rpc('eth_getBalance', [sender, block]));
// Wei per gas actually charged for a mined zero-value transaction. Anvil 1.5.1
// reports receipt.effectiveGasPrice as baseFee + tip even when maxFeePerGas
// binds, so the sender's balance change is the reliable measure.
async function chargedPerGas(rpc, hash, balanceBefore) {
  const mined = await receipt(rpc, hash);
  assert.deepEqual([mined.type, mined.status], ['0x2', '0x1']);
  const charged = balanceBefore - await balanceOf(rpc, mined.blockNumber);
  assert.equal(charged % BigInt(mined.gasUsed), 0n);
  return { perGas: charged / BigInt(mined.gasUsed), block: await rpc('eth_getBlockByNumber', [mined.blockNumber, false]) };
}

test('type-2 challenges are charged min(maxFee, baseFee + tip) per gas, never above the bid', { skip }, async t => {
  const rpc = await startAnvil(t);
  const signer = signerFor(rpc, { maxFeePerGas: 10n * GWEI });
  // No fee fields (a daemon that predates fee proposals): bid the cap with the default tip.
  let before = await balanceOf(rpc);
  const defaultBid = await signer.handle('eth_sendTransaction', [tx(0)]);
  await mine(rpc, 2n * GWEI);
  const first = await chargedPerGas(rpc, defaultBid, before);
  assert.deepEqual([BigInt(first.block.baseFeePerGas), first.perGas], [2n * GWEI, 3n * GWEI]);
  // A proposed bid whose max fee binds pays exactly the max fee, not baseFee + tip.
  before = await balanceOf(rpc);
  const proposed = await signer.handle('eth_sendTransaction', [tx(1, fees(4n * GWEI, 2n * GWEI))]);
  await mine(rpc, 3n * GWEI);
  const second = await chargedPerGas(rpc, proposed, before);
  assert.deepEqual([BigInt(second.block.baseFeePerGas), second.perGas], [3n * GWEI, 4n * GWEI]);
  const mined = await rpc('eth_getTransactionByHash', [proposed]);
  assert.deepEqual([BigInt(mined.maxFeePerGas), BigInt(mined.maxPriorityFeePerGas)], [4n * GWEI, 2n * GWEI]);
  assert.equal(await nonceOf(rpc, 'latest'), 2);
});

test('a base fee above the transaction max fee refuses with exact data and broadcasts nothing', { skip }, async t => {
  const rpc = await startAnvil(t);
  await mine(rpc, 12n * GWEI);
  const capped = signerFor(rpc, { maxFeePerGas: 10n * GWEI });
  const raised = signerFor(rpc, { maxFeePerGas: 30n * GWEI });
  const refusal = maxFee => ({
    code: -32003, message: 'Base fee exceeds the transaction max fee per gas',
    data: { reason: 'base_fee_above_max_fee', base_fee_per_gas: wei(12n * GWEI), max_fee_per_gas: wei(maxFee) },
  });
  await assert.rejects(capped.handle('eth_sendTransaction', [tx(0)]), refusal(10n * GWEI));
  await assert.rejects(raised.handle('eth_sendTransaction', [tx(0, fees(11n * GWEI, GWEI))]), refusal(11n * GWEI));
  assert.equal(await nonceOf(rpc, 'pending'), 0);
  assert.equal(await poolSize(rpc), 0, 'nothing was broadcast');
  assert.deepEqual((await capped.handle('zkapi_signerStatus', [])).warnings, ['base_fee_above_cap', 'base_fee_near_cap']);
  // A bid above the base fee lands, paying baseFee + tip and never more than its max fee.
  const before = await balanceOf(rpc);
  const landed = await raised.handle('eth_sendTransaction', [tx(0, fees(15n * GWEI, GWEI))]);
  await mine(rpc);
  const { perGas, block } = await chargedPerGas(rpc, landed, before);
  assert.equal(perGas, BigInt(block.baseFeePerGas) + GWEI);
  assert.ok(perGas > 10n * GWEI && perGas <= 15n * GWEI, 'paid more than the old cap, never more than the bid');
});

test('identical rebroadcast is idempotent; a tip-only bump is rejected; raising both fees replaces on the same nonce', { skip }, async t => {
  const rpc = await startAnvil(t);
  const signer = signerFor(rpc, { maxFeePerGas: 20n * GWEI, maxPriorityFeePerGas: 5n * GWEI });
  const original = await signer.handle('eth_sendTransaction', [tx(0, fees(4n * GWEI, GWEI))]);
  assert.equal(await signer.handle('eth_sendTransaction', [tx(0, fees(4n * GWEI, GWEI))]), original, 'an identical rebroadcast returns the same hash');
  assert.equal(await poolSize(rpc), 1);
  const tipOnly = await signer.handle('eth_sendTransaction', [tx(0, fees(4n * GWEI, 9n * GWEI / 8n))]).catch(error => error);
  assert.equal(tipOnly.code, -32000);
  assert.equal(tipOnly.data.reason, 'broadcast_ambiguous');
  assert.match(tipOnly.data.transaction_hash, /^0x[0-9a-f]{64}$/);
  assert.notEqual(tipOnly.data.transaction_hash, original);
  assert.equal(await rpc('eth_getTransactionByHash', [tipOnly.data.transaction_hash]), null, 'the pool rejected the tip-only replacement');
  assert.ok(await rpc('eth_getTransactionByHash', [original]), 'the original is still pending');
  // Both fees +12.5%: above geth/reth's 10% bump on each field (anvil only requires a higher max fee).
  const replacement = await signer.handle('eth_sendTransaction', [tx(0, fees(9n * GWEI / 2n, 9n * GWEI / 8n))]);
  assert.equal(await poolSize(rpc), 1);
  assert.equal(await rpc('eth_getTransactionByHash', [original]), null, 'the replacement evicted the original');
  await mine(rpc);
  assert.equal((await receipt(rpc, replacement)).status, '0x1');
  assert.equal(await rpc('eth_getTransactionReceipt', [original]), null, 'the original never mines');
  const mined = Transaction.from(await rpc('eth_getRawTransactionByHash', [replacement]));
  assert.deepEqual([mined.to.toLowerCase(), mined.data, mined.value, mined.nonce], [vault, data, 0n, 0]);
  assert.deepEqual([mined.maxFeePerGas, mined.maxPriorityFeePerGas], [9n * GWEI / 2n, 9n * GWEI / 8n]);
  assert.equal(await nonceOf(rpc, 'latest'), 1);
});

test('a balance below gas limit x max fee refuses before broadcast; the check uses the bid, not the cap', { skip }, async t => {
  const rpc = await startAnvil(t);
  const signer = signerFor(rpc, { maxFeePerGas: 50n * GWEI });
  const balance = GAS * 10n * GWEI - 1n;
  await rpc('anvil_setBalance', [sender, wei(balance)]);
  const refusal = maxFee => ({
    code: -32003, message: 'Sender balance cannot cover gas limit times max fee per gas',
    data: { reason: 'insufficient_balance', balance: wei(balance), required_balance: wei(GAS * maxFee) },
  });
  await assert.rejects(signer.handle('eth_sendTransaction', [tx(0, fees(10n * GWEI, GWEI))]), refusal(10n * GWEI));
  await assert.rejects(signer.handle('eth_sendTransaction', [tx(0)]), refusal(50n * GWEI));
  assert.equal(await nonceOf(rpc, 'pending'), 0);
  assert.equal(await poolSize(rpc), 0, 'nothing was broadcast');
  assert.ok((await signer.handle('zkapi_signerStatus', [])).warnings.includes('balance_below_required'));
  // A lower bid that the balance covers is signed and mines.
  const fits = await signer.handle('eth_sendTransaction', [tx(0, fees(9n * GWEI, GWEI))]);
  await mine(rpc);
  assert.equal((await receipt(rpc, fits)).status, '0x1');
});
