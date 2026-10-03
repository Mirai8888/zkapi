import { Interface, Transaction, Wallet, getAddress, isHexString, keccak256 } from 'ethers';

// Configuration errors carry fixed, secret-free messages that startup may print.
export class ConfigError extends Error {}

export function parseChainId(value) {
  if (value !== '1' && value !== '11155111') throw new ConfigError('Explicit challenge chain ID must be 1 or 11155111');
  return BigInt(value);
}
export const CHALLENGE_ABI = 'function challengeEscapeWithdrawal(uint32 noteId,(uint16 protocolVersion,uint64 chainId,address contractAddress,uint256 activeRoot,uint256 stateSigningKeyX,uint256 stateSigningKeyY,uint64 requestTime,uint128 solvencyBound,uint256 requestNullifier,uint256 authorizationTag,uint256 anonymousCommitmentX,uint256 anonymousCommitmentY) inputs,bytes proof,uint256[32] siblings)';
export const vaultInterface = new Interface([CHALLENGE_ABI]);
export const GWEI = 1_000_000_000n;
export const DEFAULT_SEPOLIA_MAX_FEE_PER_GAS = 10n * GWEI;
export const DEFAULT_PRIORITY_FEE_PER_GAS = 1n * GWEI;
export const DEFAULT_FEE_CEILING = 10_000n * GWEI;
export const ABSOLUTE_FEE_CEILING = 1_000_000n * GWEI;
export const UPSTREAM_TIMEOUT_MS = 8_000;
const readMethods = new Set([
  'eth_chainId', 'eth_blockNumber', 'eth_getBlockByNumber', 'eth_getLogs',
  'eth_getTransactionReceipt', 'eth_getTransactionByHash',
  'eth_getTransactionCount', 'eth_call', 'eth_estimateGas', 'eth_getBalance', 'eth_feeHistory',
]);
// Callers may propose both EIP-1559 fee fields (or neither). Every other fee
// or envelope field (gasPrice, type, accessList, input, blob fields) is refused.
const transactionFields = new Set(['from', 'to', 'data', 'gas', 'nonce', 'value', 'chainId', 'maxFeePerGas', 'maxPriorityFeePerGas']);
const weiDetails = new Set(['base_fee_per_gas', 'max_fee_per_gas', 'max_priority_fee_per_gas', 'balance', 'required_balance']);

export class RpcError extends Error {
  constructor(code, message, reason, details) {
    super(message); this.code = code;
    if (reason) this.data = { reason, ...details };
  }
}
const hex = value => `0x${value.toString(16)}`;
const min = (a, b) => (a < b ? a : b);
const QUANTITY = /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/;
function requireValid(condition, message, reason, details) {
  if (!condition) throw new RpcError(-32602, message, reason, details);
}
function address(value) {
  try { return getAddress(value).toLowerCase(); }
  catch { throw new RpcError(-32602, 'Invalid address'); }
}
function quantity(value, label) {
  requireValid(typeof value === 'string' && QUANTITY.test(value), `Invalid ${label}`);
  return BigInt(value);
}
// Malformed upstream answers are transient upstream failures, never invalid caller parameters.
function upstreamQuantity(value, message, reason = 'upstream_unavailable') {
  if (typeof value !== 'string' || !QUANTITY.test(value)) throw new RpcError(-32000, message, reason);
  return BigInt(value);
}

// Unset or empty means "use the default"; anything else must be a canonical
// positive decimal (no hex, sign, exponent, whitespace or leading zero).
function envInteger(env, name) {
  const value = env[name];
  if (value === undefined || value === '') return undefined;
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,30}$/.test(value)) throw new ConfigError(`${name} must be a positive decimal integer`);
  return BigInt(value);
}
export function parseSignerConfig(env) {
  if (env.ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI !== undefined) {
    throw new ConfigError('ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI is no longer supported; remove it and set ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI (the EIP-1559 fee cap in wei)');
  }
  const port = envInteger(env, 'ZKAPI_CHALLENGE_PORT') ?? 8547n;
  if (port > 65535n) throw new ConfigError('ZKAPI_CHALLENGE_PORT must be between 1 and 65535');
  return {
    chainId: parseChainId(env.ZKAPI_CHALLENGE_CHAIN_ID),
    privateKey: env.ZKAPI_CHALLENGE_PRIVATE_KEY,
    vault: env.ZKAPI_CHALLENGE_VAULT,
    rpcUrl: env.ZKAPI_CHALLENGE_RPC_URL,
    listenHost: env.ZKAPI_CHALLENGE_LISTEN_HOST || '127.0.0.1',
    port: Number(port),
    maxGas: envInteger(env, 'ZKAPI_CHALLENGE_MAX_GAS'),
    maxFeePerGas: envInteger(env, 'ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI'),
    priorityFeePerGas: envInteger(env, 'ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI'),
    maxPriorityFeePerGas: envInteger(env, 'ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI'),
    feeCeiling: envInteger(env, 'ZKAPI_CHALLENGE_FEE_CEILING_WEI'),
  };
}

// Upstream exceptions are never returned or logged: provider errors can contain
// URLs, credentials, raw signed transactions, or untrusted response bodies.
export function createUpstream(url, { timeoutMs = UPSTREAM_TIMEOUT_MS } = {}) {
  let parsed;
  try { parsed = new URL(url); } catch { throw new ConfigError('Upstream RPC URL is invalid'); }
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(parsed.hostname))) {
    throw new ConfigError('Upstream RPC must use HTTPS or loopback HTTP');
  }
  let nextId = 0;
  return async (method, params) => {
    let body;
    try {
      const response = await fetch(url, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++nextId, method, params }),
        signal: AbortSignal.timeout(timeoutMs), redirect: 'error',
      });
      if (!response.ok) throw new Error();
      body = await response.json();
    } catch { throw new RpcError(-32000, 'Upstream RPC request failed', 'upstream_unavailable'); }
    if (body && typeof body === 'object' && body.error) throw new RpcError(-32000, 'Upstream RPC rejected the request', 'upstream_rejected');
    if (!body || typeof body !== 'object' || !Object.hasOwn(body, 'result')) throw new RpcError(-32000, 'Upstream RPC request failed', 'upstream_unavailable');
    return body.result;
  };
}

export function createSigner({ privateKey, vault, rpc, chainId, maxGas = 12_000_000n, maxFeePerGas, priorityFeePerGas, maxPriorityFeePerGas, feeCeiling = DEFAULT_FEE_CEILING, log = line => console.log(JSON.stringify(line)), ...unsupported }) {
  requireValid(Object.keys(unsupported).length === 0, 'Unsupported signer option');
  requireValid(chainId === 1n || chainId === 11155111n, 'Explicit challenge chain ID must be 1 or 11155111');
  // Mainnet never inherits the testnet default; null counts as unset.
  requireValid(maxFeePerGas != null || chainId !== 1n, 'Mainnet requires an explicit ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI');
  const feeCapSource = maxFeePerGas == null ? 'default' : 'explicit';
  maxFeePerGas ??= DEFAULT_SEPOLIA_MAX_FEE_PER_GAS;
  let wallet;
  try { wallet = new Wallet(privateKey); } catch { throw new RpcError(-32602, 'Signer private key is invalid'); }
  const sender = wallet.address.toLowerCase();
  const destination = address(vault);
  requireValid(destination !== '0x0000000000000000000000000000000000000000', 'Vault must be nonzero');
  requireValid(typeof maxGas === 'bigint' && maxGas > 0n && maxGas <= 16_777_216n, 'Gas limit cap is invalid');
  const positive = value => typeof value === 'bigint' && value > 0n;
  requireValid(positive(feeCeiling) && feeCeiling <= ABSOLUTE_FEE_CEILING, 'Fee ceiling is invalid');
  requireValid(positive(maxFeePerGas) && maxFeePerGas <= feeCeiling, 'Fee cap is invalid or exceeds the fee ceiling');
  requireValid(maxPriorityFeePerGas == null || (positive(maxPriorityFeePerGas) && maxPriorityFeePerGas <= maxFeePerGas), 'Priority fee cap is invalid or exceeds the fee cap');
  priorityFeePerGas ??= min(DEFAULT_PRIORITY_FEE_PER_GAS, maxPriorityFeePerGas ?? maxFeePerGas);
  requireValid(positive(priorityFeePerGas), 'Default priority fee is invalid or exceeds the priority fee cap');
  // A small multiple of the default tip, so a caller cannot make every
  // challenge pay the whole fee cap as tip unless the operator opts in.
  maxPriorityFeePerGas ??= min(maxFeePerGas, 10n * priorityFeePerGas);
  requireValid(priorityFeePerGas <= maxPriorityFeePerGas, 'Default priority fee is invalid or exceeds the priority fee cap');
  const feeBounds = { max_fee_per_gas: hex(maxFeePerGas), max_priority_fee_per_gas: hex(maxPriorityFeePerGas) };
  let queue = Promise.resolve();

  const policy = Object.freeze({
    sender, vault: destination, transaction_type: '0x2', fee_cap_source: feeCapSource,
    max_fee_per_gas: hex(maxFeePerGas), priority_fee_per_gas: hex(priorityFeePerGas),
    max_priority_fee_per_gas: hex(maxPriorityFeePerGas), fee_ceiling: hex(feeCeiling),
    max_gas: hex(maxGas), required_balance: hex(maxGas * maxFeePerGas),
  });

  // Bounded, de-duplicated audit trail: one line per refusal transition of a
  // nonce and one per signed hash. No raw transactions, upstream text or keys.
  const lastRefusal = new Map();
  const loggedHashes = new Set();
  const evictOldest = (collection, key) => {
    if (!collection.has(key) && collection.size >= 256) collection.delete(collection.keys().next().value);
  };
  // Logging must never change an RPC outcome, whether log throws or rejects.
  function audit(line) {
    try {
      const entry = line();
      if (entry) Promise.resolve(log(entry)).catch(() => {});
    } catch { /* ignored */ }
  }
  function signedLine(transaction, hash) {
    lastRefusal.delete(transaction.nonce);
    if (loggedHashes.has(hash)) return null;
    evictOldest(loggedHashes, hash); loggedHashes.add(hash);
    return {
      event: 'challenge_signed', nonce: transaction.nonce, transaction_hash: hash,
      max_fee_per_gas_wei: transaction.maxFeePerGas.toString(10),
      max_priority_fee_per_gas_wei: transaction.maxPriorityFeePerGas.toString(10),
    };
  }
  function refusalLine(tx, error) {
    const nonce = typeof tx?.nonce === 'string' && QUANTITY.test(tx.nonce) && BigInt(tx.nonce) <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(BigInt(tx.nonce)) : null;
    const known = error instanceof RpcError;
    const { reason = known ? 'invalid_request' : 'internal_error', ...details } = (known && error.data) || {};
    const code = known ? error.code : -32603;
    const message = known ? error.message : 'Signer request failed';
    const transition = `${code}|${reason}|${message}`;
    if (lastRefusal.get(nonce) === transition) return null;
    evictOldest(lastRefusal, nonce); lastRefusal.set(nonce, transition);
    const line = { event: 'challenge_refused', nonce, code, reason, message };
    for (const [name, value] of Object.entries(details)) {
      if (name === 'transaction_hash') line.transaction_hash = value;
      else line[weiDetails.has(name) ? `${name}_wei` : name] = BigInt(value).toString(10);
    }
    return line;
  }

  async function checkChain() {
    const upstream = upstreamQuantity(await rpc('eth_chainId', []), 'Upstream RPC returned an invalid chain ID');
    if (upstream !== chainId) throw new RpcError(-32000, 'Upstream RPC does not match the configured chain', 'upstream_chain_mismatch');
  }
  // There is no legacy pricing fallback: a block without a base fee fails closed.
  async function latestBaseFee() {
    const block = await rpc('eth_getBlockByNumber', ['latest', false]);
    if (!block || typeof block !== 'object') throw new RpcError(-32000, 'Upstream block lacks a base fee', 'base_fee_unavailable');
    return {
      number: upstreamQuantity(block.number, 'Upstream block lacks a number', 'base_fee_unavailable'),
      baseFee: upstreamQuantity(block.baseFeePerGas, 'Upstream block lacks a base fee', 'base_fee_unavailable'),
    };
  }
  async function senderBalance() {
    return upstreamQuantity(await rpc('eth_getBalance', [sender, 'latest']), 'Upstream RPC returned an invalid balance');
  }
  async function status() {
    await checkChain();
    const [{ number, baseFee }, balance] = await Promise.all([latestBaseFee(), senderBalance()]);
    const warnings = [];
    if (baseFee > maxFeePerGas) warnings.push('base_fee_above_cap');
    // The next base fee may be 12.5% higher; the cap must still leave the default tip.
    if (baseFee * 9n + priorityFeePerGas * 8n > maxFeePerGas * 8n) warnings.push('base_fee_near_cap');
    if (balance < maxGas * maxFeePerGas) warnings.push('balance_below_required');
    return { chain_id: hex(chainId), ...policy, block_number: hex(number), base_fee_per_gas: hex(baseFee), balance: hex(balance), warnings };
  }

  // Both fee fields or neither. Absent fields bid (cap, default tip), which
  // keeps daemons that predate caller-proposed fees working unchanged.
  function requestedFees(tx) {
    const proposed = tx.maxFeePerGas !== undefined;
    requireValid(proposed === (tx.maxPriorityFeePerGas !== undefined), 'maxFeePerGas and maxPriorityFeePerGas must be supplied together', 'fee_out_of_bounds', feeBounds);
    if (!proposed) return { maxFee: maxFeePerGas, tip: priorityFeePerGas };
    const maxFee = quantity(tx.maxFeePerGas, 'max fee per gas');
    const tip = quantity(tx.maxPriorityFeePerGas, 'max priority fee per gas');
    requireValid(tip > 0n && tip <= maxFee && maxFee <= maxFeePerGas && tip <= maxPriorityFeePerGas, 'Requested fees are outside the configured bounds', 'fee_out_of_bounds', feeBounds);
    return { maxFee, tip };
  }

  function validateTransaction(tx) {
    requireValid(tx && typeof tx === 'object' && !Array.isArray(tx), 'Expected transaction object');
    requireValid(Object.keys(tx).every(key => transactionFields.has(key)), 'Unsupported transaction field');
    requireValid(address(tx.from) === sender, 'Sender is not authorized');
    requireValid(address(tx.to) === destination, 'Destination is not authorized');
    requireValid(tx.value === undefined || quantity(tx.value, 'value') === 0n, 'Value must be zero');
    requireValid(tx.chainId === undefined || quantity(tx.chainId, 'chain ID') === chainId, 'Chain ID does not match the configured chain');
    const gasLimit = quantity(tx.gas, 'gas');
    requireValid(gasLimit > 0n, 'Invalid gas');
    requireValid(gasLimit <= maxGas, 'Gas exceeds configured limit', 'gas_limit_exceeds_cap', { max_gas: hex(maxGas) });
    const nonce = quantity(tx.nonce, 'nonce');
    requireValid(nonce <= BigInt(Number.MAX_SAFE_INTEGER), 'Nonce is too large');
    const { maxFee, tip } = requestedFees(tx);
    requireValid(isHexString(tx.data) && tx.data.length <= 16_386, 'Invalid calldata');
    let decoded;
    try {
      decoded = vaultInterface.decodeFunctionData('challengeEscapeWithdrawal', tx.data);
      requireValid(vaultInterface.encodeFunctionData('challengeEscapeWithdrawal', decoded).toLowerCase() === tx.data.toLowerCase(), 'Noncanonical challenge calldata');
    } catch { throw new RpcError(-32602, 'Only canonical challengeEscapeWithdrawal calls are authorized'); }
    requireValid(decoded.inputs.protocolVersion === 2n && decoded.inputs.chainId === chainId && address(decoded.inputs.contractAddress) === destination, 'Challenge proof targets another deployment');
    requireValid(isHexString(decoded.proof, 256), 'Challenge requires a 256-byte Groth16 proof');
    return { type: 2, to: destination, data: tx.data, value: 0n, chainId, gasLimit, nonce: Number(nonce), maxFeePerGas: maxFee, maxPriorityFeePerGas: tip, accessList: [] };
  }

  async function simulate(call) {
    try { return await call(); }
    catch (error) {
      // Includes provider errors such as rate limits: transient, never invalid evidence.
      if (error instanceof RpcError && error.data?.reason === 'upstream_rejected') throw new RpcError(-32000, 'Challenge simulation failed', 'simulation_failed');
      throw error;
    }
  }
  async function knownTransaction(hash) {
    try {
      const known = await rpc('eth_getTransactionByHash', [hash]);
      return !!known && typeof known === 'object' && typeof known.hash === 'string' && known.hash.toLowerCase() === hash;
    } catch { return false; }
  }

  // Every failure before eth_sendRawTransaction is a definite non-broadcast.
  // From the broadcast on, the only failure is broadcast_ambiguous with the hash.
  async function signAndSend(tx) {
    const transaction = validateTransaction(tx);
    await checkChain();
    const simulation = { from: sender, to: destination, data: transaction.data, value: '0x0' };
    await simulate(() => rpc('eth_call', [simulation, 'latest']));
    const estimate = upstreamQuantity(await simulate(() => rpc('eth_estimateGas', [simulation])), 'Upstream RPC returned an invalid gas estimate');
    requireValid(estimate <= transaction.gasLimit, 'Gas limit is below current estimate', 'gas_estimate_exceeds_limit', { estimate: hex(estimate) });
    const [{ baseFee }, balance] = await Promise.all([latestBaseFee(), senderBalance()]);
    if (baseFee > transaction.maxFeePerGas) {
      throw new RpcError(-32003, 'Base fee exceeds the transaction max fee per gas', 'base_fee_above_max_fee', { base_fee_per_gas: hex(baseFee), max_fee_per_gas: hex(transaction.maxFeePerGas) });
    }
    // Pools reserve gas limit x maxFeePerGas up front, whatever is finally paid.
    const required = transaction.gasLimit * transaction.maxFeePerGas;
    if (balance < required) {
      throw new RpcError(-32003, 'Sender balance cannot cover gas limit times max fee per gas', 'insufficient_balance', { balance: hex(balance), required_balance: hex(required) });
    }
    let raw, signed;
    try {
      raw = await wallet.signTransaction(transaction);
      signed = Transaction.from(raw);
    } catch { throw new RpcError(-32603, 'Signer self-check failed'); }
    const hash = keccak256(raw);
    if (signed.type !== 2 || signed.hash !== hash || signed.from?.toLowerCase() !== sender || signed.to?.toLowerCase() !== destination
        || signed.data.toLowerCase() !== transaction.data.toLowerCase() || signed.value !== 0n || signed.chainId !== chainId
        || signed.nonce !== transaction.nonce || signed.gasLimit !== transaction.gasLimit
        || signed.maxFeePerGas !== transaction.maxFeePerGas || signed.maxPriorityFeePerGas !== transaction.maxPriorityFeePerGas
        || signed.accessList.length !== 0) {
      throw new RpcError(-32603, 'Signer self-check failed');
    }
    const ambiguous = () => new RpcError(-32000, 'Transaction broadcast outcome is unknown', 'broadcast_ambiguous', { transaction_hash: hash });
    let returned;
    try { returned = await rpc('eth_sendRawTransaction', [raw]); }
    catch {
      // Signing is deterministic, so an identical rebroadcast ("already known") is idempotent.
      if (await knownTransaction(hash)) return { hash, transaction };
      throw ambiguous();
    }
    if (typeof returned !== 'string' || returned.toLowerCase() !== hash) throw ambiguous();
    return { hash, transaction };
  }

  return {
    sender, vault: destination, chainId, policy, checkChain, status,
    async handle(method, params) {
      requireValid(Array.isArray(params), 'Expected positional parameters');
      if (method === 'eth_sendTransaction') {
        requireValid(params.length === 1, 'Expected one transaction');
        // Preserve the caller's durable nonce; never allocate a new nonce on
        // ambiguous sends. Serialize signing so callers cannot race fee checks.
        const result = queue.then(() => signAndSend(params[0])).then(
          ({ hash, transaction }) => { audit(() => signedLine(transaction, hash)); return hash; },
          error => { audit(() => refusalLine(params[0], error)); throw error; });
        queue = result.catch(() => {});
        return result;
      }
      if (method === 'zkapi_signerStatus') {
        requireValid(params.length === 0, 'Expected no parameters');
        return status();
      }
      if (!readMethods.has(method)) throw new RpcError(-32601, 'RPC method is not allowed');
      return rpc(method, params);
    },
  };
}
