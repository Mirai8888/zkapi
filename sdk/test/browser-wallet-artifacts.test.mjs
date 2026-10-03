import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import test from 'node:test';
const __dirname = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const root = __dirname;

function sha256(file) {
    return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function sourceBlockAt(source, markerIndex) {
    assert.ok(markerIndex >= 0, 'source block marker is missing');
    const blockStart = source.indexOf('{', markerIndex);
    assert.ok(blockStart >= 0, 'source block opening brace is missing');
    let depth = 0;
    for (let index = blockStart; index < source.length; index += 1) {
        if (source[index] === '{') depth += 1;
        if (source[index] === '}') {
            depth -= 1;
            if (depth === 0) return source.slice(blockStart, index + 1);
        }
    }
    assert.fail('source block closing brace is missing');
}

function sourceMethodAt(source, marker) {
    const markerIndex = source.indexOf(marker);
    assert.ok(markerIndex >= 0, `source method marker is missing: ${marker}`);
    const parametersStart = source.indexOf('(', markerIndex);
    assert.ok(parametersStart >= 0, `source method parameters are missing: ${marker}`);

    let parameterDepth = 0;
    let parametersEnd = -1;
    for (let index = parametersStart; index < source.length; index += 1) {
        if (source[index] === '(') parameterDepth += 1;
        if (source[index] === ')') {
            parameterDepth -= 1;
            if (parameterDepth === 0) {
                parametersEnd = index;
                break;
            }
        }
    }
    assert.ok(parametersEnd >= 0, `source method parameters do not close: ${marker}`);

    const bodyStart = source.indexOf('{', parametersEnd);
    assert.ok(bodyStart >= 0, `source method body is missing: ${marker}`);
    return source.slice(markerIndex, bodyStart) + sourceBlockAt(source, bodyStart);
}

test('browser build contains every wallet WASM operation', () => {
    const bytes = fs.readFileSync(path.join(__dirname, 'wasm/zkapi_browser_bg.wasm'));
    const module = new WebAssembly.Module(bytes);
    const exports = new Set(WebAssembly.Module.exports(module).map(entry => entry.name));
    for (const name of [
        'browser_circuit_id',
        'browser_generate_deposit',
        'browser_confirm_deposit',
        'browser_wallet_status',
        'browser_tree_path',
        'browser_prepare_request',
        'browserrequestprover_new',
        'browserrequestprover_prepare_request',
        'browser_complete_response',
        'browser_withdrawal_nullifier',
        'browser_prepare_withdrawal'
    ]) {
        assert.ok(exports.has(name), `missing WASM export ${name}`);
    }
});

test('browser worker retains the decoded request prover and retries failed initialization', () => {
    const glue = fs.readFileSync(path.join(__dirname, 'wasm/zkapi_browser.js'), 'utf8');
    const worker = fs.readFileSync(path.join(__dirname, 'services/zkapiWasmWorker.js'), 'utf8');
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');

    assert.match(glue, /export class BrowserRequestProver/);
    assert.match(worker, /const requestProvers = new Map\(\)/);
    assert.match(worker, /new BrowserRequestProver\(bytes\)/);
    assert.match(worker, /case 'preloadRequestProver':\s*await loadRequestProver\(payload\.provingKey\)/);
    assert.match(worker, /return parse\(prover\.prepare_request\(/);
    assert.match(worker, /if \(provingKeys\.get\(cacheKey\) === promise\) provingKeys\.delete\(cacheKey\)/);
    assert.match(worker, /requestProvers\.delete\(cacheKey\)/);
    assert.doesNotMatch(worker, /\bbrowser_prepare_request\b/);
    assert.match(runtime, /prewarmRequestProver\(\)/);
    assert.match(runtime, /this\.worker\.call\('preloadRequestProver'/);
    assert.match(runtime, /if \(this\.runtime\.state \|\| this\.runtime\.pendingDeposit\)/);
    const prepareDeposit = sourceMethodAt(runtime, 'async prepareDeposit(amount,');
    const walletStatus = sourceMethodAt(runtime, 'async walletStatus()');
    assert.match(prepareDeposit, /void this\.prewarmRequestProver\(\)/);
    assert.ok(
        prepareDeposit.indexOf('void this.prewarmRequestProver()')
            > prepareDeposit.indexOf('await withBrowserWalletLock'),
        'deposit warm-up must not block its lightweight worker preparation'
    );
    assert.match(walletStatus, /const status = await this\.worker\.call\('walletStatus'/);
    assert.match(walletStatus, /void this\.prewarmRequestProver\(\)/);
    assert.ok(
        walletStatus.indexOf('void this.prewarmRequestProver()')
            > walletStatus.indexOf("await this.worker.call('walletStatus'"),
        'funded-page warm-up must begin only after initial wallet status resolves'
    );
});

test('static proving keys match the note-bound development setup hashes', () => {
    assert.equal(
        sha256(path.join(root, 'assets/proofs/request.pk')),
        'c894b261a13f571d0df36be29734aabf2a8cd7162baddc5e08a50341aa076584'
    );
    assert.equal(
        sha256(path.join(root, 'assets/proofs/withdrawal.pk')),
        '8e41398092fdd02b9ff86c6ccbecbd7ce2402e6f22ec162e6124d1d04fe0a668'
    );
});

test('browser config pins the fresh native ETH note-bound Sepolia deployment', () => {
    const config = JSON.parse(fs.readFileSync(path.join(__dirname, 'assets/config/sepolia.json'), 'utf8'));
    assert.equal(config.deployment_manifest_url, 'https://zkapi-sepolia.openanonymity.ai/config.json');
    assert.deepEqual(config.allowed_deployment_manifest_urls, [config.deployment_manifest_url]);
    assert.equal(config.trusted_deployment.chain_id, 11155111);
    assert.equal(config.trusted_deployment.deployment_id, 'zkapi-native-eth-sepolia-note-bound-v1-fresh-20260930');
    assert.equal(config.trusted_deployment.contract_address.toLowerCase(), '0x49fa19f9bdece7a48ebc7749fd69ad40f577590f');
    assert.equal(config.trusted_deployment.billing_token_address, null);
    assert.equal(config.trusted_deployment.protocol_server_url, 'https://zkapi-sepolia.openanonymity.ai');
    assert.equal(config.trusted_deployment.indexer_url, config.trusted_deployment.protocol_server_url);
    assert.equal(config.trusted_deployment.circuit_id, 'zkapi-v2-note-bound-v1');
    assert.equal(config.deployment_status, undefined);
    assert.equal(config.trusted_deployment.request_proving_key_sha256, sha256(path.join(root, 'assets/proofs/request.pk')));
    assert.equal(config.trusted_deployment.withdrawal_proving_key_sha256, sha256(path.join(root, 'assets/proofs/withdrawal.pk')));
    assert.equal(config.proving_keys_base_url, './proofs/');
    assert.equal(config.deployment_api_proxy_path, '/zkapi-deployment/');
    assert.equal(config.trusted_deployment.billing_asset, 'native_eth');
    assert.equal(config.trusted_deployment.billing_unit, 'gwei');
    assert.equal(config.trusted_deployment.native_asset_wei_per_unit, '1000000000');
    assert.equal(config.trusted_deployment.rpc_url, 'https://ethereum-sepolia-rpc.publicnode.com');
    assert.equal(config.trusted_deployment.native_price_feed_address.toLowerCase(), '0x694aa1769357215de4fac081bf1f309adc325306');
    assert.equal(config.trusted_deployment.native_price_feed_decimals, 8);
    assert.equal(config.trusted_deployment.native_price_max_age_seconds, 4500);
    assert.equal(config.credits_per_usd, null);
    assert.equal(config.suggested_deposit_amount, undefined);
    assert.equal(config.billing_token_symbol, 'ETH');
    assert.equal(config.billing_token_decimals, 9);
    assert.equal(config.require_oa_key_source, true);
    assert.equal(config.openrouter_requests_per_key, undefined);
});

test('mainnet browser config pins the finalized native ETH note-bound deployment', () => {
    const config = JSON.parse(fs.readFileSync(path.join(__dirname, 'assets/config/mainnet.json'), 'utf8'));
    assert.equal(config.deployment_manifest_url, 'https://zkapi-mainnet.openanonymity.ai/config.json');
    assert.deepEqual(config.allowed_deployment_manifest_urls, [config.deployment_manifest_url]);
    assert.equal(config.trusted_deployment.deployment_id, 'zkapi-native-eth-mainnet-note-bound-v1-fresh-20260930');
    assert.equal(config.trusted_deployment.chain_id, 1);
    assert.equal(config.deployment_status, undefined);
    assert.equal(config.trusted_deployment.circuit_id, 'zkapi-v2-note-bound-v1');
    assert.equal(config.trusted_deployment.contract_address.toLowerCase(), '0x4386fdbda35d995beb3bf8625118ec5982ec81fe');
    assert.equal(config.trusted_deployment.protocol_server_url, 'https://zkapi-mainnet.openanonymity.ai');
    assert.equal(config.trusted_deployment.indexer_url, config.trusted_deployment.protocol_server_url);
    assert.deepEqual(config.trusted_deployment.state_signing_key, {
        x: '0x2094c5f9e183a8aef5be682556a17aa4dbafdb03fd6e6a97d75a03efed2fe5a4',
        y: '0x11c7bbbeb288a09378e6721bd06ed5cc95b87046ff8cf6733e46ced0af1300d7'
    });
    assert.deepEqual(config.trusted_deployment.clearance_signing_key, {
        x: '0x12d2b4547d9de0a359fc26abcf5e66cd359be83b53167850c9070540a8045cec',
        y: '0x11cc3f621d6d39b557b4bb64826ebaaeda04f98910f116e307d6650177dead82'
    });
    assert.equal(config.trusted_deployment.request_proving_key_sha256, sha256(path.join(root, 'assets/proofs/request.pk')));
    assert.equal(config.trusted_deployment.withdrawal_proving_key_sha256, sha256(path.join(root, 'assets/proofs/withdrawal.pk')));
    assert.equal(config.proving_keys_base_url, './proofs/');
    assert.equal(config.deployment_api_proxy_path, '/zkapi-deployment/');
    assert.equal(config.trusted_deployment.billing_asset, 'native_eth');
    assert.equal(config.trusted_deployment.billing_unit, 'gwei');
    assert.equal(config.trusted_deployment.billing_token_address, null);
    assert.equal(config.trusted_deployment.native_asset_wei_per_unit, '1000000000');
    assert.equal(config.trusted_deployment.rpc_url, 'https://ethereum-rpc.publicnode.com');
    assert.equal(config.trusted_deployment.native_price_feed_address.toLowerCase(), '0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419');
    assert.equal(config.trusted_deployment.native_price_feed_decimals, 8);
    assert.equal(config.trusted_deployment.native_price_max_age_seconds, 4500);
    assert.equal(config.trusted_deployment.openrouter_inference_base, 'https://openrouter.ai/api/v1');
    assert.equal(config.trusted_deployment.verifier_url, 'https://verifier2.openanonymity.ai');
    assert.equal(config.credits_per_usd, null);
    assert.equal(config.suggested_deposit_amount, undefined);
    assert.equal(config.billing_token_symbol, 'ETH');
    assert.equal(config.billing_token_decimals, 9);
    assert.equal(config.require_oa_key_source, true);
    assert.equal(config.openrouter_requests_per_key, undefined);
});

test('browser direct requests derive output headroom from the proof-backed dollar budget', async () => {
    const compat = await import(pathToFileURL(path.join(__dirname, 'services/zkapiRequestCompat.mjs')));
    assert.deepEqual(
        compat.ensureDirectCompletionLimit(
            { model: 'anthropic/claude-opus-5' },
            {
                spendingLimitUsd: 2,
                model: {
                    pricing: { completion: '0.000025' },
                    top_provider: { max_completion_tokens: 128_000 }
                }
            }
        ),
        { model: 'anthropic/claude-opus-5', max_tokens: 36_000 }
    );
    assert.deepEqual(
        compat.ensureDirectCompletionLimit({ model: 'openai/gpt-5.6-sol' }, { spendingLimitUsd: 5 }),
        { model: 'openai/gpt-5.6-sol', max_tokens: 90_000 }
    );
    assert.deepEqual(
        compat.ensureDirectCompletionLimit({ model: 'example/model' }),
        { model: 'example/model' }
    );
    assert.equal(compat.ensureDirectCompletionLimit({ max_tokens: 32 }).max_tokens, 32);
    assert.equal(compat.ensureDirectCompletionLimit({ max_completion_tokens: 48 }).max_completion_tokens, 48);
    assert.deepEqual(
        compat.ensureDirectCompletionLimit({ max_output_tokens: 64 }),
        { max_tokens: 64 }
    );
});

test('wallet transactions use a bounded preflight gas limit and leave EIP-1559 fees to MetaMask', async () => {
    const gas = await import(pathToFileURL(path.join(__dirname, 'services/zkapiGas.mjs')));
    assert.equal(gas.bufferedGasLimit('0x6d094d'), '0x839b46');
    assert.throws(
        () => gas.bufferedGasLimit(16_000_000n),
        error => error.code === 'transaction_gas_limit_exceeded'
    );
    assert.throws(() => gas.bufferedGasLimit('0x0'), /invalid gas estimate/);
    const contractErrors = await import(pathToFileURL(path.join(__dirname, 'services/zkapiContractError.mjs')));
    const staleRoot = contractErrors.contractEstimateError({
        message: 'execution reverted',
        data: { originalError: { data: '0x607447de' } }
    });
    assert.equal(staleRoot.code, 'stale_root');
    assert.match(staleRoot.message, /vault changed/i);
    const unknown = contractErrors.contractEstimateError({ message: 'execution reverted' });
    assert.equal(unknown.code, 'gas_estimation_failed');
    assert.match(unknown.message, /Transaction simulation failed: execution reverted/);
    assert.doesNotMatch(unknown.message, /market|gas price/i);
    const client = fs.readFileSync(path.join(__dirname, 'services/zkapiClient.js'), 'utf8');
    const send = sourceMethodAt(client, 'async sendContractTransaction(');
    const estimateIndex = send.indexOf("method: 'eth_estimateGas'");
    const gasIndex = send.indexOf('transaction.gas = bufferedGasLimit(estimate)');
    const submitIndex = send.indexOf("method: 'eth_sendTransaction'");
    assert.ok(estimateIndex >= 0 && gasIndex > estimateIndex && submitIndex > gasIndex);
    assert.match(send, /catch \(error\) \{[\s\S]*tagTransactionError\(contractEstimateError\(error\), 'estimate', false\)[\s\S]*\}\s*let hash;[\s\S]*method: 'eth_sendTransaction'/);
    assert.doesNotMatch(send, /transaction\.(?:gasPrice|maxFeePerGas|maxPriorityFeePerGas)\s*=/);
    assert.match(client, /contractRevertSelector\(error\)/);
    assert.match(client, /error\?\.code !== 'stale_root'/);
});

test('published vault challenge-period getter is probed before the reverting fallback', () => {
    const client = fs.readFileSync(path.join(__dirname, 'services/zkapiClient.js'), 'utf8');
    const method = sourceMethodAt(client, 'async loadChallengePeriod()');
    const publishedGetter = method.indexOf('ABI.legacyChallengePeriod');
    const fallbackGetter = method.indexOf('ABI.challengePeriod');

    assert.ok(publishedGetter >= 0, 'published CHALLENGE_PERIOD() getter is missing');
    assert.ok(fallbackGetter >= 0, 'challengePeriod() fallback getter is missing');
    assert.ok(
        publishedGetter < fallbackGetter,
        'the known-reverting fallback must not be probed before the published getter'
    );
});

test('browser withdrawal refreshes stale Merkle roots before retrying', () => {
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');
    const rootSync = fs.readFileSync(path.join(__dirname, 'services/zkapiWithdrawalRoot.mjs'), 'utf8');
    const client = fs.readFileSync(path.join(__dirname, 'services/zkapiClient.js'), 'utf8');
    assert.match(runtime, /expectedActiveRoot/);
    assert.match(runtime, /waitForExpectedActiveRoot/);
    assert.match(runtime, /sameFelt\(existing\.public_inputs\?\.active_root, path\.active_root\)/);
    assert.match(rootSync, /indexer_root_lag/);
    assert.match(client, /`0x\$\{ABI\.currentRoot\}`/);
    // Deposits still re-prove on any stale root.
    assert.match(client, /const attempts = 3/);
    assert.match(client, /Refreshing the Merkle path and proof/);
    // A hardened vault (root history) refreshes siblings without a new proof;
    // a repeated rejection or UnknownRoot() asks the runtime to re-prove.
    const prepare = sourceMethodAt(runtime, 'async prepareWithdrawalLocked(');
    assert.match(prepare, /if \(!reprove && provenForState && this\.vaultCapabilities\(\)\.hardenedVault\)/);
    assert.match(prepare, /siblings: path\.siblings, siblingsRoot: path\.active_root/);
    const withdraw = sourceMethodAt(client, 'async performWithdrawal(');
    assert.match(withdraw, /const withdrawalAttempts = 4/);
    assert.match(withdraw, /\['stale_root', 'unknown_root'\]\.includes\(error\?\.code\)/);
    assert.match(withdraw, /reprove = error\.code === 'unknown_root' \|\| rootRejections > 1/);
    assert.match(withdraw, /expectedActiveRoot,\s*reprove,/);
});

test('withdrawal root synchronization waits for the indexer and fails closed', async () => {
    const roots = await import(pathToFileURL(path.join(__dirname, 'services/zkapiWithdrawalRoot.mjs')));
    let calls = 0;
    const current = await roots.waitForExpectedActiveRoot(async () => {
        calls += 1;
        return { active_root: calls === 1 ? '0x10' : '0x11' };
    }, 17n, { attempts: 3, delayMs: 0, sleep: async () => {} });
    assert.equal(current.active_root, '0x11');
    assert.equal(calls, 2);
    assert.equal(roots.sameFelt('0x11', 17n), true);

    await assert.rejects(
        roots.waitForExpectedActiveRoot(
            async () => ({ active_root: '0x12' }),
            '0x13',
            { attempts: 2, delayMs: 0, sleep: async () => {} }
        ),
        error => error.code === 'indexer_root_lag'
    );
});

test('only a never-submitted prepared deposit can be replaced after cancellation', () => {
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');
    assert.match(runtime, /pending\.phase !== 'prepared' \|\| pending\.submissionId[\s\S]*pending\.transactionHash \|\| pending\.transactionHashes\?\.length/);
    assert.match(runtime, /await this\.commit\(\{ \.\.\.this\.runtime, pendingDeposit: null \}\)/);
    assert.match(runtime, /A previous deposit may already be in MetaMask\. Recover it before changing the amount/);
});

test('browser deposits refresh an unsigned Merkle path before submission', () => {
    const runtime = fs.readFileSync(path.join(__dirname, 'services/browserWalletRuntime.js'), 'utf8');
    const client = fs.readFileSync(path.join(__dirname, 'services/zkapiClient.js'), 'utf8');
    const refresh = sourceMethodAt(runtime, 'async refreshPendingDeposit(');
    assert.match(refresh, /async refreshPendingDeposit\(amount, expectedActiveRoot = null,/);
    assert.match(refresh, /const refreshed = \{[\s\S]*\.\.\.pending,[\s\S]*next_note_id: path\.note_id,[\s\S]*active_root: path\.active_root,[\s\S]*zero_path: path\.siblings/);
    assert.doesNotMatch(refresh, /secret:/);
    assert.match(client, /await browserWalletRuntime\.refreshPendingDeposit\([\s\S]*Number\(amount\),[\s\S]*expectedActiveRoot/);
    assert.match(client, /const attempts = 3/);
    assert.match(client, /error\?\.code !== 'stale_root'/);
});
