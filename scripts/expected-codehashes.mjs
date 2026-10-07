#!/usr/bin/env node
// Expected runtime codehashes of a zkAPI deployment (vault revision 3), computed from the
// pinned-compiler Forge artifacts alone: the vault's deployedBytecode with the Bn254Poseidon
// link applied and its immutableReferences filled from the constructor arguments, the adapter's
// deployedBytecode, and the library's deployedBytecode (with its own address in a call-protection
// prefix, if the compiler emitted one). Anyone can rebuild the artifacts from source
// (protocol/contracts/foundry.toml pins solc, via_ir, 10,000 runs, bytecode_hash "none" and
// cbor_metadata false) and audit a deployment.
//
//   node scripts/expected-codehashes.mjs --deployment .demo/deployment.json [--check] [--rpc URL]
//   node scripts/expected-codehashes.mjs --deployment .demo/deployment.json.pending --rpc URL \
//     --finalize .demo/deployment.json [--broadcast-log FILE] [--confirmations N]
//   node scripts/expected-codehashes.mjs --poseidon 0x.. --note-ttl 2592000 --challenge-period 172800 \
//     --max-pause-duration 3888000 --request-charge-cap 50000 --proof-adapter 0x.. \
//     --state-key-x .. --state-key-y .. --clearance-key-x .. --clearance-key-y ..
//
// --deployment reads Deploy.s.sol's manifest; flags override its fields. --artifacts DIR selects
// the Forge out directory (default protocol/contracts/out). --check compares the result with the
// manifest's recorded codehashes, and --rpc URL with eth_getCode at the manifest's addresses; any
// mismatch exits 1. Prints JSON; integers wider than 2^53 - 1 print as decimal strings.
//
// --finalize OUT turns Deploy.s.sol's provisional manifest (OUTPUT_PATH.pending, deploymentStatus
// "pending") into the deployment manifest, once the broadcast is checked on chain. forge writes the
// provisional manifest while it simulates, before it sends anything, so its addresses, codehashes
// and post-deploy checks describe the simulation. Finalizing takes each creation's transaction
// from the receipts in forge's broadcast log (--broadcast-log; default
// demo/contracts/broadcast/Deploy.s.sol/<chainId>/run-latest.json), and requires, through the RPC:
// the manifest's chain; each receipt on chain, successful and creating the manifest's address; at
// least --confirmations (default 1) blocks on the vault's creation; the three runtime codehashes
// (the manifest's, and on chain); and the vault's owner and treasury. Only then does it write OUT:
// the manifest with deploymentStatus "deployed", deployBlock (the block that created the vault, the
// indexer's and the profiles' deploy_block) and deployTransactions. Any mismatch exits 1 and any
// other failure exits 2; neither writes OUT.
//
// Integers are read exactly. Deploy.s.sol writes the signing-key coordinates as decimal strings and
// every other number below 2^53. A wider bare JSON number in a manifest from elsewhere is read
// from its source text, never rounded; a number that is neither a safe integer nor an integer
// literal (a wide fraction or exponent form) is refused.
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DAY = 86_400n;
const MIN_TREASURY_CHANGE_DELAY = 2n * DAY;
const MIN_UNPAUSE_CLAIM_GRACE = DAY;

// ------------------------------------------------------------------ keccak256 (Keccak-f[1600])

const MASK64 = (1n << 64n) - 1n;
const ROUND_CONSTANTS = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
// ROTATIONS[x][y], the rho offsets.
const ROTATIONS = [
    [0n, 36n, 3n, 41n, 18n],
    [1n, 44n, 10n, 45n, 2n],
    [62n, 6n, 43n, 15n, 61n],
    [28n, 55n, 25n, 21n, 56n],
    [27n, 20n, 39n, 8n, 14n],
];

function rotl(value, shift) {
    return shift === 0n ? value : ((value << shift) | (value >> (64n - shift))) & MASK64;
}

function keccakF(state) {
    const b = new Array(25);
    for (const constant of ROUND_CONSTANTS) {
        const c = [0, 1, 2, 3, 4].map(x => state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]);
        for (let x = 0; x < 5; x++) {
            const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1n);
            for (let y = 0; y < 25; y += 5) state[y + x] ^= d;
        }
        for (let x = 0; x < 5; x++) {
            for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(state[x + 5 * y], ROTATIONS[x][y]);
        }
        for (let x = 0; x < 5; x++) {
            for (let y = 0; y < 5; y++) {
                state[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & MASK64 & b[((x + 2) % 5) + 5 * y]);
            }
        }
        state[0] ^= constant;
    }
}

export function keccak256(bytes) {
    const rate = 136;
    const padded = new Uint8Array(Math.floor(bytes.length / rate + 1) * rate);
    padded.set(bytes);
    padded[bytes.length] ^= 0x01;
    padded[padded.length - 1] ^= 0x80;
    const state = new Array(25).fill(0n);
    for (let offset = 0; offset < padded.length; offset += rate) {
        for (let lane = 0; lane < rate / 8; lane++) {
            let value = 0n;
            for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(padded[offset + 8 * lane + i]);
            state[lane] ^= value;
        }
        keccakF(state);
    }
    let out = '0x';
    for (let lane = 0; lane < 4; lane++) {
        for (let i = 0; i < 8; i++) out += Number((state[lane] >> BigInt(8 * i)) & 0xffn).toString(16).padStart(2, '0');
    }
    return out;
}

// ------------------------------------------------------------------------------- helpers

function fail(message) {
    throw new Error(message);
}

function hexToBytes(hex) {
    const body = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (!/^([0-9a-fA-F]{2})*$/.test(body)) fail(`not hex bytes: ${hex.slice(0, 80)}...`);
    return Uint8Array.from(body.match(/../g) ?? [], pair => parseInt(pair, 16));
}

/// A JavaScript number is accepted only as a safe integer: a wider one was already rounded.
function exactNumber(value, label) {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) {
        fail(`${label}: ${value} is not a safe integer (pass a decimal string or a BigInt)`);
    }
    return value;
}

function word(value, label) {
    exactNumber(value, label);
    let n;
    try {
        n = BigInt(value);
    } catch {
        fail(`${label}: not an integer: ${value}`);
    }
    if (n < 0n || n >= 1n << 256n) fail(`${label}: out of range`);
    return n.toString(16).padStart(64, '0');
}

function address(value, label) {
    if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) fail(`${label}: not an address: ${value}`);
    return value.toLowerCase();
}

function uint(value, bits, label) {
    if (value === undefined || value === null || value === '') fail(`missing ${label}`);
    exactNumber(value, label);
    let n;
    try {
        n = BigInt(value);
    } catch {
        fail(`${label}: not an integer: ${value}`);
    }
    if (n < 0n || n >= 1n << BigInt(bits)) fail(`${label}: does not fit uint${bits}`);
    return n;
}

function artifact(dir, name) {
    const path = join(dir, `${name}.sol`, `${name}.json`);
    try {
        return JSON.parse(readFileSync(path, 'utf8'));
    } catch (error) {
        fail(`cannot read ${path} (run forge build first): ${error.message}`);
    }
}

/// AST id -> name of every immutable state variable.
function immutableNames(ast) {
    if (!ast) fail('artifact has no AST; build with ast = true (foundry.toml)');
    const names = new Map();
    const visit = node => {
        if (Array.isArray(node)) return node.forEach(visit);
        if (!node || typeof node !== 'object') return;
        if (node.nodeType === 'VariableDeclaration' && node.mutability === 'immutable') names.set(String(node.id), node.name);
        for (const value of Object.values(node)) if (value && typeof value === 'object') visit(value);
    };
    visit(ast);
    return names;
}

/// Writes `hexValue` (an even-length hex string) at byte offset `start` of the hex code string.
function patch(code, start, length, hexValue) {
    if (hexValue.length !== 2 * length) fail('patch length');
    const at = 2 * start;
    if (at + 2 * length > code.length) fail('patch beyond the code');
    return code.slice(0, at) + hexValue + code.slice(at + 2 * length);
}

// ------------------------------------------------------------------------------- codehashes

/// The constructor-derived immutables of ZkApiVault, by name, as 32-byte hex words.
export function vaultImmutables(inputs) {
    const challengePeriod = uint(inputs.challengePeriod, 64, 'challengePeriod');
    const maxPauseDuration = uint(inputs.maxPauseDuration, 64, 'maxPauseDuration');
    if (challengePeriod === 0n) fail('challengePeriod must be positive');
    if (maxPauseDuration < 2n * challengePeriod) fail('maxPauseDuration must be at least 2 * challengePeriod');
    const treasuryChangeDelay = challengePeriod > MIN_TREASURY_CHANGE_DELAY ? challengePeriod : MIN_TREASURY_CHANGE_DELAY;
    const unpauseClaimGrace = challengePeriod > MIN_UNPAUSE_CLAIM_GRACE ? challengePeriod : MIN_UNPAUSE_CLAIM_GRACE;
    return {
        noteTtl: word(uint(inputs.noteTtl, 64, 'noteTtl'), 'noteTtl'),
        challengePeriod: word(challengePeriod, 'challengePeriod'),
        treasuryChangeDelay: word(treasuryChangeDelay, 'treasuryChangeDelay'),
        unpauseClaimGrace: word(unpauseClaimGrace, 'unpauseClaimGrace'),
        requestChargeCap: word(uint(inputs.requestChargeCap, 128, 'requestChargeCap'), 'requestChargeCap'),
        proofAdapter: word(address(inputs.proofAdapter, 'proofAdapter'), 'proofAdapter'),
        stateSigningKeyX: word(inputs.stateSigningKeyX, 'stateSigningKeyX'),
        stateSigningKeyY: word(inputs.stateSigningKeyY, 'stateSigningKeyY'),
        clearanceSigningKeyX: word(inputs.clearanceSigningKeyX, 'clearanceSigningKeyX'),
        clearanceSigningKeyY: word(inputs.clearanceSigningKeyY, 'clearanceSigningKeyY'),
        maxPauseDuration: word(maxPauseDuration, 'maxPauseDuration'),
    };
}

export function expectedRuntimeCode(artifactsDir, inputs) {
    const poseidon = address(inputs.poseidonLibrary, 'poseidonLibrary').slice(2);

    const vaultArtifact = artifact(artifactsDir, 'ZkApiVault');
    let vault = vaultArtifact.deployedBytecode.object.replace(/^0x/, '');
    const links = vaultArtifact.deployedBytecode.linkReferences ?? {};
    let linked = 0;
    for (const [file, libraries] of Object.entries(links)) {
        for (const [name, refs] of Object.entries(libraries)) {
            if (name !== 'Bn254Poseidon') fail(`ZkApiVault links an unexpected library ${file}:${name}`);
            for (const ref of refs) {
                vault = patch(vault, ref.start, ref.length, poseidon);
                ++linked;
            }
        }
    }
    if (linked === 0) fail('ZkApiVault has no Bn254Poseidon link reference');
    const names = immutableNames(vaultArtifact.ast);
    const values = vaultImmutables(inputs);
    const filled = new Set();
    for (const [id, refs] of Object.entries(vaultArtifact.deployedBytecode.immutableReferences ?? {})) {
        const name = names.get(id) ?? fail(`immutable reference ${id} has no declaration in the AST`);
        const value = values[name] ?? fail(`ZkApiVault immutable ${name} is not derived by this script`);
        for (const ref of refs) vault = patch(vault, ref.start, ref.length, value);
        filled.add(name);
    }
    for (const name of Object.keys(values)) if (!filled.has(name)) fail(`ZkApiVault has no immutable ${name}`);
    if (/[^0-9a-fA-F]/.test(vault)) fail('ZkApiVault runtime code still has an unlinked placeholder');

    const adapterArtifact = artifact(artifactsDir, 'Groth16ProofAdapter');
    const adapterRefs = adapterArtifact.deployedBytecode;
    if (Object.keys(adapterRefs.linkReferences ?? {}).length || Object.keys(adapterRefs.immutableReferences ?? {}).length) {
        fail('Groth16ProofAdapter is expected to have no links and no immutables');
    }
    const adapter = adapterRefs.object.replace(/^0x/, '');

    const libraryArtifact = artifact(artifactsDir, 'Bn254Poseidon');
    let library = libraryArtifact.deployedBytecode.object.replace(/^0x/, '');
    // A library with call protection starts with PUSH20 <its own address>, written at deployment.
    // Bn254Poseidon's via-IR code has none (all its functions are pure), so its code does not
    // depend on its address.
    if (library.startsWith('73' + '0'.repeat(40))) library = patch(library, 1, 20, poseidon);

    return { vault: `0x${vault}`, adapter: `0x${adapter}`, poseidon: `0x${library}` };
}

export function expectedCodehashes(artifactsDir, inputs) {
    const code = expectedRuntimeCode(artifactsDir, inputs);
    return {
        vault_runtime_codehash: keccak256(hexToBytes(code.vault)),
        adapter_runtime_codehash: keccak256(hexToBytes(code.adapter)),
        poseidon_runtime_codehash: keccak256(hexToBytes(code.poseidon)),
    };
}

/// Parses a deployment manifest without rounding: a JSON number above 2^53 - 1 becomes a BigInt
/// read from its source text (JSON.parse source text access, Node 21 and later), and any other
/// number that is not a safe integer (a fraction, an exponent) is refused.
export function parseDeployment(text) {
    return JSON.parse(text, (key, value, context) => {
        if (typeof value !== 'number' || Number.isSafeInteger(value)) return value;
        const source = context?.source;
        if (typeof source === 'string' && /^(0|[1-9][0-9]*)$/.test(source)) return BigInt(source);
        return fail(`deployment field ${key}: ${source ?? value} is not an exact integer; write it as a decimal string`);
    });
}

// ------------------------------------------------------------------------- audit and finalize

/// A JSON-RPC client: `rpc(method, params)` resolves to the result, or throws.
export function jsonRpc(url) {
    let id = 0;
    return async (method, params) => {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
            signal: AbortSignal.timeout(20_000),
        });
        const body = await response.json();
        if (body.error || !('result' in body)) fail(`${method}: ${JSON.stringify(body.error ?? body)}`);
        return body.result;
    };
}

async function codehashAt(rpc, target) {
    const code = await rpc('eth_getCode', [target, 'latest']);
    if (typeof code !== 'string') fail(`eth_getCode ${target}: ${JSON.stringify(code)}`);
    return keccak256(hexToBytes(code));
}

function selector(signature) {
    return keccak256(new TextEncoder().encode(signature)).slice(0, 10);
}

function quantity(value, label) {
    if (typeof value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(value)) fail(`${label}: not a hex quantity: ${value}`);
    return BigInt(value);
}

/// The constructor-derived inputs of a manifest, with `overrides` (CLI flags) applied.
export function deploymentInputs(deployment, overrides = {}) {
    return {
        poseidonLibrary: deployment.poseidonLibrary,
        proofAdapter: deployment.proofAdapter,
        noteTtl: deployment.noteTtl,
        challengePeriod: deployment.challengePeriod,
        maxPauseDuration: deployment.maxPauseDuration,
        requestChargeCap: deployment.requestChargeCap,
        stateSigningKeyX: deployment.stateSigningKeyX,
        stateSigningKeyY: deployment.stateSigningKeyY,
        clearanceSigningKeyX: deployment.clearanceSigningKeyX,
        clearanceSigningKeyY: deployment.clearanceSigningKeyY,
        ...overrides,
    };
}

/// The expected codehashes of `deployment`, compared with its recorded ones (`check`) and with the
/// code at its addresses (`rpc`, a jsonRpc client). Returns { inputs, expected, mismatches }.
export async function auditDeployment({ artifacts, deployment, overrides = {}, check = false, rpc = null }) {
    const inputs = deploymentInputs(deployment, overrides);
    const expected = expectedCodehashes(artifacts, inputs);
    const mismatches = [];
    const compare = (source, field, actual) => {
        if (typeof actual !== 'string' || actual.toLowerCase() !== expected[field]) {
            mismatches.push({ source, field, expected: expected[field], actual: actual ?? null });
        }
    };
    if (check) {
        compare('deployment', 'vault_runtime_codehash', deployment.vaultRuntimeCodehash);
        compare('deployment', 'adapter_runtime_codehash', deployment.adapterRuntimeCodehash);
        compare('deployment', 'poseidon_runtime_codehash', deployment.poseidonRuntimeCodehash);
    }
    if (rpc) {
        const vault = deployment.vault ?? fail('--rpc needs the vault address from --deployment');
        compare('rpc', 'vault_runtime_codehash', await codehashAt(rpc, address(vault, 'vault')));
        compare('rpc', 'adapter_runtime_codehash', await codehashAt(rpc, address(inputs.proofAdapter, 'proofAdapter')));
        compare('rpc', 'poseidon_runtime_codehash', await codehashAt(rpc, address(inputs.poseidonLibrary, 'poseidonLibrary')));
    }
    return { inputs, expected, mismatches };
}

/// forge's broadcast log of Deploy.s.sol on `chainId`, relative to the repository root.
export function defaultBroadcastLog(chainId) {
    return join(ROOT, 'demo/contracts/broadcast/Deploy.s.sol', String(chainId), 'run-latest.json');
}

/// Checks the broadcast of Deploy.s.sol's provisional manifest `deployment` on chain (see the
/// header) and returns { manifest, mismatches, expected }: `manifest` is the final deployment
/// manifest, present only when nothing mismatched. Throws when the deployment cannot be confirmed.
/// Creations are matched to the manifest's addresses through the log's receipts only: forge's
/// `transactions` entries can pair a hash with another creation's address.
export async function finalizeDeployment({ artifacts, deployment, broadcastLog, rpc, confirmations = 1 }) {
    if (deployment.deploymentStatus !== 'pending') {
        fail(`deploymentStatus is ${JSON.stringify(deployment.deploymentStatus ?? null)}: finalize takes the provisional manifest of a broadcast run ("pending"); a dry run deploys nothing`);
    }
    const chainId = uint(deployment.chainId, 64, 'chainId');
    const rpcChain = quantity(await rpc('eth_chainId', []), 'eth_chainId');
    if (rpcChain !== chainId) fail(`the RPC serves chain ${rpcChain}, the manifest is for chain ${chainId}`);
    if (BigInt(broadcastLog?.chain ?? -1) !== chainId) fail(`the broadcast log is for chain ${broadcastLog?.chain}, not ${chainId}`);
    const lowerBound = uint(deployment.deployBlockLowerBound, 64, 'deployBlockLowerBound');

    const creations = { vault: deployment.vault, proofAdapter: deployment.proofAdapter };
    if (deployment.poseidonLibraryReused !== true) creations.poseidonLibrary = deployment.poseidonLibrary;
    const transactions = {};
    const blocks = {};
    for (const [role, target] of Object.entries(creations)) {
        const at = address(target, role);
        const logged = (broadcastLog.receipts ?? []).filter(
            receipt => typeof receipt?.contractAddress === 'string' && receipt.contractAddress.toLowerCase() === at,
        );
        if (logged.length !== 1) {
            fail(`the broadcast log has ${logged.length} receipts creating the ${role} at ${target}; complete the broadcast (forge script --resume) or check the deployer's nonce`);
        }
        const hash = logged[0].transactionHash;
        const receipt = await rpc('eth_getTransactionReceipt', [hash]);
        if (!receipt) fail(`the ${role} creation ${hash} is not on chain (dropped or reorganized)`);
        if (quantity(receipt.status, `${role} receipt status`) !== 1n) fail(`the ${role} creation ${hash} failed on chain`);
        if (typeof receipt.contractAddress !== 'string' || receipt.contractAddress.toLowerCase() !== at) {
            fail(`the ${role} creation ${hash} created ${receipt.contractAddress}, not ${target}`);
        }
        const block = quantity(receipt.blockNumber, `${role} receipt blockNumber`);
        if (block <= lowerBound) fail(`the ${role} was created in block ${block}, not after the simulated head ${lowerBound}`);
        transactions[role] = hash;
        blocks[role] = block;
    }
    const deployBlock = blocks.vault;
    if (deployBlock > BigInt(Number.MAX_SAFE_INTEGER)) fail(`deployBlock ${deployBlock} is above 2^53 - 1`);
    const latest = quantity(await rpc('eth_blockNumber', []), 'eth_blockNumber');
    const seen = latest >= deployBlock ? latest - deployBlock + 1n : 0n;
    if (seen < BigInt(confirmations)) {
        fail(`the vault's creation has ${seen} confirmations, ${confirmations} required: finalize again later`);
    }

    const { expected, mismatches } = await auditDeployment({ artifacts, deployment, check: true, rpc });
    // The codehashes cover the code and every immutable; owner and treasury are storage.
    for (const field of ['owner', 'treasury']) {
        const word = await rpc('eth_call', [{ to: address(deployment.vault, 'vault'), data: selector(`${field}()`) }, 'latest']);
        if (typeof word !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(word)) fail(`${field}(): unexpected return ${word}`);
        const actual = `0x${word.slice(-40)}`.toLowerCase();
        const wanted = address(deployment[field], field);
        if (actual !== wanted || BigInt(word) >> 160n !== 0n) mismatches.push({ source: 'rpc', field, expected: wanted, actual: word });
    }
    if (mismatches.length) return { mismatches, expected };
    const manifest = {
        ...deployment,
        deploymentStatus: 'deployed',
        deployBlock: Number(deployBlock),
        deployTransactions: transactions,
    };
    return { manifest, mismatches, expected };
}

// ------------------------------------------------------------------------------------- CLI

const FLAGS = {
    '--poseidon': 'poseidonLibrary',
    '--proof-adapter': 'proofAdapter',
    '--note-ttl': 'noteTtl',
    '--challenge-period': 'challengePeriod',
    '--max-pause-duration': 'maxPauseDuration',
    '--request-charge-cap': 'requestChargeCap',
    '--state-key-x': 'stateSigningKeyX',
    '--state-key-y': 'stateSigningKeyY',
    '--clearance-key-x': 'clearanceSigningKeyX',
    '--clearance-key-y': 'clearanceSigningKeyY',
};

function parseArgs(argv) {
    const args = { artifacts: join(ROOT, 'protocol/contracts/out'), inputs: {}, check: false, confirmations: 1 };
    for (let i = 0; i < argv.length; i++) {
        const flag = argv[i];
        const next = () => argv[++i] ?? fail(`${flag} needs a value`);
        if (flag === '--artifacts') args.artifacts = resolve(next());
        else if (flag === '--deployment') args.deployment = resolve(next());
        else if (flag === '--rpc') args.rpc = next();
        else if (flag === '--check') args.check = true;
        else if (flag === '--finalize') args.finalize = resolve(next());
        else if (flag === '--broadcast-log') args.broadcastLog = resolve(next());
        else if (flag === '--confirmations') args.confirmations = Number(uint(next(), 32, '--confirmations'));
        else if (FLAGS[flag]) args.inputs[FLAGS[flag]] = next();
        else fail(`unknown argument ${flag}`);
    }
    return args;
}

const printable = (key, value) => (typeof value === 'bigint' ? value.toString() : value);

async function main() {
    const args = parseArgs(process.argv.slice(2));
    const deployment = args.deployment ? parseDeployment(readFileSync(args.deployment, 'utf8')) : {};
    if (args.check && !args.deployment) fail('--check needs --deployment');
    if (args.finalize) {
        if (!args.deployment || !args.rpc) fail('--finalize needs --deployment (the provisional manifest) and --rpc');
        if (Object.keys(args.inputs).length) fail('--finalize takes every input from the manifest');
        if (args.finalize === args.deployment) fail('--finalize writes a new file; keep the provisional manifest');
        const logPath = args.broadcastLog ?? defaultBroadcastLog(deployment.chainId);
        if (!existsSync(logPath)) fail(`no broadcast log at ${logPath} (pass --broadcast-log)`);
        const broadcastLog = JSON.parse(readFileSync(logPath, 'utf8'));
        const { manifest, mismatches, expected } = await finalizeDeployment({
            artifacts: args.artifacts,
            deployment,
            broadcastLog,
            rpc: jsonRpc(args.rpc),
            confirmations: args.confirmations,
        });
        const report = { artifacts: args.artifacts, broadcastLog: logPath, ...expected, mismatches };
        if (manifest) {
            const temporary = `${args.finalize}.tmp`;
            writeFileSync(temporary, `${JSON.stringify(manifest, printable, 2)}\n`);
            renameSync(temporary, args.finalize);
            Object.assign(report, { finalized: args.finalize, deployBlock: manifest.deployBlock, deployTransactions: manifest.deployTransactions });
        }
        console.log(JSON.stringify(report, printable, 2));
        if (mismatches.length) process.exit(1);
        return;
    }
    const { inputs, expected, mismatches } = await auditDeployment({
        artifacts: args.artifacts,
        deployment,
        overrides: args.inputs,
        check: args.check,
        rpc: args.rpc ? jsonRpc(args.rpc) : null,
    });
    const report = { artifacts: args.artifacts, inputs, ...expected };
    if (args.check || args.rpc) report.mismatches = mismatches;
    console.log(JSON.stringify(report, printable, 2));
    if (mismatches.length) process.exit(1);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch(error => {
        console.error(`expected-codehashes: ${error.message}`);
        process.exit(2);
    });
}
