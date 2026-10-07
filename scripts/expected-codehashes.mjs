#!/usr/bin/env node
// Expected runtime codehashes of a zkAPI deployment (vault revision 3), computed from the
// pinned-compiler Forge artifacts alone: the vault's deployedBytecode with the Bn254Poseidon
// link applied and its immutableReferences filled from the constructor arguments, the adapter's
// deployedBytecode, and the library's deployedBytecode (with its own address in a call-protection
// prefix, if the compiler emitted one). Anyone can rebuild the artifacts from source (protocol/contracts/foundry.toml pins solc,
// via_ir, 10,000 runs, bytecode_hash "none" and cbor_metadata false) and audit a deployment.
//
//   node scripts/expected-codehashes.mjs --deployment .demo/deployment.json [--check] [--rpc URL]
//   node scripts/expected-codehashes.mjs --poseidon 0x.. --note-ttl 2592000 --challenge-period 172800 \
//     --max-pause-duration 3888000 --request-charge-cap 50000 --proof-adapter 0x.. \
//     --state-key-x .. --state-key-y .. --clearance-key-x .. --clearance-key-y ..
//
// --deployment reads Deploy.s.sol's manifest; flags override its fields. --artifacts DIR selects
// the Forge out directory (default protocol/contracts/out). --check compares the result with the
// manifest's recorded codehashes, and --rpc URL with eth_getCode at the manifest's addresses; any
// mismatch exits 1. Prints JSON; integers wider than 2^53 - 1 print as decimal strings.
//
// Integers are read exactly. Deploy.s.sol writes the signing-key coordinates as decimal strings and
// every other number below 2^53. A wider bare JSON number in a manifest from elsewhere is read
// from its source text, never rounded; a number that is neither a safe integer nor an integer
// literal (a wide fraction or exponent form) is refused.
import { readFileSync } from 'node:fs';
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
    const args = { artifacts: join(ROOT, 'protocol/contracts/out'), inputs: {}, check: false };
    for (let i = 0; i < argv.length; i++) {
        const flag = argv[i];
        const next = () => argv[++i] ?? fail(`${flag} needs a value`);
        if (flag === '--artifacts') args.artifacts = resolve(next());
        else if (flag === '--deployment') args.deployment = resolve(next());
        else if (flag === '--rpc') args.rpc = next();
        else if (flag === '--check') args.check = true;
        else if (FLAGS[flag]) args.inputs[FLAGS[flag]] = next();
        else fail(`unknown argument ${flag}`);
    }
    return args;
}

async function codehashAt(rpc, target) {
    const response = await fetch(rpc, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getCode', params: [target, 'latest'] }),
        signal: AbortSignal.timeout(20_000),
    });
    const body = await response.json();
    if (typeof body.result !== 'string') fail(`eth_getCode ${target}: ${JSON.stringify(body.error ?? body)}`);
    return keccak256(hexToBytes(body.result));
}

async function main() {
    const args = parseArgs(process.argv.slice(2));
    const deployment = args.deployment ? parseDeployment(readFileSync(args.deployment, 'utf8')) : {};
    const inputs = {
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
        ...args.inputs,
    };
    const expected = expectedCodehashes(args.artifacts, inputs);
    const mismatches = [];
    const compare = (source, field, actual) => {
        if (typeof actual !== 'string' || actual.toLowerCase() !== expected[field]) {
            mismatches.push({ source, field, expected: expected[field], actual: actual ?? null });
        }
    };
    if (args.check) {
        if (!args.deployment) fail('--check needs --deployment');
        compare('deployment', 'vault_runtime_codehash', deployment.vaultRuntimeCodehash);
        compare('deployment', 'adapter_runtime_codehash', deployment.adapterRuntimeCodehash);
        compare('deployment', 'poseidon_runtime_codehash', deployment.poseidonRuntimeCodehash);
    }
    if (args.rpc) {
        const vault = deployment.vault ?? fail('--rpc needs the vault address from --deployment');
        compare('rpc', 'vault_runtime_codehash', await codehashAt(args.rpc, address(vault, 'vault')));
        compare('rpc', 'adapter_runtime_codehash', await codehashAt(args.rpc, address(inputs.proofAdapter, 'proofAdapter')));
        compare('rpc', 'poseidon_runtime_codehash', await codehashAt(args.rpc, address(inputs.poseidonLibrary, 'poseidonLibrary')));
    }
    const report = { artifacts: args.artifacts, inputs, ...expected };
    if (args.check || args.rpc) report.mismatches = mismatches;
    console.log(JSON.stringify(report, (key, value) => (typeof value === 'bigint' ? value.toString() : value), 2));
    if (mismatches.length) process.exit(1);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    main().catch(error => {
        console.error(`expected-codehashes: ${error.message}`);
        process.exit(2);
    });
}
