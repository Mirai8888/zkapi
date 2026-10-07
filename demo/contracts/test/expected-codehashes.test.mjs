// scripts/expected-codehashes.mjs reads deployment manifests exactly: forge's serializeUint writes
// values up to 2^64 - 1 as bare JSON numbers, which JSON.parse would round above 2^53 - 1.
// Run with: node --test demo/contracts/test/*.test.mjs (after forge build in protocol/contracts
// for the codehash case).
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { expectedCodehashes, parseDeployment, vaultImmutables } from '../../../scripts/expected-codehashes.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const ARTIFACTS = join(ROOT, 'protocol/contracts/out');

// A Baby-JubJub subgroup point whose y lies between 2^63 and 2^64 and is odd, so no double holds it.
const WIDE_Y_X = '0x05503c73ffee28fcacc324d533595173a637420b99492265bf57c2c286f59cd7';
const WIDE_Y_Y = '9223372036854775867';

function manifest(keyY) {
    return `{
  "poseidonLibrary": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
  "proofAdapter": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
  "noteTtl": 2592000,
  "challengePeriod": 86400,
  "maxPauseDuration": 604800,
  "requestChargeCap": 1000000,
  "stateSigningKeyX": "${BigInt(WIDE_Y_X)}",
  "stateSigningKeyY": ${keyY},
  "clearanceSigningKeyX": "13",
  "clearanceSigningKeyY": "14"
}`;
}

test('parseDeployment reads integers above 2^53 - 1 exactly', () => {
    const parsed = parseDeployment('{"a": 18446744073709551615, "b": 9007199254740993, "c": 7, "d": "123", "e": [9223372036854775867]}');
    assert.equal(parsed.a, 18446744073709551615n);
    assert.equal(parsed.b, 9007199254740993n);
    assert.equal(parsed.c, 7);
    assert.equal(parsed.d, '123');
    assert.equal(parsed.e[0], 9223372036854775867n);
    assert.equal(parseDeployment(manifest(WIDE_Y_Y)).stateSigningKeyY, BigInt(WIDE_Y_Y));
});

test('parseDeployment refuses numbers that are not exact integers', () => {
    for (const text of ['{"a": 1.5}', '{"a": 1e300}', '{"a": 9007199254740993.0}', '{"a": -9007199254740993}']) {
        assert.throws(() => parseDeployment(text), /is not an exact integer/, text);
    }
});

test('immutables refuse a JavaScript number that was already rounded', () => {
    const inputs = parseDeployment(manifest(`"${WIDE_Y_Y}"`));
    const words = vaultImmutables(inputs);
    assert.equal(words.stateSigningKeyY, BigInt(WIDE_Y_Y).toString(16).padStart(64, '0'));
    assert.deepEqual(vaultImmutables({ ...inputs, stateSigningKeyY: BigInt(WIDE_Y_Y) }), words);
    assert.deepEqual(vaultImmutables({ ...inputs, stateSigningKeyY: `0x${BigInt(WIDE_Y_Y).toString(16)}` }), words);
    // eslint-disable-next-line no-loss-of-precision
    assert.throws(() => vaultImmutables({ ...inputs, stateSigningKeyY: 9223372036854775867 }), /not a safe integer/);
    assert.throws(() => vaultImmutables({ ...inputs, noteTtl: 2 ** 60 }), /not a safe integer/);
});

test('a bare wide key and its decimal string give the same codehashes', { skip: !existsSync(ARTIFACTS) && 'run forge build in protocol/contracts first' }, () => {
    const bare = expectedCodehashes(ARTIFACTS, parseDeployment(manifest(WIDE_Y_Y)));
    const quoted = expectedCodehashes(ARTIFACTS, parseDeployment(manifest(`"${WIDE_Y_Y}"`)));
    assert.deepEqual(bare, quoted);
    // What a rounding parser would have computed differs.
    const rounded = expectedCodehashes(ARTIFACTS, { ...parseDeployment(manifest(`"${WIDE_Y_Y}"`)), stateSigningKeyY: String(Number(WIDE_Y_Y)) });
    assert.notEqual(rounded.vault_runtime_codehash, bare.vault_runtime_codehash);
});
