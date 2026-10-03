# Testing and Verification

From the repository root:

```bash
cargo test --release --manifest-path protocol/rust/Cargo.toml --workspace --locked
cargo test --release --workspace --locked
```

Protocol tests cover canonical fields and serialization, Merkle trees, native
wallet persistence, browser wallet state, compact proof encoding, commitment
binding, signing-seed policy, and request/withdrawal circuit constraints. Root
tests cover the active runtime HTTP paths, startup key binding, nullifier
persistence, clearance ownership proofs, settlement terminality, challenge
processing and status, and indexer reorganization and divergence handling.

From `protocol/contracts/`, run `forge test` for deposit, native settlement,
withdrawal, challenge, root-history, pause and treasury-timelock, and real
Groth16 verifier regressions. The challenge signer's tests run with `npm test`
in `docker/aws/signer` (and `npm run test:anvil` when `anvil` is installed).

The SDK asset check is `node scripts/sync-sdk-assets.mjs --check` from the repository
root. Keep the committed WASM and key hashes synchronized with the setup
manifest. Key generation is a separate operation and is not required for
ordinary verification. The
[setup trust assumptions](../../setup/v2/README.md) apply.

For the complete current native-v2 lifecycle, run `npm run test:e2e:v2` from the
repository root. It uses real services, proofs and contracts on a local chain,
with a mocked provider and oracle. See the
[acceptance process](../../../docs/v2-acceptance.md) for the exact boundary.
