# zkAPI v2 implementation specification

This document describes the active implementation. The protocol model is in
[PROTOCOL.md](PROTOCOL.md). Source definitions linked below fix the exact field
order, encodings, and constraints.

## Cryptographic parameters

- Proof system: circuit-specific Groth16 on BN254.
- Circuit revision: `zkapi-v2-note-bound-v1`.
- Circuit field: BN254 scalar field, modulus
  `0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.
- Hash: domain-separated Poseidon, exponent 5, rate 2, capacity 1,
  8 full rounds and 57 partial rounds.
- Balance commitment: `E(B, r, L) = B*G + r*H + L*J` on Baby-JubJub,
  where `L` is the private active-note leaf.
- Server authentication: separate Baby-JubJub Schnorr keys for state and
  clearance signatures, pinned by the deployment.
- Active-note tree: depth 32, zero leaf 0, note ID as the leaf index.

[Native hash functions](rust/crates/zkapi-core/src/v2.rs) and
[circuit constraints](rust/crates/zkapi-proof/src/groth16.rs) use the
`zkapi.v2.*` domain labels. The independent note-binding generator is derived
under `zkapi.v2.note-binding.generator.v1`. Native helpers, circuits, setup
manifest, and generated Solidity must agree. This is a classical elliptic-curve
proof and signature system.

## Notes and state

A registration commitment is `C = H_reg(secret, 0)`. The active leaf is
`L = H_leaf(note_id, C, deposit_amount, expiry)`. The user keeps the secret,
private balance and blinding, current anchor, and server signature locally.
Genesis has balance equal to the deposit and anchor 1. A later spend proves a
valid signature on the deployment-bound commitment and anchor.

Binding `L` into both request and withdrawal commitments prevents a signed
state from being moved to a different membership note. Rerandomization changes
only the blinding term. The server subtracts the bounded usage charge and adds
a fresh blinding delta before signing the next state.

## Proof statements

The public statement structs and exact verifier order are defined by
[inputs.rs](rust/crates/zkapi-types/src/inputs.rs) and
[Types.sol](contracts/src/libraries/Types.sol).

The request statement contains these 12 field elements:

1. protocol version
2. chain ID
3. vault address
4. active root
5. state signing key x
6. state signing key y
7. request time
8. solvency bound
9. request nullifier
10. authorization tag
11. anonymous commitment x
12. anonymous commitment y

The request proof establishes note membership, secret knowledge, genesis or
valid signed state, balance solvency, expiry at least the request time, correct
rerandomization, and the nullifier/authorization tag. The authorization tag
binds the nullifier to a private context derived from the exact client request
ID and payload hash. Runtime validation binds the public deployment, keys,
root, time, and charge bound to the configured service. The request statement
does not bound a signed balance by the deposit; adding that constraint is a
planned circuit change.

The withdrawal statement contains these 14 field elements:

1. protocol version
2. chain ID
3. vault address
4. active root
5. state signing key x
6. state signing key y
7. clearance signing key x
8. clearance signing key y
9. note ID
10. final balance
11. destination address
12. withdrawal nullifier
13. has-clearance flag
14. withdrawal tag

The withdrawal proof establishes membership and the note-bound final state,
reveals the final balance, and binds the nullifier to the destination, balance,
and clearance mode. Mutual close additionally proves the clearance signature.
The vault checks the deployment, pinned keys, a nonzero destination, the
proof's root (the current root, or one replaced within the one-day
`ROOT_HISTORY_WINDOW`), siblings against the current root, note status,
nullifier use, and final balance before settlement.

## Wire format and persistence

[wire.rs](rust/crates/zkapi-types/src/wire.rs) defines the active HTTP schemas.
A clearance request carries `ownership_proof`, an escape-form withdrawal
statement and proof for the same nullifier.
`Groth16ProofWire` carries backend `groth16_bn254` and base64-encoded Arkworks
canonical compressed proof bytes. Public inputs are part of the enclosing
request and are verified directly. The Solidity adapter accepts the EVM proof
encoding produced by the proof library.

The internal `Felt252` name is retained for compatibility, but values are BN254
scalar-field elements. JSON fields use canonical `0x` hexadecimal strings and
reject values at or above the field modulus. Preserve the existing v2 JSON
shapes; numeric handling at browser boundaries is defined by the SDK.

The native wallet journals prepared requests before transport. The runtime
server persists nullifier reservations and finalized transcripts to make
request retries idempotent and to preserve evidence for escape challenges.
Only a finalized transcript is challenge evidence, and every lease is
finalized by a write-once settlement deadline, at worst at its solvency bound.
The browser wallet receives storage and transport from its caller.

## Native ETH settlement

[ZkApiVault](contracts/src/ZkApiVault.sol) accounts in whole gwei. A deposit
must attach exactly `amount * 1 gwei`, have positive amount, and stay within
`MAX_NATIVE_UNITS = 2^53 - 1`. The vault buckets expiry to daily boundaries.

Mutual close removes the active leaf and pays the user's final balance to the
chosen destination and the spent amount to the treasury. Escape initiation
removes the leaf immediately and starts the configured challenge period. A
valid archived request with the matching nullifier challenges the escape and
restores the leaf; unrelated root updates do not invalidate that historical
proof. The challenge clears the nullifier from `usedNullifiers` and sets
`challengedNullifiers`, so a later escape at it reverts `ChallengedNullifier()`
while a cleared mutual close remains possible. An uncontested escape can be
finalized after its deadline. Active notes can be claimed for the treasury
after `effectiveExpiry`, which adds paused time and a post-challenge grace and
is never earlier than `unpauseClaimGrace` after an unpause.

The owner can pause deposits, withdrawals and expiry claims indefinitely;
challenges and escape finalization stay open. Treasury changes are scheduled,
then accepted after `treasuryChangeDelay` of unpaused time, and failed treasury
payments accrue `treasuryArrears` instead of reverting payouts.

## Source ownership

- [zkapi-core](rust/crates/zkapi-core): native hashing and Merkle helpers.
- [zkapi-proof](rust/crates/zkapi-proof): circuits, proving and verification,
  signing, commitments, and setup serialization.
- [zkapi-browser](rust/crates/zkapi-browser): browser wallet core.
- [zkapi-client](rust/crates/zkapi-client): native wallet and persistence.
- [Root runtime crates](../crates): server, challenge service, indexer, and CLI.
- [SDK](../sdk): browser integration and public proof assets.

## Setup compatibility and verification

The wire version is v2 and the circuit ID is `zkapi-v2-note-bound-v1`.
Keys carry that circuit header. Setup files, Solidity verification keys, WASM,
and SDK asset hashes must remain paired. The committed keys use a single-party
setup with no multi-party ceremony. See [the setup README](setup/v2/README.md)
for setup provenance, compatibility requirements, and trust assumptions.

Run protocol Rust tests with
`cargo test --release --manifest-path rust/Cargo.toml --workspace --locked` and contract
tests with `forge test` from `contracts/`. The parent workspace tests the active
HTTP and settlement integration. Regenerating setup keys is a separate change
that requires regenerating all dependent artifacts and deploying their matching
verifier and vault.
