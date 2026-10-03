# Note-bound commitments

A signed balance commitment binds to the same note used by the Merkle-membership
proof:

```text
L = Poseidon(leaf_domain, note_id, registration(secret), deposit, expiry)
C = balance * G + blinding * H + L * J
```

Both request and withdrawal circuits compute `L` from the exact private values
used by the Merkle-membership proof. They use that same `L` to open the signed
commitment. `J` is independently derived with Keccak try-and-increment from
`zkapi.v2.note-binding.generator.v1`, choosing even y and clearing the cofactor.
No known scalar relation to `G` or `H` is introduced. The full canonical BN254
field representation of `L` is multiplied by J, naturally reducing modulo the
Baby-JubJub subgroup order, in both native code and the circuit.

The server updates an anonymous commitment by subtracting `charge * G` and
adding `blind_delta * H`. The note component survives that update without
revealing the note leaf. A fresh uniformly random blinding masks the leaf in
public commitments. Changing the note while retaining the signature requires
breaking the commitment binding/signature or finding an appropriate hash
collision; balancing the deposit amounts alone cannot do it.

This construction relies on the discrete-log binding assumption for the
independent third generator, alongside the Poseidon, Schnorr and Groth16
assumptions. Groth16/BN254 and Baby-JubJub are not post-quantum.

## Compatibility and setup

The circuit identifier is `zkapi-v2-note-bound-v1`. Proving and verifying key
files carry that header; loaders reject files without the expected circuit header
before decoding. Public deployment manifests must advertise
`proof_setup.circuit_id`, and clients must
pin the matching key hashes and vault address. The header guards against
accidental mismatches; it does not establish setup provenance or replace
independently pinned key hashes.

The checked-in `protocol/setup/v2` directory contains a single-party Groth16
setup. The matching Solidity verifier and SDK WASM/proving keys must travel
together. Artifact hashes identify setup files but do not establish that setup
secrets were destroyed. See [setup provenance](../protocol/setup/v2/README.md)
for the trust assumptions.

The vault has an immutable verifier and signing keys. Its circuit, proof
artifacts, denomination, and client pins must match exactly. Wallet state and
recovery journals are bound to that configuration. See
[native ETH billing](native-eth-billing.md) for asset and quote configuration.

## Challenge and settlement requirements

Operate `zkapi-challenged` alongside the server and indexer, with durable retries
and an explicit restricted signer. Challenges preserve the historical request
root and use a current restoration path. Only a finalized transcript is
challenge evidence, so an escape from a state whose lease is still settling
waits for that settlement. Keep the API server available through every
challenge window. See [service operation](challenge-service.md).

Direct OpenRouter retirement persists disable, grace, usage capture and
revocation stages and does not sign before confirmed deletion while its
settlement deadline has not passed. At that write-once deadline the server
signs the captured usage, or the proof's solvency bound if none was captured,
and keeps deleting the key in the background. Its aggregate usage API supplies
no authoritative final receipt: the configured grace must cover in-flight
calls and accounting delay. OA-org finalized receipts provide a separate
settlement path.
