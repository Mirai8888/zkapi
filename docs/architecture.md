# Native ETH architecture

```text
Host app -> browser SDK -> zkAPI server (proof-backed lease authorization)
                   |                  -> OA org/station or direct key management
                   |-> inference provider (prompts/responses)
                   |-> Ethereum native ETH vault
                   |-> indexer (current Merkle root and paths)

Challenger -> finalized server transcripts + indexer -> restricted EIP-1559 signer -> vault
```

The browser keeps note secrets, blindings, signing evidence and recovery journals.
It creates Groth16 proofs locally with the packaged WASM and matching keys.
The server verifies each exact authorization, reserves its nullifier, issues a
bounded key and persists settlement before returning a new signed balance.

The authorization includes a pinned finalized ETH/USD quote. Notes and signed
balances are integer gwei; provider costs are micro-USD converted using that
saved quote. Exact retries preserve the original proof and quote. See
[native billing](native-eth-billing.md) for rounding and recovery rules.

The indexer mirrors deposits, closes and escape transitions, and serves only a
view it has verified against the vault's root and next note ID. The
challenger uses a request as evidence only after its settlement is finalized,
preserves historical request proofs while obtaining current restoration paths,
and retries through durable deployment-bound checkpoints. It reports each
obligation on private status endpoints. See
[challenge operation](challenge-service.md).

Settlement always finalizes: a lease that never reached the wallet settles at
zero, and a delivered lease whose usage is still unavailable at its write-once
deadline settles at the proof's solvency bound. The API server must stay
available through every challenge window, because owners recover their next
signed state from it after a challenge. Mutual close sends the server an
escape-form withdrawal proof of note ownership before it signs a clearance.
The vault owner can pause exits without a time limit and schedule time-locked
treasury changes; in this vault revision a pause cannot move funds or expire
notes. See
[owner and operator powers](../docs-site/content/docs/protocol.mdx#owner-and-operator-powers)
and the [hardened vault migration](migration-hardened-vault.md).

Only the v2 Groth16/Baby-JubJub proof path and native ETH payment path are active.
The operator CLI supplies server/indexer/setup/signing-key commands; the host
application integrates the browser SDK directly. The separate [zkapi-clientd](../zkapi-clientd/README.md) frontend provides a local
OpenAI-compatible API backed by private native ETH balances. It packages a
pinned Rust wallet/prover with reviewed patches, separately from
this operator workspace. It has no ticket mode or token wallet. It checks
deposits and withdrawals against the vault and the operator's indexer before
changing private state.
