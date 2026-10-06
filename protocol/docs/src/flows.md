# End-to-End Flows

## Request

1. The wallet proves membership and a note-bound state, sufficient balance,
   rerandomization, and authorization for the exact request context.
2. The server verifies deployment, signing keys, time, root, bound, and proof.
3. A durable nullifier reservation prevents competing spends.
4. Provider execution or a short-lived OpenRouter lease determines usage.
5. The server applies the bounded charge, derives fresh blinding and anchor,
   signs the next state with Schnorr, and persists the transcript. A lease
   whose key never reached the wallet settles at zero; a delivered lease whose
   usage is still unavailable at its write-once settlement deadline settles at
   the solvency bound.
6. The wallet verifies the returned transition and installs its next state.
   Prepared-request journals support retries and recovery.

## Mutual close

The client asks for clearance on the current withdrawal nullifier and proves
note ownership with an escape-form withdrawal proof for the same nullifier,
destination and balance. The server verifies it, reserves the nullifier and
returns a clearance signature. The client proves the final balance and
clearance, and the vault removes the note leaf and settles native ETH to the
user and treasury.

## Escape and challenge

The client can prove a withdrawal without clearance. Initiation removes the
leaf and starts the challenge period. A stale state has a nullifier already
used by an accepted request. Once the server finalizes that request's
settlement, the challenge service submits its archived request proof and a
current zero-leaf path; the vault restores the leaf. Historical request roots
remain valid evidence after unrelated note-tree changes. The challenge
releases the nullifier but blocks any further escape at it; the owner recovers
the request's signed successor state from the server and withdraws from it.

After an uncontested deadline, anyone can finalize the pending withdrawal to
its previously bound destination. If the destination rejects the payout or
needs more than 100,000 gas, the vault still closes the note and pays the
treasury share, and credits the payout to that destination; anyone can deliver
it later with `claimEscapePayout(destination)`. If an active note is not
withdrawn, its deposit can be claimed for the treasury after its effective
expiry, which paused time and a challenge extend. Expiry claims are closed
while the vault is paused.
