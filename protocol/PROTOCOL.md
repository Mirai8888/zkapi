# ZK API Usage Credits

This note describes the active zkAPI v2 usage-credit protocol. The implementation
uses BN254 Groth16 proofs, BN254 Poseidon hashing, Baby-JubJub Schnorr signatures,
and native ETH settlement in whole gwei. See [SPEC.md](SPEC.md) for exact public
statements and [setup compatibility](setup/v2/README.md) for the current circuit
revision and single-party setup trust assumptions.

The goal is: a user deposits funds on-chain once, and then makes many anonymous off-chain API requests. The server must be protected against replay and non-payment, while honest users remain unlinkable.

Compared to the original [RLN-based design](https://ethresear.ch/t/zk-api-usage-credits-llms-and-beyond/24104), this version removes:
- the "two points on a line" construction,
- ticket indices,
- growing refund histories.

Instead, it uses a much simpler **state-anchor chain**: each valid request consumes the user's current private spend state and yields a fresh next state signed by the server.

## Overview

A user registers on-chain with a commitment derived from a secret.  
Off-chain, the user carries a private state consisting of:
- a private balance commitment,
- a one-time state anchor,
- a server signature on that state.

To make a request, the user proves in zero knowledge that:
- they are a registered depositor,
- they know the secret behind the registration commitment,
- they know a valid current state,
- they are authorized to spend from that state,
- they have enough balance for the maximum per-request charge.

The server accepts the request only if the derived nullifier has not been seen before.

After execution, the server computes the actual deduction, updates the private balance, generates a fresh next anchor, signs the new state, and returns it to the user.

The funds remain escrowed on-chain until close-out. The server is paid by net settlement when the user withdraws or when an expired note is claimed.

This makes the protocol naturally sequential: one state authorizes one next request.

## Primitives

- $s$: user secret.
- $C = H(s, 0)$: on-chain registration commitment.
- $D$: prepaid usage deposit locked in the contract.
- $C_{\max}$: maximum ordinary per-request charge.
- $S_{\max}$: optional higher cap for policy-violation deductions.
- $B$: current private available balance.
- $L = H_{\text{leaf}}(\text{noteId}, C, D, T_{\text{exp}})$: active membership leaf.
- $E(B)$: shorthand for the note-bound homomorphic commitment
  $E(B,r,L) = B G + r H + L J$ on Baby-JubJub. The private leaf term remains
  fixed throughout every state transition and rerandomization.
- $\tau$: current state anchor.
- $\sigma_{\text{srv}}$: server signature on the current state $(E(B), \tau)$.
- $x_w$: withdrawal nullifier.
- $\sigma_{\text{clear}}$: server clearance signature on $x_w$ for instant withdrawal.
- $A_{\text{srv}}$: server treasury address.
- $T_{\text{exp}}$: note expiry time / TTL.

Initial private state:
- $B = D$
- $\tau = 1$

## Registration

1. The user samples a secret $s$.
2. The user computes the registration commitment:

$$
C = H(s, 0)
$$

3. The user deposits:

$$
D
$$

into the smart contract.

4. The contract records the deposit amount $D$ and expiry $T_{\text{exp}}$, then inserts the full note leaf $L$ into the on-chain Merkle tree at the note ID.

## Request Generation

To make a request, the user sends:
- payload $M$,
- nullifier $x$,
- rerandomized balance commitment $E(B)_{\text{anon}}$,
- proof $\pi_{\text{req}}$.

The proof $\pi_{\text{req}}$ proves:

1. **Membership**  
   $L = H_{\text{leaf}}(\text{noteId}, H(s, 0), D, T_{\text{exp}})$ is in the active Merkle tree.

2. **Secret knowledge**  
   The prover knows $s$.

3. **Spend authorization**  
   Either:
   - first request:

$$
x = H(s, 1)
$$

   - later request:

$$
x = H(s, \tau)
$$

   where $\tau$ is the previously issued state anchor.

4. **State validity**  
   For non-genesis spends, the prover knows a valid server signature on the current state:

$$
\sigma_{\text{srv}} \text{ on } (E(B), \tau)
$$

5. **Balance correctness**  
   The prover knows the opening of $E(B)$.

6. **Rerandomization correctness**  
   $E(B)_{\text{anon}}$ is a valid rerandomization of $E(B)$.

7. **Solvency**

$$
B \geq C_{\max}
$$

If the optional policy-penalty extension below is enabled, this lower bound becomes:

$$
B \geq \max(C_{\max}, S_{\max})
$$

The public request statement includes an authorization tag binding the request
nullifier to the exact client request ID and payload hash. It also includes a
request time; the proof requires the private note expiry to be at least that
time. The server validates the current time and deployment-bound public inputs.

## Server Verification

Upon receiving a request, the server:

1. verifies $\pi_{\text{req}}$;
2. checks whether $x$ is already in `spent_nullifiers`;
3. rejects the request if $x$ was already seen;
4. otherwise stores $x$ and executes the request.

The server stores **all seen nullifiers**.

Importantly, the server does **not** need to know which state is the user's "latest" one.  
It only needs to enforce one-time use of nullifiers.

## Settlement and State Update

After execution, the server computes the actual deduction $\Delta$, with:

$$
0 \leq \Delta \leq C_{\max}
$$

The updated private balance is:

$$
B_{\text{new}} = B - \Delta
$$

The server then:

1. samples a fresh next anchor $\tau_{\text{new}}$;
2. computes the updated balance commitment $E(B_{\text{new}})$;
3. signs the new state:

$$
\sigma_{\text{new}} = \text{Sign}_{\text{srv}}(E(B_{\text{new}}), \tau_{\text{new}})
$$

4. returns:

$$
(\text{response}, E(B_{\text{new}}), \tau_{\text{new}}, \sigma_{\text{new}})
$$

The user stores:

$$
(E(B_{\text{new}}), \tau_{\text{new}}, \sigma_{\text{new}})
$$

as their new private spend state.

## Optional Policy Penalty Extension

The base protocol only needs the ordinary per-request cap $C_{\max}$.

If a deployment wants a stronger deterrent for policy-breaking requests, it may additionally define:

$$
S_{\max} \geq C_{\max}
$$

When this extension is enabled:
- the request proof must establish $B \geq \max(C_{\max}, S_{\max})$;
- ordinary requests still deduct at most $C_{\max}$;
- a request that violates provider policy may instead apply a policy deduction $\Delta_{\text{policy}}$ with:

$$
0 \leq \Delta_{\text{policy}} \leq S_{\max}
$$

In that case, the server still consumes the current nullifier, computes:

$$
B_{\text{new}} = B - \Delta_{\text{policy}}
$$

and returns a rejection payload together with the fresh next state $(E(B_{\text{new}}), \tau_{\text{new}}, \sigma_{\text{new}})$.

A practical deployment may additionally require the server to attach signed policy metadata, such as a reason code and an evidence hash, so abusive deductions remain externally auditable.

No separate on-chain policy stake or `slashPolicyStake` function is required. The larger policy penalty is just an optional bounded state transition, and it is automatically included in the eventual net settlement $D - B_{\text{final}}$.

## Withdrawal

Withdrawal is modeled as a **final spend** of the current state. The withdrawal nullifier lives in the same nullifier namespace as ordinary requests.

The user chooses a destination address $\text{Dest}$ and prepares:
- a withdrawal nullifier $x_w$,
- a withdrawal proof $\pi_{\text{wd}}$.

The proof shows:

1. membership for the full note leaf $L$ derived from $C = H(s, 0)$;
2. knowledge of $s$;
3. knowledge of the current state $(E(B_{\text{final}}), \tau_{\text{current}}, \sigma_{\text{current}})$;
4. validity of $\sigma_{\text{current}}$ on $(E(B_{\text{final}}), \tau_{\text{current}})$;
5. knowledge of the opening of $E(B_{\text{final}})$, thereby revealing $B_{\text{final}}$ as the final public balance;
6. withdrawal authorization:
   - if the user never spent before:

$$
x_w = H(s, 1)
$$

   - otherwise:

$$
x_w = H(s, \tau_{\text{current}})
$$

The withdrawal tag also binds the nullifier to the destination, final balance, and clearance mode. The user then has two close-out paths.

### Mutual Close (Instant Path)

1. The user sends $x_w$ together with an ownership proof $\pi_{\text{own}}$:
   an escape-form withdrawal proof (no clearance) for the same $x_w$,
   destination and final balance.
2. The server checks whether $x_w$ is already in `spent_nullifiers`, and
   verifies $\pi_{\text{own}}$ against its deployment, signing keys and a
   recent root. Only the note owner can produce it.
3. If both checks pass, the server signs:

$$
\sigma_{\text{clear}}(x_w)
$$

and marks $x_w$ as spent in its nullifier set.

4. The user submits:

$$
(B_{\text{final}}, \text{Dest}, x_w, \pi_{\text{wd}}, \sigma_{\text{clear}})
$$

to the contract.

5. The contract verifies $\pi_{\text{wd}}$ and $\sigma_{\text{clear}}$, then immediately settles the note.

The ownership proof's public statement shows the server the note ID, $B_{\text{final}}$ and $\text{Dest}$ when clearance is requested, slightly before the contract publishes them. $\pi_{\text{own}}$ is also a valid escape-hatch payload, so whoever holds it can start an escape for the same destination and balance; that delays the payout by the challenge window but cannot redirect it.

### Escape Hatch (Fallback Path)

If the server is offline or maliciously refuses to clear the withdrawal, the user submits the same payload without $\sigma_{\text{clear}}$:

$$
(B_{\text{final}}, \text{Dest}, x_w, \pi_{\text{wd}})
$$

The contract verifies $\pi_{\text{wd}}$, removes the active note leaf immediately, and starts the configured challenge window (24 hours by default). The proof may use the current Merkle root or one replaced within the last day; the leaf removal always applies to the current tree.

If the withdrawal is not challenged during that window, the contract settles the note exactly as in the mutual-close path.

## Challenge Rule for Escape-Hatch Withdrawal

This explicitly prevents the user from withdrawing using an **old** state that still reflects a higher balance.

Suppose the user tries to withdraw with an old state:

$$
(E(B_{\text{old}}), \tau_{\text{old}}, \sigma_{\text{old}})
$$

Then the withdrawal nullifier is:

$$
x_w = H(s, \tau_{\text{old}})
$$

But if that old state was already consumed by a later accepted request, then the server already has a valid prior transcript using the same nullifier.

During the escape-hatch challenge window, the server can submit that prior accepted transcript, once the request's settlement is final.  
The contract then rejects the stale withdrawal and restores the note. It releases $x_w$ from its spent set but records it as challenged: no later escape may use $x_w$, so the defeated withdrawal cannot be replayed, while a cleared mutual close still can. The honest user continues from the state the server signed after the request that consumed $\tau_{\text{old}}$, obtained from the server's recovery interface, and withdraws from it.

This is the clean replacement for RLN-style secret-recovery slashing in the simplified design.

## How the Server Gets Paid

Because honest off-chain requests are unlinkable, the contract cannot settle funds on a per-request basis. Instead, it pays the server in aggregate when the note closes.

On either the instant mutual-close path or a successful escape-hatch withdrawal, the withdrawal proof reveals the user's final balance $B_{\text{final}}$. The contract then performs net settlement:

$$
\text{payout to user} = B_{\text{final}}
$$

$$
\text{payout to server} = D - B_{\text{final}}
$$

and closes the note / removes the commitment.

This means the server is paid for the user's entire lifetime of API usage in one aggregated settlement transaction, including any optional policy deductions reflected in the final private balance.

To handle abandoned accounts, each note carries the expiry time $T_{\text{exp}}$. If the note is still open and no withdrawal is in progress after its effective expiry, the server may call:

$$
\text{claimExpired}(\text{noteId}, \text{siblings})
$$

The contract then closes the note and transfers the full deposit $D$ to the server treasury $A_{\text{srv}}$. The effective expiry is $T_{\text{exp}}$ extended by any time the contract spent paused, and by at least one challenge window after a successful challenge. The claim is unavailable while the contract is paused and for a grace period after each unpause. Requests still require $T_{\text{exp}}$ to be at least the request time.

This guarantees that the server is eventually paid even if the user disappears without withdrawing. An implementation may additionally offer a separate rollover / renewal transaction that extends $T_{\text{exp}}$, but that mechanism is orthogonal to the accounting model described here.

## Privacy Note

The current state anchor $\tau$ and the server signature $\sigma_{\text{srv}}$ should remain **private witnesses inside the ZK proof**, not public inputs.

This is important because it prevents the server from trivially correlating requests by directly observing the user's carried state.

In the mutual-close path, the server sees the withdrawal nullifier $x_w$ and, through the ownership proof, the note ID, final balance and destination address. The contract reveals the same values publicly when the user closes the note.

If additional hardening is desired, the next anchor $\tau_{\text{new}}$ can be derived from both server randomness and user-contributed randomness. However, this is best treated as an implementation refinement rather than part of the core protocol.

## Extensions

This base design is **sequential**: one state authorizes one next request.

If parallelism is needed, it should be added as a separate extension, for example by allowing one state transition to mint multiple child anchors.

That should remain outside the base specification so the core design stays simple and easy to reason about.

## Summary

The simplified protocol replaces RLN's line-based nullifier construction with a one-time **state-anchor chain**.

Each request:
- consumes the current state,
- emits one nullifier,
- updates the private balance,
- yields a fresh server-signed next state.

This keeps the main properties we want in the single-server setting:
- anonymous prepaid access,
- unlinkable honest usage,
- replay prevention,
- net settlement at withdrawal or expiry,
- instant mutual close with an optimistic escape hatch,
- optional higher policy-penalty cap via $S_{\max}$.

At the same time, it substantially simplifies both the protocol logic and the proving interface.
