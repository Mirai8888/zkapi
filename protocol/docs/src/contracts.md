# Solidity Contracts

[ZkApiVault](../../contracts/src/ZkApiVault.sol) accepts native ETH deposits in
whole gwei, maintains the depth-32 active-note tree, and pins the server's state
and clearance signing keys. Amounts are bounded by `2^53 - 1` gwei.

[NoteLeafLib](../../contracts/src/libraries/NoteLeafLib.sol) and
[MerkleUpdateLib](../../contracts/src/libraries/MerkleUpdateLib.sol) use the
[BN254 Poseidon implementation](../../contracts/src/libraries/Bn254Poseidon.sol)
shared with the circuit parameters.

[Groth16ProofAdapter](../../contracts/src/adapters/Groth16ProofAdapter.sol)
verifies the request and withdrawal statements directly. Public deployment
fields and pinned signing keys are checked by the vault before settlement.

Mutual close pays the final balance to the destination and the spent balance
to the treasury. A withdrawal proof may use the current root or one replaced
within `ROOT_HISTORY_WINDOW` (one day; `UnknownRoot()` otherwise), while its
siblings must match the current root (`StaleRoot()`). Escape initiation
immediately removes the active leaf. A matching historical request proof can
challenge a stale escape and restore the leaf; the challenge releases the
nullifier from `usedNullifiers` but records it in `challengedNullifiers`, so
another escape at it reverts `ChallengedNullifier()` while a cleared mutual
close remains possible. Otherwise the user finalizes after the deadline.
Active notes can be claimed for the treasury after `effectiveExpiry`, which
adds paused time, a post-challenge grace, and a grace after each unpause.
[Types.sol](../../contracts/src/libraries/Types.sol) defines the current note
state and proof statements.

The owner can pause deposits, withdrawals, expiry claims and treasury changes
without a time limit; challenges, escape finalization and `claimEscapePayout`
stay open. Treasury changes are scheduled with `setTreasury`, applied with
`acceptTreasury` after `treasuryChangeDelay` of unpaused time, and
cancellable. A treasury that rejects a payment accrues `treasuryArrears`
instead of blocking payouts; anyone can pay them with
`withdrawTreasuryArrears`. An escape destination that rejects its payout, or
needs more than 100,000 gas (`ESCAPE_PAYOUT_GAS`), is credited in
`escapePayoutCredits` instead of blocking the escape; anyone can deliver the
credit with `claimEscapePayout(destination)`, which forwards all gas. A mutual
close to a destination that rejects ETH reverts (it forwards all gas, so a
destination that only needs more gas is paid), and a withdrawal to the zero
address or the vault itself reverts `InvalidDestination()`. The
[vault reference](../../../docs-site/content/docs/api-reference/vault.mdx) lists
every view, error and event.
