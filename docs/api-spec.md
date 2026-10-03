# Native ETH protocol API

The browser SDK sends prompt-free proof authorizations to `zkapi-serverd`.
Inference runs directly against the issued provider key.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Process and deployment summary |
| GET | `/v1/attestation` | Public signing keys and protocol pins |
| GET | `/v2/auth` | Validate the configured Sepolia shared password without side effects |
| GET | `/v2/billing/quote` | Pinned finalized native ETH billing quote |
| POST | `/v2/openrouter/leases` | Verify proof and reserve a bounded runtime key |
| GET | `/v2/openrouter/leases/{client_request_id}` | Non-secret lease status and settlement deadline |
| POST | `/v2/openrouter/leases/{client_request_id}` | Retire and settle the exact lease |
| POST | `/v2/openrouter/leases/{client_request_id}/expire` | Authoritative recovery of an expired or superseded unaccepted request |
| POST | `/v2/withdraw/clearance` | Mutual-close Schnorr clearance for a nullifier whose note ownership is proven |
| GET | `/v2/requests/{client_request_id}` | Recover signed settlement |
| GET | `/v2/nullifiers/{nullifier}` | Recover by nullifier; clients also check it before discarding a transmitted request |

When public `/health` reports `testnet_password_required: true`, all `/v2/*`
routes require `X-ZKAPI-Testnet-Password`. Missing or incorrect passwords return
HTTP 401 with `error_code: "testnet_password_required"` before request parsing.
See [Sepolia shared password](testnet-auth.md) for the complete access,
transport and credential-lifecycle contract. Mainnet is unaffected.

The reference gateway in `docker/aws` also applies coarse per-source limits to
`POST /v2/*` requests. A throttled request never reaches the server: it
returns HTTP 429 with `Retry-After: 5` and
`{"status":"error","client_request_id":"","error_code":"gateway_rate_limited",...,"retriable":true,"retry_after_seconds":5}`.
Retry the exact request after the delay; it is no reason to discard a journal
or prepared withdrawal. See
[request limits](../docker/aws/README.md#request-limits).

A lease uses `ApiRequestV2`: client request ID, canonical prompt-free payload,
payload hash, public inputs and `{backend: "groth16_bn254", proof: "base64..."}`.
The authorization payload includes mode/version and its frozen `billing_quote`.
The server recomputes payload/request binding, validates the native quote and
verifies the proof. Proof bytes contain eight canonical 32-byte coordinates
(256 bytes total). Public inputs, proof coordinates and circuit ID are unchanged.

The runtime key is returned once. Retry/recovery must preserve the exact saved
request and journal, including quote and proof. A native gwei solvency bound is
converted to the provider's USD budget using the frozen quote. Settlement uses
actual provider usage converted back to gwei, then verifies/installs a signed
next balance. An unavailable receipt must not be treated as zero usage.

Settlement always terminates with a signed next balance. Usage is clamped to
the proof-bound limit before conversion, and settlement never re-validates the
frozen quote against the server's current price settings. A lease whose key
never reached the client settles at zero. A delivered lease whose usage is
still unavailable at its write-once `settlement_deadline` settles at
`solvency_bound` and is recorded for operator review. Lease status and
recovery responses carry `settlement_deadline` until then; a finalized lease
reports `charge_basis` (`measured`, `clamped`, `worst_case` or `unissued`),
which the signed payload repeats. Status `cancelled` marks a corrupt server
record that is never signed. See
[settlement terminality](native-eth-billing.md#settlement-terminality).

OA-org issuance includes verifier-backed station/org evidence checked by the
browser's independently pinned verifier. Directly managed keys use durable
disable, grace, usage capture and confirmed deletion before settlement; a
lease still unsettled at its deadline is finalized first and its key is
deleted in the background. The provider's aggregate usage delay remains an
operator assumption for direct mode.

## Clearance

`POST /v2/withdraw/clearance` takes
`{withdrawal_nullifier, ownership_proof: {public_inputs, proof}}`. The
ownership proof is an escape-form withdrawal proof (`has_clearance: false`)
for the same nullifier: `public_inputs` is `WithdrawalPublicInputsV2`, with
`destination` as 20 byte values, and `proof` is
`{backend: "groth16_bn254", proof: "base64..."}`. Build it for the real
destination and current balance; it is also a valid escape input, which lets
its holder delay, but not redirect, the payout.

The server requires the matching nullifier, `has_clearance: false`, its own
deployment and both signing keys, a valid proof, and a root it observed within
`--clearance-root-window-seconds` (default 3600) or the vault's current root.
A request proof is never accepted. Errors:

| Status | `error_code` | Meaning |
| --- | --- | --- |
| 400 | `clearance_ownership_required` | No `ownership_proof`; nothing was reserved; not retriable |
| 400 | `invalid_proof` | The proof does not verify |
| 400 | `invalid_request` | Nullifier, `has_clearance` or signing-key mismatch |
| 400 | `protocol_mismatch` | Another protocol version, chain or vault |
| 409 | `stale_root` | Unknown root; `latest_root` is the vault's `currentRoot()`. Retry the same body, then prove again |
| 409 | `nullifier_used` | The nullifier already authorized a request |
| 503 | `capacity_exhausted` | Verification capacity is busy; retry the same body |

A clearance reservation is permanent and its signature has no expiry. The
server never logs or stores ownership proofs. Public `/health` reports
`clearance_ownership_proof_required`; it is `false` only while the transitional
`--allow-legacy-clearance` setting also accepts proof-less requests, at most
`--legacy-clearance-max-per-minute` (default 60) new ones per minute.

## Indexer

The indexer provides `/v1/tree/root`, `/v1/tree/snapshot`,
`/v1/tree/notes/{note_id}/path`, `/v1/tree/notes/{note_id}/zero-path`, and
`/v1/tree/next-note-id`; see its route source for the
full endpoint set. Each response comes from one head view verified against the
vault's `currentRoot()` and `nextNoteId()` and carries that view's `root`,
`block_number` and `block_hash`; `/v1/tree/root` also returns `next_note_id`.
Without a verified view, these routes return `503` with
`Retry-After: 5` and the constant body
`{"status":"unavailable","error_code":"indexer_unavailable",...,"retriable":true,"retry_after_seconds":5}`.
`/health` (`200` only when `ok`), `/metrics` and `/v1/escapes/pending` are
internal. On-chain mutual close, escape and expiry recovery use the
native vault ABI through the browser SDK.
