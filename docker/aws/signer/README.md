# Deployment-bound challenge signer

This internal JSON-RPC sidecar supplies `eth_sendTransaction` to
`zkapi-challenged`. It signs only canonical `challengeEscapeWithdrawal` calls
for one configured vault and explicitly configured chain (Mainnet 1 or
Sepolia 11155111), from its dedicated key, with zero ETH value. It decodes the
complete ABI, checks the proof's deployment, simulates the call again, and
checks the gas, fee, transaction fee and balance bounds before signing an
EIP-1559 (type 2) transaction with ethers. It does not expose generic signing or raw-transaction
forwarding.

## Configuration

Copy [`../signer.env.example`](../signer.env.example) to `/etc/zkapi/signer.env`
(root-owned, mode `0600`). Only the signer container receives this file. Wei and
gas values are positive decimal integers: hex, signs, exponents, whitespace and
leading zeros are refused, and an empty value means the default.

| Variable | Default | Meaning |
| --- | --- | --- |
| `ZKAPI_CHALLENGE_PRIVATE_KEY` | required | Dedicated, funded sender key for this deployment. |
| `ZKAPI_CHALLENGE_RPC_URL` | required | Upstream RPC for the chain: HTTPS, or HTTP on loopback only. |
| `ZKAPI_CHALLENGE_CHAIN_ID` | required | Canonical `1` or `11155111`; no default or fallback. |
| `ZKAPI_CHALLENGE_VAULT` | required | The vault this signer may challenge on. |
| `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` | required on chain 1; 10 gwei on Sepolia | Fee cap: the highest `maxFeePerGas` the signer signs, and the bid when the caller proposes no fees. |
| `ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI` | min(1 gwei, tip cap) | Tip of a bid made without proposed fees. |
| `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI` | min(fee cap, 10 x default tip) | Tip cap: the highest `maxPriorityFeePerGas` the signer signs. At most the fee cap. |
| `ZKAPI_CHALLENGE_FEE_CEILING_WEI` | 10,000 gwei; at most 1,000,000 gwei | Typo guard: the fee cap must not exceed it. |
| `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` | 1 ETH (`1000000000000000000`) | Transaction fee cap: the highest gas limit x `maxFeePerGas` the signer signs, for proposed and default bids alike. Match the upstream node's `--rpc.txfeecap`; see [Node transaction fee cap](#node-transaction-fee-cap). The upgraded challenger reads its own copy from `deployment.env`; the earlier challenger ignores it. |
| `ZKAPI_CHALLENGE_MAX_GAS` | 12,000,000; at most 16,777,216 | Gas limit cap. |
| `ZKAPI_CHALLENGE_LISTEN_HOST`, `ZKAPI_CHALLENGE_PORT` | `127.0.0.1`, `8547` | Bind address. Compose sets the host to `0.0.0.0` on its private backend network and publishes no signer port. |
| `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI` | removed | Startup refuses while it is present, even when empty, because its meaning changed. |

**Mainnet rule:** with `ZKAPI_CHALLENGE_CHAIN_ID=1` the signer refuses to start
unless `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` is set. Only Sepolia has a default
cap, which status and the startup line report as `fee_cap_source: "default"`.
Use a fresh exclusive sender for each network and deployment. Daemon
chain/vault, signer chain/vault, decoded proof and upstream chain must all
agree.

Never proxy this service to the public internet. `GET /health` returns 200 only
while the upstream reports the configured chain, with the sender, vault and
static fee policy; otherwise 503. Use its sender as the challenge daemon's
`--sender`, and point that daemon's RPC URL at `http://signer:8547`. At startup
the signer prints one JSON line with `fee_model: "eip1559"`, the effective
policy, the balance, the latest base fee and any warnings (decimal wei). The
policy includes `tx_fee_cap_wei` and `max_fee_per_gas_allowed_at_max_gas_wei`,
the highest `maxFeePerGas` a `MAX_GAS` transaction can bid within it. It
refuses to start when the upstream is unreachable, reports another chain or
returns a block without a base fee; balance and fee warnings do not block
startup.

## Fee model

Every transaction is type 2. The chain charges `min(maxFeePerGas, baseFee +
maxPriorityFeePerGas)` per gas, so `maxFeePerGas` is the most it can ever pay.
The caller may propose both `maxFeePerGas` and `maxPriorityFeePerGas`, or
neither:

- with neither (a challenger that predates fee proposals), the signer bids
  the fee cap with the default tip, and refuses with `tx_fee_above_cap` when
  gas limit x fee cap exceeds the transaction fee cap;
- with both, the signer signs exactly those values if `0 < tip <= maxFeePerGas
  <= fee cap` and `tip <= tip cap`; otherwise it refuses with
  `fee_out_of_bounds` and calls nothing upstream.

The upgraded `zkapi-challenged` always proposes both. Its own caps
(`ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` and
`ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI` in `challenge.env`) must not
exceed this signer's, and it bids within the lower of its own
`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` (in `deployment.env`) and this signer's
`tx_fee_cap_wei`. The default tip cap is deliberately a small multiple of
the default tip, so a caller on the backend network cannot make every challenge
pay the whole cap as tip unless the operator raises it.

Choose the fee cap at or above the highest base fee the deployment must survive
for a whole challenge window times 1.125, plus the tip you expect to pay: the
next block's base fee can be 12.5% higher than the latest, and a bid whose cap
only matches the base fee leaves builders no tip. The signer refuses to sign
while the latest base fee exceeds the transaction's `maxFeePerGas`. Status warns
before that, when `baseFee x 1.125 + default tip > fee cap`. The node's
transaction fee cap (below) also bounds what any bid can offer.

There is deliberately no aggregate spending budget beyond the sender balance.
The signer is stateless: each transaction is bounded by gas limit x
`maxFeePerGas` (at most `MAX_GAS` x fee cap, and never above the transaction
fee cap), and the total only by what the sender holds. Fund it to the target
below rather than far beyond it.

### Node transaction fee cap

geth and reth refuse `eth_sendRawTransaction` before the transaction reaches
their pool when its gas limit x `maxFeePerGas` exceeds `--rpc.txfeecap`, which
defaults to 1 ETH. With that default and a real challenge's gas limit of about
7.53M, no bid above about 132.7 gwei can be broadcast, whatever the fee cap.
Either:

- raise the node's `--rpc.txfeecap` and `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`
  together, in `signer.env` and, for the upgraded challenger, in
  `deployment.env`, for example to 3.6 ETH for a 300 gwei fee cap at the
  default 12M `ZKAPI_CHALLENGE_MAX_GAS`; or
- keep the fee cap within the transaction fee cap divided by the challenge's
  gas limit: about 132.7 gwei at 1 ETH for 7.53M gas, or about 131.6 gwei to
  leave room up to 7.6M. A hosted provider's cap usually cannot be raised.

The signer checks every bid, proposed or default, against
`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` before any upstream call and refuses a larger
one with `tx_fee_above_cap`, which reports the highest `maxFeePerGas` that gas
limit allows. Status warns `tx_fee_cap_below_fee_cap` while
`ZKAPI_CHALLENGE_MAX_GAS` x fee cap exceeds it. That warning assumes the largest
gas limit the signer accepts, so it is conservative: at the default 12M gas and
1 ETH it appears above a fee cap of about 83.3 gwei, while a 7.53M-gas challenge
still signs at the full fee cap up to about 132.7 gwei. Lowering
`ZKAPI_CHALLENGE_MAX_GAS` toward the challenge's gas limit clears it (8M allows
125 gwei, 7.6M about 131.6 gwei). That changes the warning and the gas limit
bound, not which bids fit the transaction fee cap. Keep a margin above the
measured 7.53M, which is the daemon's gas estimate plus 20%: a challenge whose
gas limit exceeds `ZKAPI_CHALLENGE_MAX_GAS` is refused with
`gas_limit_exceeds_cap` (the upgraded challenger reports `signer_refused`,
critical at once), and at 7.6M one 0.9% costlier than measured already is.
8M leaves about 6%.

If the node's cap is lower than the variable, geth refuses the broadcast with
`tx fee (1.07 ether) exceeds the configured cap (1.00 ether)`, and the signer
reports `upstream_tx_fee_cap`: nothing was broadcast. Only that wording is
recognized; another client's refusal stays `broadcast_ambiguous`, so never set
the variable above the node's cap. The signer takes the node's refusal as
final: use one node, or a provider whose nodes share one cap. The signer's
status has no warning for this case, because the signer cannot read the node's
cap; the upgraded challenger's `/status` warns once the node refused a fee, and
the audit log has a `challenge_refused` line for the first such refusal of each
nonce (see [Operation](#operation)).

## Funding

Pools reserve gas limit x `maxFeePerGas` for each pending transaction before
any fee is paid, and geth sums the cost of all of a sender's pending
transactions. The signer checks each transaction against gas limit x its
`maxFeePerGas` before signing. Fund the sender with at least:

```text
(N + K) x gasLimit x feeCap
```

`N` is the number of challenges that may be pending at once, and `K` a budget of
reverted attempts. A challenge that reverts still pays for its gas, for example
when an unrelated deposit changes the vault root after the simulation, and the
daemon then retries. A real Groth16 challenge measured 6,278,618 gas; with the
daemon's 20% buffer its gas limit is about 7.53M: 0.75 ETH per challenge at a
100 gwei cap, within the default 1 ETH transaction fee cap. A 300 gwei cap
needs the node's `--rpc.txfeecap` and `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` raised to
at least 2.28 ETH (7.6M gas x 300 gwei, which leaves room above the measured
7.53M); at the default no challenge reserves more than 1 ETH.
Re-measure after redeploying the vault. `zkapi_signerStatus.required_balance`
is `MAX_GAS` x fee cap, a conservative figure for one challenge. Multiply it for
concurrency and the retry budget.

## JSON-RPC interface

`eth_sendTransaction [{from, to, data, gas, nonce, maxFeePerGas?,
maxPriorityFeePerGas?}]` takes canonical hex quantities. `value` (only `0x0`)
and `chainId` (only the configured chain) are also accepted. `gasPrice`, `type`,
`accessList`, `authorizationList`, `input` and blob fields are refused. The
caller's nonce is always used; the signer never allocates one. Sends are
serialized. The result is the transaction hash, keccak256 of the signed raw
transaction. Errors have the form `{code, message, data: {reason, ...}}`, with
wei values as hex quantities:

| Code | `data.reason` | Other `data` | Meaning |
| --- | --- | --- | --- |
| -32602 | `fee_out_of_bounds` | `max_fee_per_gas`, `max_priority_fee_per_gas` (the configured caps) | Fee fields not both-or-neither, or outside the bounds above. |
| -32602 | `gas_limit_exceeds_cap` | `max_gas` | Gas limit above `ZKAPI_CHALLENGE_MAX_GAS`. |
| -32602 | `gas_estimate_exceeds_limit` | `estimate` | A fresh estimate exceeds the requested gas limit. |
| -32602 | none | none | Any other authorization failure; the message is a fixed string. |
| -32003 | `base_fee_above_max_fee` | `base_fee_per_gas`, `max_fee_per_gas` | The latest base fee exceeds this transaction's `maxFeePerGas`. Retry the same nonce later or with a higher bid. |
| -32003 | `insufficient_balance` | `balance`, `required_balance` | The balance is below gas limit x `maxFeePerGas`. Fund the sender. |
| -32003 | `tx_fee_above_cap` | `gas_limit`, `max_fee_per_gas`, `tx_fee_cap_wei`, `max_fee_per_gas_allowed` (floor of the cap / gas limit) | Gas limit x `maxFeePerGas`, proposed or default, exceeds `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`. Checked before any upstream call. Bid at most `max_fee_per_gas_allowed`. |
| -32003 | `upstream_tx_fee_cap` | `gas_limit`, `max_fee_per_gas` | The upstream node refused the broadcast because gas limit x `maxFeePerGas` exceeds its own `--rpc.txfeecap`, which is below `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`. The node refuses before its pool, so nothing was broadcast. Lower the variable to the node's cap, or raise both. |
| -32000 | `upstream_unavailable`, `upstream_rejected`, `upstream_chain_mismatch`, `base_fee_unavailable`, `simulation_failed` | none | Upstream or simulation failure. Transient. |
| -32603 | none | none | Signer self-check failed or an internal error. |
| -32000 | `broadcast_ambiguous` | `transaction_hash` | The broadcast was attempted and its outcome is unknown. |

Every error except `broadcast_ambiguous` means nothing was broadcast. All of
them except `upstream_tx_fee_cap` are returned before `eth_sendRawTransaction`
is attempted; `upstream_tx_fee_cap` is the node's own fee-cap refusal of the
attempt (see [Node transaction fee cap](#node-transaction-fee-cap)). Any other
rejection of the broadcast, a transport error, a timeout or a malformed reply is
`broadcast_ambiguous`.
`broadcast_ambiguous` always carries the candidate hash: keep every candidate
hash for the nonce until the nonce is consumed, and look them up before sending
a different payload on it. A transport failure or timeout between the daemon
and the signer must also be treated as possibly broadcast. Signing is
deterministic, so re-sending an identical request is idempotent: an "already
known" answer from the pool returns the same hash as success.
`simulation_failed` covers every upstream error from `eth_call` or
`eth_estimateGas`, including provider rate limits, so it is transient and never
proves the evidence invalid. Each upstream call times out after 8 seconds, and a
send waits on at most six sequential upstream round trips (the base-fee and
balance reads run in parallel), about 48 seconds at worst. Give the daemon an
`eth_sendTransaction` timeout of at least 90 seconds.

`zkapi_signerStatus []` returns `{chain_id, sender, vault, transaction_type:
"0x2", fee_cap_source, max_fee_per_gas, priority_fee_per_gas,
max_priority_fee_per_gas, fee_ceiling, tx_fee_cap_wei, max_gas,
required_balance, block_number, base_fee_per_gas, balance, warnings}`. Wei
values are hex quantities that can exceed 64 bits (parse them as u128). The
upgraded challenger bids within the lower of its own
`ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` and `tx_fee_cap_wei`; the earlier challenger
ignores the field. `warnings` lists:

- `base_fee_above_cap`: the latest base fee exceeds the fee cap; every bid is
  refused;
- `base_fee_near_cap`: base fee x 1.125 + default tip exceeds the fee cap, so
  the next blocks may price out the default bid (also present whenever
  `base_fee_above_cap` is);
- `balance_below_required`: the balance is below `required_balance`;
- `tx_fee_cap_below_fee_cap`: `MAX_GAS` x fee cap exceeds the transaction fee
  cap, so bids near the fee cap at large gas limits are refused with
  `tx_fee_above_cap`. A bid is refused only when its own gas limit x
  `maxFeePerGas` exceeds the cap, so this warning can appear while real
  challenges, well below `MAX_GAS`, still sign at the fee cap (see
  [Node transaction fee cap](#node-transaction-fee-cap)).

The read-only passthrough allows `eth_chainId`, `eth_blockNumber`,
`eth_getBlockByNumber`, `eth_getLogs`, `eth_getTransactionReceipt`,
`eth_getTransactionByHash`, `eth_getTransactionCount`, `eth_call`,
`eth_estimateGas`, `eth_getBalance` and `eth_feeHistory`. Every other method
returns -32601.

## Replacing a pending challenge

Geth and reth accept a transaction on the same nonce as a pending one only when
both `maxFeePerGas` and `maxPriorityFeePerGas` rise by at least 10% (geth
`txpool.pricebump`). Raise both by at least 12.5%. A tip-only bump is rejected
everywhere and returns `broadcast_ambiguous` with the rejected candidate's hash.
Either transaction may still mine, so keep both hashes. Re-sending after the
pool dropped a transaction has no bump requirement. A legacy transaction still
pending from signer 0.1 counts its `gasPrice` as both fees, so replacing it needs
a tip of at least 1.1 x that `gasPrice`. Anvil accepts any replacement with a
higher `maxFeePerGas`, so the anvil tests cannot prove the 10% rule.

## Fee-spike runbook

With the **earlier `zkapi-challenged`**, from a release before this one (it
proposes no fees, so every challenge bids the fee cap with the default tip):

- Every challenge whose gas limit x fee cap exceeds the transaction fee cap is
  refused at any base fee (`tx_fee_above_cap`, or `upstream_tx_fee_cap` from
  the node): at the default 1 ETH, a fee cap above about 132.7 gwei refuses
  every 7.53M-gas challenge. This daemon retries a refused challenge on the
  same nonce at every poll and holds back the challenges queued after it; once
  the deadline passes, it keeps the nonce and reports
  `signer intervention required`. So keep the fee cap within that limit while
  it runs (about 131.6 gwei leaves room up to a 7.6M gas limit), or first raise
  the node's `--rpc.txfeecap` and `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` together.
  The refused challenge signs on the next poll once its bid fits. A
  `tx_fee_cap_below_fee_cap` warning alone does not mean that challenges are
  refused; see [Node transaction fee cap](#node-transaction-fee-cap).
- A refused challenge (`base_fee_above_max_fee`, `insufficient_balance`) signs
  on the daemon's next poll after you raise `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI`
  (within the transaction fee cap) or fund the sender. Restart the signer to
  apply a new cap:
  `sudo docker compose -f docker/aws/compose.yml --profile challenge up -d signer`.
- A dropped challenge is re-sent on the same nonce at the new cap.
- This daemon never replaces a still-pending challenge. Geth and reth usually
  keep a transaction whose `maxFeePerGas` is below the base fee in their pools
  until the base fee falls. To replace it by hand, raise both
  `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` and
  `ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI` by at least 12.5% (gas limit x the
  new cap must stay within the transaction fee cap), restart the
  signer, read the pending transaction with `eth_getTransactionByHash`, and send
  its `from`, `to`, `input` (as `data`), `gas` and `nonce` back through the
  signer without fee fields. Run both calls from the challenger container:

  ```sh
  sudo docker compose -f docker/aws/compose.yml --profile challenge exec challenger \
    curl -s -X POST http://signer:8547 -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["0x<pending hash>"]}'
  sudo docker compose -f docker/aws/compose.yml --profile challenge exec challenger \
    curl -s -X POST http://signer:8547 -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":2,"method":"eth_sendTransaction","params":[{"from":"0x..","to":"0x..","data":"0x..","gas":"0x..","nonce":"0x.."}]}'
  ```

  The daemon may log send errors until the replacement mines. If the vault root
  changed since the original was built, the simulation fails and the original
  would revert anyway. On Mainnet, do not rely on this procedure: deploy this
  signer together with the upgraded challenger.

With the **upgraded `zkapi-challenged`** (it proposes both fees), the daemon
replaces its own pending challenge on the same nonce, raising both fees by at
least the bump up to its caps, and jumps to its caps near the deadline. When its
status reports that it reached its caps, raise the signer's caps in `signer.env`
and restart the signer first, then raise the daemon's caps in `challenge.env`
(never above the signer's) and restart the challenger. It never bids above the
transaction fee cap / gas limit (about 132.7 gwei at 1 ETH for 7.53M gas), so
when it reports `tx_fee_cap_reached`, raising the fee caps changes nothing:
raise the node's `--rpc.txfeecap` first, then `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`
in `signer.env` (restart the signer) and in `deployment.env` (restart the
challenger). A `tx_fee_above_cap` or `upstream_tx_fee_cap` refusal means these
settings disagree; nothing was broadcast. After `upstream_tx_fee_cap` the
challenger bids within 10/11 of the lowest refused transaction fee until it
restarts, so it keeps challenging below the node's cap. Restart it after
aligning the caps.

**Private relays.** The upstream is used for reads, simulation and broadcast. A
private or MEV-protection relay may not expose pending transactions through
`eth_getTransactionByHash`. Then the idempotent re-send check and the daemon's
pending tracking report unknown transactions, which leads to
`broadcast_ambiguous` errors and re-sends. Relays may also delay, refuse or
silently drop same-nonce replacements and transactions, and some do not serve
the reads above. Prefer a full-node RPC. Verify a relay's pending visibility and
replacement behaviour on Sepolia before Mainnet.

## Upgrading from 0.1

The new signer is backward compatible with the earlier challenger and the
unchanged challenge ABI, as long as that challenger's bids fit the transaction
fee cap (step 1).

1. Remove `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI` from `signer.env`. It capped
   `eth_gasPrice` for legacy transactions; the new fee cap is bid as
   `maxFeePerGas`. Set `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI`, which is required
   on Mainnet, and set `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` to the upstream node's
   `--rpc.txfeecap` unless that is the default 1 ETH. The earlier challenger
   bids the full fee cap on every challenge, so while it runs, every challenge
   whose gas limit x fee cap exceeds the transaction fee cap is refused: at
   1 ETH, a fee cap above about 132.7 gwei refuses every 7.53M-gas challenge.
   That challenger then retries the refused challenge and holds back the ones
   after it (see the [fee-spike runbook](#fee-spike-runbook)), so choose a fee
   cap within that limit, or raise the node's cap and the variable together.
2. Fund the sender as above, then rebuild and restart the signer, and check its
   startup line and `zkapi_signerStatus`:

   ```sh
   sudo docker compose -f docker/aws/compose.yml --profile challenge build signer
   sudo docker compose -f docker/aws/compose.yml --profile challenge up -d signer
   sudo docker compose -f docker/aws/compose.yml --profile challenge exec challenger \
     curl -s -X POST http://signer:8547 -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"zkapi_signerStatus","params":[]}'
   ```

   Expect `warnings: []` before relying on the deployment. A sender funded
   with less than `required_balance` (`MAX_GAS` x fee cap, more than one
   7.53M-gas challenge needs) shows `balance_below_required`; fund up to it, as
   [Funding](#funding) asks. The one other exception is
   `tx_fee_cap_below_fee_cap` with a fee cap above the transaction fee cap /
   `ZKAPI_CHALLENGE_MAX_GAS` but within the step 1 limit (about 83.3 to 132.7
   gwei at 1 ETH and the default 12M gas): real challenges still sign there.
   Prefer to clear it by lowering `ZKAPI_CHALLENGE_MAX_GAS` toward the
   challenge's gas limit with a margin, for example 8M (see
   [Node transaction fee cap](#node-transaction-fee-cap)), which also lowers
   `required_balance`.
   Never drop the warning from alerting: while the earlier challenger runs, the
   same warning also appears for fee caps at which every challenge is refused.
   Suppress it only while `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` x 7.6M gas is at
   most `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI` (about 131.6 gwei at 1 ETH), and check
   that again after every fee-cap change.
3. Upgrade the existing deployment in place: same vault, same sender. Run a
   redeployed vault as a separate stack with its own signer, fresh sender key,
   challenger and data directory. Never repoint a signer or challenger away
   from a vault that still has active notes or pending escapes.
4. On Mainnet, deploy the upgraded challenger together with this signer.

## Operation

The challenge daemon owns nonce reservation and its durable checkpoint. This
sidecar requires the explicit nonce and never allocates another on ambiguous
send failures. Run only one challenge daemon for the deployment and never use
its dedicated sender for other transactions. No signer state is written to
disk; the container can use a read-only filesystem. Its audit lines
(`challenge_refused` once per reason change of a nonce, `challenge_signed` once
per hash) contain no raw transactions, upstream text or key material. Alert on
status `warnings` (for `tx_fee_cap_below_fee_cap`, see step 2 of
[Upgrading from 0.1](#upgrading-from-01)) and on `challenge_refused` lines with
reason `base_fee_above_max_fee`, `insufficient_balance`, `tx_fee_above_cap`,
`upstream_tx_fee_cap` or `broadcast_ambiguous`. The signer's status has no
warning for a node cap below `ZKAPI_CHALLENGE_TX_FEE_CAP_WEI`. The upgraded
challenger's `/status` warns once its node refused a fee (`the signer's node
refused a transaction fee of ... wei (upstream_tx_fee_cap)`), and the audit log
has a `challenge_refused` line for the first such refusal of each nonce: the
refusals that follow on that nonce, at lower bids, repeat its reason and are
not logged again. Keep the private key out of the server/indexer/challenger
environments and deployment manifests.

## Tests

Run `npm ci --ignore-scripts && npm test` here. The unit tests use a public
fixture key and mock RPC responses. They decode the actual ethers signatures and
cover the fee bounds, the Mainnet cap rule, strict configuration, refusal
reasons, the transaction fee cap and a node's fee-cap refusal, the no-broadcast
guarantee, candidate hashes, idempotent re-sends, status warnings, mismatched
deployment bindings, forbidden methods, durable nonce retries and sanitized
HTTP errors. `npm run test:anvil` runs a disposable anvil (`--chain-id
11155111`, automine off). It checks the price actually charged, the base-fee and
balance refusals, and same-nonce replacement. Anvil has no `--rpc.txfeecap`, so
the fee-cap test puts a JSON-RPC proxy in front of it that refuses broadcasts
above 1 ETH with geth's exact error. Without anvil those tests are skipped
unless `ZKAPI_REQUIRE_ANVIL=1`, which makes a missing anvil a failure. No test
broadcasts to a public chain.
