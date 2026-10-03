# Native ETH operator deployment

This image runs the native ETH API, indexer and escape challenger with the exact
`protocol/setup/v2` artifacts. Supply the matching vault/signing keys and pinned
native oracle configuration. Upgrading a running deployment to this release is
covered in [the hardened-vault migration guide](../../docs/migration-hardened-vault.md).

Build on a Linux VM with Docker Engine and Compose, from the complete source
tree, including the in-repository `protocol/` source:

```sh
sudo install -d -m 0700 /etc/zkapi
sudo install -d -m 0700 -o 10001 -g 10001 /var/lib/zkapi
sudo docker compose -f docker/aws/compose.yml --profile challenge build server gateway signer
```

Create these root-owned, mode `0600` files without printing their contents:

| File | Contents |
| --- | --- |
| `/etc/zkapi/deployment.env` | Copy `deployment.env.example`, then supply vault address, chain, deployment block, gwei request cap, `ZKAPI_NATIVE_BILLING_RPC_URL`, `ZKAPI_NATIVE_PRICE_FEED_ADDRESS`, feed decimals and freshness policy. It also sets the lease settlement deadline and the indexer's confirmation depth and head-age limit. |
| `/etc/zkapi/indexer.env` | `RPC_URL`, the chain's read RPC endpoint (requirements below). |
| `/etc/zkapi/server.env` | `ZKAPI_STATE_SEED` and `ZKAPI_CLEAR_SEED` (required, below), and `ZKAPI_OPENROUTER_MANAGEMENT_KEY` for direct leases; alternatively set `OA_ORG_URL` in deployment metadata and `ZKAPI_OA_ORG_SHARED_SECRET` here. For private Sepolia access, also set `ZKAPI_TESTNET_PASSWORD` here only. |
| `/etc/zkapi/challenge.env` | `ZKAPI_CHALLENGE_RPC_URL=http://signer:8547`, `ZKAPI_CHALLENGE_SENDER` (the exclusive funded sender managed by the private sidecar), and the daemon's fee caps (below). |
| `/etc/zkapi/signer.env` | Copy [`signer.env.example`](signer.env.example): `ZKAPI_CHALLENGE_PRIVATE_KEY`, `ZKAPI_CHALLENGE_CHAIN_ID`, `ZKAPI_CHALLENGE_RPC_URL` (the upstream RPC for the chain), `ZKAPI_CHALLENGE_VAULT` (the configured vault) and the fee cap. Only the signer container receives this file. |

Also create `/etc/zkapi/config.json` with mode `0644`: this is the public client
manifest containing the contract, signing-key, circuit and proving-key
hash pins. The gateway mounts it read-only and serves exactly `/config.json`,
`/proofs/request.pk`, `/proofs/withdrawal.pk`, and `/proofs/manifest.json` as static
artifacts. Proving keys are copied into the gateway image from the same checkout
as the daemon image. Other files and directories are not served.

Compose reads these as environment files; quote values containing `$`, `#` or
other Compose env-file syntax appropriately. Keep credentials out of compose
command arguments and images. `docker compose config` expands secrets, so use
`config --quiet` for validation.

### Signing seeds

`ZKAPI_STATE_SEED` and `ZKAPI_CLEAR_SEED` are required. There is no default, and
an empty value counts as missing. Generate both directly into `server.env`:

```sh
sudo sh -c 'umask 077; printf "ZKAPI_STATE_SEED=0x%s\nZKAPI_CLEAR_SEED=0x%s\n" "$(openssl rand -hex 31)" "$(openssl rand -hex 31)" >> /etc/zkapi/server.env'
```

`zkapi serverd` and `zkapi signing-keys` refuse a seed that is zero or a multiple
of the Baby-JubJub subgroup order, any seed whose key is one of the published
development keys (seeds `0x1` and `0x2`, in any spelling and either role), a
secret within 2^128 of zero or of the subgroup order (which includes every seed
of 16 bytes or fewer), and one key used for both roles. Errors name the role,
never the seed. Print the public keys for the vault constructor
(`STATE_SIGNING_KEY_X/Y` and `CLEARANCE_SIGNING_KEY_X/Y` of `Deploy.s.sol`) with:

```sh
sudo docker compose -f docker/aws/compose.yml run --rm --no-deps --entrypoint zkapi server signing-keys
```

Before it opens `/data/server.db` for writes, the server checks that
`ZKAPI_NATIVE_BILLING_RPC_URL` serves `CHAIN_ID` (`eth_chainId`), then reads the
vault's `stateSigningKeyX/Y()`, `clearanceSigningKeyX/Y()` and
`challengePeriod()` at `latest`. It refuses to start unless both derived public
keys equal the vault's; the error says which role differs and whether the seeds
look swapped. The vault keys are immutable, so the fix is the seeds whose keys
were passed to the vault constructor. An unreachable RPC is tried five times,
1, 2, 4 and 8 seconds apart (each call waits up to 15 seconds); the server then
exits and Compose restarts it. The healthcheck allows 120 seconds for this.

After a successful check the server records a `deployment_binding` row (chain,
vault, both public keys and `challengePeriod()`) in its database. A restart on
that database with the same chain, vault and seeds starts without the RPC and
re-verifies in the background (from 1 second, doubling to 60). Only a definitive
contradiction, vault keys or `challengePeriod()` that differ from the record,
stops the server; an unavailable or wrong-chain RPC is logged and retried. A
database bound to another chain or vault is refused before any RPC call, so use
one data directory per deployment. After a crash that leaves an unfinished
SQLite transaction, the server cannot read the binding read-only and runs the
RPC check again. The challenger refuses to start until this row exists.

Allow these calls on `ZKAPI_NATIVE_BILLING_RPC_URL`; it must also support the
`finalized` block tag:

| Call | Target | Block | Purpose |
| --- | --- | --- | --- |
| `eth_chainId` | | | Chain check before every vault read |
| `eth_call` `0x15fa2a9a`, `0x230e2a24` | vault | `latest` | `stateSigningKeyX()`, `stateSigningKeyY()` |
| `eth_call` `0xdc41d636`, `0x112cd6bc` | vault | `latest` | `clearanceSigningKeyX()`, `clearanceSigningKeyY()` |
| `eth_call` `0xf3f480d9` | vault | `latest` | `challengePeriod()` |
| `eth_call` `0xfdab463d` | vault | `latest` | `currentRoot()`, for clearance ownership proofs |
| `eth_call` `0x4d1352fd` | vault | `latest` | `nativeAssetWeiPerUnit()` |
| `eth_call` `0xaad24061` | vault | `latest` | `usedNullifiers(uint256)` before key issuance |
| `eth_call` `0x313ce567` | feed | `latest` | `decimals()` |
| `eth_call` `0xfeaf968c`, `0x9a6fc8f5` | feed | `finalized` | `latestRoundData()`, `getRoundData(uint80)` |

### Lease settlement deadline

Every lease row gets a write-once settlement deadline at creation: issuance +
`LEASE_TTL_SECONDS` + `SETTLEMENT_GRACE_SECONDS` +
`ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS` (default 21600). A lease that may
have been delivered and is still unsettled then is finalized at its measured
usage or, failing that, at its proof's solvency bound, with an operator review
record. The server refuses to start unless TTL + grace + deadline + twice the
2-second settlement poll + 600 seconds is at most half the vault's
`challengePeriod()`, and unless the deadline is at least the grace + 900
seconds. See [native ETH billing](../../docs/native-eth-billing.md).

### Indexer RPC

`RPC_URL` in `indexer.env` must serve `eth_chainId`, `eth_getBlockByNumber`,
`eth_getBlockByHash`, `eth_getLogs` (logs carry `blockHash` and `logIndex`) and
`eth_call` by block hash with `requireCanonical` (EIP-1898), with state for at
least the last `INDEXER_CONFIRMATIONS` blocks; archive state is not required.
An RPC without EIP-1898 support keeps the indexer in `syncing` and logs
`RPC rejected block-hash eth_call (EIP-1898); indexer cannot verify vault state`.
Use one consistent endpoint rather than a load balancer whose replicas disagree
about the head, and a provider independent of the `rpc_url` packaged in client
manifests: `zkapi-clientd` corroborates deposits and withdrawals against this
indexer's tree, and that check is only as independent as the indexer's RPC. Keep
the host clock synchronized with NTP; the indexer answers 503 when the RPC head
block is older than `INDEXER_MAX_HEAD_AGE_SECS` (180).

The indexer commits its checkpoint `INDEXER_CONFIRMATIONS` blocks (12) below the
head and serves a head view verified against the vault's `currentRoot()` and
`nextNoteId()` at the head block. Its tree routes answer 503 with
`{"status":"unavailable","error_code":"indexer_unavailable",...}` and
`Retry-After: 5` until a view verifies, and again whenever it is stale, diverged
or rebuilding. The server and the challenger start without waiting for it.

### Challenge signer and daemon

The signer reads only `signer.env`; [its README](signer/README.md) documents
every variable, the fee model and its runbooks. In short:
`ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` is the highest `maxFeePerGas` it signs.
With `ZKAPI_CHALLENGE_CHAIN_ID=1` it refuses to start without one; Sepolia
defaults to 10 gwei. The tip cap `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI`
defaults to the lower of the fee cap and 10 gwei. `ZKAPI_CHALLENGE_MAX_GAS_PRICE_WEI`
is no longer supported, and the signer refuses to start while it is present,
even empty. Fund the sender with at least (N + K) x gas limit x fee cap, where N
is the number of challenges that may be pending at once and K a budget of
reverted attempts; a real challenge has a gas limit of about 7.53M, so 0.75 ETH
per challenge at a 100 gwei cap.

`challenge.env` holds the daemon's own bounds, which it proposes to the signer:

| Variable | Requirement |
| --- | --- |
| `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI` | Required. At most the signer's `ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI`. |
| `ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI` | Required. At most the signer's tip cap and this daemon's fee cap, and at least twice the priority fee, so that replacements have room to rise. |
| `ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI` | Optional tip of a first attempt; default 2 gwei. |

The launcher binds the daemon's status listener to `127.0.0.1:3002` inside the
container. The Compose healthcheck reads its `/livez`; never publish the port or
route it through the gateway, because its status shows when challenges are
blocked. The daemon opens `/data/server.db` read-only and needs the server's
`deployment_binding` row: start the server first. See
[challenge operation](../../docs/challenge-service.md).

## Starting the deployment

Start the API first, then the challenge profile:

```sh
sudo docker compose -f docker/aws/compose.yml --profile challenge config --quiet
sudo docker compose -f docker/aws/compose.yml up -d --wait server
sudo docker compose -f docker/aws/compose.yml --profile challenge up -d --wait
sudo docker compose -f docker/aws/compose.yml --profile challenge ps
```

`--wait` also waits for the indexer, whose healthcheck allows 900 seconds for a
full replay from `DEPLOY_BLOCK`; it turns healthy as soon as the replay verifies.

The challenge profile is explicit so image building and local startup checks
can run before a signer is available. Omitting it starts only the API, indexer
and gateway; such a deployment does not have escape-challenge protection. The
challenger requires RPC `eth_sendTransaction`; an ordinary public RPC
cannot act as its signer. The included restricted signer sidecar requires an explicit supported chain
(1 or 11155111) and accepts only challenge calls to its
configured vault. Its chain must match the RPC, public manifest and daemon. Never publish its RPC port.
Keep the funded sender exclusive to this daemon and deployment. Keep the API
running whenever the challenger runs: its settlement produces the challenge
evidence, and users recover their signed state from it after a challenge.

The default HTTP origin binds `127.0.0.1:8080`. For an EC2 origin behind
CloudFront, set `ZKAPI_HTTP_BIND=0.0.0.0` and `ZKAPI_HTTP_PORT=80` for Compose,
restrict inbound port 80 in the EC2 security group to the AWS-managed prefix
list `com.amazonaws.global.cloudfront.origin-facing`, and provide HTTPS at the
public edge. The request limits below trust the last `X-Forwarded-For` element
only because CloudFront writes it; a client that can reach the origin directly
can choose its own limit key. Set CloudFront caching disabled and forward all
query strings, required request headers, and methods for API/indexer paths. No
daemon or signer port should be exposed by the VM security group. Neither
SQLite data nor the operator dashboard is served by the gateway.

For password-gated Sepolia, forward `X-ZKAPI-Testnet-Password`, `Origin`, and
both `Access-Control-Request-*` headers through CloudFront. Preserve no-store
and CORS response headers and allow OPTIONS. The gate runs in the API process;
neither an alternate proxy route nor a direct daemon connection bypasses it.
See [access configuration and rotation](../../docs/testnet-auth.md). Never log
the password header or place the password in the public client manifest.

Optional Compose settings are `ZKAPI_IMAGE_TAG`, `ZKAPI_CONFIG_DIR`,
`ZKAPI_DATA_DIR`, `ZKAPI_HTTP_BIND` and `ZKAPI_HTTP_PORT`. Persist these settings
in the operator's root-owned Compose environment file and use the same settings
on each deployment command.

## Request limits

The gateway caps POST requests per network source before they reach the API:

| Zone | Route | Rate | Burst |
| --- | --- | --- | --- |
| `zkapi_clearance` | `POST /v2/withdraw/clearance` | 10 per second | 100 |
| `zkapi_lease` | `POST /v2/openrouter/leases` | 20 per second | 200 |
| `zkapi_v2_post` | every other `POST /v2/...` (lease retirement and expiry) | 20 per second | 200 |

GET, HEAD and OPTIONS requests, recovery reads, quotes, tree paths, health,
attestation and static files are never counted. These are coarse flood ceilings,
not per-user quotas. A browser host sends its users' protocol calls through one
same-origin rewrite or privacy proxy, so the gateway sees one source for all of
that host's users; size the limits for the largest host's aggregate peak,
including a burst of withdrawals during a migration. Per-user and volumetric
protection belongs at the host's edge or in AWS WAF rate-based rules. IPv6
clients can rotate addresses within their own range.

The source is the last `X-Forwarded-For` element when it looks like an IP
address (hex digits, dots and colons, at most 45 characters), otherwise the TCP
peer. CloudFront appends the address it received the request
from, so behind CloudFront this is the viewer (or the host's egress). The
pattern is anchored and its match time is linear in the header length.

A throttled request never reaches the API. The gateway answers `429` with
`Retry-After: 5`, `Cache-Control: no-store`, and an API error body:
`{"status":"error","client_request_id":"","error_code":"gateway_rate_limited","error_message":"...","retriable":true,"retry_after_seconds":5}`.
Retry the same request unchanged after the delay; nothing was processed or
reserved. The API's own errors, including its 429s, pass through unchanged.

To change a limit, edit `nginx.conf` and rebuild and restart the gateway:

```sh
sudo docker compose -f docker/aws/compose.yml build gateway
sudo docker compose -f docker/aws/compose.yml up -d --no-deps --wait gateway
```

The gateway logs nothing per request. Each throttled request writes one line
with its status and zone only, for example
`{"event":"gateway_rate_limited","status":429,"zone":"zkapi_clearance"}`, with no
address or path.

## Monitoring

None of these checks is configured for you. Run them from the VM and alert on
the conditions listed. For the second project of a VM that runs two deployments,
add `-p` and `--env-file` as described under Upgrades.

```sh
dc() { sudo docker compose -f docker/aws/compose.yml --profile challenge "$@"; }
# Challenger: 503 means a critical obligation or stale polling; /status has the detail.
dc exec -T challenger curl -sS -w '\n%{http_code}\n' http://127.0.0.1:3002/health
dc exec -T challenger curl -sS http://127.0.0.1:3002/status
# Indexer: 200 only while a verified view is served.
dc exec -T indexer curl -sS -w '\n%{http_code}\n' http://127.0.0.1:3001/health
dc exec -T indexer curl -sS http://127.0.0.1:3001/metrics
# Signer: fee policy, balance and warnings.
dc exec -T challenger curl -sS -X POST http://signer:8547 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"zkapi_signerStatus","params":[]}'
# API: false while legacy clearance is enabled.
curl -fsS http://127.0.0.1:8080/health | jq .clearance_ownership_proof_required
# Settlement: pending leases, deadlines and open reviews (operator-only route).
dc exec -T server curl -fsS 'http://127.0.0.1:3000/v1/dashboard/settlement?limit=50'
```

On a password-gated Sepolia server the dashboard route needs the password header,
for example
`dc exec -T server sh -c 'printf "X-ZKAPI-Testnet-Password: %s\n" "$ZKAPI_TESTNET_PASSWORD" | curl -fsS -H @- http://127.0.0.1:3000/v1/dashboard/settlement'`.

Alert on:

- challenger `/health` returning 503, and any `critical` entry in its `/status`
  `alarms`: a missed deadline; an obligation with evidence whose deadline is
  within a quarter of `challengePeriod()`; an obligation blocked by
  `evidence_invalid`, `evidence_db_error`, `indexer_invalid_response`,
  `indexer_diverged` or `signer_refused`, or by any other reason for 1800
  seconds; stale polls; a diverged indexer; or an unmined nonce that needs
  signer intervention;
- the challenger log lines `MISSED escape challenge deadline`,
  `indexer mirror diverged from vault currentRoot`, and
  `challenge obligation status changed` at error level, and a rising
  `missed_total` in `/status`;
- indexer `/health` not 200 for more than two minutes (outside a planned replay),
  an increase in its `divergence_count` or `rebuild_count`
  (`zkapi_indexer_divergences_total`, `zkapi_indexer_rebuilds_total`), and a
  `head_age_seconds` near `INDEXER_MAX_HEAD_AGE_SECS`; also its ERROR log
  lines, such as `indexer mirror diverged from vault state; tree endpoints
  return 503`;
- the indexer's `root` differing from `currentRoot()` read at its `served_block`
  through a different RPC than the indexer's own (commands under Indexer resync);
- `settlement required operator review` in the server log, and a nonzero
  `open_reviews` in `/v1/dashboard/settlement`;
- a non-empty `warnings` list from `zkapi_signerStatus` (`base_fee_above_cap`,
  `base_fee_near_cap`, `balance_below_required`), signer `/health` failures, and
  signer audit lines `"event":"challenge_refused"` with reason
  `base_fee_above_max_fee`, `insufficient_balance` or `broadcast_ambiguous`;
- `clearance_ownership_proof_required: false` after the announced end of the
  legacy clearance window;
- sustained `gateway_rate_limited` lines in the gateway log, per zone.

Acknowledge a settlement review after handling it, with the host's `sqlite3`.
Run writes as the container's user 10001, so that no root-owned journal file
can be left behind:

```sh
sudo sqlite3 -readonly /var/lib/zkapi/server.db \
  "SELECT client_request_id, reason, charge_basis, charge_applied, solvency_bound, detail FROM settlement_reviews WHERE acknowledged_at IS NULL;"
sudo setpriv --reuid=10001 --regid=10001 --clear-groups sqlite3 /var/lib/zkapi/server.db \
  "UPDATE settlement_reviews SET acknowledged_at = strftime('%s','now') WHERE client_request_id = 'REPLACE_WITH_ID';"
```

## Indexer resync

Resync when the indexer reports `diverged`, when its root disagrees with the
vault, or when the challenger reports `indexer_diverged`. Waiting never repairs a
divergence. The indexer rebuilds automatically after a detected divergence or a
reorganization below its checkpoint, at most once per 300 seconds; a resync
forces an immediate rebuild from `DEPLOY_BLOCK`.

1. Compare the indexer with the vault, reading the vault through an RPC other
   than the indexer's (set `VAULT` to the vault address and `CHECK_RPC_URL` to
   that RPC):

   ```sh
   H=$(sudo docker compose -f docker/aws/compose.yml exec -T indexer curl -sS http://127.0.0.1:3001/health)
   echo "$H" | jq '{status, reason, served_block, root, next_note_id, lag_blocks, head_age_seconds, last_error}'
   B=$(echo "$H" | jq -r .served_block)
   cast to-dec "$(echo "$H" | jq -r .root)"
   cast to-dec "$(cast call "$VAULT" 'currentRoot()' --block "$B" --rpc-url "$CHECK_RPC_URL")"
   cast call "$VAULT" 'nextNoteId()(uint32)' --block "$B" --rpc-url "$CHECK_RPC_URL"
   ```

2. Request a resync and restart. The indexer archives its checkpoint as
   `indexer.cursor.resync-<unix_ms>.bak`, deletes the request file and replays
   from `DEPLOY_BLOCK`; its tree routes answer 503 until the replay verifies.

   ```sh
   sudo touch "${ZKAPI_DATA_DIR:-/var/lib/zkapi}/indexer.cursor.resync"
   sudo docker compose -f docker/aws/compose.yml restart indexer
   ```

   A directly launched `zkapi-indexerd` or `zkapi indexer` can be restarted with
   `--resync` instead; remove the flag afterwards, or every restart resyncs.

3. Watch `/health` until `status` is `ok`, then repeat step 1. If it does not
   converge, check the RPC requirements above; switch `RPC_URL` to a consistent
   endpoint if replicas disagree.

A replay costs about (head − `DEPLOY_BLOCK`) / 1000 `eth_getLogs` calls, paced at
one per 100 ms, plus verification. Start it at least twice that long before the
nearest pending challenge deadline. Never edit the checkpoint or SQLite files by
hand, never delete `challenges.json`, and never point two indexers at one
checkpoint (the second refuses: `another indexer holds this checkpoint`).

## Upgrades and running two deployments

Upgrade a deployment in place by rebuilding from the new release with a new
`ZKAPI_IMAGE_TAG`, so the previous images stay available for rollback. Back up
`/var/lib/zkapi` while the services are stopped. Release-specific order and
checks for this release are in
[the hardened-vault migration guide](../../docs/migration-hardened-vault.md).

A redeployed vault is a new deployment: new public manifest and hostname, a new
signer key and exclusive sender, and a fresh data directory (database, indexer
checkpoint and challenge checkpoint). The database refuses a second vault, and a
checkpoint is bound to its chain and vault. Never repoint a signer or challenger
at another vault while its vault still has active notes or pending escapes;
keep both stacks running until the old vault is drained.

Prefer a separate VM for each deployment. On one VM, run the deployment being
drained as a second Compose project with its own configuration directory, data
directory and HTTP port, for example `/etc/zkapi-legacy/compose.env`:

```sh
ZKAPI_CONFIG_DIR=/etc/zkapi-legacy
ZKAPI_DATA_DIR=/var/lib/zkapi-legacy
ZKAPI_HTTP_BIND=0.0.0.0
ZKAPI_HTTP_PORT=8081
ZKAPI_IMAGE_TAG=REPLACE_WITH_RELEASE_TAG
```

Pass `-p zkapi-legacy --env-file /etc/zkapi-legacy/compose.env` on every command
for that project, for example
`sudo docker compose -p zkapi-legacy --env-file /etc/zkapi-legacy/compose.env -f docker/aws/compose.yml --profile challenge ps`.
To move an existing deployment into that project, stop all of its services,
move `/etc/zkapi` and `/var/lib/zkapi` to the new paths with `mv` (keeping
ownership and the SQLite lock file with its database), start it under the new
project name, and point its CloudFront origin at the new port. The newer
deployment then uses the default paths and project. The two projects never
share a data directory, signer key, sender or hostname.

## Acceptance checks

```sh
curl --fail http://127.0.0.1:8080/health
curl --fail http://127.0.0.1:8080/v1/attestation
curl --fail http://127.0.0.1:8080/v1/tree/root
sudo docker compose -f docker/aws/compose.yml --profile challenge ps
sudo docker compose -f docker/aws/compose.yml --profile challenge exec -T challenger curl -sS http://127.0.0.1:3002/status
sudo docker compose -f docker/aws/compose.yml logs --tail=50 server challenger
```

Verify that health and attestation report protocol 2, the selected chain and the
configured vault, and that `/health` reports `clearance_ownership_proof_required:
true` unless legacy clearance is deliberately enabled. Confirm the server log
line `server signing keys match the vault's immutable keys`, and compare the
attestation keys with the vault's getters as numbers (the attestation omits
leading zeros):

```sh
for getter in stateSigningKeyX stateSigningKeyY clearanceSigningKeyX clearanceSigningKeyY; do
  cast to-dec "$(cast call "$VAULT" "$getter()" --rpc-url "$CHECK_RPC_URL")"
done
curl -fsS http://127.0.0.1:8080/v1/attestation \
  | jq -r '.state_signing_key.x, .state_signing_key.y, .clearance_signing_key.x, .clearance_signing_key.y' \
  | while read -r value; do cast to-dec "$value"; done
```

Compare the indexer root and next note ID with the vault as under Indexer
resync. Verify that `/v1/dashboard/settlement`, `/v1/dashboard/recent`,
`/v1/dashboard/events` and `/v1/escapes/pending` return 404 through the public
origin and HTTPS edge. Optionally probe the request limit: an empty body is
rejected by the API before anything is reserved, so this shows about 100 API
errors followed by `429`.

```sh
for i in $(seq 1 120); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'content-type: application/json' -d '{}' \
    http://127.0.0.1:8080/v2/withdraw/clearance
done | sort | uniq -c
```

The API health endpoint measures process health; successful chain
synchronization and challenge transaction submission require the independent
checks above and the live test flow described in the deployment docs.

All services restart after a VM reboot when Docker is enabled. Database,
indexer checkpoint and challenge checkpoint live in `/var/lib/zkapi`; preserve and
back up that directory across image updates. The challenger shares the API's
SQLite database and must use the same host filesystem for SQLite locking. A
recreated image must use the same setup artifacts as the deployed verifier.

## Validation

Run the local SDK, Rust, Solidity, launcher, gateway and signer tests before
rollout. `node --test docker/aws/run-daemon.test.mjs docker/aws/nginx.test.mjs`
checks the launcher and the gateway configuration; with an `nginx` binary on
`PATH` (or `NGINX_BIN`) the gateway test also runs the configuration against a
stub API, and `ZKAPI_REQUIRE_NGINX=1` makes a missing binary a failure. Check the
built gateway image with
`sudo docker run --rm --user 101:101 --read-only --tmpfs /tmp --entrypoint nginx zkapi/gateway:${ZKAPI_IMAGE_TAG:-note-bound-v1} -t`.
Use a separately authorized native ETH lifecycle check for the intended network;
read-only health/quote checks alone do not establish paid inference, withdrawal
or live escape-challenge success. Preserve server data, checkpoints and signer
funding throughout any deployment change.
