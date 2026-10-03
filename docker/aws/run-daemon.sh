#!/bin/sh
# Keep private seeds and provider credentials in the process environment.
set -eu

# Match the artifacts installed by docker/Dockerfile; allow an explicit override.
ZKAPI_PROOF_SETUP_DIR=${ZKAPI_PROOF_SETUP_DIR:-/srv/zkapi/protocol/setup/v2}

require() {
    for name in "$@"; do
        if ! value=$(printenv "$name") || [ -z "$value" ]; then
            echo "Missing required environment variable: $name" >&2
            exit 1
        fi
    done
}

require CHAIN_ID VAULT_ADDRESS DEPLOY_BLOCK CIRCUIT_ID
if [ "$CIRCUIT_ID" != zkapi-v2-note-bound-v1 ]; then
    echo "This image requires the zkapi-v2-note-bound-v1 circuit and a fresh vault" >&2
    exit 1
fi

case "${1:-}" in
    server)
        require ZKAPI_STATE_SEED ZKAPI_CLEAR_SEED REQUEST_CHARGE_CAP ZKAPI_NATIVE_BILLING_RPC_URL ZKAPI_NATIVE_PRICE_FEED_ADDRESS
        # zkapi serverd reads the seeds from this environment and validates them
        # itself: it refuses development keys in any spelling (by derived public
        # key), weak or reused seeds, and keys that differ from the vault's,
        # before it opens /data/server.db. A string match here would be bypassable.
        # ZKAPI_ALLOW_LEGACY_CLEARANCE, ZKAPI_LEGACY_CLEARANCE_MAX_PER_MINUTE and
        # ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS also reach serverd from the environment.
        set -- zkapi --protocol-version 2 --chain-id "$CHAIN_ID" \
            --contract-address "$VAULT_ADDRESS" \
            --request-charge-cap "$REQUEST_CHARGE_CAP" \
            --proof-setup-dir "$ZKAPI_PROOF_SETUP_DIR" \
            serverd --listen 0.0.0.0:3000 \
            --indexer-url http://indexer:3001 \
            --native-billing-rpc-url "$ZKAPI_NATIVE_BILLING_RPC_URL" \
            --native-price-feed-address "$ZKAPI_NATIVE_PRICE_FEED_ADDRESS" \
            --native-price-feed-decimals "${ZKAPI_NATIVE_PRICE_FEED_DECIMALS:-8}" \
            --native-price-max-age-seconds "${ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS:-4500}" \
            --openrouter-lease-ttl-seconds "${LEASE_TTL_SECONDS:-300}" \
            --openrouter-settlement-grace-seconds "${SETTLEMENT_GRACE_SECONDS:-5}" \
            --openrouter-settlement-deadline-seconds "${ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS:-21600}" \
            --db-path /data/server.db
        if [ -n "${OA_ORG_URL:-}" ]; then
            set -- "$@" --oa-org-url "$OA_ORG_URL"
        fi
        exec "$@"
        ;;
    indexer)
        require RPC_URL
        # The checkpoint commits at --confirmations; the served tree tracks the
        # verified head. Touch /data/indexer.cursor.resync and restart to rebuild.
        exec zkapi-indexerd --listen 0.0.0.0:3001 --rpc-url "$RPC_URL" \
            --contract-address "$VAULT_ADDRESS" --from-block "$DEPLOY_BLOCK" \
            --chain-id "$CHAIN_ID" --confirmations "${INDEXER_CONFIRMATIONS:-12}" \
            --max-head-age-secs "${INDEXER_MAX_HEAD_AGE_SECS:-180}" \
            --cursor-path /data/indexer.cursor
        ;;
    challenger)
        require ZKAPI_CHALLENGE_RPC_URL ZKAPI_CHALLENGE_SENDER \
            ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI
        # The RPC, sender and fee settings reach zkapi-challenged from the
        # environment. Its status listener stays on the container's loopback,
        # for the healthcheck and `docker compose exec`; never publish it.
        exec zkapi-challenged --indexer-url http://indexer:3001 \
            --chain-id "$CHAIN_ID" --contract-address "$VAULT_ADDRESS" \
            --from-block "$DEPLOY_BLOCK" --confirmations "${CHALLENGE_CONFIRMATIONS:-2}" \
            --db-path /data/server.db --checkpoint /data/challenges.json \
            --proof-setup-dir "$ZKAPI_PROOF_SETUP_DIR" \
            --status-listen 127.0.0.1:3002
        ;;
    *)
        echo "Usage: zkapi-run server|indexer|challenger" >&2
        exit 2
        ;;
esac
