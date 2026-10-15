#!/usr/bin/env bash
#
# zkapi-tor-cli.sh — stateful chat client for the Tor-routed zkapi daemon.
#
#   zkapi-tor-cli.sh make_single_request "What is the capital of France?"
#   zkapi-tor-cli.sh start_conversation "Hi, remember the word persimmon."
#   zkapi-tor-cli.sh ask "What word did I ask you to remember?"
#   zkapi-tor-cli.sh list_models
#   zkapi-tor-cli.sh set_model anthropic/claude-haiku-4.5
#   zkapi-tor-cli.sh withdraw <addr> [eth]  return note balance to an address
#   zkapi-tor-cli.sh fund                   show funding address/balance
#   zkapi-tor-cli.sh fund --amount 0.005    quote + approve + open a channel
#   zkapi-tor-cli.sh stop
#
# State (server pid, model, conversation history) lives under
# <config>/zkapi-clientd/cli/ — the ONE state root, so a conversation
# survives reboots, sandbox resets, and handoff between environments:
# stop in one world, start in the other, continue asking.
#
# Identity model (matches zkapi-serve-tor.sh):
#   * One long-lived Tor client; guards persist across runs.
#   * make_single_request and start_conversation signal NEWNYM on the Tor
#     control port: a brand-new circuit for every conversation, no process
#     restart. If the server is not running they start it (bootstrap wait).
#   * ask adds to the current conversation without touching circuits, so the
#     whole conversation shares one exit path (and the daemon reuses one
#     ephemeral key across it while the budget matches).
set -uo pipefail

here="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
# Repo-local .config/zkapi-clientd wins if present (portable wallet backup);
# otherwise the standard user config directory is used, matching the daemon.
if [ -f "$here/.config/zkapi-clientd/config.json" ]; then export XDG_CONFIG_HOME="$here/.config"; fi
SERVE="$here/zkapi-serve-tor.sh"
BIN="$here/zkapi-clientd/bin/zkapi-clientd"
API="http://127.0.0.1:8787/v1"
CFG_DIR="${ZKAPI_CLIENTD_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/zkapi-clientd}"
STATE_DIR="$CFG_DIR/cli"
PID_FILE="$STATE_DIR/server.pid"
MODEL_FILE="$STATE_DIR/model"
CONV_FILE="$STATE_DIR/conv.json"
DEFAULT_MODEL="openai/gpt-6-astra-pro"
READY_TIMEOUT="${ZKAPI_TORCLI_READY_TIMEOUT:-240}"
# Give the launcher's bootstrap a strictly smaller budget than our own wait,
# so a slow bootstrap either completes inside our window or the launcher dies
# first and we report its log — never a simultaneous give-up.
export TOR_ISOLATE_TIMEOUT="${TOR_ISOLATE_TIMEOUT:-$((READY_TIMEOUT - 30))}"
SETTLE_TIMEOUT="${ZKAPI_TORCLI_SETTLE_TIMEOUT:-180}"
CONFIG_DIR="${ZKAPI_CLIENTD_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/zkapi-clientd}"
COMPANION="http://127.0.0.1:8790"

mkdir -p "$STATE_DIR" || exit 1

die() { echo "zkapi-tor-cli: $*" >&2; exit 1; }

api_up() { curl -sf -m 25 "$API/models" -o /dev/null 2>/dev/null; }

# The API answering IS the server being up — whoever started it (this CLI,
# zkapi-serve-tor.sh directly, an earlier session). Circuit rotation works
# either way because it goes through the control port recorded in .tor-state.
server_running() { api_up; }


# rotate_circuit — ask the running Tor (same guards, same process) for fresh
# circuits via SIGNAL NEWNYM. Returns non-zero if unreachable, in which case
# the caller falls back to a full restart.
rotate_circuit() {
  local ctl
  ctl="$(cat "${ZKAPI_CLIENTD_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/zkapi-clientd}/tor/control_port" 2>/dev/null)" || return 1
  python3 "$here/zkapi-tor-ctl.py" "$ctl" newnym >/dev/null || return 1
  rm -f "$STATE_DIR/warm.ts"   # new circuit: the policy cache may be stale
  echo "new circuit signaled for this conversation (guards unchanged)" >&2
}

server_running() {
  [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null && api_up
}

stop_server() {
  [ -f "$PID_FILE" ] && kill -TERM "$(cat "$PID_FILE")" 2>/dev/null
  local elapsed=0
  while api_up && [ "$elapsed" -lt 20 ]; do sleep 0.5; elapsed=$((elapsed + 1)); done
  # Only this CLI's own stack is ever stopped. A live profile held by a
  # daemon in another environment is not an orphan to sweep: flock dies with
  # its holder, and the money layer (issuer one-lease-per-note, companion
  # wallet lock) already makes concurrent spenders impossible. If the claim
  # fails, the launcher names the holder; the user decides.
  rm -f "$PID_FILE"
}

start_server() {
  [ -x "$SERVE" ] || die "launcher not found at $SERVE"
  stop_server   # clear any orphan holding the loopback port before launching
  : > "$STATE_DIR/server.log"
  nohup "$SERVE" > "$STATE_DIR/server.log" 2>&1 &
  echo $! > "$PID_FILE"
  local elapsed=0 offset=0 size
  until api_up; do
    # propagate the launcher's bootstrap progress (tor's Bootstrapped %, the
    # serve script's "still bootstrapping" beeps) to the terminal, like the
    # policy/settlement waits do; full log stays in server.log
    size="$(stat -c %s "$STATE_DIR/server.log" 2>/dev/null || echo 0)"
    if [ "$size" -gt "$offset" ]; then
      tail -c "+$((offset + 1))" "$STATE_DIR/server.log" | grep -iE "bootstrap" >&2
      offset="$size"
    fi
    kill -0 "$(cat "$PID_FILE")" 2>/dev/null || { sed -n '1,20p' "$STATE_DIR/server.log" >&2; die "server exited during startup (log: $STATE_DIR/server.log)"; }
    [ "$elapsed" -ge "$READY_TIMEOUT" ] && die "API not ready after ${READY_TIMEOUT}s (log: $STATE_DIR/server.log)"
    sleep 1; elapsed=$((elapsed + 1))
  done
}

active_model() {
  if [ -s "$MODEL_FILE" ]; then cat "$MODEL_FILE"; return; fi
  # No explicit set_model yet: adopt the cheapest live model once and persist
  # it, so the default can never rot into a retired model ID.
  local pick
  pick="$(curl -sf -m 40 "$API/models" 2>/dev/null | python3 -c '
import json,sys
try: ids=[m["id"] for m in json.load(sys.stdin)["data"]]
except Exception: ids=[]
print(ids[0] if ids else "")' 2>/dev/null)"
  if [ -n "$pick" ]; then
    printf '%s\n' "$pick" > "$MODEL_FILE"
    echo "no model chosen yet; defaulting to the cheapest live model: $pick (change with set_model)" >&2
    printf '%s\n' "$pick"
  else
    printf '%s\n' "$DEFAULT_MODEL"   # offline fallback only
  fi
}

# wallet_state — prints "pending", "ready", or "unreachable" by asking the
# wallet companion directly (0-spend check, same bridge token the daemon uses).
wallet_state() {
  local token json
  token="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["zkapi"]["bridge_token"])' "$CONFIG_DIR/config.json" 2>/dev/null)" || { echo unreachable; return; }
  json="$(curl -sf -m 5 -H "Authorization: Bearer $token" "$COMPANION/wallet/status" 2>/dev/null)" || { echo unreachable; return; }
  printf '%s' "$json" | python3 -c 'import json,sys; print("pending" if json.load(sys.stdin).get("pending_request") else "ready")' 2>/dev/null || echo unreachable
}

# ---- wallet bootstrap: set up, fund, open a channel, chat ----------------
# The chat pipeline needs an open note (channel). Rather than failing at
# request time, every chat command checks the wallet companion first (a free
# local call) and shepherds the missing pieces:
#   no funds   -> show the funding address and a recommended amount
#   funds, no note -> quote + auto-approve + watch the deposit until active
MIN_WEI=5000000000000000   # 0.005 ETH
wallet_note_state() {  # "none" | "empty" | "ok" | "" (unknown/unreachable)
  local token json
  token="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["zkapi"]["bridge_token"])' "$CONFIG_DIR/config.json" 2>/dev/null)" || return 0
  json="$(curl -sf -m 8 -H "Authorization: Bearer $token" "$COMPANION/wallet/status" 2>/dev/null)" || return 0
  printf '%s' "$json" | python3 -c '
import json,sys
s=json.load(sys.stdin)
if not s.get("has_note"): print("none")
else:
    b=(s.get("note") or {}).get("current_balance") or 0
    print("ok" if b>0 else "empty")' 2>/dev/null
}

wallet_note_balance_eth() {  # entire note balance as a decimal ETH string
  local token json
  token="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["zkapi"]["bridge_token"])' "$CONFIG_DIR/config.json" 2>/dev/null)" || return 1
  json="$(curl -sf -m 8 -H "Authorization: Bearer $token" "$COMPANION/wallet/status" 2>/dev/null)" || return 1
  printf '%s' "$json" | python3 -c '
import json,sys
s=json.load(sys.stdin)
b=(s.get("note") or {}).get("current_balance")
if not b: sys.exit(1)
print(("%d" % (b/1e18)) if b % 10**9 == 0 else ("%.18f" % (b/1e18)).rstrip("0"))' 2>/dev/null
}

funding_api() {  # <METHOD> <PATH> [json-body] — the daemon's admin funding API
  local method="$1" path="$2" body="${3:-}" token mtoken listen
  token="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("api_key",""))' "$CONFIG_DIR/config.json" 2>/dev/null)"
  mtoken="$(cat "$CONFIG_DIR/management-token" 2>/dev/null)"
  listen="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("listen","127.0.0.1:8787"))' "$CONFIG_DIR/config.json" 2>/dev/null)"
  local resp bodyf code
  bodyf="$(mktemp)"
  code="$(curl -s -m 90 -o "$bodyf" -w '%{http_code}' -X "$method" -H "Authorization: Bearer $token" \
    -H "X-OA-Management-Token: $mtoken" -H "Content-Type: application/json" \
    ${body:+-d "$body"} "http://$listen$path" 2>/dev/null)"
  case "$code" in
    2*) cat "$bodyf" ;;
    *)  python3 - "$bodyf" "$code" <<'PY' 1>&2
import json,sys
try: print("funding API:", json.load(open(sys.argv[1])).get("error", "http %s" % sys.argv[2]))
except Exception: print("funding API: http %s" % sys.argv[2])
PY
      rm -f "$bodyf"; return 1 ;;
  esac
  rm -f "$bodyf"
}

wei2eth() { python3 -c 'print(f"{int(sys.argv[1])/1e18:.6f}")' "${1:-0}" 2>/dev/null || echo "?"; }

funding_advice() {
  echo "To use zkAPI, fund your zkAPI payment address (shown above)." >&2
  echo "  * Recommended: at least ${ZKAPI_FUND_RECOMMENDED:-0.005} ETH." >&2
  echo "  * You may send any amount you like; unspent money stays yours and" >&2
  echo "    keeps working - spending only happens as you chat." >&2
  echo "  * Risk of sending less: the most expensive models will refuse," >&2
  echo "    while cheaper models may still work. Start small if unsure." >&2
  echo "  * Re-run this command (or your question) after sending; the deposit" >&2
  echo "    is detected and the channel opens automatically." >&2
}

show_funding_state() {
  local s; s="$(funding_api GET /admin/funding/address)" || { echo "zkapi-tor-cli: funding API unreachable (is the server up?)" >&2; return 1; }
  printf '%s' "$s" | python3 -c '
import json,sys
s=json.load(sys.stdin)
print("zkAPI payment address: %s" % s.get("address"))
print("Available balance: %.6f ETH" % (int(s.get("eth_balance") or 0)/1e18))
if s.get("phase"): print("state:", s["phase"], s.get("message") or "")' >&2
}

open_channel() {  # quote + auto-approve + watch until the note is active
  local amount="${ZKAPI_FUND_AMOUNT:-0.005}" units quote qid s phase waited=0
  units="$(python3 -c 'print(int(round(float(sys.argv[1])*1e9)))' "$amount")" || return 1
  quote="$(funding_api POST /admin/funding/quote "{\"amount\": $units}")" || { echo "zkapi-tor-cli: could not get a deposit quote." >&2; show_funding_state; return 1; }
  printf '%s' "$quote" | python3 -c '
import json,sys
q=json.load(sys.stdin)
short=(q.get("shortfall_wei") or "").lstrip("0")
if short:
    print("Needs top-up: %.6f ETH more (recommended %.6f with buffer)." % (int(q["shortfall_wei"])/1e18, int(q.get("recommended_topup_wei") or 0)/1e18), file=sys.stderr)
    print("Send on-chain to:", q.get("address"), file=sys.stderr)
    sys.exit(1)
print(q["id"])' || { funding_advice; return 1; }  # capture the id or bail with advice
  qid="$(printf '%s' "$quote" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')"
  echo "zkapi-tor-cli: quote ok (${amount} ETH); auto-approving (broadcasts one transaction; tune via ZKAPI_FUND_AMOUNT)." >&2
  s="$(funding_api POST /admin/funding/approve "{\"quote_id\": \"$qid\"}")" || { echo "zkapi-tor-cli: approval failed." >&2; return 1; }
  while :; do
    phase="$(printf '%s' "$s" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("phase",""))' 2>/dev/null)"
    echo "zkapi-tor-cli: channel deposit $phase" >&2
    [ "$phase" = active ] && { echo "zkapi-tor-cli: channel is open." >&2; return 0; }
    [ "$waited" -ge "${ZKAPI_FUND_WAIT:-420}" ] && { echo "zkapi-tor-cli: still $phase after ${ZKAPI_FUND_WAIT:-420}s; re-run your question once it confirms." >&2; return 1; }
    sleep 5; waited=$((waited + 5))
    s="$(funding_api POST /admin/funding/deposit "{\"amount\": $units}")" || return 1
  done
}

ensure_wallet() {  # 0 = usable or unknown (speculate); 1 = handled, stop
  local state
  state="$(wallet_note_state)" || true
  case "$state" in
    ok|"") return 0 ;;
  esac
  echo "zkapi-tor-cli: no open zkAPI channel yet; provisioning..." >&2
  show_funding_state || true
  open_channel
}

# ensure_ready — if a previous lease is mid-settlement (the 60-90s window),
# sleep-and-ping until the wallet accepts new leases. After a few idle rounds,
# nudge retirement once via /wallet/settle, then keep polling.
ensure_ready() {
  local token elapsed=0 nudged=0 state
  while :; do
    state="$(wallet_state)"
    [ "$state" = ready ] && return 0
    if [ "$elapsed" -ge "$SETTLE_TIMEOUT" ]; then
      die "wallet not ready (${state}) after ${SETTLE_TIMEOUT}s; check server log and zkapi-diag.sh output"
    fi
    if [ "$state" = pending ] && [ "$nudged" -eq 0 ] && [ "$elapsed" -ge 30 ]; then
      token="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["zkapi"]["bridge_token"])' "$CONFIG_DIR/config.json" 2>/dev/null)"
      curl -sf -m 30 -X POST -H "Authorization: Bearer $token" "$COMPANION/wallet/settle" -o /dev/null 2>/dev/null && nudged=1
    fi
    echo "waiting for previous request to settle (${elapsed}s, state: $state)..." >&2
    sleep 5; elapsed=$((elapsed + 5))
  done
}

# In-flight markers: loopbacks don't cross environments, so a claimer in
# world B cannot see a request streaming in world A. The CLI stamps a
# per-PID marker for the life of every chat request; markers older than
# 6 minutes (past the 300s request timeout) are stale by definition and
# ignored, so a crashed CLI cannot wedge the wallet.
inflight() {  # a marker only counts while its owner process is alive (the
  # marker's mtime bounds the other direction: a SIGKILL'd owner is caught
  # by the 6-minute staleness rule; a 9-seconds-ago kill by /proc here)
  local f p
  for f in "$STATE_DIR"/active.*; do
    [ -e "$f" ] || continue
    [ "$f" = "$STATE_DIR/active.$$" ] && continue
    p="${f##*active.}"
    [ -d "/proc/$p" ] || { rm -f "$f"; continue; }
    [ -n "$(find "$f" -mmin -6 2>/dev/null)" ] && return 0
  done
  return 1
}
guard_inflight() {
  if [ "${ZKAPI_FORCE_TAKEOVER:-0}" != "1" ] && inflight; then
    die "a request is in flight (this or another environment; see $STATE_DIR/active.*). Starting a server now would retire the one serving it — killing the stream AFTER the provider was billed for the message. Wait for it to finish, or set ZKAPI_FORCE_TAKEOVER=1 to interrupt deliberately."
  fi
}

# py_chat <fresh|append> <text> — posts to the local API, keeps history in
# CONV_FILE, prints the assistant reply. Exit 2 = no stored conversation.
py_chat() {
  local mode="$1" text="$2"
  CONV_FILE="$CONV_FILE" python3 - "$mode" "$(active_model)" "$text" <<'PY'
import json, os, sys, urllib.error, urllib.request
mode, model, text = sys.argv[1:4]
conv = os.environ["CONV_FILE"]
if mode == "fresh":
    msgs = []
else:
    try:
        msgs = json.load(open(conv))
    except Exception:
        sys.exit(2)
msgs.append({"role": "user", "content": text})
req = urllib.request.Request(
    "http://127.0.0.1:8787/v1/chat/completions",
    data=json.dumps({"model": model, "messages": msgs}).encode(),
    headers={"content-type": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=300) as resp:
        body = json.load(resp)
except urllib.error.HTTPError as err:
    sys.stderr.write(err.read().decode("utf-8", "replace").strip() + "\n")
    sys.exit(3)
except Exception as err:
    sys.stderr.write("request failed: %s\n" % err)
    sys.exit(4)
try:
    content = body["choices"][0]["message"]["content"]
except Exception:
    sys.stderr.write(json.dumps(body)[:400] + "\n")
    sys.exit(5)
msgs.append({"role": "assistant", "content": content})
with open(conv + ".tmp", "w") as f:
    json.dump(msgs, f)
os.replace(conv + ".tmp", conv)   # atomic: power cut cannot tear the conversation
print(content)
PY
}

# warm_policy — block until the daemon can serve a non-empty model list.
# The reviewed-policy fetch lives in the DAEMON (issuer /chat/model-tickets +
# /chat/pinned-models over the anonymous transport), and GET /v1/models both
# reports it and triggers a fresh fetch on every call — so polling it IS the
# retry. The companion's /oa/v1/status is static deployment metadata and never
# carries the policy.
warm_policy() {
  local n elapsed=0 stamp="$STATE_DIR/warm.ts"
  # within 2 minutes of the last successful warm, assume still warm; a cold
  # surprise is still caught by run_chat's retry-with-warm path
  if [ -f "$stamp" ] && [ $(( $(date +%s) - $(stat -c %Y "$stamp" 2>/dev/null || echo 0) )) -lt 120 ]; then return 0; fi
  while :; do
    n="$(curl -sf -m 40 "$API/models" 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("data") or []))' 2>/dev/null)"
    if [ "${n:-0}" -gt 0 ] 2>/dev/null; then touch "$stamp"; return 0; fi
    [ "$elapsed" -ge "${ZKAPI_TORCLI_WARM_TIMEOUT:-180}" ] && return 1
    echo "waiting for the reviewed-model policy to load (${elapsed}s)..." >&2
    sleep 5; elapsed=$((elapsed + 5))
  done
}

# run_chat <fresh|append> <text> — py_chat plus one automatic recovery from
# the cold-policy race: warm the policy cache and retry the identical request.
# History is only persisted on success, so the retry never double-appends.
run_chat() {
  local mode="$1" text="$2" errf out rc tried_settle=0
  errf="$(mktemp)"
  if out="$(py_chat "$mode" "$text" 2>"$errf")"; then
    printf '%s\n' "$out"; rm -f "$errf"; return 0
  fi
  rc=$?
  if [ "$rc" -eq 2 ]; then
    rm -f "$errf"; die "no active conversation (or its history was lost); use start_conversation"
  fi
  # Speculative first: a live lease in its reuse window answers fine even
  # though /wallet/status says pending_request (that flag is true for the
  # whole life of an unsettled lease — it does NOT mean 'blocked'). Only an
  # actual failure means the lease rotated; then wait for settlement (with
  # one settle nudge after 30s) and retry the identical request once.
  if [ "$rc" -eq 3 ]; then
    if grep -q model_budget_unavailable "$errf"; then
      echo "model policy cold or model retired; warming and retrying..." >&2
      warm_policy && {
        out="$(py_chat "$mode" "$text" 2>"$errf")" && { printf '%s\n' "$out"; rm -f "$errf"; return 0; }
        rc=$?
      }
    fi
    if [ "$rc" -eq 3 ] && [ "$tried_settle" -eq 0 ]; then
      tried_settle=1
      echo "request failed (lease probably rotating); waiting for readiness and retrying once..." >&2
      ensure_ready && {
        out="$(py_chat "$mode" "$text" 2>"$errf")" && { printf '%s\n' "$out"; rm -f "$errf"; return 0; }
        rc=$?
      }
    fi
  fi
  cat "$errf" >&2
  if grep -q model_budget_unavailable "$errf"; then
    echo "available models:" >&2
    curl -sf -m 40 "$API/models" 2>/dev/null | python3 -c 'import json,sys
try:
  for m in json.load(sys.stdin)["data"]: print("  " + m["id"])
except Exception: pass' >&2
    echo "(choose one with: $0 set_model <id>)" >&2
  fi
  rm -f "$errf"; return "$rc"
}

usage() {
  sed -n '3,20p' "${BASH_SOURCE[0]}" | grep '^#' | cut -c3-
}

# Chat commands stamp a process-lifetime in-flight marker; it vanishes with
# the process on any exit path, and stale-by-time rules cover kills -9.
case "${1:-}" in
  make_single_request|start_conversation|ask) : > "$STATE_DIR/active.$$" ;;
esac
trap 'case "${1:-}" in make_single_request|start_conversation|ask) rm -f "$STATE_DIR/active.$$";; esac' EXIT

case "${1:-}" in
  make_single_request)
    [ $# -ge 2 ] || die "usage: $0 make_single_request \"question\""
    guard_inflight
    if server_running; then rotate_circuit || { echo "could not rotate circuit; restarting server" >&2; stop_server; start_server; }; else stop_server; start_server; fi
    ensure_wallet || exit 1
    warm_policy || true
    run_chat fresh "$2"
    ;;
  start_conversation)
    [ $# -ge 2 ] || die "usage: $0 start_conversation \"first message\""
    guard_inflight
    if server_running; then rotate_circuit || { echo "could not rotate circuit; restarting server" >&2; stop_server; start_server; }; else stop_server; start_server; fi
    ensure_wallet || exit 1
    warm_policy || true
    run_chat fresh "$2"
    ;;
  ask)
    [ $# -ge 2 ] || die "usage: $0 ask \"follow-up\""
    if ! server_running; then
      # The server may be live in ANOTHER environment (whose loopback is
      # invisible here) or absent entirely. Either way: claim it and serve
      # locally. History and model live in the shared state root, so the
      # conversation continues; the handover token makes any other world's
      # stack retire itself.
      guard_inflight
      echo "zkapi-tor-cli: no local server; claiming the profile and starting one here..." >&2
      start_server || {
        hint=""
        [ -s "$CFG_DIR/daemon.lock" ] && hint=" (held by: $(cat "$CFG_DIR/daemon.lock" 2>/dev/null); if that environment is suspended it cannot hand over — stop it there first)"
        die "could not start a conversation server$hint"
      }
    fi
    ensure_wallet || exit 1
    warm_policy || true
    run_chat append "$2"
    ;;
  list_models)
    server_running || start_server
    curl -sf -m 15 "$API/models" | python3 -c 'import json,sys
for m in json.load(sys.stdin)["data"]: print(m["id"])'
    ;;
  set_model)
    [ $# -ge 2 ] || { echo "current model: $(active_model)"; exit 0; }
    printf '%s\n' "$2" > "$MODEL_FILE"
    echo "model set: $2"
    ;;
  withdraw)
    shift
    [ $# -ge 1 ] || die "usage: $0 withdraw <0x-address>   (closes the note, sends its remaining balance out, then sweeps the funding address)"
    dest="$1"
    printf '%s' "$dest" | grep -qE '^0x[0-9a-fA-F]{40}$' || die "withdraw: '$dest' is not a 0x address"
    if ! server_running; then
      guard_inflight
      echo "zkapi-tor-cli: starting the server to reach the wallet..." >&2
      start_server
    fi
    btoken="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["zkapi"]["bridge_token"])' "$CONFIG_DIR/config.json" 2>/dev/null)" || die "withdraw: no bridge token in config"
    # any live lease must settle before the note can close
    echo "zkapi-tor-cli: waiting for the current lease to settle before closing the note..." >&2
    ensure_ready || die "withdraw: a lease is stuck unsettled; run again after it settles"
    echo "zkapi-tor-cli: preparing note withdrawal to $dest..." >&2
    resp=""; code=""
    resp="$(curl -s -m 60 -X POST -H "Authorization: Bearer $btoken" -H "Content-Type: application/json" -d "{\"mode\": \"${ZKAPI_WITHDRAW_MODE:-mutual}\", \"destination\": \"$dest\"}" "$COMPANION/wallet/withdraw")"
    code="$(printf '%s' "$resp" | python3 -c 'import json,sys
try: print((json.load(sys.stdin).get("error") or {}).get("code") or "")
except Exception: print("")' 2>/dev/null)"
    case "$code" in
      withdrawal_pending|withdrawal_conflict)
        # A withdrawal is already prepared (possibly toward our funding
        # address). Resume it rather than fight the locked destination: the
        # note pays out where it was promised, and the public sweep step
        # below routes everything onward to $dest anyway.
        echo "zkapi-tor-cli: a withdrawal is already prepared; resuming it (its saved destination stands; the final sweep will still deliver to $dest)." >&2 ;;
      "") : ;;
      *) printf '%s\n' "$resp" >&2; die "withdraw: the wallet refused to prepare the withdrawal" ;;
    esac
    echo "zkapi-tor-cli: confirming withdrawal (generates the close proof; give it a minute)..." >&2
    curl -sf -m 600 -X POST -H "Authorization: Bearer $btoken" -H "Content-Type: application/json" -d '{}' "$COMPANION/wallet/withdraw/confirm" >/dev/null || die "withdraw: confirmation failed (a saved withdrawal is resumable — run again)"
    waited=0
    while :; do
      has="$(curl -sf -m 8 -H "Authorization: Bearer $btoken" "$COMPANION/wallet/status" | python3 -c 'import json,sys;print("yes" if json.load(sys.stdin).get("has_note") else "no")' 2>/dev/null)"
      [ "$has" = no ] && break
      [ "$waited" -ge "${ZKAPI_WITHDRAW_WAIT:-420}" ] && die "withdraw: the note is still open after ${ZKAPI_WITHDRAW_WAIT:-420}s; run again to resume (progress is saved)"
      sleep 5; waited=$((waited + 5))
    done
    echo "zkapi-tor-cli: note closed; its remaining balance is on its way to $dest." >&2
    # sweep the funding address's own ETH if it holds anything worth a transaction
    eoa_wei="$(funding_api GET /admin/funding/address | python3 -c 'import json,sys;print(int(json.load(sys.stdin).get("eth_balance") or 0))' 2>/dev/null || echo 0)"
    if [ "${eoa_wei:-0}" -ge 50000000000000 ]; then  # >= 0.00005 ETH: worth a tx
      echo "zkapi-tor-cli: sweeping the funding address ($(wei2eth "$eoa_wei") ETH) to $dest too..." >&2
      quote="$(funding_api POST /admin/return/quote "{\"destination\": \"$dest\"}")" || { echo "zkapi-tor-cli: could not quote the public sweep (run 'withdraw' again later)." >&2; exit 0; }
      qid="$(printf '%s' "$quote" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')"
      state="$(funding_api POST /admin/return/approve "{\"quote_id\": \"$qid\"}")" || die "withdraw: public sweep approval failed"
      waited=0
      while :; do
        phase="$(printf '%s' "$state" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("phase",""))' 2>/dev/null)"
        echo "zkapi-tor-cli: public sweep $phase" >&2
        [ "$phase" = complete ] && break
        [ "$phase" != return_pending ] && [ "$phase" != confirming ] && break
        [ "$waited" -ge "${ZKAPI_WITHDRAW_WAIT:-420}" ] && { echo "zkapi-tor-cli: public sweep still $phase after ${ZKAPI_WITHDRAW_WAIT:-420}s; run again to resume." >&2; exit 1; }
        sleep 5; waited=$((waited + 5))
        state="$(funding_api POST /admin/return '{}')" || die "withdraw: lost contact during the public sweep"
      done
      printf '%s' "$state" | python3 -c '
import json,sys
s=json.load(sys.stdin)
h=s.get("transaction_hash") or ""
print("Funding sweep done." + (" Transaction: %s" % h if h else ""))' >&2
    fi
    echo "zkapi-tor-cli: withdrawn. To start spending again, just ask a question — a fresh channel opens automatically." >&2
    ;;
  fund)
    if show_funding_state; then :; fi
    if [ $# -ge 2 ] && [ "$1" = "--amount" ]; then open_channel; fi
    ;;
  stop)
    # Clean handoff between environments: stops ONLY the stack this world's
    # CLI started (its pid file lives in this world's /tmp). A daemon in the
    # other world is left alone — the lock names its holder if there is one.
    stop_server
    echo "conversation server stopped (wallet, keys and tor state persist under the config dir)"
    ;;
  *)
    usage; exit 2
    ;;
esac
