#!/usr/bin/env bash
#
# zkapi-serve-tor.sh — zkapi-native Tor for the zkAPI daemon.
#
#   * ONE long-lived Tor client (persistent DataDirectory at .tor-state/):
#     guards and directory state survive restarts, so bootstrap is fast and
#     the entry path is stable. First run pays a full bootstrap.
#   * Circuits rotate per CONVERSATION, not per request: zkapi-tor-cli.sh
#     sends SIGNAL NEWNYM on the control port when a conversation starts and
#     leaves the circuit alone while the conversation runs
#     (MaxCircuitDirtiness is set high so Tor does not rotate underneath it).
#   * Cover traffic: real HTTPS requests to a spread of small public APIs run
#     through the same SOCKS port at ~5/sec Poisson, in parallel, so the exit
#     sees steady traffic that does not exactly coincide with your requests
#     (ZKAPI_COVER_RATE=0 disables).
#   * All daemon egress flows through Tor via the built-in SOCKS5 transport
#     (config --relay-url socks5://...) — no torify, no LD_PRELOAD.
#   * On exit, direct mode is restored; .tor-state/ is kept on purpose.
set -uo pipefail

here="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
# Portable config home: if a repo-local .config/zkapi-clientd exists (e.g. a
# wallet backed up into the working tree), prefer it so the stack travels with
# the checkout; otherwise fall back to the standard user config directory.
if [ -f "$here/.config/zkapi-clientd/config.json" ]; then export XDG_CONFIG_HOME="$here/.config"; fi
BIN="$here/zkapi-clientd/bin/zkapi-clientd"
# ONE state root for everything: config, bridge tokens, wallet keys, locks,
# and the Tor client's directory. A checkout's money lives where its state
# lives; two stacks collide only if they point at the same directory.
CONFIG_DIR="${ZKAPI_CLIENTD_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/zkapi-clientd}"
[ -x "$BIN" ] || { echo "zkapi-serve-tor: daemon not found at $BIN" >&2; exit 1; }
command -v tor >/dev/null 2>&1 || { echo "zkapi-serve-tor: tor not in PATH" >&2; exit 127; }

datadir="$CONFIG_DIR/tor"
mkdir -p "$datadir" && chmod 700 "$datadir" || exit 1
log="$datadir/tor.log"; : > "$log"

# Random kernel-assigned ports (bind, read back, close — races are fine here:
# Tor rebinds and the daemon reads the saved value after bootstrap).
rand_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
socks_port="$(rand_port)"
ctl_port="$(rand_port)"

# The claim is split in two, deliberately:
#   * a PURE lock probe (flock -n) runs before bootstrapping Tor — it fails
#     fast and drives the cooperative handover without touching any service
#     logic; do NOT use `config --relay-url` here, because config runs health
#     checks that need the relay (Tor) already alive;
#   * the actual relay-URL write happens after bootstrap, when its checks can
#     succeed through the live relay.
# Ownership is a cooperative token, not a fight: $CONFIG_DIR/owner holds a
# monotonic epoch plus holder pid/host. A launcher that sees its epoch changed
# knows another world claimed the wallet while it sat idle, and retires
# itself (running its cleanup, releasing daemon.lock and the wallet). The
# claiming side bumps the epoch and waits for the lock to actually release,
# so there is never a window with two spenders — only a handover. (A
# SUSPENDED holder can't poll its epoch; then this degrades to manual, never
# to a double spend: flock and the issuer's one-lease-per-note guard money.)
OWNER="$CONFIG_DIR/owner"
owner_epoch() { awk 'NR==1{print $1}' "$OWNER" 2>/dev/null; }
epoch=""
take_ownership() {
  exec 9>"$CONFIG_DIR/owner.lock"
  flock 9
  epoch=$(( $(owner_epoch || echo 0) + 1 ))
  printf '%s %s %s\n' "$epoch" "$$" "$(hostname)" > "$OWNER.tmp"
  mv -f "$OWNER.tmp" "$OWNER"
  exec 9>&-
}
have_lock() { flock -n "$CONFIG_DIR/daemon.lock" true 2>/dev/null; }

# No "$BIN" calls until the lock is ours: the config command runs health
# checks (and a transient check-mode service) that hang or mislead while
# another daemon holds the profile. Pure probes only, until we own it.
if ! have_lock; then
  holder="$(cat "$CONFIG_DIR/daemon.lock" 2>/dev/null || echo '?')"
  echo "zkapi-serve-tor: profile held by $holder; requesting handover (epoch bump)..." >&2
  take_ownership
  waited=0
  while [ "$waited" -lt "${ZKAPI_TAKEOVER_WAIT:-60}" ]; do
    sleep 1; waited=$((waited + 1))
    have_lock && break
  done
  have_lock || {
    echo "zkapi-serve-tor: still held after ${ZKAPI_TAKEOVER_WAIT:-60}s (holder: $holder). If that environment is suspended it cannot hand over cooperatively; stop that zkapi-clientd first." >&2
    exit 1
  }
fi
take_ownership
echo "zkapi-serve-tor: owner epoch $epoch (pid $$ host $(hostname))" >&2

tor --ClientOnly 1 --PublishServerDescriptor 0 \
    --SocksPort "127.0.0.1:${socks_port}" \
    --ControlPort "127.0.0.1:${ctl_port}" \
    --DataDirectory "$datadir" \
    --MaxCircuitDirtiness 86400 \
    --SafeLogging 1 \
    ${TOR_ISOLATE_EXTRA_OPTS:+$TOR_ISOLATE_EXTRA_OPTS} \
    1>"$log" 2>&1 &
torpid=$!
coverpid=""
child=""
cleanup() {
  rc=$?
  [ -n "$watchdog" ] && kill "$watchdog" 2>/dev/null
  [ -n "$coverpid" ] && kill -KILL "$coverpid" 2>/dev/null
  [ -n "$child" ] && kill -TERM "$child" 2>/dev/null
  [ -n "$torpid" ] && kill -KILL "$torpid" 2>/dev/null
  rm -f "$datadir/socks_port" "$datadir/control_port"
  # Restore direct mode so later non-Tor runs don't fail closed on a dead
  # port — but only while WE are still the owner: after a handover the new
  # owner's relay setting must survive our exit.
  if [ -z "$epoch" ] || [ "$(owner_epoch)" = "$epoch" ]; then
    "$BIN" config --relay-url "" >/dev/null 2>&1 || true
  fi
  exit $rc
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

# Retirement watchdog: poll the ownership token; concede on claim-over.
(
  while sleep 5; do
    if [ "$(owner_epoch)" != "$epoch" ]; then
      echo "zkapi-serve-tor: profile claimed over by epoch $(owner_epoch); retiring" >&2
      kill -TERM "$$" 2>/dev/null
      exit 0
    fi
  done
) &
watchdog=$!

elapsed=0
shown=0
while ! grep -q "Bootstrapped 100" "$log" 2>/dev/null; do
  if ! kill -0 "$torpid" 2>/dev/null; then echo "tor exited early:" >&2; tail -5 "$log" >&2; exit 1; fi
  if [ "$elapsed" -ge "${TOR_ISOLATE_TIMEOUT:-180}" ]; then echo "bootstrap timed out:" >&2; tail -5 "$log" >&2; exit 1; fi
  # surface tor's actual progress lines (Bootstrapped X% (stage)) as they appear
  n=$(grep -c "Bootstrapped" "$log" 2>/dev/null); [ -z "$n" ] && n=0
  if [ "$n" -gt "$shown" ]; then grep "Bootstrapped" "$log" | tail -n $((n - shown)) >&2; shown=$n; fi
  if [ $((elapsed % 10)) -eq 0 ] && [ "$elapsed" -gt 0 ]; then echo "still bootstrapping (${elapsed}s)..." >&2; fi
  sleep 1; elapsed=$((elapsed + 1))
done
echo "$socks_port" > "$datadir/socks_port"
echo "$ctl_port" > "$datadir/control_port"

python3 "$here/zkapi-cover-traffic.py" --socks "127.0.0.1:${socks_port}" \
    --rate "${ZKAPI_COVER_RATE:-5}" --log "$datadir/cover.log" &
coverpid=$!

# Conversations ride one ephemeral provider key for its whole life (issuer
# TTL is 300s; the daemon clamps reuse to key expiry, never past it). Ask
# messages inside the window cost ~seconds; only the ~5-minute rotation pays
# the retire-and-reissue ceremony. ZKAPI_KEY_REUSE_WINDOW tunes it down.
echo "zkapi-serve-tor: route saved as socks5://127.0.0.1:${socks_port} (cover traffic ~${ZKAPI_COVER_RATE:-5}/s); serving (plain, no torify)" >&2
"$BIN" config --key-reuse-window-seconds "${ZKAPI_KEY_REUSE_WINDOW:-300}" >/dev/null 2>&1 || true
"$BIN" config --relay-url "socks5://127.0.0.1:${socks_port}" >&2 || { echo "zkapi-serve-tor: failed to save relay URL" >&2; exit 1; }
"$BIN" serve &
child=$!
rc=0
wait "$child" || rc=$?
exit $rc
