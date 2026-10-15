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
[ -x "$BIN" ] || { echo "zkapi-serve-tor: daemon not found at $BIN" >&2; exit 1; }
command -v tor >/dev/null 2>&1 || { echo "zkapi-serve-tor: tor not in PATH" >&2; exit 127; }

datadir="$here/.tor-state"
mkdir -p "$datadir" && chmod 700 "$datadir" || exit 1
log="$datadir/tor.log"; : > "$log"

# Random kernel-assigned ports (bind, read back, close — races are fine here:
# Tor rebinds and the daemon reads the saved value after bootstrap).
rand_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
socks_port="$(rand_port)"
ctl_port="$(rand_port)"

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
  [ -n "$coverpid" ] && kill -KILL "$coverpid" 2>/dev/null
  [ -n "$child" ] && kill -TERM "$child" 2>/dev/null
  [ -n "$torpid" ] && kill -KILL "$torpid" 2>/dev/null
  rm -f "$datadir/socks_port" "$datadir/control_port"
  # Restore direct mode so later non-Tor runs don't fail closed on a dead port.
  "$BIN" config --relay-url "" >/dev/null 2>&1 || true
  exit $rc
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

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

# Conversations should ride one ephemeral provider key for its whole life
# (issuer TTL is 300s; the daemon clamps reuse to the earlier of window end
# and key expiry, so this is the key's full lifetime and never past it).
# Ask messages inside the window cost ~seconds; only the ~5-minute rotation
# pays the retire-and-reissue ceremony. ZKAPI_KEY_REUSE_WINDOW tunes it down.
"$BIN" config --key-reuse-window-seconds "${ZKAPI_KEY_REUSE_WINDOW:-300}" >/dev/null 2>&1 || true

"$BIN" config --relay-url "socks5://127.0.0.1:${socks_port}" >/dev/null || { echo "failed to save relay URL" >&2; exit 1; }
echo "zkapi-serve-tor: route saved as socks5://127.0.0.1:${socks_port} (cover traffic ~${ZKAPI_COVER_RATE:-5}/s); serving (plain, no torify)" >&2
"$BIN" serve &
child=$!
rc=0
wait "$child" || rc=$?
exit $rc
