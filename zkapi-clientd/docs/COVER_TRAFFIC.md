# Native Tor cover traffic (opt-in)

The daemon can make dummy HTTPS GET requests in the background while an explicit
`serve` runtime is active. This replaces the Python/curl worker when using the
native client; no subprocess or paid inference is involved. Disabled by default.

## Configure

Stop the daemon before editing its saved settings. Configure the existing
network proxy as `tor://127.0.0.1:PORT` (not `socks5://`) and enable Tor's
`IsolateSOCKSAuth` on that SOCKS listener. Then:

```sh
CLIENT=$HOME/zkapi/zkapi-clientd/bin/zkapi-clientd-concession-tor

# Replace these examples with small static resources you control or have
# permission to poll. No service is contacted by this configuration command.
$CLIENT set-cover \
  --urls 'https://your-domain.example/cover-a.txt https://your-domain.example/cover-b.json' \
  --rate 0.2 --concurrency 4

$CLIENT set-cover          # safe status, no destination paths
$CLIENT serve             # normal deployment/funding gates still apply
$CLIENT set-cover --clear  # with daemon stopped: remove settings
```

Rate is the mean attempted arrivals/second, not guaranteed throughput. Range
0.01–5, default 0.2 (about 12 arrivals/minute). Maximum in-flight requests is
1–8, default 4. `--urls` is required each time settings are replaced; 1–16
whitespace-separated HTTPS URLs, port 443 only. Credentials, query strings,
fragments and literal local/private addresses are rejected. Names are resolved
by Tor, not locally: this validation is not a DNS-rebinding/public-IP guarantee.
Do not configure sensitive URLs, signed paths, state-changing GET endpoints,
paid APIs, zkAPI/OpenRouter/payment endpoints or a service without permission.

Unlike the old helper, no collection of third-party APIs is hammered by default.
The old rate of 5/s is still an explicit option but can generate considerable
load. At 0.2/s with every response hitting the 64 KiB cap, response payload alone
could approach 45 MiB/hour, excluding TLS/Tor overhead. Five per second can exceed
1 GiB/hour. Actual throughput can be lower because arrivals are dropped when
busy. Cover consumes bandwidth and remote resources, **not zkAPI credit**.

Settings are saved atomically under the existing profile lock. Wallet records,
credentials, rewriter settings and model choices are preserved. A configured
cover worker refuses non-Tor routing; clear it before disabling the Tor proxy.
Older binaries may reject the new `cover` field; clear it before rollback.

## Scheduling and isolation

- Random exponential (Poisson) interarrival times, independent of prompts,
  completions, rewriting, model choice or wallet activity. First arrival is also
  randomized; there is no immediate startup burst. Continues during idle periods.
- Cryptographic randomness for timing/destination selection; uniform choice of
  the configured URL entries (duplicate entries weight a destination).
- Fixed worker pool and **unbuffered** dispatch: saturation drops arrivals,
  never accumulates a queue or forgets running requests. There is no catch-up
  burst and no automatic failure retry or inference-triggered acceleration.
- At most 20 seconds/request and 64 KiB response body plus a one-byte overflow
  check. Bodies are discarded, not logged or retained. Encoded responses are
  not decompressed. No POST bodies, cookie jar, referrer, API keys or redirects.
- Each worker has its own random, process-lifetime SOCKS identity. Those
  identities never come from inference or payment contexts. Reusing this small
  pool avoids creating a new isolation identity for every dummy request.
- Authenticated `tor://` only: remote DNS, verified destination TLS, no direct
  or unauthenticated fallback, no global NEWNYM. Environment HTTP proxies are
  ignored. HTTP connections are not kept alive across requests.
- Only cancellation is inherited from the daemon, not diagnostics, wallet state,
  rewriter context or conversation identity. No individual request logs; once
  per minute and at shutdown, aggregate attempted/succeeded/failed/skipped and
  response-byte totals are printed. Raw remote errors/URLs/identities are omitted.

Shutdown cancels and joins every worker. Temporary configuration, withdrawal,
public return and model-listing runtimes do not start cover traffic. An explicit
serve can emit cover while funding/readiness is pending, but it cannot bypass
the deployment/companion startup gates. Attaching to an already running daemon
does not create an extra worker; restart to apply changes.

## Honest privacy limitations

This is background noise, **not proven traffic-analysis protection**. Different
SOCKS identities may use different circuits/exits (or the same exit); Tor can
replace circuits at any time. It is not guaranteed to mix cover with inference
at an exit. A local observer can see extra traffic through Tor, while an exit
observer may distinguish destinations and small GETs from streamed inference.
The selected hosts, generic User-Agent, TLS fingerprint, response sizes and
schedule may themselves be recognizable. A global observer can still correlate
traffic. This does not pad inference, conceal service startup/shutdown, make
constant-rate encrypted traffic, or address the rewriter's direct connection.
Do not interpret the byte cap as a total network-wire bandwidth cap.

Cover can compete with real requests for Tor bandwidth. If failures/skips stay
high, fix the route/endpoints or reduce the rate; the daemon deliberately does
not change its schedule based on user request timing. A target can log the Tor
exit and requested public path. Probes must contain no private content.

## Legacy helper and release status

`zkapi-cover-traffic.py` and `zkapi-serve-tor.sh` are retained for legacy workflows.
The wrapper still starts its own Python worker. Do not run both cover systems:
use native `serve` for this feature, rather than the old launcher. No existing
process or saved profile has been changed automatically.

The new concession release still needs reviewed deployed manifests and production
proving keys before live wallet use. Cover does not remove those blockers. Tests
use fake transports/local SOCKS and TLS fixtures, including downgrade rejection,
remote DNS, TLS rejection, bounded concurrency/read sizes and joined shutdown;
no third-party load test is run automatically. These tests do not demonstrate
an anonymity improvement or an actual Tor circuit build.
