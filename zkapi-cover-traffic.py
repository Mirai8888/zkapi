#!/usr/bin/env python3
"""zkapi-cover-traffic.py — Poisson cover traffic through the same Tor SOCKS5.

Fires real HTTPS requests (via curl, so DNS and TLS leave through the same
exit as inference) at ~rate/sec with exponentially distributed gaps, each in
its own parallel process. The endpoints are small, stable, public JSON/text
APIs chosen to resemble the size and shape of inference traffic, so an
observer watching the exit node sees a steady trickle rather than bursts that
coincide exactly with user requests.

Usage: zkapi-cover-traffic.py --socks 127.0.0.1:PORT [--rate 5] [--log FILE]
"""
import argparse
import random
import subprocess
import time
import sys

# Stable, long-lived public endpoints with small predictable responses,
# deliberately a mix of operators and content types (plain text, JSON, POST
# echo, one larger HTML page) so the profile is not one host repeated.
SITES = [
    ("https://www.cloudflare.com/cdn-cgi/trace", "GET"),
    ("https://api.ipify.org?format=json", "GET"),
    ("https://ipinfo.io/json", "GET"),
    ("https://jsonplaceholder.typicode.com/todos/1", "GET"),
    ("https://check.torproject.org/api/ip", "GET"),
    ("https://httpbin.org/json", "GET"),
    ("https://httpbin.org/get", "GET"),
    ("https://postman-echo.com/post", "POST"),
    ("https://www.wikipedia.org", "GET"),
]

MAX_INFLIGHT = 30  # a slow exit must not spawn processes without bound


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--socks", required=True, help="SOCKS5 proxy host:port")
    ap.add_argument("--rate", type=float, default=5.0, help="requests per second (0 disables)")
    ap.add_argument("--log", default="", help="append one line per completed request")
    args = ap.parse_args()
    if args.rate <= 0:
        return 0
    log = open(args.log, "a") if args.log else None

    def fire(url: str, method: str) -> subprocess.Popen:
        cmd = ["curl", "-sS", "-o", "/dev/null", "--max-time", "30",
               "-x", "socks5h://" + args.socks,
               "-w", "%{http_code} %{time_total} %{size_download}"]
        if method == "POST":
            cmd += ["-X", "POST", "--data", "probe=1"]
        cmd.append(url)
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True)

    inflight: list[tuple[subprocess.Popen, str]] = []
    while True:
        time.sleep(random.expovariate(args.rate))
        inflight = [(p, u) for (p, u) in inflight if p.poll() is None]
        while len(inflight) >= MAX_INFLIGHT:  # saturated path: drop, never queue forever
            old, _ = inflight.pop(0)
            old.poll()
            inflight = [(p, u) for (p, u) in inflight if p.poll() is None]
        url, method = random.choice(SITES)
        proc = fire(url, method)
        inflight.append((proc, url))
        if log:  # collect finished ones lazily; ordering is not the point
            for p, u in inflight:
                if p.poll() is not None:
                    out, _ = p.communicate()
                    log.write("%s %s %s\n" % (time.strftime("%H:%M:%S"), out.strip(), u))
                    log.flush()
            inflight = [(p, u) for (p, u) in inflight if p.poll() is None]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
