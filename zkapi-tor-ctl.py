#!/usr/bin/env python3
"""zkapi-tor-ctl.py — tiny Tor control-port client (stdlib only).

Usage: zkapi-tor-ctl.py PORT newnym

Sends SIGNAL NEWNYM: Tor drops all circuits and builds fresh ones (new exit,
new middle) while keeping its guard set and directory state — the cheap
"new conversation, same long-term client" boundary. Authenticates with the
DataDirectory's control cookie (SAFECOOKIE) or NULL if configured.
"""
import hashlib
import hmac
import os
import random
import socket
import sys


def read_reply(sock: socket.socket) -> list[str]:
    """Read one full control reply (possibly multiline 250-)."""
    f = sock.makefile("rb")
    lines = []
    while True:
        line = f.readline().decode("utf-8", "replace").rstrip("\r\n")
        lines.append(line)
        if len(line) >= 4 and line[3] == " ":
            return lines
        if len(line) >= 4 and line[3] == "-":
            continue
        return lines  # single-line status (e.g. 650 events) — best effort


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: zkapi-tor-ctl.py PORT newnym", file=sys.stderr)
        return 2
    port, command = int(sys.argv[1]), sys.argv[2].lower()
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)

    sock.sendall(b"PROTOCOLINFO 1\r\n")
    info = "\n".join(read_reply(sock))
    if "SAFECOOKIE" in info:
        cookiefile = info.split('COOKIEFILE="')[1].split('"')[0]
        cookie = open(cookiefile, "rb").read()
        nonce = bytes(random.getrandbits(8) for _ in range(32))
        sock.sendall(b"AUTHENTICATE SAFECOOKIE\r\n")
        challenge = "\n".join(read_reply(sock))
        server_nonce = bytes.fromhex(challenge.split("CHALLENGE=")[1].split()[0])
        key = hmac.new(cookie, b"Tor safe cookie authentication server-to-controller hash", hashlib.sha1).digest()
        client_hash = hmac.new(key, nonce + server_nonce, hashlib.sha1).hexdigest()
        sock.sendall(("AUTHENTICATE %s\r\n" % client_hash).encode())
        expect = hashlib.sha1(cookie + b"Tor safe cookie authentication controller-to-server hash" + nonce + server_nonce).hexdigest()
        reply = "\n".join(read_reply(sock))
        if expect not in reply.replace("\r\n", "").replace("HS=", ""):
            print("server hash mismatch (possible on-path impostor)", file=sys.stderr)
            return 1
    elif "NULL" in info:
        sock.sendall(b"AUTHENTICATE\r\n")
        read_reply(sock)
    else:
        print("unsupported control auth methods: %s" % info, file=sys.stderr)
        return 1

    if command == "newnym":
        sock.sendall(b"SIGNAL NEWNYM\r\n")
        reply = "\n".join(read_reply(sock))
        if not reply.startswith("250 OK"):
            print("NEWNYM rejected: %s" % reply, file=sys.stderr)
            return 1
        print("newnym signaled")
        return 0
    print("unknown command %r" % command, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
