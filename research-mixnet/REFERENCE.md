# Complete Katzenpost reference assessment

The prototype imports the unmodified Sphinx/SURB package from Katzenpost
`v0.0.107`. That does not evaluate the complete Katzenpost stack or Pigeonhole.
The process comparison reports that reference separately as
`not_run_credential_file_policy`, with no invented performance results.

## Inspected source

The pinned [Docker reference stack](https://github.com/katzenpost/katzenpost/tree/v0.0.107/docker)
has a generator and a headless Compose workflow with authorities, gateways,
mixes, services and replicas. It is a plausible reference testbed. Docker is
available locally, but the generator and testnet have not been started.

The [generator](https://github.com/katzenpost/katzenpost/blob/v0.0.107/core/genconfig/genconfig.go)
defines `identity.private.pem` and `link.private.pem` and writes private keys
while producing configuration (lines 66–68, 1476 and 1509 in this pin).
The [server](https://github.com/katzenpost/katzenpost/blob/v0.0.107/server/server.go)
also reads or creates identity and link key files during startup (lines 392–452).
These were inspected in the checksum-verified local Go module cache.

The user's execution rule says: “Keep API keys, wallet private keys, and other
credentials out of command arguments, output, files, and traces.” Persisting
these identity/link secrets conflicts with that rule. A RAM-backed filesystem
still exposes a file interface and does not by itself satisfy it. No generator
configuration, private key file, testnet, network capture or funded account was
created for this assessment.

## Work required for a reference measurement

Resolve the key-storage constraint explicitly, or review a reference modification
that injects all disposable test secrets through memory without persistence.
The latter requires inspecting every participating service; changing the generator
alone is insufficient. Then pin its complete container/build inputs, integrate
the same bounded synthetic job workload and observation boundary, and collect
real results. Do not reuse the prototype's figures as reference measurements.

Evaluate the complete stack and Pigeonhole's reply/storage behavior before adding
real research prompts, remote hosts or zkAPI credentials. The current direct
control and covered prototype are the only measured backends.
