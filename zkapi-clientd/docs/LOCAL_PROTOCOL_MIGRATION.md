# Local Tor client: concession-protocol migration

This worktree merges upstream `df88556` into the custom Tor client. Development
now lives in `/home/v/zkapi` on branch `feat/client-concession-local`, including
the prompt rewriter and target-side transcript. The migration was originally
prepared in `/home/v/zkapi-protocol`; that worktree remains as a checkpoint.
Legacy executables and wallet profiles are unchanged. This is a development
build, not a deployed production release.

## Protocol and deployment gate

The client now uses vault revision 3 and circuit `zkapi-v2-concession-v1`,
including upstream concession exits, independent exit-RPC support, and
payout-funded withdrawals where a deployed manifest enables them. The Rust
companion is `crates/zkapi-companion`, not the removed legacy companion patch.

**Both shipping networks remain `not_deployed`.** There is no configured vault,
indexer or protocol-server address. The production setup directory
`protocol/setup/v2-concession` also has no ceremony keys. The CLI checks its
embedded manifest before attaching to a daemon or starting funding. It must
not fall back to the old vault, test fixtures, or development proving keys.

Tor SOCKS authentication isolation, conversation key rotation, diagnostics,
saved default models, compact funding display, deposit-all-minus-fees and
private-plus-public guided withdrawal are retained. Actual circuit isolation
still requires Tor's `IsolateSOCKSAuth` configuration.

## Outputs

- `zkapi-clientd/bin/zkapi-clientd-concession-tor`: new Go daemon.
- `zkapi-clientd/bin/zkapi-walletd-concession`: new Rust companion compiled
  in release mode without `dev-setup`.

These binaries alone are **not an installable working wallet bundle**: pinned
production proving assets and reviewed deployed manifests are still missing.
Do not point the new daemon at the old companion/proving setup. No home-profile
configuration, wallet record, or running service was changed for this migration.

## Withdrawal interface

- Bare `withdraw`: guided private close followed by a separately approved
  public return. Credited-but-unclaimed private payouts block the public sweep
  so recovery fees remain available.
- `withdraw --public`: standalone public return.
- Explicit upstream options (`--to`, `--escape`, `--conceded`, `--fees payout`,
  `--approve`, `--resume`, `--claim`, `--collect`, `--sweep`, `--claim-credit`)
  run through a temporary runtime with **no automatic deposit**. They retain
  upstream quote/approval semantics and do not automatically sweep public ETH.
- Use `withdraw --help` for all explicit options. Configure an independent RPC
  with `config --exit-rpc-url URL`.

Legacy notes require the legacy release and their original state directories.
This migration does not convert notes or send transactions.

## Validation

Go race tests and vet; Rust companion/auth and protocol-client release tests.
The upstream Anvil adapter test skips on hosts without Foundry; a passing Rust
test command alone is not evidence of on-chain verification. Live Tor/provider,
new-vault deposit, and withdrawal tests remain unperformed.
