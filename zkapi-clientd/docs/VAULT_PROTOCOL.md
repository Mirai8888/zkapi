# Selecting the on-chain vault protocol

Use the **global** option before the command:

```sh
CLIENT=$HOME/zkapi/zkapi-clientd/bin/zkapi-clientd-concession-tor

# Existing old-vault profile: old stack's automatic funding and inference flow.
$CLIENT --vault-protocol legacy --config-dir /absolute/path/to/legacy-profile serve

# New-vault profile: new stack. Currently refuses undeployed networks.
$CLIENT --vault-protocol concession --config-dir /absolute/path/to/concession-profile serve

# Withdrawal must use the same protocol/profile that owns the note.
$CLIENT --vault-protocol legacy --config-dir /absolute/path/to/legacy-profile withdraw
```

`ZKAPI_VAULT_PROTOCOL=legacy` or `concession` sets the default; an explicit flag
wins. Without either, concession remains the default. The selector is not stored
in `config.json`: the old decoder would reject that field. Set the environment
in your service definition for a persistent preference. No files or profiles
are copied, rewritten or created by selection. `version`/top-level `help` report
the dispatcher; command-specific help in legacy mode requires its valid profile.

## This selects a stack, not an address

Concession uses circuit `zkapi-v2-concession-v1`, vault revision 3, and its current
compiled manifests. Legacy uses `zkapi-v2-note-bound-v1` and the historical
compiled manifests, client, companion and verified proving setup. A new prover
cannot operate an old vault by replacing a contract address.

Legacy dispatch verifies SHA-256 pins for the local historical executables:

- sibling `bin/zkapi-clientd-tor-mode`, preserved development client (source
  checkpoint `be04d85`, not the upstream 0.1.7 recovery release);
- the legacy profile's explicitly configured absolute companion path, matching
  the preserved `bin/zkapi-walletd` artifact.

The profile must also explicitly name its absolute original proving-setup path;
the old companion validates its own proving/deployment pins. External companions
and companion/setup overrides through this dispatcher are refused. Missing or
changed binaries fail, with no PATH lookup or concession fallback. Updating the
legacy bundle requires reviewing and updating these pins in source. This is a
local development pairing, not a downloadable production bundle.

The dispatcher replaces itself with the legacy executable, preserving terminal
interaction, signals, profile locks and exit status. It does not sign or deposit
by itself, add approval flags, call raw contracts, or modify transaction journals.
`serve` retains the selected stack's existing automatic funding behavior.

## Important current limits

- **Concession remains `not_deployed`** on both shipping networks, with missing
  production proving keys. Selection does not make it available.
- The preserved legacy binary predates native rewriter and cover traffic.
  Profiles enabling those features are rejected rather than silently sending
  raw prompts or dropping cover. New concession exit/bundler settings are also
  incompatible. Use a compatible existing legacy profile, not a sanitized copy
  that silently loses privacy requirements. Rewriter/cover are not ported back.
- Upstream's planned legacy 0.1.7 recovery line closes deposits and retires
  admission on a schedule. This selector does not establish that historical
  deposits or inference are still available today, and cannot bypass gateway,
  contract or selected-release closures. Do not deposit unless the legacy
  service's live availability and retirement schedule have been reviewed.
- The old gas-heavy deposit path remains gas-heavy. Selecting legacy is not a
  cheaper implementation of the concession protocol.
- Keep separate profile directories for the two stacks: funding records and
  pending signed transactions must not be repurposed across deployments. For
  recovery, point explicitly at the **original** legacy profile. An environment
  default config directory does not satisfy the legacy explicit-profile rule.
  Use distinct API/companion ports if running both stacks concurrently.
- Configuration/profile edits do not migrate notes. A note remains withdrawable
  only through its matching protocol and original state/proving assets.

No service is restarted or live deposit attempted by implementing this option.
Unit tests cover dispatch arguments, environment precedence, executable pins,
required explicit profiles and refusal of privacy/companion downgrades. Live
legacy deposit acceptance and new-vault availability have not been verified.
