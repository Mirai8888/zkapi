# Saved configuration

From the repository root:

```sh
CLIENT="$PWD/zkapi-clientd/bin/zkapi-clientd-concession-tor"
# Add --config-dir /absolute/profile BEFORE config when using a custom profile.
"$CLIENT" config
```

Bare `config` prints **only pretty-printed JSON** for the saved profile. It does
not initialize a wallet, start a companion, contact services or fund anything.
The view includes disabled/optional fields and the saved vault selection (default
`concession`). Credentials are `[redacted]`; URL credentials, non-root paths,
queries and fragments are hidden. It is a view, not an importable wallet backup.
An absent or invalid profile produces an error, not a newly initialized wallet.
`config --status` also prints this view. Runtime overrides are not saved settings.

Stop `serve` before editing. Settings edits validate and save atomically under
the profile lock and never run setup, send requests or make payments:

```sh
"$CLIENT" config --vault-protocol legacy
"$CLIENT" config --relay-url tor://127.0.0.1:19050
"$CLIENT" config --model openai/gpt-6.1-sol-pro
"$CLIENT" config --rewriter-url http://localhost:8012 --rewriter-model qwen3.8-flash-next
"$CLIENT" config --rewriter-notice metadata
"$CLIENT" config --cover-urls 'https://your-controlled-domain.example/cover' --cover-rate 5
"$CLIENT" config --key-reuse-window-seconds 60
```

Tor must already listen on the configured port with `IsolateSOCKSAuth`. The
client does not launch Tor. Rewriting connects directly, outside Tor. Cover
requires explicit destinations you control or have permission to poll; 5/s can
consume substantial bandwidth. Neither feature guarantees anonymity.

Related fields can be changed together (for example Tor endpoint and cover).
Omitted fields retain their existing values, including rewriter credentials.
On first configuration, cover defaults to 5/s and 4 workers; rewriter preview
defaults to `reasoning`. Read a new editor key from an environment variable with
`--rewriter-api-key-env NAME`; remove only the key with `--rewriter-clear-api-key`.
Use `--cover-concurrency N` for its bounded worker count.

```sh
"$CLIENT" config --clear-model
"$CLIENT" config --clear-rewriter
"$CLIENT" config --clear-cover
"$CLIENT" config --vault-protocol concession
"$CLIENT" config --vault-protocol default
```

Vault edits must be separate from other edits: the preference remains in the
existing `vault-protocol` file beside `config.json`, preserving profiles without
a storage migration or a non-atomic two-file update. Selecting a protocol does
not migrate notes or bypass artifact/deployment checks. Legacy companion/setup
paths cannot be replaced through this settings editor.

The top-level `set-model`, `set-rewriter`, `set-cover` and `set-vault-protocol`
commands are removed. Use `config --help` for settings, and `list-models` for the
public model catalog. `--model` validates the ID syntax without contacting the
catalog; inference still checks current model policy.

## Explicit wallet actions

```sh
"$CLIENT" config --setup   # initialize/prepare/fund; interactive wallet action
"$CLIENT" config --menu    # wallet management actions
"$CLIENT" config --edit    # legacy interactive setup editor; can prepare wallet
"$CLIENT" withdraw
"$CLIENT" serve --semi-verbose
```

Use `config --setup` instead of bare `config` in old setup/funding instructions.
`serve` retains its existing autofunding behavior; diagnostic logging flags
remain runtime-only because they expose private prompts/responses. No saved
settings, active services, notes or recovery journals are changed by an upgrade.
