# zkapi-clientd

A local OpenAI-compatible API, paid from your private ETH balance. No OA account or OpenRouter API key needed.

## Quick start

Install or update:

```sh
curl -fsSL https://github.com/ethereum/zkapi/releases/download/clientd-v0.1.6/install.sh | bash
```

Configure your wallet:

```sh
zkapi-clientd config
```

Setup updates payment details and progress in place while you wait. Menus use
the arrow keys and Enter; Ctrl+C stops safely and preserves your progress.

Then start the API:

```sh
zkapi-clientd serve
```

Choose a saved default model (stop the daemon before changing it):

```sh
zkapi-clientd list-models
zkapi-clientd set-model provider/model
zkapi-clientd set-model         # show default; --clear removes it
```

The default is used for requests that omit `model` and for funding recommendations.
Explicit request models take precedence. Listing/selection does not spend funds.

`serve` automatically opens a missing private note once funded: it prints the
ETH receiving address, network, and required top-up, then waits for funds.
Use `serve --model MODEL` for a model-aware recommendation:
`max(3 × per-query cap converted to ETH, 10 × estimated deposit gas)`, plus
network fees/buffer. Without a model or saved default, it uses the highest reviewed cap ($6).
Starting `serve` authorizes this deposit; Ctrl+C stops waiting. The recommendation
is a minimum: once funded, the unsigned deposit grows to use the available ETH
minus the quoted maximum fee allowance, rounded down to whole gwei. Unused fee
allowance/dust remain public. Signed transactions retain their amount and are
recovered rather than replaced; explicit manual deposits are not resized.

```sh
zkapi-clientd withdraw          # private withdrawal, then public remainder return
zkapi-clientd withdraw --public # return leftover funding-address ETH separately
```

After private withdrawal, the same command returns public funds to the same
destination with a separate fee approval. Interrupted returns resume; completed
returns are not repeated for dust. Withdrawals can start a temporary daemon
if none is running. See [lifecycle details](docs/CLI_ZKAPI.md#one-command-funding-and-withdrawal).

Leave that terminal running. In Open WebUI or another OpenAI-compatible client, set the base URL to **`http://127.0.0.1:8787/v1`** and leave the API key empty (use `local` if the app requires a value). Select a model and chat. The endpoint accepts local connections only.

The default reuses an OpenRouter key for a fixed window of up to 60 seconds.
Compatible requests from different chats, local clients, and Open WebUI's title
and follow-up requests can share a key and its spending cap; the provider can
link those requests. Your saved key-reuse setting is preserved across updates.
Settlement starts automatically when the window ends, even without another
request. An active response finishes first.
For conversation-aware Tor routing, configure Tor's SOCKS port with
`IsolateSOCKSAuth`, then select `zkapi-clientd config --relay-url tor://127.0.0.1:9050`
while the daemon is stopped. The ordinary OpenAI endpoint now retains a Tor
isolation identity for prefix-continuing message histories and rotates both
identity and provider key for unrelated histories. No wrapper CLI is required.
See [Tor mode and its limits](docs/CLI_ZKAPI.md#tor).

For a fresh key per inference request, stop `serve`, run
`zkapi-clientd config --key-reuse-window-seconds 0`, then restart `serve`.
With reuse disabled, settlement starts after each response. Fresh keys may wait
for the previous key's settlement.

To update, stop `serve`, rerun the install command, then start `serve` again. Your wallet is preserved. See [wallet storage and updates](docs/CLI_PACKAGING.md#wallet-storage-and-updates).

To withdraw, run `zkapi-clientd config --menu` and choose `withdraw`. It asks for the destination and waits for extra ETH for fees only if needed.

[More options, including Tor, Sepolia and Docker clients](docs/CLI_ZKAPI.md) · [Installation details](docs/CLI_PACKAGING.md) · [Privacy](docs/PRIVACY.md)

[NixOS, AUR, and Homebrew packages with background services](docs/CLI_PACKAGING.md#platform-packages-and-background-services) are also available in this repository.
