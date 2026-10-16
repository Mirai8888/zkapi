# Direct prompt rewriter (opt-in)

This development feature normalizes the writing style of the **trailing user
message**, then sends the rewritten request through the ordinary zkAPI target
path. It is not a demonstrated defense against stylometric deanonymization.

## Configure

Stop the daemon before editing its configuration. In this worktree:

```sh
CLIENT=/home/v/zkapi-protocol/zkapi-clientd/bin/zkapi-clientd-concession-tor
$CLIENT set-rewriter --url http://localhost:8011 --model qwen3.8-flash-next
$CLIENT set-rewriter                      # status, never prints the key
$CLIENT set-rewriter --clear              # disable and remove the saved key
```

No API key is sent when omitted. For a keyed service, populate an environment
variable using your normal secret-management method, then use:

```sh
$CLIENT set-rewriter --url https://rewriter.example/v1 --model MODEL \
  --api-key-env REWRITER_API_KEY
```

The variable's value is saved in owner-only `config.json` using the existing
locked, atomic configuration update. Do not put a key in the URL or command
line. Existing wallet, inference and management credentials are preserved.
Setting URL/model again without `--api-key-env` clears the rewriter key.

The URL accepts an OpenAI-compatible API base or a complete `/chat/completions`
endpoint. An origin alone adds `/v1/chat/completions`. Remote endpoints require
HTTPS with certificate verification; HTTP is allowed only on loopback.
The transport is direct: **it deliberately ignores Tor, Wisp and environment
proxies**. It uses no cookies and does not follow redirects or retry requests.

Configuration makes no model request or payment. The feature is disabled by
default. Older binaries may reject the new configuration field; clear it before
rolling back. No user's existing profile is automatically changed by this work.

## What is sent and changed

- Rewriter receives a fixed normalization instruction and a JSON array of the
  latest message's nonempty text parts. No earlier turns, system prompt, tool
  definitions/results, image URLs, names or target credentials are included.
- The editor is asked to standardize style without answering the request or
  changing meaning, and to preserve code, quotes, identifiers, numbers, paths,
  URLs and exact-output requirements. **Meaning preservation is an instruction,
  not something the daemon can prove. Review the preview.**
- Only those text parts are replaced. Nontext parts and all other request
  values are retained. Mixed image/text messages retain their images, but the
  rewriter does not see them and therefore cannot resolve visual references.
- If the final message is assistant/tool rather than user, rewriting is skipped.
  This prevents tool continuations from rewriting an old user turn repeatedly.
- Earlier messages remain as the caller supplied them. **If the caller replays
  original older user turns, the target sees their original writing style.**
  There is no rewrite-history cache or silent history mutation.
- Text input/output is limited to 128 KiB; HTTP response to 1 MiB; rewriting to
  90 seconds. Structured output must have exactly the expected number of strings
  and a successful `stop` finish reason. Invalid output, truncation, tool calls,
  refusal, cancellation and HTTP failures stop the request. The original is
  never used as a fallback. Structured output is required; incompatible models
  fail rather than silently forwarding prose or chain-of-thought.

## Immediate preview and client compatibility

Default `--notice reasoning` sends a flushed SSE prelude as soon as rewriting
finishes, **before lease acquisition or target inference**. It contains:

- `choices[0].delta.reasoning_content`, clearly labelled
  `zkapi prompt rewrite — NOT target-model thinking`;
- `zkapi_rewrite: {source, message_index, texts}`, for custom client rendering.

The rewritten strings are quoted for unambiguous display. The prelude is local
UI metadata, not part of the request sent to the target. Target reasoning,
answers, tool calls and usage follow unchanged. The UI might group the prelude
with target thinking; it is not a separately signed reasoning block.

Alternatives, selected when setting the URL/model:

- `--notice metadata`: only the structured metadata, no thinking delta. Most
  stock clients ignore this unless an adapter/extension renders it.
- `--notice off`: no preview.

For nonstreaming requests there can be no immediate HTTP-body preview:
`zkapi_rewrite` is added to the final JSON (unless off); answer/tool content is
unchanged. Nonstreaming responses with a preview are bounded to 16 MiB.

Compatibility checked against source/documentation, not live UI integration:

- **pi:** its OpenAI Chat Completions adapter consumes `reasoning_content` as
  `thinking_delta`. Thinking blocks can be collapsed/expanded with Ctrl+T.
  Use the `openai-completions` API for this daemon. See
  [adapter source](https://github.com/badlogic/pi-mono/blob/main/packages/ai/src/api/openai-completions.ts)
  and pi's local `docs/models.md`.
- **Hermes:** its CLI selects a live reasoning callback when `show_reasoning`
  and streaming are enabled; otherwise reasoning may be hidden or limited to
  a verbose preview. See
  [CLI display](https://github.com/NousResearch/hermes-agent/blob/main/hermes_cli/cli_stream_mixin.py)
  and [reasoning tests](https://github.com/NousResearch/hermes-agent/blob/main/tests/agent/test_streamed_reasoning_details.py).
- There is no universally displayed OpenAI-compatible warning field. Clients
  may persist the synthetic thinking and replay it later. For strict signed
  reasoning or clean-history requirements, use metadata/off plus a client UI
  adapter instead. No pi/Hermes extension is installed by this change.

Once a preview commits HTTP 200, later failures are returned as SSE `error`
frames followed by `[DONE]`, not a new HTTP status. Clients must handle streamed
errors. Verification response headers may not be available after early flush;
the backend still verifies leases normally. Preview does not mean inference
succeeded. It does not pause for approval: cancel the request to stop it.

## Tor overlap and privacy boundaries

Under the existing serialized request slot, the daemon first classifies the
original incoming history and selects its conversation identity. Rewriting
runs while a separate SOCKS CONNECT asks Tor for an isolated stream to the
configured inference host. This stream sends no HTTP, prompt or provider key
and closes after connection preparation. Inference uses the same SOCKS identity
with a fresh verified TLS connection. No global NEWNYM or direct/no-auth fallback.

This can trigger circuit construction while rewriting runs; SOCKS cannot prove
construction, exit rotation or circuit reuse. Tor still needs `IsolateSOCKSAuth`.
Preparation failure stops inference. Lease acquisition begins only after both
rewriting and preparation succeed, so failed rewriting cannot purchase a lease.
Tool continuations/image-only messages skip this extra preparation step.

The rewriter learns your original message and direct network identity; remote
HTTPS is encryption in transit, **not anonymity from the rewriter**. The
rewriter may itself forward the prompt elsewhere. Content facts, preserved code,
quotes, older history and timing can identify you. Parallel activity may also
help a traffic observer correlate rewriter and Tor use. No anonymity guarantee.

## Tests and deployment status

Unit/integration fixtures cover text-only disclosure, preserved history/images,
fail-closed errors, credentials/redirects, cancellation, actual SOCKS/rewrite
concurrency, preview-before-target ordering, SSE errors and config preservation.
A synthetic live test is opt-in:

```sh
cd /home/v/zkapi-protocol/zkapi-clientd
ZKAPI_TEST_REWRITER=1 go test -v ./internal/rewriter -run TestLiveLocalRewriter
```

It sends only a synthetic hash-map question to localhost:8011 and does not use
zkAPI, a wallet, or a target model. At implementation time that port refused
connections, so live Qwen rewriting was not validated.

The separate upstream blockers are unchanged: the new-protocol production
keys and deployed network manifests are missing. This feature does not bypass
those checks or enable live zkAPI use before deployment.
