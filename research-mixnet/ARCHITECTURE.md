# Private research daemon: architecture and milestones

Selected first product: a headless research daemon. Its useful unit is an
asynchronous research job, not a remotely streamed keystroke-by-keystroke chat.

## Intended flow

1. A local client submits a goal over an authenticated local API or owner-only
   Unix socket. The daemon keeps the goal, identity mapping and retained notes local.
2. A genuinely local model plans the work and constructs the minimum question
   needed for each remote task. A deterministic secret detector and a task-specific
   transformation operate across all outgoing fields, including tool results,
   instructions, document metadata and URLs. Failures stop transmission.
3. An explicit local job context scopes alias maps, provider credentials, budgets
   and transport state. Do not rely on the upstream previous-history heuristic
   as a multi-user or multi-job isolation boundary.
4. Jobs enter bounded, padded cells on a traffic schedule selected before the
   session. Cells traverse independently operated mixes; cover fills spare slots.
5. A worker obtains only the required task and return capability. A separate
   adapter handles zkAPI authorization, without giving relays wallet custody.
6. The worker returns bounded answer cells over SURBs. The local daemon checks
   completion, restores locally held context, follows citations and synthesizes.
   Public sources must support reported claims. A rewrite must not invent facts.

That complete flow is a design target. Encrypted transport, synthetic worker
plumbing and a separate-process comparison harness have been implemented.

## Decisions made for the prototype

| Decision | Reason and limitation |
| --- | --- |
| Use Katzenpost Sphinx/SURBs | Reuse packet cryptography rather than invent an onion format; does not reuse a complete deployed mixnet or inherit its anonymity analysis. |
| Independent forward and reverse schedules | A variable or direct response stream would expose job completion patterns. |
| Fixed cell bodies, random padding | Prevent application body length from directly encoding the task; HTTP/TCP and packet counts remain visible. |
| Fixed epoch, bounded pools, no catch-up | Jobs do not create extra scheduled slots; overload reduces availability instead of increasing rate. |
| Random eligible selection with residence delay | Introduces reordering; the static single-host comparison cannot establish anonymity. |
| Replay cache without eviction in a key epoch | Reject repeated packets; capacity exhaustion stops admissions. Production needs authenticated epochs, freshness and restart-safe replay handling. |
| Local-only synthetic worker | Exercise the transport without leaking prompts, issuing paid calls or importing a vulnerable wallet release. |

## What an adversary still sees

The lab operator can inspect every key and node. A network observer can see
endpoints, connection establishment, the chosen rate, session start/end, loss and
OS scheduling effects. The worker sees its plaintext task. A research target can
infer intent from rare facts, document identifiers or repeated questions even
after names are removed. An active attacker can drop traffic or exhaust bounded
capacity. The lab has no admission, Sybil-resistance or multi-operator trust model.

Continuous cover must be shared by a real population and a reviewed topology.
Just adding more dummy requests, or adding this scheduler around a single Tor
circuit, does not establish resistance to an actively colluding provider/guard.
Long-term intersection and confirmation attacks need evaluation too.

## Milestones with evidence required

| Stage | Deliverable | Evidence before advancing |
| --- | --- | --- |
| 0: local transport | Current headless loopback lab | Fixed sizes, idle traffic in both directions, real SURB replies, replay rejection, queue bounds, no catch-up, cancellation; race tests and captured aggregate demo results. |
| 1: network experiment | Separate relay processes and independently operated hosts; authenticated links and directory | Test operator compromise, active timing perturbation, drops, flooding, route churn, replay across restart, key rotation and population size. Prefer using the complete Katzenpost/Nym transport stack where possible. |
| 2: bounded research protocol | Fragmented jobs/results, expiring single-use reply capabilities, constant response polling/scheduling, bounded reassembly and acknowledgements | Malformed/reordered/duplicate fragment tests, resource caps, cancelled jobs, delayed answers, replayed replies and lost epochs. No immediate job-dependent retries. |
| 3: local content controls | Local rewrite/planning model, per-job aliases, secret detection for every egress field, local rehydration and source verification | Raw vs redaction-only vs rewrite vs task-specific transformation comparisons. Measure semantic correctness, citation fidelity, intent/identity inference and tool-output leakage. Do not label prose rewriting as encryption. |
| 4: useful research alpha | Read-only search/source connectors behind capabilities; model-independent local jobs API | Primary-source research tasks, query/document minimization, prompt-injection tests, host allowlists, SSRF/DNS controls, redirect handling and measured p50/p95 end-to-end cost/latency. |
| 5: funded release | Matching reviewed zkAPI deployment, proving artifacts, recovery tooling, signed reproducible packages | Ceremony and code/proof pins, exact-release deposit/request/settlement/independent-exit tests, upstream withdrawal fix, conservative spend caps and tested backups. No development setup substitution. |

Stage 1 now has a process-isolated, synthetic 16-client comparison with clean,
provider-delay, worker-ingress-loss and client-disconnect scenarios. It measures
two timestamp heuristics, completion, completed-job latency and TCP stream bytes.
It has no independent hosts, authenticated directory/links or comprehensive active
attacker. The complete Katzenpost reference remains blocked by its private-key
file requirements; see [assessment](REFERENCE.md). The first part of stage 1 is
implemented; the rest of stages 1–5 remain open.

The [first process comparison](evidence/process-comparison/report.md) found an
unfinished clean job and queued cover/work at epoch end. The immediate transport
priority is to evaluate fixed capacity headroom and return-cover routing, then a
bounded recovery protocol that uses predetermined slots. Low scores for two
timestamp heuristics do not justify bypassing that work or the complete transport
reference assessment.

There is no production anonymity or funded-service release
claim in this branch. The privacy features are independent from changing a vault
address: existing notes always require their original compatible stack.

## Positioning

The product opportunity is an evaluated, usable combination of local intent
minimization, transport privacy, account/payment separation and bounded agent
capabilities. Mixnets, prompt anonymization and data redaction are established
prior art. Evaluate the entire job against explicit attackers; do not market the
composition itself as a new cryptographic guarantee.
