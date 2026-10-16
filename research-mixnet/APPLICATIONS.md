# Candidate applications of the method

Research date: 2026-10-16. These are product hypotheses and experiments, not
claims of patent novelty, established demand or guaranteed anonymity.

## The first application: research without disclosing the overall objective

A founder, researcher or analyst may avoid including their name yet still expose
a confidential objective through a sequence of questions. A local planner can
retain that objective, send smaller questions through separate task contexts,
and combine the answers locally. The remote worker needs the subtask, not the
whole project, account identity, funding wallet or prior transcript.

The combination matters because these channels leak different information:
local transformations reduce task disclosure; mixing addresses transport
correlation; zkAPI addresses some payment linkage. None removes a uniquely
identifying subquestion. Colluding workers can aggregate the questions they see.

The first alpha should complete read-only primary-source research with a local
planner, bounded subquestions, retained citations and local synthesis. It should
not make purchases, sign transactions or perform account actions.

## Applications to test

| Application | Specific adaptation beyond the original wrapper | First experiment | Main failure condition |
| --- | --- | --- | --- |
| Research with a confidential objective — first product | Local goal decomposition, per-job aliases and local synthesis; workers receive only bounded questions. | Use synthetic projects with hidden goals. Compare remote attackers' goal classification and answer/source quality for raw, redacted and decomposed queries. | Query semantics reveal the objective, or decomposition loses essential context. |
| Private debugging for unreleased software | Locally extract a minimal failing example, use parser-aware symbol/path aliases, send only necessary diagnostics, and restore patches locally. Prose rewriting alone is insufficient. | Seed synthetic identifiers and secrets in source, paths, stack traces and tool results. Measure leakage and whether reconstructed patches pass independent functional tests. | Exact code reveals a distinctive project or a transformation changes behavior. |
| Supplier and product investigations | Keep buyer identity, budget and full procurement objective local; separate public specifications, supplier facts and comparisons. | Run synthetic procurement tasks without accounts or contact messages. Measure buyer/project inference, factual accuracy and completeness of cited comparisons. | A rare specification identifies the buyer, or authenticated sites defeat account separation. |
| Blind panels of model opinions | Locally assign independent contexts to multiple workers; normalize unnecessary identifying style; aggregate assessments locally. | Evaluate whether provider-visible histories can be linked and whether conclusions are more useful than a single response. | Semantically identical tasks are linkable across colluding providers; payment privacy does not attest independent model weights. |
| Privacy regression tooling for agent builders | Turn the lab into an egress test bench spanning payloads, tool outputs, credentials, timings, sizes and session transitions. | A seeded canary suite and an adversarial linkability benchmark run before every release, with synthetic data and fixed costs. | Optimizing for a narrow benchmark creates unsupported privacy claims. |

The potentially distinctive work is task-specific disclosure control and
end-to-end evidence for these workflows. A generic PII proxy, Tor wrapper or
multi-model router alone is not a new application.

## Relevant prior art and why it changes our design

- [Vitalik's fork](https://github.com/vbuterin/zkapi/tree/0fb263b0da04986cfe5c63b12340c1581018ae9b)
  already supplies conversation-aware Tor routing, user-text normalization,
  rewritten target histories and bounded cover requests. Its documented limits
  include untouched tool/system content and undeployed concession profiles.
- [Presidio](https://github.com/data-privacy-stack/presidio) already provides
  extensible PII detection and anonymization. Its documentation explicitly does
  not promise complete detection. We need to assess inferred intent as well as
  recognizable entity spans.
- [Large Language Models are Advanced Anonymizers](https://arxiv.org/abs/2402.13846)
  and its [author repository](https://github.com/eth-sri/llm-anonymization) provide
  anonymization, adversarial-inference and utility evaluation workflows, including
  synthetic data. Those are useful baselines, not proof for our coding/research domain.
- [Adaptive Text Anonymization](https://arxiv.org/abs/2602.20743) studies
  task-dependent privacy/utility objectives. This supports evaluating separate
  research and code transformations rather than choosing one universal rewrite.
- [Loopix](https://arxiv.org/abs/1703.00536) combines cover, mix delays and
  bidirectional anonymous communication. [Echomix](https://arxiv.org/abs/2501.02933)
  analyzes additional active and statistical attacks. Their full constructions
  are prior art and a review baseline; our simplified scheduler does not inherit
  their security analysis.
- [Nym](https://github.com/nymtech/nym) provides existing mixnet clients, including
  SOCKS5 integration. Assess it and the complete Katzenpost network before deciding
  to operate a new relay network.
- [Cloudflare's OHTTP implementation](https://github.com/cloudflare/privacy-gateway-server-go)
  is an alternative for separating a relay from a request-processing gateway.
  That architecture alone does not implement our delayed, continuously covered
  mix transport.

No exhaustive market, prior-art or patent search has been completed. Willingness
to pay and the population needed for a useful anonymity set remain unvalidated.
