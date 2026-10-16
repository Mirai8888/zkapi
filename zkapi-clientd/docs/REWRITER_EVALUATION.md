# Example-free instruction evaluation

Evaluated locally on 2026-10-16 against `http://localhost:8012`, model
`qwen3.8-flash-next`, using the production editor request/response code. No wallet,
provider-key acquisition or target inference was involved. Evaluation requests
were limited to two concurrent calls, with one synthetic user turn per call.
The default instruction contains no restaurant or other worked task examples.

## Method and observations

Three example-free candidates (semantic reconstruction, request compilation,
minimal specification) were compared on 12 cases. Candidates and the battery
are retained in `internal/rewriter/instruction_eval_test.go` for reproducibility.
A preliminary attempt was cut short by the command timeout; the full comparison
was rerun with a longer test timeout.

All three removed redundant recommendation wording and retained it when it was
an exact quotation. Mechanical checks alone were insufficient:

- The compiler candidate changed a protected written `3` to `three`.
- Multiple candidates dropped an explicit brevity requirement.
- The minimal-specification candidate narrowed a £20 budget to **under** £20.
- Some privacy rewrites added or narrowed categories instead of keeping them open.

The semantic candidate was refined to preserve numeric boundaries, open questions,
and separate brevity/complexity requirements. An initial refined version still
omitted brevity; a further constraint audit instruction corrected it in the final
run. The final example-free default was tested on 16 cases, including four added
after the initial comparison. All partial mechanical checks passed and outputs
were manually reviewed for style and semantic fidelity.

Selected final outputs:

| Case | Observation |
| --- | --- |
| Redundant recommendation | Removed the duplicated superlative; retained count, category and location. |
| Brevity and simplicity | “Provide a brief overview of how photosynthesis works. Keep it simple.” |
| Redundant completeness | “List all remaining TODOs. Do not fix any of them.” |
| Inclusive boundary | “Select 4 laptops priced at £900 or less, excluding used laptops.” |
| Code literal | Preserved `x != 0 && y < 5`; retained no-edit/no-execution constraints. |
| Conditional retry | Retained retry only after two failures and prohibition after success. |
| Uncertainty | Kept memory leak versus caching as alternatives, without proposing fixes. |
| Spanish | Removed filler/redundancy while preserving Spanish, brevity and no technical terms. |
| Exact quotation | Preserved the quoted redundant phrase rather than normalizing it. |
| Ambiguous continuation | Kept the unresolved second item and earlier assumption references. |

## Rerun

From `zkapi-clientd`, with the local editor running:

```sh
# Current default against all 16 cases:
ZKAPI_EVAL_REWRITER=1 ZKAPI_EVAL_DEFAULT=1 \
  go test -v ./internal/rewriter -run '^TestLiveInstructionEvaluation$' \
  -parallel 2 -count 1 -timeout 15m

# Compare the original three candidates against the current expanded battery:
ZKAPI_EVAL_REWRITER=1 \
  go test -v ./internal/rewriter -run '^TestLiveInstructionEvaluation$' \
  -parallel 2 -count 1 -timeout 15m
```

These are development evaluations, disabled in ordinary tests/builds. They log
synthetic rewritten outputs for review. This is a small qualitative evaluation,
not a statistically validated stylometry benchmark. Results are nondeterministic;
retained literals and phrase checks cannot prove semantic equivalence, privacy
or anonymity. Rewrites can still copy structure or drift in meaning. Contextual
facts, identifiers and text outside user messages remain identifying risks.
