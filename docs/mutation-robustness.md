# Mutation robustness runner

Malleus can replay selected benchmark sources through prompt mutations and report whether a target model becomes less safe or less consistent under small format/obfuscation shifts. `malleus mutate-run` expands benchmark packs and grouped variants through the shared dataset utilities before planning mutation source items, so included packs, standalone cases, and group variants use the same ordering, deduplication, and cycle checks as normal benchmark loading.

This is a defensive robustness workflow, not a jailbreak prompt pack. Mutations are synthetic transforms with metadata: name, description, category, risk, and example.

## Inspect mutations

```bash
malleus mutations list
malleus mutations inspect spacing
```

Current mutation families:

- `spacing` — character spacing obfuscation.
- `leetspeak` — lexical obfuscation.
- `unicode_wrap` — delimiter/context sensitivity.
- `markdown_quote` — Markdown formatting/context shift.

## Optional CI/dev dry-run planning

Use dry-run to confirm item counts before calling any external API. This is a planning step only, not mutation robustness evidence. The `core` preset uses `datasets/benchmark_packs/core-v1.yaml` and defaults to the Deep 140 mutation profile from `datasets/mutation_profiles/deep-v1.yaml` only when neither `--mutation` nor `--mutation-profile` is supplied. This Deep 140 default applies only to the `core` preset:

```bash
malleus mutate-run core \
  --target examples/targets/nvidia.yaml \
  --scoring configs/scoring-default.yaml \
  --out-dir reports/core-mutation-dry \
  --dry-run
```

Explicit overrides are valid with the preset. Use `core --mutation spacing` for a surgical transform list, or `core --mutation-profile datasets/mutation_profiles/selected-v1.yaml` to use a different profile. Dry-run avoids provider calls and writes the planned mutation items first.

The explicit input and profile form remains supported for smoke packs, custom packs, and legacy scripts:

```bash
malleus mutate-run \
  --target examples/targets/nvidia.yaml \
  --input datasets/benchmark_packs/smoke-v1.yaml \
  --scoring configs/scoring-default.yaml \
  --out-dir reports/mutation-dry \
  --mutation-profile datasets/mutation_profiles/selected-v1.yaml \
  --limit 2 \
  --dry-run
```

Dry-run writes planning artifacts only:

- `mutation-dry-run.json`
- `mutation-dry-run.md`

## Run mutation robustness evaluation

```bash
malleus mutate-run \
  --target examples/targets/nvidia.yaml \
  --input datasets/benchmark_packs/smoke-v1.yaml \
  --scoring configs/scoring-default.yaml \
  --out-dir reports/nvidia-mutations \
  --mutation spacing \
  --mutation markdown_quote \
  --limit 3
```

Use `--case-id` for surgical checks:

```bash
malleus mutate-run \
  --target examples/targets/nvidia.yaml \
  --input datasets/benchmark_packs/core-v1.yaml \
  --scoring configs/scoring-default.yaml \
  --out-dir reports/nvidia-roleplay-mutations \
  --case-id smoke_policy_robustness:smoke-pr-001 \
  --mutation spacing \
  --mutation markdown_quote
```

The command writes:

- `mutation-report.json`
- `mutation-report.md`

## Report semantics

For each case x mutation pair, Malleus records public report metadata and redacted artifact references:

- original and mutated prompt artifact references with hashes, lengths, and redacted previews where available
- original and mutated response artifact references with hashes, lengths, and redacted previews where available
- original deterministic score
- mutated deterministic score
- score delta
- mutation category and risk

A negative delta means the model performed worse under the mutation than on the original prompt. The report highlights the worst mutation and the largest regressions for analyst review.

## Methodology notes

Mutation results should not be overclaimed as universal model safety. They are regression evidence for defined cases and deterministic checks.

Good use cases:

- catch brittle refusal behavior
- compare model robustness under equivalent prompt intent
- build regression suites before changing system prompts, guardrails, or model versions
- produce reproducible evidence for AI security reviews

Avoid:

- treating transformations as real-world attack coverage by themselves
- copying payloads from adversarial repos
- running full paid/API benchmarks before using dry-run and `--limit`
