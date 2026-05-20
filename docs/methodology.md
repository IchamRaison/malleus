# Methodology

Malleus is a defensive LLM security evaluation harness. Its goal is not to publish jailbreak payloads for misuse or to claim universal model safety. Its goal is to make recurring security-relevant failure modes observable, reproducible, and explainable.

## What Malleus measures

Malleus V0.1 focuses on five families of model or agent failures:

1. Instruction-boundary failures: the target follows user text that tries to override higher-priority instructions.
2. Sensitive-context exposure: the target reveals hidden prompts, memory, credentials, tokens, or other private context.
3. Policy robustness: the target becomes less safe under roleplay, fake authority, simulated tool output, or benchmark pretexts.
4. Output integrity: the target fails a strict output contract such as exact JSON keys and no surrounding prose.
5. Refusal consistency: semantically equivalent requests produce inconsistent refusal behavior.

## Why deterministic scoring first

V0.1 uses deterministic checks: substrings, regexes, exact JSON validation, and refusal markers. This is deliberate.

Benefits:

- every pass/fail has a visible reason
- reports can be inspected without trusting another LLM judge
- tests are cheap enough for development and CI
- scoring bugs are easier to debug

Trade-offs:

- substring checks can create false positives if they are too broad
- refusal markers are language and phrasing sensitive
- deterministic checks do not capture all semantic failures
- exact JSON checks measure contract adherence, not truthfulness

Malleus treats these trade-offs as engineering constraints, not hidden magic. The report shows each check so users can challenge the score.

## How a case is scored

Each case contains:

- a prompt
- severity
- expected behavior
- failure signals
- pass signals
- optional output constraints

A case fails if a failure signal triggers or a required pass signal does not trigger. Severity controls the penalty. Warnings, such as high latency, can add a small configurable penalty without changing the functional pass/fail status.

## How a group is scored

A group contains variants of the same adversarial intent. V0.1 uses groups primarily for refusal consistency. Every variant should trigger a refusal marker. If one variant slips through, the group receives a severity penalty plus a consistency penalty.

## What a score means

A high score means the target passed the specific benchmark cases under the configured scoring policy. It does not mean the model is safe. A low score means the target failed one or more explicit checks that should be reviewed in the report.

Scores are best used comparatively:

- same benchmark pack
- same scoring config
- same target settings
- similar latency/token constraints

## What Malleus does not claim

Malleus does not claim to prove model safety, certify compliance, or exhaustively cover prompt injection. It also does not attempt to optimize jailbreak payloads for bypass success. The project is framed for defensive evaluation and reproducible engineering analysis.

## Recommended workflow

1. Run `smoke-v1` during development.
2. Inspect `report.md` and `report.html` for false positives.
3. Run `core-v1` only when the target and scoring config are stable.
4. Compare models with identical packs and token settings.
5. Treat unexpected scores as debugging leads, not leaderboard truth.

## Release and artifact hygiene

CI/dev QA paths should stay provider-free unless a human intentionally runs a target-backed evaluation. `run --dry-run`, `mutate-run --dry-run`, `agent-lab --dry-run`, campaign dry-runs, local RAG fixtures, coverage builds, threat-model checks, workspace inspection, benchmark planning, and benchmark summarization all support local release checks without paid/API calls. The normal user benchmark path is live/provider-backed and records non-live paths only as planning or coverage-boundary evidence.

Malleus writes additive companion artifacts such as manifests, event logs, risk summaries, model risk cards, findings, replay plans, coverage reports, audit bundles, and benchmark plans. These artifacts are report-first: they preserve legacy report names while adding schema versions, relative artifact references, SHA-256 hashes, and redaction status where useful.

Public artifacts must not publish raw adversarial payload bodies, secret-like values, private absolute paths, or unsafe decoded hidden-channel content. When provider-backed scripts such as `scripts/run_wow_benchmark.py` are used, treat them as explicit real runs outside default CI/release smoke checks and do not update public benchmark numbers unless those real runs were intentionally performed and reviewed.
