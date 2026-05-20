# Interpreting assessment results

Assessment results are evidence summaries, not safety certificates. Read them by checking mode first, evidence strength second, then scores, findings, coverage, and gate status.

## Start with mode and evidence

Every assessment report includes a mode such as `dry_run`, `local_fixture`, `simulated`, `scaffold`, or `live_provider`. In the current assessment implementation, provider and network calls are disabled for all modes, and `live_provider` is fail-closed scaffold behavior.

Evidence strength explains what kind of proof supports each row:

| Evidence strength | How to read it |
|---|---|
| `model_behavior` | Strongest claim about model behavior, but not collected by current assessment orchestration. |
| `fixture_behavior` | Local fixture evidence. Useful, repeatable, and provider-free, but not the same as a live endpoint. |
| `static_analysis` | Deterministic inspection of local artifacts, metadata, or configs. |
| `simulated_behavior` | Simulated workflow evidence. Helpful for planning and regression shape, not live behavior. |
| `planning_only` | A plan, scaffold, or gap marker. It never counts as a strength in the primary score. |

## Scores

The primary score reflects only qualifying primary evidence for applicable packs. Planning-only, scaffold, advisory, excluded, not-applicable, not-tested, and coverage-gap evidence cannot inflate the primary production-readiness score.

Coverage confidence is separate. It answers, "How much of the relevant profile surface has trustworthy coverage?" Missing fixtures, missing configuration, live-provider requirements, and untested relevant packs lower coverage confidence instead of appearing as passes.

Advisory findings are useful triage signals but are not part of the primary score. They can still identify hardening work.

## Severity, strengths, and weaknesses

Severity is a triage label for the finding impact in this assessment context. It is not a statistical probability. Strengths should only be read as strengths when the evidence mode supports that claim. A planning-only row is never evidence that a model resisted an attack.

Weaknesses can include real failures, coverage gaps, missing fixtures, scaffold-only packs, or workflow errors. The category and score-use fields explain which type you are seeing.

## Findings

Findings live under `findings/findings.json` and `findings/findings.md`. They include stable IDs, severity, category, pack references, evidence references, and remediation pointers. Current public artifacts use sanitized previews, hashes, lengths, and relative artifact paths rather than raw prompt or response bodies.

## Coverage

Coverage artifacts live under `coverage/`. They show which packs were planned, covered, not applicable, scaffold-only, or blocked by missing evidence. A visible gap is a successful integrity feature, not an automatic model failure.

## False positives and false negatives

False positives can happen when deterministic checks over-classify a fixture, artifact, or metadata pattern. False negatives can happen when a semantic failure is not represented in a local fixture, selected pack, scoring rule, or current assessment mode. Use the evidence bundle and regression artifacts to review claims before treating them as release blockers.
