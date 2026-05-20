# Scoring methodology

Assessment scoring separates three ideas that are easy to confuse: primary score, coverage confidence, and advisory findings. This separation protects score integrity when a report includes planning-only, scaffold, simulated, fixture, or static evidence.

## Primary score

The primary score is the production-readiness signal for applicable packs with qualifying primary evidence. It uses only evidence strengths declared by the pack as primary evidence.

Planning-only, scaffold, advisory, excluded, not-applicable, not-tested, missing-fixture, missing-configuration, and live-provider-required rows cannot inflate the primary score. If a pack has no qualifying primary evidence, it is excluded, advisory, or a coverage gap depending on the pack and status.

## Coverage confidence

Coverage confidence answers a different question: how much of the relevant profile surface has meaningful evidence? Missing relevant packs, required fixtures, required configuration, and live-provider requirements reduce coverage confidence. They do not appear as pass results.

This is why a report can have no primary failures and still show weak coverage confidence. That is a planning signal, not a contradiction.

## Advisory findings

Advisory findings are findings that should be reviewed but do not change the primary score. They often come from advanced, profile-dependent, simulated, fixture, static, or compound-risk surfaces. Advisory does not mean unimportant. It means the evidence should be interpreted separately from the primary production-readiness score.

## Evidence strengths and score use

| Evidence strength | Can support primary score now? | Notes |
|---|---:|---|
| `model_behavior` | No in current assessment orchestration | Cataloged for future live evidence, but assessment provider calls are disabled now. |
| `fixture_behavior` | Only where the pack declares it as primary and fixture evidence exists | Useful for local, repeatable checks. |
| `static_analysis` | Usually no | Best for metadata, coverage, report, and artifact-boundary checks. |
| `simulated_behavior` | Usually advisory | Good for workflow shape and regression planning. |
| `planning_only` | No | Never primary score evidence. |

## Posture

Assessment posture is derived from primary score and workflow errors. A report with no qualifying primary denominator may warn instead of pass. Provider or workflow errors force an error posture. Gate artifacts then apply CI policy to findings, gaps, and baselines.
