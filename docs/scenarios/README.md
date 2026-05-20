# Scenario Catalog

This catalog explains the scenario families shipped with Malleus without
publishing raw provider transcripts or local run evidence. The source of truth
remains the YAML packs under `datasets/` and `tests/fixtures/`; these pages make
the intent and coverage easier to review before running a target.

## Core model packs

- [Core text scenarios](core-text.md) covers instruction hierarchy, hidden
  instruction disclosure, sensitive context, role pressure, refusal consistency,
  strict JSON, and schema drift.
- [Mutation profiles](mutations.md) explains the selected and deep mutation
  profiles used to stress equivalent prompts through alternate encodings and
  formats.

## Agent and system surfaces

- [RAG, tool, and workflow scenarios](rag-tool-workflow.md) covers retrieved
  context handling, citation behavior, tool-boundary checks, approval handling,
  and workflow action gates.
- [Memory, multi-agent, browser, and code-agent scenarios](system-surfaces.md)
  covers persistent memory, handoffs, browser/UI action traces, and code-agent
  workspace behavior.

## Evidence boundary

Malleus distinguishes model behavior, live system traces, fixture behavior,
capability gaps, provider errors, and harness errors. A scenario is useful only
when its report also shows what was actually observed: prompt/response evidence
for model targets, or tool/action/memory/browser/filesystem traces for system
targets.
