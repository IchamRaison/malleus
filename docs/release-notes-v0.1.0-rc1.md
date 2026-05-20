# Malleus v0.1.0-rc1 Release Notes

Malleus v0.1.0-rc1 is a defensive AI-agent evaluation harness release candidate. It focuses on traceable benchmark execution, explicit target contracts, and public-safe reporting rather than broad claims about model safety.

## Highlights

- Canonical v0.1 benchmark matrix with soft and exterminatus live wrappers.
- Trace-first L2 target contracts for chat completion, RAG service, tool agent, workflow harness, code agent, memory agent, multi-agent, browser agent, and self-modification surfaces.
- Deterministic mutation profiles, selected/deep mutation orchestration, and provider-free regression generation.
- Operational evidence bundles with dashboard, findings, risk cards, regression pack, remediation drafts, and secret/private-path scanning.
- `malleus init`, `malleus quickstart`, and `malleus doctor` for a shorter first-run path.
- Installable package asset support for canonical datasets/configs plus a wheel install smoke script.
- Static dashboard and evidence-bundle outputs for compact reviewable evidence pages.
- Sandboxed code-agent execution options, isolated adapter serving, and explicit capability-gap reporting when targets cannot expose required evidence.
- Checked-in L2 examples for callable Python, LangGraph, OpenAI Agents, RAG service, browser-agent, and sandboxed code-agent integrations.

## Evidence Boundaries

- `malleus benchmark exterminatus` is exhaustive over implemented/canonical Malleus surfaces and configured mutation profiles. It is not a universal security proof.
- Capability gaps, target configuration errors, target errors, operator skips, provider errors, and checkpoint rows are coverage or operational outcomes. They are not deterministic model behavior failures.
- Provider-free assessment, dry-run plans, static scanners, scaffold artifacts, and simulated fixtures are useful engineering evidence, but they cannot replace live model or real-system trace evidence.
- Visual/OCR and browser evidence are explicit about target support: unsupported image input or missing Playwright screenshot capture is reported as a capability gap.

## Publication Guidance

- Do not commit raw local `reports/` directories.
- For provider proof material, regenerate dashboard/evidence artifacts from local run reports, inspect redaction output, and commit only reviewed summaries when needed.
- Keep `.env`, generated local reports, scratchpads, and local provider outputs untracked.

## Suggested Verification

```bash
pytest -q
ruff check src tests --select F
python -m build
python scripts/install_smoke.py --wheel dist/malleus_evals-0.1.0-py3-none-any.whl
malleus v1-readiness
malleus prod-readiness
malleus dashboard --report reports/<target-name>-soft/live-full-evidence.json --out-dir reports/<target-name>-dashboard
malleus evidence-bundle --run-report reports/<target-name>-soft/live-full-evidence.json --out-dir reports/<target-name>-evidence
```
