# Release Readiness

Status as of 2026-05-03: release-candidate ready for a public GitHub/LinkedIn
review pass after final full-suite CI verification.

## Verification Snapshot

- Full test suite: run in CI with `pytest -q`.
- Static sanity: `ruff check src tests scripts`.
- Package build: `python -m build`.
- Install smoke: `python scripts/install_smoke.py --wheel dist/malleus_evals-0.1.0-py3-none-any.whl`.
- Wheel asset smoke: install the built wheel outside the repo and validate the
  release matrix plus default scoring config through `malleus.resources`.
- Targeted packaging/quickstart/resource suite: `28 passed`.
- CLI smoke: `malleus version` and `malleus quickstart`.
- V1 gate: `malleus v1-readiness` reports `ready_for_v1`.
- Production gate: `malleus prod-readiness` reports `prod_ready` across the ten
  production-readiness axes: CI/CD, architecture, docs, release hygiene,
  providers, sandboxing, CLI UX, plugins/extensibility, observability, and public
  packaging.
- Audit artifacts: generate dashboard and evidence bundle from the final live
  run with `malleus dashboard` and `malleus evidence-bundle`.
- Whitespace checks: `git diff --check` and `git diff --cached --check`.
- Ignored local outputs: `reports/`, `.env`, `.venv/`, caches, and local planning artifacts.
- Public provider examples are kept small in `examples/targets/`; L2/provider
  validation targets live under `examples/integrations/l2/targets/`.

## Public Evidence Boundaries

- `ui-harness` remains scaffold-only and does not drive a browser or capture screenshots.
- `browser_agent` is the live browser route and can record DOM/action traces plus optional Playwright screenshots.
- Visual/OCR fixtures and vision paths are not marketed as complete live OCR-agent support.
- Provider errors are run conditions, not model behavior findings.
- Capability gaps are reported explicitly and cannot inflate a pass.
- `malleus benchmark exterminatus` is exhaustive over implemented/canonical Malleus surfaces and configured mutation profiles, not exhaustive over universal AI security.
- Audit artifacts should be regenerated from fresh local reports and reviewed
  before publication; do not commit raw `reports/` directories.
- Public examples use hashes, redacted previews, relative paths, and generated fixtures rather than secrets or private paths.
- The RAG L1 auto-wrapper performs deterministic request repair for wrapper
  corpus injection mistakes. L2 real RAG services remain responsible for their
  own retrieval ACLs, citation validation, and trace exposure.

## Maintainer Debt Before v0.2

- `src/malleus/cli.py` and `src/malleus/live_full.py` are still too large for
  long-term maintenance. New CLI flows should be added in small helper modules
  like `malleus.cli_quickstart`; live-surface orchestration should be split by
  surface once behavior is stable.
- Keep public docs focused on install, quickstart, evidence boundaries, and
  production integration. Historical planning and research notes should stay
  outside the public documentation path.
- Avoid adding provider-specific target YAMLs to `examples/targets/` unless they
  are simple model targets. Real-agent/provider validation examples belong under
  `examples/integrations/l2/targets/`.

## Proposed Commit Split

1. `docs: establish release/publication baseline`
   README, license, contributing/security files, translated README updates, publication checklist, project direction, release-readiness notes.

2. `feat: add agent trace and L2 target contracts`
   AgentTrace schema, target contracts, CLI validation/scaffolding, schemas, status taxonomy, tests.

3. `feat: add real L2 adapters and tool gateway`
   Generic callable, LangGraph, OpenAI Agents, LangChain/LlamaIndex RAG adapters, framework tool wrappers, tool gateway, isolated adapter serving.

4. `feat: add live system harnesses`
   RAG service, tool agent, workflow, code agent, memory, multi-agent, browser-agent Playwright/DOM evidence, system safety/sandboxing.

5. `feat: expand benchmark orchestration and surfaces`
   Live-full routing, soft/exterminatus benchmark suite, challenge/calibration live rows, mutation/profile updates, release matrix updates.

6. `feat: add reporting, findings, regression, and audit evidence`
   Dashboard/risk cards, findings extraction, regression generation/validation, evidence bundle, remediation and issue exports.

7. `test: add contract, harness, L2, and publication coverage`
   New unit/integration tests for adapters, harnesses, reports, docs, publication claims, and target schemas.

8. `chore: add examples and provider target fixtures`
   L2 examples, DeepSeek local target examples, Docker/packaging polish.

This split is a recommendation for reviewability. The current staged index is
valid as one large release commit, but the split above will be easier to review.

## Final Pre-Publish Checklist

- Run `pytest -q`.
- Run `ruff check src tests scripts`.
- Run `python -m build`.
- Run `python scripts/install_smoke.py --wheel dist/malleus_evals-0.1.0-py3-none-any.whl`.
- Run `malleus v1-readiness`.
- Run `malleus prod-readiness`.
- Generate final dashboard and evidence bundle from the selected live report.
- Review generated HTML/Markdown evidence locally.
- Confirm no raw local report directory is staged.
- Confirm generated local reports, scratchpads, and provider outputs remain ignored/untracked.
- Confirm docs still distinguish live evidence, provider-free assessment, static fixtures, and scaffold-only surfaces.
