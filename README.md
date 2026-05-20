<div align="center">

<img src="docs/assets/malleus-ordo-banner.jpg" alt="Malleus gothic hammer emblem over an antique map" width="100%">

# MALLEUS

### Defensive evidence for LLM and AI-agent security reviews

**Audit • Harden • Prove**

<p>
  <a href="https://github.com/IchamRaison/malleus/actions/workflows/ci.yml"><img src="https://github.com/IchamRaison/malleus/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/status-v0.1_active-brightgreen" alt="Status">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
</p>

</div>

---

Malleus is a defensive assessment workflow for LLMs and AI-agent systems.

It runs benchmark scenarios against a model or an agent target, records what happened, separates model findings from provider/configuration issues, and writes replayable reports.

Malleus is for authorized testing of systems you own or are allowed to assess. It is not a general safety certificate and not a prompt archive.

## What You Can Test

Malleus supports plain model targets and traced system targets:

| Target kind | What it tests |
|---|---|
| `chat_completion` | Normal OpenAI-compatible chat or vision model endpoints |
| `rag_service` | Retrieval, citations, tenant boundaries, document instructions |
| `tool_agent` | Tool selection, tool arguments, approval boundaries, sinks |
| `workflow_harness` | Workflow actions, approvals, blocked operations |
| `code_agent` | Workspace changes, commands, diffs, sandbox behavior |
| `memory_agent` | Memory reads/writes, cross-user boundaries, stale memory |
| `multi_agent` | Handoffs, summarization, role boundaries |
| `browser_agent` | DOM/action traces, navigation, UI instruction boundaries |

A plain model target is enough for text/model behavior tests. System surfaces need a compatible target that returns traces.

## Install

### Recommended: cloned checkout

```bash
git clone https://github.com/IchamRaison/malleus.git
cd malleus
./scripts/bootstrap
./malleus version
```

`./scripts/bootstrap` creates `.venv`, installs Malleus in editable mode, and makes `./malleus` usable without manually activating the virtual environment.

Optional installs:

```bash
./scripts/bootstrap --l2
./scripts/bootstrap --all
```

Use `--l2` for agent integration examples. Use `--all` if you want every optional dependency used by the repo.

### Alternative: pip

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
malleus version
```

After package publication:

```bash
pipx install malleus-evals
malleus version
```

## Quickstart: run a live benchmark

### 1. Check the install

```bash
./malleus doctor
./malleus quickstart
```

`doctor` checks the local install, packaged assets, optional tools, and managed targets.

`quickstart` prints the next commands for your local setup.

### 2. Add a target

Interactive setup:

```bash
./malleus init
```

Non-interactive OpenAI-compatible setup:

```bash
./malleus target init \
  --provider deepseek \
  --model deepseek-v4-flash \
  --name deepseek-v4-flash \
  --save-api-key
```

Target files store an environment variable reference such as `DEEPSEEK_API_KEY`; they do not store the raw key. Secrets can live in `.env` or in your shell environment.

Useful target commands:

```bash
./malleus target list
./malleus target show deepseek-v4-flash
./malleus target doctor deepseek-v4-flash --live-check
./malleus target test deepseek-v4-flash --allow-provider-call
```

`target doctor` validates the target configuration and, with `--live-check`, performs a small provider call.

`target test` sends a minimal test request and confirms that the endpoint can answer.

### 3. Run the default benchmark

```bash
./malleus benchmark soft --target deepseek-v4-flash
```

`soft` is the normal live benchmark. It runs the canonical Malleus v0.1 surfaces that are compatible with the target and writes reports under `reports/`.

Copy/paste contract:

```bash
malleus benchmark soft --target <target-name>
```

Use an explicit output folder when you want stable paths:

```bash
./malleus benchmark soft \
  --target deepseek-v4-flash \
  --out-dir reports/deepseek-soft
```

### 4. Run the expanded benchmark

```bash
./malleus benchmark exterminatus \
  --target deepseek-v4-flash \
  --out-dir reports/deepseek-exterminatus
```

`exterminatus` runs the expanded canonical benchmark, including deeper mutation coverage. It costs more time and provider quota.

### Live benchmark wrappers

`malleus benchmark soft` is the serious/default live benchmark wrapper. It runs the canonical Malleus v0.1 live surfaces that match the target and writes `live-full-checkpoint.json` as partial progress/recovery artifacts. Successful runs may also retain these checkpoint files as a final non-partial progress snapshot; provider/server errors remain separate operational outcomes.

`malleus benchmark exterminatus` is the expanded live wrapper for the implemented Malleus benchmark surfaces. It includes the selected profile and deep mutation profile by default, but it is not a universal security proof. `exterminatus` is exhaustive over implemented/canonical Malleus surfaces and configured mutation profiles, not exhaustive over universal AI security.

The lower-level `malleus benchmark live-full` command remains available for explicit matrix/profile orchestration.

### 5. Open the reports

```bash
./malleus dashboard \
  --report reports/deepseek-soft/live-full-evidence.json \
  --out-dir reports/deepseek-soft-dashboard

./malleus evidence-bundle \
  --run-report reports/deepseek-soft/live-full-evidence.json \
  --out-dir reports/deepseek-soft-evidence

./malleus gate \
  --report reports/deepseek-soft/live-full-evidence.json
```

The most useful files in a run directory are:

| File | Purpose |
|---|---|
| `live-full-evidence.json` | Machine-readable run evidence |
| `live-full-evidence.md` | Human-readable run evidence |
| `FULL_BENCHMARK_SUMMARY.md` | Executive summary of the full run |
| `FULL_BENCHMARK_MATRIX.json` | Per-surface benchmark matrix |
| `live-full-checkpoint.json` | Checkpoint/progress data |

## What an assessment writes

The main live benchmark writes evidence under `reports/<run>/`:

```text
reports/<run>/
├── live-full-evidence.json
├── live-full-evidence.md
├── FULL_BENCHMARK_SUMMARY.md
├── FULL_BENCHMARK_MATRIX.json
├── live-full-checkpoint.json
└── per-surface reports and artifacts
```

Provider-free release/CI planning writes local review artifacts such as risk reports, coverage summaries, findings, remediation notes, regression packs, dashboards, model-comparison summaries, and gate output.

Provider-free and scaffold artifacts are local evidence. They are useful for CI/dev planning and documentation, but they are not endpoint evidence and cannot satisfy live benchmark claims.

## Run One Surface

Use these when you want to isolate one system surface instead of running the full matrix.

| Surface | Command |
|---|---|
| RAG service | `./malleus benchmark live-rag --target <rag-target> --out-dir reports/live-rag` |
| Tool agent | `./malleus benchmark live-agentic --target <tool-agent-target> --out-dir reports/live-agentic` |
| Workflow | `./malleus benchmark live-workflow --target <workflow-target> --out-dir reports/live-workflow` |
| Code agent | `./malleus benchmark live-code-agent --target <code-agent-target> --out-dir reports/live-code-agent` |
| Memory agent | `./malleus benchmark live-memory-agent --target <memory-agent-target> --out-dir reports/live-memory` |
| Multi-agent | `./malleus benchmark live-multi-agent --target <multi-agent-target> --out-dir reports/live-multi-agent` |
| Browser agent | `./malleus benchmark live-browser-agent --target <browser-agent-target> --out-dir reports/live-browser` |
| Self-modification | `./malleus benchmark live-self-modification --target <target> --out-dir reports/live-self-modification` |

For a plain chat model, use:

```bash
./malleus run deepseek-v4-flash \
  --input datasets/benchmark_packs/smoke-v1.yaml \
  --out-dir reports/smoke
```

`malleus run` is the lower-level text benchmark command. `benchmark soft` and `benchmark exterminatus` are the higher-level benchmark wrappers.

## How to read the evidence

Malleus is trace-first: a benchmark result is useful only if you can see what was called, what evidence was returned, and why a verdict was assigned.

The main trace files are:

| File | What to open it for |
|---|---|
| `live-full-evidence.md` | Quick human-readable run review |
| `live-full-evidence.json` | Full machine-readable evidence and trace counters |
| `FULL_BENCHMARK_SUMMARY.md` | Executive summary by surface |
| `FULL_BENCHMARK_MATRIX.json` | Reproducible per-surface matrix |
| `live-full-checkpoint.json` | Progress and partial rows if a run was interrupted |
| per-surface reports | Detailed RAG/tool/workflow/code/browser/memory traces |

Build the HTML view:

```bash
./malleus dashboard \
  --report reports/<run>/live-full-evidence.json \
  --out-dir reports/<run>-dashboard
```

Then open:

```text
reports/<run>-dashboard/index.html
```

Build a portable evidence bundle:

```bash
./malleus evidence-bundle \
  --run-report reports/<run>/live-full-evidence.json \
  --out-dir reports/<run>-evidence
```

Inspect the run from the terminal:

```bash
jq '.results[] | {
  surface_id,
  status,
  evidence_level,
  direct_model_calls,
  backing_model_calls,
  system_trace_items,
  system_artifact_count,
  evidence_call_summary
}' reports/<run>/live-full-evidence.json
```

Inspect checkpoint progress:

```bash
jq '.results[] | {
  surface_id,
  checkpoint_status,
  status,
  evidence_level
}' reports/<run>/live-full-checkpoint.json
```

For system targets, also inspect the surface-specific report folders under `reports/<run>/`, for example:

```text
reports/<run>/rag-service/
reports/<run>/tool-agent/
reports/<run>/workflow-harness/
reports/<run>/code-agent/
reports/<run>/browser-agent/
reports/<run>/memory-agent/
reports/<run>/multi-agent/
```

Look for fields such as `agent_traces`, `agent_trace_summary`, `target_trace_count`, `target_call_count`, `tool_calls`, `actions`, `memory_events`, `handoffs`, `approvals`, `artifacts`, `diffs`, and `metadata.agent_trace_events`.

The important counters are:

| Evidence field | What it tells you |
|---|---|
| `direct_model_calls` | Calls made directly to a chat or multimodal model |
| `backing_model_calls` | Calls made behind a live system target or wrapper |
| `system_trace_items` | Observable events returned by an agent/RAG/workflow/browser/code target |
| `system_artifact_count` | Artifacts such as screenshots, DOM captures, diffs, logs, or sandbox reports |
| `evidence_level` | Whether the row is live model evidence, live system trace, fixture evidence, scaffold evidence, or a capability gap |

Good trace coverage does not imply a pass. It means Malleus had enough evidence to judge the run honestly.

## How to read verdicts

Malleus separates outcomes into different buckets:

| Outcome | Meaning |
|---|---|
| `passed` | The target completed the scenario without a finding |
| `failed` | Malleus recorded a model/system behavior finding |
| `provider_error` | Provider/API call failed or timed out |
| `target_error` | The configured target did not behave as expected |
| `target_config_error` | The target YAML is incomplete or invalid |
| `provider_capability_gap` | The provider lacks a required capability, such as vision |
| `target_capability_gap` | The target does not expose required system traces |
| `operator_skip` | The run intentionally skipped a surface |

Provider errors are separate. Provider errors are recorded separately from model behavior findings, and Malleus records provider errors separately from model behavior evidence/findings. Provider availability, account access, quota, routing, timeout, and adapter errors are run conditions. Only completed model responses can support model behavior findings. Provider or workflow errors force an error posture for the run, but they are operational conditions. provider errors are operational records, not model behavior findings; provider errors are run conditions, not model behavior findings.

Capability gaps, target config errors, target errors, operator skips, and checkpoint rows are reported as run/coverage outcomes, not model behavior failures. Capability gaps are also not model failures. They are run conditions.

Fixture/model-only RAG, mock agent lab tools, static plugin scanning, static code-agent trace inspection, and UI scaffold artifacts are not real system live evidence. Do not present fixture-RAG/model-only RAG, mock agent lab tools, static plugin scanner output, static code-agent trace inspection, or UI scaffold artifacts as real system live evidence.

Live system surfaces cover domains such as RAG retrieval and citation security, Tool-agent injection and authorization security, Code-agent sandbox and workspace security, and Self-modification and policy-tampering security when the target exposes compatible traces.

Planning-only, scaffold, advisory, excluded, not-applicable, not-tested, missing-fixture, missing-configuration, and live-provider-required rows cannot inflate the primary score. It is not proof that a model or system is safe in all settings.

Assessment mode remains provider-free in the current implementation. All assessment modes disable provider and network calls; use assessment for CI/dev planning artifacts, not live benchmark claims. Assessment `live_provider` mode remains fail-closed and does not instantiate adapters or collect provider response evidence. Non-assessment commands keep their documented behavior.

It does not create GitHub issues in the default path and does not drive a browser or capture screenshots.

`ui-harness` remains scaffold-only and does not drive a browser or capture screenshots. Browser/UI live evidence is available through the separate `browser_agent` target route. Without Playwright, Malleus records a DOM-only page-capture artifact.

## Profiles, packs, and gates

| Profile | Use it for |
|---|---|
| `chatbot` | Plain chat assistants without tools or retrieval |
| `rag-agent` | Systems that answer from retrieved or supplied context |
| `tool-agent` | Agents that select tools or obey tool policy |
| `code-agent` | Agents that inspect or change code, tests, prompts, or policies |
| `vision-agent` | Systems that ingest visual or artifact content |
| `model-selection` | Comparing model or configuration choices |

The canonical scope is `datasets/release_matrices/malleus-v0.1.yaml`. The core text packs live under `datasets/benchmark_packs/`, and mutation profiles live under `datasets/mutation_profiles/`.

## Capability map

Use the quickstart first. Use this map when you need one specific path.

| Need | Command |
|---|---|
| normal live benchmark | `malleus benchmark soft --target <target-name>` |
| expanded live benchmark | `malleus benchmark exterminatus --target <target-name>` |
| lower-level text benchmark | `malleus run <target-name> --input datasets/benchmark_packs/smoke-v1.yaml` |
| one RAG service surface | `malleus benchmark live-rag --target <rag-service-target>` |
| one tool-agent surface | `malleus benchmark live-agentic --target <tool-agent-target>` |
| one workflow surface | `malleus benchmark live-workflow --target <workflow-target>` |
| one code-agent surface | `malleus benchmark live-code-agent --target <code-agent-target>` |
| one memory-agent surface | `malleus benchmark live-memory-agent --target <memory-agent-target>` |
| one multi-agent surface | `malleus benchmark live-multi-agent --target <multi-agent-target>` |
| one browser-agent surface | `malleus benchmark live-browser-agent --target <browser-agent-target>` |
| dashboard | `malleus dashboard --report reports/<run>/live-full-evidence.json --out-dir reports/<run>-dashboard` |
| evidence bundle | `malleus evidence-bundle --run-report reports/<run>/live-full-evidence.json --out-dir reports/<run>-evidence` |
| gate | `malleus gate --report reports/<run>/live-full-evidence.json` |

## Command reference

### Setup and health

| Command | What it does |
|---|---|
| `./malleus version` | Prints the installed Malleus version |
| `./malleus doctor` | Checks install, assets, optional integrations, sandbox tools, targets |
| `./malleus quickstart` | Prints setup-specific next steps |
| `./malleus init` | Interactive first-run setup |

### Targets

| Command | What it does |
|---|---|
| `./malleus target init` | Creates a managed target YAML |
| `./malleus target add <path>` | Adds an existing target YAML to the managed target store |
| `./malleus target list` | Lists managed targets |
| `./malleus target show <name>` | Prints a target config without exposing secrets |
| `./malleus target doctor <name>` | Validates target configuration and trace coverage |
| `./malleus target test <name> --allow-provider-call` | Sends a small live test call |

### Benchmarks

| Command | What it does |
|---|---|
| `./malleus benchmark soft --target <name>` | Normal canonical live benchmark |
| `./malleus benchmark exterminatus --target <name>` | Expanded canonical live benchmark |
| `./malleus benchmark live-full --target <name>` | Lower-level full matrix runner |
| `./malleus run <name> --input <pack>` | Lower-level text benchmark runner |
| `./malleus list-cases --input <pack>` | Lists cases in a benchmark pack |
| `./malleus validate --input <pack>` | Validates a benchmark pack |
| `./malleus list-cases --input <pack>` | Lists cases in a benchmark pack |
| `./malleus benchmark plan --models <panel>` | Builds a provider-free benchmark plan |
| `./malleus benchmark summarize --reports <dir>` | Summarizes existing benchmark reports |
| `./malleus assess --target <target> --profile chatbot --mode dry_run` | Builds provider-free release/CI planning artifacts |

### Reports and gates

| Command | What it does |
|---|---|
| `./malleus dashboard --report <report.json>` | Builds a static HTML dashboard |
| `./malleus evidence-bundle --run-report <report.json>` | Builds a sanitized evidence bundle |
| `./malleus gate --report <report.json>` | Applies pass/fail/warn gate rules |
| `./malleus diff-runs --old <old.json> --new <new.json>` | Compares two run reports |
| `./malleus compare --target <name> --model a --model b` | Compares multiple models through one target config |

### Mutations

| Command | What it does |
|---|---|
| `./malleus mutations list` | Lists available mutation transforms |
| `./malleus mutations inspect <name>` | Explains one mutation |
| `./malleus mutate --mutation <name> "text"` | Applies one mutation to text |
| `./malleus mutate-run core --target <name>` | Runs core text cases with mutation coverage |
| `./malleus mutate-run --target <name> --mutation-profile <file>` | Runs a custom mutation profile |

### Local analysis tools

| Command | What it does |
|---|---|
| `./malleus inspect-refusal "text"` | Explains refusal/compliance classifier output |
| `./malleus inspect-text --file <file>` | Inspects hidden text/artifact channels |
| `./malleus artifact-firewall --file <file>` | Reviews an artifact for hidden channels |
| `./malleus visual-lab generate` | Generates local visual fixtures |
| `./malleus visual-lab run --fixture <file>` | Runs provider-free visual fixture review |
| `./malleus visual-lab vision-run --target <target> --image <file>` | Runs a vision target when compatible |
| `./malleus campaign run --target <target> --campaign <file>` | Runs a multi-step campaign pack |
| `./malleus rag run --fixture <file>` | Runs local RAG fixture checks |
| `./malleus agent-lab --target <target> --scenarios <file>` | Runs local agent-lab scenarios |
| `./malleus coverage build --input <pack>` | Builds coverage metadata for packs |
| `./malleus threat-model init --profile <profile>` | Creates a threat-model template |
| `./malleus threat-model coverage --model <file> --coverage <file>` | Compares threat model and coverage |
| `./malleus taxonomy snapshot --input <pack>` | Exports taxonomy coverage |
| `./malleus taxonomy diff --old <old.json> --new <new.json>` | Compares taxonomy snapshots |
| `./malleus triage --source <report.json>` | Produces triage output from a report |
| `./malleus rescore --source <report.json>` | Re-runs deterministic scoring over a report |
| `./malleus findings export --findings <file>` | Exports findings |
| `./malleus patch suggest --finding <file>` | Suggests remediation patches |
| `./malleus replay <finding-id> --report <dir>` | Builds replay instructions |
| `./malleus regression generate --report <dir>` | Generates a regression pack |
| `./malleus regression validate --pack <file>` | Validates a regression pack |
| `./malleus adjudicate --finding <id> --report <dir>` | Records a review decision |
| `./malleus issues export --findings <file>` | Exports issue drafts locally |
| `./malleus compound-risk --findings <file>` | Builds compound-risk summaries |
| `./malleus studio export --report-dir <dir>` | Builds static studio output |
| `./malleus ui-harness run --config <file>` | Runs scaffold-only UI review |
| `./malleus workspace init --path <dir>` | Creates a local review workspace |
| `./malleus workspace status --path <dir>` | Shows workspace status |
| `./malleus workspace next --path <dir>` | Shows next workspace action |

### Agent integration examples

| Command | What it does |
|---|---|
| `./malleus agent serve-callable <module:object>` | Serves a Python callable as an agent target |
| `./malleus agent serve-langgraph <module:graph>` | Serves a LangGraph-style target |
| `./malleus agent serve-openai-agents <module:agent>` | Serves an OpenAI Agents-style target |
| `./malleus agent serve-langchain-rag <module:chain>` | Serves a RAG chain/service target |

See `examples/integrations/l2/README.md` for runnable examples.

## Repository Map

| Path | Purpose |
|---|---|
| `src/malleus/` | Python package and CLI implementation |
| `datasets/` | Source benchmark packs, mutation profiles, release matrix |
| `src/malleus/assets/` | Packaged assets used after install |
| `configs/` | Default scoring and gateway configs |
| `examples/targets/` | Example provider/model target YAMLs |
| `examples/integrations/l2/` | Agent integration examples |
| `tests/fixtures/` | Test and documentation fixtures |
| `docs/` | Detailed documentation |
| `reports/` | Local run outputs; ignored by git |

## Useful Docs

- `docs/quickstart.md`
- `docs/what-malleus-tests.md`
- `docs/interpreting-results.md`
- `docs/providers.md`
- `docs/production-stack-coverage.md`
- `docs/trace-schema.md`
- `docs/agent-target-contract.md`
- `docs/integrations/README.md`
- `docs/security-model.md`
- `docs/release-readiness.md`
- `docs/release-notes-v0.1.0-rc1.md`

## Development

```bash
./scripts/bootstrap
./malleus doctor
.venv/bin/pytest -q
.venv/bin/ruff check src tests scripts
.venv/bin/python -m build
```

CI mirrors the same basic expectations: tests, lint, build, install smoke, CLI smoke, and package asset checks.

## License

MIT.
