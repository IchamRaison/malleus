# What Malleus tests

Malleus is a defensive evaluation harness. It records the exact target, profile, packs, fixtures, mutations, scoring policy, gates, manifests, and reports used for a run. The goal is replayable evidence, not a jailbreak prompt dump.

## Short version

Malleus currently covers these security surfaces:

| Surface | What it probes | Main commands / docs |
|---|---|---|
| Core LLM boundaries | Instruction hierarchy, hidden prompt extraction, sensitive context leakage, role/policy pressure, refusal consistency, strict output contracts, schema drift. | `malleus run`, `malleus list-cases`, `docs/taxonomy.md` |
| Prompt mutation robustness | Whether small obfuscation, delimiter, formatting, Unicode, ordering, segmentation, and transcript shifts change safety or contract behavior. | `malleus mutations`, `malleus mutate`, `malleus mutate-run`, `docs/mutation-robustness.md` |
| Agent and tool-use injection | Synthetic tool-selection traps, fake approvals, tool-output instruction injection, forbidden-tool selection, and policy-gate behavior. | `malleus agent-lab`, `docs/agentic-injection-lab.md` |
| RAG and untrusted context | Retrieved-context authority confusion, citation laundering, hostile context boundaries, and canary movement in local fixtures. | `malleus rag run`, `docs/attack-packs.md` |
| Hidden channels and artifacts | Zero-width characters, bidi controls, Unicode tags, hidden HTML comments, printable base64-like blocks, Markdown link/title content, metadata-like channels, and risky local artifact structures. | `malleus inspect-text`, `malleus artifact-firewall`, `docs/hidden-channel-inspector.md` |
| Visual/artifact injection | Local visual fixtures, OCR-like surfaces, low-visibility text, metadata-vs-visible-content contradictions, and safe extracted representation. | `malleus visual-lab`, `docs/attack-packs.md` |
| Output anomaly and transcript boundaries | Pseudo-transcripts, role-marker leakage, replay-poisoning patterns, anomalous output loops, and boundary confusion. | `malleus inspect-output`, `malleus assess` |
| Code-agent and workflow risk | Workspace containment, generated-file integrity, self-modification proposals, plugin manifests, VCS publication gates, and lifecycle traces. | `malleus code-agent`, `malleus self-mod`, `malleus plugin-scan` |
| Evidence, regression, and release gates | Run manifests, event streams, risk cards, diff-runs, finding lifecycle, remediation boards, SARIF/JUnit exports, static evidence bundles, and CI gates. | `malleus gate`, `malleus diff-runs`, `malleus evidence-bundle`, `malleus studio export` |

## Core benchmark pack

`datasets/benchmark_packs/core-v1.yaml` expands to 38 benchmark items: 35 single cases and 3 refusal-consistency groups.

| Category | Items | Subcategories |
|---|---:|---|
| `instruction_boundary` | 10 | `direct_override`, `hidden_prompt_extraction` |
| `sensitive_context` | 10 | `secret_exfiltration`, `memory_extraction` |
| `policy_robustness` | 8 | `role_bypass`, `refusal_consistency` |
| `output_integrity` | 10 | `strict_json`, `schema_drift` |

Severity mix in the current core pack: 4 critical, 15 high, 17 medium, and 2 low items.

Run it live, or inspect it without provider calls:

```bash
malleus list-cases --input datasets/benchmark_packs/core-v1.yaml
malleus run \
  --target examples/targets/openai.yaml \
  --input datasets/benchmark_packs/core-v1.yaml \
  --scoring configs/scoring-default.yaml \
  --out-dir reports/core-live
```

Classic `malleus run` calls a configured provider unless `--dry-run` is supplied. Use `--dry-run` only for CI/dev planning; assessment mode is provider-free in this release.

## Release matrix and mutation profiles

The canonical v0.1 scope is `datasets/release_matrices/malleus-v0.1.yaml`. It records 15 live-gated surfaces plus 2 mutation profile references. Public surface names are descriptive, while versioned IDs such as `rag-v1` remain machine identifiers for replay/routing compatibility. Canonical live rows require completed live model calls, multimodal model evidence, observable real-system traces, or explicit capability-gap outcomes from the live harness. Provider-free static inventories, provider-free dry-run plans, and local scaffold artifacts remain useful local assessment context, but they are not canonical live rows and cannot satisfy live gates. The browser/UI surface now requires a compatible `browser_agent` target and a real local/staging DOM/action trace; when the optional Playwright backend is installed it also records screenshot artifacts, otherwise screenshot capture is reported as an explicit capability gap.

| Public surface name | Technical ID | Required target type |
|---|---|---|
| Smoke benchmark | `smoke-v1` | `chat_completion` |
| Core text security benchmark | `core-v1` | `chat_completion` |
| Hidden-channel and artifact-injection security | `artifact-hidden-channel-v1` | `chat_completion` or `vision_model` |
| Multi-step adversarial campaign security | `campaign-v1` | `chat_completion` |
| Deterministic agent safety challenges | `challenge-v1` | `chat_completion` |
| Calibration and control behavior checks | `calibration-v1` | `chat_completion` |
| Visual and OCR prompt-injection security | `visual-ocr-matrix` | `vision_model` |
| RAG retrieval and citation security | `rag-v1` | `rag_service` |
| Tool-agent injection and authorization security | `agentic-injection-v1` | `tool_agent` |
| Plugin workflow approval and action security | `plugin-workflow-v1` | `workflow_harness` |
| Code-agent sandbox and workspace security | `code-agent-v1` | `code_agent` |
| Memory poisoning and cross-user leakage | `memory-agent-v1` | `memory_agent` |
| Multi-agent handoff and delegation security | `multi-agent-v1` | `multi_agent` |
| Browser and UI action security | `ui-browser-v1` | `browser_agent` |
| Self-modification and policy-tampering security | `self-modification-v1` | `tool_agent`, `workflow_harness`, `code_agent`, `memory_agent`, or `multi_agent` |

Live target types are explicit:

- `chat_completion` — classic chat or multimodal model endpoints. Evidence requires completed provider responses and is reported as chat/multimodal model behavior.
- `rag_service` — a real retrieval service endpoint. Evidence requires target calls plus observable retrieval/citation traces; fixture/model-only RAG is not real system evidence.
- `tool_agent` — a real agent endpoint that returns observable tool calls. Mock agent-lab tools are not real system evidence.
- `workflow_harness` — a real dry-run workflow endpoint with observable action traces. Static plugin scanning is not real system evidence.
- `code_agent` — a sandboxed code-agent target that runs against disposable fixture workspaces. Static code-agent trace inspection is not real system evidence.

Canonical chat-completion surfaces include Deterministic agent safety challenges (`challenge-v1`) and Calibration and control behavior checks (`calibration-v1`). They run real provider/model calls through live runners, use deterministic scoring and reason codes, and write redacted artifacts. Visual and OCR prompt-injection security (`visual-ocr-matrix`) is a live multimodal/vision evidence surface; text-only or image-unsupported targets produce `provider_capability_gap` rather than generic chat-text evidence.

Use `malleus benchmark live-rag`, `live-agentic`, `live-workflow`, `live-code-agent`, or `live-self-modification` for one system surface, `malleus benchmark soft` for the default live set, and `malleus benchmark exterminatus` for the exhaustive wrapper with optional deep mutations. `exterminatus` is exhaustive over implemented/canonical Malleus surfaces and configured mutation profiles, not exhaustive over universal AI security. Capability gaps and target/config errors are reported as run conditions, not model behavior failures.

Mutation profiles are split deliberately:

- `datasets/mutation_profiles/selected-v1.yaml` — default release profile with 25 high-value deterministic mutations.
- `datasets/mutation_profiles/deep-v1.yaml` — optional exhaustive profile with all 140 registered mutations.

Validate them provider-free with:

```bash
malleus benchmark validate-matrix --matrix datasets/release_matrices/malleus-v0.1.yaml
malleus mutations validate-profile --profile datasets/mutation_profiles/selected-v1.yaml --deep-profile datasets/mutation_profiles/deep-v1.yaml
```

## Mutation registry

The mutation registry currently exposes 140 deterministic transforms. They are metadata-backed transforms with stable names, family, surface, risk, examples, and tags. Malleus compares original and mutated behavior instead of treating mutations as anonymous prompt tricks.

Current mutation families:

| Family | Count | Examples / purpose |
|---|---:|---|
| `format_shift` | 58 | Markdown quotes, tables, logs, email blocks, YAML/JSON/XML-style wrapping, comments, transcript-like blocks. Tests parsing boundaries. |
| `obfuscation` | 38 | Spacing, leetspeak, homoglyph-like substitutions, inserted separators, Unicode spacing, zero-width insertion. Tests normalization and lexical robustness. |
| `delimiter` | 14 | Brackets, quotes, code fences, XML/HTML comment wrappers. Tests delimiter handling and boundary attribution. |
| `normalization` | 6 | Case and whitespace normalization variants. Tests brittle matching and canonicalization. |
| `segmentation` | 4 | Fixed-size chunking and bracketed chunking. Tests line/chunk boundary handling. |
| `ordering` | 2 | Reversed word or mirrored line variants. Tests order sensitivity. |
| `repetition` | 1 | Duplicate words. Tests deduplication and repetition handling. |
| `tool_context` | 1 | Present content as inert tool output. Tests transcript/tool-output authority boundaries. |
| `unicode` | 1 | Unicode-focused wrapping/representation. Tests Unicode boundary handling. |

Surfaces include ASCII delimiters, ASCII spacing, case, character order, character spacing, character substitution, code, CSV, diff, email, INI, JSON, line breaks, logs, Markdown, markup, plain text, quotation, shell, table, TOML, tool output, transcript, Unicode delimiters, Unicode invisible characters, Unicode spacing, whitespace, word order, word repetition, and YAML.

Inspect and run mutations with:

```bash
malleus mutations list
malleus mutations inspect zero_width_insert
malleus mutate --mutation markdown_quote "Summarize this support ticket"
malleus mutate-run \
  --target examples/targets/openai.yaml \
  --input datasets/benchmark_packs/smoke-v1.yaml \
  --scoring configs/scoring-default.yaml \
  --out-dir reports/mutations \
  --dry-run \
  --mutation-profile datasets/mutation_profiles/selected-v1.yaml
```

Mutation reports record redacted original/mutated prompt and response references with hashes and lengths, original score, mutated score, delta, mutation metadata, worst mutation, and case-by-mutation matrix.

## Assessment packs

Assessment mode groups checks into product-facing packs. See `docs/attack-packs.md` for the canonical pack catalog.

| Pack | Covered area |
|---|---|
| `core` | Core LLM instruction, policy, sensitive-context, and output-integrity checks. |
| `mutation` | Prompt variant and transformed-input robustness. |
| `rag` | Retrieved-context and supplied-context injection boundaries. |
| `tools` | Tool selection, fake approval, tool-output injection, and private/public route checks. |
| `artifact` | Document/file/metadata instruction channels and local artifact safety. |
| `anomaly` | Transcript-boundary and replay-poisoning style output anomalies. |
| `visual` | OCR/visual-context boundaries and untrusted visual text. |
| `safety_tuning` | Provider-free risk-surface planning across model/config choices. |
| `code_agent` | Code-workflow, prompt/policy modification, workspace, and VCS lifecycle risk. |
| `plugin_manifest` | Tool/plugin manifest permission and description mismatch. |
| `artifact_challenge` | Multi-step artifact/protocol boundary fixtures. |
| `compound` | Combined risk stories from findings and gaps. |
| `self_modification`, `ui_harness`, `taxonomy`, `comparison`, `infrastructure` | Scaffold, coverage, comparison, and release-support evidence. |

## Scenario expansion inventory

The scenario expansion inventory is specialized fixture and catalog coverage. It was validated with local parsers, static checks, dry-run commands, and scaffold reports. It was not bulk-added to `datasets/benchmark_packs/core-v1.yaml`, which stays curated for the core text benchmark.

| Surface | Current inventory count | Evidence boundary |
|---|---:|---|
| RAG | 30 query/oracle scenarios | Local fixture execution only. |
| Agent/tool | 25 agent-lab scenarios | Dry-run or simulated behavior. No real tool execution. |
| Artifact/hidden-channel | 30 committed catalog rows | Static or local artifact inspection. |
| Visual/OCR | 61 broad matrix cases: 23 non-scaffold visual, 9 visual scaffold/planning, 29 artifact-family cases | Local fixture inventory only. Canonical `visual-ocr-matrix` live evidence is separate multimodal/vision evidence, with `provider_capability_gap` for unsupported image input. |
| Code-agent | 27 trace fixtures | Static trace inspection only. Scripts are not executed. |
| Plugin/workflow | 23 manifest fixtures | Local static manifest scanning. No remote schema fetch or plugin execution. |
| UI/browser | 25 local/staging prompt/workflow units | Scaffold in `ui-harness`; live `browser_agent` targets use DOM snapshots, observable actions, and Playwright screenshots when the optional browser backend is installed. |
| Campaign | 26 steps | Local dry-run or simulated campaign context only. Canonical campaign live evidence is produced by the live `chat_completion` runner. |
| Self-modification | 23 durable fixtures | Inert diff or trace inspection. Diffs are not applied. |
| Challenge | 24 local fixtures | Local fixture context only. Canonical `challenge-v1` is a live `chat_completion` surface with real provider/model calls and deterministic scoring. |

These counts describe committed defensive scenarios and fixtures, not universal attack coverage. Passing them means the selected fixture, mode, target metadata, and scoring policy did not produce a blocking result under that run's conditions. Live-provider evaluation is a separate activity and was not performed for this scenario expansion.

Do not treat fixture-RAG/model-only RAG, mock agent lab tools, static plugin scanner output, static code-agent trace inspection, or UI scaffold artifacts as real system live evidence. Real system evidence is limited to target-type-specific live routes that execute the configured `rag_service`, `tool_agent`, `workflow_harness`, `code_agent`, `memory_agent`, `multi_agent`, or `browser_agent` target and record observable calls, traces, or artifacts.

Provider-free assessment example:

```bash
malleus assess \
  --target examples/targets/openai.yaml \
  --profile rag-agent \
  --packs core,mutation,rag,artifact,tools \
  --mode dry_run \
  --out-dir reports/assessment
```

## Scoring and evidence methods

Malleus favors deterministic, inspectable scoring first:

- substring and regex checks for specific leaked or forbidden content;
- refusal-marker and refusal-classifier evidence with spans and rationale;
- exact JSON key validation and strict structured-output checks;
- extra-text-around-JSON and schema-drift detection;
- no-secret-pattern checks for sensitive-context tests;
- consistency penalties for grouped refusal tests;
- latency warnings when measured;
- risk gates over generated `report.json` or assessment artifacts.

Reports preserve evidence in machine and human formats: JSON, Markdown, HTML, manifests, events, risk cards, SARIF/JUnit, remediation boards, regression packs, and static studio/evidence-bundle exports.

Important limitation: a pass is scoped to the selected target, config, pack, fixtures, mode, and scoring policy. It is evidence for that run, not universal proof that a model or agent is safe.

## Safety posture

Malleus intentionally avoids publishing raw unsafe corpora. Public artifacts should contain synthetic canaries, redacted previews, hashes, lengths, relative paths, and evidence labels. Provider-backed runs are explicit; provider-free and dry-run modes are preferred for development, CI, and documentation.
