# Attack packs

Attack packs are product-facing groups of checks for a specific model, context, artifact, tool, or workflow surface. Every pack declares its tier, maturity, supported modes, evidence strengths, and score-use behavior so reports can separate strong evidence from planning-only or advisory findings.

The current assessment implementation is provider-free. Packs that need live evidence are represented as planning-only or coverage-gap evidence until an explicit live-provider run produces completed model responses for chat/multimodal targets or observable target traces for real-system targets. Classic `malleus run` can call a configured provider unless `--dry-run` is supplied.

## Canonical v0.1 release matrix

The release scope is encoded in `datasets/release_matrices/malleus-v0.1.yaml`. It contains 15 public surfaces and 2 mutation profile references. The public surface names are intentionally descriptive; the versioned IDs remain machine identifiers for replay, routing, and backward compatibility.

| Public surface name | Technical ID | Evidence route |
|---|---|---|
| Smoke benchmark | `smoke-v1` | Live chat model |
| Core text security benchmark | `core-v1` | Live chat model |
| Hidden-channel and artifact-injection security | `artifact-hidden-channel-v1` | Live chat or vision model |
| Multi-step adversarial campaign security | `campaign-v1` | Live chat model |
| Deterministic agent safety challenges | `challenge-v1` | Live chat model |
| Calibration and control behavior checks | `calibration-v1` | Live chat model |
| Visual and OCR prompt-injection security | `visual-ocr-matrix` | Live multimodal/vision model |
| RAG retrieval and citation security | `rag-v1` | `rag_service` trace |
| Tool-agent injection and authorization security | `agentic-injection-v1` | `tool_agent` trace |
| Plugin workflow approval and action security | `plugin-workflow-v1` | `workflow_harness` trace |
| Code-agent sandbox and workspace security | `code-agent-v1` | `code_agent` trace |
| Memory poisoning and cross-user leakage | `memory-agent-v1` | `memory_agent` trace |
| Multi-agent handoff and delegation security | `multi-agent-v1` | `multi_agent` trace |
| Browser and UI action security | `ui-browser-v1` | `browser_agent` trace |
| Self-modification and policy-tampering security | `self-modification-v1` | Compatible system-agent trace |

- Local/provider-free assessment context: artifact/hidden-channel fixtures, visual/OCR fixture inventories, campaign dry runs, challenge fixtures, calibration controls, and code-agent/plugin/self-modification fixture-only review remain useful non-live context. They are not canonical live rows and cannot satisfy live gates.
- Optional deep test: Deep mutation robustness profile (`deep-v1`), the full 140-mutation profile, available but not part of default release gating.

Validate the scope with:

```bash
malleus benchmark validate-matrix --matrix datasets/release_matrices/malleus-v0.1.yaml
malleus mutations validate-profile --profile datasets/mutation_profiles/selected-v1.yaml --deep-profile datasets/mutation_profiles/deep-v1.yaml
```

## Pack catalog

| Pack ID | Title | Tier | Maturity | Surfaces covered | Current assessment evidence | Score use |
|---|---|---|---|---|---|---|
| `core` | Core LLM Security | core | stable | Instruction boundaries, policy resistance, sensitive-context handling, output integrity. | `planning_only` now, `model_behavior` is cataloged for future live evidence. | Included only with qualifying primary evidence. |
| `mutation` | Mutation Robustness | core | stable | Prompt variants, transformed inputs, refusal consistency under mutations. | `planning_only` now, `model_behavior` is cataloged for future live evidence. | Profile-dependent primary evidence when supported. |
| `rag` | RAG Injection | core | stable | Retrieved-context authority confusion, citation laundering, hostile context boundaries. | `fixture_behavior` or `static_analysis` when local fixtures exist, otherwise a coverage gap. | Profile-dependent for RAG profiles. |
| `tools` | Tool-Use and Agent Policy | core | stable | Tool selection, fake approval, tool-output injection, private-to-public route checks. | `simulated_behavior` in simulated mode, planning gap where live evidence would be needed. | Profile-dependent when model behavior exists. |
| `artifact` | Artifact Injection | core | stable | Untrusted files, document text, metadata, and artifact-derived instruction channels. | `fixture_behavior` or `static_analysis` when local fixtures exist. | Profile-dependent for artifact-aware profiles. |
| `anomaly` | Output Anomaly and Transcript Boundary | core | stable | Transcript-like output, hidden channel markers, replay-poisoning risk. | `planning_only` now, `model_behavior` is cataloged for future live evidence. | Included only with qualifying primary evidence. |
| `visual` | Visual Injection | advanced | beta | OCR surfaces, visual-context boundaries, artifact text treated as untrusted. | Local fixture or static evidence only. No browser or vision-provider execution in assessment mode. | Advisory unless explicitly made primary by future policy. |
| `safety_tuning` | Safety Tuning and Risk Surface | advanced | beta | Model selection, decoding, safety configuration, risk surface tradeoffs. | `planning_only` now. | Advisory in current assessment paths. |
| `code_agent` | Code-Agent Workflow Risk | advanced | beta | Code workspace risk, prompt or policy modification, test and scoring manipulation. | Simulated or planning evidence only. | Advisory in current assessment paths. |
| `plugin_manifest` | Plugin and Tool Manifest Risk | advanced | beta | Tool manifest metadata, permission description mismatch, unsafe tool affordances. | Local fixture or static evidence when configured. | Advisory in current assessment paths. |
| `artifact_challenge` | Artifact Challenge / Agent Protocol | advanced | beta | Multi-step artifact and protocol boundary checks. | Fixture or simulated evidence. | Advisory. |
| `compound` | Compound Risk | advanced | beta | Combined risk from findings, coverage gaps, and workflow context. | Fixture, simulated, or static evidence. | Advisory. |
| `self_modification` | Self-Modification Safety | experimental | scaffold | Workflows that might alter prompts, tests, policies, or code. | `planning_only` or static scaffold evidence. | Excluded. |
| `ui_harness` | UI Harness Scaffold | experimental | scaffold | UI workflow planning, selectors, and expected evidence shape. | `planning_only` or static scaffold evidence. It records UI plan metadata only. | Excluded. |
| `taxonomy` | Taxonomy and Coverage | core | stable | Pack inventory, coverage mapping, and reporting completeness. | Static or planning evidence. | Excluded from the primary score. |
| `comparison` | Model Comparison | advanced | beta | Provider-free comparison over normalized assessment report data and target metadata. | Planning-only unless future live runs produce comparable primary evidence. | Excluded from the primary score. |
| `infrastructure` | Findings, Remediation, Regression, Coverage, Gates | core | stable | Report tree, findings shape, remediation board, regression pack, CI gate artifacts. | Static or planning evidence. | Excluded from the primary score. |

## What failures mean

A failing pack indicates that the tested surface produced a finding, coverage gap, scaffold-only result, or workflow error under the selected mode and configuration. Treat the finding as evidence for that exact run, profile, pack, mode, and target metadata. Do not generalize it to every deployment of the same model.

Coverage gaps matter. If a pack is relevant but needs a fixture, configuration, or live provider path that is not active, Malleus records that gap instead of counting it as a pass.

## What is not covered

Assessment packs do not create a complete proof of safety. Current assessment paths do not call providers, operate browsers, send external issue requests, or publish unsafe prompt corpora. Some surfaces are represented with local fixture, static, simulated, scaffold, or planning-only evidence.

## Scenario expansion counts

The expanded inventory uses specialized fixtures, catalogs, and scaffold configs rather than adding every scenario to `datasets/benchmark_packs/core-v1.yaml`. Counts below are scoped to committed local assets and provider-free verification paths.

| Pack or surface | Count after expansion | What the count means |
|---|---:|---|
| RAG | 30 | Query/oracle scenarios in the local RAG fixture. |
| Agent/tool | 25 | Agent-lab scenarios with tool-policy decisions. |
| Artifact/hidden-channel | 30 | Committed catalog rows for artifact and hidden-channel carriers. |
| Visual/OCR | 61 | Broad visual matrix cases, split into 23 non-scaffold visual, 9 visual scaffold/planning, and 29 artifact-family cases. |
| Code-agent | 27 | Static code-agent trace fixtures. |
| Plugin/workflow | 23 | Static plugin, OpenAPI, or workflow manifest fixtures. |
| UI/browser | 25 | Local scaffold prompt/workflow units plus live `browser_agent` route. Screenshots require the optional Playwright backend. |
| Campaign | 26 | Campaign steps with unique tactics and oracles. |
| Self-modification | 23 | Durable inert diff or trace fixtures. |
| Challenge | 24 | Local challenge fixtures. |

These counts support repeatable local assessment and documentation. They do not mean every deployment, model, browser workflow, or provider endpoint has been tested. Live-provider model behavior remains separate from local, dry-run, simulated, static, and scaffold evidence.
