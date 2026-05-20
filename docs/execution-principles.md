# Execution principles for live-first Malleus

These principles guide future changes to commands, reports, docs, and tests. They preserve the live-first direction while keeping provider-free support safe and useful.

## Non-negotiables

1. Real claims require real execution. A live feature must call or run the target surface it claims to test.
2. Any OpenAI-compatible endpoint should be a first-class path for live model testing when the user supplies a safe local target config.
3. Provider-free, dry-run, fixture, simulated, scaffold, and static paths must stay clearly labeled.
4. Planning evidence cannot be counted as live model, service, workflow, or code-agent evidence.
5. A code-agent test must run a real sandboxed code-agent workflow against disposable code. Prose, planned steps, static traces, or fake transcripts are not enough.
6. Provider errors are operational records. They do not prove model behavior.
7. Capability gaps are coverage facts. They do not prove pass or fail.
8. Reports must make evidence strength clear enough for a reviewer to audit the claim without guessing.
9. Credentials must be referenced through local environment or ignored local config. Documentation must not include real or fake secret values.
10. Do not overstate the current implementation. When a path is still fail-closed or scaffold-only, say so.

## Evidence labels

Use precise evidence language. Prefer labels that tell operators what actually happened:

| Label | Meaning |
|---|---|
| `model_behavior` | A configured provider returned a completed model response |
| `service_trace` | A configured service returned observable behavior and trace data |
| `agent_trace` | A configured agent returned observable tool, policy, or action traces |
| `workflow_trace` | A configured workflow harness returned observable dry-run or sandbox action traces |
| `code_agent_trace` | A sandboxed code-agent workflow ran against disposable code and produced observable effects |
| `fixture_behavior` | A local fixture was evaluated without live target execution |
| `static_analysis` | A file, manifest, report, or stored artifact was inspected without live target execution |
| `simulated_behavior` | A local simulation produced behavior-like records without a real target call |
| `planning_only` | The command planned or described work, but did not execute the live target |
| `capability_gap` | The target or configuration cannot support the requested surface |
| `target_error` | The target path failed operationally before usable behavior evidence was collected |

The exact schema can evolve, but the distinction must remain: live evidence is observed behavior from the claimed target surface. Everything else is support evidence, a gap, or an operational outcome.

## Provider handling

Provider setup should be boring and safe. Users should be able to point Malleus at an OpenAI-compatible endpoint with a model name, base URL, and credential reference. Reports should record the configured target metadata, adapter type, model identifier, command, packs, profiles, matrix, and scoring policy without exposing secrets.

Live runs should be the normal user benchmark path and remain explicit with operator confirmation. Dry runs and provider-free commands are CI/dev/planning support paths only. When a command may spend quota or call a network endpoint, require clear operator intent and write reports that distinguish live responses from operational failures.

## Code-agent execution principle

Code-agent coverage is only real when it executes a sandboxed workflow against disposable code. A valid live code-agent path should include:

1. A temporary or disposable workspace.
2. A configured code-agent command, subprocess, or endpoint.
3. Safety boundaries for files, network, credentials, and destructive operations.
4. Observable commands, traces, file reads, file writes, diffs, or test outputs.
5. Cleanup or containment after the run.
6. Redacted reporting that proves what happened without leaking private content.

Static code-agent trace review can remain useful, but it must be labeled as static analysis. It cannot satisfy a claim that Malleus ran a code agent.

## Reporting principle

A report should never make weak evidence look strong. Every row should answer:

1. Was this live, provider-free, dry-run, fixture, simulated, scaffold, static, or planning-only?
2. Which target type was expected?
3. Which target type actually ran?
4. What observable evidence was collected?
5. What failed, skipped, or could not be tested?
6. Does this row support a product claim, or is it only supporting context?

Primary scores and feature completion summaries should not be inflated by planning-only rows, unsupported target types, provider errors, scaffold outputs, or static fixtures.

## Documentation principle

Docs should be honest before they are exciting. If a command is fail-closed, say it fails closed. If a surface is scaffold-only, say it is scaffold-only. If a live path requires a target type that the user has not configured, record a gap. Avoid wording that lets readers believe a simulated or provider-free path is already a real live test.

## Definition of done

A future live-first feature is done only when all of these are true:

1. The feature has a target type or target contract that matches the claimed surface.
2. A user can configure a safe local target without committing credentials.
3. The live path executes the real target surface when explicitly requested.
4. The provider-free or dry-run path remains available only as labeled support.
5. Reports separate live evidence, support evidence, gaps, skips, and operational errors.
6. The feature has tests for planning paths and fake local live paths that do not need real credentials.
7. Docs describe both the current behavior and the live evidence boundary.
8. No advertised claim depends on a scaffold, fixture, or mock pretending to be live.

If any item is missing, the feature can still ship as planning, scaffold, fixture, or experimental support, but it should not be marketed as a completed live capability.
