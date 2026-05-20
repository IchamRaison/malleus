# Assessment mode

Malleus assessment mode is the CI/dev planning workflow for reviewing a model or agent configuration against defined security surfaces without provider calls. It collects pack metadata, coverage gaps, evidence references, findings, remediation notes, regression artifacts, model-comparison artifacts when requested, and CI gate output in one assessment directory.

Use it when you want a structured answer to three questions: what was tested, what evidence supports the result, and what should be fixed or retested next. It does not prove that a model or system is safe in all settings.

## CI/dev planning command

```bash
malleus assess \
  --target examples/targets/openai.yaml \
  --profile rag-agent \
  --packs core,rag \
  --mode dry_run \
  --out-dir reports/assessment
```

Assessment mode is provider-free in the current implementation. `dry_run`, `local_fixture`, `simulated`, `scaffold`, and `live_provider` all keep provider and network calls disabled in assessment orchestration. `live_provider` is a fail-closed scaffold, not a live endpoint run. For normal benchmark evidence, use the live benchmark commands such as `malleus benchmark soft --target ...`.

## Profiles

Profiles map common system shapes to relevant packs:

| Profile | Use it for | Evidence quality to expect now |
|---|---|---|
| `chatbot` | Plain chat assistants without tools or retrieval. | Mostly planning-only assessment evidence unless a live-capable path is added later. |
| `rag-agent` | Systems that answer from retrieved or supplied context. | Planning-only plus local fixture or static evidence where fixtures exist. |
| `tool-agent` | Agents that select tools or obey tool policy. | Planning-only or simulated evidence in current assessment paths. |
| `code-agent` | Agents that inspect or change code, tests, prompts, or policies. | Simulated, fixture, static, and scaffold labels depending on pack. |
| `vision-agent` | Systems that ingest visual or artifact content. | Local fixture, static, and scaffold evidence only. |
| `model-selection` | Planning model or configuration follow-up tests. | Provider-free comparison over normalized assessment outputs; not live model ranking evidence. |

See `docs/assessment-profiles.md` for pack mappings.

## Packs

Packs describe the attack surface under review. Each pack has a tier, maturity label, supported modes, evidence-strength labels, and score-use policy. Core packs are intended to be stable product surfaces. Advanced packs are useful but may depend on fixtures, simulation, or more review. Experimental packs are scaffold-only or excluded from the primary score.

See `docs/attack-packs.md` for the full pack table.

## Evidence modes and strength

Assessment reports keep mode and evidence strength visible because not all evidence has the same meaning.

| Label | Meaning |
|---|---|
| `model_behavior` | Live or recorded model behavior evidence. Current assessment orchestration does not collect this. |
| `fixture_behavior` | Provider-free local fixture behavior. Useful for regression and boundary checks; not live benchmark evidence. |
| `static_analysis` | Deterministic local analysis of config, artifacts, coverage, or report metadata. |
| `simulated_behavior` | Deterministic simulated workflow evidence. It must not be read as live model behavior. |
| `planning_only` | Plan or scaffold evidence. It never inflates the primary score. |

## Outputs

An assessment output directory can include:

```text
risk-report.json
risk-report.html
executive-summary.md
strengths-weaknesses.md
assessment-manifest.json
coverage/coverage.json
coverage/coverage.md
coverage/coverage.html
findings/findings.json
findings/findings.md
remediation/remediation-board.md
remediation/issue-export.json
regression/regression-pack.yaml
regression/replay-commands.md
evidence-bundle/index.html
evidence-bundle/artifact-index.json
evidence-bundle/audit-summary.md
studio/index.html
model-comparison/comparison.json
model-comparison/comparison-summary.md
model-comparison/leaderboard.html
gate/gate-summary.json
gate/gate-summary.md
gate/gate-results.sarif
gate/gate-results.junit.xml
raw/<pack-id>/planning-metadata.json
```

`model-comparison/` appears when comparison targets are supplied. `gate/` is written with assessment gate status. Public artifacts use sanitized references, hashes, lengths, mode labels, evidence strength, pack IDs, and relative paths instead of raw prompt or response bodies.

## Safe default behavior

Assessment mode is designed to be safe for CI and documentation examples by default. It writes local artifacts, keeps missing evidence explicit, and records coverage gaps instead of pretending that untested packs passed.
