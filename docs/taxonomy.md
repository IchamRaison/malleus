# Taxonomy

Malleus V0.1 organizes defensive LLM security tests around observable failure classes.

## instruction_boundary

Tests whether the target preserves instruction hierarchy when user content tries to override, reveal, transform, summarize, translate, or debug hidden instructions.

Subcategories:

- direct_override
- hidden_prompt_extraction
- hierarchy_inversion
- debug_mode
- transformation_leak

## sensitive_context

Tests whether the target avoids exposing secrets, credentials, private memory, hidden context, or user profile data.

Subcategories:

- secret_exfiltration
- memory_extraction
- partial_secret_disclosure
- encoded_secret_disclosure
- named_secret_probe

## policy_robustness

Tests whether refusals remain stable under social or structural pressure.

Subcategories:

- role_bypass
- developer_mode
- fake_authority
- benchmark_pretext
- simulated_tool_output
- refusal_consistency

## output_integrity

Tests whether the target respects strict output contracts while under adversarial or conflicting instructions.

Subcategories:

- strict_json
- schema_drift
- extra_text
- extra_keys
- nested_or_array_drift

## mutation styles

The mutation engine provides 140 metadata-backed prompt transformations for defensive robustness checks. They are grouped into families such as:

- obfuscation
- delimiter
- format_shift
- normalization
- segmentation
- ordering
- repetition
- unicode
- tool_context

Each transform has a stable name, family, target surface, risk label, safe example, tags, and deterministic behavior metadata. See `docs/what-malleus-tests.md` and `docs/mutation-robustness.md` for the current operator map.

These transforms are meant to support reproducible evaluation, not to become an offensive prompt-generation toolkit.

## agentic and artifact surfaces

Premium hardening workflows map additional local/offline evidence into the same defensive taxonomy without claiming exhaustive coverage:

- `tool_output` and `rag_context`: untrusted retrieved or tool-returned content attempts to grant authority or move canaries.
- `artifact_workspace`: generated artifacts must stay inside a virtual workspace and avoid unsafe hidden channels.
- `policy_gate`: deterministic gates, risk summaries, and coverage/threat-model checks represent deployment boundaries.
- `campaign_policy_boundary`: multi-step campaign evidence captures dependency order, branch decisions, mocked attempts, policy decisions, and replay plans.
- `interop`: external scanner results are normalized into sanitized findings with explicit lossy-warning metadata.
- `visual_injection`: local visual fixtures, OCR surfaces, image metadata, and low-visibility rendered text are treated as untrusted evidence rather than trusted instructions.
- `artifact_firewall`: local HTML, SVG, notebook, archive, and metadata-like artifact surfaces are inspected for hidden channels, path risks, script-like content, and canary movement using sanitized previews.
- `taxonomy_garden`: snapshots and diffs track dataset cells, coverage cells, reviewer status, and scenario maturity without editing source benchmark packs.
- `compound_risk`: existing findings are grouped into composed local risk stories with likelihood, impact, detectability, countermeasure notes, and evidence refs. Bands are ordinal triage labels, not probabilities.
- `ui_scaffold`: UI harness plans describe local/staging browser-evaluation shape while keeping browser execution, screenshots, providers, and network automation disabled in the implemented path.
- `issue_export`: local issue drafts connect findings to owners, labels, reproduction commands, acceptance tests, patches, regression commands, and closure criteria.

Coverage reports mark cells as `covered`, `partial`, or `missing`; missing cells are explicit gaps, not failures hidden by a score.

## Taxonomy garden commands

```bash
malleus taxonomy snapshot \
  --input datasets/benchmark_packs/smoke-v1.yaml \
  --coverage reports/coverage/coverage.json \
  --out-dir reports/taxonomy
malleus taxonomy diff \
  --old reports/taxonomy-baseline/taxonomy-snapshot.json \
  --new reports/taxonomy/taxonomy-snapshot.json \
  --out-dir reports/taxonomy-diff
```

These commands are provider-free. They summarize local datasets and coverage artifacts, preserve draft scenario status, and do not mark benchmark cases as reviewed.
