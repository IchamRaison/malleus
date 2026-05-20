# Case Study: Synthetic Model Configuration Risk Surface

## Summary

A provider-free `model-selection` assessment highlighted model configuration as a risk surface. The evidence is static and planning-oriented, based on target metadata and assessment artifacts. It is intended to guide review of configuration choices, not to rank live provider behavior.

## Case

- Case id: `synthetic-model-config-001`
- Profile: `model-selection`
- Packs: `comparison,safety_tuning`
- Mode: `dry_run`
- Evidence strength: `planning_only` and `static_analysis`
- Score use: advisory and coverage review only

## Evidence refs

- `raw/comparison/planning-metadata.json`
- `raw/safety_tuning/planning-metadata.json`
- `findings/findings.json`
- `regression/regression-pack.yaml`
- `evidence-bundle/artifact-index.json`

These refs point to provider-free local artifacts with sanitized metadata, hashes, lengths, pack IDs, and relative paths. They do not include credentials, provider responses, private paths, prompt bodies, response bodies, or token-looking values.

## Risk explanation

The synthetic finding describes configuration choices that can widen the review surface, such as unclear target ownership, missing safety metadata, incomplete pack coverage, or parameters that need human approval before production use. These signals help reviewers focus on target hygiene and evidence quality. They do not claim that any provider endpoint behaved unsafely.

## Remediation

- Keep target configs minimal and reviewed, with clear owner, adapter, model, base URL, and intended use metadata.
- Store secrets outside committed files and load them from local environment only.
- Document decoding, routing, and safety-relevant options that affect assessment repeatability.
- Add regression artifacts for configuration changes so reviewers can compare findings, coverage, and gate status over time.

## Regression and retest

After tightening configuration review, rerun the same provider-free assessment shape:

```bash
malleus assess \
  --target examples/targets/openai.yaml \
  --profile model-selection \
  --packs comparison,safety_tuning \
  --mode dry_run \
  --out-dir reports/case-studies/model-config-retest
```

Review `findings/findings.json`, `model-comparison/comparison.json` when comparison targets are used, `regression/regression-pack.yaml`, and `evidence-bundle/artifact-index.json` for sanitized refs and coverage changes.

## Limitations

This case study is provider-free and static. It does not contact live endpoints, compare live model responses, or certify a deployment. It is not live model behavior and is not proof of live endpoint behavior. A clean retest means the selected local configuration artifacts no longer report the same synthetic risk surface. It does not certify safety across other providers, models, prompts, routing policies, or deployment settings.
