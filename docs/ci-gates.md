# CI gates for assessments

Assessment gates turn a local risk report into CI-friendly status artifacts. They help teams fail closed on malformed policy, incompatible baselines, high-severity findings, or too many findings while keeping evidence mode visible.

Run a dry assessment with a gate policy:

```bash
malleus assess \
  --target examples/targets/openai.yaml \
  --profile rag-agent \
  --packs core,rag \
  --mode dry_run \
  --policy configs/assessment-gate.yaml \
  --out-dir reports/assessment-ci
```

If you do not supply a policy, the default gate blocks critical and high findings, warns on coverage gaps, and writes local gate artifacts.

## Outputs

Gate artifacts live under `gate/`:

```text
gate/gate-summary.json
gate/gate-summary.md
gate/gate-results.sarif
gate/gate-results.junit.xml
```

Statuses are `PASS`, `WARN`, `FAIL`, or `ERROR`. `PASS` and `WARN` map to exit code 0 in the artifact. `FAIL` and `ERROR` map to exit code 1. Invalid policy or baseline input fails closed as `ERROR`.

## Evidence-aware gating

Gates should be read with the assessment evidence mix. A warning from a dry-run coverage gap is a planning signal. A blocker from qualifying primary evidence is stronger. Planning-only, scaffold, advisory, and excluded evidence do not inflate the primary score, but they can still produce useful warnings for CI review.

## Regression pack gating

If assessment metadata points to a configured regression pack, the gate validates it before reporting success. Invalid or malformed regression packs fail closed as `ERROR`. If findings are present and no regression pack is configured, the gate warns with `regression_pack_missing_for_findings`.

You can validate a pack directly in CI:

```bash
malleus regression validate \
  --pack reports/regression/regression-pack.yaml \
  --source-findings reports/findings.json \
  --out-dir reports/regression-validation
```

## Safe CI defaults

Assessment mode is provider-free in this implementation, including `live_provider` fail-closed scaffolding. That makes dry assessment gates suitable for CI checks that should not spend provider quota, reach the network, run browsers, or create external issues.
