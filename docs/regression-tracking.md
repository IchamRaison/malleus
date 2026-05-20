# Regression tracking

Malleus can compare two `report.json` files and produce a deterministic regression report with evidence references for changed cases.

This is useful when testing a new model version, prompt policy, adapter, dataset revision, or scoring change. Instead of reading two full reports manually, `diff-runs` highlights exactly which cases or groups changed state.

## CLI usage

```bash
malleus diff-runs \
  --old reports/baseline/report.json \
  --new reports/current/report.json \
  --out-dir reports/regression-diff
```

Outputs:

- `diff-runs-report.json`
- `diff-runs-report.md`

## Provider-free regression packs

Findings can also be converted into a CI-safe regression pack without calling a provider:

```bash
malleus regression generate \
  --report reports/current \
  --out-dir reports/current-regressions

malleus regression validate \
  --pack reports/current-regressions/regression-pack.yaml \
  --source-findings reports/current/findings.json \
  --out-dir reports/current-regressions/validation
```

Outputs:

- `regression-pack.yaml`
- `replay-commands.md`
- `regression-manifest.json`
- optional `regression-validation.json`
- optional `regression-validation.md`

The generated pack is provider-free by construction: provider calls and network access are disabled, replay commands must be dry-run commands, and validation fails closed if a pack tries to enable live/provider execution.

## What is compared

The diff indexes both reports by stable item identifier:

- cases: `case:<category>:<case_id>`
- groups: `group:<category>:<group_id>`

It reports:

- total score delta
- pass-rate delta
- newly failing items
- newly passing items
- added items
- removed items
- unchanged items
- per-category score and pass-rate deltas

## Transition semantics

- `regressed`: old item passed, new item failed
- `improved`: old item failed, new item passed
- `added`: item only exists in the new report
- `removed`: item only exists in the old report
- `unchanged`: pass/fail state did not change, even if score changed

Score deltas are still recorded for unchanged items, so partial-score changes are visible in JSON even when pass/fail stayed stable.

## Example workflow

Run a baseline:

```bash
malleus run \
  --target examples/targets/nvidia.yaml \
  --input datasets/benchmark_packs/smoke-v1.yaml \
  --scoring configs/scoring-default.yaml \
  --out-dir reports/baseline
```

Run a candidate after changing model/config:

```bash
malleus run \
  --target examples/targets/nvidia.yaml \
  --input datasets/benchmark_packs/smoke-v1.yaml \
  --scoring configs/scoring-default.yaml \
  --out-dir reports/current
```

Compare:

```bash
malleus diff-runs \
  --old reports/baseline/report.json \
  --new reports/current/report.json \
  --out-dir reports/regression-diff
```

Inspect:

```bash
less reports/regression-diff/diff-runs-report.md
```

## Interpretation

A newly failing item is usually more important than a raw score drop because it represents a pass/fail transition on a named security behavior.

Category deltas help identify whether a regression is concentrated in one area, such as `policy_robustness` or `refusal_consistency`.

Added and removed items are separated from pass/fail transitions so dataset changes do not get confused with model behavior changes.

## Limitations

`diff-runs` compares already-generated reports. It does not rerun models and does not judge semantic similarity between responses.

The stable identifier includes item category. If a case moves categories between dataset versions, it is treated as removed from the old category and added to the new one.
