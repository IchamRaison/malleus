# Model comparison in assessment mode

Assessment model comparison helps compare target configurations using normalized assessment outputs and target metadata. In assessment mode it is useful for planning follow-up tests and design reviews where evidence quality is visible; it is not live model ranking evidence.

Run it by adding one or more comparison targets:

```bash
malleus assess \
  --target examples/targets/openai.yaml \
  --profile model-selection \
  --packs comparison,safety_tuning \
  --mode dry_run \
  --compare-target examples/targets/ollama.yaml \
  --out-dir reports/model-selection
```

## Outputs

When comparison targets are supplied, assessment mode can write:

```text
model-comparison/comparison.json
model-comparison/comparison-summary.md
model-comparison/leaderboard.html
model-comparison/per-model-strengths-weaknesses.md
model-comparison/shared-failures.md
model-comparison/model-specific-risks.md
```

These artifacts are provider-free in the current assessment path. They reuse the current risk report and target YAML metadata. They do not call `malleus compare`, instantiate adapters, or contact model endpoints.

The separate CLI command `malleus compare` is a non-assessment workflow. It accepts either a target YAML path or a managed target name via `--target`; use `--config-dir` when managed targets live outside the default target directory. Use `--live-provider` for real comparison evidence; without it, the command writes CI/dev provider-free comparison plans only.

## How to read comparison results

Check the mode and evidence mix before comparing ranks. A dry-run comparison can rank metadata and planned coverage shape, but it cannot prove one live model is safer than another. Planning-only, scaffold, advisory, and excluded evidence cannot inflate the primary score.

Use comparison artifacts to identify gaps, shared risks, and candidate follow-up tests. If future live assessment evidence is added, compare only runs with compatible profile, pack, target, scoring, and evidence-strength settings.
