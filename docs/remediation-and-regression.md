# Remediation and regression

Assessment mode turns findings and gaps into local follow-up artifacts. The goal is to make hardening work reviewable and retestable without exposing raw prompts, raw responses, credentials, or private paths.

Run an assessment:

```bash
malleus assess \
  --target examples/targets/openai.yaml \
  --profile rag-agent \
  --packs core,rag \
  --mode dry_run \
  --out-dir reports/remediation-review
```

## Remediation outputs

Remediation artifacts include:

```text
remediation/remediation-board.md
remediation/issue-export.json
```

The board groups findings, coverage gaps, and suggested next actions for human review. The issue export is local only in assessment mode. It does not open remote issue-tracker tickets or send data to external systems.

Evidence quality matters for remediation priority. A coverage gap from `planning_only` evidence usually means "add fixture, configuration, or live-capable evidence later." A qualifying behavioral finding means "review the model, policy, retrieval, tool, or artifact boundary that produced the finding."

## Regression outputs

Regression artifacts include:

```text
regression/regression-pack.yaml
regression/replay-commands.md
```

They provide safe local references for retesting the same pack and finding shape. Replay commands are rendered as command lines with placeholder output paths and sanitized arguments. They do not embed raw exploit text, raw report bodies, credentials, or private paths.

For findings collected outside `malleus assess`, generate the same provider-free loop explicitly:

```bash
malleus regression generate --report reports/run-or-assessment --out-dir reports/regression
malleus regression validate --pack reports/regression/regression-pack.yaml --out-dir reports/regression-validation
```

Validation checks that provider calls and network access remain disabled and that every replay command is dry-run only.

## Retest flow

1. Triage findings by severity, evidence strength, and score use.
2. Fix the relevant prompt, policy, retrieval boundary, tool approval rule, artifact handling, or configuration.
3. Re-run the same profile, packs, mode, and target metadata where possible.
4. Compare coverage, findings, primary score, and coverage confidence.

Regression is strongest when evidence mode stays consistent across runs. Do not compare a planning-only dry run as if it were live model evidence.

Accepted-risk waivers should include an expiration date:

```bash
malleus adjudicate \
  --finding MF-1 \
  --report reports/run-or-assessment \
  --status accepted_risk \
  --reviewer analyst \
  --reason-code temporary_exception \
  --expires-at 2026-12-31T00:00:00+00:00
```

Expired accepted-risk records are counted as open findings again.
