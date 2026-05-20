# Case Study: Synthetic Tool-Use Fake Approval Weakness

## Summary

A provider-free `tool-agent` assessment recorded a synthetic fake-approval risk shape for tool use. The evidence is simulated and planning-oriented, built from local assessment artifacts rather than model calls or real tool executions.

## Case

- Case id: `synthetic-tool-approval-001`
- Profile: `tool-agent`
- Packs: `core,tools`
- Mode: `dry_run`
- Evidence strength: `planning_only` and `simulated_behavior`
- Score use: advisory and coverage review only

## Evidence refs

- `raw/tools/planning-metadata.json`
- `findings/findings.json`
- `regression/regression-pack.yaml`
- `evidence-bundle/artifact-index.json`

These refs are safe public pointers to local artifacts. They carry mode labels, pack IDs, sanitized summaries, hashes, lengths, and relative paths. They do not contain tool message bodies, prompt bodies, response bodies, secrets, provider results, or external issue links.

## Risk explanation

The synthetic finding describes a workflow where an agent might accept an approval statement from untrusted task context instead of checking the trusted approval channel. In production, that can lead to unsafe tool selection, skipped human review, or incorrect policy state. This case study only records the risk pattern and expected controls. It does not claim a live model approved or ran a tool.

## Remediation

- Require tool approval state to come from a trusted controller, not from user, retrieval, or tool-output text.
- Bind high-impact tools to explicit policy checks before execution.
- Record approval source, timestamp, scope, and actor in local audit artifacts.
- Add negative fixtures for fake approval wording using sanitized summaries rather than unsafe instruction text.

## Regression and retest

After adding trusted approval checks, rerun the same provider-free assessment shape:

```bash
malleus assess \
  --target examples/targets/openai.yaml \
  --profile tool-agent \
  --packs core,tools \
  --mode dry_run \
  --out-dir reports/case-studies/tool-approval-retest
```

Review `findings/findings.json`, `regression/regression-pack.yaml`, and `evidence-bundle/artifact-index.json` for the same finding shape, updated remediation notes, and sanitized evidence refs.

## Limitations

This case study is provider-free and simulated. It does not execute tools, open browser sessions, contact providers, open remote tickets, or certify live agent behavior. It is not live model behavior and is not proof of live endpoint behavior. A passing retest means the selected local artifacts no longer show the same synthetic fake-approval risk shape under the same profile and packs.
