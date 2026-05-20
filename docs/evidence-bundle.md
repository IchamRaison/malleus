# Evidence bundle dashboard

Malleus can aggregate multiple security-evaluation artifacts into one static HTML evidence bundle.

This is meant for internal review packets, audit handoff, release evidence, and local incident analysis. It does not rerun models. It reads local JSON reports and renders a single `index.html` with summary cards and section-level evidence.

## Supported inputs

- benchmark run reports: `report.json`
- mutation robustness reports: `mutation-report.json`
- agentic injection lab reports: `agent-lab-report.json`
- hidden-channel inspection reports: `hidden-channel-report.json`
- regression diff reports: `diff-runs-report.json`
- artifact firewall reports: `artifact-firewall-report.json`
- visual lab reports: `visual-lab-report.json` and `visual-run-report.json`
- RAG harness reports: `rag-report.json`
- campaign reports: `campaign-report.json`
- coverage reports: `coverage.json`
- threat model YAML files
- safety tuner reports: `safety-tuning-report.json`
- anomaly reports: `anomaly-report.json`
- benchmark plans/panels and summaries: `benchmark-plan.json`, panel YAML, and `leaderboard.json`
- patch suggestion manifests: `patch-suggestions-*.json`
- replay artifacts: `replay-*.json`, `rag-replay.json`, `campaign-replay.json`, and `replay-spec.json`
- compound-risk reports: `compound-risk-report.json`
- local remediation exports: `issue-export.json` and `remediation-board.md`
- neighboring optional artifacts such as `findings.json`, `risk-summary.json`, `adjudications.json`, and model risk cards when present

The bundle reads local artifacts only. It does not run model calls, browsers, GitHub commands, or provider-backed workflows.

## CLI usage

```bash
malleus evidence-bundle \
  --title "Malleus Security Evidence Bundle" \
  --run-report reports/nvidia-smoke/report.json \
  --mutation-report reports/nvidia-mutations/mutation-report.json \
  --agent-report reports/agent-lab/agent-lab-report.json \
  --hidden-report reports/hidden-channel-review/hidden-channel-report.json \
  --diff-report reports/regression-diff/diff-runs-report.json \
  --artifact-report reports/artifacts/artifact-firewall-report.json \
  --visual-report reports/visual/visual-lab-report.json \
  --rag-report reports/rag/rag-report.json \
  --campaign-report reports/campaign/campaign-report.json \
  --coverage-report reports/coverage/coverage.json \
  --threat-model reports/threat-model.yaml \
  --safety-report reports/safety/safety-tuning-report.json \
  --anomaly-report reports/anomaly/anomaly-report.json \
  --benchmark-report reports/benchmark-plan/benchmark-plan.json \
   --benchmark-panel tests/fixtures/models/panel.yaml \
   --patch-report reports/patches/patch-suggestions-mf-example.json \
   --replay-report reports/replay/replay-mf-example.json \
  --compound-report reports/compound-risk/compound-risk-report.json \
  --issue-report reports/issues/issue-export.json \
  --remediation-board reports/issues/remediation-board.md \
   --out-dir reports/evidence-bundle
```

Output:

- `index.html`

Audit mode:

```bash
malleus evidence-bundle \
  --title "Malleus Audit Bundle" \
  --run-report reports/nvidia-smoke/report.json \
  --out-dir reports/audit-bundle \
  --audit-mode
```

Audit-mode output:

- `index.html`
- `audit-summary.md`
- `risk-register.json`
- `remediation-table.json`
- `artifact-index.json`

Open it locally:

```bash
xdg-open reports/evidence-bundle/index.html
```

## What the dashboard shows

The top cards summarize:

- agentic violations
- failed benchmark items
- worst mutation delta
- hidden-channel findings
- newly failing regression items
- total run reports and score

Sections include:

- benchmark runs table
- mutation robustness cards
- agentic injection cards
- hidden-channel hygiene cards
- artifact firewall cards
- visual lab cards
- RAG harness cards
- campaign workflow cards
- coverage matrix cards
- threat-model status cards
- safety tuner cards
- anomaly signal cards
- benchmark plan and panel cards
- patch suggestion cards
- replay command cards
- compound-risk cards
- issue export and remediation-board cards
- regression tracking cards

## Design posture

The page uses a Linear-inspired dark technical dashboard style:

- near-black canvas
- subtle transparent panels
- violet accent
- green/warning/red evidence tones
- no external JavaScript
- no external fonts, CDN links, or network dependency
- static HTML only

It uses system font stacks only so the dashboard remains fully local and readable without network access.

Audit mode is stricter: the auditor HTML is local-only and uses no external JavaScript, fonts, CDN, server, or network dependency.

## Security posture

Input JSON reports are treated as untrusted display data. The HTML renderer escapes untrusted values before inserting them into the page.

Audit mode also avoids embedding raw report bodies. It indexes artifacts by sanitized relative or basename path, SHA-256, byte size, and type so reviewers can verify artifact presence without publishing private absolute paths, unsafe strings, or secret-like values.

The dashboard is a presentation layer. It should not be treated as a cryptographic attestation or proof that a model is safe.

Provider-free, simulated, and scaffold report inputs are displayed with their mode labels. They should be read as local artifact evidence, not model-endpoint results.

## Review Flow

Generate bundles from the reports you actually want to review, then keep the raw
run directory local unless you have explicitly scrubbed it for publication.
