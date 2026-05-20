# Artifact compatibility and schema versions

Malleus keeps release artifacts additive and backward-compatible. Existing consumers can continue reading legacy outputs such as `report.json`, `report.md`, `report.html`, `dry-run.json`, `dry-run.md`, `mutation-report.json`, `agent-lab-report.json`, and `hidden-channel-report.json`; newer consumers can use companion manifests, schema versions, hashes, and redaction metadata.

## Versioning contract

- Core IR models use `malleus.ir.v1`.
- Artifact references use `malleus.artifact.v1` and preserve legacy `path` and `kind` fields while adding `artifact_type`, `sha256`, `relative_path`, and `redaction_status`.
- Report manifests use `malleus.report_manifest.v1` and list sibling artifacts by sanitized relative path plus SHA-256.
- Event logs use `malleus.events.v1`.
- Risk and gate outputs use `malleus.gates.v1`.
- Findings, patch suggestions, adjudications, interop reports, repeated summaries, coverage, threat models, workspaces, benchmark plans, benchmark summaries, visual lab reports, artifact firewall reports, taxonomy snapshots, compound-risk reports, issue exports, UI harness reports, and studio indexes each carry their own additive `malleus.*.v1` schema version.

Schema-version bumps should be reserved for breaking field changes. Adding optional fields, new artifact types, or new manifest entries should remain within the current v1 contracts.

## Artifact families

- **Run and dry-run artifacts:** legacy reports stay stable; `events.jsonl`, `manifest.json`, `report-manifest.json`, `risk-summary.json`, and `model-risk-card.md` are additive companions. Dry runs never call providers.
- **Findings and replay:** `findings.json`, `findings.md`, and replay artifacts store hashes, evidence references, redacted excerpts, and provider-free replay commands rather than raw prompts or responses.
- **Visual and artifact evidence:** visual lab generation/inspection, visual fixture runs, and artifact firewall reports use local fixtures or local files. They store hashes, lengths, redacted previews, untrusted surface labels, evidence refs, and relative paths. `vision-run --live-provider` is scaffold-only in this release and must not be described as a live provider evaluation.
- **Patch and adjudication:** patch suggestions are deterministic defensive starting points derived from sanitized finding fields; adjudications are append-only review records and do not rewrite original findings.
- **Issues and remediation:** issue export writes local `issue-export.json`, `remediation-board.md`, and Markdown issue drafts. GitHub creation remains fail-closed/scaffold metadata only in the implemented path.
- **Interop:** imports normalize supported promptfoo, garak, PyRIT, and Inspect-style JSON into sanitized findings; exports support SARIF, JUnit XML, promptfoo-style JSON, Inspect-like summaries, and GitHub annotation JSON/JSONL. Unsupported fields are reported with sanitized warning labels.
- **Coverage and threat-model:** coverage emits JSON/Markdown/HTML cells with evidence counts and explicit gaps. `threat-model` YAML is deterministic and local; coverage comparison fails closed when required cells are missing.
- **Taxonomy and compound risk:** taxonomy snapshots/diffs are provider-free local summaries of dataset, coverage, reviewer status, and scenario maturity. Compound-risk reports compose existing local findings into deterministic ordinal risk bands; they are triage aids, not probability estimates or proof of safe behavior.
- **Workspace:** workspace state is local-only metadata plus deterministic directories for runs, findings, patches, adjudications, coverage, and risk cards. Status and next-step commands inspect artifacts only.
- **Benchmark workflow:** `benchmark plan --dry-run` writes command plans with provider calls disabled. `benchmark summarize` reads local report fixtures and only edits README when `--write-readme` is explicitly supplied.
- **UI harness and studio:** UI harness outputs are local/staging scaffolds with browser/provider execution disabled. Studio export is a static local narrative over sanitized reports and writes `studio/index.html` plus `studio/artifact-index.json`.
- **Audit bundle:** audit mode writes `index.html`, `audit-summary.md`, `risk-register.json`, `remediation-table.json`, and `artifact-index.json`. It indexes artifacts by sanitized relative/basename paths with SHA-256 and byte size, and it must not embed raw report bodies, absolute private paths, unsafe payload strings, secret-like values, external JavaScript, fonts, CDN links, or network dependencies.

## Sanitization contract

Public and auditor-facing artifacts are sanitized by default. Raw payload fields such as `raw_payload`, raw bodies, unsafe decoded hidden-channel content, reviewer notes, external unsupported keys, and secret-like values are rejected or redacted at contract boundaries before serialization. Mentions of `raw_payload` in docs/tests are limited to validation and sanitization behavior. Malleus does not ship or advertise unsafe prompt collections; fixture examples are synthetic and defensive.

## Compatibility checklist for releases

Before a release, verify that legacy outputs still exist, new manifests reference their sibling artifacts with correct hashes, generated Markdown/HTML escapes untrusted values, provider-free dry-run and fixture workflows pass, audit bundles contain no absolute private paths or secret-like values, and docs distinguish optional provider-backed scripts from default CI-safe workflows.
