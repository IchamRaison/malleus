# Case Study: Synthetic RAG Injection Weakness

## Summary

A provider-free `rag-agent` assessment marked the RAG surface as a coverage gap with a synthetic injection weakness shape. The evidence is local planning and static assessment metadata only. It is useful for remediation planning, but it is not proof of live endpoint behavior.

## Case

- Case id: `synthetic-rag-injection-001`
- Profile: `rag-agent`
- Packs: `core,rag`
- Mode: `dry_run`
- Evidence strength: `planning_only` and `static_analysis`
- Score use: advisory and coverage review only

## Evidence refs

- `raw/rag/planning-metadata.json`
- `findings/findings.json`
- `regression/regression-pack.yaml`
- `evidence-bundle/artifact-index.json`

These refs contain sanitized metadata such as pack IDs, evidence strength, artifact hashes, lengths, and relative paths. They do not include retrieved text bodies, prompt bodies, response bodies, provider output, credentials, or private paths.

## Risk explanation

The synthetic finding describes a RAG boundary where untrusted retrieved content could be treated as higher priority than application instructions. In a deployed system, that pattern can weaken source trust, answer grounding, and policy separation. In this case study, Malleus records the risk shape and missing live evidence instead of claiming that a model followed a malicious document.

## Remediation

- Label retrieved content as untrusted context before it reaches the model or agent planner.
- Keep system policy, developer guidance, and retrieval snippets in separate fields with clear precedence.
- Add retrieval allowlists, source metadata checks, and answer citation requirements for high-risk collections.
- Add local fixtures that exercise safe handling of untrusted snippets without embedding raw exploit text in public artifacts.

## Regression and retest

After hardening the retrieval boundary, rerun the same provider-free assessment shape:

```bash
malleus assess \
  --target examples/targets/openai.yaml \
  --profile rag-agent \
  --packs core,rag \
  --mode dry_run \
  --out-dir reports/case-studies/rag-injection-retest
```

Review `findings/findings.json`, `coverage/coverage.json`, `regression/regression-pack.yaml`, and `evidence-bundle/artifact-index.json` for changed finding status, coverage confidence, and artifact refs.

## Limitations

This case study uses provider-free dry-run evidence. It is local, planning-oriented, and partly static. It is not live model behavior and is not proof of live endpoint behavior. A clean retest means the selected local assessment artifacts no longer report the same synthetic weakness shape. It does not prove that every RAG deployment, document source, prompt, or provider configuration is safe.
