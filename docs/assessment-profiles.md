# Assessment profiles

Assessment profiles choose a starting set of packs for common AI system shapes. They help users avoid hand-picking every pack while still keeping the evidence quality visible in reports.

Run a profile with:

```bash
malleus assess \
  --target examples/targets/openai.yaml \
  --profile rag-agent \
  --packs default \
  --mode dry_run \
  --out-dir reports/assessment
```

Current assessment execution is provider-free. Profile selection changes which packs are planned, marked applicable, or reported as gaps. It does not enable live provider calls.

## Profile mappings

| Profile | Default packs | What the profile asks | Evidence quality in current assessment paths |
|---|---|---|---|
| `chatbot` | `core`, `mutation`, `anomaly`, `taxonomy`, `infrastructure` | Does a plain assistant preserve instruction and output boundaries? | Planning-only and static evidence unless future live evidence is added. |
| `rag-agent` | `core`, `mutation`, `anomaly`, `rag`, `artifact`, `taxonomy`, `infrastructure` | Does retrieved or supplied context stay treated as untrusted data? | Planning-only plus local fixture or static evidence when fixture inputs exist. |
| `tool-agent` | `core`, `mutation`, `anomaly`, `tools`, `plugin_manifest`, `compound`, `taxonomy`, `infrastructure` | Does the agent preserve tool policy, approvals, and private/public boundaries? | Planning-only, simulated, fixture, or static evidence depending on pack. |
| `code-agent` | `core`, `mutation`, `anomaly`, `code_agent`, `plugin_manifest`, `artifact_challenge`, `self_modification`, `taxonomy`, `infrastructure` | Can workflow, code, prompt, or policy changes be manipulated? | Simulated, fixture, static, scaffold, and planning-only evidence. |
| `vision-agent` | `core`, `mutation`, `anomaly`, `artifact`, `visual`, `ui_harness`, `taxonomy`, `infrastructure` | Are visual and artifact-derived channels handled as untrusted input? | Local fixture, static, scaffold, and planning-only evidence. No browser or provider automation. |
| `model-selection` | `comparison`, `safety_tuning`, `taxonomy`, `infrastructure` | Which target configuration looks better under normalized assessment evidence? | Provider-free comparison from local report and target metadata. |

## Using explicit packs

You can override a profile with a comma-separated pack list:

```bash
malleus assess \
  --target examples/targets/openai.yaml \
  --profile tool-agent \
  --packs core,tools,plugin_manifest \
  --mode dry_run \
  --out-dir reports/tool-assessment
```

`--packs all` includes all catalog packs, including advanced and scaffold surfaces. That can be useful for planning, but it may lower coverage confidence because more relevant gaps become visible. Planning-only, scaffold, advisory, and excluded evidence cannot inflate the primary score.

## Choosing a profile

Choose the closest system shape, then inspect coverage and evidence strength. A `rag-agent` profile is better for any system that consumes untrusted retrieved context. A `tool-agent` profile is better when the system can select actions, call tools, or route data. Use `model-selection` when comparing target configurations, not when trying to prove one model is broadly safe.
