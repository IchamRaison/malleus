# Agent trace contract

`AgentTrace` is the canonical Phase 2 trace envelope for live agent and real-system evidence. It does not replace the detailed harness-specific result objects. It gives every live-capable surface a comparable summary shape so reports can be reviewed across RAG, tool-agent, workflow, and code-agent targets.

## Contract

Every `AgentTrace` records:

- `target_type` — the configured Malleus target type.
- `evidence_type` — the trace category, such as `service_trace`, `agent_trace`, `workflow_trace`, or `code_agent_trace`.
- `status` — normalized status: `ok`, `failed`, `capability_gap`, `target_error`, `target_config_error`, or `not_run`.
- `case_id` — the query, scenario, workflow, or fixture id.
- `target_call_count` — target calls attempted for this row.
- `target_trace_count` — observable trace items collected for this row.
- `live_model_calls` — backing live model calls reported by the target or wrapper when available.
- `capability_gaps` — normalized gap reason codes such as `missing_tool_trace`, `missing_retrieval_trace`, or `unsupported_tool_trace_shape`.
- `reason_codes` — deterministic reason codes from the source harness.
- `events` — comparable trace events derived from retrievals, tool calls, actions, workflow steps, file diffs, and artifacts.
- `evidence_ref` — JSON pointer into the source report result.
- `artifact_refs` — sanitized artifact paths or URIs.

## Current mappings

| Source harness | Target type | Evidence type | Required observable trace |
|---|---|---|---|
| RAG service harness | `rag_service` | `service_trace` | Retrieval or citation trace. |
| Tool-agent harness | `tool_agent` | `agent_trace` | Parseable tool-call trace. |
| Workflow harness | `workflow_harness` | `workflow_trace` | Dry-run or sandbox workflow action trace, approval trace, blocked operation, sink, or event. |
| Code-agent harness | `code_agent` | `code_agent_trace` | Sandboxed subprocess trace plus command/file/diff/test evidence. |

## Capability gaps

Capability gaps are coverage facts, not behavior failures. A target that cannot expose the trace required for a surface should produce `status=capability_gap` and a specific gap code.

Current normalized gap examples:

- `missing_retrieval_trace`
- `missing_tool_trace`
- `unsupported_tool_trace_shape`
- `missing_workflow_trace`

Future surfaces should follow the same pattern:

- `missing_filesystem_trace`
- `missing_approval_trace`
- `missing_memory_trace`
- `missing_browser_trace`
- `missing_multi_agent_handoff_trace`

## Reporting rule

Harness-specific reports should continue to expose detailed result fields, but they should also include `agent_traces` at report level. This makes cross-surface dashboards, gates, risk cards, and future regression generation possible without losing the detail needed to debug a specific harness.

`live-full` matrix rows also carry `metadata.agent_trace_summary` for system surfaces. This keeps RAG, tool-agent, workflow, and code-agent rows comparable in the aggregate report even when the detailed trace bodies live in the child harness reports.

## CLI summary

Use `trace-summary` to collect canonical traces from one or more JSON reports:

```bash
malleus trace-summary --report reports/tool-agent/report.json --report reports/rag/report.json --out reports/agent-traces.json
```

The command is provider-free. It reads existing reports, prints cross-surface counts, and can write a normalized `malleus.agent_trace_collection.v1` JSON artifact for dashboards, gates, or future regression generation.
