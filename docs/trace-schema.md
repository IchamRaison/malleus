# Agent Trace Schema

Malleus standardizes production agent evidence through `metadata.agent_trace_events`.
Adapters may also expose legacy structured fields such as `tool_calls`,
`actions`, `memory_events`, or `diffs`; Malleus normalizes them into the same
trace summary.

## Event Envelope

```json
{
  "event_type": "tool_call",
  "event_id": "call-1",
  "summary": "called classify_ticket",
  "status": "ok",
  "role": "assistant",
  "name": "classify_ticket",
  "direction": "output",
  "redacted_preview": "{\"classification\":\"safe_review\"}",
  "sha256": "redacted-content-sha256",
  "length": 39,
  "parent_event_id": "step-1",
  "timestamp": "2026-04-30T12:00:00Z",
  "metadata": {
    "source": "agent_runtime"
  }
}
```

Raw secrets or full sensitive payloads should not be emitted. Use redacted
previews and hashes when possible.

## Canonical Event Types

Request and messages:

- `prompt_input`
- `message`
- `system_message`
- `developer_message`
- `user_message`

Tooling and actions:

- `tool_call`
- `tool_args`
- `tool_output`
- `action`
- `approval`
- `handoff`

RAG and memory:

- `retrieval`
- `citation`
- `memory_read`
- `memory_write`
- `memory_event`

Browser and side effects:

- `browser_action`
- `navigation`
- `network_egress`
- `file_write`
- `file_diff`
- `command_execution`

Runtime and policy:

- `retry`
- `streaming_chunk`
- `background_job`
- `policy_block`
- `sink`
- `blocked_operation`
- `refusal`
- `capability_gap`

Outputs and evidence:

- `final_answer`
- `artifact`

## Standard Structured Fields

Malleus also recognizes these response fields and maps them into trace coverage:

- `tool_calls`
- `actions`
- `memory_events`
- `handoffs`
- `approvals`
- `sinks`
- `blocked_operations`
- `artifacts`
- `diffs`
- `live_model_calls`
- `backing_model_calls`

If a production stack cannot expose one of these signals, return an explicit
capability gap, for example:

```json
{
  "metadata": {
    "agent_trace_events": [
      {
        "event_type": "capability_gap",
        "summary": "browser runtime cannot expose screenshot trace in this environment",
        "status": "capability_gap",
        "metadata": {
          "gap": "missing_screenshot_trace"
        }
      }
    ]
  }
}
```

## Minimum Useful L2 Response

```json
{
  "final_answer": "Done.",
  "tool_calls": [
    {
      "id": "call-1",
      "name": "classify_ticket",
      "args": {
        "classification": "safe_review"
      },
      "status": "ok"
    }
  ],
  "metadata": {
    "live_model_calls": 1,
    "agent_trace_events": [
      {
        "event_type": "user_message",
        "summary": "received scenario prompt",
        "direction": "input"
      },
      {
        "event_type": "tool_call",
        "summary": "called classify_ticket",
        "name": "classify_ticket",
        "direction": "output"
      },
      {
        "event_type": "final_answer",
        "summary": "returned final answer",
        "direction": "output"
      }
    ]
  }
}
```

The stack coverage report is derived from these events and row metadata. Missing
fields lower trace coverage; they do not automatically count as model failures.
