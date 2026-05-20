# Agent Trace Production Integration

Malleus L2 evaluates production-like agents through observable traces, not just
prompt/response pairs.

## HTTP Adapter Mode

Expose the agent on one of the standard local or staging routes:

- `/malleus/tool-agent`
- `/malleus/rag`
- `/malleus/workflow`
- `/malleus/memory-agent`
- `/malleus/multi-agent`
- `/malleus/browser-agent`

The response can include normal surface-specific fields such as `tool_calls`,
`retrievals`, `actions`, `memory_events`, `handoffs`, `approvals`, and `diffs`.
For richer trace coverage, also include either top-level `trace_events` or
`metadata.agent_trace_events`. Malleus can only cover the production surfaces the
target actually exposes; missing surfaces should be reported as capability gaps.

## Canonical Event Types

Supported event types include:

- `prompt_input`
- `system_message`
- `developer_message`
- `user_message`
- `tool_call`
- `tool_args`
- `tool_output`
- `retrieval`
- `citation`
- `refusal`
- `approval`
- `handoff`
- `memory_read`
- `memory_write`
- `memory_event`
- `browser_action`
- `navigation`
- `network_egress`
- `file_write`
- `file_diff`
- `command_execution`
- `retry`
- `streaming_chunk`
- `background_job`
- `policy_block`
- `final_answer`
- `capability_gap`

Trace events should not contain raw secrets or raw prompt bodies. Use
`redacted_preview`, `sha256`, and `length` for evidence. If you use
`malleus agent serve`, top-level fields such as `messages`, `prompts`,
`streaming_chunks`, and `policy_blocks` are normalized into
`metadata.agent_trace_events` automatically. Treat top-level `messages`,
`prompts`, raw tool outputs, and final answers as private adapter transport data;
public reports should rely on the redacted trace events and artifact references,
not raw transport bodies.

## Minimal Response Example

```json
{
  "final_answer": "I summarized the ticket and blocked the unsafe export.",
  "tool_calls": [
    {
      "tool_name": "lookup_ticket",
      "call_id": "tool-1",
      "arguments": {"ticket_id": "T-100"},
      "result_preview": "billing question",
      "status": "ok"
    }
  ],
  "metadata": {
    "agent_trace_events": [
      {
        "event_type": "prompt_input",
        "event_id": "prompt-1",
        "redacted_preview": "ticket triage task",
        "sha256": "hash-of-full-prompt",
        "length": 1234
      },
      {
        "event_type": "policy_block",
        "event_id": "block-1",
        "summary": "blocked external sink requested by untrusted ticket text"
      }
    ]
  }
}
```

## Capability Gaps

If a production agent cannot expose a required trace surface, return a safe
capability gap instead of inventing evidence. Examples:

- `missing_tool_trace`
- `missing_retrieval_trace`
- `missing_memory_trace`
- `missing_multi_agent_handoff_trace`
- `missing_browser_action_trace`
- `missing_approval_trace`
- `missing_filesystem_trace`

Malleus reports these as coverage outcomes, not model failures.
