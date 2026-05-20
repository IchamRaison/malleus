# Production Stack Coverage

Malleus is an agent trace security evaluation harness. A live run is strongest
when the target exposes the production signals that explain what the agent did,
not only the final answer.

## What Malleus Covers

Malleus can evaluate:

- prompt/model behavior on canonical text and multimodal packs;
- real RAG service behavior, including retrievals, citations, tenant metadata,
  stale-source handling, and source priority;
- real tool-agent behavior, including tool calls, arguments, outputs, approval
  claims, forbidden-tool attempts, and private-to-public sinks;
- workflow harness behavior, including approvals, delegated steps, and policy
  blocks;
- code-agent behavior, including diffs, file writes, command execution,
  workspace isolation, lifecycle scripts, lockfile drift, and sandbox evidence;
- browser/UI agents, including actions, navigation, screenshots or DOM capture,
  network egress, and browser capability gaps;
- memory agents, including reads, writes, stale memory, poisoning, namespace
  leakage, and unauthorized writes;
- multi-agent systems, including handoffs, role confusion, delegated authority,
  and summarizer poisoning;
- capability gaps, provider errors, target errors, and scaffold/static outcomes
  as coverage outcomes rather than model failures.

## What The Target Must Expose

For production-stack coverage, expose your agent through one of the L2 target
contracts:

- `/malleus/tool-agent`
- `/malleus/rag`
- `/malleus/workflow`
- `/malleus/memory-agent`
- `/malleus/multi-agent`
- `/malleus/browser-agent`
- local subprocess/workspace config for `code_agent`

Responses should include a final answer plus structured trace fields:

- `metadata.agent_trace_events` with canonical event types;
- `tool_calls`, `actions`, `memory_events`, `handoffs`, `approvals`, `sinks`;
- `blocked_operations`, `artifacts`, `diffs`;
- `live_model_calls` or `backing_model_calls` when an agent delegates to a
  backing model;
- capability-gap metadata when a signal cannot be exposed.

Declare side-effect safety in target metadata when possible:

```yaml
metadata:
  agent_framework: langgraph
  agent_target_depth: L2
  side_effect_safety: local_only
```

Accepted public values include `dry_run`, `staging`, `sandbox`, `read_only`,
`disposable_fixture`, `isolated`, and `local_only`.

## What Malleus Cannot Guess

Malleus cannot infer hidden production behavior that is not reported by the
target or observable in artifacts. In particular, it cannot prove:

- unreported tool calls did not happen;
- unreported network egress did not happen;
- a backing model was or was not called unless the target reports calls or
  Malleus observes them through its wrapper;
- a memory store was not modified unless memory events or store snapshots are
  exposed;
- an approval was legitimate unless approval events include actor, scope, and
  policy context;
- an external system was safe for side effects unless the target declares a safe
  mode or runs in a controlled local/staging fixture.

Missing coverage is therefore surfaced as `missing`, `declared_gap`, or
`target_capability_gap`, not silently ignored.

## Target YAML Examples

Tool agent:

```yaml
name: l2-langgraph-tool-agent
target_type: tool_agent
tool_agent:
  endpoint_url: http://127.0.0.1:8788/malleus/tool-agent
  auth:
    bearer_token_env: MALLEUS_EXAMPLE_AGENT_TOKEN
  allowed_tools:
    - classify_ticket
metadata:
  agent_framework: langgraph
  agent_target_depth: L2
  side_effect_safety: local_only
```

RAG service:

```yaml
name: l2-rag-service
target_type: rag_service
rag_service:
  endpoint_url: http://127.0.0.1:8790/malleus/rag
  auth:
    bearer_token_env: MALLEUS_EXAMPLE_AGENT_TOKEN
  retrieval_top_k: 5
metadata:
  agent_framework: langchain
  agent_target_depth: L2
  side_effect_safety: local_only
```

## RAG Auto-Repair Boundary

RAG has two execution shapes:

- **L1 auto-wrapper:** the user supplies a normal `chat_completion` target, and
  Malleus creates a temporary local RAG-like service around that model so the
  RAG pack can run.
- **L2 real service:** the user supplies a `target_type: rag_service` endpoint
  that exposes its own retrievals, citations, and metadata.

The L1 auto-wrapper applies deterministic request repair before scoring. It
uses the query-specific documents, filters private documents that belong to a
different tenant, hydrates declared required sources when available, and removes
forbidden citations from the wrapper's citation list. Reports expose this under
`metadata.rag_auto_repair_summary`.

This repair exists to keep the wrapper honest. Without it, a convenience wrapper
can create false mass failures by accidentally injecting the wrong corpus into
every prompt. After repair, model behavior is still evaluated normally: a model
can still fail by following retrieved instructions, moving canaries, relying on
stale sources, or laundering citations.

For L2 real services, Malleus does not mutate the production retriever or fix
your service. The same problems are reported as target behavior. A production
service should enforce tenant ACLs before retrieval, validate citations against
retrieved source ids, preserve source priority, and expose trace fields so the
report can distinguish model behavior from retrieval-system behavior.

Code agent:

```yaml
name: l2-code-agent
target_type: code_agent
code_agent:
  workspace_path: examples/integrations/l2/fixtures/code-agent-workspace
  command_env:
    AGENT_TOKEN: MALLEUS_EXAMPLE_AGENT_TOKEN
  allowed_actions:
    - read
    - write
    - diff
    - test
metadata:
  agent_framework: generic_subprocess
  agent_target_depth: L2
  side_effect_safety: sandbox
  code_agent_command:
    - python
    - examples/integrations/l2/agents/deepseek_real_agents.py
```

Run the doctor before live execution:

```bash
malleus target doctor examples/integrations/l2/targets/langgraph-tool-agent.yaml --out-dir reports/doctor/langgraph
```

## Coverage Report Example

Every live-full, soft, exterminatus, and individual live-surface run writes:

- `stack-coverage.json`
- `stack-coverage.md`

Example excerpt:

```json
{
  "schema_version": "malleus.stack_coverage.v1",
  "target_name": "l2-langgraph-tool-agent",
  "target_type": "tool_agent",
  "summary": {
    "covered": 9,
    "declared_gap": 1,
    "missing": 6,
    "not_applicable": 8,
    "total": 24
  },
  "entries": [
    {
      "signal": "tool_calls",
      "category": "tooling",
      "status": "covered",
      "observed_count": 4
    },
    {
      "signal": "network_egress",
      "category": "side_effect",
      "status": "missing",
      "notes": "not observed in live evidence"
    }
  ]
}
```

This is production-stack trace coverage for Malleus surfaces, not a claim of
universal security coverage.
