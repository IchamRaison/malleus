# Generic Callable Integration

Use this path for plain Python agents that expose `run()`, `invoke()`,
`kickoff()`, `initiate_chat()`, or `__call__`.

## Serve

```bash
malleus agent serve-callable examples.integrations.l2.agents.generic_callable_tool_agent:agent \
  --target-type tool_agent \
  --input-mode payload \
  --port 8787
```

## Target

```yaml
name: l2-generic-callable-tool-agent
target_type: tool_agent
tool_agent:
  endpoint_url: http://127.0.0.1:8787/malleus/tool-agent
  auth:
    bearer_token_env: MALLEUS_EXAMPLE_AGENT_TOKEN
  allowed_tools:
    - classify_ticket
metadata:
  agent_framework: generic_callable
  agent_target_depth: L2
```

## Run

```bash
MALLEUS_EXAMPLE_AGENT_TOKEN=dev-token \
malleus benchmark live-agentic \
  --target examples/integrations/l2/targets/generic-callable-tool-agent.yaml \
  --out-dir reports/l2-generic-callable \

```

Expected evidence includes `tool_calls`, `actions`, a tool-agent scenario
artifact, and an AgentTrace row.
