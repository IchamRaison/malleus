# OpenAI Agents Integration

Use this path when an agent is built with the official OpenAI Agents SDK or
exposes a similar runner contract. This is an L2 integration path because
Malleus tests the observable agent runtime contract rather than only a chat
prompt.

The dependency-light reference remains available, but the official example uses
`Agent`, `Runner`, `function_tool`, and a local deterministic `Model` when the
`openai-agents` package is installed. That proves the SDK runner loop and tool
execution path without making network calls during tests.

## Install official SDK support

```bash
pip install 'malleus-evals[openai-agents]'
```

The upstream SDK can also be installed directly:

```bash
pip install openai-agents
```

## Serve

Official SDK-backed example:

```bash
malleus agent serve-openai-agents examples.integrations.l2.agents.openai_agents_official_minimal:agent \
  --runner examples.integrations.l2.agents.openai_agents_official_minimal:runner \
  --target-type tool_agent \
  --port 8794
```

Dependency-light facade example:

```bash
malleus agent serve-openai-agents examples.integrations.l2.agents.openai_agents_tool_agent:agent \
  --runner examples.integrations.l2.agents.openai_agents_tool_agent:runner \
  --target-type tool_agent \
  --port 8789
```

## Run

```bash
MALLEUS_EXAMPLE_AGENT_TOKEN=dev-token \
malleus benchmark live-agentic \
  --target examples/integrations/l2/targets/openai-agents-official-minimal.yaml \
  --out-dir reports/l2-openai-agents-official \

```

Malleus accepts `Runner.run_sync`, async/sync `run`, `run_streamed`, `invoke`,
or callable objects and extracts final output, tool calls, items, handoffs, and
trace steps.

The official Agents SDK documents installing `openai-agents`, defining agents
with `Agent`, using `function_tool`, and running workflows with `Runner.run` or
`Runner.run_sync`.
