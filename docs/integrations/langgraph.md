# LangGraph Integration

Use this path for compiled LangGraph graphs or graph-like objects that expose
`invoke()` or `stream()`.

The reference example does not require LangGraph to be installed. It implements
the public shape Malleus needs from a graph object.

## Serve

```bash
malleus agent serve-langgraph examples.integrations.l2.agents.langgraph_tool_agent:graph \
  --target-type tool_agent \
  --run-mode stream \
  --port 8788
```

## Run

```bash
MALLEUS_EXAMPLE_AGENT_TOKEN=dev-token \
malleus benchmark live-agentic \
  --target examples/integrations/l2/targets/langgraph-tool-agent.yaml \
  --out-dir reports/l2-langgraph \

```

Malleus normalizes graph messages, tool calls, retrieval-like context, stream
events, and action steps into the L2 trace contract.
