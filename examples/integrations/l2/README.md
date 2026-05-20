# L2 Integration Examples

These examples are dependency-light reference targets for real agent integration.
They are intended to be read, copied, and exercised by tests.

Provider-specific targets used for live local validation are kept under
`targets/deepseek/` so the public `examples/targets/` directory stays focused on
simple model/provider YAMLs. The DeepSeek files are examples of the same L2
contracts, not special-case harness code.

## Generic Callable Tool Agent

```bash
malleus agent serve-callable examples.integrations.l2.agents.generic_callable_tool_agent:agent \
  --target-type tool_agent \
  --port 8787

MALLEUS_EXAMPLE_AGENT_TOKEN=dev-token \
malleus benchmark live-agentic \
  --target examples/integrations/l2/targets/generic-callable-tool-agent.yaml \
  --out-dir reports/l2-generic-callable \
  --yes
```

## LangGraph-Style Agent

This example does not require LangGraph to be installed. It exposes the same
`invoke()` and `stream()` shape that the Malleus adapter expects from a compiled
graph.

```bash
malleus agent serve-langgraph examples.integrations.l2.agents.langgraph_tool_agent:graph \
  --target-type tool_agent \
  --run-mode stream \
  --port 8788
```

## LangGraph Official Minimal

`agents/langgraph_official_minimal.py` uses the official `StateGraph` API when
`langgraph` is installed. In a dependency-light checkout it falls back to a
graph-shaped object and reports that the official package is missing.

```bash
malleus agent serve-langgraph examples.integrations.l2.agents.langgraph_official_minimal:graph \
  --target-type tool_agent \
  --run-mode stream \
  --port 8793

malleus target doctor examples/integrations/l2/targets/langgraph-official-minimal.yaml
```

## OpenAI Agents-Style Agent

This example does not require the OpenAI Agents SDK. It provides an agent object
and a runner with a `run_sync(agent, input)` method so the adapter can exercise
the same public contract.

```bash
malleus agent serve-openai-agents examples.integrations.l2.agents.openai_agents_tool_agent:agent \
  --runner examples.integrations.l2.agents.openai_agents_tool_agent:runner \
  --target-type tool_agent \
  --port 8789
```

## OpenAI Agents Official Minimal

The checkout includes `agents/openai_agents_official_minimal.py`. If the
`openai-agents` package is installed, it builds a real SDK `Agent`, uses
`Runner`, registers a `function_tool`, and runs against a local deterministic
SDK `Model` so tests do not need network access. Without the package, the module
returns an explicit fallback status and remains contract-loadable.

```bash
pip install 'malleus-evals[openai-agents]'
```

```bash
malleus agent serve-openai-agents examples.integrations.l2.agents.openai_agents_official_minimal:agent \
  --runner examples.integrations.l2.agents.openai_agents_official_minimal:runner \
  --target-type tool_agent \
  --port 8794

malleus target doctor examples/integrations/l2/targets/openai-agents-official-minimal.yaml
```

## RAG Service

```bash
malleus agent serve-langchain-rag examples.integrations.l2.agents.rag_service:rag_chain \
  --input-mode mapping \
  --port 8790

malleus benchmark live-rag \
  --target examples/integrations/l2/targets/rag-service-local.yaml \
  --fixture examples/integrations/l2/fixtures/rag-service.yaml \
  --out-dir reports/l2-rag-service \
  --yes
```

## Browser Agent

Serve a local page, then serve the browser agent:

```bash
python -m http.server 8791 --directory examples/integrations/l2/fixtures/browser-site

malleus agent serve-callable examples.integrations.l2.agents.browser_agent:agent \
  --target-type browser_agent \
  --port 8792

malleus benchmark live-browser-agent \
  --target examples/integrations/l2/targets/browser-agent-local.yaml \
  --fixture examples/integrations/l2/fixtures/browser-agent.yaml \
  --out-dir reports/l2-browser-agent \
  --yes
```

If Playwright is installed, Malleus records screenshots and page-capture JSON.
Without Playwright, it records a DOM-only page-capture artifact and a clean
capability gap.

## Sandboxed Code Agent

```bash
malleus benchmark live-code-agent \
  --target examples/integrations/l2/targets/code-agent-sandboxed.yaml \
  --fixture examples/integrations/l2/fixtures/code-agent-workspace \
  --sandbox-backend fake_test \
  --out-dir reports/l2-code-agent \
  --yes
```

Use `--sandbox-backend bwrap` on Linux hosts with bubblewrap installed.
