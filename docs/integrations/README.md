# L2 Agent Integrations

L2 integrations connect Malleus to a real agent runtime instead of testing only
a prompt/model endpoint. The agent must expose either a Malleus-compatible HTTP
route or a sandboxed subprocess contract with observable traces.

Reference examples live in [`examples/integrations/l2`](../../examples/integrations/l2/README.md).

Run `malleus doctor` before exercising optional integrations. It reports whether
Playwright, LangGraph, OpenAI Agents, LangChain, and `bwrap` are available in the
current environment.

## Integration Paths

| Integration | When to use it | Docs |
| --- | --- | --- |
| Generic callable | Plain Python objects, internal prototypes, custom agents | [`generic-callable.md`](generic-callable.md) |
| LangGraph | Compiled graphs or graph-like objects with `invoke()`/`stream()` | [`langgraph.md`](langgraph.md) |
| OpenAI Agents | Agents SDK objects or runners | [`openai-agents.md`](openai-agents.md) |
| RAG service | Retrieval services, LangChain chains, LlamaIndex query engines | [`rag-service.md`](rag-service.md) |
| Browser agent | Agents that operate over local/staging DOM state | [`browser-agent.md`](browser-agent.md) |
| Code agent | Agents that edit a disposable workspace | [`code-agent.md`](code-agent.md) |

## Contract Expectations

Every L2 target should provide:

- a target YAML with `target_type`;
- redaction-safe metadata including `agent_framework` and `agent_target_depth: L2`;
- observable traces such as `tool_calls`, `retrievals`, `actions`, `diffs`, or artifacts;
- explicit capability gaps when the agent cannot provide a required trace;
- no raw secrets, private absolute paths, or unredacted private documents in returned metadata.

See [`docs/agent-target-contract.md`](../agent-target-contract.md) for the
canonical contract.
