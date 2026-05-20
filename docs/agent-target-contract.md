# Malleus Agent Target Contract

Malleus supports three practical depths for live agent testing:

- `L0`: classic `chat_completion` or `vision_model` target. Malleus sends prompts to a model API.
- `L1`: auto-wrapper target. Malleus wraps a chat-compatible model in an ephemeral local system surface.
- `L2`: real external-agent target. Your agent runtime exposes a Malleus-compatible endpoint or subprocess contract, and Malleus evaluates the observable trace.

Use L2 when you want to test the actual application behavior of a LangGraph, OpenAI Agents SDK, CrewAI, AutoGen, custom RAG service, browser agent, code agent, or workflow agent.

## Commands

Serve a Python adapter:

```bash
malleus agent serve my_project.malleus_adapter:adapter --target-type tool_agent --framework langgraph
```

Serve a Python adapter in an isolated child process:

```bash
malleus agent serve my_project.malleus_adapter:adapter \
  --target-type tool_agent \
  --isolated \
  --cwd /path/to/project \
  --pythonpath /path/to/project \
  --env MY_AGENT_API_KEY
```

Serve a LangGraph graph directly:

```bash
malleus agent serve-langgraph my_project.graph:graph --target-type tool_agent
```

Serve an OpenAI Agents SDK agent directly:

```bash
malleus agent serve-openai-agents my_project.agents:support_agent --target-type tool_agent
```

Serve a plain Python callable/object directly:

```bash
malleus agent serve-callable my_project.agent:agent --target-type tool_agent --input-mode payload
```

Serve a native RAG framework object directly:

```bash
malleus agent serve-langchain-rag my_project.rag:chain
malleus agent serve-llamaindex-rag my_project.rag:query_engine
```

Inspect an adapter without starting the server:

```bash
malleus agent inspect my_project.malleus_adapter:adapter
malleus agent inspect-callable my_project.agent:agent --target-type tool_agent
malleus agent inspect-langgraph my_project.graph:graph
malleus agent inspect-openai-agents my_project.agents:support_agent
malleus agent inspect-langchain-rag my_project.rag:chain
malleus agent inspect-llamaindex-rag my_project.rag:query_engine
```

Create a scaffold:

```bash
malleus target scaffold-agent \
  --name "LangGraph Tool Agent" \
  --target-type tool_agent \
  --framework langgraph \
  --out-dir examples/agent_adapters/langgraph-tool
```

Validate a target YAML:

```bash
malleus target validate-agent examples/agent_adapters/langgraph-tool/langgraph-tool-agent.yaml
```

Run the matching live surface:

```bash
malleus benchmark live-agentic --target examples/agent_adapters/langgraph-tool/langgraph-tool-agent.yaml --out-dir reports/l2-tool-agent
```

## Supported L2 Surfaces

| Target type | Default endpoint | Matching benchmark |
| --- | --- | --- |
| `rag_service` | `/malleus/rag` | `malleus benchmark live-rag` |
| `tool_agent` | `/malleus/tool-agent` | `malleus benchmark live-agentic` |
| `workflow_harness` | `/malleus/workflow` | `malleus benchmark live-workflow` |
| `code_agent` | local sandboxed subprocess | `malleus benchmark live-code-agent` |
| `memory_agent` | `/malleus/memory-agent` | `malleus benchmark live-memory-agent` |
| `multi_agent` | `/malleus/multi-agent` | `malleus benchmark live-multi-agent` |
| `browser_agent` | `/malleus/browser-agent` | `malleus benchmark live-browser-agent` |

## Response Shape

HTTP L2 adapters should return JSON. Malleus accepts surface-specific details, but the stable fields are:

- `final_answer` or `answer`: user-visible result.
- `retrievals` or `citations`: RAG evidence when relevant.
- `tool_calls`: tool-agent calls with redacted arguments and result previews.
- `actions`: ordered observable actions.
- `trace`: normalized trace events.
- `metadata`: redaction-safe labels such as framework, run id, policy id, or target depth.

Do not return raw secrets, full private documents, raw browser screenshots, or unredacted filesystem content in metadata. Evidence should be replayable but redacted.

## YAML Metadata

L2 target YAML should include:

```yaml
metadata:
  agent_framework: langgraph
  agent_target_depth: L2
  agent_contract_schema: malleus.agent_target_contract.v1
```

The framework label is not used for scoring. It makes reports comparable across real agent systems.

## Python Adapter SDK

Native adapters implement `BaseAgentAdapter` and return `AgentResponse`.

```python
from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter
from malleus.schemas import HarnessToolCall, HarnessTraceAction


class Adapter(BaseAgentAdapter):
    target_type = "tool_agent"
    framework = "langgraph"

    def run(self, request: AgentRequest) -> AgentResponse:
        result = graph.invoke(request.payload)
        return AgentResponse(
            final_answer=result["answer"],
            tool_calls=[
                HarnessToolCall(
                    tool_name=call["name"],
                    arguments=call.get("args", {}),
                    result_preview=call.get("preview", ""),
                )
                for call in result.get("tool_calls", [])
            ],
            actions=[
                HarnessTraceAction(action_type="framework_event", summary=event["summary"])
                for event in result.get("events", [])
            ],
            metadata={"agent_framework": "langgraph", "agent_target_depth": "L2"},
        )


adapter = Adapter()
```

For simple agents or framework-like objects, `serve-callable` accepts `run()`, `invoke()`, `kickoff()`, `initiate_chat()`, or `__call__`. It normalizes common dict fields such as `answer`, `tool_calls`, `actions`, `retrievals`, and `diffs` into the same L2 response contract.

Then serve it:

```bash
malleus agent serve my_project.malleus_adapter:adapter
```

For local agent code, prefer the isolated child-process mode:

```bash
malleus agent serve my_project.malleus_adapter:adapter \
  --isolated \
  --cwd /path/to/project \
  --pythonpath /path/to/project \
  --env MY_AGENT_API_KEY
```

`--isolated` keeps adapter imports and execution out of the Malleus CLI process. The child receives only a minimal runtime environment plus variables explicitly listed with `--env`, and only the paths listed with `--pythonpath`.

For stricter local L2 serving on Linux hosts with bubblewrap installed, add an explicit sandbox:

```bash
malleus agent serve my_project.malleus_adapter:adapter \
  --isolated \
  --sandbox bwrap \
  --network-allowlist tcp://127.0.0.1:8787 \
  --cwd /path/to/project \
  --pythonpath /path/to/project \
  --env MY_AGENT_API_KEY
```

`--sandbox bwrap` runs the isolated child inside a bubblewrap namespace with explicit read-only runtime binds, a writable project working directory, `/tmp` tmpfs, and the same environment allowlist behavior as plain `--isolated`. Because the adapter is served over HTTP, Malleus requires `--network-allowlist` and uses a shared network namespace for that listener; treat the allowlist as an explicit serving policy, not as packet-level egress filtering. Use dedicated disposable credentials and local/staging endpoints when testing untrusted agents.

For strict network egress blocking, keep the public HTTP target in the Malleus parent process and run only the agent adapter in a no-network bwrap child:

```bash
malleus agent serve my_project.malleus_adapter:adapter \
  --isolated \
  --sandbox bwrap \
  --network-mode blocked \
  --tool-policy configs/tool-gateway-default.yaml \
  --cwd /path/to/project \
  --pythonpath /path/to/project \
  --env MY_AGENT_API_KEY
```

`--network-mode blocked` removes `--share-net` from the bubblewrap child and uses a local JSONL stdio bridge between the parent HTTP server and the sandboxed adapter. Existing HTTP target configs can still point at `http://127.0.0.1:8787/...`, but the imported agent code itself has no network namespace shared with the host. This is the preferred mode when evaluating untrusted local agent code that does not need direct provider or tool-network access from inside the adapter process.

`--tool-policy` accepts a YAML or JSON gateway policy. When omitted, Malleus uses a local defensive fixture policy.

## Tool Gateway

In blocked-network mode, adapters can request local tools through the Malleus parent instead of calling tools directly:

```python
from malleus.agent_adapter import AgentRequest, AgentResponse, BaseAgentAdapter
from malleus.agent_tools import tool_call


class Adapter(BaseAgentAdapter):
    target_type = "tool_agent"

    def run(self, request: AgentRequest) -> AgentResponse:
        search = tool_call("search", {"query": "policy"})
        email = tool_call("send_email", {"to": "public@example.test"})
        return AgentResponse(final_answer=f"search={search['decision']['action']} email={email['decision']['action']}")
```

`tool_call()` uses the same JSONL bridge as the isolated adapter. The parent-side `ToolGateway` applies a local policy before returning a result. The default v1 gateway includes fixture tools for `search`, `read_private_doc`, `send_email`, `delete_file`, and `public_export`; it blocks forbidden tools, missing trusted approvals, fake approval sources, private-to-public sinks, and secret-like/canary values in tool arguments.

A policy file looks like:

```yaml
schema_version: malleus.tool_gateway.v1
trusted_approval_sources:
  - trusted_harness
canaries:
  - MALLEUS_SYNTHETIC_CANARY_TOOL_ARG_003
tools:
  search:
    name: search
    allowed: true
    result:
      items:
        - title: Policy fixture
          snippet: Local gateway search result.
  send_email:
    name: send_email
    allowed: false
    sink: external
  delete_file:
    name: delete_file
    allowed: true
    requires_approval: true
    sink: destructive
```

Gateway events are attached to the adapter response as canonical `tool_calls`, `actions`, and `trace` entries. Response metadata includes a `tool_gateway` object with the policy hash, number of calls, blocked count, and reason codes. This makes tool behavior visible to scoring and public reports without giving the sandboxed agent direct network or filesystem authority.

Framework helpers are available when adapting existing agents:

```python
from malleus.agent_frameworks.tools import (
    malleus_langchain_tools,
    malleus_langgraph_tools,
    malleus_openai_agent_tools,
    malleus_tool,
)

search = malleus_tool("search")
langchain_tools = malleus_langchain_tools(["search", "send_email"])
langgraph_tools = malleus_langgraph_tools(["search", "send_email"])
openai_agent_tools = malleus_openai_agent_tools(["search", "send_email"])
```

These helpers are dependency-optional. If a framework package is unavailable, Malleus returns callable gateway tools with `__call__`, `invoke()`, and `run()` methods so the same adapter code can still be exercised in local tests.

## Auto Suite

Once a target YAML exists, Malleus can select compatible release-matrix packs automatically:

```bash
malleus benchmark suite \
  --target examples/integrations/l2/targets/deepseek/deepseek-tool-agent-local.yaml \
  --matrix datasets/release_matrices/malleus-v0.1.yaml \
  --out-dir reports/tool-agent-suite \
  --dry-run
```

The suite writes `benchmark-suite-report.json` and `benchmark-suite-report.md`, with one output directory per selected surface under `surfaces/<pack-id>/`.

## Native LangGraph Adapter

For LangGraph, Malleus can wrap a graph directly. The imported object can be a compiled graph exposing `invoke()` or `stream()`, or a graph-like callable.

```bash
malleus agent serve-langgraph my_project.graph:graph \
  --target-type tool_agent \
  --input-mode hybrid \
  --run-mode auto
```

Input modes:

- `hybrid`: preserve the original Malleus payload and add a `messages` state plus `malleus_context`.
- `payload`: pass the Malleus payload directly to the graph.
- `messages`: pass only a LangGraph-style `{"messages": [...]}` state.

Run modes:

- `auto`: use `stream()` when available, otherwise `invoke()`.
- `invoke`: call `graph.invoke(state)`.
- `stream`: collect stream chunks as trace events and use the final merged state as output.

The adapter extracts final answers from direct output fields or the last message, tool calls from `tool_calls` on messages or state, retrievals from common RAG fields, and stream chunks as `HarnessTraceAction` events.

## Native OpenAI Agents Adapter

For OpenAI Agents SDK, Malleus can wrap an agent directly. The imported object can be an SDK agent used with `Runner`, an object exposing `run_sync()`, `run()`, or `invoke()`, or a compatible callable.

```bash
malleus agent serve-openai-agents my_project.agents:support_agent \
  --target-type tool_agent \
  --input-mode text \
  --run-mode auto
```

If you need a custom runner object:

```bash
malleus agent serve-openai-agents my_project.agents:support_agent \
  --runner my_project.agents:Runner \
  --target-type tool_agent
```

Input modes:

- `text`: convert the Malleus payload into one user task string.
- `payload`: pass the Malleus payload dictionary directly.
- `messages`: pass a list with one `{role, content}` user message.

Run modes:

- `auto`: prefer `Runner.run_sync`, then `Runner.run`, then agent methods.
- `run_sync`: call a synchronous SDK runner or agent method.
- `run`: call an async or sync runner/agent run method.
- `invoke`: call `agent.invoke(input)`.
- `call`: call the imported object directly.

The adapter extracts `final_output`, `new_items`, tool calls, handoffs, message output items, and generic events into Malleus `AgentResponse` fields.

## Native LangChain And LlamaIndex RAG Adapters

Malleus can expose common RAG objects as `rag_service` targets without requiring custom HTTP code.

```bash
malleus agent serve-langchain-rag my_project.rag:chain
malleus agent serve-llamaindex-rag my_project.rag:query_engine
```

Supported object shapes:

- LangChain chain exposing `invoke(input)`.
- LangChain retriever exposing `get_relevant_documents(query)`, `retrieve(query)`, or `invoke(query)`.
- LlamaIndex query engine exposing `query(query)`.
- LlamaIndex retriever exposing `retrieve(query)`.
- Compatible callable returning a dict-like response.

Input modes:

- `query`: pass only the query string.
- `mapping`: pass `{query, question, input, tenant, top_k}`.
- `payload`: pass the full Malleus request payload.

Run modes:

- `auto`: choose `query`, then `invoke`, then retriever/callable.
- `invoke`: call `obj.invoke(input)`.
- `query`: call `obj.query(query)`.
- `retrieve`: call retriever methods and return retrieval trace.
- `call`: call the imported object directly.

The adapters normalize LangChain `source_documents`, LlamaIndex `source_nodes`, retriever documents, node metadata, ids, scores, previews, and citations into Malleus retrieval evidence.

## RAG Auto-Wrapper Versus Real RAG Targets

When a `chat_completion` target is routed through a RAG live surface, Malleus
may use an L1 auto-wrapper. That wrapper is only a temporary compatibility
layer. It builds a local RAG-style endpoint around the backing model and reports
`metadata.rag_auto_repair` for each query when it filters or hydrates retrieved
context.

Auto-wrapper repair can:

- drop private documents whose `tenant` does not match the query tenant;
- add declared `required_retrieved_ids` from the fixture when the wrapper has
  access to them;
- prefer declared `required_citations`;
- suppress declared `forbidden_citations` from the wrapper's citation trace.

Auto-wrapper repair cannot prove that a production RAG stack is safe. A real
`rag_service` target remains responsible for its own retriever, ACLs, source
priority, citation generation, and trace reporting. Malleus evaluates the
returned trace; it does not silently edit real endpoint behavior.
