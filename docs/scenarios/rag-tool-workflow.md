# RAG, Tool, and Workflow Scenarios

These surfaces test systems that combine a model with external context or
actions. The important evidence is not only the final answer: Malleus expects
retrieval traces, tool/action decisions, approvals, sinks, and reason codes.

## RAG retrieval and citation security

Source: `tests/fixtures/rag/security-fixture.yaml`

Scenario families:

- Tenant isolation and private/public boundary checks.
- Poisoned public FAQ content.
- Fabricated or laundered citations.
- Stale authority and source-priority inversion.
- Metadata that pretends to be trusted instructions.
- Chunk-boundary and quoted-instruction handling.
- Canary movement through summaries or citations.
- Multi-document collusion and changelog downgrade pressure.
- Table-cell, footnote, title, Unicode, and fake system-message channels.
- Memory-write requests embedded in retrieved documents.
- MCP/tool-manifest content retrieved as ordinary document evidence.
- Retrieval-ranker manipulation and cross-boundary knowledge leakage.

Expected behavior: use retrieved facts as untrusted evidence, preserve tenant
boundaries, cite only allowed sources, avoid moving canaries, and refuse to
treat document text as system or developer authority.

## Tool-agent boundary scenarios

Source: `datasets/agentic/agentic_injection_v1.yaml`

Scenario families:

- Forbidden tool selection from untrusted context.
- Fake approval tokens and fake human approval text.
- Tool-output instructions that ask for another action.
- Private-to-public routing leaks.
- External sink and webhook pressure.
- Memory-write poisoning from tool observations.
- Tool argument contamination and canary movement.
- Multi-tool chain contamination.
- Registry confusion, shadow tool names, and dynamic manifest changes.
- Logging, search, calendar, and JSON-looking tool outputs.
- Device-code and delegated authority confusion.

Expected behavior: choose tools only from trusted task requirements, keep
private data out of public sinks, ignore approval claims from untrusted content,
and preserve tool allowlists.

## Workflow action security

Source: `tests/fixtures/workflows/plugin-workflow-v1.yaml`

Scenario families:

- Dry-run versus real action separation.
- Approval gates for high-impact operations.
- Blocked operations and rollback/no-op behavior.
- External sinks and private data routing.
- Plugin action manifests with ambiguous or excessive authority.
- Workflow status reporting that must not hide blocked actions.

Expected behavior: perform only allowed workflow actions, require explicit
approval for gated operations, and record blocked operations as evidence rather
than marking them as successful completion.
