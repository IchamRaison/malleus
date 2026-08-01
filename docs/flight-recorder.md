# Malleus Flight Recorder

The Flight Recorder converts model, RAG, tool, approval, memory, handoff,
browser, workspace, command, and network observations into one causal event
contract. It is designed for evidence-backed security investigation rather
than prompt-only scanning.

## Workflow

```bash
malleus flight capture trace.jsonl --out recording.json
malleus flight investigate recording.json --out attack-graph.json
malleus flight replay recording.json --violation <id> --out replay.json
malleus flight regression-generate recording.json --out regressions.yaml
malleus flight gate --baseline before.json --candidate after.json
```

`capture` accepts Malleus agent traces, generic JSON/JSONL events, and
OpenTelemetry-shaped span records. Events without explicit parents are linked
to the previous event in the same trace. Explicit parent identifiers always
take precedence.

## Invariants

Invariants are deterministic policy checks. The initial contract supports:

- forbidden event types;
- explicit approval requirements;
- forbidden causal transitions;
- cross-tenant data isolation.

Every violation identifies the exact event and its minimal causal ancestry.
Malleus does not treat an LLM judge opinion as a confirmed authorization
violation.

## Signed evidence

```bash
export MALLEUS_SIGNING_KEY='<secret from the CI secret store>'
malleus flight sign reports/run --key-id release-ci
malleus flight verify reports/run --manifest reports/run/signed-manifest.json
```

The v1 signature uses HMAC-SHA256. The key must remain outside the evidence
directory. A future asymmetric signature format can be added as a new schema
version without changing existing manifests.

## Organization history

Recordings can be retained in the local SQLite control plane or submitted to
the equivalent Studio API endpoints. The store keeps the complete canonical
recording and exposes project trends without requiring provider credentials.
