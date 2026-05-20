# Security model

Malleus assessment mode treats model inputs, retrieved context, artifacts, tool outputs, report bodies, and fixture content as untrusted. Public artifacts are designed to preserve evidence traceability without publishing unsafe raw content.

## What assessment mode executes

Current assessment orchestration writes local files, reads local target configuration, resolves profiles and packs, computes score and coverage metadata, and produces report artifacts. It does not call providers, reach the network, operate browsers, take screenshots, or open remote issue-tracker tickets.

Live benchmark commands are separate from assessment mode. Commands such as `malleus benchmark live-browser-agent` a local/staging URL allowlist through the target config, and a compatible `browser_agent` endpoint. When the optional Playwright backend is installed, browser-agent runs capture redacted page-capture JSON plus screenshot artifacts; without Playwright they fall back to DOM-only evidence and record the screenshot capability gap.

`malleus assess --mode live_provider` is fail-closed scaffold behavior in this implementation. It records the disabled state and exits nonzero instead of contacting a provider.

## Artifact handling

Assessment public artifacts use relative paths, hashes, lengths, pack IDs, evidence IDs, mode labels, evidence-strength labels, score-use explanations, and redacted previews. Raw prompt bodies, raw response bodies, authorization token values, private paths, and secret-like values are not intended to appear in public assessment outputs.

Static HTML outputs are local files. They should not depend on external fonts, CDNs, remote scripts, iframes, event-handler attributes, or network calls.

## Untrusted content boundaries

RAG, artifact, visual, plugin, tool, code-agent, and UI-harness surfaces are treated as potentially hostile. Local fixture and static analysis evidence can show that these surfaces are represented and inspected, but it does not prove live endpoint behavior.

## Scaffold boundaries

Scaffold packs document planned integration shape or missing evidence. Scaffold and planning-only evidence can produce findings or coverage gaps, but it cannot count as a primary model strength. This protects score integrity when a report includes broad attack-surface planning.

## Credential hygiene

Keep credentials in environment variables or ignored local files. Safe environment variable names such as `NVIDIA_API_KEY` may appear in docs, but real values must not. If a key appears in a report, issue export, screenshot, or committed file, rotate it and remove the artifact.
