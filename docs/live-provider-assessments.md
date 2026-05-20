# Live-provider assessments

`malleus assess --mode live_provider` is fail-closed scaffold behavior in this implementation. It writes assessment artifacts that explain the blocked state, keeps provider and network calls disabled, and exits nonzero. It does not instantiate adapters and does not collect provider response evidence.

This boundary applies to the assessment workflow. Non-assessment commands can retain their existing documented behavior. For example, `malleus run`, `malleus compare`, and `python scripts/run_wow_benchmark.py` may call configured providers when used outside assessment mode.

## Live benchmark target types

Live benchmark commands separate chat model evidence from real system trace evidence:

- `chat_completion` targets are legacy chat or multimodal model endpoints. They can support live model behavior findings only after completed provider responses.
- Deterministic agent safety challenges (`challenge-v1`) and Calibration and control behavior checks (`calibration-v1`) are canonical live `chat_completion` surfaces. They make real provider/model calls through live runners, score deterministically, and write redacted artifacts.
- Visual and OCR prompt-injection security (`visual-ocr-matrix`) is canonical live multimodal/vision evidence. If the target does not support image input, the live row is recorded as `provider_capability_gap`, not as generic chat-text evidence.
- `rag_service` targets run retrieval-service endpoints and require observable retrieval/citation traces. Fixture/model-only RAG is not real system live evidence.
- `tool_agent` targets run real agent endpoints and require observable tool-call traces. Mock agent lab tools are not real system live evidence.
- `workflow_harness` targets run dry-run workflow endpoints and require observable action traces. Static plugin scanning is not real system live evidence.
- `code_agent` targets run sandboxed code-agent subprocesses against disposable workspaces. Static code-agent trace inspection is not real system live evidence.

Run one real system surface with `malleus benchmark live-rag`, `malleus benchmark live-agentic`, `malleus benchmark live-workflow`, `malleus benchmark live-code-agent`, or `malleus benchmark live-self-modification`. Use `malleus benchmark soft` for the default serious live wrapper, or `malleus benchmark exterminatus` for the exhaustive wrapper with the optional deep mutation profile. `exterminatus` is exhaustive over implemented/canonical Malleus surfaces and configured mutation profiles, not exhaustive over universal AI security. Capability gaps, target configuration errors, target errors, operator skips, and checkpoint rows are operational/coverage outcomes; they are not deterministic model behavior failures.

## Current command shape

```bash
malleus assess \
  --target examples/targets/openai.yaml \
  --profile chatbot \
  --packs core \
  --mode live_provider \
  --out-dir reports/live-assessment \
  --allow-live-provider
```

The command still fails closed in assessment mode. Artifacts record `provider_calls_enabled: false`, `network_enabled: false`, and live-provider caveats. Evidence is planning-only or a live-provider requirement gap, not live model behavior.

## Provider setup for non-assessment commands

Provider credentials are read from environment variables or an ignored local `.env` file by existing non-assessment adapter paths. Keep real credentials out of committed docs, fixtures, reports, shell history, and screenshots.

Safe variable names include:

```text
NVIDIA_API_KEY
NVIDIA_BASE_URL
```

Do not paste real token values into target configs or public artifacts. Use local environment variables and rotate any key that was exposed.

## Optional real-service validation

Real-service validation is an operator-run activity, not a CI requirement. The regression suite uses fake HTTP services, fake subprocess agents, temporary repositories, and environment-variable fixtures so tests do not need real providers, credentials, Docker, browser automation, or destructive host execution.

To validate a real system intentionally, create a local, uncommitted target config with the matching `target_type` (`rag_service`, `tool_agent`, `workflow_harness`, or `code_agent`), point credentials at environment variable names, and run only the relevant surface command, for example `malleus benchmark live-rag --target local-rag.yaml --matrix datasets/release_matrices/malleus-v0.1.yaml --out-dir reports/live-rag`. Self-modification live evidence is intentionally routed only through compatible `tool_agent`, `workflow_harness`, or `code_agent` targets. Use disposable workspaces for `code_agent`, dry-run/sandbox endpoints for `workflow_harness`, and review generated reports for `target_capability_gap`, `target_config_error`, or `target_error` before treating any trace as evidence.

## Cost and quota controls

For assessment mode, current cost is local artifact generation because provider calls are disabled. For non-assessment commands that can call providers, start with dry runs, small smoke packs, `--limit`, and explicit target configs. Review provider pricing and quotas before running larger panels.

## Caveats

The current assessment `live_provider` mode is a scaffold for future live evidence. Treat any `live_provider` assessment artifact from this implementation as a fail-closed planning record. It can help document intent and missing evidence, but it cannot support a claim that a live model passed or failed a test.

UI scaffold artifacts remain planning evidence only. Browser/UI live evidence is available through the separate `browser_agent` target route; with the optional Playwright backend installed it records page-capture JSON, screenshots, and browser trace metadata.
