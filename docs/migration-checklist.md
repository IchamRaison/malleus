# Migration checklist for live-first features

Use this checklist before changing Malleus commands, docs, reports, target schemas, or evidence logic. It helps move the repo toward the live-first product direction without deleting useful provider-free support.

## 1. Classify the feature claim

Before implementation, write the claim in one sentence.

Examples of claims that require real execution:

1. Malleus tests a live OpenAI-compatible chat model.
2. Malleus tests a live RAG service.
3. Malleus tests a live tool agent.
4. Malleus tests a workflow harness.
5. Malleus tests a code agent.

If the claim says live, real, endpoint, service, workflow, agent, or code agent, it needs matching target execution. If the feature only plans, scans, simulates, or reviews fixtures, label it that way.

## 2. Choose the target type

Map the feature to the target type that can produce valid evidence.

| Feature surface | Target type | Required evidence |
|---|---|---|
| Chat or multimodal model | `chat_completion` | Completed provider responses from the configured model endpoint |
| Retrieval service | `rag_service` | Answer plus retrieval, citation, or context trace |
| Tool-using agent | `tool_agent` | Tool, policy, action, or refusal trace |
| Workflow harness | `workflow_harness` | Observable dry-run or sandbox workflow trace |
| Code agent | `code_agent` | Sandboxed execution against disposable code with commands, traces, and file effects |

Do not satisfy a target type with weaker evidence. A chat response is not a RAG service trace. A mock tool call is not a live tool-agent trace. A static transcript is not a code-agent run.

## 3. Preserve provider-free support

Keep provider-free, dry-run, fixture, simulated, scaffold, and static paths where they help. They are useful for CI, planning, regression tests, scoring tests, report tests, and safety checks.

For each support path, verify that:

1. The command output labels it clearly.
2. The report records evidence strength accurately.
3. It cannot inflate live evidence counts.
4. It cannot mark a live feature as complete by itself.
5. It explains what real target configuration would be needed.

Do not remove provider-free concepts just to make the product sound live. Make the boundary clear instead.

## 4. Add or update the live path

For a live path, verify that the implementation:

1. Requires an explicit target config or managed target name.
2. Accepts OpenAI-compatible model endpoints for `chat_completion` where applicable.
3. Uses environment variable references or ignored local config for credentials.
4. Requires explicit operator intent before network calls or quota use.
5. Executes the target surface that matches the feature claim.
6. Records provider, target, model, command, matrix, pack, profile, mutation, and scoring metadata.
7. Redacts or hashes sensitive content in public artifacts.
8. Separates completed evidence from provider errors, target errors, skips, and capability gaps.

## 5. Special checklist for code-agent tests

A code-agent feature is not real until it runs a sandboxed code-agent workflow against disposable code.

Verify that it has:

1. A disposable workspace or temporary repository.
2. A configured agent command, subprocess, or endpoint.
3. Guardrails for paths, credentials, network, and destructive commands.
4. Observable command traces, file changes, diffs, test output, or structured events.
5. Clear cleanup or containment behavior.
6. Report artifacts that prove execution happened without exposing secrets.
7. Negative handling for target errors, timeouts, sandbox denial, and unsupported capability.

If the feature only inspects a stored transcript or generates a plan, label it static analysis or planning-only.

## 6. Update reports and scoring safely

Reports and scoring must not reward missing live evidence.

Check that:

1. Evidence strength is visible in JSON and human-readable reports.
2. Primary scores ignore planning-only, scaffold, unsupported, skipped, and error rows unless the scoring policy explicitly treats them as coverage gaps.
3. Provider errors are reported as operational outcomes, not model behavior findings.
4. Capability gaps reduce or qualify coverage, not model safety.
5. The report says what would be needed for a stronger claim.

## 7. Update docs honestly

When docs change, use wording that matches the implementation.

Acceptable wording:

1. Provider-free planning run.
2. Scaffold-only artifact.
3. Static trace review.
4. Fails closed until a live target is implemented.
5. Live model evidence from completed provider responses.
6. Live code-agent evidence from sandboxed execution against disposable code.

Avoid wording that implies a support path is real evidence. Do not say a command tests a live service if it only reads fixtures. Do not say a code-agent test ran if Malleus only generated text about a hypothetical run.

## 8. Verification before marking done

Before calling a migration complete, confirm:

1. The real execution path exists for the advertised claim.
2. Provider-free support still works and is labeled correctly.
3. Reports distinguish live evidence, support evidence, gaps, skips, and errors.
4. Target-type mismatches are reported as gaps or config errors.
5. No fake API keys or secret-like values were added to docs, fixtures, or reports.
6. The docs avoid claiming that current scaffold or fail-closed behavior is already live.
7. The feature has local tests or fake target tests that do not require real credentials.
8. Any optional real-provider validation is documented as operator-run, not required CI.

## 9. Definition of done

The migration is done when a future engineer can read the docs, run the safe provider-free checks, optionally run a live target with their own credentials, and understand exactly which evidence supports which claim.

If the product claim still depends on dry-run, fixture, scaffold, simulated, static, or planning-only output, the migration is not done. Ship it under the weaker label until real evidence exists.
