# Limitations

Malleus assessment mode is evidence-first, but evidence has boundaries. Read every report in the context of its target config, profile, packs, mode, evidence strength, scoring policy, and date.

## Not a complete safety proof

Malleus does not prove global safety. A passing result means the selected checks, under the selected configuration and scoring policy, did not produce blocking findings. It does not certify behavior for other prompts, users, tools, retrieval corpora, providers, versions, or deployments.

## Current assessment provider boundary

The current assessment workflow is provider-free. `live_provider` assessment mode is fail-closed scaffold behavior, so it does not collect live endpoint evidence. Non-assessment commands may still have separate provider-backed behavior documented elsewhere.

## Deterministic and local evidence limits

Deterministic checks can miss semantic failures. Local fixture, static, simulated, and planning-only evidence can help with repeatability, CI, and product review, but they are not the same as live model behavior. Treat them as narrower evidence modes.

## Coverage limits

Coverage confidence can drop when relevant packs are not tested, need fixtures, need configuration, or require a future live-provider path. That is intentional. Missing evidence should appear as a gap, not as a pass.

## Provider and model drift

For workflows outside current assessment mode that call providers, behavior can change because model weights, safety settings, routing, provider policies, prompts, and decoding parameters may change over time. Store target metadata and rerun important checks before relying on old results.

## Reporting limits

Public assessment artifacts avoid raw prompt and response dumps. That protects safety and privacy, but it also means an analyst may need access to private internal evidence or fixture sources to fully reproduce a specific claim.
