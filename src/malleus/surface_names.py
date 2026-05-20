from __future__ import annotations

PUBLIC_SURFACE_NAMES: dict[str, str] = {
    "smoke-v1": "Smoke benchmark",
    "core-v1": "Core text security benchmark",
    "rag-v1": "RAG retrieval and citation security",
    "agentic-injection-v1": "Tool-agent injection and authorization security",
    "artifact-hidden-channel-v1": "Hidden-channel and artifact-injection security",
    "visual-ocr-matrix": "Visual and OCR prompt-injection security",
    "code-agent-v1": "Code-agent sandbox and workspace security",
    "plugin-workflow-v1": "Plugin workflow approval and action security",
    "memory-agent-v1": "Memory poisoning and cross-user leakage",
    "multi-agent-v1": "Multi-agent handoff and delegation security",
    "ui-browser-v1": "Browser and UI action security",
    "campaign-v1": "Multi-step adversarial campaign security",
    "self-modification-v1": "Self-modification and policy-tampering security",
    "challenge-v1": "Deterministic agent safety challenges",
    "calibration-v1": "Calibration and control behavior checks",
}

PUBLIC_PROFILE_NAMES: dict[str, str] = {
    "selected-v1": "Selected mutation robustness profile",
    "deep-v1": "Deep mutation robustness profile",
}


def public_surface_name(identifier: str) -> str:
    key = _public_key(identifier)
    if key in PUBLIC_SURFACE_NAMES:
        return PUBLIC_SURFACE_NAMES[key]
    if key in PUBLIC_PROFILE_NAMES:
        return PUBLIC_PROFILE_NAMES[key]
    if ":" in str(identifier or ""):
        return str(identifier)
    return _humanize_key(key)


def public_profile_name(identifier: str, fallback: str = "") -> str:
    key = _public_key(identifier)
    if key in PUBLIC_PROFILE_NAMES:
        return PUBLIC_PROFILE_NAMES[key]
    return fallback.strip() or _humanize_key(key)


def _public_key(identifier: str) -> str:
    value = str(identifier or "").strip()
    if value.startswith("pack:") or value.startswith("mutation-profile:"):
        value = value.split(":", 1)[1]
    return value


def _humanize_key(identifier: str) -> str:
    value = identifier[:-3] if identifier.endswith("-v1") else identifier
    return value.replace("-", " ").replace("_", " ").title()
