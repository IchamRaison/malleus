from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

REDACTION_MARKER = "[REDACTED]"
REDACTION_HASH_FIELD = "sha256="
REDACTION_LENGTH_FIELD = "length="

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<!SYNTHETIC-)(?<!FAKE-)\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(
        r"\b(?:api[_ -]?key|secret|token|password|credential|bearer)\s*[:=]\s*[^\s`|<>]+",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+[^\s`|<>]+",
        re.IGNORECASE,
    ),
    re.compile(r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}\b", re.IGNORECASE),
    re.compile(r"\bbasic\s+[A-Za-z0-9._~+/=-]{8,}\b", re.IGNORECASE),
)
_ABSOLUTE_PRIVATE_PATH_RE = re.compile(
    r"(?:"
    r"/home/[^\s`|<>\]\)]+"
    r"|/Users/[^\s`|<>\]\)]+"
    r"|/root/[^\s`|<>\]\)]+"
    r"|[A-Za-z]:[/\\]Users[/\\][^\s`|<>\]\)]+"
    r"|\\\\[A-Za-z0-9_.-]+[/\\][A-Za-z0-9_.-]+(?:[/\\][^\s`|<>\]\)]+)*"
    r")"
)
_SYNTHETIC_CANARY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bWOWPPSECRET\b"),
    re.compile(r"\bMALLEUS-CANARY-[A-Za-z0-9_-]+\b"),
    re.compile(r"\bWOWPP-CANARY-[A-Za-z0-9_-]+\b"),
    re.compile(r"\bSYNTHETIC-SK-[A-Za-z0-9_-]+\b"),
    re.compile(r"\bRAG-CANARY-[A-Za-z0-9_-]+\b", re.IGNORECASE),
    re.compile(r"\bRAG-SECRET-[A-Za-z0-9_-]+\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class RedactionResult:
    text: str
    sha256: str
    length: int
    redacted: bool
    matched_labels: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PublicArtifactScanResult:
    passed: bool
    findings: list[str] = field(default_factory=list)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def redaction_label(value: str, *, kind: str = "sensitive") -> str:
    return f"{REDACTION_MARKER} {kind} sha256={sha256_text(value)[:16]} length={len(value)}"


def redact(text: str) -> str:
    return redact_public_text(text).text


def redact_public_text(text: str, *, limit: int | None = None) -> RedactionResult:
    original = str(text)
    redacted = original
    labels: list[str] = []

    for pattern in _SECRET_PATTERNS:
        def replace_secret(match: re.Match[str]) -> str:
            labels.append("secret")
            return redaction_label(match.group(0), kind="sensitive")

        redacted = pattern.sub(replace_secret, redacted)

    for pattern in _SYNTHETIC_CANARY_PATTERNS:
        def replace_canary(match: re.Match[str]) -> str:
            labels.append("synthetic_canary")
            return redaction_label(match.group(0), kind="synthetic_canary")

        redacted = pattern.sub(replace_canary, redacted)

    def replace_path(match: re.Match[str]) -> str:
        labels.append("private_path")
        return redaction_label(match.group(0), kind="private_path")

    redacted = _ABSOLUTE_PRIVATE_PATH_RE.sub(replace_path, redacted)
    if limit is not None and len(redacted) > limit:
        redacted = redacted[:limit] + "…"
    return RedactionResult(
        text=redacted,
        sha256=sha256_text(original),
        length=len(original),
        redacted=bool(labels),
        matched_labels=labels,
    )


def redacted_preview(text: str, *, limit: int = 240) -> str:
    result = redact_public_text(text, limit=limit)
    if result.redacted:
        return result.text
    collapsed = re.sub(r"\s+", " ", str(text)).strip()
    return collapsed[:limit] + ("…" if len(collapsed) > limit else "")


def _has_complete_redaction_metadata(text: str) -> bool:
    return REDACTION_MARKER in text and REDACTION_HASH_FIELD in text and REDACTION_LENGTH_FIELD in text


def scan_public_artifact_text(text: str, *, require_redaction_markers: bool = False) -> PublicArtifactScanResult:
    candidate = str(text)
    findings: list[str] = []
    has_complete_markers = _has_complete_redaction_metadata(candidate)

    for pattern in _SECRET_PATTERNS:
        if pattern.search(candidate):
            findings.append("raw_secret_pattern")
    if any(pattern.search(candidate) for pattern in _SYNTHETIC_CANARY_PATTERNS) and not has_complete_markers:
        findings.append("raw_synthetic_canary")
    if _ABSOLUTE_PRIVATE_PATH_RE.search(candidate):
        findings.append("absolute_private_path")
    if (require_redaction_markers or REDACTION_MARKER in candidate) and REDACTION_MARKER in candidate:
        if not has_complete_markers:
            findings.append("incomplete_redaction_marker")
    return PublicArtifactScanResult(passed=not findings, findings=sorted(set(findings)))
