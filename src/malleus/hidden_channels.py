from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import math
import quopri
import re
import unicodedata
from collections import Counter
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Literal
from urllib.parse import unquote_plus

from pydantic import BaseModel, Field

HiddenSeverity = Literal["low", "medium", "high", "critical"]
HighestSeverity = Literal["none", "low", "medium", "high", "critical"]
GateRecommendation = Literal["allow", "warn", "quarantine", "block"]
HiddenKind = Literal[
    "zero_width",
    "bidi_control",
    "unicode_tag",
    "html_comment",
    "base64_block",
    "hex_block",
    "binary_block",
    "quoted_printable_block",
    "data_uri",
    "variation_selector",
    "confusable_text",
    "markdown_link_title",
]

_SEVERITY_ORDER: dict[HighestSeverity, int] = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_ZERO_WIDTH = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    "\u2060": "WORD JOINER",
}
_BIDI_CONTROLS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}
_HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_DATA_URI_RE = re.compile(r"\bdata:(?P<mime>[-\w.+/]+)?(?:;charset=[-\w.]+)?(?P<base64>;base64)?,(?P<body>[A-Za-z0-9+/=%_.!~*'() -]{12,4096})", re.IGNORECASE)
_MARKDOWN_LINK_TITLE_RE = re.compile(r"!?\[[^\]\n]{1,200}\]\([^\)\n]*?[ \t]+([\"'])(?P<title>.*?)(?<!\\)\1\)")
_INSTRUCTIONISH_RE = re.compile(
    r"\b(system|developer|instruction|ignore|override|secret|token|password|api[_ -]?key|prompt)\b",
    re.IGNORECASE,
)
_PRINTABLE_RE = re.compile(r"^[\x09\x0a\x0d\x20-\x7e]+$")
_TOKEN_RE = re.compile(r"\S+")
_SECRETISH_RE = re.compile(
    r"\b(?:api[_ -]?key|token|password|secret|credential|bearer|sk-[A-Za-z0-9_-]{10,})\b|[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}",
    re.IGNORECASE,
)
_TOOL_ACTION_RE = re.compile(
    r"\b(?:call|invoke|execute|run|use|select)\s+(?:tool|function|api|exfiltrate|delete|write|curl|bash|shell)|\b[a-z_]+\([^\)]{0,120}\)",
    re.IGNORECASE,
)
_CANARY_RE = re.compile(r"\b(?:MALLEUS-CANARY-[A-Za-z0-9_-]+|canary[_:-]?[A-Za-z0-9_-]*)\b", re.IGNORECASE)
_HEX_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{16,})(?![A-Fa-f0-9])")
_BINARY_RE = re.compile(r"(?<![01])(?:[01]{8}(?:\s+[01]{8}){1,}|[01]{32,})(?![01])")
_QUOTED_PRINTABLE_RE = re.compile(r"(?:=[0-9A-Fa-f]{2}|=\r?\n|=[ \t]*\r?\n){3,}")
_UNSAFE_PREVIEW_RE = re.compile(r"(?i)(api[_ -]?key|token|password|secret|bearer)\s*[:=]\s*[^\s`|<>]+")
_CONFUSABLES = str.maketrans(
    {
        "Α": "A",
        "А": "A",
        "Β": "B",
        "В": "B",
        "Ε": "E",
        "Е": "E",
        "Η": "H",
        "Н": "H",
        "Ι": "I",
        "І": "I",
        "Κ": "K",
        "К": "K",
        "Μ": "M",
        "М": "M",
        "Ν": "N",
        "О": "O",
        "Ρ": "P",
        "Р": "P",
        "Τ": "T",
        "Т": "T",
        "Χ": "X",
        "Х": "X",
        "Υ": "Y",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "０": "0",
        "１": "1",
        "２": "2",
        "３": "3",
        "４": "4",
        "５": "5",
        "６": "6",
        "７": "7",
        "８": "8",
        "９": "9",
    }
)
_VARIATION_SELECTOR_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))
_CONFUSABLE_RE = re.compile(r"[ΑАΒВΕЕΗНΙІΚКΜМΝОΡРΤТΧХΥаеорсуіх０-９]")


class _PlainTextHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def get_text(self) -> str:
        return " ".join(part.strip() for part in self.parts if part.strip())


class HiddenChannelFinding(BaseModel):
    kind: HiddenKind
    severity: HiddenSeverity
    description: str
    start: int
    end: int
    text: str
    codepoints: list[str] = Field(default_factory=list)
    decoded_preview: str | None = None


class HiddenChannelSummary(BaseModel):
    total_findings: int
    highest_severity: HighestSeverity
    counts_by_kind: dict[str, int] = Field(default_factory=dict)


class TextStatistics(BaseModel):
    length: int
    codepoints: int
    bytes_utf8: int
    tokens_approx: int
    lines: int
    unique_codepoints: int
    combining_marks: int
    control_characters: int
    invisible_characters: int
    bidi_controls: int
    grapheme_clusters_approx: int
    entropy: float
    printable_ratio: float


class CanonicalView(BaseModel):
    name: str
    description: str
    sha256: str
    length: int
    changed: bool
    redacted_preview: str


class DecodeGraphNode(BaseModel):
    id: str
    depth: int
    transform: str
    sha256: str
    length: int
    entropy: float
    printable_ratio: float
    instruction_like_score: float
    secret_like_score: float
    tool_action_like_score: float
    canary_matches: list[str] = Field(default_factory=list)
    redacted_preview: str


class DecodeGraphEdge(BaseModel):
    source: str
    target: str
    transform: str


class DecodeGraph(BaseModel):
    max_depth: int
    candidate_limit: int
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)
    nodes: list[DecodeGraphNode] = Field(default_factory=list)
    edges: list[DecodeGraphEdge] = Field(default_factory=list)


class DeepInspection(BaseModel):
    canonical_views: list[CanonicalView] = Field(default_factory=list)
    statistics: TextStatistics
    decode_graph: DecodeGraph
    gate_recommendation: GateRecommendation
    gate_reasons: list[str] = Field(default_factory=list)


class HiddenChannelReport(BaseModel):
    inspected_at: str
    source: str
    length: int
    findings: list[HiddenChannelFinding] = Field(default_factory=list)
    summary: HiddenChannelSummary
    deep: DeepInspection | None = None
    gate_recommendation: GateRecommendation | None = None


def _codepoint(char: str) -> str:
    return f"U+{ord(char):04X}"


def _highest(findings: list[HiddenChannelFinding]) -> HighestSeverity:
    highest: HighestSeverity = "none"
    for finding in findings:
        if _SEVERITY_ORDER[finding.severity] > _SEVERITY_ORDER[highest]:
            highest = finding.severity
    return highest


def _instructionish(text: str) -> bool:
    return bool(_INSTRUCTIONISH_RE.search(text))


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return round(-sum((count / length) * math.log2(count / length) for count in counts.values()), 4)


def _printable_ratio(text: str) -> float:
    if not text:
        return 1.0
    printable = sum(1 for char in text if char in "\t\n\r" or 32 <= ord(char) <= 126)
    return round(printable / len(text), 4)


def _score(pattern: re.Pattern[str], text: str) -> float:
    matches = len(pattern.findall(text))
    return round(min(1.0, matches / 3), 4)


def _canary_matches(text: str) -> list[str]:
    return sorted({_redact_preview(match.group(0), limit=80) for match in _CANARY_RE.finditer(text)})


def _redact_preview(text: str, *, limit: int = 160) -> str:
    if _instructionish(text) or _SECRETISH_RE.search(text) or _TOOL_ACTION_RE.search(text) or _UNSAFE_PREVIEW_RE.search(text) or "```" in text or re.search(r"(?m)^\s{0,3}#", text):
        return f"[REDACTED potentially unsafe text sha256={_sha256_text(text)[:16]} length={len(text)}]"
    preview = text[:limit]
    preview = _UNSAFE_PREVIEW_RE.sub(r"\1=[REDACTED]", preview)
    if len(text) > limit:
        preview += "…"
    return preview


def _redacted_finding_text(text: str) -> str:
    return f"[REDACTED inspected finding text sha256={_sha256_text(text)[:16]} length={len(text)}]"


def _public_report_dump(report: HiddenChannelReport) -> dict[str, object]:
    payload = report.model_dump(mode="json")
    findings = payload.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            raw_text = finding.get("text")
            if not isinstance(raw_text, str):
                continue
            finding["text_sha256"] = _sha256_text(raw_text)
            finding["text_length"] = len(raw_text)
            finding["redacted_text_preview"] = _redacted_finding_text(raw_text)
            finding["text"] = _redacted_finding_text(raw_text)
    return payload


def _statistics(text: str) -> TextStatistics:
    grapheme_clusters = 0
    for char in text:
        if not unicodedata.combining(char):
            grapheme_clusters += 1
    return TextStatistics(
        length=len(text),
        codepoints=len(text),
        bytes_utf8=len(text.encode("utf-8", errors="replace")),
        tokens_approx=len(_TOKEN_RE.findall(text)),
        lines=text.count("\n") + (1 if text else 0),
        unique_codepoints=len(set(text)),
        combining_marks=sum(1 for char in text if unicodedata.combining(char)),
        control_characters=sum(1 for char in text if unicodedata.category(char).startswith("C")),
        invisible_characters=sum(1 for char in text if char in _ZERO_WIDTH or 0xE0000 <= ord(char) <= 0xE007F),
        bidi_controls=sum(1 for char in text if char in _BIDI_CONTROLS),
        grapheme_clusters_approx=grapheme_clusters,
        entropy=_entropy(text),
        printable_ratio=_printable_ratio(text),
    )


def _node(node_id: str, text: str, *, depth: int, transform: str) -> DecodeGraphNode:
    return DecodeGraphNode(
        id=node_id,
        depth=depth,
        transform=transform,
        sha256=_sha256_text(text),
        length=len(text),
        entropy=_entropy(text),
        printable_ratio=_printable_ratio(text),
        instruction_like_score=_score(_INSTRUCTIONISH_RE, text),
        secret_like_score=_score(_SECRETISH_RE, text),
        tool_action_like_score=_score(_TOOL_ACTION_RE, text),
        canary_matches=_canary_matches(text),
        redacted_preview=_redact_preview(text),
    )


def _strip_invisibles(text: str) -> str:
    return "".join(char for char in text if char not in _ZERO_WIDTH and not (0xE0000 <= ord(char) <= 0xE007F))


def _strip_bidi(text: str) -> str:
    return "".join(char for char in text if char not in _BIDI_CONTROLS)


def _markdown_plain(text: str) -> str:
    text = _HTML_COMMENT_RE.sub(" ", text)
    text = re.sub(r"!?\[([^\]\n]{0,200})\]\([^\)\n]*\)", r"\1", text)
    text = re.sub(r"[`*_>#~-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _html_plain(text: str) -> str:
    parser = _PlainTextHTMLParser()
    parser.feed(text)
    plain = parser.get_text()
    return plain if plain else _HTML_COMMENT_RE.sub(" ", re.sub(r"<[^>]+>", " ", text)).strip()


def _canonical_views(text: str) -> list[CanonicalView]:
    candidates = [
        ("raw", "Original text as inspected", text),
        ("nfkc", "Unicode NFKC normalized text", unicodedata.normalize("NFKC", text)),
        ("invisibles_stripped", "Zero-width and Unicode tag characters removed", _strip_invisibles(text)),
        ("bidi_removed", "Bidirectional control characters removed", _strip_bidi(text)),
        ("confusable_skeleton", "Stdlib-safe approximation for common confusables", unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)),
        ("markdown_plain", "Approximate Markdown plain-text view", _markdown_plain(text)),
        ("html_plain", "Approximate HTML plain-text view", _html_plain(text)),
        ("url_html_decoded", "URL percent-decoded and HTML-entity-decoded text", html.unescape(unquote_plus(text))),
    ]
    return [
        CanonicalView(
            name=name,
            description=description,
            sha256=_sha256_text(value),
            length=len(value),
            changed=value != text,
            redacted_preview=_redact_preview(value),
        )
        for name, description, value in candidates
    ]


def _decode_base64_token(token: str) -> str | None:
    padded = token + "=" * ((4 - len(token) % 4) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        value = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not value or _printable_ratio(value) < 0.85:
        return None
    return value


def _decode_hex_token(token: str) -> str | None:
    if len(token) % 2:
        return None
    try:
        value = bytes.fromhex(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if not value or _printable_ratio(value) < 0.85:
        return None
    return value


def _decode_binary_token(token: str) -> str | None:
    compact = re.sub(r"\s+", "", token)
    if len(compact) % 8:
        return None
    try:
        value = bytes(int(compact[index : index + 8], 2) for index in range(0, len(compact), 8)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if not value or _printable_ratio(value) < 0.85:
        return None
    return value


def _decode_quoted_printable_token(token: str) -> str | None:
    try:
        value = quopri.decodestring(token).decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not value or value == token or _printable_ratio(value) < 0.85:
        return None
    return value


def _is_variation_selector(char: str) -> bool:
    codepoint = ord(char)
    return any(start <= codepoint <= end for start, end in _VARIATION_SELECTOR_RANGES)


def _decode_data_uri(match: re.Match[str]) -> str | None:
    body = match.group("body")
    if match.group("base64"):
        return _decode_base64_token(body)
    try:
        value = unquote_plus(body)
    except ValueError:
        return None
    if not value or _printable_ratio(value) < 0.85:
        return None
    return value


def _candidate_decodes(text: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    transforms = [
        ("nfkc", unicodedata.normalize("NFKC", text)),
        ("strip_invisibles", _strip_invisibles(text)),
        ("remove_bidi", _strip_bidi(text)),
        ("html_unescape", html.unescape(text)),
        ("url_decode", unquote_plus(text)),
        ("markdown_plain", _markdown_plain(text)),
        ("html_plain", _html_plain(text)),
    ]
    candidates.extend((name, value) for name, value in transforms if value and value != text)
    for match in _BASE64_RE.finditer(text):
        decoded = _decode_base64_token(match.group(0))
        if decoded and decoded != text:
            candidates.append(("base64_decode", decoded))
    stripped = text.strip()
    if _BASE64_RE.fullmatch(stripped):
        decoded = _decode_base64_token(stripped)
        if decoded and decoded != text:
            candidates.append(("base64_decode_full", decoded))
    for match in _HEX_RE.finditer(text):
        decoded = _decode_hex_token(match.group(0))
        if decoded and decoded != text:
            candidates.append(("hex_decode", decoded))
    if _HEX_RE.fullmatch(stripped):
        decoded = _decode_hex_token(stripped)
        if decoded and decoded != text:
            candidates.append(("hex_decode_full", decoded))
    for match in _BINARY_RE.finditer(text):
        decoded = _decode_binary_token(match.group(0))
        if decoded and decoded != text:
            candidates.append(("binary_decode", decoded))
    for match in _QUOTED_PRINTABLE_RE.finditer(text):
        decoded = _decode_quoted_printable_token(match.group(0))
        if decoded and decoded != text:
            candidates.append(("quoted_printable_decode", decoded))
    for match in _DATA_URI_RE.finditer(text):
        decoded = _decode_data_uri(match)
        if decoded and decoded != text:
            candidates.append(("data_uri_decode", decoded))
    return candidates


def _decode_graph(text: str, *, max_depth: int = 2, candidate_limit: int = 50) -> DecodeGraph:
    graph = DecodeGraph(max_depth=max_depth, candidate_limit=candidate_limit)
    texts_by_id = {"n0": text}
    seen = {_sha256_text(text): "n0"}
    graph.nodes.append(_node("n0", text, depth=0, transform="raw"))
    frontier = ["n0"]
    next_index = 1
    while frontier:
        source_id = frontier.pop(0)
        source_text = texts_by_id[source_id]
        source_depth = next(node.depth for node in graph.nodes if node.id == source_id)
        if source_depth >= max_depth:
            continue
        for transform, decoded in _candidate_decodes(source_text):
            digest = _sha256_text(decoded)
            if digest in seen:
                graph.edges.append(DecodeGraphEdge(source=source_id, target=seen[digest], transform=transform))
                continue
            if len(graph.nodes) >= candidate_limit:
                graph.truncated = True
                warning = f"candidate limit {candidate_limit} reached; additional decode candidates omitted"
                if warning not in graph.warnings:
                    graph.warnings.append(warning)
                return graph
            node_id = f"n{next_index}"
            next_index += 1
            seen[digest] = node_id
            texts_by_id[node_id] = decoded
            graph.nodes.append(_node(node_id, decoded, depth=source_depth + 1, transform=transform))
            graph.edges.append(DecodeGraphEdge(source=source_id, target=node_id, transform=transform))
            frontier.append(node_id)
    return graph


def _recommendation(findings: list[HiddenChannelFinding], graph: DecodeGraph) -> tuple[GateRecommendation, list[str]]:
    reasons: list[str] = []
    highest = _highest(findings)
    if highest in {"high", "critical"}:
        reasons.append(f"highest finding severity is {highest}")
    suspicious_nodes = [
        node
        for node in graph.nodes
        if node.depth > 0
        and (node.instruction_like_score >= 0.34 or node.secret_like_score >= 0.34 or node.tool_action_like_score >= 0.34 or node.canary_matches)
    ]
    if suspicious_nodes:
        reasons.append("decoded candidate contains instruction-like, secret-like, tool-action-like, or canary content")
    if graph.truncated:
        reasons.append("decode graph was truncated by safety limits")
    if any(node.tool_action_like_score >= 0.34 and node.secret_like_score >= 0.34 for node in graph.nodes):
        return "block", reasons
    if any(node.canary_matches for node in suspicious_nodes):
        return "quarantine", reasons
    if highest in {"high", "critical"} or suspicious_nodes or graph.truncated:
        return "quarantine", reasons
    if highest in {"low", "medium"}:
        return "warn", reasons or ["low-visibility text features detected"]
    return "allow", reasons or ["no hidden-channel findings or suspicious decoded candidates detected"]


def _decoded_base64_text(token: str) -> str | None:
    if len(token) % 4:
        token = token + "=" * (4 - len(token) % 4)
    try:
        decoded = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded or len(decoded) < 8:
        return None
    try:
        preview = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not _PRINTABLE_RE.match(preview):
        return None
    return preview


def _decoded_base64_preview(token: str) -> str | None:
    decoded = _decoded_base64_text(token)
    if decoded is None:
        return None
    return _redact_preview(decoded)


def _inspect_text_shallow(text: str, *, source: str = "inline") -> HiddenChannelReport:
    findings: list[HiddenChannelFinding] = []

    for index, char in enumerate(text):
        if char in _ZERO_WIDTH:
            findings.append(
                HiddenChannelFinding(
                    kind="zero_width",
                    severity="medium",
                    description=f"Invisible formatting character: {_ZERO_WIDTH[char]}",
                    start=index,
                    end=index + 1,
                    text=char,
                    codepoints=[_codepoint(char)],
                )
            )
        elif char in _BIDI_CONTROLS:
            findings.append(
                HiddenChannelFinding(
                    kind="bidi_control",
                    severity="high",
                    description=f"Bidirectional text control: {_BIDI_CONTROLS[char]}",
                    start=index,
                    end=index + 1,
                    text=char,
                    codepoints=[_codepoint(char)],
                )
            )
        elif 0xE0000 <= ord(char) <= 0xE007F:
            findings.append(
                HiddenChannelFinding(
                    kind="unicode_tag",
                    severity="high",
                    description="Unicode tag character can hide machine-readable text from casual review",
                    start=index,
                    end=index + 1,
                    text=char,
                    codepoints=[_codepoint(char)],
                )
            )
        elif _is_variation_selector(char):
            findings.append(
                HiddenChannelFinding(
                    kind="variation_selector",
                    severity="medium",
                    description="Variation selector can be abused as a visually hidden steganographic channel",
                    start=index,
                    end=index + 1,
                    text=char,
                    codepoints=[_codepoint(char)],
                )
            )

    confusable_matches = list(_CONFUSABLE_RE.finditer(text))
    if confusable_matches:
        skeleton = unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)
        if skeleton != text and _instructionish(skeleton):
            severity: HiddenSeverity = "high"
        else:
            severity = "medium" if len(confusable_matches) >= 3 else "low"
        first = confusable_matches[0]
        findings.append(
            HiddenChannelFinding(
                kind="confusable_text",
                severity=severity,
                description="Unicode confusable characters may spoof visible policy, tool, or secret labels",
                start=first.start(),
                end=confusable_matches[-1].end(),
                text=text[first.start() : confusable_matches[-1].end()],
                codepoints=sorted({_codepoint(match.group(0)) for match in confusable_matches}),
                decoded_preview=_redact_preview(skeleton),
            )
        )

    for match in _HTML_COMMENT_RE.finditer(text):
        snippet = match.group(0)
        findings.append(
            HiddenChannelFinding(
                kind="html_comment",
                severity="high" if _instructionish(snippet) else "medium",
                description="HTML comment content is hidden in rendered Markdown/HTML views",
                start=match.start(),
                end=match.end(),
                text=snippet,
            )
        )

    for match in _BASE64_RE.finditer(text):
        token = match.group(0)
        decoded_text = _decoded_base64_text(token)
        if decoded_text is None:
            continue
        findings.append(
            HiddenChannelFinding(
                kind="base64_block",
                severity="high" if _instructionish(decoded_text) else "medium",
                description="Base64-like block decodes to printable text and may hide instructions or secrets",
                start=match.start(),
                end=match.end(),
                text=token,
                decoded_preview=_redact_preview(decoded_text),
            )
        )

    for match in _HEX_RE.finditer(text):
        token = match.group(0)
        decoded_text = _decode_hex_token(token)
        if decoded_text is None:
            continue
        findings.append(
            HiddenChannelFinding(
                kind="hex_block",
                severity="high" if _instructionish(decoded_text) else "medium",
                description="Hex-encoded block decodes to printable text and may hide instructions or secrets",
                start=match.start(),
                end=match.end(),
                text=token,
                decoded_preview=_redact_preview(decoded_text),
            )
        )

    for match in _BINARY_RE.finditer(text):
        token = match.group(0)
        decoded_text = _decode_binary_token(token)
        if decoded_text is None:
            continue
        findings.append(
            HiddenChannelFinding(
                kind="binary_block",
                severity="high" if _instructionish(decoded_text) else "medium",
                description="Binary octet block decodes to printable text and may hide instructions or secrets",
                start=match.start(),
                end=match.end(),
                text=token,
                decoded_preview=_redact_preview(decoded_text),
            )
        )

    for match in _QUOTED_PRINTABLE_RE.finditer(text):
        token = match.group(0)
        decoded_text = _decode_quoted_printable_token(token)
        if decoded_text is None:
            continue
        findings.append(
            HiddenChannelFinding(
                kind="quoted_printable_block",
                severity="high" if _instructionish(decoded_text) else "medium",
                description="Quoted-printable block decodes to printable text and may hide instructions or secrets",
                start=match.start(),
                end=match.end(),
                text=token,
                decoded_preview=_redact_preview(decoded_text),
            )
        )

    for match in _DATA_URI_RE.finditer(text):
        decoded_text = _decode_data_uri(match)
        if decoded_text is None:
            continue
        findings.append(
            HiddenChannelFinding(
                kind="data_uri",
                severity="high" if _instructionish(decoded_text) else "medium",
                description="Data URI embeds inline decoded content that may be hidden in rendered documents",
                start=match.start(),
                end=match.end(),
                text=match.group(0),
                decoded_preview=_redact_preview(decoded_text),
            )
        )

    for match in _MARKDOWN_LINK_TITLE_RE.finditer(text):
        title = match.group("title")
        findings.append(
            HiddenChannelFinding(
                kind="markdown_link_title",
                severity="medium",
                description="Markdown link/image title is not always visible in rendered views",
                start=match.start("title"),
                end=match.end("title"),
                text=title,
            )
        )

    findings.sort(key=lambda finding: (finding.start, finding.end, finding.kind))
    counts = Counter(finding.kind for finding in findings)
    summary = HiddenChannelSummary(
        total_findings=len(findings),
        highest_severity=_highest(findings),
        counts_by_kind=dict(sorted(counts.items())),
    )
    return HiddenChannelReport(
        inspected_at=datetime.now(UTC).isoformat(),
        source=source,
        length=len(text),
        findings=findings,
        summary=summary,
    )


def inspect_text_deep(
    text: str,
    *,
    source: str = "inline",
    max_depth: int = 2,
    candidate_limit: int = 50,
) -> HiddenChannelReport:
    report = _inspect_text_shallow(text, source=source)
    graph = _decode_graph(text, max_depth=max_depth, candidate_limit=candidate_limit)
    gate_recommendation, gate_reasons = _recommendation(report.findings, graph)
    report.deep = DeepInspection(
        canonical_views=_canonical_views(text),
        statistics=_statistics(text),
        decode_graph=graph,
        gate_recommendation=gate_recommendation,
        gate_reasons=gate_reasons,
    )
    report.gate_recommendation = gate_recommendation
    return report


def inspect_text(text: str, *, source: str = "inline") -> HiddenChannelReport:
    return inspect_text_deep(text, source=source)


def _markdown_fence(text: str) -> str:
    runs = [len(match.group(0)) for match in re.finditer(r"`+", text)]
    fence_len = max(3, max(runs, default=0) + 1)
    return "`" * fence_len


def _append_deep_markdown(lines: list[str], report: HiddenChannelReport) -> None:
    if report.deep is None:
        return
    deep = report.deep
    graph = deep.decode_graph
    lines.extend(
        [
            "",
            "## Deep inspection",
            "",
            f"- Gate recommendation: {deep.gate_recommendation}",
            f"- Gate reasons: {'; '.join(deep.gate_reasons)}",
            f"- Approx tokens: {deep.statistics.tokens_approx}",
            f"- Approx grapheme clusters: {deep.statistics.grapheme_clusters_approx}",
            f"- Entropy: {deep.statistics.entropy}",
            f"- Printable ratio: {deep.statistics.printable_ratio}",
            f"- Decode graph nodes: {len(graph.nodes)}",
            f"- Decode graph edges: {len(graph.edges)}",
            f"- Decode graph truncated: {graph.truncated}",
        ]
    )
    if graph.warnings:
        lines.append(f"- Warnings: {'; '.join(graph.warnings)}")
    lines.extend(["", "### Canonical views", ""])
    for view in deep.canonical_views:
        lines.append(f"- `{view.name}` changed={view.changed} length={view.length} sha256={view.sha256[:12]} preview={view.redacted_preview!r}")
    lines.extend(["", "### Decode graph candidates", ""])
    for node in graph.nodes[:12]:
        lines.append(
            f"- `{node.id}` depth={node.depth} via={node.transform} length={node.length} "
            f"scores(i={node.instruction_like_score}, s={node.secret_like_score}, t={node.tool_action_like_score}) "
            f"canaries={len(node.canary_matches)} preview={node.redacted_preview!r}"
        )
    if len(graph.nodes) > 12:
        lines.append(f"- … {len(graph.nodes) - 12} additional nodes omitted from Markdown summary; see JSON for full graph.")


def render_hidden_channel_markdown(report: HiddenChannelReport) -> str:
    lines = [
        "# Malleus Hidden-Channel Inspection",
        "",
        f"- Source: {report.source}",
        f"- Inspected at: {report.inspected_at}",
        f"- Length: {report.length}",
        f"- Findings: {report.summary.total_findings}",
        f"- Highest severity: {report.summary.highest_severity}",
        f"- Gate recommendation: {report.gate_recommendation or 'n/a'}",
        "",
    ]
    if not report.findings:
        lines.append("No hidden-channel findings detected.")
        _append_deep_markdown(lines, report)
        return "\n".join(lines).rstrip() + "\n"

    lines.extend(["## Findings", ""])
    for finding in report.findings:
        decoded_lines: list[str]
        if finding.decoded_preview:
            decoded_fence = _markdown_fence(finding.decoded_preview)
            decoded_lines = ["- Decoded preview:", "", f"{decoded_fence}text", finding.decoded_preview, decoded_fence]
        else:
            decoded_lines = ["- Decoded preview: n/a"]
        redacted_text = _redacted_finding_text(finding.text)
        lines.extend(
            [
                f"### `{finding.kind}` [{finding.start}:{finding.end}]",
                "",
                f"- Severity: {finding.severity}",
                f"- Description: {finding.description}",
                f"- Codepoints: {', '.join(finding.codepoints) if finding.codepoints else 'n/a'}",
                f"- Matched text: {redacted_text}",
                *decoded_lines,
                "",
            ]
        )
    _append_deep_markdown(lines, report)
    return "\n".join(lines).rstrip() + "\n"


def write_hidden_channel_report(report: HiddenChannelReport, output_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "hidden-channel-report.json"
    markdown_path = destination / "hidden-channel-report.md"
    json_path.write_text(json.dumps(_public_report_dump(report), indent=2), encoding="utf-8")
    markdown_path.write_text(render_hidden_channel_markdown(report), encoding="utf-8")
    return json_path, markdown_path
