from __future__ import annotations

import hashlib
import html
import re
import struct
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from malleus.hidden_channels import inspect_text

ArtifactRecommendation = Literal["allow", "warn", "quarantine", "block"]
ArtifactSeverity = Literal["info", "low", "medium", "high", "critical"]

_RECOMMENDATION_ORDER: dict[ArtifactRecommendation, int] = {"allow": 0, "warn": 1, "quarantine": 2, "block": 3}
_SEVERITY_RECOMMENDATION: dict[ArtifactSeverity, ArtifactRecommendation] = {
    "info": "allow",
    "low": "warn",
    "medium": "warn",
    "high": "quarantine",
    "critical": "block",
}
_SECRETISH_RE = re.compile(
    r"\b(?:api[_ -]?key|token|password|secret|credential|bearer|sk-[A-Za-z0-9_-]{10,})\b|[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}",
    re.IGNORECASE,
)
_UNSAFE_RE = re.compile(r"\b(system|developer|instruction|ignore|override|secret|token|password|api[_ -]?key|prompt|execute|script)\b", re.IGNORECASE)
_HTML_SCRIPT_RE = re.compile(r"<script\b[^>]*>(?P<body>[\s\S]*?)</script\s*>", re.IGNORECASE)
_EVENT_ATTR_RE = re.compile(r"\s(?P<name>on[a-zA-Z0-9_:-]+)\s*=\s*(?P<quote>['\"])(?P<value>[\s\S]*?)(?P=quote)", re.IGNORECASE)
_SVG_METADATA_RE = re.compile(r"<(?:metadata|desc|title)\b[^>]*>(?P<body>[\s\S]*?)</(?:metadata|desc|title)\s*>", re.IGNORECASE)
_SVG_TEXT_RE = re.compile(r"<text\b(?P<attrs>[^>]*)>(?P<body>[\s\S]*?)</text\s*>", re.IGNORECASE)
_HIDDEN_STYLE_RE = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?|font-size\s*:\s*0|(?:left|right|top|bottom|x|y)\s*:\s*-\d{2,}|(?:x|y)\s*=\s*['\"]-\d{2,})",
    re.IGNORECASE,
)
_PDF_TOKEN_RE = re.compile(rb"/(Title|Author|Subject|Keywords|Creator|Producer)\s*\((?P<value>(?:\\.|[^\\)]){0,500})\)")
_PDF_ACTION_RE = re.compile(rb"/(OpenAction|AA|JS|JavaScript|Launch|URI)\b")
_MARKDOWN_SPECIALS_RE = re.compile(r"([`*_{}\[\]<>|#])")


class ArtifactFinding(BaseModel):
    kind: str
    severity: ArtifactSeverity
    description: str
    evidence: str | None = None


class ArtifactSurface(BaseModel):
    name: str
    kind: str
    length: int
    sha256: str
    redacted_preview: str


class DeepInspectionEvidence(BaseModel):
    surface_name: str
    gate_recommendation: ArtifactRecommendation
    total_findings: int
    highest_severity: str
    gate_reasons: list[str] = Field(default_factory=list)
    graph_truncated: bool = False
    suspicious_previews: list[str] = Field(default_factory=list)


class ArchiveEntry(BaseModel):
    name: str
    size: int
    compressed_size: int | None = None
    kind: Literal["file", "directory", "other"]
    nested_archive: bool = False


class ArtifactManifest(BaseModel):
    format: str
    size_bytes: int
    sha256: str
    entries: list[ArchiveEntry] = Field(default_factory=list)
    chunks: list[dict[str, int | str]] = Field(default_factory=list)
    metadata: dict[str, str | int | bool] = Field(default_factory=dict)
    truncated: bool = False
    appended_data_detected: bool = False


class ArtifactFirewallReport(BaseModel):
    schema_version: str = "malleus.artifact_firewall.v1"
    inspected_at: str
    source: str
    manifest: ArtifactManifest
    surfaces: list[ArtifactSurface] = Field(default_factory=list)
    findings: list[ArtifactFinding] = Field(default_factory=list)
    deep_inspection: list[DeepInspectionEvidence] = Field(default_factory=list)
    recommendation: ArtifactRecommendation
    recommendation_reasons: list[str] = Field(default_factory=list)


class ArtifactLimits(BaseModel):
    max_read_bytes: int = 2_000_000
    max_text_surface_chars: int = 50_000
    max_archive_items: int = 25
    max_archive_total_size: int = 10_000_000
    max_png_chunks: int = 64


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _redact_preview(text: str, *, limit: int = 180) -> str:
    if _SECRETISH_RE.search(text) or _UNSAFE_RE.search(text):
        digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]
        return f"[REDACTED potentially unsafe artifact text sha256={digest} length={len(text)}]"
    preview = text[:limit]
    if len(text) > limit:
        preview += "…"
    return preview


def _surface(name: str, kind: str, text: str) -> ArtifactSurface:
    return ArtifactSurface(
        name=name,
        kind=kind,
        length=len(text),
        sha256=hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
        redacted_preview=_redact_preview(text),
    )


def _add_finding(findings: list[ArtifactFinding], kind: str, severity: ArtifactSeverity, description: str, evidence: str | None = None) -> None:
    findings.append(ArtifactFinding(kind=kind, severity=severity, description=description, evidence=evidence))


def _stronger(left: ArtifactRecommendation, right: ArtifactRecommendation) -> ArtifactRecommendation:
    return left if _RECOMMENDATION_ORDER[left] >= _RECOMMENDATION_ORDER[right] else right


def _detect_format(path: Path, data: bytes) -> str:
    suffix = path.suffix.lower()
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if zipfile.is_zipfile(path):
        return "zip"
    if tarfile.is_tarfile(path):
        return "tar"
    if suffix == ".svg" or b"<svg" in data[:512].lower():
        return "svg"
    if suffix in {".html", ".htm"} or b"<html" in data[:512].lower():
        return "html"
    if suffix == ".json":
        return "json"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix in {".md", ".markdown", ".txt"}:
        return "markdown" if suffix in {".md", ".markdown"} else "text"
    return "binary"


def _read_text_surface(data: bytes, limits: ArtifactLimits) -> str:
    return data[: limits.max_read_bytes].decode("utf-8", errors="replace")[: limits.max_text_surface_chars]


def _inspect_surfaces(surfaces: list[tuple[str, str]], findings: list[ArtifactFinding]) -> list[DeepInspectionEvidence]:
    evidence: list[DeepInspectionEvidence] = []
    for name, text in surfaces:
        inspected = inspect_text(text, source=name)
        deep = inspected.deep
        suspicious_previews: list[str] = []
        if deep is not None:
            for node in deep.decode_graph.nodes[:8]:
                if node.depth > 0 and (node.instruction_like_score or node.secret_like_score or node.tool_action_like_score or node.canary_matches):
                    suspicious_previews.append(node.redacted_preview)
        gate = inspected.gate_recommendation or "allow"
        if gate in {"quarantine", "block"}:
            _add_finding(findings, "deep_inspection", "high", f"Deep inspector recommended {gate} for {name}")
        evidence.append(
            DeepInspectionEvidence(
                surface_name=name,
                gate_recommendation=gate,
                total_findings=inspected.summary.total_findings,
                highest_severity=inspected.summary.highest_severity,
                gate_reasons=list(deep.gate_reasons if deep else []),
                graph_truncated=bool(deep and deep.decode_graph.truncated),
                suspicious_previews=suspicious_previews,
            )
        )
    return evidence


def _collect_html_svg_surfaces(text: str, *, svg: bool, surfaces: list[tuple[str, str]], finding_list: list[ArtifactFinding]) -> None:
    for index, match in enumerate(_HTML_SCRIPT_RE.finditer(text), start=1):
        body = html.unescape(match.group("body"))
        surfaces.append((f"script[{index}]", body))
        _add_finding(finding_list, "script_text", "high", "Script block text was found and inspected as inert untrusted text", _redact_preview(body))
    for index, match in enumerate(_EVENT_ATTR_RE.finditer(text), start=1):
        value = html.unescape(match.group("value"))
        attr = match.group("name")
        surfaces.append((f"event[{index}].{attr}", value))
        _add_finding(finding_list, "event_handler_text", "high", f"Event handler attribute {attr} was found and inspected as inert untrusted text", _redact_preview(value))
    if svg:
        for index, match in enumerate(_SVG_METADATA_RE.finditer(text), start=1):
            body = re.sub(r"<[^>]+>", " ", html.unescape(match.group("body")))
            surfaces.append((f"svg_metadata[{index}]", body))
            if body.strip():
                _add_finding(finding_list, "svg_metadata", "medium", "SVG metadata/title/description text was inspected", _redact_preview(body))
        for index, match in enumerate(_SVG_TEXT_RE.finditer(text), start=1):
            attrs = html.unescape(match.group("attrs"))
            body = re.sub(r"<[^>]+>", " ", html.unescape(match.group("body"))).strip()
            if not body:
                continue
            surface_name = f"svg_text[{index}]"
            surfaces.append((surface_name, body))
            if _HIDDEN_STYLE_RE.search(attrs):
                _add_finding(finding_list, "svg_hidden_text", "high", "SVG text appears hidden, transparent, or off-canvas and was inspected as untrusted text", _redact_preview(body))
    for index, match in enumerate(_HIDDEN_STYLE_RE.finditer(text), start=1):
        if svg and "svg_hidden_text" in {finding.kind for finding in finding_list}:
            continue
        _add_finding(finding_list, "hidden_layout_style", "medium", "Hidden, transparent, or off-canvas layout marker was found in document markup", match.group(0)[:120])


def _inspect_textlike(format_name: str, data: bytes, limits: ArtifactLimits, findings: list[ArtifactFinding]) -> tuple[list[ArtifactSurface], list[tuple[str, str]]]:
    text = _read_text_surface(data, limits)
    surfaces = [(format_name, text)]
    if len(data) > limits.max_read_bytes or len(text) >= limits.max_text_surface_chars:
        _add_finding(findings, "text_truncated", "medium", "Text artifact exceeded configured read/surface limits")
    if format_name in {"html", "svg"}:
        _collect_html_svg_surfaces(text, svg=format_name == "svg", surfaces=surfaces, finding_list=findings)
    return [_surface(name, "text", value) for name, value in surfaces], surfaces


def _inspect_pdf(data: bytes, findings: list[ArtifactFinding]) -> tuple[list[ArtifactSurface], list[tuple[str, str]], bool]:
    surfaces: list[tuple[str, str]] = []
    eof_index = data.rfind(b"%%EOF")
    appended = eof_index != -1 and data[eof_index + len(b"%%EOF") :].strip() != b""
    if appended:
        _add_finding(findings, "appended_data", "high", "Bytes were found after the final PDF EOF marker")
    for match in _PDF_TOKEN_RE.finditer(data[:2_000_000]):
        key = match.group(1).decode("ascii", errors="replace")
        value = match.group("value").replace(b"\\)", b")").replace(b"\\(", b"(").decode("utf-8", errors="replace")
        surfaces.append((f"pdf.{key}", value))
    actions = sorted({token.decode("ascii", errors="replace") for token in _PDF_ACTION_RE.findall(data[:2_000_000])})
    if actions:
        text = " ".join(actions)
        surfaces.append(("pdf.actions", text))
        _add_finding(findings, "pdf_action", "high", "PDF action/JavaScript-related keys were detected by metadata-only byte scan", ", ".join(actions))
    return [_surface(name, "pdf_metadata", value) for name, value in surfaces], surfaces, appended


def _inspect_png(data: bytes, limits: ArtifactLimits, findings: list[ArtifactFinding]) -> tuple[list[ArtifactSurface], list[tuple[str, str]], list[dict[str, int | str]], bool]:
    chunks: list[dict[str, int | str]] = []
    surfaces: list[tuple[str, str]] = []
    offset = 8
    appended = False
    while offset + 12 <= len(data) and len(chunks) < limits.max_png_chunks:
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8].decode("ascii", errors="replace")
        chunk_start = offset + 8
        chunk_end = chunk_start + length
        crc_end = chunk_end + 4
        if crc_end > len(data):
            _add_finding(findings, "png_truncated", "high", "PNG chunk length exceeds file bounds")
            break
        chunks.append({"type": chunk_type, "length": length})
        payload = data[chunk_start:chunk_end]
        if chunk_type in {"tEXt", "iTXt"}:
            text = payload.decode("utf-8", errors="replace")[:2000]
            surfaces.append((f"png.{chunk_type}.{len(surfaces) + 1}", text))
        offset = crc_end
        if chunk_type == "IEND":
            appended = data[offset:].strip(b"\x00\r\n\t ") != b""
            break
    if len(chunks) >= limits.max_png_chunks:
        _add_finding(findings, "png_chunk_limit", "medium", "PNG chunk listing reached configured chunk limit")
    if appended:
        _add_finding(findings, "appended_data", "high", "Bytes were found after the PNG IEND chunk")
    return [_surface(name, "png_metadata", value) for name, value in surfaces], surfaces, chunks, appended


def _entry_kind_zip(info: zipfile.ZipInfo) -> Literal["file", "directory", "other"]:
    return "directory" if info.is_dir() else "file"


def _is_nested_archive(name: str) -> bool:
    return Path(name).suffix.lower() in {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz"}


def _inspect_zip(path: Path, limits: ArtifactLimits, findings: list[ArtifactFinding]) -> list[ArchiveEntry]:
    entries: list[ArchiveEntry] = []
    total_size = 0
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if len(entries) >= limits.max_archive_items:
                _add_finding(findings, "archive_item_limit", "high", "ZIP manifest listing reached configured item limit")
                break
            total_size += info.file_size
            nested = _is_nested_archive(info.filename)
            if nested:
                _add_finding(findings, "nested_archive", "medium", "Nested archive entry listed but not extracted", info.filename)
            entries.append(
                ArchiveEntry(
                    name=info.filename,
                    size=info.file_size,
                    compressed_size=info.compress_size,
                    kind=_entry_kind_zip(info),
                    nested_archive=nested,
                )
            )
    if total_size > limits.max_archive_total_size:
        _add_finding(findings, "archive_size_limit", "critical", "ZIP uncompressed manifest total exceeds configured size limit")
    return entries


def _inspect_tar(path: Path, limits: ArtifactLimits, findings: list[ArtifactFinding]) -> list[ArchiveEntry]:
    entries: list[ArchiveEntry] = []
    total_size = 0
    with tarfile.open(path) as archive:
        for member in archive:
            if len(entries) >= limits.max_archive_items:
                _add_finding(findings, "archive_item_limit", "high", "TAR manifest listing reached configured item limit")
                break
            total_size += member.size
            if member.isdir():
                kind: Literal["file", "directory", "other"] = "directory"
            elif member.isfile():
                kind = "file"
            else:
                kind = "other"
            nested = _is_nested_archive(member.name)
            if nested:
                _add_finding(findings, "nested_archive", "medium", "Nested archive entry listed but not extracted", member.name)
            entries.append(ArchiveEntry(name=member.name, size=member.size, kind=kind, nested_archive=nested))
    if total_size > limits.max_archive_total_size:
        _add_finding(findings, "archive_size_limit", "critical", "TAR manifest total exceeds configured size limit")
    return entries


def inspect_artifact(path: str | Path, *, limits: ArtifactLimits | None = None) -> ArtifactFirewallReport:
    artifact_path = Path(path)
    active_limits = limits or ArtifactLimits()
    data = artifact_path.read_bytes()
    findings: list[ArtifactFinding] = []
    format_name = _detect_format(artifact_path, data)
    manifest = ArtifactManifest(format=format_name, size_bytes=len(data), sha256=_sha256_bytes(data))
    artifact_surfaces: list[ArtifactSurface] = []
    text_surfaces: list[tuple[str, str]] = []

    if format_name in {"markdown", "text", "html", "json", "yaml", "svg"}:
        artifact_surfaces, text_surfaces = _inspect_textlike(format_name, data, active_limits, findings)
    elif format_name == "pdf":
        artifact_surfaces, text_surfaces, manifest.appended_data_detected = _inspect_pdf(data, findings)
    elif format_name == "png":
        artifact_surfaces, text_surfaces, manifest.chunks, manifest.appended_data_detected = _inspect_png(data, active_limits, findings)
    elif format_name == "zip":
        manifest.entries = _inspect_zip(artifact_path, active_limits, findings)
        manifest.truncated = any(finding.kind == "archive_item_limit" for finding in findings)
        text_surfaces = [("zip_manifest", "\n".join(f"{entry.kind} {entry.name} size={entry.size}" for entry in manifest.entries))]
        artifact_surfaces = [_surface("zip_manifest", "archive_manifest", text_surfaces[0][1])] if text_surfaces[0][1] else []
    elif format_name == "tar":
        manifest.entries = _inspect_tar(artifact_path, active_limits, findings)
        manifest.truncated = any(finding.kind == "archive_item_limit" for finding in findings)
        text_surfaces = [("tar_manifest", "\n".join(f"{entry.kind} {entry.name} size={entry.size}" for entry in manifest.entries))]
        artifact_surfaces = [_surface("tar_manifest", "archive_manifest", text_surfaces[0][1])] if text_surfaces[0][1] else []
    else:
        _add_finding(findings, "unsupported_binary", "medium", "Unsupported binary artifact; only size/hash metadata was inspected")

    deep_evidence = _inspect_surfaces(text_surfaces, findings) if text_surfaces else []
    recommendation: ArtifactRecommendation = "allow"
    reasons: list[str] = []
    for finding in findings:
        next_recommendation = _SEVERITY_RECOMMENDATION[finding.severity]
        recommendation = _stronger(recommendation, next_recommendation)
        if next_recommendation != "allow":
            reasons.append(f"{finding.kind}: {finding.description}")
    for evidence in deep_evidence:
        recommendation = _stronger(recommendation, evidence.gate_recommendation)
        if evidence.gate_recommendation != "allow":
            reasons.append(f"deep inspector recommended {evidence.gate_recommendation} for {evidence.surface_name}")
    if not reasons:
        reasons.append("no artifact firewall findings or suspicious deep-inspection evidence detected")

    return ArtifactFirewallReport(
        inspected_at=datetime.now(UTC).isoformat(),
        source=str(artifact_path),
        manifest=manifest,
        surfaces=artifact_surfaces,
        findings=findings,
        deep_inspection=deep_evidence,
        recommendation=recommendation,
        recommendation_reasons=sorted(dict.fromkeys(reasons)),
    )


def _markdown_fence(text: str) -> str:
    runs = [len(match.group(0)) for match in re.finditer(r"`+", text)]
    return "`" * max(3, max(runs, default=0) + 1)


def _md_escape(text: str) -> str:
    return _MARKDOWN_SPECIALS_RE.sub(r"\\\1", text)


def render_artifact_firewall_markdown(report: ArtifactFirewallReport) -> str:
    lines = [
        "# Malleus Artifact Firewall Report",
        "",
        f"- Source: `{_md_escape(report.source)}`",
        f"- Inspected at: {report.inspected_at}",
        f"- Format: {report.manifest.format}",
        f"- Size bytes: {report.manifest.size_bytes}",
        f"- SHA-256: `{report.manifest.sha256}`",
        f"- Recommendation: **{report.recommendation}**",
        f"- Findings: {len(report.findings)}",
        "",
        "## Recommendation reasons",
        "",
    ]
    lines.extend(f"- {_md_escape(reason)}" for reason in report.recommendation_reasons)
    lines.extend(["", "## Extracted surfaces", ""])
    if not report.surfaces:
        lines.append("No text or metadata surfaces were extracted.")
    for surface in report.surfaces:
        fence = _markdown_fence(surface.redacted_preview)
        lines.extend(
            [
                f"### `{_md_escape(surface.name)}`",
                "",
                f"- Kind: {surface.kind}",
                f"- Length: {surface.length}",
                f"- SHA-256: `{surface.sha256}`",
                "- Redacted preview:",
                "",
                f"{fence}text",
                surface.redacted_preview,
                fence,
                "",
            ]
        )
    lines.extend(["## Findings", ""])
    if not report.findings:
        lines.append("No artifact firewall findings detected.")
    for finding in report.findings:
        lines.extend(
            [
                f"- **{finding.severity}** `{_md_escape(finding.kind)}`: {_md_escape(finding.description)}"
                + (f" Evidence: `{_md_escape(finding.evidence)}`" if finding.evidence else "")
            ]
        )
    lines.extend(["", "## Deep inspection evidence", ""])
    if not report.deep_inspection:
        lines.append("No deep text inspection was performed.")
    for evidence in report.deep_inspection:
        lines.extend(
            [
                f"- `{_md_escape(evidence.surface_name)}`: recommendation={evidence.gate_recommendation}, "
                f"findings={evidence.total_findings}, highest={evidence.highest_severity}, graph_truncated={evidence.graph_truncated}",
            ]
        )
        for reason in evidence.gate_reasons:
            lines.append(f"  - Reason: {_md_escape(reason)}")
        for preview in evidence.suspicious_previews[:4]:
            lines.append(f"  - Redacted preview: `{_md_escape(preview)}`")
    if report.manifest.entries:
        lines.extend(["", "## Archive manifest", ""])
        for entry in report.manifest.entries:
            nested = " nested-archive" if entry.nested_archive else ""
            lines.append(f"- `{_md_escape(entry.name)}` kind={entry.kind} size={entry.size}{nested}")
    if report.manifest.chunks:
        lines.extend(["", "## PNG chunks", ""])
        for chunk in report.manifest.chunks:
            lines.append(f"- `{chunk['type']}` length={chunk['length']}")
    return "\n".join(lines).rstrip() + "\n"


def write_artifact_firewall_report(report: ArtifactFirewallReport, output_dir: str | Path) -> tuple[Path, Path]:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    json_path = destination / "artifact-firewall-report.json"
    markdown_path = destination / "artifact-firewall-report.md"
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(render_artifact_firewall_markdown(report), encoding="utf-8")
    return json_path, markdown_path
