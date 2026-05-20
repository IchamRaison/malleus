# Hidden-channel inspector

Malleus includes a deterministic text inspector for hidden channels that can make prompts, Markdown, or pasted artifacts look benign while carrying machine-readable instructions.

This is not a decoder/exploitation tool. It is a defensive review aid for AI security evaluations, prompt supply-chain checks, dataset review, and report triage. Decoded candidates are treated as inert evidence: Malleus does not execute, render, browse, or expand decoded content.

## Detected channels

The inspector currently detects:

- zero-width characters such as `U+200B`, `U+200C`, `U+200D`, `U+FEFF`, and `U+2060`
- bidirectional controls such as `U+202E` and isolate/override controls
- Unicode tag characters in the `U+E0000..U+E007F` range
- HTML comments hidden in rendered Markdown/HTML
- base64-like blocks that decode to printable UTF-8 text
- Markdown link or image titles, which may be hidden or visually easy to miss in rendered views

It also performs deep inspection through `inspect_text_deep()` and the default `inspect_text()` report path. Existing top-level JSON fields remain stable (`inspected_at`, `source`, `length`, `findings`, and `summary`), while newer consumers can read additive `deep` fields and the top-level `gate_recommendation`.

Each finding includes:

- kind
- severity
- description
- start/end character offsets
- matched text for visible input surfaces, with unsafe decoded candidates represented by redacted previews and hashes
- Unicode codepoints when relevant
- decoded preview for base64-like findings when safe; unsafe decoded previews are redacted

## Deep inspection fields

Deep inspection adds canonical views, approximate text statistics, and a bounded decode graph.

Canonical views include:

- `raw`
- `nfkc`
- `invisibles_stripped`
- `bidi_removed`
- `confusable_skeleton` using a small stdlib-only approximation for common confusables
- `markdown_plain`
- `html_plain`
- `url_html_decoded`

Statistics are stdlib-safe approximations: UTF-8 bytes, codepoints, token-like spans, line count, unique codepoints, combining marks, controls, invisible characters, bidi controls, approximate grapheme clusters, entropy, and printable ratio.

## Decode graph

The decode graph starts at the raw input node and explores safe text transforms up to a bounded depth. The default depth is `2`, with a candidate limit to prevent expansion abuse. Graph nodes contain hashes, redacted previews, entropy, printable ratio, instruction-like score, secret-like score, tool-action-like score, and canary matches. Edges record the transform used, such as URL decode, HTML unescape, base64 decode, hex decode, binary decode, Markdown/plain, or HTML/plain.

Graph previews are redacted when decoded content looks instruction-like, secret-like, or tool-action-like. The JSON report stores hashes, scores, canary indicators, and redacted previews rather than raw unsafe decoded payload bodies.

If limits are reached, `deep.decode_graph.truncated` is `true` and `deep.decode_graph.warnings` explains which limit stopped expansion.

## Gate recommendation

Reports include a deterministic recommendation:

- `allow`: no hidden-channel findings or suspicious decoded candidates
- `warn`: low/medium visibility issues that need review
- `quarantine`: high-severity findings, suspicious decoded candidates, canary matches, or graph truncation
- `block`: decoded content combines tool-action-like and secret-like signals

The recommendation is advisory. It is intended for artifact hygiene gates and analyst triage, not as a claim of malicious intent.

## CLI usage

Inspect inline text:

```bash
malleus inspect-text "hello<zero-width-space>world"
```

Inspect a file and emit JSON:

```bash
malleus inspect-text --file suspicious.md --json
```

Write JSON and Markdown reports:

```bash
malleus inspect-text \
  --file suspicious.md \
  --out-dir reports/hidden-channel-review
```

Outputs:

- `hidden-channel-report.json`
- `hidden-channel-report.md`

JSON output includes the decode graph:

```bash
malleus inspect-text --file tests/fixtures/hidden_channels/nested-encoded-canary.md --json
```

## Severity model

Current deterministic severities are intentionally simple:

- `high`: bidirectional controls, Unicode tags, instruction-like HTML comments, instruction-like decoded base64
- `medium`: zero-width characters, generic HTML comments, printable base64-like blocks, Markdown link titles
- `none`: no findings

The inspector does not claim malicious intent. It flags review-worthy hidden or low-visibility content.

## False-positive posture

Base64 detection is conservative:

- very short tokens are ignored
- tokens must decode successfully with strict base64 validation
- decoded content must be printable UTF-8

Deep graph expansion is also conservative:

- default graph depth is limited to `2`
- candidate count is bounded
- duplicate decoded text is deduplicated by SHA-256
- unsafe-looking decoded previews are redacted
- decoded content is never executed or rendered

Markdown title detection is reported as medium even if it contains instruction-like text, because title attributes are a visibility issue rather than direct evidence of execution.

## Use in Malleus workflow

Recommended uses:

1. Inspect adversarial datasets before publishing them.
2. Inspect model outputs that appear visually strange.
3. Inspect Markdown/HTML reports or copied prompts before sharing screenshots.
4. Feed findings into gates, evidence bundles, audit bundles, and release artifact hygiene checks.

Example:

```bash
malleus inspect-text --file datasets/smoke/smoke_cases.yaml --out-dir reports/dataset-hygiene
```

## Limitations

The inspector is text-only today. It does not inspect PDFs, images, EXIF metadata, Office documents, archives, or rendered DOM state.

It also does not automatically remove hidden content. Sanitization should be an explicit separate step to avoid destructive edits.
