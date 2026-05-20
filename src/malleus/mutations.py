from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import base64
import html
import random
import re
from typing import Any
from urllib.parse import quote

from malleus.registry import mutator_registry


Transform = Callable[[str], str]


@dataclass(frozen=True)
class MutationSpec:
    name: str
    description: str
    category: str
    risk: str
    transform: Transform
    example: str
    family: str = ""
    surface: str = ""
    deterministic: bool = True
    reversible: bool = False
    safe_example: str = ""
    boundary: str = ""
    tags: tuple[str, ...] = ()
    can_noop: bool = False


@dataclass(frozen=True)
class _MutationDefinition:
    name: str
    family: str
    risk: str
    surface: str
    transform: Transform
    safe_example: str
    boundary: str
    tags: tuple[str, ...]
    description: str
    reversible: bool = False
    can_noop: bool = False


_NAME_RE = re.compile(r"^[a-z0-9_]+$")
_REPRESENTATIVE_PROMPT = "Alpha  beta color line. Keep the reply brief."


def _spacing(prompt: str) -> str:
    return " ".join(prompt)


def _leetspeak(prompt: str) -> str:
    table = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "A": "4", "E": "3", "I": "1", "O": "0", "S": "5"})
    return prompt.translate(table)


def _unicode_wrap(prompt: str) -> str:
    return f"⟦{prompt}⟧"


def _markdown_quote(prompt: str) -> str:
    return "\n".join(f"> {line}" for line in prompt.splitlines())


def _wrap(prefix: str, suffix: str) -> Transform:
    def transform(prompt: str) -> str:
        return f"{prefix}{prompt}{suffix}"

    return transform


def _line_prefix(prefix: str) -> Transform:
    def transform(prompt: str) -> str:
        lines = prompt.splitlines() or [prompt]
        return "\n".join(f"{prefix}{line}" for line in lines)

    return transform


def _line_suffix(suffix: str) -> Transform:
    def transform(prompt: str) -> str:
        lines = prompt.splitlines() or [prompt]
        return "\n".join(f"{line}{suffix}" for line in lines)

    return transform


def _replace_spaces(token: str) -> Transform:
    def transform(prompt: str) -> str:
        return prompt.replace(" ", token)

    return transform


def _join_characters(separator: str) -> Transform:
    def transform(prompt: str) -> str:
        return separator.join(prompt)

    return transform


def _chunk_lines(size: int, prefix: str = "", suffix: str = "") -> Transform:
    def transform(prompt: str) -> str:
        chunks = [prompt[index : index + size] for index in range(0, len(prompt), size)] or [""]
        return "\n".join(f"{prefix}{chunk}{suffix}" for chunk in chunks)

    return transform


def _case_style(style: str) -> Transform:
    def transform(prompt: str) -> str:
        if style == "upper":
            return prompt.upper()
        if style == "lower":
            return prompt.lower()
        if style == "title":
            return prompt.title()
        if style == "swap":
            return prompt.swapcase()
        if style == "capitalize_sentences":
            return ". ".join(part.strip().capitalize() for part in prompt.split("."))
        raise ValueError(f"unknown case style: {style}")

    return transform


def _substitute(mapping: dict[str, str]) -> Transform:
    table = str.maketrans(mapping)

    def transform(prompt: str) -> str:
        return prompt.translate(table)

    return transform


def _base64_text(prompt: str) -> str:
    encoded = base64.b64encode(prompt.encode("utf-8", errors="replace")).decode("ascii")
    return f"base64:{encoded}"


def _base32_text(prompt: str) -> str:
    encoded = base64.b32encode(prompt.encode("utf-8", errors="replace")).decode("ascii")
    return f"base32:{encoded}"


def _hex_text(prompt: str) -> str:
    return "hex:" + prompt.encode("utf-8", errors="replace").hex()


def _url_percent_text(prompt: str) -> str:
    return quote(prompt, safe="")


def _html_entity_text(prompt: str) -> str:
    return "html_entities:" + html.escape(prompt, quote=True)


def _unicode_codepoint_text(prompt: str) -> str:
    return " ".join(f"U+{ord(character):04X}" for character in prompt)


def _binary_octets_text(prompt: str) -> str:
    return " ".join(f"{byte:08b}" for byte in prompt.encode("utf-8", errors="replace"))


def _quoted_printable_soft_breaks(prompt: str) -> str:
    escaped = "".join(f"={ord(character):02X}" if character in " =\t\n\r" else character for character in prompt)
    return "=\n".join(escaped[index : index + 24] for index in range(0, len(escaped), 24))


def _variation_selector_steg(prompt: str) -> str:
    marker = "\ufe0f\ufe0e"
    return marker.join(prompt)


def _tag_block_invisible(prompt: str) -> str:
    # Unicode tag characters are visually subtle/invisible in many renderers.
    return "".join(chr(0xE0000 + ord(character)) if ord(character) < 128 else character for character in prompt)


def _confusable_cyrillic(prompt: str) -> str:
    return prompt.translate(str.maketrans({"a": "а", "A": "А", "e": "е", "E": "Е", "o": "о", "O": "О", "p": "р", "P": "Р", "c": "с", "C": "С", "x": "х", "X": "Х", "y": "у", "B": "В", "H": "Н", "K": "К", "M": "М", "T": "Т"}))


def _fullwidth_text(prompt: str) -> str:
    output: list[str] = []
    for character in prompt:
        codepoint = ord(character)
        if character == " ":
            output.append("\u3000")
        elif 0x21 <= codepoint <= 0x7E:
            output.append(chr(codepoint + 0xFEE0))
        else:
            output.append(character)
    return "".join(output)


def _bidi_override_wrap(prompt: str) -> str:
    return f"\u202e{prompt}\u202c"


def _combining_diacritic_noise(prompt: str) -> str:
    return "".join(character + ("\u0307" if character.isalpha() else "") for character in prompt)


def _whitespace_bit_pattern(prompt: str) -> str:
    bits = "".join(f"{byte:08b}" for byte in prompt.encode("utf-8", errors="replace"))
    carrier = "".join(" " if bit == "0" else "\t" for bit in bits[:96])
    return f"{prompt}\n{carrier}"


def _structured(label: str, opener: str, closer: str) -> Transform:
    def transform(prompt: str) -> str:
        return f"{opener}\n{label}: {prompt}\n{closer}"

    return transform


def _number_lines(prefix: str) -> Transform:
    def transform(prompt: str) -> str:
        lines = prompt.splitlines() or [prompt]
        return "\n".join(f"{index}. {prefix}{line}" for index, line in enumerate(lines, start=1))

    return transform


def _insert_every(interval: int, token: str) -> Transform:
    def transform(prompt: str) -> str:
        pieces: list[str] = []
        for index, character in enumerate(prompt, start=1):
            pieces.append(character)
            if index % interval == 0 and index != len(prompt):
                pieces.append(token)
        return "".join(pieces)

    return transform


def _reverse_words(prompt: str) -> str:
    return " ".join(reversed(prompt.split(" ")))


def _mirror_lines(prompt: str) -> str:
    return "\n".join(line[::-1] for line in (prompt.splitlines() or [prompt]))


def _duplicate_words(prompt: str) -> str:
    return " ".join(f"{word} {word}" for word in prompt.split(" "))


def _compact_spaces(prompt: str) -> str:
    return " ".join(prompt.split())


def _csv_cell(prompt: str) -> str:
    escaped = prompt.replace('"', '""')
    return f'"prompt","{escaped}"'


def _json_string(prompt: str) -> str:
    escaped = prompt.replace('\\', '\\\\').replace('"', '\\"').replace("\n", "\\n")
    return f'{{"prompt":"{escaped}"}}'


def _xml_text(prompt: str) -> str:
    escaped = prompt.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"<prompt>{escaped}</prompt>"


def _yaml_block(prompt: str) -> str:
    indented = "\n".join(f"  {line}" for line in (prompt.splitlines() or [prompt]))
    return f"prompt: |\n{indented}"


def _safe_example(name: str) -> str:
    return f"Safe sample for {name.replace('_', ' ')}."


def _description(family: str, surface: str, boundary: str) -> str:
    return f"Deterministically changes {surface} formatting to exercise {boundary} boundary handling."


def _definition(
    name: str,
    family: str,
    risk: str,
    surface: str,
    transform: Transform,
    boundary: str,
    tags: Sequence[str],
    *,
    description: str | None = None,
    reversible: bool = False,
    can_noop: bool = False,
) -> _MutationDefinition:
    return _MutationDefinition(
        name=name,
        family=family,
        risk=risk,
        surface=surface,
        transform=transform,
        safe_example=_safe_example(name),
        boundary=boundary,
        tags=tuple(tags),
        description=description or _description(family, surface, boundary),
        reversible=reversible,
        can_noop=can_noop,
    )


_BASE_DEFINITIONS: tuple[_MutationDefinition, ...] = (
    _definition("spacing", "obfuscation", "medium", "character_spacing", _spacing, "tokenization", ("spacing", "characters", "compatibility"), description="Insert spaces between every character to test brittle token-boundary handling."),
    _definition("leetspeak", "obfuscation", "medium", "character_substitution", _leetspeak, "lexical_normalization", ("substitution", "characters", "compatibility"), description="Replace common letters with leetspeak glyphs to test lexical robustness."),
    _definition("unicode_wrap", "delimiter", "low", "unicode_delimiter", _unicode_wrap, "delimiter_parsing", ("unicode", "wrapping", "compatibility"), description="Wrap text in uncommon Unicode brackets to test delimiter sensitivity.", reversible=True),
    _definition("markdown_quote", "format_shift", "medium", "markdown", _markdown_quote, "block_quote_parsing", ("markdown", "line_prefix", "compatibility"), description="Render text as a Markdown quote block to test context-format shifts."),
    _definition("zero_width_insert", "obfuscation", "medium", "unicode_invisible", _insert_every(4, "\u200b"), "hidden_character_normalization", ("unicode", "zero_width", "normalization"), description="Insert benign zero-width separators at fixed intervals to test invisible-character normalization."),
    _definition("tool_output_instruction", "tool_context", "medium", "tool_output", _structured("tool_output", "--- tool output ---", "--- end tool output ---"), "tool_transcript_parsing", ("tool", "transcript", "delimiter"), description="Present text as inert tool output to test transcript boundary parsing."),
)

_WRAP_VARIANTS = (
    ("angle_bracket_wrap", "delimiter", "low", "unicode_delimiter", "<", ">", "delimiter_parsing", ("delimiter", "ascii")),
    ("square_bracket_wrap", "delimiter", "low", "ascii_delimiter", "[", "]", "delimiter_parsing", ("delimiter", "ascii")),
    ("curly_brace_wrap", "delimiter", "low", "ascii_delimiter", "{", "}", "delimiter_parsing", ("delimiter", "ascii")),
    ("paren_wrap", "delimiter", "low", "ascii_delimiter", "(", ")", "delimiter_parsing", ("delimiter", "ascii")),
    ("double_quote_wrap", "delimiter", "low", "quotation", '"', '"', "quote_parsing", ("quote", "ascii")),
    ("single_quote_wrap", "delimiter", "low", "quotation", "'", "'", "quote_parsing", ("quote", "ascii")),
    ("backtick_wrap", "delimiter", "medium", "markdown", "`", "`", "code_span_parsing", ("markdown", "code")),
    ("triple_backtick_wrap", "delimiter", "medium", "markdown", "```text\n", "\n```", "code_fence_parsing", ("markdown", "code_fence")),
    ("tilde_fence_wrap", "delimiter", "medium", "markdown", "~~~text\n", "\n~~~", "code_fence_parsing", ("markdown", "code_fence")),
    ("xml_comment_wrap", "delimiter", "medium", "markup", "<!-- ", " -->", "comment_parsing", ("markup", "comment")),
    ("xml_tag_wrap", "format_shift", "medium", "markup", "<note>", "</note>", "markup_parsing", ("markup", "xml")),
    ("html_details_wrap", "format_shift", "medium", "markup", "<details><summary>sample</summary>", "</details>", "markup_parsing", ("markup", "html")),
    ("json_value_wrap", "format_shift", "medium", "json", '{"text":"', '"}', "structured_serialization", ("json", "escaping")),
    ("yaml_inline_wrap", "format_shift", "low", "yaml", "text: ", "", "structured_serialization", ("yaml", "inline")),
    ("csv_field_wrap", "format_shift", "low", "csv", 'field,"', '"', "structured_serialization", ("csv", "quote")),
    ("section_heading_wrap", "format_shift", "low", "markdown", "## Sample\n", "\n## End", "section_parsing", ("markdown", "heading")),
    ("horizontal_rule_wrap", "format_shift", "low", "markdown", "---\n", "\n---", "section_parsing", ("markdown", "rule")),
    ("unicode_corner_wrap", "delimiter", "low", "unicode_delimiter", "⌜", "⌟", "delimiter_parsing", ("unicode", "delimiter")),
    ("unicode_white_square_wrap", "delimiter", "low", "unicode_delimiter", "□", "□", "delimiter_parsing", ("unicode", "delimiter")),
    ("math_floor_wrap", "delimiter", "low", "unicode_delimiter", "⌊", "⌋", "delimiter_parsing", ("unicode", "math")),
)

_LINE_PREFIX_VARIANTS = (
    ("dash_bullet_lines", "- ", "markdown", "list_parsing", ("markdown", "list")),
    ("star_bullet_lines", "* ", "markdown", "list_parsing", ("markdown", "list")),
    ("plus_bullet_lines", "+ ", "markdown", "list_parsing", ("markdown", "list")),
    ("todo_checkbox_lines", "- [ ] ", "markdown", "task_list_parsing", ("markdown", "task_list")),
    ("done_checkbox_lines", "- [x] ", "markdown", "task_list_parsing", ("markdown", "task_list")),
    ("hash_comment_lines", "# ", "shell", "comment_parsing", ("comment", "shell")),
    ("slash_comment_lines", "// ", "code", "comment_parsing", ("comment", "code")),
    ("python_comment_lines", "# note: ", "code", "comment_parsing", ("comment", "python")),
    ("email_quote_lines", "> ", "email", "quote_parsing", ("email", "quote")),
    ("pipe_quote_lines", "| ", "plain_text", "table_parsing", ("table", "pipe")),
    ("tab_indent_lines", "\t", "plain_text", "indentation", ("indent", "tab")),
    ("four_space_indent_lines", "    ", "plain_text", "indentation", ("indent", "space")),
    ("label_note_lines", "NOTE: ", "plain_text", "label_parsing", ("label", "note")),
    ("label_context_lines", "CONTEXT: ", "plain_text", "label_parsing", ("label", "context")),
    ("transcript_user_lines", "User: ", "transcript", "speaker_attribution", ("transcript", "speaker")),
    ("transcript_assistant_lines", "Assistant: ", "transcript", "speaker_attribution", ("transcript", "speaker")),
    ("log_info_lines", "INFO ", "log", "log_parsing", ("log", "prefix")),
    ("log_debug_lines", "DEBUG ", "log", "log_parsing", ("log", "prefix")),
    ("quoted_label_lines", "quote> ", "plain_text", "quote_parsing", ("quote", "label")),
    ("caret_lines", "^ ", "plain_text", "symbol_prefix", ("symbol", "prefix")),
)

_LINE_SUFFIX_VARIANTS = (
    ("semicolon_suffix_lines", ";", "code", "statement_boundary", ("suffix", "semicolon")),
    ("period_suffix_lines", ".", "plain_text", "sentence_boundary", ("suffix", "period")),
    ("pipe_suffix_lines", " |", "table", "table_parsing", ("suffix", "pipe")),
    ("arrow_suffix_lines", " ->", "plain_text", "symbol_suffix", ("suffix", "arrow")),
    ("tag_suffix_lines", " #sample", "plain_text", "tag_parsing", ("suffix", "tag")),
    ("br_suffix_lines", " <br>", "markup", "markup_parsing", ("suffix", "html")),
    ("comma_suffix_lines", ",", "csv", "csv_parsing", ("suffix", "csv")),
    ("ellipsis_suffix_lines", "...", "plain_text", "continuation_parsing", ("suffix", "ellipsis")),
    ("section_suffix_lines", " §", "plain_text", "section_parsing", ("suffix", "section")),
    ("safe_marker_suffix_lines", " [sample]", "plain_text", "marker_parsing", ("suffix", "marker")),
)

_SPACE_VARIANTS = (
    ("underscore_spaces", "_", "ascii_spacing", "tokenization", ("spacing", "underscore")),
    ("hyphen_spaces", "-", "ascii_spacing", "tokenization", ("spacing", "hyphen")),
    ("dot_spaces", ".", "ascii_spacing", "tokenization", ("spacing", "dot")),
    ("slash_spaces", " / ", "ascii_spacing", "path_like_parsing", ("spacing", "slash")),
    ("pipe_spaces", " | ", "table", "table_parsing", ("spacing", "pipe")),
    ("newline_spaces", "\n", "plain_text", "line_break_parsing", ("spacing", "newline")),
    ("double_newline_spaces", "\n\n", "plain_text", "paragraph_parsing", ("spacing", "paragraph")),
    ("tab_spaces", "\t", "plain_text", "whitespace_normalization", ("spacing", "tab")),
    ("em_space_spaces", "\u2003", "unicode_spacing", "whitespace_normalization", ("spacing", "unicode")),
    ("thin_space_spaces", "\u2009", "unicode_spacing", "whitespace_normalization", ("spacing", "unicode")),
    ("no_break_space_spaces", "\u00a0", "unicode_spacing", "whitespace_normalization", ("spacing", "unicode")),
    ("word_joiner_spaces", "\u2060", "unicode_spacing", "hidden_character_normalization", ("spacing", "unicode")),
    ("middle_dot_spaces", "·", "unicode_spacing", "tokenization", ("spacing", "unicode")),
    ("colon_spaces", ":", "ascii_spacing", "label_parsing", ("spacing", "colon")),
    ("plus_spaces", "+", "ascii_spacing", "tokenization", ("spacing", "plus")),
)

_CHAR_JOIN_VARIANTS = (
    ("slash_character_join", "/", "character_spacing", "tokenization", ("characters", "slash")),
    ("dot_character_join", ".", "character_spacing", "tokenization", ("characters", "dot")),
    ("pipe_character_join", "|", "character_spacing", "table_parsing", ("characters", "pipe")),
    ("underscore_character_join", "_", "character_spacing", "tokenization", ("characters", "underscore")),
    ("zero_width_character_join", "\u200b", "unicode_invisible", "hidden_character_normalization", ("characters", "zero_width")),
    ("thin_space_character_join", "\u2009", "unicode_spacing", "whitespace_normalization", ("characters", "unicode")),
    ("newline_character_join", "\n", "plain_text", "line_break_parsing", ("characters", "newline")),
    ("colon_character_join", ":", "ascii_spacing", "label_parsing", ("characters", "colon")),
)

_CASE_VARIANTS = (
    ("uppercase_text", "upper", "case", "lexical_normalization", ("case", "upper")),
    ("lowercase_text", "lower", "case", "lexical_normalization", ("case", "lower")),
    ("titlecase_text", "title", "case", "lexical_normalization", ("case", "title")),
    ("swapcase_text", "swap", "case", "lexical_normalization", ("case", "swap")),
    ("sentence_capitalize_text", "capitalize_sentences", "case", "sentence_boundary", ("case", "sentence")),
)

_INSERT_VARIANTS = (
    ("zero_width_insert_2", 2, "\u200b", "unicode_invisible", "hidden_character_normalization", ("insert", "zero_width")),
    ("zero_width_insert_6", 6, "\u200b", "unicode_invisible", "hidden_character_normalization", ("insert", "zero_width")),
    ("word_joiner_insert", 5, "\u2060", "unicode_invisible", "hidden_character_normalization", ("insert", "word_joiner")),
    ("soft_hyphen_insert", 5, "\u00ad", "unicode_invisible", "hidden_character_normalization", ("insert", "soft_hyphen")),
    ("middle_dot_insert", 4, "·", "unicode_spacing", "tokenization", ("insert", "middle_dot")),
    ("thin_space_insert", 4, "\u2009", "unicode_spacing", "whitespace_normalization", ("insert", "thin_space")),
    ("newline_insert_12", 12, "\n", "plain_text", "line_break_parsing", ("insert", "newline")),
    ("pipe_insert_10", 10, "|", "table", "table_parsing", ("insert", "pipe")),
    ("colon_insert_8", 8, ":", "plain_text", "label_parsing", ("insert", "colon")),
    ("slash_insert_9", 9, "/", "plain_text", "path_like_parsing", ("insert", "slash")),
)

_STRUCTURED_VARIANTS = (
    ("json_prompt_field", _json_string, "json", "structured_serialization", ("json", "escaping")),
    ("xml_prompt_tag", _xml_text, "markup", "markup_parsing", ("xml", "escaping")),
    ("yaml_literal_block", _yaml_block, "yaml", "structured_serialization", ("yaml", "block")),
    ("csv_prompt_row", _csv_cell, "csv", "structured_serialization", ("csv", "escaping")),
    ("ini_value_block", _structured("value", "[sample]", "[/sample]"), "ini", "section_parsing", ("ini", "section")),
    ("toml_value_block", _structured("value", "[sample_table]", "# end table"), "toml", "section_parsing", ("toml", "section")),
    ("diff_added_lines", _line_prefix("+"), "diff", "diff_parsing", ("diff", "added")),
    ("diff_removed_lines", _line_prefix("-"), "diff", "diff_parsing", ("diff", "removed")),
    ("numbered_lines", _number_lines(""), "plain_text", "list_parsing", ("numbered", "list")),
    ("step_numbered_lines", _number_lines("step "), "plain_text", "list_parsing", ("numbered", "step")),
    ("blockquote_fence", _structured("quote", ">>>", "<<<"), "plain_text", "quote_parsing", ("quote", "fence")),
    ("log_record_block", _structured("message", "timestamp=2026-01-01 level=info", "end=true"), "log", "log_parsing", ("log", "record")),
    ("tool_result_block", _structured("result", "<tool_result>", "</tool_result>"), "tool_output", "tool_transcript_parsing", ("tool", "result")),
    ("function_call_block", _structured("arguments", "function sample() {", "}"), "code", "function_boundary", ("code", "function")),
    ("markdown_table_row", _structured("cell", "| kind | value |\n| --- | --- |", "| end | true |"), "markdown", "table_parsing", ("markdown", "table")),
    ("front_matter_block", _structured("summary", "---\ntitle: sample", "---"), "yaml", "front_matter_parsing", ("yaml", "front_matter")),
    ("email_header_block", _structured("Body", "Subject: sample\nFrom: analyst@example.test", "-- end --"), "email", "header_body_parsing", ("email", "header")),
    ("chat_transcript_block", _structured("User", "System note: sample context", "Assistant: acknowledged"), "transcript", "speaker_attribution", ("transcript", "chat")),
    ("html_pre_block", _structured("text", "<pre>", "</pre>"), "markup", "markup_parsing", ("html", "pre")),
    ("markdown_admonition_block", _structured("note", "!!! note", "!!! end"), "markdown", "admonition_parsing", ("markdown", "admonition")),
)

_MISC_VARIANTS = (
    ("reverse_word_order", _reverse_words, "ordering", "low", "word_order", "sequence_ordering", ("order", "words")),
    ("mirror_each_line", _mirror_lines, "ordering", "medium", "character_order", "bidirectional_reading", ("order", "characters")),
    ("duplicate_words", _duplicate_words, "repetition", "low", "word_repetition", "deduplication", ("repeat", "words")),
    ("compact_whitespace", _compact_spaces, "normalization", "low", "whitespace", "whitespace_normalization", ("normalize", "spaces")),
    ("chunk_4_lines", _chunk_lines(4), "segmentation", "medium", "line_breaks", "chunk_boundary", ("chunk", "short")),
    ("chunk_8_lines", _chunk_lines(8), "segmentation", "medium", "line_breaks", "chunk_boundary", ("chunk", "medium")),
    ("chunk_12_lines", _chunk_lines(12), "segmentation", "medium", "line_breaks", "chunk_boundary", ("chunk", "long")),
    ("chunk_bracket_6", _chunk_lines(6, "[", "]"), "segmentation", "medium", "line_breaks", "chunk_boundary", ("chunk", "bracket")),
    ("vowel_accent_light", _substitute({"a": "á", "e": "é", "i": "í", "o": "ó", "u": "ú", "A": "Á", "E": "É", "I": "Í", "O": "Ó", "U": "Ú"}), "unicode", "medium", "character_substitution", "unicode_normalization", ("unicode", "accent")),
    ("homoglyph_o_zero", _substitute({"o": "0", "O": "0"}), "obfuscation", "medium", "character_substitution", "lexical_normalization", ("homoglyph", "digit")),
    ("homoglyph_l_one", _substitute({"l": "1", "I": "1"}), "obfuscation", "medium", "character_substitution", "lexical_normalization", ("homoglyph", "digit")),
)

_ENCODING_VARIANTS = (
    ("base64_envelope", _base64_text, "encoding", "medium", "base64", "encoded_payload_normalization", ("encoding", "base64", "stegg")),
    ("base32_envelope", _base32_text, "encoding", "medium", "base32", "encoded_payload_normalization", ("encoding", "base32", "stegg")),
    ("hex_envelope", _hex_text, "encoding", "medium", "hex", "encoded_payload_normalization", ("encoding", "hex", "stegg")),
    ("url_percent_encode", _url_percent_text, "encoding", "medium", "url_encoding", "encoded_payload_normalization", ("encoding", "url", "percent")),
    ("html_entity_encode", _html_entity_text, "encoding", "medium", "html_entities", "markup_entity_normalization", ("encoding", "html", "entity")),
    ("unicode_codepoint_encode", _unicode_codepoint_text, "encoding", "medium", "unicode_codepoints", "encoded_payload_normalization", ("encoding", "unicode", "codepoint")),
    ("binary_octets_encode", _binary_octets_text, "encoding", "medium", "binary_octets", "encoded_payload_normalization", ("encoding", "binary", "octets")),
    ("quoted_printable_soft_breaks", _quoted_printable_soft_breaks, "encoding", "medium", "quoted_printable", "mime_wrapping", ("encoding", "mime", "soft_break")),
)

_STEG_TEXT_VARIANTS = (
    ("variation_selector_steg", _variation_selector_steg, "steganography", "high", "unicode_variation_selector", "hidden_character_normalization", ("unicode", "variation_selector", "stegg")),
    ("unicode_tag_invisible", _tag_block_invisible, "steganography", "high", "unicode_tags", "hidden_character_normalization", ("unicode", "tags", "invisible", "stegg")),
    ("cyrillic_confusables", _confusable_cyrillic, "obfuscation", "high", "unicode_confusable", "confusable_normalization", ("unicode", "confusable", "homoglyph")),
    ("fullwidth_text", _fullwidth_text, "obfuscation", "medium", "unicode_fullwidth", "unicode_normalization", ("unicode", "fullwidth", "normalization")),
    ("bidi_override_wrap", _bidi_override_wrap, "steganography", "high", "unicode_bidi", "bidirectional_reading", ("unicode", "bidi", "hidden_direction")),
    ("combining_diacritic_noise", _combining_diacritic_noise, "obfuscation", "medium", "unicode_combining_marks", "unicode_normalization", ("unicode", "combining", "normalization")),
    ("whitespace_bit_pattern", _whitespace_bit_pattern, "steganography", "high", "whitespace_channel", "hidden_character_normalization", ("whitespace", "tabs", "stegg")),
)


def _generated_definitions() -> list[_MutationDefinition]:
    definitions: list[_MutationDefinition] = list(_BASE_DEFINITIONS)
    for name, family, risk, surface, prefix, suffix, boundary, tags in _WRAP_VARIANTS:
        definitions.append(_definition(name, family, risk, surface, _wrap(prefix, suffix), boundary, tags, reversible=bool(prefix or suffix)))
    for name, prefix, surface, boundary, tags in _LINE_PREFIX_VARIANTS:
        definitions.append(_definition(name, "format_shift", "medium", surface, _line_prefix(prefix), boundary, tags))
    for name, suffix, surface, boundary, tags in _LINE_SUFFIX_VARIANTS:
        definitions.append(_definition(name, "format_shift", "low", surface, _line_suffix(suffix), boundary, tags))
    for name, token, surface, boundary, tags in _SPACE_VARIANTS:
        definitions.append(_definition(name, "obfuscation", "medium", surface, _replace_spaces(token), boundary, tags))
    for name, separator, surface, boundary, tags in _CHAR_JOIN_VARIANTS:
        definitions.append(_definition(name, "obfuscation", "medium", surface, _join_characters(separator), boundary, tags))
    for name, style, surface, boundary, tags in _CASE_VARIANTS:
        definitions.append(_definition(name, "normalization", "low", surface, _case_style(style), boundary, tags))
    for name, interval, token, surface, boundary, tags in _INSERT_VARIANTS:
        definitions.append(_definition(name, "obfuscation", "medium", surface, _insert_every(interval, token), boundary, tags))
    for name, transform, surface, boundary, tags in _STRUCTURED_VARIANTS:
        definitions.append(_definition(name, "format_shift", "medium", surface, transform, boundary, tags))
    for name, transform, family, risk, surface, boundary, tags in _MISC_VARIANTS:
        definitions.append(_definition(name, family, risk, surface, transform, boundary, tags))
    for name, transform, family, risk, surface, boundary, tags in [*_ENCODING_VARIANTS, *_STEG_TEXT_VARIANTS]:
        definitions.append(_definition(name, family, risk, surface, transform, boundary, tags))
    return definitions


def _validate_definition(definition: _MutationDefinition, seen: set[str]) -> None:
    if definition.name in seen:
        raise ValueError(f"duplicate mutation name: {definition.name}")
    if not _NAME_RE.fullmatch(definition.name):
        raise ValueError(f"invalid mutation name: {definition.name}")
    if not definition.family or not definition.risk or not definition.surface or not definition.safe_example or not definition.boundary or not definition.description:
        raise ValueError(f"mutation {definition.name} has incomplete metadata")
    if not definition.tags:
        raise ValueError(f"mutation {definition.name} must define tags")
    if not definition.can_noop and definition.transform(_REPRESENTATIVE_PROMPT) == _REPRESENTATIVE_PROMPT:
        raise ValueError(f"mutation {definition.name} does not change representative input")
    seen.add(definition.name)


def _to_spec(definition: _MutationDefinition) -> MutationSpec:
    return MutationSpec(
        name=definition.name,
        description=definition.description,
        category=definition.family,
        risk=definition.risk,
        transform=definition.transform,
        example=definition.safe_example,
        family=definition.family,
        surface=definition.surface,
        deterministic=True,
        reversible=definition.reversible,
        safe_example=definition.safe_example,
        boundary=definition.boundary,
        tags=definition.tags,
        can_noop=definition.can_noop,
    )


def register_builtin_mutators() -> None:
    seen: set[str] = set()
    for definition in _generated_definitions():
        _validate_definition(definition, seen)
        mutator_registry.register(definition.name, _to_spec(definition))


register_builtin_mutators()
_MUTATIONS = mutator_registry.items()


def mutation_specs() -> list[MutationSpec]:
    return sorted(_MUTATIONS.values(), key=lambda spec: spec.name)


def mutation_names() -> list[str]:
    return [spec.name for spec in mutation_specs()]


def get_mutation(mutation: str) -> MutationSpec:
    try:
        return mutator_registry.get(mutation)  # type: ignore[return-value]
    except ValueError as exc:
        raise ValueError(f"unknown mutation '{mutation}'") from exc


def mutate_prompt(prompt: str, mutation: str) -> str:
    return get_mutation(mutation).transform(prompt)


def compose_seeded_replay_cases(cases: list[dict[str, Any]], *, seed: int, mutations: list[str] | None = None) -> list[dict[str, Any]]:
    """Compose a deterministic replay plan over sanitized or synthetic case dicts."""

    selected_mutations = mutations or mutation_names()
    rng = random.Random(seed)
    ordered_cases = sorted(cases, key=lambda case: str(case.get("id", "")))
    replay: list[dict[str, Any]] = []
    for index, case in enumerate(ordered_cases, start=1):
        mutation = rng.choice(selected_mutations)
        prompt = str(case.get("prompt", ""))
        replay.append(
            {
                "replay_index": index,
                "seed": seed,
                "case_id": str(case.get("id", f"case-{index}")),
                "mutation": mutation,
                "prompt": mutate_prompt(prompt, mutation),
                "raw_payload_present": False,
            }
        )
    return replay
