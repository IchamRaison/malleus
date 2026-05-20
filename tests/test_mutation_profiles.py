from __future__ import annotations

from pathlib import Path

import pytest

from malleus.datasets import load_mutation_profile, load_release_matrix, validate_mutation_profile_pair
from malleus.mutations import get_mutation, mutation_names
from malleus.schemas import MUTATION_PROFILE_SCHEMA_VERSION


REPO_ROOT = Path(__file__).resolve().parents[1]
SELECTED_PROFILE = REPO_ROOT / "datasets/mutation_profiles/selected-v1.yaml"
DEEP_PROFILE = REPO_ROOT / "datasets/mutation_profiles/deep-v1.yaml"
RELEASE_MATRIX = REPO_ROOT / "datasets/release_matrices/malleus-v0.1.yaml"

EXPECTED_SELECTED_MUTATIONS = [
    "unicode_wrap",
    "zero_width_insert",
    "zero_width_insert_6",
    "soft_hyphen_insert",
    "word_joiner_insert",
    "homoglyph_o_zero",
    "homoglyph_l_one",
    "leetspeak",
    "middle_dot_insert",
    "thin_space_insert",
    "triple_backtick_wrap",
    "xml_comment_wrap",
    "angle_bracket_wrap",
    "double_quote_wrap",
    "chat_transcript_block",
    "transcript_user_lines",
    "transcript_assistant_lines",
    "tool_result_block",
    "function_call_block",
    "json_prompt_field",
    "yaml_literal_block",
    "front_matter_block",
    "diff_added_lines",
    "chunk_4_lines",
    "uppercase_text",
]

REQUIRED_DEEP_MUTATION_COVERAGE = {
    "format_wrappers": {"angle_bracket_wrap", "square_bracket_wrap", "xml_tag_wrap", "html_details_wrap"},
    "obfuscation": {"leetspeak", "zero_width_insert", "soft_hyphen_insert", "homoglyph_o_zero"},
    "word_order_transforms": {"reverse_word_order", "duplicate_words", "mirror_each_line"},
    "unicode_wrappers_and_invisible": {"unicode_wrap", "unicode_corner_wrap", "word_joiner_insert", "zero_width_character_join"},
    "markdown_fences": {"triple_backtick_wrap", "tilde_fence_wrap", "blockquote_fence"},
    "json_blocks": {"json_prompt_field", "json_value_wrap"},
    "encoded_payloads": {"base64_envelope", "html_entity_encode", "url_percent_encode", "quoted_printable_soft_breaks"},
    "steganographic_text": {"variation_selector_steg", "unicode_tag_invisible", "whitespace_bit_pattern", "bidi_override_wrap"},
    "confusables": {"cyrillic_confusables", "fullwidth_text", "combining_diacritic_noise"},
}


def _profile_yaml(mutations: list[str], **overrides: object) -> str:
    import yaml

    data = {
        "schema_version": MUTATION_PROFILE_SCHEMA_VERSION,
        "id": "fixture-v1",
        "version": "1.0.0",
        "name": "Fixture mutation profile",
        "optional": False,
        "deep": False,
        "default": False,
        "substitutions": [],
        "metadata": {"description": "Fixture profile."},
        "mutations": mutations,
    }
    data.update(overrides)
    return yaml.safe_dump(data, sort_keys=False)


def _write_profile(tmp_path: Path, mutations: list[str], **overrides: object) -> Path:
    path = tmp_path / "profile.yaml"
    path.write_text(_profile_yaml(mutations, **overrides), encoding="utf-8")
    return path


def test_selected_profile_is_exact_release_set() -> None:
    profile = load_mutation_profile(SELECTED_PROFILE)

    assert profile.schema_version == MUTATION_PROFILE_SCHEMA_VERSION
    assert profile.id == "selected-v1"
    assert profile.source_path == str(SELECTED_PROFILE.resolve())
    assert profile.optional is False
    assert profile.deep is False
    assert profile.default is True
    assert profile.substitutions == []
    assert profile.mutations == EXPECTED_SELECTED_MUTATIONS
    assert len(profile.mutations) == 25
    assert len(profile.mutations) == len(set(profile.mutations))
    assert set(profile.mutations).issubset(set(mutation_names()))


def test_deep_profile_tracks_complete_registry_and_is_optional() -> None:
    profile = load_mutation_profile(DEEP_PROFILE)

    assert profile.id == "deep-v1"
    assert profile.optional is True
    assert profile.deep is True
    assert profile.default is False
    assert profile.substitutions == []
    assert profile.metadata["release_matrix_ref"] == "deep-v1"
    assert len(profile.mutations) == 140
    assert profile.mutations == mutation_names()
    assert profile.mutations == sorted(profile.mutations)
    assert len(profile.mutations) == len(set(profile.mutations))
    assert [get_mutation(name).name for name in profile.mutations] == profile.mutations


def test_deep_profile_covers_required_mutation_surfaces() -> None:
    profile = load_mutation_profile(DEEP_PROFILE)
    profile_names = set(profile.mutations)

    for coverage_names in REQUIRED_DEEP_MUTATION_COVERAGE.values():
        assert coverage_names.issubset(profile_names)


def test_selected_profile_is_subset_of_deep_profile() -> None:
    selected = load_mutation_profile(SELECTED_PROFILE)
    deep = load_mutation_profile(DEEP_PROFILE)

    validate_mutation_profile_pair(selected, deep)
    assert set(selected.mutations).issubset(set(deep.mutations))


def test_mutation_profile_rejects_unknown_registry_name(tmp_path: Path) -> None:
    path = _write_profile(tmp_path, ["unicode_wrap", "missing_mutation"])

    with pytest.raises(ValueError, match="references unknown mutations: missing_mutation"):
        load_mutation_profile(path)


def test_mutation_profile_rejects_duplicate_names(tmp_path: Path) -> None:
    path = _write_profile(tmp_path, ["unicode_wrap", "unicode_wrap"])

    with pytest.raises(Exception, match="duplicate mutation profile name: unicode_wrap"):
        load_mutation_profile(path)


def test_deep_profile_cannot_be_default(tmp_path: Path) -> None:
    path = _write_profile(tmp_path, ["unicode_wrap"], id="deep-fixture", deep=True, default=True)

    with pytest.raises(Exception, match="deep mutation profiles cannot be default"):
        load_mutation_profile(path)


def test_selected_deep_pair_rejects_missing_subset_member(tmp_path: Path) -> None:
    selected = load_mutation_profile(_write_profile(tmp_path, ["unicode_wrap"], id="selected-fixture"))
    deep = load_mutation_profile(_write_profile(tmp_path, ["leetspeak"], id="deep-fixture", deep=True, optional=True))

    with pytest.raises(ValueError, match="selected mutation profile selected-fixture is not a subset of deep-fixture: unicode_wrap"):
        validate_mutation_profile_pair(selected, deep)


def test_release_matrix_refs_stay_aligned_to_profile_files() -> None:
    matrix = load_release_matrix(RELEASE_MATRIX)

    assert [(profile.id, profile.path) for profile in matrix.selected_mutation_profiles] == [("selected-v1", "datasets/mutation_profiles/selected-v1.yaml")]
    assert [(profile.id, profile.path) for profile in matrix.deep_mutation_profiles] == [("deep-v1", "datasets/mutation_profiles/deep-v1.yaml")]
