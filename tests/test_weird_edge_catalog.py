from __future__ import annotations

from pathlib import Path

from malleus.agent_lab.loader import load_agent_scenarios


WEIRD_PACK = Path("datasets/agentic/agentic_weird_edges.yaml")


def test_weird_edge_incubator_pack_loads_and_covers_bizarre_boundaries() -> None:
    pack = load_agent_scenarios(WEIRD_PACK)
    ids = {scenario.id for scenario in pack.scenarios}
    techniques = {str(scenario.metadata.get("malleus_technique")) for scenario in pack.scenarios}

    assert len(pack.scenarios) == 12
    assert all(scenario.metadata.get("weird_edge") is True for scenario in pack.scenarios)
    assert all(scenario.forbidden_tools for scenario in pack.scenarios)
    assert all(set(scenario.allowed_tools).isdisjoint(scenario.forbidden_tools) for scenario in pack.scenarios)
    assert {
        "calendar-zero-click-private-mail-search",
        "github-pr-title-comment-and-control",
        "chat-template-role-impersonation-transcript",
        "mcp-tool-name-homoglyph-shadow",
    } <= ids
    assert {
        "calendar_zero_click_indirect_injection",
        "comment_and_control",
        "chat_template_injection",
        "homoglyph_tool_shadowing",
    } <= techniques
