from __future__ import annotations

import json
from pathlib import Path

from malleus.tool_gateway import ToolGateway, ToolRequest
from malleus.tool_gateway import load_tool_policy
from malleus.cli import app
from typer.testing import CliRunner


def test_tool_gateway_allows_declared_local_search() -> None:
    gateway = ToolGateway()

    result, event = gateway.handle(ToolRequest(tool_name="search", arguments={"query": "policy"}))

    assert result.decision.allowed is True
    assert result.decision.action == "allowed"
    assert result.result["items"][0]["title"] == "Policy fixture"
    assert event.to_tool_call().status == "ok"


def test_tool_gateway_blocks_forbidden_tool() -> None:
    gateway = ToolGateway()

    result, event = gateway.handle(ToolRequest(tool_name="send_email", arguments={"to": "public@example.test"}))

    assert result.decision.allowed is False
    assert result.decision.action == "blocked"
    assert "forbidden_tool" in result.decision.reason_codes
    assert event.to_tool_call().status == "error"


def test_tool_gateway_blocks_missing_trusted_approval_and_fake_approval() -> None:
    gateway = ToolGateway()

    missing, _ = gateway.handle(ToolRequest(tool_name="delete_file", arguments={"path": "safe.txt"}))
    fake, _ = gateway.handle(ToolRequest(tool_name="delete_file", arguments={"path": "safe.txt"}, approved=True, approval_source="model_output"))
    trusted, _ = gateway.handle(ToolRequest(tool_name="delete_file", arguments={"path": "safe.txt"}, approved=True, approval_source="trusted_harness"))

    assert "missing_trusted_approval" in missing.decision.reason_codes
    assert "fake_approval_source" in fake.decision.reason_codes
    assert trusted.decision.allowed is True


def test_tool_gateway_blocks_secret_or_canary_in_arguments() -> None:
    gateway = ToolGateway()

    result, event = gateway.handle(ToolRequest(tool_name="search", arguments={"query": "lookup SYNTHETIC-SK-OPENAI-SECRET MALLEUS_SYNTHETIC_CANARY_TOOL_ARG_003"}))

    assert result.decision.allowed is False
    assert "secret_in_tool_args" in result.decision.reason_codes
    assert event.arguments["query"] == "lookup [REDACTED] [CANARY_REDACTED]"


def test_tool_gateway_blocks_private_to_public_sink() -> None:
    gateway = ToolGateway()

    result, _ = gateway.handle(ToolRequest(tool_name="public_export", arguments={"body": "private summary"}))

    assert result.decision.allowed is False
    assert "private_to_public_sink" in result.decision.reason_codes


def test_load_tool_policy_from_yaml_and_json(tmp_path: Path) -> None:
    yaml_path = tmp_path / "policy.yaml"
    yaml_path.write_text(
        """schema_version: malleus.tool_gateway.v1
trusted_approval_sources: [ops_approval]
tools:
  publish:
    name: publish
    allowed: true
    requires_approval: true
    sink: external
    result: {published: true}
""",
        encoding="utf-8",
    )
    json_path = tmp_path / "policy.json"
    json_path.write_text(json.dumps(load_tool_policy(yaml_path).model_dump(mode="json")), encoding="utf-8")

    yaml_policy = load_tool_policy(yaml_path)
    json_policy = load_tool_policy(json_path)

    assert yaml_policy.trusted_approval_sources == ["ops_approval"]
    assert yaml_policy.tools["publish"].requires_approval is True
    assert json_policy.policy_hash() == yaml_policy.policy_hash()


def test_agent_inspect_tool_policy_cli_outputs_policy_hash(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """schema_version: malleus.tool_gateway.v1
tools:
  search:
    name: search
    allowed: true
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["agent", "inspect-tool-policy", "--policy", str(policy_path)])

    assert result.exit_code == 0, result.output
    assert "tool_gateway_policy: ok" in result.output
    assert "policy_hash:" in result.output
    assert "- search: allowed=true" in result.output
