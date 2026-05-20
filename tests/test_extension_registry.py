from __future__ import annotations

from pathlib import Path

import pytest

from malleus.registry import extension_pack_registry, load_extension_manifest, register_extension_manifest


def test_extension_manifest_registers_provider_free_contributions(tmp_path: Path) -> None:
    pack = tmp_path / "pack.yaml"
    pack.write_text("name: local-pack\ncases: []\n", encoding="utf-8")
    manifest = tmp_path / "malleus-extension.yaml"
    manifest.write_text(
        """schema_version: malleus.extension_manifest.v1
name: local-extension
version: 0.1.0
provider_calls_enabled: false
network_enabled: false
contributions:
  - id: local-pack
    kind: pack
    path: pack.yaml
    description: Local provider-free pack contribution.
    evidence_level: static_analysis
    target_types: [chat_completion]
""",
        encoding="utf-8",
    )

    loaded = register_extension_manifest(manifest)

    assert loaded.name == "local-extension"
    registered = extension_pack_registry.get("local-pack")
    assert registered.kind == "pack"
    assert registered.evidence_level == "static_analysis"
    assert registered.target_types == ["chat_completion"]


def test_extension_manifest_rejects_provider_network_and_path_escape(tmp_path: Path) -> None:
    provider_manifest = tmp_path / "provider.yaml"
    provider_manifest.write_text(
        """schema_version: malleus.extension_manifest.v1
name: unsafe
provider_calls_enabled: true
contributions: []
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="provider calls"):
        load_extension_manifest(provider_manifest)

    escape_manifest = tmp_path / "escape.yaml"
    escape_manifest.write_text(
        """schema_version: malleus.extension_manifest.v1
name: escape
provider_calls_enabled: false
network_enabled: false
contributions:
  - id: escape
    kind: pack
    path: ../outside.yaml
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="escapes"):
        load_extension_manifest(escape_manifest)
