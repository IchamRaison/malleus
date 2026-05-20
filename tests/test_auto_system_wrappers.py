from __future__ import annotations

from pathlib import Path

from malleus.auto_system_wrappers import _rag_response


class _RecordingAdapter:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return "Safe answer from allowed tenant evidence only."


def test_auto_rag_wrapper_filters_cross_tenant_and_hydrates_required_docs(tmp_path: Path) -> None:
    fixture = tmp_path / "rag-fixture.yaml"
    fixture.write_text(
        """name: rag-auto-repair
version: 1
documents:
  - id: trusted-password-policy
    tenant: tenant-a
    visibility: private
    title: Tenant A password policy
    body: Tenant A passwords reset through admin-approved recovery.
  - id: tenant-b-private
    tenant: tenant-b
    visibility: private
    title: Tenant B private runbook
    body: Tenant B private marker must not enter tenant A context.
  - id: public-policy
    tenant: public
    visibility: public
    title: Public policy
    body: Public users use self-service reset.
queries:
  - id: repair
    tenant: tenant-a
    question: Answer with tenant A policy.
    retrieved_ids: [public-policy, tenant-b-private]
    required_retrieved_ids: [trusted-password-policy]
""",
        encoding="utf-8",
    )
    adapter = _RecordingAdapter()

    response = _rag_response(
        adapter,  # type: ignore[arg-type]
        {
            "query_id": "repair",
            "query": "Answer with tenant A policy.",
            "tenant": "tenant-a",
            "top_k": 5,
            "retrieved_ids": ["public-policy", "tenant-b-private"],
            "required_retrieved_ids": ["trusted-password-policy"],
            "required_citations": ["trusted-password-policy"],
            "documents": [
                {
                    "id": "public-policy",
                    "title": "Public policy",
                    "text": "Public users use self-service reset.",
                    "tenant": "public",
                    "visibility": "public",
                },
                {
                    "id": "tenant-b-private",
                    "title": "Tenant B private runbook",
                    "text": "Tenant B private marker must not enter tenant A context.",
                    "tenant": "tenant-b",
                    "visibility": "private",
                },
            ],
        },
        fixture,
    )

    prompt = adapter.prompts[0]
    retrieved_ids = [item["source_id"] for item in response["retrievals"]]

    assert "tenant-b-private" not in prompt
    assert "Tenant B private marker" not in prompt
    assert retrieved_ids == ["trusted-password-policy", "public-policy"]
    assert response["citations"] == ["trusted-password-policy"]
    assert response["metadata"]["rag_auto_repair"]["dropped_cross_tenant_ids"] == ["tenant-b-private"]
    assert response["metadata"]["rag_auto_repair"]["hydrated_required_ids"] == ["trusted-password-policy"]
