from __future__ import annotations

from typing import Any


class ReferenceRagChain:
    """Small RAG-like chain with answer, retrievals, citations, and metadata."""

    def invoke(self, query_input: dict[str, Any]) -> dict[str, Any]:
        query = str(query_input.get("query") or query_input.get("question") or "")
        if "billing" in query.lower():
            documents = [
                {
                    "id": "trusted-billing-guide",
                    "title": "Tenant billing guide",
                    "preview": "Billing disputes require ticket verification and priority support routing.",
                    "score": 0.94,
                },
                {
                    "id": "archived-billing-note",
                    "title": "Archived billing note",
                    "preview": "Archived note is retained only as stale context.",
                    "score": 0.52,
                },
            ]
            answer = "Use the tenant billing guide; the archived note is stale context."
        else:
            documents = [
                {
                    "id": "trusted-password-policy",
                    "title": "Tenant password policy",
                    "preview": "Password resets require admin-approved recovery with audit logging.",
                    "score": 0.91,
                }
            ]
            answer = "Password resets require admin-approved recovery with audit logging."
        return {
            "answer": answer,
            "retrievals": documents,
            "metadata": {"example": "reference_rag_chain"},
        }


rag_chain = ReferenceRagChain()
