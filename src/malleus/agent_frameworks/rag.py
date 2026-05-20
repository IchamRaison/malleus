from __future__ import annotations

from typing import Any, Literal

from malleus.agent_adapter import AgentAdapterError, AgentRequest, AgentResponse, BaseAgentAdapter, LoadedAgentAdapter, load_import_object, serve_loaded_agent_adapter
from malleus.agent_target_contracts import SURFACE_CONTRACTS
from malleus.schemas import HarnessRetrieval
from malleus.utils.redact import redact_public_text


RagInputMode = Literal["query", "payload", "mapping"]
RagRunMode = Literal["auto", "invoke", "query", "retrieve", "call"]


class _BaseRagAdapter(BaseAgentAdapter):
    target_type = "rag_service"

    def __init__(self, obj: Any, *, input_mode: RagInputMode = "query", run_mode: RagRunMode = "auto", top_k: int | None = None) -> None:
        self.obj = obj
        self.input_mode = input_mode
        self.run_mode = run_mode
        self.top_k = top_k

    def run(self, request: AgentRequest) -> AgentResponse:
        query = str(request.payload.get("query") or request.payload.get("question") or request.payload.get("user_task") or "")
        output = self._execute(query, request.payload)
        return _response_from_rag_output(output, framework=self.framework, query=query, input_mode=self.input_mode, run_mode=self.run_mode)

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "target_type": self.target_type,
            "framework": self.framework,
            "input_mode": self.input_mode,
            "run_mode": self.run_mode,
            "object_type": type(self.obj).__name__,
        }

    def _execute(self, query: str, payload: dict[str, Any]) -> Any:
        if self.run_mode in {"auto", "retrieve"}:
            retriever = self.obj if _looks_like_retriever(self.obj) else getattr(self.obj, "retriever", None)
            if retriever is None and hasattr(self.obj, "as_retriever"):
                retriever = self.obj.as_retriever()
            if retriever is not None and self.run_mode == "retrieve":
                return {"answer": "", "retrievals": _retrieve(retriever, query)}
        if self.run_mode in {"auto", "query"} and hasattr(self.obj, "query"):
            return self.obj.query(query)
        if self.run_mode in {"auto", "invoke"} and hasattr(self.obj, "invoke"):
            return self.obj.invoke(_input_value(query, payload, self.input_mode))
        if self.run_mode in {"auto", "retrieve"}:
            retriever = self.obj if _looks_like_retriever(self.obj) else getattr(self.obj, "retriever", None)
            if retriever is None and hasattr(self.obj, "as_retriever"):
                retriever = self.obj.as_retriever()
            if retriever is not None:
                return {"answer": "", "retrievals": _retrieve(retriever, query)}
        if self.run_mode in {"auto", "call"} and callable(self.obj):
            return self.obj(_input_value(query, payload, self.input_mode))
        raise AgentAdapterError(f"{self.framework} RAG object must expose query(), invoke(), retriever/get_relevant_documents(), or be callable")


class LangChainRagAdapter(_BaseRagAdapter):
    """Malleus L2 adapter for LangChain chains and retrievers."""

    framework = "langchain"


class LlamaIndexRagAdapter(_BaseRagAdapter):
    """Malleus L2 adapter for LlamaIndex query engines, retrievers, and indexes."""

    framework = "llamaindex"


def load_langchain_rag_adapter(
    import_path: str,
    *,
    input_mode: RagInputMode = "mapping",
    run_mode: RagRunMode = "auto",
    route: str | None = None,
) -> LoadedAgentAdapter:
    return _load_rag_adapter(import_path, adapter_cls=LangChainRagAdapter, input_mode=input_mode, run_mode=run_mode, route=route)


def load_llamaindex_rag_adapter(
    import_path: str,
    *,
    input_mode: RagInputMode = "query",
    run_mode: RagRunMode = "auto",
    route: str | None = None,
) -> LoadedAgentAdapter:
    return _load_rag_adapter(import_path, adapter_cls=LlamaIndexRagAdapter, input_mode=input_mode, run_mode=run_mode, route=route)


def serve_langchain_rag_adapter(import_path: str, *, input_mode: RagInputMode = "mapping", run_mode: RagRunMode = "auto", host: str = "127.0.0.1", port: int = 8787, route: str | None = None) -> None:
    loaded = load_langchain_rag_adapter(import_path, input_mode=input_mode, run_mode=run_mode, route=route)
    serve_loaded_agent_adapter(loaded, host=host, port=port)


def serve_llamaindex_rag_adapter(import_path: str, *, input_mode: RagInputMode = "query", run_mode: RagRunMode = "auto", host: str = "127.0.0.1", port: int = 8787, route: str | None = None) -> None:
    loaded = load_llamaindex_rag_adapter(import_path, input_mode=input_mode, run_mode=run_mode, route=route)
    serve_loaded_agent_adapter(loaded, host=host, port=port)


def _load_rag_adapter(import_path: str, *, adapter_cls: type[_BaseRagAdapter], input_mode: str, run_mode: str, route: str | None) -> LoadedAgentAdapter:
    if input_mode not in {"query", "payload", "mapping"}:
        raise AgentAdapterError("RAG input_mode must be query, payload, or mapping")
    if run_mode not in {"auto", "invoke", "query", "retrieve", "call"}:
        raise AgentAdapterError("RAG run_mode must be auto, invoke, query, retrieve, or call")
    obj = load_import_object(import_path)
    adapter = adapter_cls(obj, input_mode=input_mode, run_mode=run_mode)  # type: ignore[arg-type]
    contract = SURFACE_CONTRACTS["rag_service"]
    return LoadedAgentAdapter(import_path=import_path, adapter=adapter, target_type="rag_service", framework=adapter.framework, route=route or contract.default_endpoint_path or "/malleus/rag")


def _input_value(query: str, payload: dict[str, Any], input_mode: str) -> Any:
    if input_mode == "payload":
        return dict(payload)
    if input_mode == "mapping":
        mapping = {
            "query": query,
            "question": query,
            "input": query,
            "tenant": payload.get("tenant"),
            "top_k": payload.get("top_k"),
        }
        for key in (
            "query_id",
            "retrieved_ids",
            "documents",
            "retrieved_documents",
            "contexts",
            "required_retrieved_ids",
            "required_citations",
            "forbidden_citations",
            "index_name",
            "target_tenant_id",
        ):
            if key in payload:
                mapping[key] = payload[key]
        return mapping
    return query


def _looks_like_retriever(obj: Any) -> bool:
    return any(hasattr(obj, name) for name in ("get_relevant_documents", "aget_relevant_documents", "retrieve"))


def _retrieve(retriever: Any, query: str) -> list[Any]:
    if hasattr(retriever, "get_relevant_documents"):
        return retriever.get_relevant_documents(query)
    if hasattr(retriever, "retrieve"):
        return retriever.retrieve(query)
    if hasattr(retriever, "invoke"):
        result = retriever.invoke(query)
        return result if isinstance(result, list) else [result]
    return []


def _response_from_rag_output(output: Any, *, framework: str, query: str, input_mode: str, run_mode: str) -> AgentResponse:
    answer = _answer(output)
    retrieval_items = _retrieval_items(output)
    retrievals = [_retrieval(item, index, framework=framework) for index, item in enumerate(retrieval_items)]
    retrievals = [item for item in retrievals if item is not None]
    citations = [{"source_id": item.source_id} for item in retrievals]
    output_metadata = _output_metadata(output)
    return AgentResponse(
        final_answer=answer,
        answer=answer,
        retrievals=retrievals,
        citations=citations,
        metadata={
            **output_metadata,
            "agent_framework": framework,
            "agent_target_depth": "L2",
            "target_type": "rag_service",
            "input_mode": input_mode,
            "run_mode": run_mode,
            "query_length": len(query),
            "retrieval_count": len(retrievals),
        },
    )


def _answer(output: Any) -> str:
    if isinstance(output, str):
        return output
    value = _first_string(output, ("answer", "result", "response", "output", "output_text", "text", "final_answer"))
    if value:
        return value
    response = _get(output, "response")
    if isinstance(response, str):
        return response
    return str(output) if output is not None and not isinstance(output, (dict, list)) else ""


def _retrieval_items(output: Any) -> list[Any]:
    if isinstance(output, list):
        return output
    items: list[Any] = []
    for key in ("retrievals", "retrieved_documents", "documents", "source_documents", "contexts", "source_nodes", "nodes", "citations"):
        value = _get(output, key)
        if isinstance(value, list):
            items.extend(value)
    source_nodes = _get(output, "source_nodes")
    if source_nodes and not isinstance(source_nodes, list):
        items.append(source_nodes)
    return items


def _retrieval(item: Any, index: int, *, framework: str) -> HarnessRetrieval | None:
    raw = _model_dump(item)
    node = _get(raw, "node") or _get(item, "node")
    if node is not None:
        raw_node = _model_dump(node)
        raw = {**(raw if isinstance(raw, dict) else {}), **(raw_node if isinstance(raw_node, dict) else {})}
    if isinstance(raw, str):
        return HarnessRetrieval(source_id=raw, metadata={"source": framework})
    if not isinstance(raw, dict):
        return None
    metadata = _metadata(raw)
    source_id = _first_string(raw, ("source_id", "id", "doc_id", "document_id", "node_id", "ref_doc_id", "citation")) or _first_string(metadata, ("source_id", "id", "doc_id", "document_id")) or f"{framework}-source-{index + 1}"
    preview = _first_string(raw, ("redacted_preview", "preview", "excerpt", "snippet", "page_content", "text", "content")) or _first_string(metadata, ("preview", "excerpt", "title"))
    score = _score(raw)
    return HarnessRetrieval(
        source_id=source_id,
        title=_first_string(raw, ("title", "name")) or _first_string(metadata, ("title", "name")) or None,
        uri=_first_string(raw, ("uri", "url", "source")) or _first_string(metadata, ("uri", "url", "source")) or None,
        score=score,
        redacted_preview=redact_public_text(preview, limit=180).text if preview else None,
        citation=_first_string(raw, ("citation", "citation_id")) or source_id,
        metadata={"source": framework},
    )


def _metadata(raw: dict[str, Any]) -> dict[str, Any]:
    for key in ("metadata", "extra_info", "node_info"):
        value = raw.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _output_metadata(output: Any) -> dict[str, Any]:
    raw = _model_dump(output)
    if isinstance(raw, dict) and isinstance(raw.get("metadata"), dict):
        return dict(raw["metadata"])
    return {}


def _score(raw: dict[str, Any]) -> float | None:
    for key in ("score", "similarity", "relevance_score"):
        value = raw.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return None


def _get(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        return value.get(key)
    return getattr(value, key, None)


def _model_dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict") and callable(value.dict):
        return value.dict()
    if hasattr(value, "__dict__") and not isinstance(value, type):
        return dict(value.__dict__)
    return value


def _first_string(value: Any, keys: tuple[str, ...]) -> str:
    value = _model_dump(value)
    if not isinstance(value, dict):
        return str(value) if isinstance(value, str) else ""
    for key in keys:
        item = value.get(key)
        if isinstance(item, str) and item:
            return item
    return ""


__all__ = [
    "LangChainRagAdapter",
    "LlamaIndexRagAdapter",
    "load_langchain_rag_adapter",
    "load_llamaindex_rag_adapter",
    "serve_langchain_rag_adapter",
    "serve_llamaindex_rag_adapter",
]
