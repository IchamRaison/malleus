from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from malleus.studio_runtime import (
    StudioProviderDiscoverRequest,
    StudioProviderKeyRequest,
    StudioRunManager,
    StudioRunRequest,
    StudioScanRunRequest,
    StudioScanPlanRequest,
    apply_studio_provider_keys,
    build_studio_scan_plan,
    delete_studio_provider_key,
    discover_provider_models,
    list_studio_provider_key_statuses,
    list_studio_attacks,
    list_studio_providers,
    list_studio_scan_profiles,
    list_studio_targets,
    render_studio_run_export_html,
    resolve_studio_run_artifact,
    save_studio_provider_key,
)


def _studio_cors_origins() -> list[str]:
    default_origins = ["http://127.0.0.1:3000", "http://localhost:3000"]
    configured = os.environ.get("MALLEUS_STUDIO_CORS_ORIGINS", "")
    extra_origins = [origin.strip().rstrip("/") for origin in configured.split(",") if origin.strip()]
    return [*default_origins, *extra_origins]


def create_studio_app(
    *,
    runs_root: str | Path = "reports/studio-runs",
    target_dir: str | Path | None = None,
    session_target_dir: str | Path = ".malleus/studio/targets",
    provider_keys_path: str | Path = ".malleus/studio/provider-keys.json",
) -> Any:
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
    except ImportError as exc:  # pragma: no cover - exercised through CLI boundary
        raise RuntimeError("Malleus Studio server requires the 'studio' optional dependencies: pip install -e '.[studio]'") from exc

    apply_studio_provider_keys(provider_keys_path)
    manager = StudioRunManager(root=runs_root, target_dir=target_dir, session_target_dir=session_target_dir)
    app = FastAPI(title="Malleus Studio API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_studio_cors_origins(),
        allow_origin_regex=r"https?://(127\.0\.0\.1|localhost):\d+",
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health() -> dict[str, object]:
        return {"ok": True, "service": "malleus-studio-api"}

    @app.get("/api/targets")
    def targets() -> dict[str, object]:
        return {"targets": [target.model_dump(mode="json") for target in list_studio_targets(target_dir, session_target_dir)]}

    @app.get("/api/attacks")
    def attacks() -> dict[str, object]:
        return {"attacks": [attack.model_dump(mode="json") for attack in list_studio_attacks()]}

    @app.get("/api/scan-profiles")
    def scan_profiles() -> dict[str, object]:
        return {"profiles": [profile.model_dump(mode="json") for profile in list_studio_scan_profiles()]}

    @app.post("/api/scan-plan")
    def scan_plan(request: StudioScanPlanRequest) -> dict[str, object]:
        try:
            plan = build_studio_scan_plan(request, target_dir=target_dir, session_target_dir=session_target_dir)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"plan": plan.model_dump(mode="json")}

    @app.get("/api/providers")
    def providers() -> dict[str, object]:
        return {"providers": [provider.model_dump(mode="json") for provider in list_studio_providers()]}

    @app.get("/api/provider-keys")
    def provider_keys() -> dict[str, object]:
        return {"provider_keys": [status.model_dump(mode="json") for status in list_studio_provider_key_statuses(provider_keys_path)]}

    @app.put("/api/provider-keys/{provider_id}")
    def save_provider_key(provider_id: str, request: StudioProviderKeyRequest) -> dict[str, object]:
        try:
            status = save_studio_provider_key(provider_id, request.api_key, provider_keys_path)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"provider_key": status.model_dump(mode="json")}

    @app.delete("/api/provider-keys/{provider_id}")
    def delete_provider_key(provider_id: str) -> dict[str, object]:
        try:
            status = delete_studio_provider_key(provider_id, provider_keys_path)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"provider_key": status.model_dump(mode="json")}

    @app.post("/api/providers/{provider_id}/discover")
    def discover_provider(provider_id: str, request: StudioProviderDiscoverRequest) -> dict[str, object]:
        try:
            result = discover_provider_models(
                provider_id,
                request,
                session_target_dir=session_target_dir,
                provider_keys_path=provider_keys_path,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return result.model_dump(mode="json")

    @app.post("/api/runs")
    def create_run(request: StudioRunRequest) -> dict[str, object]:
        try:
            summary = manager.create_run(request)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"run": summary.model_dump(mode="json")}

    @app.post("/api/scan-runs")
    def create_scan_run(request: StudioScanRunRequest) -> dict[str, object]:
        try:
            summary = manager.create_scan_run(request)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"run": summary.model_dump(mode="json")}

    @app.get("/api/runs")
    def runs() -> dict[str, object]:
        return {"runs": [run.model_dump(mode="json") for run in manager.list_runs()]}

    @app.get("/api/run-history")
    def run_history(limit: int = 50) -> dict[str, object]:
        bounded_limit = max(1, min(limit, 200))
        return {"runs": [item.model_dump(mode="json") for item in manager.list_history()[:bounded_limit]]}

    @app.get("/api/runs/{run_id}")
    def run_detail(run_id: str) -> dict[str, object]:
        try:
            summary = manager.get_run(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return {"run": summary.model_dump(mode="json")}

    @app.get("/api/runs/{run_id}/events.json")
    def run_events_json(run_id: str, limit: int = 1000) -> dict[str, object]:
        try:
            events = manager.events_for_run(run_id, limit=max(1, min(limit, 5000)))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return {"events": [event.model_dump(mode="json") for event in events]}

    @app.get("/api/runs/{run_id}/artifact")
    def run_artifact(run_id: str, path: str) -> FileResponse:
        try:
            artifact = resolve_studio_run_artifact(runs_root, run_id, path)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="artifact not found") from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return FileResponse(artifact, filename=artifact.name)

    @app.get("/api/runs/{run_id}/export.json")
    def run_export_json(run_id: str) -> JSONResponse:
        try:
            export = manager.export_run(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return JSONResponse(export.model_dump(mode="json"))

    @app.get("/api/runs/{run_id}/export.html")
    def run_export_html(run_id: str) -> HTMLResponse:
        try:
            export = manager.export_run(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return HTMLResponse(render_studio_run_export_html(export))

    @app.post("/api/runs/{run_id}/cancel")
    def cancel_run(run_id: str) -> dict[str, object]:
        try:
            summary = manager.cancel_run(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc
        return {"run": summary.model_dump(mode="json")}

    @app.get("/api/runs/{run_id}/events")
    async def run_events(run_id: str, since: int = 0) -> StreamingResponse:
        try:
            manager.get_run(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="run not found") from exc

        async def stream():
            sequence = since
            while True:
                emitted = False
                for event in manager.events_since(run_id, sequence):
                    sequence = event.sequence
                    emitted = True
                    yield _sse("studio.event", event.model_dump(mode="json"))
                summary = manager.get_run(run_id)
                if summary.status in {"completed", "failed", "cancelled"} and not emitted:
                    yield _sse("studio.done", summary.model_dump(mode="json"))
                    break
                if not emitted:
                    await asyncio.sleep(0.5)

        return StreamingResponse(stream(), media_type="text/event-stream")

    return app


def run_studio_server(*, host: str = "127.0.0.1", port: int = 8765, runs_root: str | Path = "reports/studio-runs", target_dir: str | Path | None = None) -> None:
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - exercised through CLI boundary
        raise RuntimeError("Malleus Studio server requires uvicorn: pip install -e '.[studio]'") from exc
    app = create_studio_app(runs_root=runs_root, target_dir=target_dir)
    uvicorn.run(app, host=host, port=port, log_level="info")


def _sse(event: str, payload: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False, sort_keys=True)}\n\n"
