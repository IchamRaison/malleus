from __future__ import annotations

import json
from pathlib import Path

from malleus.compare import write_comparison_report
from malleus.runner import run_benchmark

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reports" / "wow-benchmark"
TARGET_TEMPLATE = ROOT / "examples" / "targets" / "nvidia.yaml"
INPUT = ROOT / "datasets" / "benchmark_packs" / "smoke-v1.yaml"
SCORING = ROOT / "configs" / "scoring-default.yaml"

# Diverse NVIDIA Build/API Catalog panel: NVIDIA + partner publishers.
# Chosen from https://build.nvidia.com/models and verified against /v1/models.
MODELS = [
    "nvidia/nemotron-mini-4b-instruct",
    "meta/llama-3.2-3b-instruct",
    "mistralai/mistral-small-4-119b-2603",
    "google/gemma-3n-e2b-it",
    "qwen/qwen3-next-80b-a3b-instruct",
    "microsoft/phi-4-mini-instruct",
    "minimaxai/minimax-m2.7",
    "z-ai/glm4.7",
]


def slug(model: str) -> str:
    return model.replace("/", "__").replace(":", "_")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    import yaml

    target_data = yaml.safe_load(TARGET_TEMPLATE.read_text(encoding="utf-8"))
    results = []
    report_paths = []
    for model in MODELS:
        model_slug = slug(model)
        target = dict(target_data)
        target["name"] = f"wow-{model_slug}"
        target["model"] = model
        target.setdefault("request", {})["max_tokens"] = 128
        target.setdefault("request", {})["timeout"] = 90
        target_path = OUT / f"target-{model_slug}.yaml"
        target_path.write_text(yaml.safe_dump(target, sort_keys=False), encoding="utf-8")
        model_out = OUT / model_slug
        print(f"\n=== Running {model} ===", flush=True)
        try:
            report = run_benchmark(target_path, INPUT, SCORING, model_out)
            report_path = model_out / "report.json"
            report_paths.append(report_path)
            results.append(
                {
                    "model": model,
                    "status": "ok",
                    "score_total": report.summary.score_total,
                    "max_score_total": report.summary.max_score_total,
                    "passed_items": report.summary.passed_items,
                    "total_items": report.summary.total_items,
                    "report": str(report_path.relative_to(ROOT)),
                }
            )
            print(f"OK {model}: {report.summary.score_total}/{report.summary.max_score_total}", flush=True)
        except Exception as exc:  # noqa: BLE001 - benchmark harness should continue across model failures
            results.append({"model": model, "status": "error", "error": f"{type(exc).__name__}: {exc}"})
            print(f"ERROR {model}: {type(exc).__name__}: {exc}", flush=True)
    (OUT / "run-summary.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    if report_paths:
        write_comparison_report(report_paths, OUT)
    print("\nDone. Summary:")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
