# NVIDIA target notes

Malleus supports NVIDIA API Catalog / NIM-style chat-completions endpoints through the `nvidia` adapter.

## Setup

Create `.env` in the repository root and set your NVIDIA API key plus base URL locally.
Do not paste real keys into committed docs, reports, or examples.

Required variable names:

```text
NVIDIA_API_KEY
NVIDIA_BASE_URL
```

`.env` is gitignored. Do not commit keys.

## Smoke run

```bash
malleus run \
  --target examples/targets/nvidia.yaml \
  --input datasets/benchmark_packs/smoke-v1.yaml \
  --scoring configs/scoring-default.yaml \
  --out-dir reports/nvidia-smoke
```

## Quota-friendly comparison

```bash
malleus compare \
  --target examples/targets/nvidia.yaml \
  --input datasets/benchmark_packs/smoke-v1.yaml \
  --scoring configs/scoring-default.yaml \
  --out-dir reports/nvidia-compare \
  --model nvidia/nemotron-mini-4b-instruct \
  --model meta/llama-3.1-8b-instruct \
  --limit 3
```

Use `--limit` while developing. Add `--live-provider` for real NVIDIA comparison evidence; without it, `malleus compare` writes per-model `dry-run.json` CI/dev plans only. Run larger live packs only after smoke tests, quota checks, and scoring checks are stable.
