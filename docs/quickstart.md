# Quickstart

This is the shortest path from an API key or local target to a useful Malleus
report.

## 0. Install

Recommended CLI install:

```bash
pipx install git+https://github.com/IchamRaison/malleus.git
```

From a cloned checkout:

```bash
./scripts/bootstrap
./malleus version
```

Manual contributor install:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## 1. Create a target

Use the guided target flow:

```bash
malleus init
```

The lower-level equivalent is:

```bash
malleus target init
```

The target is saved in the managed target store, so later commands can use the
short target name instead of a full YAML path.

## 2. Check it

```bash
malleus target doctor <target-name> --live-check
```

The doctor checks config shape, credential presence, endpoint reachability when
requested, provider preflight when `--live-check` is supplied, trace coverage for
agent targets, and the exact next benchmark command.

## 3. Run the default live benchmark

```bash
malleus benchmark soft --target <target-name>
```

Malleus creates `reports/<target-name>-soft-<timestamp>/` automatically. Use
`--out-dir reports/<target-name>-soft` only when you want a fixed path.

## 4. Read the result

Start with:

```text
reports/<target-name>-soft-<timestamp>/live-full-summary.md
reports/<target-name>-soft-<timestamp>/live-full-summary.html
reports/<target-name>-soft-<timestamp>/stack-coverage.md
```

Use the dashboard and evidence bundle when you want reviewable local artifacts:

```bash
malleus dashboard --report reports/<target-name>-soft/live-full-evidence.json --out-dir reports/<target-name>-dashboard
malleus evidence-bundle --run-report reports/<target-name>-soft/live-full-evidence.json --out-dir reports/<target-name>-evidence
```

## Copy/Paste Helper

To render the same flow without remembering commands:

```bash
malleus quickstart
malleus quickstart --target <target-name>
```

To check the local installation before a run:

```bash
malleus doctor
```

## Evidence Boundary

Provider errors, target errors, capability gaps, dry-run artifacts, and scaffold
artifacts are not model behavior failures. Malleus reports them separately so a
run can explain whether it tested the model, the agent system, or only the local
fixture/planning path.
