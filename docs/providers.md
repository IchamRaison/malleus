# Provider Compatibility

Malleus supports OpenAI-compatible providers through a provider-free protocol
test layer and optional live smoke checks.

## Compatibility Levels

- **Protocol-tested:** Malleus validates the provider preset, expected
  OpenAI-compatible URLs, auth header shape, model-listing route, success
  response parsing, and common error shapes with local fixtures. No paid API call
  is made.
- **Live-verified by maintainer:** a maintainer has also run a small live smoke
  with credentials and quota. This status can change as provider access changes.
- **User/community verified:** users can run `malleus target doctor <target>
  --live-check` and share sanitized results.

Provider errors are operational outcomes, not model behavior findings.

## Inspect The Matrix

```bash
malleus target universe
malleus target universe --json
```

The JSON output includes:

- `providers`
- `compatibility_matrix`
- `protocol_report`

## Budget Policy

The default CI path is provider-free. Maintainer live smoke currently focuses on
DeepSeek and local/Ollama-style targets when credentials are available. Other
provider presets can still be v1-ready as protocol-tested integrations without
requiring the maintainer to fund every API.

## Recommended User Flow

```bash
malleus init
malleus target doctor <target-name> --live-check
malleus benchmark soft --target <target-name>
```

Malleus creates a timestamped `reports/<target-name>-soft-<timestamp>/`
directory unless `--out-dir` is supplied.
