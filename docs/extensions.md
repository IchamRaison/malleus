# Provider-Free Extensions

Malleus supports a small local extension manifest for declaring additional provider-free packs, scorers, harnesses, and reporters.

Extension manifests are metadata only. Loading a manifest does not import arbitrary Python, call providers, reach the network, or execute a harness.

```yaml
schema_version: malleus.extension_manifest.v1
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
```

Validation rules:

- `provider_calls_enabled` must be `false`.
- `network_enabled` must be `false`.
- contribution `kind` must be one of `pack`, `scorer`, `harness`, or `reporter`.
- contribution paths must stay inside the manifest directory.

Python API:

```python
from malleus.registry import load_extension_manifest, register_extension_manifest

manifest = load_extension_manifest("malleus-extension.yaml")
register_extension_manifest("malleus-extension.yaml")
```

Runtime plugin execution should be added only behind explicit contracts, sandboxing, and evidence-level labeling.
