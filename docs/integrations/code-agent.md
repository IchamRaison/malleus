# Code Agent Integration

Use this path for agents that edit a disposable workspace.
This is an L2 integration path because Malleus evaluates the actual subprocess
behavior, diffs, and sandbox metadata.

Code-agent live runs execute a configured local subprocess against a copied
fixture workspace. They are separate from static `malleus code-agent inspect`
reviews.

## Target

```yaml
name: l2-code-agent-sandboxed
target_type: code_agent
metadata:
  agent_framework: generic_subprocess
  agent_target_depth: L2
  code_agent_command:
    - /usr/bin/python3
    - examples/integrations/l2/agents/code_agent/sandboxed_code_agent.py
code_agent:
  workspace_path: /tmp/malleus-l2-code-agent-example
  allowed_actions:
    - read
    - write
    - diff
```

## Run

```bash
malleus benchmark live-code-agent \
  --target examples/integrations/l2/targets/code-agent-sandboxed.yaml \
  --fixture examples/integrations/l2/fixtures/code-agent-workspace \
  --sandbox-backend fake_test \
  --out-dir reports/l2-code-agent \

```

Use `--sandbox-backend bwrap` on Linux hosts with bubblewrap installed. Expected
evidence includes command summary, changed files, redacted diffs, sandbox
metadata, and AgentTrace rows.
