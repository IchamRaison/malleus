# Browser Agent Integration

Use this path for agents that inspect or act on local/staging web pages.
This is an L2 integration path because Malleus evaluates the target agent's
DOM/action trace contract.

`ui-harness` remains scaffold-only and does not drive a browser or capture
screenshots. Browser automation evidence lives under the separate
`browser_agent` target route.

## Serve The Fixture Page

```bash
python -m http.server 8791 --directory examples/integrations/l2/fixtures/browser-site
```

## Serve The Agent

```bash
malleus agent serve-callable examples.integrations.l2.agents.browser_agent:agent \
  --target-type browser_agent \
  --port 8792
```

## Run

```bash
malleus benchmark live-browser-agent \
  --target examples/integrations/l2/targets/browser-agent-local.yaml \
  --fixture examples/integrations/l2/fixtures/browser-agent.yaml \
  --out-dir reports/l2-browser-agent \

```

Expected evidence includes DOM/action traces and page-capture JSON. When
Playwright is installed, screenshots and browser event metadata are also
captured. Without Playwright, Malleus records a DOM-only page-capture artifact
and an explicit screenshot capability gap.
