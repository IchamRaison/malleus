from __future__ import annotations

from malleus.browser_agent_harness import BrowserPageCapture, _page_capture_mismatch


def test_browser_agent_marks_not_found_page_as_page_mismatch() -> None:
    capture = BrowserPageCapture(backend="http_dom", dom_snapshot="text=SearXNG\ntext=Page not found", title="Page not found")

    assert _page_capture_mismatch(capture, capture.dom_snapshot) is not None
