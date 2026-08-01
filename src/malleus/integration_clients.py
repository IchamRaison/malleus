from __future__ import annotations

from typing import Any, Literal
from urllib.parse import quote

import httpx


def submit_issue(
    *,
    platform: Literal["github", "gitlab", "jira"],
    base_url: str,
    project: str,
    token: str,
    payload: dict[str, Any],
    timeout: float = 30.0,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    base = base_url.rstrip("/")
    if platform == "github":
        url = f"{base}/repos/{project}/issues"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    elif platform == "gitlab":
        url = f"{base}/api/v4/projects/{quote(project, safe='')}/issues"
        headers = {"PRIVATE-TOKEN": token}
    else:
        url = f"{base}/rest/api/3/issue"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    with httpx.Client(timeout=timeout, transport=transport) as client:
        response = client.post(url, headers=headers, json=payload)
    if response.status_code >= 400:
        raise RuntimeError(f"{platform} issue submission failed with HTTP {response.status_code}")
    result = response.json()
    if not isinstance(result, dict):
        raise RuntimeError(f"{platform} issue submission returned a non-object response")
    return result
