import httpx

from malleus.integration_clients import submit_issue


def test_submit_github_issue_uses_project_endpoint_and_bearer_token() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["authorization"] = request.headers["Authorization"]
        return httpx.Response(201, json={"number": 42})

    result = submit_issue(
        platform="github",
        base_url="https://api.github.test",
        project="acme/agent",
        token="secret",
        payload={"title": "Finding"},
        transport=httpx.MockTransport(handler),
    )

    assert result == {"number": 42}
    assert captured == {
        "url": "https://api.github.test/repos/acme/agent/issues",
        "authorization": "Bearer secret",
    }


def test_submit_gitlab_issue_url_encodes_project() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.raw_path == b"/api/v4/projects/acme%2Fagent/issues"
        assert request.headers["PRIVATE-TOKEN"] == "secret"
        return httpx.Response(201, json={"iid": 7})

    result = submit_issue(
        platform="gitlab",
        base_url="https://gitlab.test",
        project="acme/agent",
        token="secret",
        payload={"title": "Finding"},
        transport=httpx.MockTransport(handler),
    )
    assert result["iid"] == 7
