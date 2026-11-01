from __future__ import annotations

import inspect

import httpx2 as httpx
import pytest

from pr_sentinel.github import REVIEW_EVENT, GitHubClient, GitHubError


def client(handler, sleeps: list[float] | None = None, **kw) -> GitHubClient:  # type: ignore[no-untyped-def]
    recorded = sleeps if sleeps is not None else []
    return GitHubClient("tok", "o/r", transport=httpx.MockTransport(handler), sleep=recorded.append, **kw)


def test_retries_server_errors_then_succeeds() -> None:
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(502) if len(calls) < 3 else httpx.Response(200, json={"ok": True})

    sleeps: list[float] = []
    assert client(handler, sleeps).get_pull(1) == {"ok": True}
    assert len(calls) == 3 and len(sleeps) == 2


def test_honours_retry_after_on_secondary_rate_limit() -> None:
    responses = iter(
        [
            httpx.Response(403, headers={"retry-after": "7"}, json={"message": "secondary rate limit"}),
            httpx.Response(200, json={}),
        ]
    )
    sleeps: list[float] = []
    client(lambda req: next(responses), sleeps).get_pull(1)
    assert sleeps == [7.0]


def test_gives_up_when_rate_limit_reset_is_too_far_away() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"})

    with pytest.raises(GitHubError, match="rate limited"):
        client(handler).get_pull(1)


def test_client_errors_are_not_retried() -> None:
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(404, json={"message": "Not Found"})

    with pytest.raises(GitHubError) as info:
        client(handler).get_pull(1)
    assert info.value.status == 404 and len(calls) == 1
    assert "tok" not in str(info.value)


def test_transport_errors_are_retried() -> None:
    attempts = []

    def handler(req: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) == 1:
            raise httpx.ConnectError("reset", request=req)
        return httpx.Response(200, json={})

    client(handler).get_pull(1)
    assert len(attempts) == 2


def test_pagination_follows_link_header() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        page = int(req.url.params["page"])
        items = [{"n": i} for i in range(100)] if page == 1 else [{"n": 100}]
        headers = {"link": '<https://api.github.com/x?page=2>; rel="next"'} if page == 1 else {}
        return httpx.Response(200, json=items, headers=headers)

    assert len(client(handler).list_pull_files(1)) == 101


def test_reviews_are_always_comment_only() -> None:
    sent = {}

    def handler(req: httpx.Request) -> httpx.Response:
        import json

        sent.update(json.loads(req.content))
        return httpx.Response(200, json={"id": 1})

    client(handler).create_comment_review(1, "a" * 40, "body", [])
    assert sent["event"] == REVIEW_EVENT == "COMMENT"


def test_no_write_methods_beyond_comments() -> None:
    public = {name for name, _ in inspect.getmembers(GitHubClient, inspect.isfunction) if not name.startswith("_")}
    assert public == {
        "close",
        "get_pull",
        "list_pull_files",
        "list_review_comments",
        "list_issue_comments",
        "create_comment_review",
        "create_issue_comment",
        "update_issue_comment",
    }
    src = inspect.getsource(GitHubClient)
    for forbidden in ("APPROVE", "REQUEST_CHANGES", "/merge", "/git/refs", "/contents/"):
        assert forbidden not in src
