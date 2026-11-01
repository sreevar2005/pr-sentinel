"""Minimal GitHub REST client.

The write surface is deliberately tiny: a COMMENT review and one summary issue comment.
There are no methods to approve, request changes, merge, push, label, or edit code, so
no bug or prompt-injection elsewhere can make PR Sentinel do those things. The workflow
token is additionally scoped to `pull-requests: write` + read-only contents.
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx2 as httpx

log = logging.getLogger(__name__)

API_VERSION = "2022-11-28"
REVIEW_EVENT = "COMMENT"  # the only review event PR Sentinel ever sends


class GitHubError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class GitHubClient:
    def __init__(
        self,
        token: str,
        repository: str,
        api_url: str = "https://api.github.com",
        *,
        timeout: float = 30.0,
        max_retries: int = 4,
        max_wait_seconds: float = 60.0,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if "/" not in repository:
            raise ValueError("repository must be 'owner/name'")
        self.repository = repository
        self._max_retries = max_retries
        self._max_wait = max_wait_seconds
        self._sleep = sleep
        self._http = httpx.Client(
            base_url=api_url.rstrip("/"),
            timeout=timeout,
            transport=transport,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "pr-sentinel",
            },
        )

    def close(self) -> None:
        self._http.close()

    # -- transport -------------------------------------------------------------------------

    def _retry_delay(self, resp: httpx.Response | None, attempt: int) -> float | None:
        """Seconds to wait before retrying, or None if the response is not retryable."""
        backoff = min(2.0**attempt, 30.0) + random.uniform(0, 0.5)  # noqa: S311 - jitter, not crypto
        if resp is None:
            return backoff
        if resp.status_code >= 500:
            return backoff
        if resp.status_code in (403, 429):
            retry_after = resp.headers.get("retry-after")
            if retry_after and retry_after.isdigit():
                return float(retry_after)
            if resp.headers.get("x-ratelimit-remaining") == "0":
                reset = float(resp.headers.get("x-ratelimit-reset", "0"))
                return max(reset - time.time(), 1.0)
            if resp.status_code == 429 or "secondary rate limit" in resp.text.lower():
                return max(backoff, 60.0)
        return None

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        for attempt in range(self._max_retries + 1):
            resp: httpx.Response | None
            try:
                resp = self._http.request(method, path, **kwargs)
            except httpx.TransportError as exc:
                resp = None
                error: str = type(exc).__name__
            else:
                if resp.status_code < 400:
                    return resp
                error = f"HTTP {resp.status_code}"
            delay = self._retry_delay(resp, attempt)
            if delay is None or attempt == self._max_retries:
                break
            if delay > self._max_wait:
                raise GitHubError(f"{method} {path}: rate limited for {delay:.0f}s, giving up", 429)
            log.info("GitHub %s %s -> %s; retrying in %.1fs", method, path, error, delay)
            self._sleep(delay)
        status = resp.status_code if resp is not None else None
        detail = ""
        if resp is not None:
            try:
                detail = str(resp.json().get("message", ""))[:200]
            except ValueError:
                detail = resp.text[:200]
        raise GitHubError(f"{method} {path} failed: {error} {detail}".strip(), status)

    def _paginate(self, path: str, max_pages: int = 30) -> Iterator[dict[str, Any]]:
        for page in range(1, max_pages + 1):
            resp = self._request("GET", path, params={"per_page": 100, "page": page})
            items = resp.json()
            if not isinstance(items, list):
                raise GitHubError(f"GET {path}: expected a list")
            yield from items
            if len(items) < 100 or 'rel="next"' not in resp.headers.get("link", ""):
                return

    # -- reads -----------------------------------------------------------------------------

    def get_pull(self, number: int) -> dict[str, Any]:
        data: dict[str, Any] = self._request("GET", f"/repos/{self.repository}/pulls/{number}").json()
        return data

    def list_pull_files(self, number: int) -> list[dict[str, Any]]:
        # GitHub caps this endpoint at 3000 files; patches are omitted for large/binary files.
        return list(self._paginate(f"/repos/{self.repository}/pulls/{number}/files"))

    def list_review_comments(self, number: int) -> list[dict[str, Any]]:
        return list(self._paginate(f"/repos/{self.repository}/pulls/{number}/comments"))

    def list_issue_comments(self, number: int) -> list[dict[str, Any]]:
        return list(self._paginate(f"/repos/{self.repository}/issues/{number}/comments"))

    # -- writes (COMMENT only) -------------------------------------------------------------

    def create_comment_review(
        self, number: int, commit_id: str, body: str, comments: list[dict[str, Any]]
    ) -> dict[str, Any]:
        payload = {"commit_id": commit_id, "body": body, "event": REVIEW_EVENT, "comments": comments}
        data: dict[str, Any] = self._request(
            "POST", f"/repos/{self.repository}/pulls/{number}/reviews", json=payload
        ).json()
        return data

    def create_issue_comment(self, number: int, body: str) -> dict[str, Any]:
        data: dict[str, Any] = self._request(
            "POST", f"/repos/{self.repository}/issues/{number}/comments", json={"body": body}
        ).json()
        return data

    def update_issue_comment(self, comment_id: int, body: str) -> dict[str, Any]:
        data: dict[str, Any] = self._request(
            "PATCH", f"/repos/{self.repository}/issues/comments/{comment_id}", json={"body": body}
        ).json()
        return data
