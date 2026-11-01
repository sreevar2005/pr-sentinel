"""Deterministic provider for tests, dry runs, and demos without an API key."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pr_sentinel.ai.provider import ModelRequest, ModelResponse, ProviderError


class FakeProvider:
    name = "fake"

    def __init__(
        self,
        responses: list[str | dict[str, Any] | Exception] | None = None,
        responder: Callable[[ModelRequest], str] | None = None,
    ) -> None:
        self._responses = list(responses or [])
        self._responder = responder
        self.requests: list[ModelRequest] = []

    @classmethod
    def from_file(cls, path: Path) -> FakeProvider:
        """Replay a canned response; the same response is returned for every chunk."""
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls(responder=lambda _req: json.dumps(payload))

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        if self._responder is not None:
            return ModelResponse(text=self._responder(request), model="fake")
        if not self._responses:
            return ModelResponse(text='{"findings": []}', model="fake")
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            if isinstance(item, ProviderError):
                raise item
            raise ProviderError(str(item))
        text = item if isinstance(item, str) else json.dumps(item)
        return ModelResponse(text=text, model="fake")
