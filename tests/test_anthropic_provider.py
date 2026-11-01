"""AnthropicProvider against a stub client: request shape, stop reasons, error mapping."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2 as httpx
import pytest

from pr_sentinel.ai.anthropic_provider import AnthropicProvider
from pr_sentinel.ai.provider import ModelRequest, ProviderError
from pr_sentinel.ai.schema import OUTPUT_SCHEMA

REQ = ModelRequest(system="sys", user="diff", output_schema=OUTPUT_SCHEMA, max_output_tokens=4000)


def message(stop_reason: str = "end_turn", text: str = '{"findings": []}', **extra: Any) -> SimpleNamespace:
    return SimpleNamespace(
        stop_reason=stop_reason,
        content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)],
        model="claude-opus-5-5",
        usage=SimpleNamespace(input_tokens=1200, output_tokens=80),
        **extra,
    )


class StubMessages:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def provider(result: Any, fallback: bool = True) -> tuple[AnthropicProvider, StubMessages]:
    stub = StubMessages(result)
    client = SimpleNamespace(messages=stub, beta=SimpleNamespace(messages=stub))
    p = AnthropicProvider(
        api_key="",
        model="claude-opus-5-5",
        effort="high",
        timeout_seconds=60,
        max_retries=2,
        refusal_fallback=fallback,
        client=client,
    )  # type: ignore[arg-type]
    return p, stub


def test_request_uses_structured_output_effort_and_fallback() -> None:
    p, stub = provider(message())
    resp = p.complete(REQ)
    [call] = stub.calls
    assert call["model"] == "claude-opus-5-5"
    assert call["output_config"] == {"effort": "high", "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}}
    assert call["betas"] == ["server-side-fallback-2026-07-01"] and call["fallbacks"] == "default"
    assert call["system"] == "sys" and call["messages"] == [{"role": "user", "content": "diff"}]
    assert "tools" not in call  # the reviewer model never gets tools
    assert resp.text == '{"findings": []}' and resp.input_tokens == 1200


def test_fallback_can_be_disabled() -> None:
    p, stub = provider(message(), fallback=False)
    p.complete(REQ)
    assert "betas" not in stub.calls[0] and "fallbacks" not in stub.calls[0]


def test_refusal_and_truncation_are_errors() -> None:
    p, _ = provider(message("refusal", stop_details=SimpleNamespace(category="cyber")))
    with pytest.raises(ProviderError, match="declined"):
        p.complete(REQ)
    p, _ = provider(message("max_tokens"))
    with pytest.raises(ProviderError, match="truncated"):
        p.complete(REQ)


def _status_error(cls: type[anthropic.APIStatusError], code: int) -> anthropic.APIStatusError:
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    return cls("boom", response=httpx.Response(code, request=req), body=None)


@pytest.mark.parametrize(
    ("exc", "retryable", "match"),
    [
        (_status_error(anthropic.AuthenticationError, 401), False, "authentication"),
        (_status_error(anthropic.RateLimitError, 429), True, "rate limited"),
        (_status_error(anthropic.InternalServerError, 500), True, "API error 500"),
        (anthropic.APIConnectionError(request=httpx.Request("POST", "https://x")), True, "network"),
    ],
)
def test_sdk_errors_are_mapped(exc: Exception, retryable: bool, match: str) -> None:
    p, _ = provider(exc)
    with pytest.raises(ProviderError, match=match) as info:
        p.complete(REQ)
    assert info.value.retryable is retryable


def test_missing_key_is_reported_without_a_client() -> None:
    with pytest.raises(ProviderError, match="ANTHROPIC_API_KEY"):
        AnthropicProvider(api_key="", model="m", effort="high", timeout_seconds=10, max_retries=0)
