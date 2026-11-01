"""GeminiProvider against a stub client: request shape, finish reasons, error mapping."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from google.genai import errors

from pr_sentinel.ai.gemini_provider import GeminiProvider
from pr_sentinel.ai.provider import ModelRequest, ProviderError
from pr_sentinel.ai.schema import OUTPUT_SCHEMA

REQ = ModelRequest(system="sys", user="diff", output_schema=OUTPUT_SCHEMA, max_output_tokens=4000)


def response(finish: str = "STOP", text: str = '{"findings": []}', block: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        text=text,
        prompt_feedback=SimpleNamespace(block_reason=block) if block else None,
        candidates=[SimpleNamespace(finish_reason=SimpleNamespace(name=finish))],
        usage_metadata=SimpleNamespace(prompt_token_count=900, candidates_token_count=40),
    )


class StubModels:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[dict[str, Any]] = []

    def generate_content(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def provider(result: Any) -> tuple[GeminiProvider, StubModels]:
    stub = StubModels(result)
    p = GeminiProvider(
        api_key="", model="gemini-2.5-flash", timeout_seconds=60, max_retries=2, client=SimpleNamespace(models=stub)
    )
    return p, stub


def test_request_uses_json_schema_and_system_instruction() -> None:
    p, stub = provider(response())
    resp = p.complete(REQ)
    [call] = stub.calls
    assert call["model"] == "gemini-2.5-flash" and call["contents"] == "diff"
    cfg = call["config"]
    assert cfg.system_instruction == "sys"
    assert cfg.response_mime_type == "application/json"
    assert cfg.response_json_schema == OUTPUT_SCHEMA
    assert cfg.max_output_tokens == 4000
    assert not cfg.tools  # the reviewer model never gets tools
    assert (resp.text, resp.input_tokens, resp.output_tokens) == ('{"findings": []}', 900, 40)


@pytest.mark.parametrize(
    ("result", "match"),
    [
        (response("MAX_TOKENS"), "truncated"),
        (response("SAFETY"), "declined"),
        (response(block="PROHIBITED_CONTENT"), "declined"),
        (SimpleNamespace(text=None, prompt_feedback=None, candidates=[], usage_metadata=None), "no candidates"),
    ],
)
def test_bad_finish_reasons_are_errors(result: Any, match: str) -> None:
    p, _ = provider(result)
    with pytest.raises(ProviderError, match=match):
        p.complete(REQ)


@pytest.mark.parametrize(
    ("exc", "retryable", "match"),
    [
        (
            errors.ClientError(403, {"error": {"message": "API key not valid"}}),
            False,
            "access denied.*API key not valid",
        ),
        (errors.ClientError(404, {"error": {"message": "nope"}}), False, "model not found"),
        (errors.ClientError(429, {"error": {"message": "quota"}}), True, "quota"),
        (errors.ServerError(503, {"error": {"message": "overloaded"}}), True, "API error 503"),
        (httpx.ConnectError("reset"), True, "network"),
    ],
)
def test_sdk_errors_are_mapped(exc: Exception, retryable: bool, match: str) -> None:
    p, _ = provider(exc)
    with pytest.raises(ProviderError, match=match) as info:
        p.complete(REQ)
    assert info.value.retryable is retryable


def test_missing_key_is_reported() -> None:
    with pytest.raises(ProviderError, match="GEMINI_API_KEY"):
        GeminiProvider(api_key="", model="m", timeout_seconds=10, max_retries=0)
