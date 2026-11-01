"""Gemini provider (Google AI Studio / Gemini API, JSON-schema structured output)."""

from __future__ import annotations

from typing import Any

import httpx  # the transport google-genai uses (separate from the httpx2 used elsewhere)
from google import genai
from google.genai import errors, types

from pr_sentinel.ai.provider import ModelRequest, ModelResponse, ProviderError

# Finish reasons that mean the model declined or was stopped by a policy filter.
_BLOCKED = {"SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "RECITATION", "LANGUAGE"}


class GeminiProvider:
    name = "gemini"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_retries: int,
        client: Any | None = None,
    ) -> None:
        if not api_key and client is None:
            raise ProviderError("GEMINI_API_KEY is not set")
        # The SDK retries 408/429/5xx with exponential backoff; `attempts` includes the first try.
        self._client = client or genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(
                timeout=int(timeout_seconds * 1000),
                retry_options=types.HttpRetryOptions(attempts=max_retries + 1),
            ),
        )
        self._model = model

    def complete(self, request: ModelRequest) -> ModelResponse:
        config = types.GenerateContentConfig(
            system_instruction=request.system,
            max_output_tokens=request.max_output_tokens,
            response_mime_type="application/json",
            response_json_schema=request.output_schema,
        )
        try:
            response = self._client.models.generate_content(model=self._model, contents=request.user, config=config)
        except errors.ClientError as exc:
            # Google's error messages do not echo the key; the text says *why* (bad key, billing,
            # region), which a bare "auth failed" would hide. Still truncated and redacted upstream.
            if exc.code in (401, 403):
                detail = str(exc.message or "")[:200]
                raise ProviderError(f"access denied (HTTP {exc.code}): {detail or 'check GEMINI_API_KEY'}") from exc
            if exc.code == 404:
                raise ProviderError(f"model not found: {self._model}") from exc
            if exc.code == 429:
                raise ProviderError("rate limited or free-tier quota exhausted", retryable=True) from exc
            raise ProviderError(f"request rejected (HTTP {exc.code}): {str(exc.message)[:200]}") from exc
        except errors.ServerError as exc:
            raise ProviderError(f"API error {exc.code} after retries", retryable=True) from exc
        except errors.APIError as exc:
            raise ProviderError(f"API error {exc.code}") from exc
        except (httpx.TransportError, OSError) as exc:  # connection, DNS, read timeout after retries
            raise ProviderError(f"network error: {type(exc).__name__}", retryable=True) from exc

        feedback = getattr(response, "prompt_feedback", None)
        if feedback is not None and getattr(feedback, "block_reason", None):
            raise ProviderError(f"model declined to review this chunk ({feedback.block_reason})")
        candidates = getattr(response, "candidates", None) or []
        if not candidates:
            raise ProviderError("model returned no candidates")
        reason = str(getattr(candidates[0].finish_reason, "name", candidates[0].finish_reason) or "")
        if reason == "MAX_TOKENS":
            raise ProviderError("model output truncated at max_output_tokens")
        if reason in _BLOCKED:
            raise ProviderError(f"model declined to review this chunk ({reason})")

        usage = getattr(response, "usage_metadata", None)
        return ModelResponse(
            text=response.text or "",
            model=self._model,
            input_tokens=int(getattr(usage, "prompt_token_count", 0) or 0),
            output_tokens=int(getattr(usage, "candidates_token_count", 0) or 0),
        )
