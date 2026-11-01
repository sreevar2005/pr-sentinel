"""Claude provider (Anthropic Messages API, structured outputs)."""

from __future__ import annotations

from typing import Any

import anthropic

from pr_sentinel.ai.provider import ModelRequest, ModelResponse, ProviderError

_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        effort: str,
        timeout_seconds: float,
        max_retries: int,
        refusal_fallback: bool = True,
        client: anthropic.Anthropic | None = None,
    ) -> None:
        if not api_key and client is None:
            raise ProviderError("ANTHROPIC_API_KEY is not set")
        # The SDK retries connection errors, 408, 409, 429 and 5xx with backoff and honours
        # retry-after. We do not stack a second retry loop on top of it.
        self._client = client or anthropic.Anthropic(api_key=api_key, timeout=timeout_seconds, max_retries=max_retries)
        self._model = model
        self._effort = effort
        self._refusal_fallback = refusal_fallback

    def complete(self, request: ModelRequest) -> ModelResponse:
        params: dict[str, Any] = {
            "model": self._model,
            "max_tokens": request.max_output_tokens,
            "system": request.system,
            "messages": [{"role": "user", "content": request.user}],
            "output_config": {
                "effort": self._effort,
                "format": {"type": "json_schema", "schema": request.output_schema},
            },
        }
        try:
            if self._refusal_fallback:
                # On a safety-classifier decline the API re-runs the request on a fallback
                # model chosen by refusal category. Security-review content occasionally
                # trips cyber classifiers, so this materially improves availability.
                message: Any = self._client.beta.messages.create(betas=[_FALLBACK_BETA], fallbacks="default", **params)
            else:
                message = self._client.messages.create(**params)
        except anthropic.AuthenticationError as exc:
            raise ProviderError("authentication failed (check ANTHROPIC_API_KEY)") from exc
        except anthropic.PermissionDeniedError as exc:
            raise ProviderError("API key lacks permission for this model") from exc
        except anthropic.NotFoundError as exc:
            raise ProviderError(f"model not found: {self._model}") from exc
        except anthropic.BadRequestError as exc:
            raise ProviderError(f"request rejected: {exc.message[:300]}") from exc
        except anthropic.RateLimitError as exc:
            raise ProviderError("rate limited after retries", retryable=True) from exc
        except anthropic.APITimeoutError as exc:
            raise ProviderError("request timed out after retries", retryable=True) from exc
        except anthropic.APIStatusError as exc:
            raise ProviderError(f"API error {exc.status_code} after retries", retryable=exc.status_code >= 500) from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderError("network error after retries", retryable=True) from exc

        if message.stop_reason == "refusal":
            category = getattr(getattr(message, "stop_details", None), "category", None)
            raise ProviderError(f"model declined to review this chunk (category: {category})")
        if message.stop_reason == "max_tokens":
            raise ProviderError("model output truncated at max_tokens")

        text = "".join(b.text for b in message.content if getattr(b, "type", None) == "text")
        usage = message.usage
        return ModelResponse(
            text=text,
            model=str(message.model),
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
        )
