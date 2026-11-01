"""Build the configured model provider (shared by the CLI and the local GUI)."""

from __future__ import annotations

import os
from pathlib import Path

from pr_sentinel.ai.anthropic_provider import AnthropicProvider
from pr_sentinel.ai.fake_provider import FakeProvider
from pr_sentinel.ai.gemini_provider import GeminiProvider
from pr_sentinel.ai.provider import ReviewProvider
from pr_sentinel.config import SentinelConfig
from pr_sentinel.pipeline import ProviderFactory


def provider_factory(config: SentinelConfig, fake_response: Path | None = None) -> ProviderFactory:
    """Return a zero-arg callable so providers (and key checks) are only built if AI runs."""
    ai = config.review.ai

    def build() -> ReviewProvider:
        if ai.provider == "fake" or fake_response is not None:
            return FakeProvider.from_file(fake_response) if fake_response else FakeProvider()
        if ai.provider == "gemini":
            return GeminiProvider(
                api_key=os.environ.get("GEMINI_API_KEY", ""),
                model=ai.model_name,
                timeout_seconds=ai.request_timeout_seconds,
                max_retries=ai.max_retries,
            )
        return AnthropicProvider(
            api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            model=ai.model_name,
            effort=ai.effort,
            timeout_seconds=ai.request_timeout_seconds,
            max_retries=ai.max_retries,
            refusal_fallback=ai.refusal_fallback,
        )

    return build
