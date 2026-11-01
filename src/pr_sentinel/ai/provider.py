"""Model provider interface.

A provider turns (system prompt, user prompt, JSON schema) into JSON text. Everything
else - prompt construction, chunking, validation, grounding, filtering - lives in
`reviewer.py`, so swapping providers never touches review logic and a provider can never
bypass validation.

Providers get no tools and no repository access: the model can only return text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class ModelRequest:
    system: str
    user: str
    output_schema: dict[str, Any]
    max_output_tokens: int


@dataclass(frozen=True)
class ModelResponse:
    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0


class ProviderError(Exception):
    """Raised for any provider failure. Messages must never contain credentials."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class ReviewProvider(Protocol):
    name: str

    def complete(self, request: ModelRequest) -> ModelResponse: ...
