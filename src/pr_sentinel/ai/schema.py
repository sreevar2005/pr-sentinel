"""The only output shape the model is allowed to produce.

The JSON schema is sent to the provider for constrained decoding; the Pydantic models
re-validate on our side regardless, because a provider (or a future replacement) may not
enforce the schema, and because bounds like lengths and confidence ranges are checked here.
"""

from __future__ import annotations

from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field

AICategory = Literal["bug", "security", "reliability", "performance", "risky-change"]
AISeverity = Literal["critical", "high", "medium", "low"]

OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path exactly as shown in the FILE header."},
                    "line": {"type": "integer", "description": "New-file line number from the left column."},
                    "category": {"type": "string", "enum": list(get_args(AICategory))},
                    "severity": {"type": "string", "enum": list(get_args(AISeverity))},
                    "title": {"type": "string", "description": "One-line statement of the defect."},
                    "evidence": {
                        "type": "string",
                        "description": "Verbatim code copied from the diff at or next to `line`.",
                    },
                    "explanation": {"type": "string", "description": "Concrete failure scenario."},
                    "recommendation": {"type": "string", "description": "Specific fix."},
                    "confidence": {"type": "number", "description": "0.0-1.0 probability this is a real defect."},
                },
                "required": [
                    "path",
                    "line",
                    "category",
                    "severity",
                    "title",
                    "evidence",
                    "explanation",
                    "recommendation",
                    "confidence",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["findings"],
    "additionalProperties": False,
}


class AIFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=500)
    line: int = Field(ge=1)
    category: AICategory
    severity: AISeverity
    title: str = Field(min_length=3, max_length=200)
    evidence: str = Field(min_length=1, max_length=500)
    explanation: str = Field(min_length=1, max_length=2000)
    recommendation: str = Field(min_length=1, max_length=2000)
    confidence: float = Field(ge=0.0, le=1.0)
