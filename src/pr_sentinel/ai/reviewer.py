"""AI review: chunk the diff, call the provider, and admit only grounded findings.

Every model finding passes these gates, in order; each rejection is counted by reason so
the summary can say how much was filtered:

  schema      -> item does not validate against AIFinding
  unknown_file-> path is not one of the files sent in this chunk
  bad_line    -> line is not a commentable new-file line in the diff
  ungrounded  -> evidence text is not present at/near the cited line
  unchanged   -> no added line near the cited line (finding is about untouched code)
  low_confidence -> below `min_confidence`
  over_limit  -> beyond `max_findings` after ranking
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from dataclasses import dataclass, field

from pydantic import ValidationError

from pr_sentinel.ai.prompt import SYSTEM_PROMPT, build_user_prompt, render_file
from pr_sentinel.ai.provider import ModelRequest, ProviderError, ReviewProvider
from pr_sentinel.ai.schema import OUTPUT_SCHEMA, AIFinding
from pr_sentinel.config import AIConfig, Limits
from pr_sentinel.diff import FileDiff
from pr_sentinel.filters import SkippedFile
from pr_sentinel.models import Category, Finding, Severity, Source
from pr_sentinel.redact import redact

log = logging.getLogger(__name__)

GROUNDING_WINDOW = 3
_WS = re.compile(r"\s+")


@dataclass
class AIReviewResult:
    findings: list[Finding] = field(default_factory=list)
    dropped: Counter[str] = field(default_factory=Counter)
    errors: list[str] = field(default_factory=list)
    files_reviewed: list[str] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)
    chunks_total: int = 0
    chunks_failed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""

    @property
    def ran(self) -> bool:
        return self.chunks_total > 0

    @property
    def degraded(self) -> bool:
        return self.chunks_failed > 0


def _norm(s: str) -> str:
    return _WS.sub(" ", s).strip()


def build_chunks(files: list[FileDiff], limits: Limits) -> tuple[list[list[tuple[FileDiff, str]]], list[SkippedFile]]:
    """Greedy pack rendered files into chunks; anything beyond the budget is skipped, not cut.

    Files are never split mid-hunk: a partial file is a common source of hallucinated
    "missing" code.
    """
    chunks: list[list[tuple[FileDiff, str]]] = []
    skipped: list[SkippedFile] = []
    current: list[tuple[FileDiff, str]] = []
    size = 0
    # Smaller files first maximises how many files fit in the budget.
    for fd in sorted(files, key=lambda f: len(f.patch or "")):
        rendered = render_file(fd)
        if len(rendered) > limits.max_chunk_chars:
            skipped.append(SkippedFile(fd.path, "too large for a single AI request"))
            continue
        if current and size + len(rendered) > limits.max_chunk_chars:
            chunks.append(current)
            current, size = [], 0
        if len(chunks) >= limits.max_chunks:
            skipped.append(SkippedFile(fd.path, f"AI budget of {limits.max_chunks} request(s) exhausted"))
            continue
        current.append((fd, rendered))
        size += len(rendered)
    if current and len(chunks) < limits.max_chunks:
        chunks.append(current)
    return chunks, skipped


def ground_finding(item: AIFinding, files: dict[str, FileDiff]) -> tuple[Finding | None, str]:
    fd = files.get(item.path)
    if fd is None:
        return None, "unknown_file"
    right = fd.right_side
    if item.line not in right:
        return None, "bad_line"
    evidence = _norm(item.evidence)
    if len(evidence) < 4:
        return None, "ungrounded"

    window = range(item.line - GROUNDING_WINDOW, item.line + GROUNDING_WINDOW + 1)
    # The model saw redacted text, so compare against redacted text.
    window_lines = {n: _norm(redact(right[n])) for n in window if n in right}

    def matches(text: str) -> bool:
        # Evidence quotes this line, or multi-line evidence contains this (non-trivial) line.
        return evidence in text or (len(text) >= 8 and text in evidence)

    anchor = next(
        (n for n in sorted(window_lines, key=lambda n: abs(n - item.line)) if matches(window_lines[n])),
        None,
    )
    if anchor is None:
        joined = " ".join(window_lines[n] for n in sorted(window_lines))
        if evidence not in joined:
            return None, "ungrounded"
        anchor = item.line
    added = fd.added
    if not any(n in added for n in window):
        return None, "unchanged"

    finding = Finding(
        source=Source.AI,
        rule_id=f"ai-{item.category}",
        category=Category(item.category),
        severity=Severity(item.severity),
        title=item.title,
        path=fd.path,
        line=anchor,
        evidence=redact(item.evidence.strip())[:500],
        explanation=redact(item.explanation),
        recommendation=redact(item.recommendation),
        confidence=item.confidence,
    )
    return finding, ""


def parse_items(text: str, result: AIReviewResult) -> list[AIFinding]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        result.errors.append("model returned invalid JSON")
        return []
    raw_items = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(raw_items, list):
        result.errors.append("model output missing `findings` list")
        return []
    items: list[AIFinding] = []
    for raw in raw_items[:100]:
        try:
            items.append(AIFinding.model_validate(raw))
        except ValidationError:
            result.dropped["schema"] += 1
    return items


class AIReviewer:
    def __init__(self, provider: ReviewProvider, config: AIConfig, limits: Limits) -> None:
        self._provider = provider
        self._config = config
        self._limits = limits

    def review(self, files: list[FileDiff], pr_title: str = "", pr_body: str = "") -> AIReviewResult:
        result = AIReviewResult(model=self._config.model)
        chunks, result.skipped = build_chunks(files, self._limits)
        result.chunks_total = len(chunks)
        candidates: list[Finding] = []

        for index, chunk in enumerate(chunks, start=1):
            by_path = {fd.path: fd for fd, _ in chunk}
            request = ModelRequest(
                system=SYSTEM_PROMPT,
                user=build_user_prompt([r for _, r in chunk], pr_title, pr_body),
                output_schema=OUTPUT_SCHEMA,
                max_output_tokens=self._config.max_output_tokens,
            )
            try:
                response = self._provider.complete(request)
            except ProviderError as exc:
                result.chunks_failed += 1
                result.errors.append(f"chunk {index}/{len(chunks)}: {exc}")
                log.warning("AI chunk %d failed: %s", index, exc)
                continue
            result.model = response.model or result.model
            result.input_tokens += response.input_tokens
            result.output_tokens += response.output_tokens
            result.files_reviewed.extend(by_path)

            for item in parse_items(response.text, result):
                finding, reason = ground_finding(item, by_path)
                if finding is None:
                    result.dropped[reason] += 1
                    continue
                if finding.confidence < self._config.min_confidence:
                    result.dropped["low_confidence"] += 1
                    continue
                candidates.append(finding)

        # Same root cause reported twice (e.g. across overlapping wording): keep the strongest.
        unique: dict[tuple[str | None, int | None, str], Finding] = {}
        for f in candidates:
            key = (f.path, f.line, f.category)
            prev = unique.get(key)
            if prev is not None:
                result.dropped["duplicate"] += 1
                if (f.severity.rank, f.confidence) <= (prev.severity.rank, prev.confidence):
                    continue
            unique[key] = f

        ranked = sorted(unique.values(), key=lambda f: (-f.severity.rank, -f.confidence, f.location))
        limit = self._config.max_findings
        result.dropped["over_limit"] += max(0, len(ranked) - limit)
        result.findings = ranked[:limit]
        result.dropped = +result.dropped  # drop zero counts
        return result
