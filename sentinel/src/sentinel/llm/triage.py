from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Callable, Optional

from sentinel.core.alert import AlertCandidate
from sentinel.llm.prompts import (
    LIKELIHOODS,
    PROMPT_VERSION,
    SEVERITIES,
    TRIAGE_SCHEMA,
    build_messages,
    sanitize,
)
from sentinel.llm.provider import LLMClient, LLMError, LLMTimeout, LLMUnavailable

logger = logging.getLogger(__name__)

_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass
class TriageResult:
    status: str                      # ok | unavailable | timeout | invalid_output | skipped
    data: Optional[dict] = None      # validated triage fields, only when status == "ok"
    model: str = ""
    latency_s: float = 0.0
    prompt_version: str = PROMPT_VERSION
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "data": self.data,
            "model": self.model,
            "latency_s": round(self.latency_s, 2),
            "prompt_version": self.prompt_version,
            "error": self.error,
        }


def validate_output(raw: str) -> dict:
    """Parse and check the model's JSON. Raises ValueError if it can't be trusted."""
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ValueError("JSON root is not an object")

    summary = obj.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("summary missing or empty")
    severity = obj.get("severity_suggestion")
    if severity not in SEVERITIES:
        raise ValueError(f"bad severity_suggestion: {severity!r}")
    likelihood = obj.get("false_positive_likelihood")
    if likelihood not in LIKELIHOODS:
        raise ValueError(f"bad false_positive_likelihood: {likelihood!r}")
    steps = obj.get("next_steps")
    if not isinstance(steps, list) or not all(isinstance(s, str) for s in steps):
        raise ValueError("next_steps must be a list of strings")

    technique = obj.get("mitre_hypothesis")
    technique = technique.strip().upper() if isinstance(technique, str) else ""
    return {
        "summary": sanitize(summary, 600),
        "severity_suggestion": severity,
        "mitre_hypothesis": technique if _TECHNIQUE.match(technique) else None,
        "false_positive_likelihood": likelihood,
        "next_steps": [sanitize(s, 200) for s in steps[:5]],
    }


class Triager:
    """Advisory second opinion. It never raises, never changes severity, never drops an alert."""

    def __init__(
        self,
        client: LLMClient,
        max_events: int = 20,
        failure_threshold: int = 3,
        cooldown_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.client = client
        self.max_events = max_events
        self.failure_threshold = failure_threshold
        self.cooldown_s = cooldown_s
        self._clock = clock
        self._consecutive_failures = 0
        self._open_until = 0.0

    def triage(self, candidate: AlertCandidate) -> TriageResult:
        model = getattr(self.client, "model", "")
        if self._clock() < self._open_until:
            return TriageResult(status="skipped", model=model, error="circuit breaker open")

        start = self._clock()
        try:
            messages = build_messages(candidate, self.max_events)
            data = None
            error = None
            for _ in range(2):  # one retry, only for invalid output
                raw = self.client.complete(messages, TRIAGE_SCHEMA)
                try:
                    data = validate_output(raw)
                    break
                except ValueError as exc:
                    error = str(exc)
            if data is None:
                return self._finish("invalid_output", start, model, error=error, failed=True)
            return self._finish("ok", start, model, data=data, failed=False)
        except LLMTimeout as exc:
            return self._finish("timeout", start, model, error=str(exc), failed=True)
        except LLMUnavailable as exc:
            return self._finish("unavailable", start, model, error=str(exc), failed=True)
        except LLMError as exc:
            return self._finish("unavailable", start, model, error=str(exc), failed=True)
        except Exception as exc:  # triage must never break the pipeline
            logger.exception("unexpected triage error")
            return self._finish("unavailable", start, model, error=repr(exc), failed=True)

    def apply(self, candidate: AlertCandidate) -> AlertCandidate:
        """Attach the triage to the candidate. Severity stays the one detection decided."""
        candidate.triage = self.triage(candidate).to_dict()
        return candidate

    def _finish(self, status, start, model, data=None, error=None, failed=False) -> TriageResult:
        if failed:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.failure_threshold:
                self._open_until = self._clock() + self.cooldown_s
                self._consecutive_failures = 0
                logger.warning("LLM triage paused for %.0fs after repeated failures", self.cooldown_s)
        else:
            self._consecutive_failures = 0
        return TriageResult(
            status=status, data=data, model=model,
            latency_s=self._clock() - start, error=error,
        )