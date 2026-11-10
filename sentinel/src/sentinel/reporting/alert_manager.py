from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timedelta
from typing import Callable, Iterable, Optional

from sentinel.core.alert import AlertCandidate
from sentinel.llm.triage import Triager
from sentinel.mitre.mapping import enrich

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _rank(candidate: AlertCandidate) -> int:
    return SEVERITY_RANK.get(candidate.severity, len(SEVERITY_RANK))


class AlertManager:
    """Collects candidates: enriches (MITRE), merges repeats, correlates sources, triages.

    Triage is advisory: it is added to each alert and never removes or re-ranks one.
    """

    def __init__(
        self,
        triager: Optional[Triager] = None,
        dedupe_minutes: int = 10,
        max_triage: int = 20,
    ) -> None:
        self.triager = triager
        self.dedupe_window = timedelta(minutes=dedupe_minutes)
        self.max_triage = max_triage
        self._alerts: list[AlertCandidate] = []
        self._last_by_key: dict[tuple, AlertCandidate] = {}

    def add(self, candidates: Iterable[AlertCandidate]) -> None:
        for candidate in sorted(candidates, key=lambda c: c.window_start):
            enrich(candidate)
            key = (candidate.source, candidate.title, candidate.entity, candidate.mitre)
            previous = self._last_by_key.get(key)
            if previous is not None and candidate.window_start - previous.window_end <= self.dedupe_window:
                # Same thing again, close in time: merge instead of creating another alert.
                previous.details["repeat_count"] = previous.details.get("repeat_count", 1) + 1
                if candidate.window_end > previous.window_end:
                    previous.window_end = candidate.window_end
                continue
            self._last_by_key[key] = candidate
            self._alerts.append(candidate)

    def correlate(self) -> None:
        """Mark alerts whose entity was flagged by more than one source (rule, ml, aggregator)."""
        sources: dict[str, set[str]] = defaultdict(set)
        for alert in self._alerts:
            sources[alert.entity].add(alert.source)
        for alert in self._alerts:
            if len(sources[alert.entity]) > 1:
                alert.details["correlated_sources"] = sorted(sources[alert.entity])

    def triage(self, on_progress: Optional[Callable[[int, int, AlertCandidate], None]] = None) -> dict:
        """Triage the most severe alerts first, up to max_triage. Returns counts by status."""
        counts: dict[str, int] = defaultdict(int)
        if self.triager is None:
            return dict(counts)

        ordered = self.results()
        for index, alert in enumerate(ordered):
            if index >= self.max_triage:
                alert.triage = {
                    "status": "skipped",
                    "data": None,
                    "error": f"triage cap reached ({self.max_triage})",
                }
            else:
                if on_progress:
                    on_progress(index + 1, min(len(ordered), self.max_triage), alert)
                self.triager.apply(alert)
            counts[alert.triage["status"]] += 1
        return dict(counts)

    def results(self) -> list[AlertCandidate]:
        """Alerts ordered by severity, then by time."""
        return sorted(self._alerts, key=lambda c: (_rank(c), c.window_start))
