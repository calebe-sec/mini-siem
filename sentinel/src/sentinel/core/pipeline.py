from __future__ import annotations

from collections import defaultdict, deque
from typing import Iterable, Optional

from sentinel.core.alert import AlertCandidate
from sentinel.core.event import Event
from sentinel.detection.engine import EngineRule
from sentinel.detection.sliding_window import Aggregator
from sentinel.ml.anomaly import AnomalyDetector
from sentinel.ml.features import DEFAULT_CONFIG, FeatureConfig, build_windows, classify


class EventProcessor:
    """Connects the rule engine and the Aggregator to AlertCandidate.

    It keeps the last events of each IP, so a candidate carries real evidence
    (the Aggregator only stores timestamps).
    """

    def __init__(
        self,
        aggregator: Aggregator,
        max_events_per_ip: int = 50,
        engine: Optional[EngineRule] = None,
    ) -> None:
        if max_events_per_ip < 1:
            raise ValueError("max_events_per_ip must be at least 1")
        self.aggregator = aggregator
        self.engine = engine
        self.max_events_per_ip = max_events_per_ip
        # deque(maxlen=N) drops the oldest event by itself when it is full.
        # Known limit (v1.0): an IP seen once keeps its small buffer until the process ends.
        self.buffers: dict[str, deque[Event]] = defaultdict(
            lambda: deque(maxlen=self.max_events_per_ip)
        )

    def process(self, event: Event) -> list[AlertCandidate]:
        """Handle one event. Returns [] most of the time, candidates when something fires."""
        buffer = self.buffers[event.source_ip] if event.source_ip else None
        if buffer is not None:
            buffer.append(event)

        candidates: list[AlertCandidate] = []

        # 1. YAML rules (they also run on events without IP, like sudo)
        if self.engine is not None:
            evidence = list(buffer) if buffer is not None else [event]
            for match in self.engine.run(event.to_rule_dict()):
                candidates.append(AlertCandidate.from_rule(match, event, evidence))

        # 2. Aggregator (needs an IP and a username)
        if buffer is not None and classify(event) == "failure" and event.username:
            fired = self.aggregator.add_failure(event.username, event.source_ip, event.timestamp)
            if fired:
                evidence = list(buffer)  # a copy: the deque keeps changing afterwards
                count = sum(1 for e in evidence if classify(e) == "failure")
                candidates.append(
                    AlertCandidate.from_aggregator(
                        user=event.username,
                        source_ip=event.source_ip,
                        count=count,
                        window_start=evidence[0].timestamp,
                        window_end=evidence[-1].timestamp,
                        evidence=evidence,
                    )
                )
        return candidates


def run_ml(
    events: Iterable[Event],
    detector: AnomalyDetector,
    cfg: FeatureConfig = DEFAULT_CONFIG,
) -> list[AlertCandidate]:
    """Batch ML pass: one feature row per (IP, window); every anomaly becomes a candidate."""
    events = list(events)
    anomalies = detector.detect(build_windows(events, cfg))

    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.source_ip:
            by_ip[event.source_ip].append(event)

    return [
        AlertCandidate.from_anomaly(
            anomaly,
            [e for e in by_ip[anomaly.entity] if anomaly.window_start <= e.timestamp < anomaly.window_end],
        )
        for anomaly in anomalies
    ]


def analyze(
    events: Iterable[Event],
    processor: EventProcessor,
    detector: Optional[AnomalyDetector] = None,
    cfg: FeatureConfig = DEFAULT_CONFIG,
) -> list[AlertCandidate]:
    """Run a whole list of events (in log order) through rules, aggregator and, optionally, ML."""
    events = list(events)
    candidates: list[AlertCandidate] = []
    for event in events:
        candidates.extend(processor.process(event))
    if detector is not None:
        candidates.extend(run_ml(events, detector, cfg))
    return candidates
