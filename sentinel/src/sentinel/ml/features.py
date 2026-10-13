from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Protocol, Sequence

import numpy as np

# Order matters: it is the column order of the feature matrix and it is checked when a
# saved model is loaded. Adding, removing or reordering a feature means retraining.
FEATURE_NAMES: tuple[str, ...] = (
    "total_events",            
    "failed_logins",
    "successful_logins",
    "failure_ratio",           
    "distinct_usernames",      
    "mean_gap_seconds",        
    "std_gap_seconds",         
    "hour_of_day",             
    "success_after_failures",  )

class EventLike(Protocol):
    timestamp: datetime
    source_ip: str | None
    username: str | None
    event_type: object

#every shapes feature types
@dataclass(frozen=True)
class FeatureConfig:
    window_minutes: int = 5
    min_events: int = 1
    success_after_failures_min: int = 3
    failure_markers: tuple[str, ...] = ("FAIL", "INVALID", "DENIED")
    success_markers: tuple[str, ...] = ("SUCCESS", "ACCEPT")

    def __post_init__(self) -> None:
        if not 0 < self.window_minutes <= 24 * 60:
            raise ValueError("window_minutes must be between 1 and 1440")
        if self.min_events < 1:
            raise ValueError("min_events must be at least 1")
        if self.success_after_failures_min < 1:
            raise ValueError("success_after_failures_min must be at least 1")

    @property
    def window(self) -> timedelta:
        return timedelta(minutes=self.window_minutes)


DEFAULT_CONFIG = FeatureConfig()


@dataclass(frozen=True)
class WindowFeatures:
    """One feature row: an entity (source IP), its window, and values aligned with FEATURE_NAMES."""

    entity: str
    window_start: datetime
    window_end: datetime
    values: tuple[float, ...]

    def as_dict(self) -> dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.values))


def window_start_for(ts: datetime, window: timedelta) -> datetime:
    """Start of the tumbling window containing ts, aligned to midnight of ts's day."""
    midnight = ts.replace(hour=0, minute=0, second=0, microsecond=0)
    bucket = int((ts - midnight).total_seconds() // window.total_seconds())
    return midnight + bucket * window


def _type_name(event_type: object) -> str:
    return str(getattr(event_type, "name", event_type)).upper()

#turn if succes or failure
def classify(event: EventLike, cfg: FeatureConfig = DEFAULT_CONFIG) -> str:
    name = _type_name(event.event_type)
    if any(marker in name for marker in cfg.failure_markers):
        return "failure"
    if any(marker in name for marker in cfg.success_markers):
        return "success"
    return "other"


def extract_window_features(
    entity: str,
    window_start: datetime,
    events: Sequence[EventLike],
    cfg: FeatureConfig = DEFAULT_CONFIG, ) -> WindowFeatures:
    #Turn the events of one (entity, window) into a feature row.
    ordered = sorted(events, key=lambda e: e.timestamp)

    failed = 0
    success = 0
    suspicious_success = False
    usernames: set[str] = set()
    for event in ordered:
        kind = classify(event, cfg)
        if kind == "failure":
            failed += 1
        elif kind == "success":
            success += 1
            if failed >= cfg.success_after_failures_min:
                suspicious_success = True
        if event.username:
            usernames.add(event.username)

    auth_total = failed + success
    failure_ratio = failed / auth_total if auth_total else 0.0

    gaps = np.array(
        [(b.timestamp - a.timestamp).total_seconds() for a, b in zip(ordered, ordered[1:])],
        dtype=float,
    )
    if gaps.size:
        mean_gap, std_gap = float(gaps.mean()), float(gaps.std())
    else:
        # One event carries no rhythm information: use a neutral "as slow as possible" value.
        mean_gap, std_gap = cfg.window.total_seconds(), 0.0

    values = (
        float(len(ordered)),
        float(failed),
        float(success),
        failure_ratio,
        float(len(usernames)),
        mean_gap,
        std_gap,
        float(window_start.hour),
        1.0 if suspicious_success else 0.0,
    )
    return WindowFeatures(entity, window_start, window_start + cfg.window, values)


def build_windows(
    events: Iterable[EventLike],
    cfg: FeatureConfig = DEFAULT_CONFIG,
) -> list[WindowFeatures]:
    #Group events by (source_ip, window) and extract one feature row per group.
    #Rows come back sorted by window start, then by IP, so output is deterministic.

    buckets: dict[tuple[str, datetime], list[EventLike]] = defaultdict(list)
    for event in events:
        if not event.source_ip:
            continue
        buckets[(event.source_ip, window_start_for(event.timestamp, cfg.window))].append(event)

    windows = [
        extract_window_features(ip, start, group, cfg)
        for (ip, start), group in buckets.items()
        if len(group) >= cfg.min_events
    ]
    windows.sort(key=lambda w: (w.window_start, w.entity))
    return windows


def to_matrix(windows: Sequence[WindowFeatures]) -> np.ndarray:
    """Stack feature rows into an (n_windows, n_features) float array."""
    if not windows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=float)
    return np.array([w.values for w in windows], dtype=float)
