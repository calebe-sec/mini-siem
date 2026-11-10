from __future__ import annotations

from typing import Iterable

from sentinel.core.event import Event
from sentinel.ml.anomaly import AnomalyDetector
from sentinel.ml.features import DEFAULT_CONFIG, FeatureConfig, build_windows


def train_detector(
    events: Iterable[Event],
    cfg: FeatureConfig = DEFAULT_CONFIG,
    calibration_fraction: float = 0.2,
    **detector_params,
) -> AnomalyDetector:
    """Train on CLEAN events only (a log you trust has no attacks).

    Time-based split: the earliest windows train the forest, the latest ones set the
    threshold, so the threshold is measured on data the forest has not seen.
    """
    if not 0 <= calibration_fraction < 1:
        raise ValueError("calibration_fraction must be in [0, 1)")
    windows = build_windows(events, cfg)   # sorted by window start
    split = int(len(windows) * (1 - calibration_fraction))
    train, calibration = windows[:split], windows[split:]
    detector = AnomalyDetector(**detector_params)
    return detector.fit(train, calibration=calibration or None)
