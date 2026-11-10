from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from sentinel.ml.anomaly import AnomalyDetector

logger = logging.getLogger(__name__)


def load_detector(path: str | Path) -> Optional[AnomalyDetector]:
    """Load a saved detector. Returns None (and logs why) so the pipeline can run without ML."""
    target = Path(path)
    if not target.exists():
        logger.warning("no detector at %s: running without the ML layer", target)
        return None
    try:
        return AnomalyDetector.load(target)
    except (ValueError, KeyError, OSError) as exc:
        logger.warning("could not load detector %s (%s): running without the ML layer", target, exc)
        return None
