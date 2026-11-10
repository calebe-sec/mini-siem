from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from sentinel.core.event import Event
from sentinel.normalizer.normalizer import normalize
from sentinel.parsers.auth_parser import AuthLogParser

logger = logging.getLogger(__name__)

# <project>/config/log_patterns.yaml (this file is <project>/src/sentinel/core/ingest.py)
DEFAULT_PATTERNS = Path(__file__).resolve().parents[3] / "config" / "log_patterns.yaml"


def load_events(
    log_path: str | Path,
    year: Optional[int] = None,
    patterns_path: str | Path = DEFAULT_PATTERNS,
) -> tuple[list[Event], dict]:
    """Parse and normalize an auth.log file. Returns (events, stats).

    Lines the parser does not recognize, or that fail normalization, are counted and
    skipped: one bad line must not stop the whole run.
    """
    parser = AuthLogParser(patterns_path=str(patterns_path))
    raw_events = parser.parse(str(log_path))

    events: list[Event] = []
    stats = {"parsed_lines": len(raw_events), "unrecognized": 0, "invalid": 0, "events": 0}
    for raw in raw_events:
        if not raw.get("event_type"):
            stats["unrecognized"] += 1
            continue
        try:
            events.append(normalize(raw, "auth_log", year=year))
        except (ValueError, KeyError) as exc:
            stats["invalid"] += 1
            logger.warning("skipping invalid log line: %s", exc)
    stats["events"] = len(events)
    return events, stats
