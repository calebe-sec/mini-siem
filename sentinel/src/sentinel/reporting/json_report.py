from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence

from sentinel.core.alert import AlertCandidate
from sentinel.core.event import Event

MAX_EVIDENCE = 20  # events kept per alert in the report (first and last ones)


def event_to_dict(event: Event) -> dict:
    return {
        "timestamp": event.timestamp.isoformat(),
        "source_ip": event.source_ip,
        "event_type": event.event_type.value if event.event_type else None,
        "username": event.username,
        "port": event.port,
        "hostname": event.hostname,
        "process": event.process,
        "command": event.command,
        "raw_message": event.raw_message,
    }


def select_evidence(evidence: Sequence[Event], limit: int = MAX_EVIDENCE) -> list[Event]:
    if len(evidence) <= limit:
        return list(evidence)
    head = limit // 2
    return list(evidence[:head]) + list(evidence[-(limit - head):])


def candidate_to_dict(candidate: AlertCandidate, max_evidence: int = MAX_EVIDENCE) -> dict:
    return {
        "source": candidate.source,
        "title": candidate.title,
        "severity": candidate.severity,
        "entity": candidate.entity,
        "window_start": candidate.window_start.isoformat(),
        "window_end": candidate.window_end.isoformat(),
        "mitre": candidate.mitre,
        "details": candidate.details,
        "triage": candidate.triage,
        "evidence_total": len(candidate.evidence),
        "evidence": [event_to_dict(e) for e in select_evidence(candidate.evidence, max_evidence)],
    }


def build_report(candidates: Sequence[AlertCandidate], meta: Optional[dict] = None) -> dict:
    by_severity: dict[str, int] = {}
    for c in candidates:
        by_severity[c.severity] = by_severity.get(c.severity, 0) + 1
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "meta": meta or {},
        "summary": {"alerts": len(candidates), "by_severity": by_severity},
        "alerts": [candidate_to_dict(c) for c in candidates],
    }


def write_json(candidates: Sequence[AlertCandidate], path: str | Path, meta: Optional[dict] = None) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(build_report(candidates, meta), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return target
