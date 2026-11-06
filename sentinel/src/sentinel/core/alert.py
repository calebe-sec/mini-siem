from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from sentinel.core.event import Event
from sentinel.ml.anomaly import Anomaly

@dataclass
class AlertCandidate:
    #features
    source: str             #"rule" | "ml" | "aggregator"
    title: str
    severity: str           #severity classify: low or medium or high or critical
    entity: str             #ussualy the source ip
    window_start: datetime
    window_end: datetime
    evidence: list[Event] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    mitre: Optional[str] = None
    triage: Optional[dict] = None      #LLM result, filled later; advisory only

    @classmethod
    def from_aggregator(cls, user: str, source_ip: str, count: int, window_start: datetime, window_end: datetime, evidence: list[Event],) -> "AlertCandidate":
        return cls(source="aggregator",
                   title="Multiple failed logins", 
                   severity="medium", 
                   entity=source_ip, 
                   window_start=window_start, 
                   window_end=window_end, 
                   evidence=evidence, 
                   details={"user": user, "failure_count": count}, 
                   mitre="T1110")
    
    @classmethod
    def from_anomaly(cls, anomaly: Anomaly, evidence: list[Event]) -> "AlertCandidate":
        return cls(
            source="ml",
            title="Anomalous activity from source IP",
            severity="medium",
            entity=anomaly.entity,
            window_start=anomaly.window_start,
            window_end=anomaly.window_end,
            evidence=evidence,
            details=anomaly.to_dict(),
        )
    
    
    


