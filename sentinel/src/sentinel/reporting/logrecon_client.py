from __future__ import annotations

import logging
from typing import Optional, Sequence

import requests

from sentinel.core.alert import AlertCandidate
from sentinel.core.event import Event
from sentinel.mitre.mapping import primary_tactic

logger = logging.getLogger(__name__)

MAX_DESCRIPTION = 255   # LogRecon's Alert.description is a plain String (VARCHAR 255)
MAX_EVENTS_PER_ALERT = 20


class LogReconError(Exception):
    """LogRecon could not be reached, or answered with an error."""


class LogReconClient:
    """Sends Sentinel's results to LogRecon's REST API.

    LogRecon needs things to exist before an alert arrives, so the order is:
    source -> tactic -> rule -> events (they return an id) -> alert.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        session=None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.session = session or requests.Session()
        self._tactics: set[str] = set()
        self._rules: set[str] = set()
        self._event_ids: dict[int, int] = {}   # id(Event) -> LogRecon event id
        self._source_ready: set[str] = set()

    # ------------------------------------------------------------------ http

    def _post(self, path: str, payload: dict) -> dict:
        headers = {"X-API-Key": self.api_key} if self.api_key else {}
        try:
            response = self.session.post(
                f"{self.base_url}{path}", json=payload, headers=headers, timeout=self.timeout
            )
        except requests.exceptions.RequestException as exc:
            raise LogReconError(f"cannot reach LogRecon at {self.base_url}: {exc}") from exc
        if response.status_code >= 400:
            raise LogReconError(f"POST {path} -> HTTP {response.status_code}: {response.text[:200]}")
        try:
            return response.json()
        except ValueError:
            return {}

    def _post_if_missing(self, path: str, payload: dict) -> None:
        """Create something once. A failure may just mean it already exists, so only log it."""
        try:
            self._post(path, payload)
        except LogReconError as exc:
            logger.debug("could not create %s (it may already exist): %s", path, exc)

    # ------------------------------------------------------------ preparation

    def ensure_source(self, name: str, host: str = "localhost", log_type: str = "auth", fmt: str = "syslog") -> None:
        if name in self._source_ready:
            return
        self._post_if_missing("/api/sources", {"name": name, "host": host, "logType": log_type, "format": fmt})
        self._source_ready.add(name)

    def ensure_tactic(self, tactic_id: str, name: str, description: str = "") -> None:
        if tactic_id in self._tactics:
            return
        self._post_if_missing("/api/tactics", {"tacticId": tactic_id, "name": name, "description": description})
        self._tactics.add(tactic_id)

    def ensure_rule(self, name: str, tactic_id: str, severity: str, condition_config: str = "") -> None:
        if name in self._rules:
            return
        self._post_if_missing(
            "/api/rules",
            {"tacticId": tactic_id, "name": name, "conditionConfig": condition_config, "severity": severity},
        )
        self._rules.add(name)

    # ---------------------------------------------------------------- sending

    def post_event(self, event: Event, source_name: str, severity: str) -> int:
        """Send one event (once). Returns the id LogRecon gave it."""
        cached = self._event_ids.get(id(event))
        if cached is not None:
            return cached
        body = self._post("/api/events", {
            "sourceName": source_name,
            "timestamp": event.timestamp.isoformat(),
            "sourceIp": event.source_ip,
            "eventType": event.event_type.value if event.event_type else "unknown",
            "username": event.username,
            "rawMessage": event.raw_message or "",
            "severity": severity,
        })
        event_id = body.get("id")
        if event_id is None:
            raise LogReconError("LogRecon did not return an id for the event")
        self._event_ids[id(event)] = event_id
        return event_id

    @staticmethod
    def build_description(candidate: AlertCandidate) -> str:
        """Pack the alert and the advisory triage into LogRecon's single 255-char field."""
        text = f"[{candidate.source}] {candidate.entity}: {candidate.title}"
        data = (candidate.triage or {}).get("data")
        if data:
            text += f" | AI(advisory): {data['summary']} | fp={data['false_positive_likelihood']}"
        return text[:MAX_DESCRIPTION]

    def send_alert(self, candidate: AlertCandidate, source_name: str) -> dict:
        tactic_id, tactic_name = primary_tactic(candidate)
        self.ensure_tactic(tactic_id, tactic_name)
        self.ensure_rule(candidate.title, tactic_id, candidate.severity)

        events = list(candidate.evidence[-MAX_EVENTS_PER_ALERT:])
        event_ids = [self.post_event(e, source_name, candidate.severity) for e in events]
        return self._post("/api/alerts", {
            "rule": candidate.title,
            "status": "OPEN",
            "description": self.build_description(candidate),
            "logEventIds": event_ids,
        })

    def send_all(self, candidates: Sequence[AlertCandidate], source_name: str = "auth.log") -> tuple[int, list[str]]:
        """Send every alert. One failure does not stop the others. Returns (sent, errors)."""
        self.ensure_source(source_name)
        sent, errors = 0, []
        for candidate in candidates:
            try:
                self.send_alert(candidate, source_name)
                sent += 1
            except LogReconError as exc:
                errors.append(f"{candidate.title} ({candidate.entity}): {exc}")
        return sent, errors
