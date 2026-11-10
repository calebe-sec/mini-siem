import pytest
import requests

from sentinel.core.alert import AlertCandidate # type: ignore
from sentinel.reporting.logrecon_client import LogReconClient, LogReconError # type: ignore
from conftest import T0


class Resp:
    def __init__(self, status=201, body=None):
        self.status_code, self._body, self.text = status, body or {}, str(body)

    def json(self):
        return self._body


class FakeSession:
    """Records every POST. Events get ids 1, 2, 3..."""

    def __init__(self, fail_paths=(), raise_error=None):
        self.calls, self.fail_paths, self.raise_error, self._next_id = [], set(fail_paths), raise_error, 0

    def post(self, url, json=None, headers=None, timeout=None):
        if self.raise_error:
            raise self.raise_error
        path = url.split("8080", 1)[1]
        self.calls.append((path, json, headers))
        if path in self.fail_paths:
            return Resp(500, {"error": "boom"})
        if path == "/api/events":
            self._next_id += 1
            return Resp(201, {"id": self._next_id})
        return Resp(201, {"id": 1})


def make_alert(make_event, n=3, triage=None):
    events = [make_event(i) for i in range(n)]
    return AlertCandidate("aggregator", "Multiple failed logins", "medium", "10.0.0.1", T0, T0, events,
                          {"mitre_tactics": ["credential_access"]}, "T1110", triage)


def paths(session):
    return [c[0] for c in session.calls]


def test_alert_is_sent_after_source_tactic_rule_and_events(make_event):
    session = FakeSession()
    client = LogReconClient("http://localhost:8080", session=session)
    sent, errors = client.send_all([make_alert(make_event)], "auth.log")
    assert (sent, errors) == (1, [])
    assert paths(session) == ["/api/sources", "/api/tactics", "/api/rules",
                              "/api/events", "/api/events", "/api/events", "/api/alerts"]
    alert_body = session.calls[-1][1]
    assert alert_body["rule"] == "Multiple failed logins" and alert_body["logEventIds"] == [1, 2, 3]
    assert alert_body["status"] == "OPEN"
    tactic_body = session.calls[1][1]
    assert tactic_body["tacticId"] == "TA0006"


def test_source_tactic_and_rule_are_created_once_and_events_not_resent(make_event):
    session = FakeSession()
    client = LogReconClient("http://localhost:8080", session=session)
    a = make_alert(make_event)
    b = AlertCandidate("rule", "Multiple failed logins", "low", "10.0.0.2", T0, T0, a.evidence[:1], {}, "T1110")
    client.send_all([a, b], "auth.log")
    assert paths(session).count("/api/sources") == 1
    assert paths(session).count("/api/rules") == 1
    assert paths(session).count("/api/events") == 3   # the shared event is sent once


def test_description_fits_logrecon_limit_and_includes_advisory_triage(make_event):
    triage = {"status": "ok", "data": {"summary": "S" * 600, "false_positive_likelihood": "low"}}
    text = LogReconClient.build_description(make_alert(make_event, triage=triage))
    assert len(text) == 255 and text.startswith("[aggregator] 10.0.0.1")


def test_api_key_is_sent_as_header(make_event):
    session = FakeSession()
    LogReconClient("http://localhost:8080", api_key="secret", session=session).send_all([make_alert(make_event)])
    assert all(call[2] == {"X-API-Key": "secret"} for call in session.calls)


def test_existing_rule_or_tactic_error_does_not_stop_the_alert(make_event):
    session = FakeSession(fail_paths={"/api/tactics", "/api/rules"})
    sent, errors = LogReconClient("http://localhost:8080", session=session).send_all([make_alert(make_event)])
    assert sent == 1 and errors == []


def test_alert_failure_is_reported_and_next_alerts_still_go(make_event):
    session = FakeSession(fail_paths={"/api/alerts"})
    sent, errors = LogReconClient("http://localhost:8080", session=session).send_all(
        [make_alert(make_event), make_alert(make_event)])
    assert sent == 0 and len(errors) == 2 and "HTTP 500" in errors[0]


def test_unreachable_logrecon_raises_logrecon_error(make_event):
    session = FakeSession(raise_error=requests.exceptions.ConnectionError("refused"))
    client = LogReconClient("http://localhost:8080", session=session)
    with pytest.raises(LogReconError):
        client.post_event(make_event(), "auth.log", "low")
    sent, errors = client.send_all([make_alert(make_event)])
    assert sent == 0 and errors
