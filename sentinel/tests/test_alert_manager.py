import json
from datetime import timedelta

from sentinel.core.alert import AlertCandidate # type: ignore
from sentinel.llm.provider import LLMUnavailable # type: ignore
from sentinel.llm.triage import Triager # type: ignore
from sentinel.reporting.alert_manager import AlertManager # type: ignore
from conftest import T0

GOOD = {"summary": "ok", "severity_suggestion": "low", "mitre_hypothesis": "",
        "false_positive_likelihood": "low", "next_steps": []}


class Fake:
    model = "fake"

    def __init__(self, reply=GOOD):
        self.reply, self.calls = reply, 0

    def complete(self, messages, schema):
        self.calls += 1
        if isinstance(self.reply, Exception):
            raise self.reply
        return json.dumps(self.reply)


def alert(source="rule", title="T", severity="medium", entity="1.1.1.1", start=0, length=1, mitre="T1110"):
    return AlertCandidate(source, title, severity, entity, T0 + timedelta(minutes=start),
                          T0 + timedelta(minutes=start + length), mitre=mitre)


def test_repeats_close_in_time_are_merged():
    m = AlertManager()
    m.add([alert(start=0), alert(start=3), alert(start=6)])
    (a,) = m.results()
    assert a.details["repeat_count"] == 3
    assert a.window_end == T0 + timedelta(minutes=7)


def test_repeats_far_apart_are_separate_alerts():
    m = AlertManager(dedupe_minutes=10)
    m.add([alert(start=0), alert(start=60)])
    assert len(m.results()) == 2


def test_different_entities_are_never_merged():
    m = AlertManager()
    m.add([alert(entity="1.1.1.1"), alert(entity="2.2.2.2")])
    assert len(m.results()) == 2


def test_correlation_marks_entities_flagged_by_several_sources():
    m = AlertManager()
    m.add([alert("rule", "A"), alert("ml", "B"), alert("rule", "C", entity="9.9.9.9")])
    m.correlate()
    by_entity = {a.title: a for a in m.results()}
    assert by_entity["A"].details["correlated_sources"] == ["ml", "rule"]
    assert "correlated_sources" not in by_entity["C"].details


def test_results_are_ordered_most_severe_first():
    m = AlertManager()
    m.add([alert(title="low", severity="low"), alert(title="crit", severity="critical", entity="2.2.2.2"),
           alert(title="high", severity="high", entity="3.3.3.3")])
    assert [a.severity for a in m.results()] == ["critical", "high", "low"]


def test_triage_cap_triages_most_severe_and_marks_the_rest_skipped():
    client = Fake()
    m = AlertManager(triager=Triager(client), max_triage=2)
    m.add([alert(title=f"a{i}", severity=s, entity=f"1.1.1.{i}")
           for i, s in enumerate(["low", "critical", "medium", "high"])])
    counts = m.triage()
    assert counts == {"ok": 2, "skipped": 2}
    assert client.calls == 2
    results = m.results()
    assert [a.triage["status"] for a in results] == ["ok", "ok", "skipped", "skipped"]


def test_triage_failure_keeps_the_alert_and_severity():
    m = AlertManager(triager=Triager(Fake(LLMUnavailable("down"))))
    m.add([alert(severity="high")])
    m.triage()
    (a,) = m.results()
    assert a.severity == "high" and a.triage["status"] == "unavailable"


def test_without_triager_triage_is_a_noop():
    m = AlertManager()
    m.add([alert()])
    assert m.triage() == {}
    assert m.results()[0].triage is None
