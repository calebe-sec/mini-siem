import json
from datetime import timedelta

from sentinel.core.alert import AlertCandidate # type: ignore
from sentinel.core.event_type import EventType # type: ignore
from sentinel.reporting.json_report import build_report, write_json # type: ignore
from sentinel.reporting.markdown_report import render_markdown, write_markdown # type: ignore
from sentinel.reporting.terminal import render_summary # type: ignore
from conftest import T0

TRIAGE_OK = {"status": "ok", "model": "fake", "data": {
    "summary": "Looks like brute force.", "severity_suggestion": "high", "mitre_hypothesis": "T1110",
    "false_positive_likelihood": "low", "next_steps": ["Block the IP"]}}


def make_alert(make_event, n=3, triage=None, msg=None):
    events = [make_event(i, msg=msg) for i in range(n)]
    return AlertCandidate("aggregator", "Multiple failed logins", "medium", "10.0.0.1", events[0].timestamp,
                          events[-1].timestamp, events, {"failure_count": n}, "T1110", triage)


def test_json_report_is_valid_json_with_summary_and_capped_evidence(make_event, tmp_path):
    a = make_alert(make_event, n=100, triage=TRIAGE_OK)
    path = write_json([a], tmp_path / "out" / "r.json", meta={"log": "x"})
    data = json.loads(path.read_text())
    assert data["summary"] == {"alerts": 1, "by_severity": {"medium": 1}}
    alert = data["alerts"][0]
    assert alert["evidence_total"] == 100 and len(alert["evidence"]) == 20
    assert alert["triage"]["data"]["severity_suggestion"] == "high"
    assert alert["evidence"][0]["event_type"] == "ssh_failed_password"


def test_markdown_report_shows_triage_as_advisory(make_event, tmp_path):
    text = render_markdown([make_alert(make_event, triage=TRIAGE_OK)])
    assert "advisory" in text.lower()
    assert "Looks like brute force." in text and "T1110" in text and "Block the IP" in text
    assert (write_markdown([], tmp_path / "x.md")).read_text().startswith("# Sentinel report")


def test_markdown_report_neutralizes_hostile_log_text(make_event):
    evil = "x | y\n## FAKE HEADING `code`\r\n" + "A" * 500
    text = render_markdown([make_alert(make_event, msg=evil)])
    assert "\n## FAKE HEADING" not in text
    assert "x \\| y" in text
    assert "A" * 200 not in text


def test_markdown_explains_when_triage_failed(make_event):
    text = render_markdown([make_alert(make_event, triage={"status": "timeout", "data": None, "error": "slow"})])
    assert "not available (timeout" in text


def test_terminal_summary_lists_alerts_and_triage_status(make_event):
    text = render_summary([make_alert(make_event, triage=TRIAGE_OK)], {"log": "auth.log"})
    assert "alerts: 1" in text and "Multiple failed logins" in text and "ok (fp: low)" in text


def test_build_report_with_no_alerts(make_event):
    assert build_report([])["summary"]["alerts"] == 0
