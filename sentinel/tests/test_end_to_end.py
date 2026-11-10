"""Whole path on generated logs, with a fake LLM: generate -> parse -> rules/aggregator/ML -> triage -> reports."""
import json
import sys
from datetime import datetime

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "scripts"))
from scripts import run_pipeline  # noqa: E402

from sentinel.utils.log_generator import generate  # noqa: E402 # type: ignore


@pytest.fixture(scope="module")
def logs(tmp_path_factory):
    d = tmp_path_factory.mktemp("logs")
    (d / "clean.log").write_text("\n".join(generate(days=30, seed=1)) + "\n")
    (d / "attack.log").write_text("\n".join(generate(days=0, seed=2, attacks=True, start=datetime(2026, 11, 5))) + "\n")
    return d


def test_train_then_run_pipeline_finds_all_three_attacks(logs, tmp_path, capsys):
    from sentinel.core.ingest import load_events # type: ignore
    from sentinel.ml.trainer import train_detector # type: ignore

    events, _ = load_events(logs / "clean.log", year=2026)
    detector = train_detector(events)
    detector.save(tmp_path / "det.joblib")

    code = run_pipeline.main(["--log", str(logs / "attack.log"), "--year", "2026", "--no-llm",
                              "--detector", str(tmp_path / "det.joblib"), "--out", str(tmp_path / "reports")])
    assert code == 0
    out = capsys.readouterr().out
    for title in ("Root SSH Login Accepted", "Multiple failed logins", "Sudo Command Touching Shadow File",
                  "SSH Login Attempt With Invalid User"):
        assert title in out
    assert " ml " in out                       # the ML layer flagged something too

    report = json.loads(next((tmp_path / "reports" / "json").glob("*.json")).read_text())
    assert report["summary"]["alerts"] >= 6
    brute = [a for a in report["alerts"] if a["entity"] == "203.0.113.9"]
    assert {a["source"] for a in brute} >= {"rule", "aggregator"}
    assert any("correlated_sources" in a["details"] for a in brute)
    assert next((tmp_path / "reports" / "markdown").glob("*.md")).read_text().startswith("# Sentinel report")


def test_pipeline_without_ollama_still_creates_alerts(logs, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(run_pipeline.OllamaClient, "is_available", lambda self: False)
    code = run_pipeline.main(["--log", str(logs / "attack.log"), "--year", "2026", "--no-ml",
                              "--out", str(tmp_path / "r")])
    captured = capsys.readouterr()
    assert code == 0 and "without LLM triage" in captured.err and "Root SSH Login Accepted" in captured.out


def test_pipeline_with_fake_llm_adds_triage_and_respects_cap(logs, tmp_path, capsys, monkeypatch):
    good = json.dumps({"summary": "Brute force then root login.", "severity_suggestion": "critical",
                       "mitre_hypothesis": "T1110", "false_positive_likelihood": "low", "next_steps": ["Block IP"]})
    monkeypatch.setattr(run_pipeline.OllamaClient, "is_available", lambda self: True)
    monkeypatch.setattr(run_pipeline.OllamaClient, "complete", lambda self, messages, schema: good)
    code = run_pipeline.main(["--log", str(logs / "attack.log"), "--year", "2026", "--no-ml",
                              "--max-triage", "2", "--out", str(tmp_path / "r")])
    assert code == 0
    alerts = json.loads(next((tmp_path / "r" / "json").glob("*.json")).read_text())["alerts"]
    statuses = [a["triage"]["status"] for a in alerts]
    assert statuses.count("ok") == 2 and statuses.count("skipped") == len(alerts) - 2
    assert all(a["severity"] != "critical" for a in alerts)   # the LLM's suggestion never changes severity


def test_missing_log_is_a_clean_error(tmp_path, capsys):
    assert run_pipeline.main(["--log", str(tmp_path / "nope.log")]) == 2
    assert "not found" in capsys.readouterr().err


def test_logrecon_failure_returns_nonzero_but_writes_reports(logs, tmp_path, capsys):
    code = run_pipeline.main(["--log", str(logs / "attack.log"), "--year", "2026", "--no-ml", "--no-llm",
                              "--logrecon", "http://127.0.0.1:1", "--out", str(tmp_path / "r")])
    assert code == 1
    assert list((tmp_path / "r" / "json").glob("*.json"))
