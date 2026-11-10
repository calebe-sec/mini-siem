import random

import pytest

from sentinel.core.event_type import EventType # type: ignore
from sentinel.core.pipeline import EventProcessor, analyze, run_ml # type: ignore
from sentinel.detection.engine import EngineRule # type: ignore
from sentinel.detection.rule_loader import RulerLoader # type: ignore
from sentinel.detection.sliding_window import Aggregator # type: ignore
from sentinel.ml.features import FeatureConfig # type: ignore
from sentinel.ml.trainer import train_detector # type: ignore


def quiet_traffic(make_event, windows=300):
    """Varied but harmless traffic: a few typos and logins per window, jittered, spread over IPs and times.

    Isolation Forest needs variety in the clean data: if every clean window looks the same,
    an unusual one does not stand out.
    """
    rng = random.Random(7)
    events = []
    for i in range(windows):
        ip, base, user = f"10.0.{i % 7}.{i % 50}", i * 600 + rng.uniform(0, 30), f"u{i % 5}"
        for _ in range(rng.randint(0, 4)):
            events.append(make_event(base + rng.uniform(0, 200), ip=ip, user=user))          # typos
        for _ in range(rng.randint(1, 3)):
            events.append(make_event(base + rng.uniform(0, 250), etype=EventType.SSH_ACCEPTED_PASSWORD, ip=ip, user=user))
    return events


def attack_burst(make_event):
    """Spray over many usernames, then a successful login: extreme on several features at once."""
    burst = [make_event(100_000 + i, ip="203.0.113.9", user=f"victim{i % 15}") for i in range(40)]
    burst.append(make_event(100_045, etype=EventType.SSH_ACCEPTED_PASSWORD, ip="203.0.113.9", user="victim3"))
    return burst


@pytest.fixture
def processor():
    engine = EngineRule(RulerLoader().open_conditions_yaml(RulerLoader.FILES))
    return EventProcessor(Aggregator(window_minutes=5, threshold=5), engine=engine)


def test_rule_candidate_carries_recent_events_as_evidence(make_event, processor):
    for i in range(3):
        processor.process(make_event(i))
    (candidate,) = processor.process(make_event(10, etype=EventType.SSH_ACCEPTED_PASSWORD, user="root"))
    assert candidate.source == "rule" and candidate.mitre == "T1078"
    assert len(candidate.evidence) == 4          # 3 failures + the login
    assert candidate.details["rule_id"] == "IAC-001"


def test_rules_run_on_events_without_ip(make_event, processor):
    event = make_event(etype=EventType.SUDO_COMMAND, ip=None, user="bob", command="/bin/cat /etc/shadow")
    (candidate,) = processor.process(event)
    assert candidate.entity == "web01"            # falls back to the hostname


def test_rule_and_aggregator_can_both_fire_on_one_event(make_event, processor):
    results = []
    for i in range(5):
        results.extend(processor.process(make_event(i, etype=EventType.SSH_FAILED_PASSWORD, user="root")))
    assert [c.source for c in results] == ["aggregator"]


def test_analyze_runs_all_events_and_ml(make_event):
    cfg = FeatureConfig()
    detector = train_detector(quiet_traffic(make_event), cfg, min_train_windows=50)
    ml = run_ml(attack_burst(make_event), detector, cfg)
    assert ml and ml[0].source == "ml" and ml[0].entity == "203.0.113.9"
    assert len(ml[0].evidence) == 41

    # A spray over many usernames never gives one (user, ip) enough failures for the aggregator;
    # that is exactly the gap the ML layer covers.
    proc = EventProcessor(Aggregator(window_minutes=5, threshold=5))
    assert {c.source for c in analyze(attack_burst(make_event), proc, detector, cfg)} == {"ml"}

    # One username hammered from one IP is the aggregator's job (and ml may flag it too).
    one_user = [make_event(100_000 + i, ip="203.0.113.9", user="root") for i in range(40)]
    proc = EventProcessor(Aggregator(window_minutes=5, threshold=5))
    assert "aggregator" in {c.source for c in analyze(one_user, proc, detector, cfg)}


def test_run_ml_with_no_events_is_empty(make_event):
    detector = train_detector(quiet_traffic(make_event), min_train_windows=50)
    assert run_ml([], detector) == []
