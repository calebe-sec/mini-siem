from datetime import datetime, timedelta

import pytest

from sentinel.core.event import Event # type: ignore 
from sentinel.core.event_type import EventType # type: ignore
from sentinel.core.pipeline import EventProcessor # type: ignore
from sentinel.detection.sliding_window import Aggregator # type: ignore

T0 = datetime(2026, 1, 1, 12, 0, 0)


def fail(i, ip="10.0.0.1", user="root"):
    return Event(
        timestamp=T0 + timedelta(seconds=10 * i),
        source_ip=ip,
        event_type=EventType.SSH_FAILED_PASSWORD,
        source="auth_log",
        raw_message=f"Failed password for {user}",
        username=user,
    )


@pytest.fixture
def proc():
    return EventProcessor(Aggregator(window_minutes=5, threshold=5), max_events_per_ip=50)


def test_below_threshold_returns_nothing(proc):
    assert all(proc.process(fail(i)) == [] for i in range(4))


def test_fifth_failure_returns_one_candidate(proc):
    results = [proc.process(fail(i)) for i in range(5)]
    assert results[:4] == [[], [], [], []]
    (candidate,) = results[4]
    assert candidate.source == "aggregator"
    assert candidate.entity == "10.0.0.1"
    assert candidate.mitre == "T1110"
    assert len(candidate.evidence) == 5
    assert candidate.details["failure_count"] == 5
    assert candidate.window_start == T0
    assert candidate.window_end == T0 + timedelta(seconds=40)


def test_no_second_candidate_after_threshold(proc):
    for i in range(5):
        proc.process(fail(i))
    assert proc.process(fail(5)) == []


def test_two_ips_do_not_mix(proc):
    for i in range(4):
        proc.process(fail(i, ip="10.0.0.1"))
    assert proc.process(fail(4, ip="10.0.0.2")) == []
    assert len(proc.buffers["10.0.0.1"]) == 4
    assert len(proc.buffers["10.0.0.2"]) == 1


def test_buffer_is_bounded():
    proc = EventProcessor(Aggregator(window_minutes=5, threshold=1000), max_events_per_ip=3)
    for i in range(10):
        proc.process(fail(i))
    assert len(proc.buffers["10.0.0.1"]) == 3


def test_event_without_ip_is_ignored(proc):
    assert proc.process(fail(0, ip=None)) == []
    assert not proc.buffers


def test_failure_without_username_does_not_reach_aggregator(proc):
    for i in range(10):
        assert proc.process(fail(i, user=None)) == []


def test_evidence_is_a_copy(proc):
    for i in range(4):
        proc.process(fail(i))
    (candidate,) = proc.process(fail(4))
    proc.process(fail(5))
    assert len(candidate.evidence) == 5


def test_invalid_max_events():
    with pytest.raises(ValueError):
        EventProcessor(Aggregator(), max_events_per_ip=0)