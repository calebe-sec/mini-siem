from datetime import datetime, timedelta

import pytest

from src.sentinel.detection.sliding_window import Aggregator  # adjust to your real import path

T0 = datetime(2026, 1, 1, 12, 0, 0)


def feed(agg, n, start, step, user="root", ip="10.0.0.1"):
    """Send n failures starting at `start`, spaced by `step`. Returns the list of results."""
    return [agg.add_failure(user, ip, start + i * step) for i in range(n)]


@pytest.fixture
def agg():
    return Aggregator(window_minutes=5, threshold=5)


def test_below_threshold_does_not_trigger(agg):
    results = feed(agg, 4, T0, timedelta(seconds=10))
    assert not any(results)


def test_triggers_exactly_on_threshold(agg):
    results = feed(agg, 5, T0, timedelta(seconds=10))
    assert results == [False, False, False, False, True]


def test_no_spam_after_threshold(agg):
    results = feed(agg, 8, T0, timedelta(seconds=10))
    assert results.count(True) == 1
    assert results[4] is True


def test_slow_attack_outside_window_does_not_trigger(agg):
    # 5 failures, 2 minutes apart: never more than 3 inside a 5-minute window
    results = feed(agg, 5, T0, timedelta(minutes=2))
    assert not any(results)


def test_different_ips_are_counted_separately(agg):
    a = feed(agg, 4, T0, timedelta(seconds=10), ip="10.0.0.1")
    b = feed(agg, 4, T0, timedelta(seconds=10), ip="10.0.0.2")
    assert not any(a) and not any(b)


def test_alerts_again_after_attack_cools_down(agg):
    first = feed(agg, 5, T0, timedelta(seconds=1))
    second = feed(agg, 5, T0 + timedelta(minutes=20), timedelta(seconds=1))
    assert first.count(True) == 1
    assert second.count(True) == 1


def test_idle_keys_are_removed(agg):
    agg.add_failure("bob", "1.1.1.1", T0)
    # a later event from someone else triggers the sweep (more than one window later)
    agg.add_failure("alice", "2.2.2.2", T0 + timedelta(minutes=6))
    assert ("bob", "1.1.1.1") not in agg.failures
    assert ("alice", "2.2.2.2") in agg.failures