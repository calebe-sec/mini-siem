from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

import numpy as np
import pytest

from sentinel.ml.features import ( # type: ignore #ignore
    FEATURE_NAMES,
    FeatureConfig,
    build_windows,
    classify,
    to_matrix,
    window_start_for,
)

T0 = datetime(2026, 1, 1, 12, 0, 0)


class T(Enum):
    LOGIN_FAILURE = 1
    LOGIN_SUCCESS = 2
    OTHER = 3


@dataclass
class Ev:
    timestamp: datetime
    source_ip: str | None
    username: str | None
    event_type: object


def ev(seconds, kind=T.LOGIN_FAILURE, ip="10.0.0.1", user="root"):
    return Ev(T0 + timedelta(seconds=seconds), ip, user, kind)


def row(window):
    return window.as_dict()


def test_window_start_aligns_to_bucket():
    ts = datetime(2026, 1, 1, 12, 7, 30)
    assert window_start_for(ts, timedelta(minutes=5)) == datetime(2026, 1, 1, 12, 5, 0)


def test_window_start_is_stable_at_boundary():
    ts = datetime(2026, 1, 1, 12, 5, 0)
    assert window_start_for(ts, timedelta(minutes=5)) == ts


def test_counts_and_ratio():
    events = [ev(0), ev(10), ev(20), ev(30, T.LOGIN_SUCCESS)]
    (w,) = build_windows(events)
    r = row(w)
    assert r["failed_logins"] == 3
    assert r["successful_logins"] == 1
    assert r["failure_ratio"] == pytest.approx(0.75)
    assert r["total_events"] == 4


def test_other_events_count_in_total_but_not_in_ratio():
    events = [ev(0, T.OTHER), ev(10, T.LOGIN_FAILURE)]
    (w,) = build_windows(events)
    r = row(w)
    assert r["total_events"] == 2
    assert r["failure_ratio"] == 1.0


def test_no_auth_events_gives_zero_ratio():
    (w,) = build_windows([ev(0, T.OTHER), ev(5, T.OTHER)])
    assert row(w)["failure_ratio"] == 0.0


def test_distinct_usernames():
    events = [ev(0, user="a"), ev(5, user="b"), ev(10, user="a"), ev(15, user=None)]
    (w,) = build_windows(events)
    assert row(w)["distinct_usernames"] == 2


def test_gap_mean_and_std():
    # gaps are 10s and 20s: mean 15, population std 5
    (w,) = build_windows([ev(0), ev(10), ev(30)])
    r = row(w)
    assert r["mean_gap_seconds"] == pytest.approx(15.0)
    assert r["std_gap_seconds"] == pytest.approx(5.0)


def test_gaps_do_not_depend_on_input_order():
    (a,) = build_windows([ev(0), ev(10), ev(30)])
    (b,) = build_windows([ev(30), ev(0), ev(10)])
    assert a.values == b.values


def test_single_event_uses_neutral_gap_values():
    (w,) = build_windows([ev(0)])
    r = row(w)
    assert r["mean_gap_seconds"] == 300.0   # the window length
    assert r["std_gap_seconds"] == 0.0


def test_hour_of_day_comes_from_the_event_not_the_clock():
    (w,) = build_windows([ev(0)])
    assert row(w)["hour_of_day"] == 12


def test_success_after_failures_flag():
    attack = [ev(0), ev(5), ev(10), ev(15, T.LOGIN_SUCCESS)]
    benign = [ev(0, T.LOGIN_SUCCESS), ev(5), ev(10), ev(15)]
    (a,) = build_windows(attack)
    (b,) = build_windows(benign)
    assert row(a)["success_after_failures"] == 1.0
    assert row(b)["success_after_failures"] == 0.0


def test_success_after_failures_needs_enough_failures():
    events = [ev(0), ev(5), ev(10, T.LOGIN_SUCCESS)]   # only 2 failures, default minimum is 3
    (w,) = build_windows(events)
    assert row(w)["success_after_failures"] == 0.0
    (w2,) = build_windows(events, FeatureConfig(success_after_failures_min=2))
    assert row(w2)["success_after_failures"] == 1.0


def test_different_ips_make_separate_rows():
    events = [ev(0, ip="10.0.0.1"), ev(5, ip="10.0.0.2")]
    assert [w.entity for w in build_windows(events)] == ["10.0.0.1", "10.0.0.2"]


def test_same_ip_in_different_windows_makes_separate_rows():
    events = [ev(0), ev(400)]   # 400s later is the next 5-minute window
    assert len(build_windows(events)) == 2


def test_events_without_ip_are_skipped():
    assert build_windows([ev(0, ip=None), ev(5, ip="")]) == []


def test_min_events_filters_small_windows():
    events = [ev(0, ip="10.0.0.1"), ev(5, ip="10.0.0.2"), ev(10, ip="10.0.0.2"), ev(15, ip="10.0.0.2")]
    windows = build_windows(events, FeatureConfig(min_events=3))
    assert [w.entity for w in windows] == ["10.0.0.2"]


def test_classify_accepts_plain_strings_and_enums():
    assert classify(ev(0, "ssh_failed_password")) == "failure"
    assert classify(ev(0, "accepted_publickey")) == "success"
    assert classify(ev(0, T.OTHER)) == "other"


def test_matrix_shape_and_empty_case():
    windows = build_windows([ev(0), ev(400)])
    matrix = to_matrix(windows)
    assert matrix.shape == (2, len(FEATURE_NAMES))
    assert matrix.dtype == float
    assert to_matrix([]).shape == (0, len(FEATURE_NAMES))


def test_every_row_matches_feature_names():
    for w in build_windows([ev(0), ev(10, T.LOGIN_SUCCESS)]):
        assert len(w.values) == len(FEATURE_NAMES)
        assert set(w.as_dict()) == set(FEATURE_NAMES)


@pytest.mark.parametrize("bad", [0, -5, 1441])
def test_config_rejects_bad_window(bad):
    with pytest.raises(ValueError):
        FeatureConfig(window_minutes=bad)


def test_matrix_values_are_finite():
    windows = build_windows([ev(0), ev(10), ev(30, T.LOGIN_SUCCESS)])
    assert np.isfinite(to_matrix(windows)).all()