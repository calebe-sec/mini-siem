import json
from datetime import datetime

import joblib
import numpy as np
import pytest

from sentinel.ml.anomaly import MODEL_FORMAT_VERSION, AnomalyDetector
from sentinel.ml.features import FEATURE_NAMES, build_windows
from sentinel.ml.synthetic import ATTACK_NAMES, attack_events, clean_events

SEED = 42


def clean_windows(n, start, seed):
    return build_windows(clean_events(n, start, np.random.default_rng(seed)))


@pytest.fixture(scope="module")
def scenario():
    """Train in September, calibrate in October, test in November (time-based split)."""
    train = clean_windows(2000, datetime(2026, 9, 1), seed=1)
    calibration = clean_windows(500, datetime(2026, 10, 1), seed=2)

    rng = np.random.default_rng(3)
    atk_events, labels = attack_events(datetime(2026, 11, 1), rng)
    clean_test_events = clean_events(400, datetime(2026, 11, 1), rng)
    test = build_windows(clean_test_events + atk_events)

    detector = AnomalyDetector(random_state=SEED).fit(train, calibration=calibration)
    return detector, train, test, labels


def test_all_injected_attacks_are_flagged(scenario):
    detector, _, test, labels = scenario
    flagged = {a.entity for a in detector.detect(test)}
    assert set(labels) <= flagged, f"missed: {sorted(set(labels) - flagged)}"


def test_false_positives_stay_low(scenario):
    detector, _, test, labels = scenario
    n_clean = sum(w.entity not in labels for w in test)
    false_positives = [a for a in detector.detect(test) if a.entity not in labels]
    # The budget is about 1%; allow a generous 5% so the test is not brittle.
    assert len(false_positives) <= 0.05 * n_clean


def test_anomalies_are_sorted_most_anomalous_first(scenario):
    detector, _, test, _ = scenario
    scores = [a.score for a in detector.detect(test)]
    assert scores == sorted(scores)


def test_username_spray_is_explained_by_distinct_usernames(scenario):
    detector, _, test, labels = scenario
    sprays = [a for a in detector.detect(test) if labels.get(a.entity) == "username_spray"]
    assert sprays
    for anomaly in sprays:
        assert "distinct_usernames" in [name for name, _ in anomaly.top_deviations]


def test_every_attack_type_is_covered(scenario):
    _, _, _, labels = scenario
    assert set(labels.values()) == set(ATTACK_NAMES)


def test_anomaly_fields_and_json(scenario):
    detector, _, test, _ = scenario
    anomaly = detector.detect(test)[0]
    assert anomaly.source == "ml"
    assert anomaly.score < anomaly.threshold
    assert len(anomaly.top_deviations) == detector.top_k
    assert set(anomaly.features) == set(FEATURE_NAMES)
    payload = json.loads(json.dumps(anomaly.to_dict()))   # must be JSON-serializable
    assert payload["entity"] == anomaly.entity


def test_same_seed_gives_same_scores(scenario):
    _, train, test, _ = scenario
    a = AnomalyDetector(random_state=SEED).fit(train)
    b = AnomalyDetector(random_state=SEED).fit(train)
    assert np.allclose(a.score(test), b.score(test))


def test_detect_on_nothing_returns_nothing(scenario):
    detector, *_ = scenario
    assert detector.detect([]) == []
    assert detector.score([]).size == 0


def test_not_fitted_raises():
    with pytest.raises(RuntimeError):
        AnomalyDetector().detect([])


def test_too_little_training_data_is_rejected():
    tiny = clean_windows(20, datetime(2026, 9, 1), seed=1)
    with pytest.raises(ValueError, match="at least"):
        AnomalyDetector().fit(tiny)


@pytest.mark.parametrize("bad", [0, -1, 50, 80])
def test_threshold_percentile_is_validated(bad):
    with pytest.raises(ValueError):
        AnomalyDetector(threshold_percentile=bad)


def test_save_and_load_round_trip(scenario, tmp_path):
    detector, _, test, _ = scenario
    path = tmp_path / "models" / "detector.joblib"
    detector.save(path)

    loaded = AnomalyDetector.load(path)
    assert loaded.threshold_ == detector.threshold_
    assert np.allclose(loaded.score(test), detector.score(test))
    assert [a.entity for a in loaded.detect(test)] == [a.entity for a in detector.detect(test)]


def test_load_rejects_model_trained_with_other_features(tmp_path):
    path = tmp_path / "old.joblib"
    joblib.dump(
        {"version": MODEL_FORMAT_VERSION, "feature_names": ("only_one",), "params": {}, "state": None},
        path,
    )
    with pytest.raises(ValueError, match="different features"):
        AnomalyDetector.load(path)