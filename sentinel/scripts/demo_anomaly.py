"""


Runnable demo of Sentinel's ML layer on synthetic data.

    python scripts/demo_anomaly.py                      # run the demo
    python scripts/demo_anomaly.py --save models/anomaly_detector.joblib

Needs the package importable (pip install -e .) and: numpy, scikit-learn, joblib.
The data is fake: a good result proves the plumbing, not real-world detection.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime

import numpy as np

from sentinel.ml.anomaly import AnomalyDetector # type: ignore
from sentinel.ml.features import FeatureConfig, build_windows # type: ignore
from sentinel.ml.synthetic import ATTACK_NAMES, attack_events, clean_events # type: ignore

SEED = 42            # arbitrary, only there so every run gives the same numbers
TRAIN_WINDOWS = 2000      # clean baseline (September)
CALIBRATION_WINDOWS = 500  # clean, unseen by the forest (October): sets the threshold
TEST_CLEAN_WINDOWS = 400   # clean traffic mixed with the attacks (November)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--save", metavar="PATH", help="write the trained detector to PATH")
    args = parser.parse_args()

    cfg = FeatureConfig()
    window_seconds = cfg.window_minutes * 60
    rng = np.random.default_rng(SEED)

    # Time-based split: train earliest, calibrate next, test latest.
    train = build_windows(clean_events(TRAIN_WINDOWS, datetime(2026, 9, 1), rng, window_seconds), cfg)
    calibration = build_windows(
        clean_events(CALIBRATION_WINDOWS, datetime(2026, 10, 1), rng, window_seconds), cfg
    )
    attacks, labels = attack_events(datetime(2026, 11, 1), rng, window_seconds=window_seconds)
    test = build_windows(
        clean_events(TEST_CLEAN_WINDOWS, datetime(2026, 11, 1), rng, window_seconds) + attacks, cfg
    )

    detector = AnomalyDetector(random_state=SEED).fit(train, calibration=calibration)
    anomalies = detector.detect(test)

    flagged = {a.entity for a in anomalies}
    n_clean = sum(w.entity not in labels for w in test)
    false_positives = [a for a in anomalies if a.entity not in labels]

    print(
        f"train={len(train)} calibration={len(calibration)} test={len(test)}  "
        f"threshold={detector.threshold_:.3f}\n"
    )
    for name in ATTACK_NAMES:
        ips = [ip for ip, label in labels.items() if label == name]
        hits = sum(ip in flagged for ip in ips)
        print(f"{name:<18} flagged {hits}/{len(ips)}")
    print(f"{'clean windows':<18} flagged {len(false_positives)}/{n_clean}  <- false positives")

    print("\nMost anomalous windows:")
    for a in anomalies[:5]:
        devs = ", ".join(f"{name} ({z:+.1f} sd)" for name, z in a.top_deviations)
        label = labels.get(a.entity, "clean")
        print(f"  {a.window_start:%Y-%m-%d %H:%M}  {a.entity:<15} score={a.score:.3f}  [{label}]  {devs}")

    if anomalies:
        print("\nPayload the LLM triage step would receive for the top anomaly:")
        print(json.dumps(anomalies[0].to_dict(), indent=2))

    if args.save:
        detector.save(args.save)
        print(f"\nSaved detector to {args.save}")


if __name__ == "__main__":
    main()