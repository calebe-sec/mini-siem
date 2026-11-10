"""Train the Isolation Forest on a CLEAN auth.log and save it.

    python scripts/train_model.py --log datasets/synthetic/clean.log --year 2026

Train only on a log you trust (no attacks), otherwise attacks become "normal".
"""
from __future__ import annotations

import argparse
from pathlib import Path

from sentinel.core.ingest import load_events # type: ignore
from sentinel.ml.trainer import train_detector # type: ignore


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the anomaly detector")
    parser.add_argument("--log", required=True, help="clean auth.log")
    parser.add_argument("--year", type=int, default=None, help="year of the log (auth.log has none)")
    parser.add_argument("--out", default="models/anomaly_detector.joblib")
    parser.add_argument("--min-windows", type=int, default=100, help="minimum clean windows to train")
    args = parser.parse_args()

    events, stats = load_events(args.log, year=args.year)
    print(f"events: {stats}")
    detector = train_detector(events, min_train_windows=args.min_windows)
    detector.save(Path(args.out))
    print(f"saved detector to {args.out} (threshold={detector.threshold_:.4f})")


if __name__ == "__main__":
    main()
