"""Generate a fake auth.log.

    python scripts/generate_logs.py --out datasets/synthetic/clean.log --days 14
    python scripts/generate_logs.py --out datasets/synthetic/attack.log --days 1 --attacks --start 2026-11-01

Use a clean log (no --attacks) to train the ML layer, and an --attacks log to test detection.
The data is fake: it proves the plumbing, not real-world detection.
"""
from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from sentinel.utils.log_generator import generate # type: ignore


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a synthetic auth.log")
    parser.add_argument("--out", required=True, help="output file")
    parser.add_argument("--days", type=int, default=7, help="days of normal traffic (default 7)")
    parser.add_argument("--attacks", action="store_true", help="add attacks on the day after the normal days")
    parser.add_argument("--start", default="2026-10-01", help="first day, YYYY-MM-DD")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    lines = generate(days=args.days, seed=args.seed, attacks=args.attacks,
                     start=datetime.strptime(args.start, "%Y-%m-%d"))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} lines to {out}")


if __name__ == "__main__":
    main()
