"""Run Sentinel on an auth.log: parse, normalize, rules, aggregator, ML, LLM triage, reports.

    python scripts/run_pipeline.py --log datasets/synthetic/attack.log --year 2026 --no-llm
    python scripts/run_pipeline.py --log /var/log/auth.log --year 2026 --detector models/anomaly_detector.joblib
    python scripts/run_pipeline.py --log attack.log --year 2026 --logrecon http://localhost:8080

LLM triage needs Ollama running with the model pulled (ollama pull qwen2.5:3b).
If Ollama is not reachable, the alerts are still created, just without triage.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from sentinel.core.ingest import load_events # type: ignore
from sentinel.core.pipeline import EventProcessor, analyze # type: ignore
from sentinel.detection.engine import EngineRule # type: ignore
from sentinel.detection.rule_loader import RulerLoader # type: ignore
from sentinel.detection.sliding_window import Aggregator # type: ignore
from sentinel.llm.ollama_client import OllamaClient # type: ignore
from sentinel.llm.triage import Triager # type: ignore
from sentinel.ml.predictor import load_detector # type: ignore
from sentinel.reporting.alert_manager import AlertManager # type: ignore
from sentinel.reporting.json_report import write_json # type: ignore
from sentinel.reporting.logrecon_client import LogReconClient # type: ignore
from sentinel.reporting.markdown_report import write_markdown # type: ignore
from sentinel.reporting.terminal import print_summary # type: ignore


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run the Sentinel pipeline on an auth.log")
    p.add_argument("--log", required=True, help="auth.log file")
    p.add_argument("--year", type=int, default=None, help="year of the log (auth.log has none; default: current year)")
    p.add_argument("--out", default="reports", help="reports folder (default: reports)")
    p.add_argument("--threshold", type=int, default=5, help="failed logins that trigger the aggregator")
    p.add_argument("--window-minutes", type=int, default=5, help="aggregator window")
    p.add_argument("--detector", default="models/anomaly_detector.joblib", help="saved ML detector (skipped if missing)")
    p.add_argument("--no-ml", action="store_true", help="do not run the ML layer")
    p.add_argument("--no-llm", action="store_true", help="do not run LLM triage")
    p.add_argument("--model", default=os.environ.get("OLLAMA_MODEL", "qwen2.5:3b"))
    p.add_argument("--ollama-host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    p.add_argument("--max-triage", type=int, default=20, help="triage at most N alerts (most severe first)")
    p.add_argument("--logrecon", default=None, metavar="URL", help="send alerts to LogRecon, e.g. http://localhost:8080")
    p.add_argument("--api-key", default=os.environ.get("LOGRECON_API_KEY"))
    p.add_argument("--source-name", default="auth.log", help="LogRecon source name")
    return p


def build_triager(args) -> Triager | None:
    if args.no_llm:
        return None
    client = OllamaClient(model=args.model, host=args.ollama_host)
    if not client.is_available():
        print(f"warning: Ollama model {args.model!r} not reachable at {args.ollama_host}; "
              "continuing without LLM triage", file=sys.stderr)
        return None
    return Triager(client)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    log_path = Path(args.log)
    if not log_path.is_file():
        print(f"error: log file not found: {log_path}", file=sys.stderr)
        return 2

    events, stats = load_events(log_path, year=args.year)
    if not events:
        print(f"error: no usable events in {log_path} ({stats})", file=sys.stderr)
        return 2

    engine = EngineRule(RulerLoader().open_conditions_yaml(RulerLoader.FILES))
    processor = EventProcessor(
        Aggregator(window_minutes=args.window_minutes, threshold=args.threshold), engine=engine
    )
    detector = None if args.no_ml else load_detector(args.detector)
    candidates = analyze(events, processor, detector)

    manager = AlertManager(triager=build_triager(args), max_triage=args.max_triage)
    manager.add(candidates)
    manager.correlate()
    triage_counts = manager.triage(
        on_progress=lambda i, n, c: print(f"triage {i}/{n}: {c.title} ({c.entity})", file=sys.stderr)
    )
    alerts = manager.results()

    meta = {
        "log": str(log_path),
        "events": stats["events"],
        "lines_unrecognized": stats["unrecognized"],
        "lines_invalid": stats["invalid"],
        "ml": "on" if detector is not None else "off",
        "triage": triage_counts or "off",
    }
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(args.out)
    json_path = write_json(alerts, out / "json" / f"alerts_{stamp}.json", meta)
    md_path = write_markdown(alerts, out / "markdown" / f"report_{stamp}.md", meta)
    print_summary(alerts, meta)
    print(f"json report:     {json_path}")
    print(f"markdown report: {md_path}")

    if args.logrecon:
        client = LogReconClient(args.logrecon, api_key=args.api_key)
        sent, errors = client.send_all(alerts, args.source_name)
        print(f"logrecon: sent {sent}/{len(alerts)} alerts")
        for error in errors:
            print(f"  failed: {error}", file=sys.stderr)
        if errors:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
