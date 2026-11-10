from __future__ import annotations

import sys
from typing import Optional, Sequence

from sentinel.core.alert import AlertCandidate
from sentinel.llm.prompts import sanitize


def render_summary(candidates: Sequence[AlertCandidate], meta: Optional[dict] = None) -> str:
    """Plain-text summary (no colors, so it is easy to test and to redirect to a file)."""
    lines = ["", "=== Sentinel summary ==="]
    for key, value in (meta or {}).items():
        lines.append(f"{key}: {value}")
    lines.append(f"alerts: {len(candidates)}")

    if candidates:
        lines.append("")
        lines.append(f"{'#':>3}  {'SEVERITY':<9} {'SOURCE':<11} {'ENTITY':<18} {'TRIAGE':<15} TITLE")
        for i, c in enumerate(candidates, 1):
            status = c.triage["status"] if c.triage else "-"
            extra = ""
            if c.triage and c.triage.get("data"):
                extra = f" (fp: {c.triage['data']['false_positive_likelihood']})"
            lines.append(
                f"{i:>3}  {c.severity:<9} {c.source:<11} {sanitize(c.entity, 18):<18} "
                f"{status + extra:<15} {sanitize(c.title, 60)}"
            )
    lines.append("")
    return "\n".join(lines)


def print_summary(candidates: Sequence[AlertCandidate], meta: Optional[dict] = None, file=None) -> None:
    print(render_summary(candidates, meta), file=file or sys.stdout)
