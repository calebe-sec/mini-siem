from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence

from sentinel.core.alert import AlertCandidate
from sentinel.llm.prompts import sanitize
from sentinel.reporting.json_report import select_evidence

MD_EVIDENCE = 10


def _cell(value: object, max_len: int = 120) -> str:
    """Log text is untrusted: one line, bounded, and without characters that break a table."""
    return sanitize(value if value is not None else "", max_len).replace("|", "\\|").replace("`", "'")


def render_markdown(candidates: Sequence[AlertCandidate], meta: Optional[dict] = None) -> str:
    meta = meta or {}
    lines = ["# Sentinel report", ""]
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    for key, value in meta.items():
        lines.append(f"- {key}: {_cell(value, 200)}")
    lines += ["", f"**{len(candidates)} alert(s).** LLM triage is an advisory second opinion: "
              "severity below is the one decided by detection.", ""]

    if candidates:
        lines += ["| # | Severity | Source | Entity | Title | Triage |", "|---|---|---|---|---|---|"]
        for i, c in enumerate(candidates, 1):
            status = c.triage["status"] if c.triage else "-"
            lines.append(f"| {i} | {c.severity} | {c.source} | {_cell(c.entity)} | {_cell(c.title)} | {status} |")
        lines.append("")

    for i, c in enumerate(candidates, 1):
        lines += [f"## {i}. {_cell(c.title)}", ""]
        lines.append(f"- **Severity:** {c.severity}")
        lines.append(f"- **Source:** {c.source}")
        lines.append(f"- **Entity:** {_cell(c.entity)}")
        lines.append(f"- **Window:** {c.window_start.isoformat()} to {c.window_end.isoformat()}")
        if c.mitre:
            name = c.details.get("mitre_name")
            lines.append(f"- **MITRE ATT&CK:** {c.mitre}" + (f" ({_cell(name)})" if name else ""))
        if c.details.get("repeat_count"):
            lines.append(f"- **Repeated:** {c.details['repeat_count']} times in a short period")
        if c.details.get("correlated_sources"):
            lines.append(f"- **Also flagged by:** {', '.join(c.details['correlated_sources'])}")
        lines.append("")

        if c.triage and c.triage.get("status") == "ok" and c.triage.get("data"):
            d = c.triage["data"]
            lines += ["**LLM triage (advisory):**", "",
                      f"- Summary: {_cell(d['summary'], 600)}",
                      f"- Suggested severity: {d['severity_suggestion']}",
                      f"- False positive likelihood: {d['false_positive_likelihood']}"]
            if d.get("mitre_hypothesis"):
                lines.append(f"- MITRE hypothesis: {d['mitre_hypothesis']}")
            if d.get("next_steps"):
                lines.append("- Next steps:")
                lines += [f"  - {_cell(step, 200)}" for step in d["next_steps"]]
            lines.append("")
        elif c.triage:
            lines += [f"_LLM triage not available ({c.triage.get('status')}: "
                      f"{_cell(c.triage.get('error'), 200)})_", ""]

        if c.evidence:
            shown = select_evidence(c.evidence, MD_EVIDENCE)
            lines += [f"Evidence ({len(shown)} of {len(c.evidence)} events):", "",
                      "| Time | Type | User | Message |", "|---|---|---|---|"]
            for e in shown:
                kind = e.event_type.value if e.event_type else "-"
                lines.append(f"| {e.timestamp.isoformat()} | {kind} | {_cell(e.username)} | {_cell(e.raw_message)} |")
            lines.append("")
    return "\n".join(lines) + "\n"


def write_markdown(candidates: Sequence[AlertCandidate], path: str | Path, meta: Optional[dict] = None) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_markdown(candidates, meta), encoding="utf-8")
    return target
