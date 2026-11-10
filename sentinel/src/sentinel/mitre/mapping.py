from __future__ import annotations

from sentinel.core.alert import AlertCandidate
from sentinel.mitre.techniques import TACTIC_IDS, TACTIC_NAMES, lookup


def enrich(candidate: AlertCandidate) -> AlertCandidate:
    """Add the technique name and tactics (from the local catalog) to candidate.details."""
    entry = lookup(candidate.mitre)
    if entry is not None:
        candidate.details["mitre_name"] = entry["name"]
        candidate.details["mitre_tactics"] = list(entry["tactics"])
    return candidate


def primary_tactic(candidate: AlertCandidate) -> tuple[str, str]:
    """(tactic_id, tactic_name) for the candidate, e.g. ("TA0006", "Credential Access").

    Unmapped candidates (for example ML anomalies) get ("UNMAPPED", "Unmapped").
    """
    tactics = candidate.details.get("mitre_tactics") or []
    slug = candidate.details.get("tactic") or (tactics[0] if tactics else None)
    if slug in TACTIC_IDS:
        return TACTIC_IDS[slug], TACTIC_NAMES[slug]
    return "UNMAPPED", "Unmapped"
