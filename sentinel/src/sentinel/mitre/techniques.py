"""Small MITRE ATT&CK catalog: only the techniques Sentinel's rules use.

Not the full ATT&CK matrix. Extend it when you add rules.
"""
from __future__ import annotations

# Tactic id (ATT&CK Enterprise) by the slug used in the YAML rules.
TACTIC_IDS: dict[str, str] = {
    "reconnaissance": "TA0043",
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "command_and_control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}

TACTIC_NAMES: dict[str, str] = {
    slug: slug.replace("_", " ").title() for slug in TACTIC_IDS
}

TECHNIQUES: dict[str, dict] = {
    "T1003":     {"name": "OS Credential Dumping", "tactics": ["credential_access"]},
    "T1003.001": {"name": "LSASS Memory", "tactics": ["credential_access"]},
    "T1003.008": {"name": "/etc/passwd and /etc/shadow", "tactics": ["credential_access"]},
    "T1204":     {"name": "User Execution", "tactics": ["execution"]},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactics": ["lateral_movement"]},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactics": ["lateral_movement"]},
    "T1021.006": {"name": "Windows Remote Management", "tactics": ["lateral_movement"]},
    "T1053.005": {"name": "Scheduled Task", "tactics": ["execution", "persistence", "privilege_escalation"]},
    "T1059.001": {"name": "PowerShell", "tactics": ["execution"]},
    "T1059.003": {"name": "Windows Command Shell", "tactics": ["execution"]},
    "T1078":     {"name": "Valid Accounts", "tactics": ["defense_evasion", "persistence", "privilege_escalation", "initial_access"]},
    "T1110":     {"name": "Brute Force", "tactics": ["credential_access"]},
    "T1110.001": {"name": "Password Guessing", "tactics": ["credential_access"]},
    "T1110.003": {"name": "Password Spraying", "tactics": ["credential_access"]},
    "T1136.001": {"name": "Local Account", "tactics": ["persistence"]},
    "T1543.003": {"name": "Windows Service", "tactics": ["persistence", "privilege_escalation"]},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "tactics": ["persistence", "privilege_escalation"]},
    "T1548.003": {"name": "Sudo and Sudo Caching", "tactics": ["privilege_escalation", "defense_evasion"]},
    "T1558.003": {"name": "Kerberoasting", "tactics": ["credential_access"]},
}


def lookup(technique_id: str | None) -> dict | None:
    """Catalog entry for a technique id, or None if unknown."""
    if not technique_id:
        return None
    return TECHNIQUES.get(technique_id.strip().upper())


def is_known(technique_id: str | None) -> bool:
    return lookup(technique_id) is not None
