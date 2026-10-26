from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

import numpy as np

ATTACK_NAMES = ("brute_force", "username_spray", "offhours_success")

USERS = [f"user{i:02d}" for i in range(30)]


class SyntheticEventType(Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"


@dataclass(frozen=True)
class SyntheticEvent:
    # Has the same four attributes features.py reads from your real Event.

    timestamp: datetime
    source_ip: str
    username: str
    event_type: SyntheticEventType


FAIL = SyntheticEventType.LOGIN_FAILURE
OK = SyntheticEventType.LOGIN_SUCCESS


def _midnight(dt: datetime) -> datetime:
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def clean_events(n_windows: int, start: datetime, rng: np.random.Generator, window_seconds: int = 300,) -> list[SyntheticEvent]:
   
    base = _midnight(start)
    buckets_per_hour = max(1, 3600 // window_seconds)
    events: list[SyntheticEvent] = []

    for i in range(n_windows):
        hour = int(np.clip(rng.normal(14, 3.5), 0, 23))           # centered at 2 p.m.
        window_start = base + timedelta(
            days=i % 30, hours=hour, seconds=window_seconds * (i % buckets_per_hour)
        )
        ip = f"192.168.{rng.integers(0, 4)}.{rng.integers(2, 250)}"
        owner = USERS[int(rng.integers(len(USERS)))]

        n_fail = int(rng.poisson(0.6))
        n_ok = max(1, int(rng.poisson(3)))
        offsets = np.sort(rng.uniform(0, window_seconds, n_fail + n_ok))   # irregular, human-like

        for k, offset in enumerate(offsets):
            who = owner if rng.random() >= 0.05 else USERS[int(rng.integers(len(USERS)))]
            events.append(
                SyntheticEvent(
                    window_start + timedelta(seconds=float(offset)),
                    ip,
                    who,
                    FAIL if k < n_fail else OK,   # typos come before the successful login
                )
            )
    return events


def _burst(window_start: datetime, ip: str, attempts: list[tuple[str, SyntheticEventType]], gap: float, window_seconds: int, rng: np.random.Generator,) -> list[SyntheticEvent]:
    """Evenly spaced attempts with a little jitter: the regular rhythm of a script."""
    out = []
    for i, (user, kind) in enumerate(attempts):
        offset = (i + rng.uniform(-0.1, 0.1)) * gap
        offset = min(max(offset, 0.0), window_seconds - 0.001)
        out.append(SyntheticEvent(window_start + timedelta(seconds=offset), ip, user, kind))
    return out


def attack_events(start: datetime, rng: np.random.Generator, per_attack: int = 5, window_seconds: int = 300,) -> tuple[list[SyntheticEvent], dict[str, str]]:
    if per_attack > 40:
        raise ValueError("per_attack must be 40 or less (attack IPs would collide)")

    base = _midnight(start)
    events: list[SyntheticEvent] = []
    labels: dict[str, str] = {}

    for k, name in enumerate(ATTACK_NAMES):
        for j in range(per_attack):
            ip = f"203.0.113.{10 + k * 40 + j}"
            labels[ip] = name

            if name == "brute_force":
                hour = int(rng.integers(0, 24))
                attempts = [("root", FAIL)] * 60
                gap = window_seconds / 60
            elif name == "username_spray":
                hour = 3
                attempts = [(f"acct{n:03d}", FAIL) for n in range(40)]
                gap = window_seconds / 40
            else:  # offhours_success
                hour = 3
                attempts = [(f"acct{n % 6:03d}", FAIL) for n in range(8)] + [("acct000", OK)]
                gap = window_seconds / 15

            window_start = base + timedelta(days=j, hours=hour)
            events += _burst(window_start, ip, attempts, gap, window_seconds, rng)

    return events, labels