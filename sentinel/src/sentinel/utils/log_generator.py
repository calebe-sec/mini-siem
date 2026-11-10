"""Synthetic auth.log generator, for demos and tests. The data is fake."""
from __future__ import annotations

import random
from datetime import datetime, timedelta

HOST = "web01"
USERS = [f"user{i:02d}" for i in range(12)]
OFFICE_IPS = [f"192.168.1.{n}" for n in range(10, 30)]


def _stamp(ts: datetime) -> str:
    # syslog style: day padded with a space ("Nov  1")
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"


class _Writer:
    def __init__(self) -> None:
        self.rows: list[tuple[datetime, str]] = []
        self._pid = 1000

    def pid(self) -> int:
        self._pid += 1
        return self._pid

    def ssh(self, ts: datetime, message: str) -> None:
        self.rows.append((ts, f"{_stamp(ts)} {HOST} sshd[{self.pid()}]: {message}"))

    def sudo(self, ts: datetime, message: str) -> None:
        # sudo lines have no [pid]
        self.rows.append((ts, f"{_stamp(ts)} {HOST} sudo: {message}"))

    def failed(self, ts: datetime, user: str, ip: str, invalid: bool = False) -> None:
        port = random.randint(20000, 60000)
        if invalid:
            self.ssh(ts, f"Invalid user {user} from {ip} port {port}")
            self.ssh(ts + timedelta(seconds=1), f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        else:
            self.ssh(ts, f"Failed password for {user} from {ip} port {port} ssh2")

    def accepted(self, ts: datetime, user: str, ip: str) -> None:
        self.ssh(ts, f"Accepted password for {user} from {ip} port {random.randint(20000, 60000)} ssh2")

    def sudo_cmd(self, ts: datetime, user: str, command: str) -> None:
        self.sudo(ts, f"  {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}")


def generate(days: int = 7, seed: int = 42, attacks: bool = False, start: datetime = datetime(2026, 10, 1)) -> list[str]:
    """Return auth.log lines (sorted by time). Clean office traffic, plus attacks if asked."""
    random.seed(seed)
    w = _Writer()

    for day in range(days):
        base = start + timedelta(days=day)
        for ip in OFFICE_IPS:
            for _ in range(random.randint(1, 4)):
                ts = base + timedelta(hours=random.randint(7, 20), minutes=random.randint(0, 59), seconds=random.randint(0, 59))
                user = random.choice(USERS)
                roll = random.random()
                if roll < 0.20:      # a typo or two before the right password
                    for k in range(random.randint(1, 2)):
                        w.failed(ts - timedelta(seconds=10 * (k + 1)), user, ip)
                elif roll < 0.27:    # forgot the password: a short burst of failures
                    for k in range(random.randint(3, 6)):
                        w.failed(ts - timedelta(seconds=7 * (k + 1)), user, ip)
                w.accepted(ts, user, ip)
                if random.random() < 0.15:   # a second login close to the first
                    w.accepted(ts + timedelta(minutes=random.randint(1, 4)), user, ip)
                for k in range(random.choice([0, 0, 1, 2, 3])):
                    w.sudo_cmd(ts + timedelta(minutes=2 + k), user,
                               random.choice(["/usr/bin/apt update", "/usr/bin/systemctl status nginx", "/usr/bin/journalctl -xe"]))

    if attacks:
        day = start + timedelta(days=days)   # the day right after the clean period
        # 1. brute force from one IP, then a root login
        t = day + timedelta(hours=3, minutes=10)
        for i in range(30):
            w.failed(t + timedelta(seconds=2 * i), "root", "203.0.113.9")
        w.accepted(t + timedelta(seconds=70), "root", "203.0.113.9")
        # 2. username spray from another IP (one failure per username)
        t = day + timedelta(hours=14, minutes=5)
        for i, name in enumerate(["admin", "test", "oracle", "ubuntu", "postgres", "git", "ftp", "guest", "jenkins", "pi"]):
            w.failed(t + timedelta(seconds=3 * i), name, "203.0.113.20", invalid=True)
        # 3. sudo abuse
        t = day + timedelta(hours=15)
        w.sudo(t, "pam_unix(sudo:auth): authentication failure; logname=user03 uid=1003 euid=0 tty=/dev/pts/0 ruser=user03 rhost=  user=user03")
        w.sudo_cmd(t + timedelta(minutes=1), "user03", "/bin/cat /etc/shadow")

    w.rows.sort(key=lambda row: row[0])
    return [line for _, line in w.rows]
