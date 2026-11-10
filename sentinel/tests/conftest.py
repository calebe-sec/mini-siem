from datetime import datetime, timedelta

import pytest

from sentinel.core.event import Event # type: ignore
from sentinel.core.event_type import EventType # type: ignore

T0 = datetime(2026, 1, 1, 12, 0, 0)


@pytest.fixture
def make_event():
    def _make(i=0, etype=EventType.SSH_FAILED_PASSWORD, ip="10.0.0.1", user="root", command=None,
              msg=None, hostname="web01"):
        return Event(
            timestamp=T0 + timedelta(seconds=i),
            source_ip=ip,
            event_type=etype,
            source="auth_log",
            raw_message=msg if msg is not None else f"{etype.value} {user}",
            username=user,
            hostname=hostname,
            command=command,
        )
    return _make
