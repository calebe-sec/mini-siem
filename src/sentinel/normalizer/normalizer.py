from datetime import datetime

from ..core.event import Event
from ..core.event_type import EventType
from ..normalizer.schema import validate_event

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

def _build_timestamp_auth(data, current_year=2026):
    return datetime(
        year=current_year,
        month=MONTHS[data["month"]],
        day=int(data["day"]),
        hour=int(data["hour"].split(":")[0]),
        minute=int(data["hour"].split(":")[1]),
        second=int(data["hour"].split(":")[2]),
    )

def _build_timestamp_web(data):
    return datetime(
        year=int(data["year"]),
        month=MONTHS[data["month"]],
        day=int(data["day"]),
        hour=int(data["hour"]),
        minute=int(data["min"]),
        second=int(data["sec"]),
    )

def _normalize_auth(data):
    event_type = EventType(data["event_type"]) if data.get("event_type") else None

    return Event(
        timestamp=_build_timestamp_auth(data),
        source_ip=data.get("ip"),
        event_type=event_type,
        source="auth_log",
        raw_message=data.get("message", ""),
        user=data.get("user"),
        port=int(data["port"]) if data.get("port") else None,
        hostname=data.get("hostname"),
        process=data.get("process"),
        pid=int(data["pid"]) if data.get("pid") else None,
        target_user=data.get("target_user"),
        command=data.get("command"),
    )

def _normalize_web(data, source):
    return Event(
        timestamp=_build_timestamp_web(data),
        source_ip=data.get("ip"),
        event_type=EventType.WEB_REQUEST,
        source=source,
        raw_message=f"{data.get('method')} {data.get('url')}",
        method=data.get("method"),
        url=data.get("url"),
        status_code=int(data["status_code"]) if data.get("status_code") else None,
        user_agent=data.get("user_agent"),
        referrer=data.get("referrer"),
    )

def normalize(data, source):
    if source == "auth_log":
        event = _normalize_auth(data)
    elif source in ("nginx", "apache"):
        event = _normalize_web(data, source)
    else:
        raise ValueError(f"unknown source: {source}")

    validate_event(event)
    return event