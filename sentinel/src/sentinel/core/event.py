from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .event_type import EventType

@dataclass
class Event:
    #always present
    timestamp: datetime
    source_ip: str
    event_type: EventType
    source: str
    raw_message: str

    #some have
    username: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None

    #ssh/sudo/su
    target_user: Optional[str] = None
    command: Optional[str] = None

    #web
    method: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    referrer: Optional[str] = None
