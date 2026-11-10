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

    def to_rule_dict(self) -> dict:
        """Flat dict for the rule engine. Enums become plain strings so YAML rules can match them."""
        return {
            "event_type": self.event_type.value if self.event_type else None,
            "source": self.source,
            "source_ip": self.source_ip,
            "username": self.username,
            "port": self.port,
            "hostname": self.hostname,
            "process": self.process,
            "pid": self.pid,
            "target_user": self.target_user,
            "command": self.command,
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "user_agent": self.user_agent,
            "referrer": self.referrer,
        }
