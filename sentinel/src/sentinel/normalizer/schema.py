import logging

from ..core.event_type import EventType

logger = logging.getLogger(__name__)

EXPECTED_FIELDS = {
    EventType.SSH_FAILED_PASSWORD: {"user", "port"},
    EventType.SSH_ACCEPTED_PASSWORD: {"user", "port"},
    EventType.SSH_INVALID_USER: {"user", "port"},
    EventType.SSH_CONNECTION_CLOSED: {"port"},
    EventType.SSH_DISCONNECTION: {"user", "port"},

    EventType.SUDO_COMMAND: {"user", "command"},
    EventType.SUDO_AUTH_FAILURE: {"user"},
    EventType.SU_AUTH_FAILURE: {"user"},
    EventType.SU_SESSION_OPENED: {"user", "target_user"},

    EventType.WEB_REQUEST: {"method", "url", "status_code", "user_agent", "referrer"} 

}

ALL_OPTIONAL_FIELDS = {
    "user", "port", "hostname", "process", "pid",
    "target_user", "command",
    "method", "url", "status_code", "user_agent", "referrer",
}

def validate_event(event):
    expected = EXPECTED_FIELDS.get(event.event_type, set())
    unexpected = ALL_OPTIONAL_FIELDS - expected

    for field in unexpected:
        valor = getattr(event, field)
        if valor is not None:
            logger.warning(
                f"unexpected field '{field}={valor}' to event_type={event.event_type.value}"
            )
    for field in expected:
        valor = getattr(event, field)
        if valor is None:
            logger.warning(
                f"expected field '{field}' absent for event_type={event.event_type.value}"
            )