import logging

from ..core.event_type import EventType

logger = logging.getLogger(__name__)

EXPECTED_FIELDS = {
    EventType.SSH_FAILED_PASSWORD: {"username", "port"},
    EventType.SSH_ACCEPTED_PASSWORD: {"username", "port"},
    EventType.SSH_INVALID_USER: {"username", "port"},
    EventType.SSH_CONNECTION_CLOSED: {"port"},
    EventType.SSH_DISCONNECTION: {"username", "port"},

    EventType.SUDO_COMMAND: {"username", "command"},
    EventType.SUDO_AUTH_FAILURE: {"username"},
    EventType.SU_AUTH_FAILURE: {"username"},
    EventType.SU_SESSION_OPENED: {"username", "target_user"},

    EventType.WEB_REQUEST: {"method", "url", "status_code", "user_agent", "referrer"},
}

# Metadata any event may carry: never reported as unexpected.
COMMON_FIELDS = {"hostname", "process", "pid"}

ALL_OPTIONAL_FIELDS = {
    "username", "port",
    "target_user", "command",
    "method", "url", "status_code", "user_agent", "referrer",
}


def _type_name(event) -> str:
    # event_type can be None when the parser found no type
    return getattr(event.event_type, "value", repr(event.event_type))


def _safe(value) -> str:
    # The value comes from the log file (untrusted): escape newlines and
    # control characters so it cannot forge a second log line.
    return repr(str(value))[1:-1]


# validates events against expected and unexpected ones
def validate_event(event):
    expected = EXPECTED_FIELDS.get(event.event_type, set())
    unexpected = ALL_OPTIONAL_FIELDS - expected

    for field in unexpected:
        value = getattr(event, field)
        if value is not None:
            logger.warning(
                f"unexpected field '{field}={_safe(value)}' to event_type={_type_name(event)}"
            )
    for field in expected:
        value = getattr(event, field)
        if value is None:
            logger.warning(
                f"expected field '{field}' absent for event_type={_type_name(event)}"
            )