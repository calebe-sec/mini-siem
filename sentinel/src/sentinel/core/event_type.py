from enum import Enum

class EventType(Enum):
    SSH_FAILED_PASSWORD = "ssh_failed_password"
    SSH_ACCEPTED_PASSWORD = "ssh_accepted_password"
    SSH_INVALID_USER = "ssh_invalid_user"
    SSH_CONNECTION_CLOSED = "ssh_connection_closed"
    SSH_DISCONNECTION = "ssh_disconnection"

    SUDO_COMMAND = "sudo_command"
    SUDO_AUTH_FAILURE = "sudo_auth_failure"
    SU_SESSION_OPENED = "su_session_opened"
    SU_AUTH_FAILURE = "su_auth_failure"

    WEB_REQUEST = "web_request"