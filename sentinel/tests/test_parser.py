import pytest

from sentinel.core.ingest import DEFAULT_PATTERNS, load_events # type: ignore
from sentinel.parsers.auth_parser import AuthLogParser # type: ignore


@pytest.fixture
def parse(tmp_path):
    def _parse(text):
        path = tmp_path / "auth.log"
        path.write_text(text)
        return AuthLogParser(patterns_path=str(DEFAULT_PATTERNS)).parse(str(path))
    return _parse


def test_single_digit_day_is_parsed(parse):
    (ev,) = parse("Nov  1 09:05:03 web01 sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2\n")
    assert ev["day"] == "1"
    assert ev["user"] == "root" and ev["ip"] == "1.2.3.4"


def test_sudo_line_without_pid_is_parsed(parse):
    (ev,) = parse("Nov 10 09:05:03 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls\n")
    assert ev["event_type"] == "sudo_command"
    assert ev["user"] == "alice" and ev["command"] == "/bin/ls"
    assert ev["pid"] is None


def test_failed_password_for_invalid_user_keeps_the_real_name(parse):
    (ev,) = parse("Nov 10 09:05:03 web01 sshd[9]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2\n")
    assert ev["user"] == "admin"


def test_message_is_kept_for_raw_message(parse):
    (ev,) = parse("Nov 10 09:05:03 web01 sshd[9]: Accepted password for bob from 1.2.3.4 port 22 ssh2\n")
    assert ev["message"].startswith("Accepted password for bob")


def test_disconnection_maps_to_an_event_type(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("Nov 10 09:05:03 web01 sshd[9]: Disconnected from user bob 1.2.3.4 port 22\n")
    events, stats = load_events(path, year=2026)
    assert stats["invalid"] == 0 and events[0].event_type.value == "ssh_disconnection"


def test_unrecognized_and_garbage_lines_are_counted_not_fatal(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        "not a log line at all\n"
        "Nov 10 09:05:03 web01 CRON[5]: pam_unix(cron:session): session opened for user root\n"
        "Nov 10 09:05:04 web01 sshd[9]: Failed password for bob from 1.2.3.4 port 22 ssh2\n"
    )
    events, stats = load_events(path, year=2026)
    assert len(events) >= 1
    assert stats["events"] == len(events)
    assert events[-1].username == "bob" and events[-1].timestamp.year == 2026
