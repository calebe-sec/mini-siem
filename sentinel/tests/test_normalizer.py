from datetime import datetime
import pytest
import logging
from sentinel.normalizer.normalizer import normalize
from sentinel.core.event_type import EventType
from sentinel.core.event import Event

def test_normalize_auth_log_ssh_success():
    data = {
        "event_type": "ssh_accepted_password",
        "month": "Aug",
        "day": "6",
        "hour": "11:30:15",
        "ip": "192.168.1.50",
        "message": "Accepted password for root from 192.168.1.50 port 54321 ssh2",
        "user": "root",
        "port": "54321",
        "hostname": "test-host",
        "process": "sshd",
        "pid": "1234"
    }
    
    event = normalize(data, "auth_log")
    
    assert event.timestamp == datetime(2026, 8, 6, 11, 30, 15)
    assert event.source_ip == "192.168.1.50"
    assert event.event_type == EventType.SSH_ACCEPTED_PASSWORD
    assert event.source == "auth_log"
    assert event.raw_message == "Accepted password for root from 192.168.1.50 port 54321 ssh2"
    assert event.user == "root"
    assert event.port == 54321
    assert event.hostname == "test-host"
    assert event.process == "sshd"
    assert event.pid == 1234

def test_normalize_auth_log_sudo():
    data = {
        "event_type": "sudo_command",
        "month": "Dec",
        "day": "25",
        "hour": "23:59:59",
        "ip": "127.0.0.1",
        "message": "root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt update",
        "user": "root",
        "hostname": "localhost",
        "process": "sudo",
        "pid": "9999",
        "target_user": "root",
        "command": "/usr/bin/apt update"
    }
    
    event = normalize(data, "auth_log")
    
    assert event.timestamp == datetime(2026, 12, 25, 23, 59, 59)
    assert event.source_ip == "127.0.0.1"
    assert event.event_type == EventType.SUDO_COMMAND
    assert event.source == "auth_log"
    assert event.user == "root"
    assert event.port is None
    assert event.hostname == "localhost"
    assert event.process == "sudo"
    assert event.pid == 9999
    assert event.target_user == "root"
    assert event.command == "/usr/bin/apt update"

def test_normalize_web_nginx():
    data = {
        "year": "2026",
        "month": "Jan",
        "day": "12",
        "hour": "14",
        "min": "05",
        "sec": "30",
        "ip": "10.0.0.5",
        "method": "GET",
        "url": "/admin",
        "status_code": "200",
        "user_agent": "Mozilla/5.0",
        "referrer": "https://google.com"
    }
    
    event = normalize(data, "nginx")
    
    assert event.timestamp == datetime(2026, 1, 12, 14, 5, 30)
    assert event.source_ip == "10.0.0.5"
    assert event.event_type == EventType.WEB_REQUEST
    assert event.source == "nginx"
    assert event.raw_message == "GET /admin"
    assert event.method == "GET"
    assert event.url == "/admin"
    assert event.status_code == 200
    assert event.user_agent == "Mozilla/5.0"
    assert event.referrer == "https://google.com"

def test_normalize_web_apache():
    data = {
        "year": "2026",
        "month": "Feb",
        "day": "28",
        "hour": "08",
        "min": "15",
        "sec": "45",
        "ip": "172.16.0.4",
        "method": "POST",
        "url": "/login",
        "status_code": "401",
        "user_agent": "curl/7.68.0",
        "referrer": "-"
    }
    
    event = normalize(data, "apache")
    
    assert event.timestamp == datetime(2026, 2, 28, 8, 15, 45)
    assert event.source_ip == "172.16.0.4"
    assert event.event_type == EventType.WEB_REQUEST
    assert event.source == "apache"
    assert event.raw_message == "POST /login"
    assert event.method == "POST"
    assert event.url == "/login"
    assert event.status_code == 401
    assert event.user_agent == "curl/7.68.0"
    assert event.referrer == "-"

def test_normalize_unknown_source():
    data = {
        "month": "Aug",
        "day": "6",
        "hour": "11:30:15",
        "ip": "1.1.1.1"
    }
    with pytest.raises(ValueError) as exc_info:
        normalize(data, "unknown_syslog")
    assert "unknown source: unknown_syslog" in str(exc_info.value)

def test_validate_event_schema_logging(caplog):
    data = {
        "event_type": "ssh_failed_password",
        "month": "Aug",
        "day": "6",
        "hour": "11:30:15",
        "ip": "192.168.1.50",
        "user": "root",
        "command": "whoami"
    }
    
    with caplog.at_level(logging.WARNING):
        event = normalize(data, "auth_log")
    
    assert event is not None
    
    warnings = [record.message for record in caplog.records]
    assert any("expected field 'port' absent" in w for w in warnings)
    assert any("unexpected field 'command=whoami'" in w for w in warnings)
