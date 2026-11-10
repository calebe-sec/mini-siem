import pytest

from sentinel.core.event_type import EventType # type: ignore
from sentinel.detection.engine import EngineRule # type: ignore
from sentinel.detection.rule_loader import RulerLoader # type: ignore


@pytest.fixture(scope="module")
def engine():
    return EngineRule(RulerLoader().open_conditions_yaml(RulerLoader.FILES))


def test_all_shipped_rules_load_and_have_valid_operators(engine):
    assert len(engine.rules) >= 20


def test_unknown_operator_fails_at_startup():
    bad = [{"id": "X-1", "when": {"field": "a", "operator": "sounds_like", "value": 1},
            "response": {"title": "t", "message": "m", "severity": "low"}}]
    with pytest.raises(ValueError, match="X-1"):
        EngineRule(bad)


def test_missing_field_never_matches_contains_or_greater_than(engine):
    assert engine.run({}) == []
    assert EngineRule.OPERATORS["contains"](None, "none") is False
    assert EngineRule.OPERATORS["greater_than"](None, 5) is False


def test_root_login_rule_matches_event_dict(make_event, engine):
    event = make_event(etype=EventType.SSH_ACCEPTED_PASSWORD, user="root")
    ids = [m["rule_id"] for m in engine.run(event.to_rule_dict())]
    assert ids == ["IAC-001"]


def test_normal_user_login_matches_nothing(make_event, engine):
    assert engine.run(make_event(etype=EventType.SSH_ACCEPTED_PASSWORD, user="alice").to_rule_dict()) == []


def test_shadow_command_matches_and_carries_mitre_metadata(make_event, engine):
    event = make_event(etype=EventType.SUDO_COMMAND, user="bob", command="/bin/cat /etc/SHADOW")
    (match,) = engine.run(event.to_rule_dict())
    assert match["rule_id"] == "SUDO-002"
    assert match["metadata"]["mitre"]["technique"] == "T1003.008"


def test_to_rule_dict_turns_enum_into_string(make_event):
    assert make_event().to_rule_dict()["event_type"] == "ssh_failed_password"
