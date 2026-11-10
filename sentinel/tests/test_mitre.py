from datetime import timedelta

from sentinel.core.alert import AlertCandidate # type: ignore
from sentinel.mitre.mapping import enrich, primary_tactic # type: ignore 
from sentinel.mitre.techniques import TECHNIQUES, is_known, lookup # type: ignore
from sentinel.detection.rule_loader import RulerLoader # type: ignore
from conftest import T0


def candidate(mitre, **details):
    return AlertCandidate("rule", "t", "low", "1.1.1.1", T0, T0 + timedelta(seconds=1), details=dict(details), mitre=mitre)


def test_every_technique_used_by_the_shipped_rules_is_in_the_catalog():
    used = set()
    for rule in RulerLoader().open_conditions_yaml(RulerLoader.FILES):
        mitre = rule["metadata"]["mitre"]
        used.update([mitre["technique"]] if "technique" in mitre else mitre["techniques"])
    assert used <= set(TECHNIQUES), used - set(TECHNIQUES)


def test_lookup_is_case_insensitive_and_unknown_is_none():
    assert lookup("t1110")["name"] == "Brute Force"
    assert lookup("T9999") is None and lookup(None) is None and not is_known("nope")


def test_enrich_adds_name_and_tactics():
    c = enrich(candidate("T1110"))
    assert c.details["mitre_name"] == "Brute Force"
    assert primary_tactic(c) == ("TA0006", "Credential Access")


def test_unmapped_candidate_gets_unmapped_tactic():
    assert primary_tactic(enrich(candidate(None))) == ("UNMAPPED", "Unmapped")
