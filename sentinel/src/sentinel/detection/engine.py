from pathlib import Path
from sentinel.detection.rule_loader import RulerLoader

class EngineRule:

    OPERATORS = {
        "equals": lambda actual, expected: actual == expected,
        "contains": lambda actual, expected: actual is not None and str(expected).lower() in str(actual).lower(),
        "greater_than": lambda actual, expected: actual is not None and actual > expected,
        "any_of": lambda actual, expected: actual in expected,
        }

    def __init__(self, rules):
        self.rules = rules
        for rule in rules:
            self._check_condition(rule["when"], rule.get("id", "?"))

    # Fail when the engine is built (startup), not in the middle of a log run.
    def _check_condition(self, condition: dict, rule_id: str) -> None:
        for key in ("all", "any"):
            if key in condition:
                for sub in condition[key]:
                    self._check_condition(sub, rule_id)
                return
        if condition.get("operator") not in self.OPERATORS:
            raise ValueError(f"rule {rule_id}: unknown operator {condition.get('operator')!r}")

    # This method will look for the condition specified in the .yaml file.
    def evaluate_condition(self,condition: dict, event: dict) -> bool:
        if "all" in condition:
            return all(self.evaluate_condition(c,event) for c in condition["all"])
        if "any" in condition:
            return any(self.evaluate_condition(c,event) for c in condition["any"])
        return self.evaluate_field(condition, event)
    
    #here are the fields found in the .yaml
    def evaluate_field(self, condition: dict, event: dict) -> bool:
        actual = event.get(condition["field"])
        expected = condition["value"]

        if condition.get("case_sensitive", True) is False:
            if isinstance(actual, str):
                actual = actual.lower()
            if isinstance(expected, str):
                expected = expected.lower()
            elif isinstance(expected, list):
                expected = [v.lower() if isinstance(v, str) else v for v in expected]

        return self.OPERATORS[condition["operator"]](actual, expected)

    #simple constructor for response
    def build_response(self, rule: dict, event: dict) -> dict:
        response = rule["response"]
        return {
            "rule_id": rule["id"],
            "title": response["title"],
            "message": response["message"],
            "severity": response["severity"],
            "metadata": rule.get("metadata", {}),
            "matched_event": event,
        }
    
    #run everything
    def run(self, event: dict) -> list[dict]:
        alerts = []
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            if self.evaluate_condition(rule["when"], event):
                alerts.append(self.build_response(rule, event))
        return alerts
    
if __name__ == "__main__":
    loader = RulerLoader()
    rules = loader.open_conditions_yaml(RulerLoader.FILES)
    
    engine = EngineRule(rules)

    event_test = {"process": "powershell.exe", 
                  "command_line": "powershell.exe -enc SGVsbG8="}
    alerts = engine.run(event_test)
    print(alerts)
