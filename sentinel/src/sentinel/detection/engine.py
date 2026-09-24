from pathlib import Path
from rule_loader import RulerLoader

class EngineRule:

    OPERATORS = {
        "equals": lambda actual, expected: actual == expected,
        "contains": lambda actual, expected: expected.lower() in str(actual).lower(),
        "greater_than": lambda actual, expected: actual > expected,
        "any_of": lambda actual, expected: actual in expected,
        }

    def __init__(self, rules):
        self.rules = rules

    #esse metodo aqui vai proocurar a condição que tem no .yaml
    def evaluate_condition(self,condition: dict, event: dict) -> bool:
        if "all" in condition:
            return all(self.evaluate_condition(c,event) for c in condition["all"])
        if "any" in condition:
            return any(self.evaluate_condition(c,event) for c in condition["any"])
        return self.evaluate_field(condition, event)
    
    #aqui vai por campos que tem no .yaml
    def evaluate_field(self, condition: dict, event: dict) -> bool:
        field_name = condition["field"]
        operator_name = condition["operator"]
        expected_value = condition["value"]

        actual_value = event.get(field_name)

        operator_func = self.OPERATORS[operator_name]
        return operator_func(actual_value, expected_value)
    
    #construtor simples de resposta
    def build_response(self, rule: dict, event: dict) -> dict:
        
        response = rule["response"]
        return {
            "rule_id": rule["id"],
            "title": response["title"],
            "message": response["message"],
            "severity": response["severity"],
            "matched_event": event,
        }
    
    #rodar tudo
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
