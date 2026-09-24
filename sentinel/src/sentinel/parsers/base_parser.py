import yaml
import re

from abc import ABC, abstractmethod

def load_patterns(path,category):
    with open(path) as f:
        raw = yaml.safe_load(f)

    compiled = {}
    for event_type, data in raw[category].items():
        compiled[data["keyword"]] = (event_type, re.compile(data["regex"]))
    return compiled


class BaseParser(ABC):
    @abstractmethod
    
    def parse(self, log_line: str) -> dict:
        pass
