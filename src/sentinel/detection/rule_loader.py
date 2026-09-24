import yaml
import logging

from pathlib import Path

class RulerLoader:

    BASE_DIR = Path(__file__).parent

    FILES = list(BASE_DIR.glob("rules/*.yaml"))

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    #metodo silencioso só para validar os caminhos
    def _valid_path(self, source: list) -> bool:
        if not source:
            self.logger.error(f"[!] None path yaml finded")
            return False
        return True
    
    #vai abrir os .yaml e retornar num dict com tudo
    def open_conditions_yaml(self, source: list) -> dict:
        all_rules = []
        if self._valid_path(source) is True:
            for file in source:
                with open(file, "r") as f:
                    data = yaml.safe_load(f)
                    all_rules.extend(data["rules"])
            return all_rules
        else:
            self._valid_path(source)
            return []

if __name__ == "__main__":
    loader = RulerLoader()
    rules = loader.open_conditions_yaml(RulerLoader.FILES)
    
    # Rodei isso para poder saber pq não retornava as listas
    # print(RulerLoader.FILES)