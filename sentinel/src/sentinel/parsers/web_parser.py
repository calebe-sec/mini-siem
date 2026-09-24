import re
import yaml

from base_parser import BaseParser

class NginxParseLog(BaseParser):
    HEADER = re.compile(r"(?P<ip>[\d.]+).+\[(?P<day>\d{2})/(?P<month>\w{3})/(?P<year>\d{4}):(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})\s+(?P<tz>[+-]\d{4})\]\s+\"(?P<method>\w+)\s+(?P<url>\S+)\s+HTTP/(?P<version>\d\.\d)\"\s+(?P<stcd>\d{3})\s+(?P<bytes>\d+)\s+\"(?P<referrer>[^\"]*)\"\s+\"(?P<user_agent>[^\"]*)")

    #def __init__(self, patterns_path="config/log_patterns.yaml"):

    def parse(self, filepath):
        
        events = []
        
        with open(filepath) as f:
            for line in f:

                match = self.HEADER.search(line)

                if not match:
                    continue

                dados = match.groupdict()
                dados["status_code"] = dados.pop("stcd")
                dados["timezone"] = dados.pop("tz")
                
                events.append(dados)

        return events

if __name__ == "__main__":
    parser = NginxParseLog()
    events = parser.parse("datasets/synthetic/nginx_test.log")

    for evento in events:
        print(evento)

    print(f"\nTotal de eventos: {len(events)}")




                