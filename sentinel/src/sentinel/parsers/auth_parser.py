import re
import yaml

from .base_parser import BaseParser, load_patterns


class AuthLogParser(BaseParser):
    HEADER = re.compile(r"(?P<month>[a-zA-Z]{3})\s+(?P<day>\d{2})\s+(?P<hour>\d{2}:\d{2}:\d{2})\s+(?P<hostname>[\w-]+)\s+(?P<process>[\w-]+)\[(?P<pid>\d+)\]:\s+(?P<message>.*)", re.VERBOSE,)

    def __init__(self, patterns_path="config/log_patterns.yaml"):
        self.ssh_patterns = load_patterns(patterns_path, "ssh")
        self.sudo_patterns = load_patterns(patterns_path, "sudo")


    def parse(self, filepath):

        events = []
     
        with open(filepath) as f:
            for line in f:

                match = self.HEADER.search(line)
                
                if not match:
                    continue

                msg = match.group("message")

                event_type = None
                detail_match = None

                for keyword, (etype, regex) in {**self.ssh_patterns, **self.sudo_patterns}.items():
                    if keyword in msg:
                        event_type = etype
                        detail_match = regex.search(msg)
                        break
                    
                details = detail_match.groupdict() if detail_match else {}

                events.append({
                    "month"      : match.group("month"),
                    "day"        : match.group("day"),
                    "hour"       : match.group("hour"),
                    "hostname"   : match.group("hostname"),
                    "process"    : match.group("process"),
                    "pid"        : match.group("pid"),
                    "event_type" : event_type,
                    **details,
                    
                })

        return events
if __name__ == "__main__":

    parser = AuthLogParser(patterns_path="config/log_patterns.yaml")
    events = parser.parse("datasets/synthetic/auth_test.log")

    for event in events:
        print(event)

    print(f"\n Total de eventos: {len(events)}")