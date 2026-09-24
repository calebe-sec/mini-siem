from collections import defaultdict
from datetime import datetime, timedelta

import logging

class Aggregator:
    
    def __init__(self, window_minutes: int = 5):
        self.window = timedelta(minutes=window_minutes)
        self.failures = defaultdict(list)
        self.logger = logging.getLogger(__name__)
    
    def add_failure(self, user: str, source_ip: str) -> int:
        key = (user, source_ip)
        now = datetime.now()

        self.failures[key].append(now)

        self.failures[key] = [
            t for t in self.failures[key]
            if (now - t) <= self.window
        ]

        count = len(self.failures[key])
        if count > 5:
            self.logger.warning(f"[!] {count} login failures for user={user} ip={source_ip} in the last {self.window}")
        return count
            
        

        

        