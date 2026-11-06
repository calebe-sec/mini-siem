from collections import defaultdict, deque

from sentinel.core.alert import AlertCandidate
from sentinel.core.event import Event
from sentinel.ml.features import classify
from sentinel.detection.sliding_window import Aggregator

#this class does connection with aggregator and AlertCandidate
class EventProcessor:
    def __init__(self, aggregator: Aggregator, max_events_per_ip=50) -> None:
        if max_events_per_ip < 1:
            raise ValueError("max_events_per_ip must be at least 1")
        self.aggregator = aggregator
        self.max_events_per_ip = max_events_per_ip
        self.buffers = defaultdict(lambda: deque(maxlen=max_events_per_ip))

    def process(self, event: Event) -> list[AlertCandidate]:
        if not event.source_ip:
            return []
        
        buffer = self.buffers[event.source_ip]
        buffer.append(event)

        if classify(event) != "failure" or not event.username:
            return []
        
        fired = self.aggregator.add_failure(event.username, event.source_ip, event.timestamp)
        if not fired:
            return []
        
        evidence = list(buffer)
        count = sum(1 for e in evidence if classify(e) == "failure")
        return [AlertCandidate.from_aggregator(
            user=event.username,
            source_ip=event.source_ip,
            count=count,
            window_start=evidence[0].timestamp,
            window_end=evidence[-1].timestamp,
            evidence=evidence,
        )]
