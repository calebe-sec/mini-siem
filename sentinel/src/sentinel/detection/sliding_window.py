import logging
from collections import defaultdict
from datetime import datetime, timedelta

Key = tuple[str, str]  # (user, source_ip)


class Aggregator:
    def __init__(self, window_minutes: int = 5, threshold: int = 5):
        self.window = timedelta(minutes=window_minutes)
        self.threshold = threshold
        self.failures: dict[Key, list[datetime]] = defaultdict(list)
        self._alerted: set[Key] = set()
        self._last_sweep: datetime | None = None
        self.logger = logging.getLogger(__name__)

    def add_failure(self, user: str, source_ip: str, timestamp: datetime) -> bool:
        """Register a failure. Returns True only when the threshold is first crossed."""
        key = (user, source_ip)
        self.failures[key].append(timestamp)

        self._prune_key(key, timestamp)
        self._sweep(timestamp)

        count = len(self.failures[key])
        if count >= self.threshold and key not in self._alerted:
            self._alerted.add(key)
            self.logger.warning(
                "%d login failures for user=%s ip=%s within %s",
                count, user, source_ip, self.window,
            )
            return True
        return False

    def _prune_key(self, key: Key, now: datetime) -> None:
        """Drop expired timestamps for one key; forget the key if nothing is left."""
        recent = [ts for ts in self.failures[key] if (now - ts) <= self.window]
        if not recent:
            del self.failures[key]
            self._alerted.discard(key)
            return

        self.failures[key] = recent
        if len(recent) < self.threshold:
            self._alerted.discard(key)  # attack cooled down, allow a future alert

    def _sweep(self, now: datetime) -> None:
        """Prune every key, at most once per window, so idle keys don't leak memory."""
        if self._last_sweep is not None and (now - self._last_sweep) < self.window:
            return
        self._last_sweep = now
        for key in list(self.failures):  # copy: we delete while iterating
            self._prune_key(key, now)