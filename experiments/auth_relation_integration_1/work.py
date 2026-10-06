"""Per-invocation exact work counters; global admission remains in the guard."""

from dataclasses import dataclass


class WorkLimit(RuntimeError):
    pass


@dataclass
class EventMeter:
    limit: int
    events: int = 0

    def __call__(self, count=1):
        if type(count) is not int or count < 0:
            raise ValueError("nonnegative exact work count")
        if self.events + count > self.limit:
            raise WorkLimit("admitted invocation work-event ceiling")
        self.events += count
