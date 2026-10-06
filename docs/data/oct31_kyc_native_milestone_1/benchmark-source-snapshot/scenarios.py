"""The frozen 276-trial schedule; no implicit retries or admission decisions."""

from dataclasses import dataclass

SCENARIOS = ("ISSUE", "PRESENT-A", "PRESENT-B", "REVOKE-UPDATE")


@dataclass(frozen=True)
class Trial:
    scenario: str
    session: int
    phase: str
    index: int

    @property
    def name(self):
        return f"{self.scenario}-s{self.session}-{self.phase}-{self.index:02d}"


def session_trials(scenario, session):
    if scenario not in SCENARIOS or type(session) is not int or session not in range(1, 4):
        raise ValueError("trial outside frozen scenario/session schedule")
    return (
        [Trial(scenario, session, "cold", 0)]
        + [Trial(scenario, session, "warmup", index) for index in range(2)]
        + [Trial(scenario, session, "warm", index) for index in range(20)]
    )


def schedule():
    return [
        trial
        for scenario in SCENARIOS
        for session in range(1, 4)
        for trial in session_trials(scenario, session)
    ]
