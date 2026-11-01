"""Many runs per setup, so conclusions rest on distributions, not one story."""

from __future__ import annotations

import statistics
from dataclasses import dataclass

from .assumptions import DAY, HOUR
from .defences import Defences
from .sim import Result, simulate


@dataclass
class Summary:
    label: str
    runs: int
    detonated: float
    """Share of runs where encryption happened at all."""
    hosts_encrypted_mean: float
    backups_destroyed: float
    diversion_hours_mean: float
    diversion_hours_p90: float
    ehr_down_hours_mean: float
    domain_admin: float
    """Share of runs where the attacker reached domain admin."""

    def row(self) -> list[str]:
        return [
            self.label,
            f"{self.detonated:.0%}",
            f"{self.hosts_encrypted_mean:.1f}",
            f"{self.backups_destroyed:.0%}",
            f"{self.diversion_hours_mean:.0f} h",
            f"{self.diversion_hours_p90:.0f} h",
            f"{self.ehr_down_hours_mean:.0f} h",
        ]


HEADER = ["Setup", "Encrypted at all", "Hosts encrypted", "Backups lost", "ED diversion (mean)", "(worst 10%)", "Records down"]


def percentile(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    if not xs:
        return 0.0
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def summarise(label: str, results: list[Result]) -> Summary:
    n = len(results)
    diversion = [r.diversion_minutes / HOUR for r in results]
    return Summary(
        label=label,
        runs=n,
        detonated=sum(r.detonated_at is not None for r in results) / n,
        hosts_encrypted_mean=statistics.fmean(r.hosts_encrypted for r in results),
        backups_destroyed=sum(r.backups_destroyed for r in results) / n,
        diversion_hours_mean=statistics.fmean(diversion),
        diversion_hours_p90=percentile(diversion, 0.9),
        ehr_down_hours_mean=statistics.fmean(r.service_downtime["Patient records (EHR)"] / HOUR for r in results),
        domain_admin=sum(r.time_to_domain_admin is not None for r in results) / n,
    )


def run_many(defences: Defences, runs: int, first_seed: int = 1) -> list[Result]:
    return [simulate(seed, defences) for seed in range(first_seed, first_seed + runs)]


def single_defence_ranking(runs: int) -> list[Summary]:
    """Baseline, then each defence alone (best first), then everything together.

    Every setup uses the same seeds, so each comparison faces the same attacks.
    """
    baseline = summarise("No defences", run_many(Defences(), runs))
    singles = [summarise(name.replace("_", " "), run_many(Defences.only(name), runs)) for name in Defences.names()]
    singles.sort(key=lambda s: s.diversion_hours_mean)
    everything = summarise("All defences", run_many(Defences.all(), runs))
    return [baseline, *singles, everything]


def markdown(rows: list[Summary]) -> str:
    lines = ["| " + " | ".join(HEADER) + " |", "|" + "---|" * len(HEADER)]
    lines += ["| " + " | ".join(r.row()) + " |" for r in rows]
    return "\n".join(lines)


def horizon_days() -> float:
    from .assumptions import Assumptions

    return Assumptions().horizon / DAY
