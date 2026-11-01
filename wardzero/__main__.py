"""Command line.

    python -m wardzero run --seed 4                  # tell one incident's story
    python -m wardzero run --seed 4 --defence offline_backups --defence admin_tiering
    python -m wardzero compare --runs 300            # rank every defence
    python -m wardzero export --out web/data         # data for the replay page
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .assumptions import DAY, HOUR
from .compare import markdown, single_defence_ranking
from .defences import Defences
from .hospital import build
from .sim import TECHNIQUES, Result, simulate


def clock(minutes: int) -> str:
    d, rem = divmod(minutes, DAY)
    h, m = divmod(rem, HOUR)
    return f"day {d + 1} {h:02d}:{m:02d}"


def story(r: Result) -> str:
    lines = [f"Seed {r.seed} · defences: {', '.join(r.defences) or 'none'}"]
    keep = {"compromised", "domain_admin", "alert", "isolated", "contained", "panic", "backups", "detonate", "blocked", "credentials"}
    for e in r.events:
        if e.kind in keep:
            tag = f" [{e.technique}]" if e.technique else ""
            lines.append(f"  {clock(e.t)}  {e.host or '-':10s} {e.detail}{tag}")
    lines.append("")
    lines.append(f"  Hosts encrypted: {r.hosts_encrypted}   Backups destroyed: {'yes' if r.backups_destroyed else 'no'}")
    lines.append(f"  Ambulances diverted for {r.diversion_minutes / HOUR:.0f} hours")
    for name, mins in r.service_downtime.items():
        if mins:
            lines.append(f"    {name}: down {mins / HOUR:.0f} h")
    return "\n".join(lines)


def to_json(r: Result) -> dict:
    h = build()
    return {
        "seed": r.seed,
        "defences": r.defences,
        "hosts": [{"id": x.id, "kind": x.kind, "zone": x.zone, "edr": x.edr, "patched": x.patched} for x in h.hosts.values()],
        "services": [{"name": s.name, "needs": s.needs, "any_of": s.any_of, "critical": s.critical} for s in h.services],
        "events": [asdict(e) for e in r.events],
        "encrypted": r.encrypted,
        "isolated": r.isolated,
        "isolated_until": r.isolated_until,
        "restored": r.restored,
        "metrics": {
            "vector": r.vector,
            "time_to_domain_admin": r.time_to_domain_admin,
            "first_alert": r.first_alert,
            "detonated_at": r.detonated_at,
            "contained_at": r.contained_at,
            "backups_destroyed": r.backups_destroyed,
            "hosts_encrypted": r.hosts_encrypted,
            "diversion_hours": round(r.diversion_minutes / HOUR, 1),
            "service_downtime_hours": {k: round(v / HOUR, 1) for k, v in r.service_downtime.items()},
        },
        "techniques": TECHNIQUES,
    }


def main() -> None:
    p = argparse.ArgumentParser(prog="wardzero", description="Ransomware outbreak simulator for a hospital network")
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="simulate one incident and tell its story")
    run.add_argument("--seed", type=int, default=1)
    run.add_argument("--defence", action="append", default=[], choices=Defences.names())
    run.add_argument("--all", action="store_true", help="turn on every defence")
    run.add_argument("--json", type=Path, help="also write the incident as JSON")

    cmp_ = sub.add_parser("compare", help="rank each defence over many runs")
    cmp_.add_argument("--runs", type=int, default=300)

    exp = sub.add_parser("export", help="write data for the replay page")
    exp.add_argument("--out", type=Path, default=Path("web/data"))
    exp.add_argument("--runs", type=int, default=300)
    exp.add_argument("--seed", type=int, default=4)

    args = p.parse_args()
    if args.cmd == "run":
        d = Defences.all() if args.all else Defences(**{n: True for n in args.defence})
        r = simulate(args.seed, d)
        print(story(r))
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(json.dumps(to_json(r)))
    elif args.cmd == "compare":
        print(markdown(single_defence_ranking(args.runs)))
    elif args.cmd == "export":
        args.out.mkdir(parents=True, exist_ok=True)
        scenarios = {
            "none": Defences(),
            "offline_backups": Defences(offline_backups=True),
            "admin_tiering": Defences(admin_tiering=True),
            "all": Defences.all(),
        }
        for name, d in scenarios.items():
            (args.out / f"run-{name}.json").write_text(json.dumps(to_json(simulate(args.seed, d))))
        ranking = [asdict(s) for s in single_defence_ranking(args.runs)]
        (args.out / "ranking.json").write_text(json.dumps({"runs": args.runs, "rows": ranking}, indent=1))
        print(f"wrote {len(scenarios)} incidents and a {args.runs}-run ranking to {args.out}")


if __name__ == "__main__":
    main()
