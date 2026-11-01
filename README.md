# Ward Zero

**A seeded simulation of a ransomware outbreak in a hospital network, and which defences actually keep the emergency department open.**

Ward Zero models a fictional 60-host hospital: admin, ward and ED workstations, imaging modalities, infusion pumps, the EHR, a domain controller and backups. An attacker gets in by phishing or by brute-forcing an internet-facing RDP server, then steals credentials, moves sideways, destroys backups and detonates. Every step is tagged with a MITRE ATT&CK technique. Recovery is limited by a small IT team, and the cost is measured in **hours of ambulance diversion**, not in hosts.

The replay page lets you scrub through one incident under different defences. It shows the network map, which clinical services are down, the incident log, and a ranking of each defence over 300 runs.

## Run it

```bash
python -m wardzero run --seed 4                    # tell one incident's story
python -m wardzero run --seed 4 --defence offline_backups
python -m wardzero compare --runs 300              # rank every single defence
python -m wardzero export --out web/data           # data for the replay page
python -m http.server -d web 8000                  # open http://localhost:8000
```

Python 3.11+ and no dependencies. Tests use `pytest`.

## What the model says (300 seeded runs)

Each defence is switched on alone, against the same seeds.

| Setup | Encrypted at all | Hosts encrypted | Backups lost | ED diversion (mean) | (worst 10%) | Records down |
|---|---|---|---|---|---|---|
| No defences | 88% | 38.8 | 88% | 285 h | 381 h | 75 h |
| admin tiering | 76% | 8.7 | 0% | 15 h | 24 h | 0 h |
| offline backups | 88% | 38.8 | 0% | 43 h | 53 h | 19 h |
| soc 24x7 | 92% | 34.8 | 91% | 236 h | 383 h | 72 h |
| edr everywhere | 89% | 35.6 | 88% | 260 h | 377 h | 75 h |
| phishing training | 84% | 37.8 | 84% | 276 h | 382 h | 73 h |
| segmentation | 94% | 39.6 | 85% | 282 h | 382 h | 73 h |
| patching | 89% | 39.0 | 87% | 286 h | 379 h | 75 h |
| mfa | 88% | 39.5 | 87% | 292 h | 385 h | 75 h |
| canaries | 96% | 41.2 | 95% | 293 h | 393 h | 83 h |
| All defences | 0% | 0.0 | 0% | 0 h | 0 h | 0 h |

Two things stand out. First, **the defences that protect the domain admin account and the backups do most of the work**: without domain admin, the attacker can't reach the servers or the backups. Second, **no single defence stops the attack from getting in**; they only change how bad it gets.

## Caveats

- **Every number is an assumption.** Click rates, exploit odds, EDR detection rates, dwell time and restore times live in [`wardzero/assumptions.py`](wardzero/assumptions.py). They are plausible, not measured. Change them and the ranking can change.
- **Detection can look worse than nothing.** Canaries and SOC alerts sometimes make the attacker detonate early ("panic detonation"). That effect comes from the `panic_detonation` assumption, and the model has no partial-encryption benefit from early response. Read those rows as "detection without fast containment doesn't help much", not as "detection is harmful".
- **Segmentation is coarse.** It only blocks workstation-to-workstation paths; the attacker can still follow domain admin to the servers. Real micro-segmentation would score better.
- One hospital, one attacker playbook, single defences in isolation. Defences interact; the "all defences" row hides which ones matter together.
- No real exploit code. The hospital is fictional.

## Layout

```
wardzero/assumptions.py   every tunable probability and timing
wardzero/hospital.py      hosts, zones, firewall rules, clinical services
wardzero/defences.py      the nine defences and how they change the hospital
wardzero/sim.py           event-driven attack, detection, response and recovery
wardzero/compare.py       Monte Carlo ranking
web/                      the replay page (vanilla JS + SVG)
tests/                    determinism and invariants
```

## Licence

MIT
