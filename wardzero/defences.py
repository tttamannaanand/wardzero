"""Defences that can be switched on, alone or together.

Each one changes the hospital or the assumptions in a specific, documented
way, so a comparison shows exactly what each control buys.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, fields, replace

from .assumptions import HOUR, Assumptions
from .hospital import RDP, SMB, ZONES, Hospital


@dataclass(frozen=True)
class Defences:
    segmentation: bool = False
    """Workstations can only reach servers over SMB; zones can't reach each other;
    imaging and backups are reachable only from the server zone."""
    patching: bool = False
    """Every patchable host is up to date (vendor-locked scanner consoles stay as they are)."""
    mfa: bool = False
    """Two-factor login on internet-facing remote access."""
    edr_everywhere: bool = False
    """Detection agents on every workstation, not just servers."""
    soc_24x7: bool = False
    """A round-the-clock security team: alerts are handled in minutes, not hours."""
    canaries: bool = False
    """Decoy file shares that sound an alarm when touched."""
    admin_tiering: bool = False
    """Domain admins never log in to workstations, and every workstation gets
    its own local admin password (no shared password to reuse)."""
    phishing_training: bool = False
    """Staff are trained to spot phishing."""
    offline_backups: bool = False
    """Immutable, offline backups the attacker can't reach or delete."""

    @classmethod
    def names(cls) -> list[str]:
        return [f.name for f in fields(cls)]

    @classmethod
    def only(cls, name: str) -> Defences:
        return cls(**{name: True})

    @classmethod
    def all(cls) -> Defences:
        return cls(**{n: True for n in cls.names()})

    def active(self) -> list[str]:
        return [n for n in self.names() if getattr(self, n)]


def apply(d: Defences, hospital: Hospital, a: Assumptions) -> tuple[Hospital, Assumptions]:
    """Return a copy of the hospital and assumptions with the defences in place."""
    h = copy.deepcopy(hospital)

    if d.segmentation:
        allow: set[tuple[str, str, int]] = set()
        for z in ["admin", "clinical", "ed"]:
            allow.add((z, "servers", SMB))  # apps and file shares only
        for z in ZONES:
            if z != "servers":
                allow |= {("servers", z, SMB), ("servers", z, RDP)}  # management from servers
        allow.add(("dmz", "servers", SMB))
        h.allow = allow
    if d.patching:
        for host in h.hosts.values():
            if host.kind != "modality":
                host.patched = True
    if d.edr_everywhere:
        for host in h.hosts.values():
            if host.kind in ("workstation", "admin-workstation"):
                host.edr = True

    if d.soc_24x7:
        # A round-the-clock team answers fast and resets passwords on the first alert.
        a = replace(a, soc_response=(10, 1 * HOUR), containment_time=(30, 2 * HOUR), full_containment_after_alerts=1)
    if d.phishing_training:
        a = replace(a, click_rate=a.click_rate_trained)
    return h, a
