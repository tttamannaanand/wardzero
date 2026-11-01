"""The hospital network: hosts, zones, firewall rules and clinical services.

A fictional mid-sized hospital, laid out the way many real ones are, with a
deliberately common weakness: a mostly flat network where most zones can
reach each other on file sharing (SMB) and remote desktop (RDP).
"""

from __future__ import annotations

from dataclasses import dataclass, field

SMB, RDP = 445, 3389

ZONES = ["dmz", "admin", "clinical", "ed", "imaging", "iot", "servers", "backup"]


@dataclass
class Host:
    id: str
    kind: str
    zone: str
    patched: bool = True
    edr: bool = True
    """Runs an endpoint detection agent. Medical devices usually can't."""
    rdp_internet: bool = False
    """Remote desktop exposed to the internet."""
    user: bool = False
    """A staff workstation that receives email."""
    encryptable: bool = True
    """Ordinary Windows hosts can be encrypted; embedded devices usually can't."""


@dataclass
class Service:
    name: str
    needs: list[str]
    """Host ids that must all be up for the service to work."""
    any_of: list[str] = field(default_factory=list)
    """At least one of these must also be up (e.g. one scanner)."""
    critical: bool = False
    """If down, the emergency department diverts ambulances."""


@dataclass
class Hospital:
    hosts: dict[str, Host]
    allow: set[tuple[str, str, int]]
    """Firewall: (from zone, to zone, port) pairs that are allowed."""
    services: list[Service]

    def reachable(self, src: Host, dst: Host, port: int) -> bool:
        return src.zone == dst.zone or (src.zone, dst.zone, port) in self.allow

    def by_kind(self, kind: str) -> list[Host]:
        return [h for h in self.hosts.values() if h.kind == kind]


def build() -> Hospital:
    """The default hospital: about 60 hosts across eight zones."""
    hosts: list[Host] = []

    def add(n: int, prefix: str, kind: str, zone: str, **kw) -> None:
        for i in range(1, n + 1):
            hosts.append(Host(id=f"{prefix}{i:02d}" if n > 1 else prefix, kind=kind, zone=zone, **kw))

    # Staff workstations: everyone gets email. A few lag behind on patches.
    # Baseline: detection agents only on servers, a common real-world gap.
    add(10, "adm-ws", "workstation", "admin", user=True, edr=False)
    add(16, "ward-ws", "workstation", "clinical", user=True, edr=False)
    add(6, "ed-ws", "workstation", "ed", user=True, edr=False)
    hosts.append(Host("it-admin", "admin-workstation", "admin", user=True, edr=False))

    # Imaging: the archive and the scanner consoles (old, vendor-locked Windows).
    hosts.append(Host("pacs", "pacs", "imaging"))
    for s in ["mri-console", "ct-console", "xray-console"]:
        hosts.append(Host(s, "modality", "imaging", patched=False, edr=False))

    # Medical IoT: pumps and monitors, managed by one server.
    add(8, "pump", "infusion-pump", "iot", edr=False, encryptable=False)
    add(4, "monitor", "patient-monitor", "iot", edr=False, encryptable=False)
    hosts.append(Host("pump-mgr", "server", "servers"))

    # Core servers.
    for s in ["dc", "ehr-app", "ehr-db", "lab", "pharmacy", "file", "ed-board", "mail"]:
        hosts.append(Host(s, "server", "servers"))
    hosts.append(Host("vpn", "server", "dmz", rdp_internet=True))  # a jump box with RDP open
    hosts.append(Host("backup", "backup-server", "backup"))

    by_id = {h.id: h for h in hosts}
    # A realistic mix: a handful of unpatched workstations and servers.
    for hid in ["adm-ws03", "ward-ws07", "ward-ws12", "ed-ws02", "lab", "file"]:
        by_id[hid].patched = False

    # A flat-ish network: most zones can talk SMB and RDP to most others.
    allow: set[tuple[str, str, int]] = set()
    inner = ["admin", "clinical", "ed", "imaging", "servers", "backup", "dmz"]
    for a in inner:
        for b in inner:
            if a != b:
                allow |= {(a, b, SMB), (a, b, RDP)}
    # IoT is reachable from servers (to manage it) but rarely the other way.
    allow |= {("servers", "iot", SMB), ("servers", "iot", RDP)}

    services = [
        Service("Patient records (EHR)", ["ehr-app", "ehr-db", "dc"], critical=True),
        Service("ED tracking board", ["ed-board", "ehr-app"], critical=True),
        Service("Imaging", ["pacs"], any_of=["mri-console", "ct-console", "xray-console"], critical=True),
        Service("Lab results", ["lab"]),
        Service("Pharmacy dispensing", ["pharmacy", "dc"]),
        Service("Infusion pump management", ["pump-mgr"]),
        Service("Email", ["mail", "dc"]),
        Service("Shared drives", ["file", "dc"]),
    ]
    return Hospital(hosts=by_id, allow=allow, services=services)
