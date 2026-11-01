"""One simulated ransomware incident, from first click to recovery.

An event-driven simulation: the attacker's moves, the defenders' alerts and
responses, and the encryption itself are events on a single timeline, all
drawn from one seeded random generator so every run can be replayed.

Attacker techniques are tagged with MITRE ATT&CK IDs.
"""

from __future__ import annotations

import heapq
import random
from dataclasses import dataclass, field

from .assumptions import DAY, Assumptions
from .defences import Defences, apply
from .hospital import RDP, SMB, Hospital, Host, build

TECHNIQUES = {
    "T1566.001": "Phishing: malicious attachment",
    "T1110": "Brute-forcing a remote desktop password",
    "T1133": "External remote services",
    "T1003.001": "Dumping credentials from memory",
    "T1078.002": "Using stolen domain admin credentials",
    "T1078.003": "Reusing a shared local admin password",
    "T1210": "Exploiting an unpatched remote service",
    "T1021.001": "Moving over remote desktop",
    "T1021.002": "Moving over SMB admin shares",
    "T1003.006": "Copying every password from the domain controller (DCSync)",
    "T1490": "Destroying backups",
    "T1486": "Encrypting data for impact",
}


@dataclass
class Event:
    t: int
    kind: str
    host: str = ""
    technique: str = ""
    detail: str = ""


@dataclass
class Result:
    seed: int
    defences: list[str]
    vector: str = ""
    time_to_domain_admin: int | None = None
    first_alert: int | None = None
    detonated_at: int | None = None
    contained_at: int | None = None
    backups_destroyed: bool = False
    encrypted: dict[str, int] = field(default_factory=dict)
    isolated: dict[str, int] = field(default_factory=dict)
    isolated_until: dict[str, int] = field(default_factory=dict)
    restored: dict[str, int] = field(default_factory=dict)
    service_downtime: dict[str, int] = field(default_factory=dict)
    """Minutes each clinical service was down."""
    service_first_down: dict[str, int | None] = field(default_factory=dict)
    diversion_minutes: int = 0
    """Minutes any critical service was down: ambulances divert."""
    events: list[Event] = field(default_factory=list)

    @property
    def hosts_encrypted(self) -> int:
        return len(self.encrypted)


class Incident:
    def __init__(self, seed: int, defences: Defences, hospital: Hospital | None, a: Assumptions):
        self.rng = random.Random(seed)
        self.d = defences
        self.h, self.a = apply(defences, hospital or build(), a)
        self.r = Result(seed=seed, defences=defences.active())
        self.queue: list[tuple[int, int, str, tuple]] = []
        self.seq = 0
        self.now = 0

        self.compromised: dict[str, int] = {}
        self.isolated_until: dict[str, int] = {}
        self.domain_admin = False
        self.shared_local_admin = False
        self.detonation_scheduled = False
        self.containment_scheduled = False
        self.alerts = 0

        # Who has admin credentials cached in memory, decided once per run.
        self.cached_admin: set[str] = {"it-admin"}
        for host in sorted(self.h.hosts.values(), key=lambda x: x.id):
            if self.d.admin_tiering:
                break  # admins only ever log in to the domain controller
            rate = self.a.admin_logged_in_rate * (2.4 if host.kind == "server" else 1.0)
            if host.kind in ("workstation", "server") and self.rng.random() < rate:
                self.cached_admin.add(host.id)
        if self.d.admin_tiering:
            self.cached_admin = set()

    # ------------------------------------------------------------ plumbing

    def between(self, span: tuple[int, int]) -> int:
        return self.rng.randint(span[0], span[1])

    def at(self, t: int, kind: str, *args) -> None:
        self.seq += 1
        heapq.heappush(self.queue, (t, self.seq, kind, args))

    def log(self, kind: str, host: str = "", technique: str = "", detail: str = "") -> None:
        self.r.events.append(Event(self.now, kind, host, technique, detail))

    def host(self, hid: str) -> Host:
        return self.h.hosts[hid]

    def active(self, hid: str) -> bool:
        """Still an attacker foothold: compromised, not isolated, not encrypted."""
        return hid in self.compromised and hid not in self.isolated_until and hid not in self.r.encrypted

    # ------------------------------------------------------------ run

    def run(self) -> Result:
        self.at(self.between((0, 8 * 60)), "phish")
        rdp_hosts = [h for h in sorted(self.h.hosts) if self.host(h).rdp_internet]
        for hid in rdp_hosts:
            if not self.d.mfa:
                self.at(self.between(self.a.rdp_bruteforce_time), "rdp_in", hid)

        while self.queue:
            t, _, kind, args = heapq.heappop(self.queue)
            if t > self.a.horizon:
                break
            self.now = t
            getattr(self, f"on_{kind}")(*args)

        self.recover()
        self.measure()
        return self.r

    # ------------------------------------------------------------ initial access

    def on_phish(self) -> None:
        users = sorted(h.id for h in self.h.hosts.values() if h.user)
        for hid in self.rng.sample(users, min(self.a.phishing_recipients, len(users))):
            if self.rng.random() < self.a.click_rate:
                self.at(self.now + self.between((1, 240)), "open_attachment", hid)

    def on_open_attachment(self, hid: str) -> None:
        if self.host(hid).edr and self.rng.random() < self.a.edr_block_payload:
            self.log("blocked", hid, "T1566.001", "EDR blocked the malicious attachment")
            self.alert(hid)
            return
        self.compromise(hid, "T1566.001", vector="phishing")

    def on_rdp_in(self, hid: str) -> None:
        self.compromise(hid, "T1110", vector="exposed remote desktop")

    # ------------------------------------------------------------ the attacker

    def compromise(self, hid: str, technique: str, vector: str = "") -> None:
        if hid in self.compromised or hid in self.r.encrypted or hid in self.isolated_until:
            return
        if vector and not self.r.vector:
            self.r.vector = vector
            # If escalation stalls, they'll settle for encrypting what they have.
            self.at(self.now + self.between(self.a.fallback_detonation), "detonate")
        self.compromised[hid] = self.now
        self.log("compromised", hid, technique, TECHNIQUES[technique])
        self.detect(hid)
        if hid == "dc" and not self.domain_admin:
            self.gain_domain_admin(hid, "T1003.006")
        self.at(self.now + self.between(self.a.harvest_delay), "harvest", hid)
        self.at(self.now + self.between(self.a.lateral_interval), "lateral", hid)

    def on_harvest(self, hid: str) -> None:
        if not self.active(hid):
            return
        self.log("harvest", hid, "T1003.001", TECHNIQUES["T1003.001"])
        self.detect(hid)
        host = self.host(hid)
        if host.kind == "workstation" and not self.d.admin_tiering and not self.shared_local_admin:
            self.shared_local_admin = True
            self.log("credentials", hid, "T1078.003", "Got the local admin password shared by every workstation")
        if hid in self.cached_admin and not self.domain_admin:
            self.gain_domain_admin(hid, "T1078.002")

    def gain_domain_admin(self, hid: str, technique: str) -> None:
        self.domain_admin = True
        if self.r.time_to_domain_admin is None:
            self.r.time_to_domain_admin = self.now
        self.log("domain_admin", hid, technique, "Attacker now holds domain admin")
        if not self.detonation_scheduled:
            self.detonation_scheduled = True
            self.at(self.now + self.between(self.a.dwell_before_detonation), "detonate")

    def on_lateral(self, hid: str) -> None:
        if not self.active(hid) or self.r.detonated_at is not None:
            return
        src = self.host(hid)
        targets = sorted(
            h.id
            for h in self.h.hosts.values()
            if h.id not in self.compromised
            and h.id not in self.isolated_until
            and h.encryptable
            and (self.h.reachable(src, h, SMB) or self.h.reachable(src, h, RDP))
        )
        if targets:
            # With domain admin, the domain controller is the prize.
            target = "dc" if self.domain_admin and "dc" in targets else self.rng.choice(targets)
            dst = self.host(target)
            method = self.how_to_move(src, dst)
            if method and self.rng.random() < (self.a.exploit_success if method == "T1210" else self.a.creds_success):
                self.log("lateral", target, method, f"{TECHNIQUES[method]} from {hid}")
                self.at(self.now + self.between((5, 60)), "land", target, method)
            if self.d.canaries and self.rng.random() < 0.12:
                self.log("canary", hid, "", "Attacker browsed a decoy file share")
                if self.rng.random() < self.a.canary_detect:
                    self.alert(hid)
        self.at(self.now + self.between(self.a.lateral_interval), "lateral", hid)

    def how_to_move(self, src: Host, dst: Host) -> str | None:
        rdp = self.h.reachable(src, dst, RDP)
        smb = self.h.reachable(src, dst, SMB)
        if self.domain_admin:
            return "T1021.001" if rdp else "T1021.002"
        if dst.kind == "workstation" and self.shared_local_admin and smb:
            return "T1021.002"
        if not dst.patched and smb:
            return "T1210"
        return None

    def on_land(self, target: str, method: str) -> None:
        self.compromise(target, method)

    # ------------------------------------------------------------ the defenders

    def detect(self, hid: str) -> None:
        if self.host(hid).edr and self.rng.random() < self.a.edr_detect_per_technique:
            self.alert(hid)

    def alert(self, hid: str) -> None:
        self.alerts += 1
        if self.r.first_alert is None:
            self.r.first_alert = self.now
        self.log("alert", hid, "", "Security alert raised")
        self.at(self.now + self.between(self.a.soc_response), "isolate", hid)
        if self.alerts >= self.a.full_containment_after_alerts and not self.containment_scheduled:
            self.containment_scheduled = True
            self.at(self.now + self.between(self.a.containment_time), "contain")

    def on_isolate(self, hid: str) -> None:
        if hid in self.r.encrypted or hid in self.isolated_until:
            return
        was_foothold = self.active(hid)
        self.isolated_until[hid] = self.now + self.between(self.a.isolation_outage)
        self.r.isolated[hid] = self.now
        self.log("isolated", hid, "", "Host cut off from the network")
        # Losing one of their own machines can spook an attacker into encrypting early.
        if was_foothold and self.domain_admin and self.r.detonated_at is None and self.rng.random() < self.a.panic_detonation:
            self.log("panic", hid, "", "Attacker noticed and detonated early")
            self.on_detonate()

    def on_contain(self) -> None:
        if self.r.detonated_at is not None:
            return
        self.r.contained_at = self.now
        self.domain_admin = False
        self.shared_local_admin = False
        for hid in sorted(self.compromised):
            if hid not in self.isolated_until:
                self.isolated_until[hid] = self.now + self.between(self.a.isolation_outage)
                self.r.isolated[hid] = self.now
        self.log("contained", "", "", "Every domain password reset and all known footholds isolated")

    # ------------------------------------------------------------ impact

    def on_detonate(self) -> None:
        if self.r.detonated_at is not None:
            return
        footholds = [h for h in sorted(self.compromised) if self.active(h)]
        if not footholds:
            return
        self.r.detonated_at = self.now
        if self.domain_admin:
            backup = self.host("backup")
            reach = any(self.h.reachable(self.host(f), backup, SMB) for f in footholds)
            if reach and not self.d.offline_backups:
                self.r.backups_destroyed = True
                self.log("backups", "backup", "T1490", TECHNIQUES["T1490"])
            targets = sorted(
                h.id
                for h in self.h.hosts.values()
                if h.encryptable
                and h.id not in self.isolated_until
                and any(self.h.reachable(self.host(f), h, SMB) for f in footholds)
            )
        else:
            targets = footholds  # without admin rights, only what they already hold
        self.log("detonate", "", "T1486", f"Mass encryption begins on {len(targets)} hosts")
        for hid in targets:
            self.at(self.now + self.between(self.a.encrypt_spread), "encrypt", hid)

    def on_encrypt(self, hid: str) -> None:
        if hid in self.r.encrypted or hid in self.isolated_until:
            return
        self.r.encrypted[hid] = self.now
        self.log("encrypted", hid, "T1486", "Encrypted")

    # ------------------------------------------------------------ aftermath

    def recover(self) -> None:
        """IT restores encrypted hosts, most critical first, a few at a time."""
        if not self.r.encrypted:
            return
        priority = ["dc", "ehr-db", "ehr-app", "ed-board", "pacs", "pharmacy", "lab", "pump-mgr", "mail", "file"]
        order = sorted(self.r.encrypted, key=lambda h: (priority.index(h) if h in priority else 99, h))
        start = max(self.r.encrypted.values()) + 12 * 60  # half a day to scope the damage first
        span = self.a.rebuild_per_host if self.r.backups_destroyed else self.a.restore_per_host
        workers = [start] * self.a.it_staff
        for hid in order:
            i = workers.index(min(workers))
            workers[i] += self.between(span)
            self.r.restored[hid] = workers[i]

    def down_intervals(self, hid: str) -> list[tuple[int, int]]:
        out = []
        if hid in self.r.encrypted:
            out.append((self.r.encrypted[hid], self.r.restored.get(hid, self.a.horizon)))
        if hid in self.r.isolated:
            out.append((self.r.isolated[hid], self.isolated_until.get(hid, self.r.isolated[hid])))
        return out

    def measure(self) -> None:
        self.r.isolated_until = dict(self.isolated_until)
        step = 10
        down = {hid: self.down_intervals(hid) for hid in self.h.hosts}

        def is_down(hid: str, t: int) -> bool:
            return any(a <= t < b for a, b in down[hid])

        for svc in self.h.services:
            minutes, first = 0, None
            for t in range(0, self.a.horizon, step):
                broken = any(is_down(n, t) for n in svc.needs) or (
                    svc.any_of and all(is_down(n, t) for n in svc.any_of)
                )
                if broken:
                    minutes += step
                    first = t if first is None else first
            self.r.service_downtime[svc.name] = minutes
            self.r.service_first_down[svc.name] = first

        critical = [s for s in self.h.services if s.critical]
        for t in range(0, self.a.horizon, step):
            if any(
                any(is_down(n, t) for n in s.needs) or (s.any_of and all(is_down(n, t) for n in s.any_of))
                for s in critical
            ):
                self.r.diversion_minutes += step


def simulate(seed: int, defences: Defences | None = None, hospital: Hospital | None = None,
             assumptions: Assumptions | None = None) -> Result:
    return Incident(seed, defences or Defences(), hospital, assumptions or Assumptions()).run()


def days(minutes: int | None) -> str:
    return "never" if minutes is None else f"{minutes / DAY:.1f} days"
