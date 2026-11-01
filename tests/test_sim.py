from dataclasses import replace

import pytest

from wardzero.assumptions import Assumptions
from wardzero.compare import percentile, summarise
from wardzero.defences import Defences, apply
from wardzero.hospital import RDP, SMB, build
from wardzero.sim import TECHNIQUES, simulate

SEEDS = range(1, 41)


def test_same_seed_same_incident():
    a, b = simulate(7), simulate(7)
    assert [(e.t, e.kind, e.host) for e in a.events] == [(e.t, e.kind, e.host) for e in b.events]
    assert a.encrypted == b.encrypted


def test_different_seeds_tell_different_stories():
    timelines = {tuple((e.t, e.host) for e in simulate(s).events[:5]) for s in range(1, 11)}
    assert len(timelines) > 5


def test_no_way_in_means_nothing_happens():
    quiet = replace(Assumptions(), click_rate=0.0)
    r = simulate(3, Defences(mfa=True), assumptions=quiet)
    assert r.vector == ""
    assert r.encrypted == {}
    assert r.diversion_minutes == 0


def test_every_technique_is_a_real_attack_id():
    for s in SEEDS:
        for e in simulate(s).events:
            assert e.technique == "" or e.technique in TECHNIQUES


def test_medical_devices_are_never_encrypted():
    h = build()
    devices = {hid for hid, host in h.hosts.items() if not host.encryptable}
    for s in SEEDS:
        assert not devices & simulate(s).encrypted.keys()


def test_offline_backups_always_survive():
    for s in SEEDS:
        assert not simulate(s, Defences(offline_backups=True)).backups_destroyed


def test_with_tiering_domain_admin_only_comes_from_the_domain_controller():
    for s in SEEDS:
        r = simulate(s, Defences(admin_tiering=True))
        if r.time_to_domain_admin is not None:
            assert "dc" in r.encrypted or any(e.kind == "compromised" and e.host == "dc" for e in r.events)
        assert not any(e.technique == "T1078.003" for e in r.events), "no shared local admin password to steal"


def test_segmentation_cuts_workstation_to_workstation_paths():
    h, _ = apply(Defences(segmentation=True), build(), Assumptions())
    ward, ed = h.hosts["ward-ws01"], h.hosts["ed-ws01"]
    assert not h.reachable(ward, ed, SMB)
    assert not h.reachable(ward, ed, RDP)
    assert h.reachable(ward, h.hosts["ehr-app"], SMB), "staff still reach their applications"
    assert not h.reachable(ward, h.hosts["backup"], SMB)


def test_restoring_always_comes_after_encryption():
    for s in SEEDS:
        r = simulate(s)
        for hid, t in r.encrypted.items():
            assert r.restored[hid] > t


def test_downtime_is_bounded_and_diversion_covers_critical_services():
    horizon = Assumptions().horizon
    h = build()
    critical = [svc.name for svc in h.services if svc.critical]
    for s in SEEDS:
        r = simulate(s)
        assert all(0 <= m <= horizon for m in r.service_downtime.values())
        assert r.diversion_minutes >= max(r.service_downtime[c] for c in critical)


def test_lost_backups_mean_slower_recovery():
    with_backups = summarise("b", [simulate(s, Defences(offline_backups=True)) for s in SEEDS])
    without = summarise("n", [simulate(s) for s in SEEDS])
    assert with_backups.diversion_hours_mean < without.diversion_hours_mean / 2


def test_every_defence_together_stops_encryption():
    for s in SEEDS:
        assert simulate(s, Defences.all()).encrypted == {}


def test_percentile():
    assert percentile([1, 2, 3, 4, 5], 0.5) == 3
    assert percentile([], 0.9) == 0.0
    assert percentile([0, 10], 0.9) == pytest.approx(9)
