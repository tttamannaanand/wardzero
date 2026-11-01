"""Every probability and duration the model uses, in one place.

These are ILLUSTRATIVE assumptions chosen to be plausible, not measured
values. Change them and see how the conclusions move: that sensitivity is
the point of a model like this. Times are in minutes.
"""

from dataclasses import dataclass

HOUR = 60
DAY = 24 * HOUR


@dataclass(frozen=True)
class Assumptions:
    # --- Initial access -------------------------------------------------
    phishing_recipients: int = 25
    """Staff who receive the phishing email in one wave."""
    click_rate: float = 0.12
    """Chance a recipient opens the attachment and runs it."""
    click_rate_trained: float = 0.04
    """Click rate after phishing-awareness training."""
    rdp_bruteforce_time: tuple[int, int] = (6 * HOUR, 3 * DAY)
    """How long guessing a weak password on an internet-facing RDP host takes."""

    # --- Spreading inside the network ----------------------------------
    lateral_interval: tuple[int, int] = (20, 4 * HOUR)
    """Time between the attacker's attempts to move from one foothold."""
    exploit_success: float = 0.6
    """Chance an attack on an unpatched, reachable service works."""
    creds_success: float = 0.9
    """Chance logging in with stolen, valid credentials works."""
    harvest_delay: tuple[int, int] = (30, 6 * HOUR)
    """Time after compromise before credentials are dumped from memory."""
    admin_logged_in_rate: float = 0.25
    """Chance a domain admin's credentials are cached on a given workstation."""

    # --- The attacker's patience ---------------------------------------
    dwell_before_detonation: tuple[int, int] = (2 * DAY, 9 * DAY)
    """How long the attacker waits after owning the domain before encrypting."""
    fallback_detonation: tuple[int, int] = (5 * DAY, 14 * DAY)
    """Without domain admin, how long after getting in the attacker gives up
    escalating and encrypts whatever they already hold."""
    panic_detonation: float = 0.6
    """Chance an attacker holding domain admin encrypts early when one of
    their footholds is suddenly cut off."""
    encrypt_spread: tuple[int, int] = (2, 90)
    """Delay for each host once mass encryption starts (it isn't instant)."""

    # --- Detection and response ----------------------------------------
    edr_detect_per_technique: float = 0.18
    """Chance EDR flags one technique on a host that runs an agent."""
    edr_block_payload: float = 0.35
    """Chance EDR blocks the initial malicious file outright."""
    canary_detect: float = 0.9
    """Chance touching a decoy (canary) share raises an alert."""
    soc_response: tuple[int, int] = (30, 8 * HOUR)
    """Time from an alert to someone isolating the host."""
    full_containment_after_alerts: int = 2
    """Separate alerts needed before IT resets every domain credential."""
    containment_time: tuple[int, int] = (2 * HOUR, 12 * HOUR)
    """Time to reset domain credentials once containment starts."""

    # --- Recovery --------------------------------------------------------
    restore_per_host: tuple[int, int] = (3 * HOUR, 10 * HOUR)
    """Restoring one host from surviving backups."""
    rebuild_per_host: tuple[int, int] = (1 * DAY, 4 * DAY)
    """Rebuilding one host from scratch when backups are gone."""
    it_staff: int = 4
    """Hosts the IT team can restore in parallel."""
    isolation_outage: tuple[int, int] = (1 * HOUR, 6 * HOUR)
    """How long an isolated (not encrypted) host stays offline while checked."""

    horizon: int = 21 * DAY
    """How long each simulated incident runs."""
