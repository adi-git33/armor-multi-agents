"""
Ground-truth confusion-matrix judging and derived-metric formulas
(DR / FPR / MTTR / availability / social welfare, SRS §7.2/§7.3),
extracted out of StateCollector so the pure math is readable and
testable on its own, separate from the live state it's applied to.
"""

from __future__ import annotations

# The live dashboard flips ground truth the instant a scenario button is
# clicked, but the attack itself takes a few seconds to manifest (DDoS ramp)
# and a few seconds to drain after it stops. The offline validation suite
# accounts for this with warmup/buffer windows (§V-SYS-01); these two windows
# mirror that methodology for the live metrics so a report during the ramp
# counts as detection *latency*, not a miss, and a report just after "calm"
# is residual, not a false positive.
ATTACK_GRACE_SECS = 5.0   # after attack start: NOISE here is not an FN
CALM_LINGER_SECS  = 10.0  # after attack end: threat flags here are not FPs

# Which TMA alert modality carries each attack type — a NOISE verdict on a
# volume alert during a *port-scan* attack is correct (the scan doesn't move
# pps), so only same-modality NOISE verdicts can count as misses.
ATTACK_MODALITY = {"DDOS": "VOLUME_SPIKE", "PORT_SCAN": "PORT_SCAN"}


def classify_threat_report(
    *,
    classification: str,
    source_alert: str,
    segment: str,
    now: float,
    active_attacks: dict[str, str],
    attack_started: dict[str, float],
    attack_ended: dict[str, float],
) -> str | None:
    """Return which confusion-matrix bucket ("tp"/"fp"/"fn"/"tn") this
    threat-report classification falls into against ground truth.
    None means no bucket changes (e.g. a mismatched threat type mid-attack
    is neither a hit nor a calm-moment error)."""
    attack_type  = active_attacks.get(segment)
    under_attack = attack_type is not None
    in_grace  = (under_attack and
                 now - attack_started.get(segment, now) < ATTACK_GRACE_SECS)
    in_linger = (not under_attack and
                 now - attack_ended.get(segment, float("-inf")) < CALM_LINGER_SECS)

    if classification == "NOISE":
        if under_attack and source_alert == ATTACK_MODALITY.get(attack_type):
            # NOISE on the attack's own modality is a miss — unless the
            # attack just started and is still ramping (grace window).
            return None if in_grace else "fn"
        return "tn"   # correctly quiet (or off-modality chatter)

    if under_attack:
        return "tp" if classification == attack_type else None
    return None if in_linger else "fp"   # genuinely calm moment flagged as a threat


def compute_metrics(
    *,
    tp: int, fp: int, fn: int, tn: int,
    mttr_ms: list[float],
    disruption_secs: float,
    elapsed_secs: float,
    blocked_ip_count: int,
    quarantined_seg_count: int,
) -> dict:
    """Standard confusion-matrix rates against ground truth plus the
    weighted social-welfare utility sum (SRS §7.2)."""
    el = max(1.0, elapsed_secs)

    dr  = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    mttr = (sum(mttr_ms) / len(mttr_ms)) if mttr_ms else 0.0
    avail = max(0.96, 1.0 - (disruption_secs / el) * 0.12)

    u_tma = dr * 0.88            if el > 5  else 0.0
    u_aca = dr * (1 - fpr)       if el > 5  else 0.0
    u_rca = (avail * min(1.5, 1000 / max(600, mttr)) * 0.85
             if mttr > 0 else avail * 0.35)
    u_tia = min(1.0, (tp + blocked_ip_count + quarantined_seg_count) * 0.25)
    u_raa = 0.88
    sw = (0.20 * u_tma + 0.30 * u_aca + 0.25 * u_rca +
          0.15 * u_tia + 0.10 * u_raa)

    return {
        "dr":           round(min(1.0, dr),   3),
        "fpr":          round(max(0.0, fpr),  3),
        "mttr":         round(mttr),
        "availability": round(avail,           4),
        "sw":           round(min(1.0, max(0.0, sw)), 3),
    }
