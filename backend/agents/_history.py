"""
Sliding-window / cooldown helpers shared by the agents that keep a
per-segment (or per-key) rolling history of recent events.
"""

from __future__ import annotations


def append_and_expire(
    history: list[dict], entry: dict, now: float, window: float
) -> list[dict]:
    """Append `entry` (must carry a "time" key) to `history`, then drop
    everything older than `window` seconds. Returns the trimmed list —
    callers must reassign it back (history is not mutated in place)."""
    history.append(entry)
    return [item for item in history if now - item["time"] <= window]


def cooldown_ok(last_time: float, now: float, cooldown: float) -> bool:
    """True once at least `cooldown` seconds have passed since `last_time`."""
    return (now - last_time) >= cooldown
