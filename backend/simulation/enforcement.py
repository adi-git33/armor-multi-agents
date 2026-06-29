"""
Enforcement Stub — placeholder for RAA (Part 8).

Subscribes to the `resolution` topic and simulates applying defensive
actions.  When RAA is built it will replace this stub entirely:
  - RAA runs a sealed-bid auction among agents competing for the same
    defensive resource (firewall slot, rate-limiter bandwidth, etc.)
  - RAA publishes the grant to `resource-grants` so enforcement actually
    happens in the simulated network layer.

For now, this stub simply records what WOULD have been enforced so that
tests and logs can verify the decision chain end-to-end without RAA.

Supported actions
-----------------
BLOCK_SOURCE_IP       resolution["enforcement_target"]["src_ip"]    → blocked_ips
QUARANTINE_SEGMENT    resolution["enforcement_target"]["segment"]    → quarantined_segments
LOG_ONLY              recorded in log, no resource effect
"""

from __future__ import annotations
import logging
import time

from bus.message_bus import MessageBus
from core.messages import Message, Topic

logger = logging.getLogger(__name__)


class EnforcementStub:

    def __init__(self, bus: MessageBus) -> None:
        self._bus = bus
        self.blocked_ips:          set[str]   = set()
        self.quarantined_segments: set[str]   = set()
        self.log:                  list[dict] = []

    async def start(self) -> None:
        self._bus.subscribe(Topic.RESOLUTION, self._on_resolution)
        logger.info("[EnforcementStub] ready — listening on resolution topic")

    async def _on_resolution(self, msg: Message) -> None:
        c = msg.content
        if c.get("outcome") != "EXECUTED":
            return

        action = c.get("action", "")
        target = c.get("enforcement_target", {})
        entry  = {
            "ts":     time.monotonic(),
            "action": action,
            "target": target,
        }
        self.log.append(entry)

        if action == "BLOCK_SOURCE_IP":
            ip = target.get("src_ip", "")
            if ip:
                self.blocked_ips.add(ip)
                logger.info("[EnforcementStub] BLOCK_SOURCE_IP  ip=%s", ip)

        elif action == "QUARANTINE_SEGMENT":
            seg = target.get("segment", "")
            if seg:
                self.quarantined_segments.add(seg)
                logger.info("[EnforcementStub] QUARANTINE_SEGMENT  seg=%s", seg)

        elif action == "LOG_ONLY":
            logger.info("[EnforcementStub] LOG_ONLY  target=%s", target)

    # ── Query helpers ──────────────────────────────────────────────────

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def is_quarantined(self, segment: str) -> bool:
        return segment in self.quarantined_segments
