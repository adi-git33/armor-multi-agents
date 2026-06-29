"""
Resource Allocator Agent  (SDD §4.6)
======================================
Manages limited defensive resources across simultaneous incidents using
a sealed-bid auction.  Each resolved incident carries an implicit bid:

    bid_value = confidence × (votes_accept / total_votes)

High confidence + unanimous vote → high bid → priority access.

When capacity is free:   grant immediately.
When capacity is full:   compare incoming bid vs the weakest existing
                         allocation (minimum bid in that resource pool).
  incoming > weakest  →  evict weakest, grant incoming.
  incoming <= weakest  →  deny incoming.

Resources modelled
------------------
FIREWALL   capacity = 3   consumed by BLOCK_SOURCE_IP
QUARANTINE capacity = 2   consumed by QUARANTINE_SEGMENT
LOG        unlimited      consumed by LOG_ONLY (never contends)

RAA also applies simulated enforcement: it maintains blocked_ips and
quarantined_segments sets, making EnforcementStub unnecessary once RAA
is in the system.

Publications
------------
resource-grants topic:
  INFORM   → resource granted
  REJECT   → incoming request denied (outbid by existing pool)
  FAILURE  → existing allocation evicted (outbid by incoming)

BDI roles
----------
Beliefs  : _allocations per resource type, current bid landscape
Desires  : maximise threat response quality within resource limits
Intention: _on_resolution → _allocate → _grant | _evict+_grant | _deny
"""

from __future__ import annotations
import logging
import time
import uuid
from dataclasses import dataclass, field

from agents.base import BaseAgent
from bus.message_bus import MessageBus
from core.messages import Message, Performative, Topic

logger = logging.getLogger(__name__)

# ── resource model ─────────────────────────────────────────────────────
RESOURCE_CAPACITY: dict[str, int] = {
    "FIREWALL":   3,
    "QUARANTINE": 2,
    "LOG":        999_999,   # effectively unlimited
}

RESOURCE_MAP: dict[str, str] = {
    "BLOCK_SOURCE_IP":    "FIREWALL",
    "QUARANTINE_SEGMENT": "QUARANTINE",
    "LOG_ONLY":           "LOG",
}

REQUIRED_GRANT_FIELDS = {
    "allocation_id", "incident_id", "segment", "action",
    "resource_type", "bid_value", "enforcement_target", "outcome",
}


@dataclass
class Allocation:
    allocation_id:      str
    incident_id:        str
    segment:            str
    action:             str
    resource_type:      str
    bid_value:          float
    enforcement_target: dict
    granted_at:         float = field(default_factory=time.monotonic)


class ResourceAllocatorAgent(BaseAgent):

    def __init__(self, agent_id: str, bus: MessageBus) -> None:
        super().__init__(agent_id, bus)

        # active allocations per resource type
        self._allocations: dict[str, list[Allocation]] = {
            r: [] for r in RESOURCE_CAPACITY
        }

        # simulated network enforcement state
        self.blocked_ips:          set[str] = set()
        self.quarantined_segments: set[str] = set()

        # audit ledger (for tests and introspection)
        self.grants:    list[dict] = []
        self.denials:   list[dict] = []
        self.evictions: list[dict] = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        await super().start()
        self.bus.subscribe(Topic.RESOLUTION,    self._on_resolution)
        self.bus.subscribe(Topic.RESOURCE_BIDS, self._on_resource_bid)
        logger.info("[%s] ready  capacity=%s", self.agent_id, RESOURCE_CAPACITY)

    # ------------------------------------------------------------------
    # Incoming resolution → compute bid, attempt allocation
    # ------------------------------------------------------------------

    async def _on_resolution(self, msg: Message) -> None:
        if not self._running:
            return
        c = msg.content
        if c.get("outcome") != "EXECUTED":
            return

        confidence  = float(c.get("confidence", 0.0))
        votes_a     = int(c.get("votes_accept", 1))
        votes_r     = int(c.get("votes_reject", 0))
        vote_ratio  = votes_a / max(votes_a + votes_r, 1)
        bid_value   = round(confidence * vote_ratio, 4)

        action        = c.get("action", "")
        resource_type = RESOURCE_MAP.get(action, "LOG")

        request = Allocation(
            allocation_id      = str(uuid.uuid4())[:8],
            incident_id        = c.get("incident_id", ""),
            segment            = c.get("segment", ""),
            action             = action,
            resource_type      = resource_type,
            bid_value          = bid_value,
            enforcement_target = c.get("enforcement_target", {}),
        )

        await self._allocate(request)

    # ------------------------------------------------------------------
    # Sealed-bid allocation decision
    # ------------------------------------------------------------------

    async def _allocate(self, request: Allocation) -> None:
        rtype    = request.resource_type
        capacity = RESOURCE_CAPACITY[rtype]
        current  = self._allocations[rtype]

        if len(current) < capacity:
            await self._grant(request)
            return

        # At capacity — find weakest existing allocation
        weakest = min(current, key=lambda a: a.bid_value)

        if request.bid_value > weakest.bid_value:
            await self._evict(weakest, reason=f"outbid by incident {request.incident_id}")
            await self._grant(request)
        else:
            await self._deny(
                request,
                reason=(
                    f"at capacity ({len(current)}/{capacity}); "
                    f"bid {request.bid_value:.4f} <= weakest existing {weakest.bid_value:.4f}"
                ),
            )

    # ------------------------------------------------------------------
    # Grant
    # ------------------------------------------------------------------

    async def _grant(self, request: Allocation) -> None:
        self._allocations[request.resource_type].append(request)
        self._enforce(request)

        entry = {
            "allocation_id":     request.allocation_id,
            "incident_id":       request.incident_id,
            "segment":           request.segment,
            "action":            request.action,
            "resource_type":     request.resource_type,
            "bid_value":         request.bid_value,
            "enforcement_target": request.enforcement_target,
            "outcome":           "GRANTED",
            "granted_at":        request.granted_at,
        }
        self.grants.append(entry)

        await self.publish(
            topic        = Topic.RESOURCE_GRANTS,
            performative = Performative.INFORM,
            content      = entry,
        )
        logger.info(
            "[%s] GRANTED  id=%s  action=%-20s  bid=%.4f  used=%d/%d  target=%s",
            self.agent_id, request.allocation_id, request.action,
            request.bid_value,
            len(self._allocations[request.resource_type]),
            RESOURCE_CAPACITY[request.resource_type],
            request.enforcement_target,
        )

    # ------------------------------------------------------------------
    # Evict an existing allocation (outbid by incoming)
    # ------------------------------------------------------------------

    async def _evict(self, existing: Allocation, reason: str) -> None:
        self._allocations[existing.resource_type] = [
            a for a in self._allocations[existing.resource_type]
            if a.allocation_id != existing.allocation_id
        ]

        entry = {
            "allocation_id": existing.allocation_id,
            "incident_id":   existing.incident_id,
            "segment":       existing.segment,
            "action":        existing.action,
            "resource_type": existing.resource_type,
            "bid_value":     existing.bid_value,
            "outcome":       "EVICTED",
            "reason":        reason,
        }
        self.evictions.append(entry)

        await self.publish(
            topic        = Topic.RESOURCE_GRANTS,
            performative = Performative.FAILURE,
            content      = entry,
        )
        logger.info(
            "[%s] EVICTED  id=%s  bid=%.4f  reason=%s",
            self.agent_id, existing.allocation_id, existing.bid_value, reason,
        )

    # ------------------------------------------------------------------
    # Deny incoming request (cannot beat existing pool)
    # ------------------------------------------------------------------

    async def _deny(self, request: Allocation, reason: str) -> None:
        entry = {
            "allocation_id": request.allocation_id,
            "incident_id":   request.incident_id,
            "segment":       request.segment,
            "action":        request.action,
            "resource_type": request.resource_type,
            "bid_value":     request.bid_value,
            "outcome":       "DENIED",
            "reason":        reason,
        }
        self.denials.append(entry)

        await self.publish(
            topic        = Topic.RESOURCE_GRANTS,
            performative = Performative.REJECT,
            content      = entry,
        )
        logger.info(
            "[%s] DENIED   id=%s  bid=%.4f  reason=%s",
            self.agent_id, request.allocation_id, request.bid_value, reason,
        )

    # ------------------------------------------------------------------
    # Simulated enforcement (network state)
    # ------------------------------------------------------------------

    def _enforce(self, request: Allocation) -> None:
        action = request.action
        target = request.enforcement_target

        if action == "BLOCK_SOURCE_IP":
            ip = target.get("src_ip", "")
            if ip:
                self.blocked_ips.add(ip)
                logger.info("[%s] enforced BLOCK_SOURCE_IP  ip=%s", self.agent_id, ip)

        elif action == "QUARANTINE_SEGMENT":
            seg = target.get("segment", request.segment)
            if seg:
                self.quarantined_segments.add(seg)
                logger.info(
                    "[%s] enforced QUARANTINE_SEGMENT  seg=%s", self.agent_id, seg
                )

    # ------------------------------------------------------------------
    # Stub for future explicit bids from agents
    # ------------------------------------------------------------------

    async def _on_resource_bid(self, msg: Message) -> None:
        pass   # explicit agent bids not yet used — reserved for future extension

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def used_capacity(self, resource_type: str) -> int:
        return len(self._allocations.get(resource_type, []))

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def is_quarantined(self, segment: str) -> bool:
        return segment in self.quarantined_segments
