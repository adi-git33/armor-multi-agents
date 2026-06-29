"""
FIPA-ACL Message Format  (SDD §3.1.1)
======================================
All inter-agent communication uses this envelope.  The `performative`
field expresses the communicative intent so agents can distinguish
INFORM from REQUEST from BID without parsing free-text content.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import datetime
import uuid


# ── Performatives ─────────────────────────────────────────────────────────────

class Performative(str, Enum):
    INFORM            = "INFORM"
    REQUEST           = "REQUEST"
    PROPOSE           = "PROPOSE"
    ACCEPT            = "ACCEPT"
    REJECT            = "REJECT"
    CALL_FOR_PROPOSAL = "CALL-FOR-PROPOSAL"
    BID               = "BID"
    FAILURE           = "FAILURE"
    NOT_UNDERSTOOD    = "NOT-UNDERSTOOD"


# ── Topic registry  (SDD Table 2) ─────────────────────────────────────────────

class Topic:
    ALERTS          = "alerts"           # TMA  -> ACA
    THREAT_REPORTS  = "threat-reports"   # ACA  -> RCA, TIA
    THREAT_INTEL    = "threat-intel"     # TIA, ACA -> ACA, RCA, RAA
    RESOURCE_BIDS   = "resource-bids"    # TMA, ACA, RCA -> RAA
    RESOURCE_GRANTS = "resource-grants"  # RAA  -> all
    COALITION       = "coalition"        # TIA  -> ACA, RCA, RAA
    VOTES           = "votes"            # RCA  -> coalition members
    RESOLUTION      = "resolution"       # RCA  -> coalition, RAA

    ALL: list[str]   # populated below


Topic.ALL = [
    Topic.ALERTS, Topic.THREAT_REPORTS, Topic.THREAT_INTEL,
    Topic.RESOURCE_BIDS, Topic.RESOURCE_GRANTS,
    Topic.COALITION, Topic.VOTES, Topic.RESOLUTION,
]


# ── Message envelope ──────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


@dataclass
class Message:
    """
    FIPA-ACL message envelope.

    Fields the SENDER fills in:
        performative, sender, topic, content
        receiver      (default BROADCAST)
        conversation_id (auto-generated if omitted — group related messages)
        reply_by      (ISO-8601 deadline for time-bounded interactions)

    Fields the BUS fills in on publish:
        msg_id        (always fresh UUID)
        lamport_ts    (bus Lamport clock value at publish time)
        seq           (per-sender monotonic counter, used for deduplication)
        timestamp     (wall-clock UTC)
    """

    # --- sender fills these ---
    performative:    Performative
    sender:          str                # "<agent_type>:<agent_id>"
    topic:           str                # one of Topic.*
    content:         dict[str, Any]

    receiver:        str      = "BROADCAST"
    conversation_id: str      = field(default_factory=lambda: str(uuid.uuid4()))
    reply_by:        str | None = None  # ISO-8601, enforced by receiving agent

    # --- bus fills these ---
    msg_id:     str = field(default_factory=lambda: str(uuid.uuid4()))
    lamport_ts: int = 0
    seq:        int = 0
    timestamp:  str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "msg_id":          self.msg_id,
            "performative":    self.performative.value,
            "sender":          self.sender,
            "receiver":        self.receiver,
            "topic":           self.topic,
            "conversation_id": self.conversation_id,
            "reply_by":        self.reply_by,
            "content":         self.content,
            "timestamp":       self.timestamp,
            "lamport_ts":      self.lamport_ts,
            "seq":             self.seq,
        }

    def __repr__(self) -> str:
        return (
            f"Message({self.performative.value} "
            f"{self.sender}->{self.receiver} "
            f"topic={self.topic} "
            f"L={self.lamport_ts} seq={self.seq})"
        )
