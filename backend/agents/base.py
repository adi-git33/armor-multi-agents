"""
BaseAgent  (SDD §4.1)
======================
Minimal foundation shared by every agent in the system.

Provides:
  - agent_id  (e.g. "TMA:1", "ACA:2")
  - message bus reference + publish() helper (auto-increments seq)
  - start() / stop() lifecycle hooks (override in subclass)
"""

from __future__ import annotations
import logging

from core.messages import Message, Performative, Topic
from bus.message_bus import MessageBus

logger = logging.getLogger(__name__)


class BaseAgent:

    def __init__(self, agent_id: str, bus: MessageBus) -> None:
        self.agent_id = agent_id
        self.bus      = bus
        self._running = False
        self._seq     = 0           # per-agent outgoing sequence counter

    # ------------------------------------------------------------------
    # Lifecycle  (override in subclasses; always call super())
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        logger.debug("[%s] started", self.agent_id)

    async def stop(self) -> None:
        self._running = False
        logger.debug("[%s] stopped", self.agent_id)

    # ------------------------------------------------------------------
    # Communication helper
    # ------------------------------------------------------------------

    async def publish(
        self,
        topic:        str,
        performative: Performative,
        content:      dict,
        receiver:     str = "BROADCAST",
        **kwargs,
    ) -> None:
        """
        Build and publish one FIPA-ACL message on behalf of this agent.
        The seq is managed here so the bus dedup logic works correctly.
        """
        self._seq += 1
        msg = Message(
            performative    = performative,
            sender          = self.agent_id,
            topic           = topic,
            content         = content,
            receiver        = receiver,
            seq             = self._seq,
            **kwargs,
        )
        await self.bus.publish(msg)
