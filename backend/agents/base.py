"""
BaseAgent  (SDD §4.1)
======================
Minimal foundation shared by every agent in the system.

Provides:
  - agent_id  (e.g. "TMA:1", "ACA:2")
  - message bus reference + publish() helper (auto-increments seq)
  - start() / stop() lifecycle hooks (override in subclass)
  - subscribe() — bus subscription auto-guarded against post-stop() delivery
  - _short_id() — short opaque id for incidents/allocations
"""

from __future__ import annotations
import logging
import uuid
from typing import Any, Awaitable, Callable

from core.messages import Message, Performative
from bus.message_bus import MessageBus

logger = logging.getLogger(__name__)

EventHandler = Callable[[Any], Awaitable[None]]


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
    # Communication helpers
    # ------------------------------------------------------------------

    def _guarded(self, handler: EventHandler) -> EventHandler:
        """Wrap a handler so it silently no-ops once stop() has been
        called, instead of every handler re-checking self._running."""
        async def _wrapped(event: Any) -> None:
            if not self._running:
                return
            await handler(event)
        return _wrapped

    def subscribe(self, topic: str, handler: EventHandler) -> None:
        """Subscribe `handler` on the bus with the running-guard applied.
        Call from within start(), after `await super().start()`."""
        self.bus.subscribe(topic, self._guarded(handler))

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

    # ------------------------------------------------------------------
    # Misc helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _short_id() -> str:
        return str(uuid.uuid4())[:8]
