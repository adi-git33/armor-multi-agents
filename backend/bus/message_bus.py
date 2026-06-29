"""
Message Bus  (SDD §3.1)
========================
Central pub/sub backbone for all inter-agent communication.

Guarantees (SDD §3.1.3):
  1. FIFO per-topic delivery  — one asyncio.Queue + one delivery task per topic
  2. Lamport clock ordering   — every message stamped; clock updated on recv
  3. Idempotent deduplication — (sender, seq) pairs are tracked; retries dropped
  4. Non-blocking delivery    — handlers are awaited sequentially per topic;
                                a slow handler delays that topic, not others
"""

import asyncio
import logging
from typing import Callable, Awaitable

from core.messages import Message, Topic

logger = logging.getLogger(__name__)

MessageHandler = Callable[[Message], Awaitable[None]]


class MessageBus:

    def __init__(self) -> None:
        # One FIFO queue per topic
        self._queues: dict[str, asyncio.Queue[Message]] = {
            t: asyncio.Queue() for t in Topic.ALL
        }
        # Registered async callbacks per topic (called in registration order)
        self._subscribers: dict[str, list[MessageHandler]] = {
            t: [] for t in Topic.ALL
        }
        # Lamport logical clock (shared across all topics)
        self._lamport: int = 0
        # Deduplication store: set of (sender_id, seq) already seen
        # Note: grows unbounded — for production use a TTL cache
        self._seen: set[tuple[str, int]] = set()
        # Per-sender outgoing sequence counter (assigned if msg.seq == 0)
        self._sender_seq: dict[str, int] = {}

        self._running: bool = False
        self._tasks:   list[asyncio.Task] = []

        # Observable counters
        self.published_count: int = 0
        self.delivered_count: int = 0
        self.dropped_count:   int = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start one delivery loop task per topic."""
        self._running = True
        self._tasks = [
            asyncio.create_task(
                self._delivery_loop(topic), name=f"bus-{topic}"
            )
            for topic in Topic.ALL
        ]
        logger.debug("[bus] Started — %d topic queues active", len(Topic.ALL))

    async def stop(self) -> None:
        """Cancel all delivery loops and wait for them to finish."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.debug("[bus] Stopped")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def subscribe(self, topic: str, handler: MessageHandler) -> None:
        """Register an async callback for every message on `topic`."""
        if topic not in self._subscribers:
            raise ValueError(f"Unknown topic '{topic}'. Valid: {Topic.ALL}")
        self._subscribers[topic].append(handler)

    async def publish(self, message: Message) -> None:
        """
        Publish a message to the bus.

        Steps:
          1. Increment Lamport clock and stamp the message.
          2. Assign a per-sender seq number (if the caller left it at 0).
          3. Deduplication check — drop silently if already seen.
          4. Enqueue onto the topic's FIFO queue.
        """
        if not self._running:
            raise RuntimeError("Call await bus.start() before publishing.")

        # 1. Lamport clock — increment on every send
        self._lamport += 1
        message.lamport_ts = self._lamport

        # 2. Assign seq if caller didn't set one
        if message.seq == 0:
            n = self._sender_seq.get(message.sender, 0) + 1
            self._sender_seq[message.sender] = n
            message.seq = n

        # 3. Deduplication
        key = (message.sender, message.seq)
        if key in self._seen:
            self.dropped_count += 1
            logger.debug("[bus] Dropped duplicate %s", key)
            return
        self._seen.add(key)

        # 4. Validate topic and enqueue
        if message.topic not in self._queues:
            logger.warning(
                "[bus] Unknown topic '%s' from %s — message dropped",
                message.topic, message.sender,
            )
            return

        await self._queues[message.topic].put(message)
        self.published_count += 1
        logger.debug("[bus] Published %r", message)

    def stats(self) -> dict:
        return {
            "published":   self.published_count,
            "delivered":   self.delivered_count,
            "dropped":     self.dropped_count,
            "lamport_now": self._lamport,
            "senders":     len(self._sender_seq),
        }

    # ------------------------------------------------------------------
    # Internal delivery loop
    # ------------------------------------------------------------------

    async def _delivery_loop(self, topic: str) -> None:
        """
        Drain the topic queue and call every subscriber in order.
        Uses a 100 ms timeout so the loop can notice _running=False promptly.
        """
        queue    = self._queues[topic]
        handlers = self._subscribers[topic]

        while self._running:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=0.1)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            # Update Lamport clock on receive (SDD §3.1.3, rule 1)
            self._lamport = max(self._lamport, message.lamport_ts) + 1

            for handler in handlers:
                try:
                    await handler(message)
                    self.delivered_count += 1
                except Exception as exc:
                    logger.error(
                        "[bus] Handler error on topic '%s': %s", topic, exc
                    )
