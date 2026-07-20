"""
AgentSupervisor
================
Minimal liveness watchdog: polls a set of registered agents and, when one
stops unexpectedly, builds and starts a replacement via its factory.

This is the one real failure-detection + reassignment mechanism in the
codebase — everywhere else (e.g. the old Scenario 5 "reassigned within 2s"
check), a validation harness manually stopped an agent and manually built
its replacement, which can't help but pass. Here the supervisor itself
notices the failure (by polling BaseAgent.is_running) and does the
reassignment, with no harness involvement.

Detection is polling-based because BaseAgent.stop() doesn't emit any signal
a supervisor could otherwise listen for (see agents/base.py) — nothing in
this cooperative asyncio system crashes on its own; "failure" here means an
agent's is_running flipped to False while the supervisor is still watching it.
"""
from __future__ import annotations
import asyncio
import time
from typing import Callable


class AgentSupervisor:

    def __init__(self, poll_interval: float = 0.05) -> None:
        self._poll_interval = poll_interval
        self._watched: dict[str, dict] = {}   # role -> {"agent": obj, "factory": callable}
        self._task: asyncio.Task | None = None
        self.events: list[dict] = []

    def watch(self, role: str, agent, factory: Callable[[], object]) -> None:
        """Register `agent` under `role`; if it's found stopped during a
        poll, `factory()` is called to build its replacement, which is
        then started and takes over the same role."""
        self._watched[role] = {"agent": agent, "factory": factory}

    def current(self, role: str):
        return self._watched[role]["agent"]

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def _loop(self) -> None:
        while True:
            for role, entry in list(self._watched.items()):
                agent = entry["agent"]
                if not agent.is_running:
                    t0        = time.monotonic()
                    new_agent = entry["factory"]()
                    await new_agent.start()
                    reassign_ms = (time.monotonic() - t0) * 1000
                    self._watched[role]["agent"] = new_agent
                    self.events.append({
                        "role":        role,
                        "old_id":      agent.agent_id,
                        "new_id":      new_agent.agent_id,
                        "reassign_ms": round(reassign_ms, 2),
                    })
            await asyncio.sleep(self._poll_interval)
