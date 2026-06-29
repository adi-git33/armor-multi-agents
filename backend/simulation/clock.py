import asyncio
import time


class SimClock:
    """
    Wraps wall time with an optional speed multiplier.
    speed=1.0  → real time
    speed=2.0  → simulation runs at 2× real time
    """

    def __init__(self, speed: float = 1.0):
        if speed <= 0:
            raise ValueError("speed must be positive")
        self._speed = speed
        self._start_wall = time.monotonic()
        self._start_sim = 0.0

    @property
    def now(self) -> float:
        elapsed_wall = time.monotonic() - self._start_wall
        return self._start_sim + elapsed_wall * self._speed

    @property
    def speed(self) -> float:
        return self._speed

    async def sleep(self, sim_seconds: float):
        """Sleep for sim_seconds of simulation time (adjusted for speed)."""
        await asyncio.sleep(sim_seconds / self._speed)
