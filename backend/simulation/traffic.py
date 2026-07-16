import asyncio
from collections import deque
from typing import Callable, Awaitable

import numpy as np

from core.models import Packet, TrafficSample, SegmentStats
from simulation.clock import SimClock
from simulation.network import NetworkSegment, NetworkTopology

# FR-01: sample at minimum 10 times per second
SAMPLE_RATE = 10          # Hz
SAMPLE_INTERVAL = 1.0 / SAMPLE_RATE   # seconds between samples

# FR-04: baseline window = 60 seconds of samples
BASELINE_WINDOW = SAMPLE_RATE * 60    # 600 samples

# Minimum samples before get_stats() reports a real deviation — see the
# warmup guard in get_stats(). 30 samples = 3 s at the 10 Hz sample rate.
MIN_BASELINE_SAMPLES = 30


SampleCallback = Callable[[TrafficSample], Awaitable[None]]


class TrafficGenerator:
    """
    Generates synthetic network traffic for all four segments.

    Each segment runs its own async loop emitting one TrafficSample
    every SAMPLE_INTERVAL seconds.  Registered callbacks receive every
    sample, allowing agents (in later parts) to subscribe.

    The pps value is drawn from N(baseline_mean, baseline_std²) and
    clamped to ≥ 0.  A rolling window of the last 60 s is maintained
    per segment so agents can query live baseline statistics.
    """

    def __init__(
        self,
        topology: NetworkTopology,
        clock: SimClock,
        rng_seed: int = 42,
    ):
        self._topology = topology
        self._clock = clock
        self._rng = np.random.default_rng(rng_seed)
        self._running = False

        # Rolling pps window per segment (maxlen = BASELINE_WINDOW)
        self._windows: dict[str, deque[float]] = {
            sid: deque(maxlen=BASELINE_WINDOW)
            for sid in topology.segment_ids()
        }

        self._callbacks: list[SampleCallback] = []

        # Segments cut off by RCA — no pps, overlay, or packets flow
        # through a quarantined segment until it's released.
        self._quarantined: set[str] = set()

        # Attack overlays: {segment_id: {attacker_id: extra_pps}}
        # Multiple attackers can target the same segment; their pps stacks.
        self._attack_overlays: dict[str, dict[str, float]] = {
            sid: {} for sid in topology.segment_ids()
        }

        # Attack packet buffer: attackers deposit individual Packet objects here
        # so the TMA can inspect packet-level details (e.g. port diversity).
        # Drained by the TMA on every sample tick — not a persistent log.
        self._attack_packets: dict[str, list] = {
            sid: [] for sid in topology.segment_ids()
        }

        # Separate, non-destructive mirror of the same deposits — for
        # observers (e.g. the visualization layer) that must not compete
        # with the TMA's own drain_attack_packets() consumption above.
        self._attack_packets_peek: dict[str, list] = {
            sid: [] for sid in topology.segment_ids()
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def topology(self) -> NetworkTopology:
        return self._topology

    def quarantine(self, segment_id: str) -> None:
        """Cut a segment off from the network: the broadcast pps (and every
        derived display/packet feed) drops to 0 while quarantined. The
        rolling stats window keeps recording real underlying traffic the
        whole time — like a SPAN port that mirrors the wire regardless of
        an ACL drop — so get_stats() stays an accurate, real-time read of
        whether the segment is still under attack. That's what lets a
        caller (RCA's auto-release check) poll "has this gone quiet yet?"
        while still blocked, instead of only finding out after unblocking."""
        self._quarantined.add(segment_id)

    def unquarantine(self, segment_id: str) -> None:
        """Restore normal traffic flow to a previously quarantined segment."""
        self._quarantined.discard(segment_id)

    def add_attack_traffic(
        self, segment_id: str, attacker_id: str, extra_pps: float
    ) -> None:
        """Called by an attacker to inject extra pps into a segment."""
        self._attack_overlays[segment_id][attacker_id] = extra_pps

    def clear_attack_traffic(self, segment_id: str, attacker_id: str) -> None:
        """Called by an attacker when it stops or pauses."""
        self._attack_overlays[segment_id].pop(attacker_id, None)

    def get_attack_pps(self, segment_id: str) -> float:
        """Total extra pps currently injected into a segment by all attackers."""
        if segment_id in self._quarantined:
            return 0.0
        return sum(self._attack_overlays[segment_id].values())

    def add_attack_packets(self, segment_id: str, packets: list) -> None:
        """Attackers call this to deposit individual probe packets for TMA inspection."""
        self._attack_packets[segment_id].extend(packets)
        self._attack_packets_peek[segment_id].extend(packets)

    def drain_attack_packets(self, segment_id: str) -> list:
        """TMA calls this each tick to collect and clear new attack packets."""
        packets = self._attack_packets[segment_id][:]
        self._attack_packets[segment_id].clear()
        return [] if segment_id in self._quarantined else packets

    def peek_attack_packets(self, segment_id: str) -> list:
        """
        Non-destructive-to-TMA read of recently deposited attack packets, for
        visualization/observer use. Each packet is returned exactly once —
        this call clears its own private mirror, but never touches the
        buffer drain_attack_packets() draws from.
        """
        packets = self._attack_packets_peek[segment_id][:]
        self._attack_packets_peek[segment_id].clear()
        return [] if segment_id in self._quarantined else packets

    def on_sample(self, cb: SampleCallback) -> None:
        """Register an async callback invoked on every new TrafficSample."""
        self._callbacks.append(cb)

    def get_stats(self, segment_id: str) -> SegmentStats:
        """
        Return rolling statistics for a segment.

        The current (most recent) pps is excluded from the mean/std
        calculation so the baseline reflects historical normal, not
        the instant being evaluated.
        """
        seg = self._topology.get(segment_id)
        window = self._windows[segment_id]

        # A tiny window can't support a real baseline: with a handful of
        # samples std collapses toward the 1.0-pps div-by-zero guard below
        # (real segment stds are 8-75 pps), so the very first readings
        # produce absurd "+100σ" deviations that every downstream consumer
        # (TMA alerts, ACA's 30 s max-deviation feature, the dashboard
        # health badge) treats as a monster attack. Until the window holds
        # MIN_BASELINE_SAMPLES, report the configured design baseline with
        # deviation 0 — "no reading yet", same contract as an empty window.
        if len(window) < MIN_BASELINE_SAMPLES:
            return SegmentStats(
                segment=segment_id,
                current_pps=seg.baseline_mean,
                baseline_mean=seg.baseline_mean,
                baseline_std=seg.baseline_std,
                deviation=0.0,
                sample_count=len(window),
                timestamp=self._clock.now,
            )

        arr     = np.array(window)
        current = float(arr[-1])
        history = arr[:-1]

        # Use the OLDEST 50 % of the history for baseline so that a recent
        # attack cannot quickly poison the mean and std.  In a 60-second
        # window an attack must run for > 30 s before the baseline shifts —
        # more than enough time for the TMA to detect and respond.
        cutoff       = max(10, len(history) // 2)
        clean        = history[:cutoff]
        mean         = float(np.mean(clean))
        std          = float(np.std(clean)) or 1.0   # guard div-by-zero

        return SegmentStats(
            segment      = segment_id,
            current_pps  = current,
            baseline_mean= mean,
            baseline_std = std,
            deviation    = (current - mean) / std,
            sample_count = len(window),
            timestamp    = self._clock.now,
        )

    def get_all_stats(self) -> dict[str, SegmentStats]:
        return {sid: self.get_stats(sid) for sid in self._topology.segment_ids()}

    async def run(self) -> None:
        self._running = True
        tasks = [
            asyncio.create_task(self._segment_loop(seg))
            for seg in self._topology.all()
        ]
        await asyncio.gather(*tasks)

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _segment_loop(self, seg: NetworkSegment) -> None:
        while self._running:
            overlay  = sum(self._attack_overlays[seg.segment_id].values())
            real_pps = self._draw_pps(seg) + overlay
            # Always record the real reading — see quarantine()'s docstring
            # for why the window must stay live even while blocked.
            self._windows[seg.segment_id].append(real_pps)

            quarantined = seg.segment_id in self._quarantined
            pps = 0.0 if quarantined else real_pps

            sample = TrafficSample(
                segment=seg.segment_id,
                packets_per_sec=pps,
                packet_count=max(0, int(round(pps * SAMPLE_INTERVAL))),
                timestamp=self._clock.now,
            )

            for cb in self._callbacks:
                await cb(sample)

            await asyncio.sleep(SAMPLE_INTERVAL)

    def _draw_pps(self, seg: NetworkSegment) -> float:
        """Sample pps from the segment's Gaussian baseline (clamped ≥ 0)."""
        pps = self._rng.normal(seg.baseline_mean, seg.baseline_std)
        return max(0.0, float(pps))

    def generate_packets(self, seg: NetworkSegment, count: int) -> list[Packet]:
        """
        Synthesise `count` Packet objects for a segment using the host
        registry traffic patterns.  Each packet reflects a real src/dst
        host pair and service port — used by agents from Part 2 onward.
        """
        if seg.segment_id in self._quarantined:
            return []

        patterns = self._topology.registry.patterns_for(seg.segment_id)
        if not patterns:
            return []

        weights = np.array([p.weight for p in patterns], dtype=float)
        weights /= weights.sum()

        indices = self._rng.choice(len(patterns), size=count, p=weights)
        packets = []
        for idx in indices:
            pattern = patterns[int(idx)]
            src_ip  = self._topology.registry.resolve_src_ip(pattern.src_ip, self._rng)
            packets.append(Packet(
                src_ip   = src_ip,
                dst_ip   = pattern.dst_ip,
                src_port = int(self._rng.integers(1024, 65535)),
                dst_port = pattern.dst_port,
                protocol = pattern.protocol,
                pkt_size = int(self._rng.integers(64, 1500)),
                segment  = seg.segment_id,
                label    = pattern.label,
                timestamp= self._clock.now,
            ))
        return packets
