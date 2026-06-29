"""
Attacker Agents  (SRS §3.2)
============================
Simulated adversaries that stress-test the defense system.
They inject extra traffic into segments via TrafficGenerator's
attack overlay mechanism — the normal baseline keeps running
underneath, so defenders see the combined picture.

Implemented:
  DDoSAttacker   — floods a segment at N× baseline, ramps gradually
  PortScanner    — low-volume structured port probing
"""

import asyncio
import time

import numpy as np

from core.models import Packet


class BaseAttacker:
    """
    Common interface for all attacker agents.

    Every action is recorded to action_log so the post-simulation
    constraint checker (SRS FR-27) can verify attack behaviour.
    """

    def __init__(
        self,
        attacker_id: str,
        target_segment: str,
        rng_seed: int = 99,
    ) -> None:
        self.attacker_id    = attacker_id
        self.target_segment = target_segment
        self._rng           = np.random.default_rng(rng_seed)
        self._running       = False
        self.action_log: list[dict] = []

    async def launch(self, duration: float) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        self._running = False

    def _record(self, action: str, **kwargs) -> None:
        self.action_log.append({
            "ts":       round(time.monotonic(), 3),
            "attacker": self.attacker_id,
            "segment":  self.target_segment,
            "action":   action,
            **kwargs,
        })

    def _random_public_ip(self) -> str:
        """Generate a random public IP to simulate a botnet source."""
        return (
            f"{int(self._rng.integers(1, 100))}."
            f"{int(self._rng.integers(0, 256))}."
            f"{int(self._rng.integers(0, 256))}."
            f"{int(self._rng.integers(1, 254))}"
        )


# ──────────────────────────────────────────────────────────────────────────────

class DDoSAttacker(BaseAttacker):
    """
    Simulates a volumetric DDoS attack (SRS §3.2, FR-24).

    Behaviour:
    - Ramps from 0 to peak_pps over `ramp_seconds` (gradual escalation)
    - Sustains peak traffic for the remainder of `duration`
    - Uses randomised source IPs every tick to mimic a botnet
    - Clears the overlay when the attack ends so traffic recovers

    Detection signal: pps deviation shoots well above +2σ within
    ramp_seconds and stays there until the attack stops.
    """

    def __init__(
        self,
        attacker_id: str,
        target_segment: str,
        generator,                          # TrafficGenerator
        intensity_multiplier: float = 10.0, # peak = baseline × this
        ramp_seconds: float = 5.0,
        rng_seed: int = 99,
    ) -> None:
        super().__init__(attacker_id, target_segment, rng_seed)
        self._gen        = generator
        self._multiplier = intensity_multiplier
        self._ramp       = ramp_seconds

    async def launch(self, duration: float) -> None:
        self._running = True
        baseline  = self._gen.topology.get(self.target_segment).baseline_mean
        peak_extra = baseline * (self._multiplier - 1.0)   # extra above normal

        self._record(
            "attack_start",
            baseline_pps = baseline,
            peak_pps     = baseline * self._multiplier,
            multiplier   = self._multiplier,
            duration_s   = duration,
        )

        start = time.monotonic()
        while self._running and (time.monotonic() - start) < duration:
            elapsed    = time.monotonic() - start
            ramp_ratio = min(1.0, elapsed / self._ramp)
            extra_pps  = peak_extra * ramp_ratio

            self._gen.add_attack_traffic(
                self.target_segment, self.attacker_id, extra_pps
            )
            self._record(
                "flood",
                elapsed_s  = round(elapsed, 2),
                extra_pps  = round(extra_pps, 1),
                ramp_ratio = round(ramp_ratio, 2),
                src_ip     = self._random_public_ip(),
            )
            await asyncio.sleep(0.1)

        self._gen.clear_attack_traffic(self.target_segment, self.attacker_id)
        self._record("attack_end", log_entries=len(self.action_log))
        self._running = False


# ──────────────────────────────────────────────────────────────────────────────

class PortScanner(BaseAttacker):
    """
    Simulates a systematic port scan (SRS §3.2, FR-25).

    Behaviour:
    - Probes ports in a pseudo-random order that varies per run
    - Sends a tiny burst (SYN-sized, 64 bytes) per port then pauses
    - Volume is deliberately low — it won't spike pps above 2σ alone
    - Detection signal is port diversity: one IP hitting many ports fast

    The ACA (Part 5) will classify this by seeing an unusual spread
    of destination ports from a single source IP.
    """

    # Representative set of ports a scanner would probe
    SCAN_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 993, 995, 1433, 1521, 3306, 3389,
        5432, 5900, 6379, 8080, 8443, 27017,
    ]

    def __init__(
        self,
        attacker_id: str,
        target_segment: str,
        generator,
        src_ip: str = "45.33.32.156",    # fixed scanner IP (easy to spot)
        burst_size: int = 3,             # packets sent per port probe
        probe_interval: float = 0.3,     # seconds between port probes;
                                         # raise to 0.7+ for stealthy scan
        rng_seed: int = 77,
    ) -> None:
        super().__init__(attacker_id, target_segment, rng_seed)
        self._gen            = generator
        self._src_ip         = src_ip
        self._burst_size     = burst_size
        self._probe_interval = probe_interval
        self.scanned_ports: list[int]    = []
        self.scan_packets: list[Packet]  = []

    async def launch(self, duration: float) -> None:
        self._running = True
        hosts      = self._gen.topology.hosts_in(self.target_segment)
        target_ips = [h.ip for h in hosts]

        # Shuffle port order each run (FR-25: vary across runs)
        ports = list(self.SCAN_PORTS)
        self._rng.shuffle(ports)

        self._record(
            "scan_start",
            src_ip     = self._src_ip,
            target_ips = target_ips,
            port_order = ports[:6],
        )

        start      = time.monotonic()
        port_index = 0

        while self._running and (time.monotonic() - start) < duration:
            port      = ports[port_index % len(ports)]
            dst_ip    = target_ips[int(self._rng.integers(len(target_ips)))]

            # Inject a micro-burst then immediately clear (stealthy pattern)
            self._gen.add_attack_traffic(
                self.target_segment, self.attacker_id, float(self._burst_size)
            )

            # Build the probe packet and deposit it into the generator's
            # attack packet buffer so the TMA can inspect port diversity.
            pkt = Packet(
                src_ip   = self._src_ip,
                dst_ip   = dst_ip,
                src_port = int(self._rng.integers(1024, 65535)),
                dst_port = port,
                protocol = "TCP",
                pkt_size = 64,
                segment  = self.target_segment,
                label    = f"scan-probe {self._src_ip} -> {dst_ip}:{port}",
            )
            self._gen.add_attack_packets(self.target_segment, [pkt])
            self.scan_packets.append(pkt)
            self.scanned_ports.append(port)

            self._record(
                "probe",
                dst_ip    = dst_ip,
                port      = port,
                elapsed_s = round(time.monotonic() - start, 2),
            )

            port_index += 1
            half = self._probe_interval / 2.0
            await asyncio.sleep(half)
            self._gen.clear_attack_traffic(self.target_segment, self.attacker_id)
            await asyncio.sleep(half)

        self._gen.clear_attack_traffic(self.target_segment, self.attacker_id)
        self._record(
            "scan_end",
            unique_ports = len(set(self.scanned_ports)),
            total_probes = len(self.scanned_ports),
        )
        self._running = False
