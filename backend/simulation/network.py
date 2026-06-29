from dataclasses import dataclass
from simulation.hosts import HostRegistry
from core.models import Host, TrafficPattern


@dataclass
class NetworkSegment:
    segment_id: str
    display_name: str
    ip_range: str           # CIDR /24
    baseline_mean: float    # packets/sec under normal load
    baseline_std: float     # natural pps variation
    description: str = ""

    @property
    def ip_base(self) -> str:
        """First three octets, e.g. '10.0.1'."""
        return ".".join(self.ip_range.split("/")[0].split(".")[:3])


class NetworkTopology:
    """
    Four-segment corporate network (SRS §2).

    Exposes both segment metadata and the HostRegistry so that any
    component (traffic generator, agents) can look up hosts and
    traffic patterns through a single object.
    """

    def __init__(self) -> None:
        self._segments: dict[str, NetworkSegment] = {}
        self.registry  = HostRegistry()
        self._build()

    # ------------------------------------------------------------------
    # Segment access
    # ------------------------------------------------------------------

    def get(self, segment_id: str) -> NetworkSegment:
        return self._segments[segment_id]

    def all(self) -> list[NetworkSegment]:
        return list(self._segments.values())

    def segment_ids(self) -> list[str]:
        return list(self._segments.keys())

    # ------------------------------------------------------------------
    # Host / pattern access (delegates to registry)
    # ------------------------------------------------------------------

    def hosts_in(self, segment_id: str) -> list[Host]:
        return self.registry.hosts_in(segment_id)

    def patterns_for(self, segment_id: str) -> list[TrafficPattern]:
        return self.registry.patterns_for(segment_id)

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def _build(self) -> None:
        for seg in [
            NetworkSegment(
                "public-facing", "Public-Facing Services",
                "172.16.0.0/24", 500.0, 75.0,
                "Web servers and APIs exposed to the internet",
            ),
            NetworkSegment(
                "server", "Server Zone",
                "10.0.2.0/24", 200.0, 30.0,
                "Internal databases and application servers",
            ),
            NetworkSegment(
                "internal", "Internal User Subnet",
                "10.0.1.0/24", 300.0, 55.0,
                "Employee workstations and user-facing services",
            ),
            NetworkSegment(
                "sec-mon", "Security Monitoring Zone",
                "10.0.3.0/24", 50.0, 8.0,
                "IDS, SIEM, and monitoring infrastructure",
            ),
        ]:
            self._segments[seg.segment_id] = seg
