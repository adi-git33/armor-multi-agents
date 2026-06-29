from dataclasses import dataclass, field
import time

# Sentinel source IPs used in TrafficPattern definitions
INTERNET     = "INTERNET"       # traffic originating from the public internet
ANY_INTERNAL = "ANY_INTERNAL"   # any internal host (used for log/syslog flows)


@dataclass
class Service:
    port: int
    name: str               # e.g. "HTTPS", "PostgreSQL"
    protocol: str = "TCP"


@dataclass
class Host:
    hostname: str
    ip: str
    segment_id: str
    role: str               # e.g. "web-server", "database", "workstation"
    os: str                 # e.g. "Linux Ubuntu 22.04", "Windows 11"
    services: list[Service]
    description: str = ""


@dataclass
class TrafficPattern:
    src_ip: str             # real IP, INTERNET, or ANY_INTERNAL
    dst_ip: str             # real IP of destination host
    dst_port: int
    protocol: str
    label: str              # human-readable, e.g. "HTTPS ingress"
    weight: float           # relative frequency (unnormalised)


@dataclass
class Packet:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    pkt_size: int           # bytes
    segment: str
    label: str = ""         # traffic pattern label, set when pattern-based
    timestamp: float = field(default_factory=time.monotonic)


@dataclass
class TrafficSample:
    segment: str
    packets_per_sec: float
    packet_count: int       # int(pps * sample_interval)
    timestamp: float = field(default_factory=time.monotonic)


@dataclass
class SegmentStats:
    segment: str
    current_pps: float
    baseline_mean: float
    baseline_std: float
    deviation: float        # signed, in standard deviations
    sample_count: int
    timestamp: float = field(default_factory=time.monotonic)
