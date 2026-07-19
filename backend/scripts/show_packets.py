"""
Show Packets
============
Generates and displays sample packets from each segment so you can
see what a packet looks like inside the simulation.

    python show_packets.py
"""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from simulation.clock import SimClock
from simulation.network import NetworkTopology
from simulation.traffic import TrafficGenerator

PACKETS_PER_SEGMENT = 8


def main() -> None:
    clock    = SimClock()
    topology = NetworkTopology()
    gen      = TrafficGenerator(topology, clock, rng_seed=42)

    print("=" * 78)
    print("  Sample Packets — what moves inside each segment")
    print("=" * 78)

    for seg in topology.all():
        packets = gen.generate_packets(seg, PACKETS_PER_SEGMENT)

        print(f"\n  [{seg.display_name}]  {seg.ip_range}")
        print(f"  {'#':<3} {'Source IP':<18} {'Destination IP':<18} "
              f"{'Port':<6} {'Proto':<5} {'Size':>6}  What is this?")
        print("  " + "-" * 74)

        for i, p in enumerate(packets, 1):
            # Look up what host owns the destination IP
            dst_host = topology.registry.get_host(p.dst_ip)
            src_host = topology.registry.get_host(p.src_ip)

            dst_name = dst_host.hostname if dst_host else "?"
            src_name = src_host.hostname if src_host else "internet"

            # Find which service name matches the port
            svc_name = ""
            if dst_host:
                for svc in dst_host.services:
                    if svc.port == p.dst_port:
                        svc_name = svc.name
                        break

            description = f"{src_name} -> {dst_name}:{svc_name or p.dst_port}"

            print(
                f"  {i:<3} {p.src_ip:<18} {p.dst_ip:<18} "
                f"{p.dst_port:<6} {p.protocol:<5} {p.pkt_size:>5}b  "
                f"{description}"
            )

    print()
    print("=" * 78)
    print("  What each field means:")
    print("  Source IP      — where the packet came from")
    print("  Destination IP — where it is going")
    print("  Port           — which service/door it is knocking on")
    print("  Proto          — TCP (connection-based) or UDP (fire-and-forget)")
    print("  Size           — how large the packet is in bytes (64-1500)")
    print("=" * 78)


if __name__ == "__main__":
    main()
