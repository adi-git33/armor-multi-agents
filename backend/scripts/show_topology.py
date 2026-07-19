"""
Show Topology
=============
Run this any time to inspect every segment, host, and traffic pattern
in the simulated network.

    python show_topology.py
"""

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

from simulation.network import NetworkTopology


def main() -> None:
    topology = NetworkTopology()

    print("=" * 78)
    print("  Cyber-Defense Prototype  |  Network Topology")
    print("=" * 78)

    for seg in topology.all():
        hosts    = topology.hosts_in(seg.segment_id)
        patterns = topology.patterns_for(seg.segment_id)
        total_w  = sum(p.weight for p in patterns) or 1.0

        print(f"\n{'─' * 78}")
        print(f"  SEGMENT : {seg.display_name}  ({seg.segment_id})")
        print(f"  Range   : {seg.ip_range}")
        print(f"  Baseline: {seg.baseline_mean:.0f} pps  +/- {seg.baseline_std:.0f}")
        print(f"  Info    : {seg.description}")

        # Hosts
        print(f"\n  Hosts ({len(hosts)}):")
        print(f"    {'Hostname':<18} {'IP':<16} {'Role':<20} {'OS':<26} Services")
        print(f"    {'.' * 74}")
        for h in hosts:
            svcs = "  ".join(f"{s.port}/{s.name}" for s in h.services)
            print(
                f"    {h.hostname:<18} {h.ip:<16} {h.role:<20} {h.os:<26} {svcs}"
            )

        # Traffic patterns
        if patterns:
            print(f"\n  Traffic Patterns ({len(patterns)}):")
            print(
                f"    {'Source':<20} {'Destination':<22} {'Proto':<6} "
                f"{'Label':<32} Freq"
            )
            print(f"    {'.' * 74}")
            for p in patterns:
                freq  = f"{p.weight / total_w * 100:.0f}%"
                dst   = f"{p.dst_ip}:{p.dst_port}"
                src   = p.src_ip  # INTERNET / ANY_INTERNAL / real IP
                print(
                    f"    {src:<20} {dst:<22} {p.protocol:<6} "
                    f"{p.label:<32} {freq:>4}"
                )

    print(f"\n{'─' * 78}")
    all_hosts = topology.registry.all_hosts()
    print(f"\n  Total hosts : {len(all_hosts)}")
    for sid in topology.segment_ids():
        n = len(topology.hosts_in(sid))
        print(f"    {sid:<20} {n} hosts")
    print()


if __name__ == "__main__":
    main()
