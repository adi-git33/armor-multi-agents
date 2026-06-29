"""
Host Registry
=============
Defines every named host in the simulated network and the traffic patterns
that describe normal communication between them.

Traffic patterns have a `weight` that controls how often that type of
connection appears in a packet sample.  Weights are relative (not
percentages); they are normalised to probabilities inside TrafficGenerator.
"""

import numpy as np

from core.models import Host, Service, TrafficPattern, INTERNET, ANY_INTERNAL


class HostRegistry:
    """
    Single source of truth for hosts and inter-host traffic patterns.

    Segments and their hosts
    ─────────────────────────────────────────────────────────────────────
    public-facing  172.16.0.0/24   lb-01, web-01, web-02, api-01
    server         10.0.2.0/24     app-01, app-02, db-primary,
                                   db-replica, cache-01
    internal       10.0.1.0/24     dc-01, fileserver-01,
                                   workstation-01..05, laptop-01..02
    sec-mon        10.0.3.0/24     siem-01, ids-01, log-collector
    """

    def __init__(self) -> None:
        self._hosts: list[Host] = []
        self._by_ip: dict[str, Host] = {}
        self._patterns: dict[str, list[TrafficPattern]] = {}
        self._build()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def all_hosts(self) -> list[Host]:
        return list(self._hosts)

    def hosts_in(self, segment_id: str) -> list[Host]:
        return [h for h in self._hosts if h.segment_id == segment_id]

    def get_host(self, ip: str) -> Host | None:
        return self._by_ip.get(ip)

    def patterns_for(self, segment_id: str) -> list[TrafficPattern]:
        return self._patterns.get(segment_id, [])

    def resolve_src_ip(self, src: str, rng: np.random.Generator) -> str:
        """
        Turn a sentinel source value into a concrete IP address.

        INTERNET     → a random public IP (first octet 1-99)
        ANY_INTERNAL → a random IP chosen from all non-sec-mon hosts
                       (used for syslog / IPFIX flows that come from
                       every segment)
        anything else → returned unchanged (it's already a real IP)
        """
        if src == INTERNET:
            return (
                f"{int(rng.integers(1, 100))}."
                f"{int(rng.integers(0, 256))}."
                f"{int(rng.integers(0, 256))}."
                f"{int(rng.integers(1, 254))}"
            )
        if src == ANY_INTERNAL:
            candidates = [
                h.ip for h in self._hosts if h.segment_id != "sec-mon"
            ]
            return candidates[int(rng.integers(len(candidates)))]
        return src

    # ------------------------------------------------------------------
    # Build helpers
    # ------------------------------------------------------------------

    def _add(self, host: Host) -> Host:
        self._hosts.append(host)
        self._by_ip[host.ip] = host
        return host

    def _build(self) -> None:
        self._build_public_facing()
        self._build_server_zone()
        self._build_internal()
        self._build_sec_mon()

    # --- Public-Facing Services (172.16.0.0/24) -----------------------

    def _build_public_facing(self) -> None:
        lb = self._add(Host(
            "lb-01", "172.16.0.2", "public-facing", "load-balancer",
            "Linux Ubuntu 22.04",
            [Service(80, "HTTP"), Service(443, "HTTPS")],
            "HAProxy load balancer — internet entry point",
        ))
        w1 = self._add(Host(
            "web-01", "172.16.0.10", "public-facing", "web-server",
            "Linux Ubuntu 22.04",
            [Service(80, "HTTP"), Service(443, "HTTPS")],
            "Nginx web server (primary)",
        ))
        w2 = self._add(Host(
            "web-02", "172.16.0.11", "public-facing", "web-server",
            "Linux Ubuntu 22.04",
            [Service(80, "HTTP"), Service(443, "HTTPS")],
            "Nginx web server (secondary)",
        ))
        api = self._add(Host(
            "api-01", "172.16.0.20", "public-facing", "api-server",
            "Linux Ubuntu 22.04",
            [Service(8080, "HTTP-API"), Service(8443, "HTTPS-API")],
            "REST API gateway",
        ))

        self._patterns["public-facing"] = [
            TrafficPattern(INTERNET, lb.ip,  443, "TCP", "HTTPS ingress",    40.0),
            TrafficPattern(INTERNET, lb.ip,   80, "TCP", "HTTP ingress",     12.0),
            TrafficPattern(lb.ip,    w1.ip,   80, "TCP", "LB -> web-01",     18.0),
            TrafficPattern(lb.ip,    w2.ip,   80, "TCP", "LB -> web-02",     18.0),
            TrafficPattern(w1.ip,    api.ip, 8080, "TCP", "web-01 -> API",    6.0),
            TrafficPattern(w2.ip,    api.ip, 8080, "TCP", "web-02 -> API",    6.0),
        ]

    # --- Server Zone (10.0.2.0/24) ------------------------------------

    def _build_server_zone(self) -> None:
        app1 = self._add(Host(
            "app-01", "10.0.2.10", "server", "app-server",
            "Linux Ubuntu 22.04",
            [Service(8080, "HTTP-APP")],
            "Application server (primary)",
        ))
        app2 = self._add(Host(
            "app-02", "10.0.2.11", "server", "app-server",
            "Linux Ubuntu 22.04",
            [Service(8080, "HTTP-APP")],
            "Application server (secondary)",
        ))
        dbp = self._add(Host(
            "db-primary", "10.0.2.20", "server", "database",
            "Linux Ubuntu 22.04",
            [Service(5432, "PostgreSQL")],
            "PostgreSQL primary (read-write)",
        ))
        dbr = self._add(Host(
            "db-replica", "10.0.2.21", "server", "database",
            "Linux Ubuntu 22.04",
            [Service(5432, "PostgreSQL")],
            "PostgreSQL replica (read-only)",
        ))
        cache = self._add(Host(
            "cache-01", "10.0.2.30", "server", "cache",
            "Linux Ubuntu 22.04",
            [Service(6379, "Redis")],
            "Redis in-memory cache",
        ))

        self._patterns["server"] = [
            TrafficPattern(app1.ip, dbp.ip,   5432, "TCP", "app-01 -> DB write",   28.0),
            TrafficPattern(app2.ip, dbp.ip,   5432, "TCP", "app-02 -> DB write",   28.0),
            TrafficPattern(app1.ip, cache.ip, 6379, "TCP", "app-01 -> Cache",      14.0),
            TrafficPattern(app2.ip, cache.ip, 6379, "TCP", "app-02 -> Cache",      14.0),
            TrafficPattern(dbp.ip,  dbr.ip,   5432, "TCP", "DB replication",        8.0),
            TrafficPattern(app1.ip, dbr.ip,   5432, "TCP", "app-01 -> DB read",     4.0),
            TrafficPattern(app2.ip, dbr.ip,   5432, "TCP", "app-02 -> DB read",     4.0),
        ]

    # --- Internal User Subnet (10.0.1.0/24) --------------------------

    def _build_internal(self) -> None:
        dc = self._add(Host(
            "dc-01", "10.0.1.2", "internal", "domain-controller",
            "Windows Server 2022",
            [Service(389, "LDAP"), Service(88, "Kerberos"), Service(445, "SMB")],
            "Active Directory domain controller",
        ))
        fs = self._add(Host(
            "fileserver-01", "10.0.1.3", "internal", "file-server",
            "Windows Server 2022",
            [Service(445, "SMB"), Service(2049, "NFS", "TCP")],
            "Corporate file server",
        ))

        workstations: list[Host] = []
        for i in range(1, 6):
            ws = self._add(Host(
                f"workstation-0{i}", f"10.0.1.{9 + i}", "internal",
                "workstation", "Windows 11",
                [Service(3389, "RDP")],
                f"Employee workstation {i}",
            ))
            workstations.append(ws)

        laptops: list[Host] = []
        for i in range(1, 3):
            lp = self._add(Host(
                f"laptop-0{i}", f"10.0.1.{19 + i}", "internal",
                "laptop", "Windows 11",
                [Service(3389, "RDP")],
                f"Employee laptop {i}",
            ))
            laptops.append(lp)

        patterns: list[TrafficPattern] = []
        for ws in workstations:
            patterns += [
                TrafficPattern(ws.ip, dc.ip, 389, "TCP", f"{ws.hostname} -> DC LDAP",       4.0),
                TrafficPattern(ws.ip, dc.ip,  88, "TCP", f"{ws.hostname} -> DC Kerberos",   3.0),
                TrafficPattern(ws.ip, fs.ip, 445, "TCP", f"{ws.hostname} -> FS SMB",        3.5),
            ]
        for lp in laptops:
            patterns += [
                TrafficPattern(lp.ip, dc.ip, 389, "TCP", f"{lp.hostname} -> DC LDAP",      3.0),
                TrafficPattern(lp.ip, fs.ip, 445, "TCP", f"{lp.hostname} -> FS SMB",       3.0),
            ]
        # Occasional lateral peer-to-peer (small weight — will look suspicious)
        for ws in workstations[:3]:
            peer = workstations[-1]
            patterns.append(
                TrafficPattern(ws.ip, peer.ip, 445, "TCP", f"{ws.hostname} -> peer SMB",   0.5)
            )

        self._patterns["internal"] = patterns

    # --- Security Monitoring Zone (10.0.3.0/24) ----------------------

    def _build_sec_mon(self) -> None:
        siem = self._add(Host(
            "siem-01", "10.0.3.2", "sec-mon", "siem",
            "Linux Ubuntu 22.04",
            [Service(9200, "Elasticsearch"), Service(5601, "Kibana")],
            "SIEM — centralised security event correlation",
        ))
        ids = self._add(Host(
            "ids-01", "10.0.3.3", "sec-mon", "ids-sensor",
            "Linux Ubuntu 22.04",
            [Service(514, "Syslog", "UDP")],
            "Intrusion Detection System sensor",
        ))
        logc = self._add(Host(
            "log-collector", "10.0.3.4", "sec-mon", "log-collector",
            "Linux Ubuntu 22.04",
            [Service(514, "Syslog", "UDP"), Service(4739, "IPFIX", "UDP")],
            "Centralised log and network-flow collector",
        ))

        self._patterns["sec-mon"] = [
            TrafficPattern(ANY_INTERNAL, logc.ip, 514,  "UDP", "Any host -> syslog",          35.0),
            TrafficPattern(ANY_INTERNAL, logc.ip, 4739, "UDP", "Any host -> IPFIX flows",     15.0),
            TrafficPattern(logc.ip,      siem.ip, 9200, "TCP", "log-collector -> ES ingest",  25.0),
            TrafficPattern(ids.ip,       siem.ip, 9200, "TCP", "IDS -> ES alerts",            15.0),
            TrafficPattern(siem.ip,      siem.ip, 5601, "TCP", "Kibana dashboard polling",    10.0),
        ]
