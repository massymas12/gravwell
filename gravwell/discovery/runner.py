"""Discovery orchestrator — runs selected methods and returns a ParseResult."""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass, field
from gravwell.models.dataclasses import Host, ParseResult
from gravwell.models.ingestion import ingest_parse_result


@dataclass
class DiscoveryConfig:
    target: str                    # CIDR or single IP
    methods: list[str] = field(default_factory=lambda: ["ping", "arp", "tcp"])
    snmp_community: str = "public"
    snmp_port: int = 161
    snmp_timeout: float = 2.0
    # Additional communities to try (credential stuffing)
    snmp_communities: list[str] = field(default_factory=lambda: [
        "public", "private", "community", "snmp", "cisco", "manager",
    ])
    tcp_ports: list[int] | None = None  # None → use default port list
    ping_timeout_ms: int = 800
    max_workers: int = 64
    # Walk ARP/CDP/LLDP on discovered SNMP-enabled devices
    follow_snmp_neighbors: bool = True


@dataclass
class DiscoveryResult:
    hosts: list[Host] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    method_counts: dict[str, int] = field(default_factory=dict)

    def to_parse_result(self) -> ParseResult:
        pr = ParseResult(
            hosts=self.hosts,
            source_file="discovery",
            parser_name="discovery",
            warnings=self.warnings,
            errors=self.errors,
        )
        return pr


def discover(cfg: DiscoveryConfig) -> DiscoveryResult:
    """Run selected discovery methods against the target network.

    Returns a DiscoveryResult whose hosts can be ingested directly.
    """
    result = DiscoveryResult()
    merged: dict[str, Host] = {}

    def _add(h: Host) -> None:
        if h.ip in merged:
            _merge(merged[h.ip], h)
        else:
            merged[h.ip] = h

    def _merge(existing: Host, new: Host) -> None:
        """Merge new host data into existing host record."""
        # Hostnames union
        for hn in new.hostnames:
            if hn not in existing.hostnames:
                existing.hostnames.append(hn)
        # OS: keep higher confidence
        if (new.os_name and
                (not existing.os_name or new.os_confidence > existing.os_confidence)):
            existing.os_name = new.os_name
            existing.os_family = new.os_family
            existing.os_confidence = new.os_confidence
        # MAC
        if new.mac and not existing.mac:
            existing.mac = new.mac
            existing.mac_vendor = new.mac_vendor
        # Services union (by port+protocol)
        existing_keys = {(s.port, s.protocol) for s in existing.services}
        for svc in new.services:
            if (svc.port, svc.protocol) not in existing_keys:
                existing.services.append(svc)
        # Source files union
        for sf in new.source_files:
            if sf not in existing.source_files:
                existing.source_files.append(sf)
        # Tags union
        for t in new.tags:
            if t not in existing.tags:
                existing.tags.append(t)

    # ── Ping sweep ────────────────────────────────────────────────────────
    if "ping" in cfg.methods:
        try:
            from gravwell.discovery.ping import ping_sweep
            hosts = ping_sweep(cfg.target,
                               max_workers=cfg.max_workers,
                               timeout_ms=cfg.ping_timeout_ms)
            for h in hosts:
                _add(h)
            result.method_counts["ping"] = len(hosts)
        except Exception as e:
            result.warnings.append(f"Ping sweep error: {e}")

    # ── ARP table ─────────────────────────────────────────────────────────
    if "arp" in cfg.methods:
        try:
            from gravwell.discovery.arp import get_arp_hosts
            hosts = get_arp_hosts()
            # Filter to target network if a CIDR was given
            try:
                net = ipaddress.ip_network(cfg.target, strict=False)
                hosts = [h for h in hosts
                         if ipaddress.ip_address(h.ip) in net]
            except ValueError:
                pass
            for h in hosts:
                _add(h)
            result.method_counts["arp"] = len(hosts)
        except Exception as e:
            result.warnings.append(f"ARP table error: {e}")

    # ── TCP connect scan on live hosts ────────────────────────────────────
    if "tcp" in cfg.methods:
        try:
            from gravwell.discovery.tcp import tcp_scan
            ips = list(merged.keys()) if merged else _expand_target(cfg.target)
            hosts = tcp_scan(ips, ports=cfg.tcp_ports,
                             max_workers=cfg.max_workers)
            for h in hosts:
                _add(h)
            result.method_counts["tcp"] = len(hosts)
        except Exception as e:
            result.warnings.append(f"TCP scan error: {e}")

    # ── SNMP poll on live hosts ───────────────────────────────────────────
    snmp_hosts: list[Host] = []
    if "snmp" in cfg.methods:
        from gravwell.discovery.snmp import (
            snmp_get_host, snmp_walk_arp_cache,
            snmp_walk_cdp, snmp_walk_lldp,
        )
        import concurrent.futures
        ips = list(merged.keys()) if merged else _expand_target(cfg.target)
        communities = ([cfg.snmp_community]
                       if cfg.snmp_community != "public"
                       else cfg.snmp_communities)

        def _poll_snmp(ip: str) -> Host | None:
            for community in communities:
                h = snmp_get_host(ip, community,
                                  port=cfg.snmp_port,
                                  timeout=cfg.snmp_timeout)
                if h:
                    h._snmp_community = community  # stash for neighbor walk
                    return h
            return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(cfg.max_workers, 32)
        ) as ex:
            futures = {ex.submit(_poll_snmp, ip): ip for ip in ips}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    h = fut.result()
                    if h:
                        snmp_hosts.append(h)
                        _add(h)
                except Exception:
                    pass

        result.method_counts["snmp"] = len(snmp_hosts)

        # ── ARP cache walk via discovered SNMP devices ─────────────────
        if cfg.follow_snmp_neighbors and snmp_hosts:
            arp_found = 0
            cdp_found = 0
            lldp_found = 0
            for sh in snmp_hosts:
                comm = getattr(sh, "_snmp_community", cfg.snmp_community)

                arp_neighbors = snmp_walk_arp_cache(
                    sh.ip, comm, cfg.snmp_port, cfg.snmp_timeout
                )
                for h in arp_neighbors:
                    _add(h)
                arp_found += len(arp_neighbors)

                cdp_neighbors = snmp_walk_cdp(
                    sh.ip, comm, cfg.snmp_port, cfg.snmp_timeout
                )
                for h in cdp_neighbors:
                    _add(h)
                cdp_found += len(cdp_neighbors)

                lldp_neighbors = snmp_walk_lldp(
                    sh.ip, comm, cfg.snmp_port, cfg.snmp_timeout
                )
                for h in lldp_neighbors:
                    _add(h)
                lldp_found += len(lldp_neighbors)

            if arp_found:
                result.method_counts["snmp_arp"] = arp_found
            if cdp_found:
                result.method_counts["cdp"] = cdp_found
            if lldp_found:
                result.method_counts["lldp"] = lldp_found

    result.hosts = list(merged.values())
    return result


def _expand_target(target: str) -> list[str]:
    """Return all host addresses in *target* (single IP or CIDR)."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [target]
