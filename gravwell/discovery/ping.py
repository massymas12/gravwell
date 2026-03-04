"""ICMP ping sweep — subprocess-based, cross-platform, no extra deps."""
from __future__ import annotations
import ipaddress
import platform
import subprocess
import concurrent.futures
from gravwell.models.dataclasses import Host


def ping_sweep(
    network: str,
    max_workers: int = 64,
    timeout_ms: int = 800,
) -> list[Host]:
    """Return a Host for every IP in *network* that responds to ping.

    Works on Windows and POSIX without extra dependencies.
    Refuses to scan ranges larger than /16 (65 534 hosts) to prevent accidents.
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid network: {e}") from e

    if net.num_addresses > 65536:
        raise ValueError(
            f"Network {network} is too large ({net.num_addresses} addresses). "
            "Limit to /16 or smaller."
        )

    ips = [str(ip) for ip in net.hosts()]
    live: list[Host] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_ping_one, ip, timeout_ms): ip for ip in ips}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    live.append(Host(
                        ip=ip,
                        status="up",
                        source_files=["discovery:ping"],
                    ))
            except Exception:
                pass

    return live


def _ping_one(ip: str, timeout_ms: int) -> bool:
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_s = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout_s + 2
                           if "windows" not in system else timeout_ms / 1000 + 2)
        return r.returncode == 0
    except Exception:
        return False
