"""TCP connect scan — stdlib only, no raw sockets or root required."""
from __future__ import annotations
import socket
import concurrent.futures
from gravwell.models.dataclasses import Host, Service
from gravwell.models.os_inference import infer_os

# Common ports likely to be open on active hosts
DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    389, 443, 445, 1433, 1521, 3306, 3389,
    5432, 5900, 5985, 8080, 8443,
]

_PORT_SERVICE: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds",
    1433: "ms-sql-s", 1521: "oracle", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 5985: "winrm", 8080: "http-alt", 8443: "https-alt",
}


def tcp_scan(
    ips: list[str],
    ports: list[int] | None = None,
    timeout: float = 1.0,
    max_workers: int = 256,
) -> list[Host]:
    """Connect-scan *ips* on *ports*.  Returns Host objects with open services."""
    if ports is None:
        ports = DEFAULT_PORTS

    open_ports: dict[str, list[int]] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_try_connect, ip, port, timeout): (ip, port)
            for ip in ips
            for port in ports
        }
        for fut in concurrent.futures.as_completed(futures):
            ip, port = futures[fut]
            try:
                if fut.result():
                    open_ports.setdefault(ip, []).append(port)
            except Exception:
                pass

    hosts: list[Host] = []
    for ip, p_list in open_ports.items():
        svcs = [
            Service(
                port=p,
                protocol="tcp",
                state="open",
                service_name=_PORT_SERVICE.get(p),
            )
            for p in sorted(p_list)
        ]
        os_name, os_family, conf = infer_os(svcs, [], None)
        hosts.append(Host(
            ip=ip,
            services=svcs,
            os_name=os_name,
            os_family=os_family or "Unknown",
            os_confidence=conf,
            status="up",
            source_files=["discovery:tcp"],
        ))

    return hosts


def _try_connect(ip: str, port: int, timeout: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        return sock.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        sock.close()
