"""UDP probe sweep — detect hosts by eliciting application-layer responses.

Unlike TCP connect-scan, UDP probes reveal hosts that pass specific UDP traffic
through firewalls (e.g. DNS/NTP allowed, TCP blocked).

Three probes are used — all operate at the application layer so no raw sockets
or elevated privileges are required:

  dns   — DNS A-query to port 53 (most environments allow DNS out)
  ntp   — NTP mode-3 client request to port 123
  snmp  — SNMP v1 GetRequest for sysDescr.0 to port 161

Response semantics
------------------
  "open"         → got an application-level reply (port is listening)
  "icmp_unreach" → ICMP port unreachable received (host alive, port closed)
                   On Linux this is surfaced as ConnectionRefusedError.
                   On Windows as OSError errno 10054 (WSAECONNRESET).
  "timeout"      → no response (filtered or host down)
"""
from __future__ import annotations

import concurrent.futures
import socket

from gravwell.models.dataclasses import Host, Service


# ── Probe payloads ─────────────────────────────────────────────────────────────

# DNS query: TXID=0x0001, RD=1, one question for "version.bind." IN CH TXT
# Using CHAOS class avoids recursive-resolver overhead on most devices.
_DNS_QUERY = (
    b"\x00\x01"                      # TXID
    b"\x01\x00"                      # Flags: standard query, RD=1
    b"\x00\x01"                      # QDCOUNT=1
    b"\x00\x00"                      # ANCOUNT=0
    b"\x00\x00"                      # NSCOUNT=0
    b"\x00\x00"                      # ARCOUNT=0
    b"\x07version\x04bind\x00"       # QNAME
    b"\x00\x10"                      # QTYPE  TXT
    b"\x00\x03"                      # QCLASS CH (CHAOS)
)

# NTP mode-3 (client) minimal 48-byte packet — LI=0, VN=3, Mode=3
_NTP_QUERY = b"\x1b" + b"\x00" * 47

# SNMP v1 GetRequest for sysDescr.0 OID (1.3.6.1.2.1.1.1.0)
# Community: "public" — we only need any valid response to confirm liveness.
_SNMP_GET = bytes([
    0x30, 0x26,                                     # SEQUENCE, length 38
    0x02, 0x01, 0x00,                               # INTEGER version = 0 (v1)
    0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # OCTET STRING "public"
    0xa0, 0x19,                                     # GetRequest-PDU, length 25
    0x02, 0x01, 0x01,                               # INTEGER request-id = 1
    0x02, 0x01, 0x00,                               # INTEGER error-status = 0
    0x02, 0x01, 0x00,                               # INTEGER error-index = 0
    0x30, 0x0e,                                     # SEQUENCE (VarBindList)
    0x30, 0x0c,                                     # SEQUENCE (VarBind)
    0x06, 0x08,                                     # OID sysDescr.0
    0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
    0x05, 0x00,                                     # NULL value
])

# probe_name → (port, payload, service_name)
_PROBES: dict[str, tuple[int, bytes, str]] = {
    "dns":  (53,  _DNS_QUERY,  "dns"),
    "ntp":  (123, _NTP_QUERY,  "ntp"),
    "snmp": (161, _SNMP_GET,   "snmp"),
}

DEFAULT_UDP_PROBES: list[str] = ["dns", "ntp", "snmp"]


def udp_probe_sweep(
    ips: list[str],
    probes: list[str] | None = None,
    timeout: float = 2.0,
    max_workers: int = 128,
) -> list[Host]:
    """Probe *ips* with UDP packets on DNS/NTP/SNMP ports.

    Returns Host objects for every IP that:
    - responds at the application layer (port open/reply received), OR
    - returns ICMP port-unreachable (host alive, port just closed).

    Hosts discovered only via ICMP unreachable carry no open services but
    still contribute a discovery_score signal to confirm the host is alive.
    """
    if probes is None:
        probes = DEFAULT_UDP_PROBES

    # ip → {probe_name: outcome}
    probe_results: dict[str, dict[str, str]] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs: dict = {}
        for ip in ips:
            for probe_name in probes:
                if probe_name not in _PROBES:
                    continue
                port, payload, _ = _PROBES[probe_name]
                f = ex.submit(_udp_probe, ip, port, payload, timeout)
                futs[f] = (ip, probe_name)

        for fut in concurrent.futures.as_completed(futs):
            ip, probe_name = futs[fut]
            try:
                outcome = fut.result()
            except Exception:
                outcome = "timeout"
            if outcome in ("open", "icmp_unreach"):
                probe_results.setdefault(ip, {})[probe_name] = outcome

    hosts: list[Host] = []
    for ip, results in probe_results.items():
        svcs: list[Service] = []
        for probe_name, outcome in results.items():
            if outcome == "open":
                port, _, svc_name = _PROBES[probe_name]
                svcs.append(Service(
                    port=port,
                    protocol="udp",
                    state="open",
                    service_name=svc_name,
                ))
        hosts.append(Host(
            ip=ip,
            status="up",
            services=svcs,
            source_files=["discovery:udp"],
        ))

    return hosts


def _udp_probe(ip: str, port: int, payload: bytes, timeout: float) -> str:
    """Send a single UDP probe packet and classify the response.

    Returns "open", "icmp_unreach", or "timeout".
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        # connect() enables per-socket ICMP error delivery on most platforms
        sock.connect((ip, port))
        sock.send(payload)
        try:
            sock.recv(512)
            return "open"
        except ConnectionRefusedError:
            # Linux: ICMP port unreachable → host is alive, port closed
            return "icmp_unreach"
        except OSError as exc:
            # Windows: WSAECONNRESET (errno 10054) = ICMP port unreachable
            if getattr(exc, "winerror", None) == 10054 or \
               getattr(exc, "errno", None) == 10054:
                return "icmp_unreach"
            return "timeout"
        except socket.timeout:
            return "timeout"
    except Exception:
        return "timeout"
    finally:
        try:
            sock.close()
        except Exception:
            pass
