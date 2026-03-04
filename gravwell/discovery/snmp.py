"""Pure-Python SNMPv2c discovery — no external libraries required.

Implements just enough BER encoding/decoding to perform SNMP GET and
GETNEXT requests.  Retrieves:
    - sysDescr   (1.3.6.1.2.1.1.1.0)  → OS fingerprint
    - sysName    (1.3.6.1.2.1.1.5.0)  → hostname
    - ARP cache  (ipNetToMediaTable)   → hidden hosts behind routers
    - CDP neighbor table               → Cisco device topology
    - LLDP neighbor table              → 802.1ab device topology

All results are returned as Host/Service dataclass objects that plug
directly into the existing ingestion pipeline.
"""
from __future__ import annotations

import ipaddress
import socket
import struct
from gravwell.models.dataclasses import Host, Service
from gravwell.models.os_inference import infer_os, normalize_os_family, CONF_EXPLICIT_HIGH

# ── Well-known OIDs ───────────────────────────────────────────────────────────
_OID_SYS_DESCR  = "1.3.6.1.2.1.1.1.0"
_OID_SYS_NAME   = "1.3.6.1.2.1.1.5.0"

# ipNetToMediaTable — ARP cache visible to device
_OID_ARP_IP  = "1.3.6.1.2.1.4.22.1.3"  # ipNetToMediaNetAddress
_OID_ARP_MAC = "1.3.6.1.2.1.4.22.1.2"  # ipNetToMediaPhysAddress

# Cisco CDP neighbor table
_OID_CDP_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"  # cdpCacheDeviceId
_OID_CDP_ADDRESS   = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"  # cdpCacheAddress
_OID_CDP_PLATFORM  = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"  # cdpCachePlatform

# LLDP neighbor table (IEEE 802.1ab)
_OID_LLDP_CHASSIS = "1.0.8802.1.1.2.1.4.1.1.5"   # lldpRemChassisId
_OID_LLDP_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"   # lldpRemSysName
_OID_LLDP_SYSDESC = "1.0.8802.1.1.2.1.4.1.1.10"  # lldpRemSysDesc


# ── BER encoding helpers ──────────────────────────────────────────────────────

def _ber_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82, n >> 8, n & 0xFF])


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_length(len(value)) + value


def _encode_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".")]
    enc = bytearray([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        if n == 0:
            enc.append(0)
        else:
            chunks: list[int] = []
            while n:
                chunks.append(n & 0x7F)
                n >>= 7
            chunks.reverse()
            for i, chunk in enumerate(chunks):
                enc.append(chunk | (0x80 if i < len(chunks) - 1 else 0))
    return _ber_tlv(0x06, bytes(enc))


def _build_get(community: str, oids: list[str], request_id: int = 1) -> bytes:
    varbinds = b"".join(
        _ber_tlv(0x30, _encode_oid(oid) + b"\x05\x00")
        for oid in oids
    )
    pdu = _ber_tlv(
        0xA0,  # GetRequest-PDU
        _ber_tlv(0x02, request_id.to_bytes(4, "big"))
        + _ber_tlv(0x02, b"\x00")   # error-status
        + _ber_tlv(0x02, b"\x00")   # error-index
        + _ber_tlv(0x30, varbinds),
    )
    return _ber_tlv(
        0x30,
        _ber_tlv(0x02, b"\x01")           # version 1 = SNMPv2c
        + _ber_tlv(0x04, community.encode())
        + pdu,
    )


def _build_getnext(community: str, oid: str, request_id: int = 1) -> bytes:
    """Build a GETNEXT PDU for table walking."""
    varbind = _ber_tlv(0x30, _encode_oid(oid) + b"\x05\x00")
    pdu = _ber_tlv(
        0xA1,  # GetNextRequest-PDU
        _ber_tlv(0x02, request_id.to_bytes(4, "big"))
        + _ber_tlv(0x02, b"\x00")
        + _ber_tlv(0x02, b"\x00")
        + _ber_tlv(0x30, varbind),
    )
    return _ber_tlv(
        0x30,
        _ber_tlv(0x02, b"\x01")
        + _ber_tlv(0x04, community.encode())
        + pdu,
    )


# ── BER decoding helpers ──────────────────────────────────────────────────────

def _read_length(data: bytes, pos: int) -> tuple[int, int]:
    """Return (length, new_pos)."""
    b = data[pos]
    if b < 0x80:
        return b, pos + 1
    n = b & 0x7F
    return int.from_bytes(data[pos + 1: pos + 1 + n], "big"), pos + 1 + n


def _decode_oid(data: bytes) -> str:
    """Decode a BER-encoded OID value (without the tag/length prefix)."""
    if not data:
        return ""
    parts = [data[0] // 40, data[0] % 40]
    i, cur = 1, 0
    while i < len(data):
        b = data[i]
        cur = (cur << 7) | (b & 0x7F)
        if b & 0x80 == 0:
            parts.append(cur)
            cur = 0
        i += 1
    return ".".join(str(p) for p in parts)


def _parse_varbinds(data: bytes) -> list[tuple[str, bytes, int]]:
    """Walk a BER blob and yield (oid_str, raw_value, value_tag) tuples.

    Does a loose scan — skips unknown tags and length errors gracefully.
    """
    results: list[tuple[str, bytes, int]] = []
    i = 0

    def _scan(buf: bytes) -> None:
        j = 0
        while j < len(buf) - 2:
            tag = buf[j]
            try:
                length, offset = _read_length(buf, j + 1)
            except (IndexError, ValueError):
                break
            value = buf[offset: offset + length]

            if tag == 0x30:              # SEQUENCE — recurse
                _scan(value)
            elif tag == 0x06:            # OID
                oid_str = _decode_oid(value)
                # Peek at the next TLV — that's the value
                nj = offset + length
                if nj < len(buf) - 1:
                    val_tag = buf[nj]
                    try:
                        val_len, val_off = _read_length(buf, nj + 1)
                        val_data = buf[val_off: val_off + val_len]
                        results.append((oid_str, val_data, val_tag))
                    except (IndexError, ValueError):
                        pass

            j = offset + length

    _scan(data)
    return results


def _udp_exchange(
    ip: str,
    port: int,
    payload: bytes,
    timeout: float,
) -> bytes | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (ip, port))
        data, _ = sock.recvfrom(8192)
        return data
    except Exception:
        return None
    finally:
        sock.close()


# ── Public API ────────────────────────────────────────────────────────────────

def snmp_get_host(
    ip: str,
    community: str = "public",
    port: int = 161,
    timeout: float = 2.0,
) -> Host | None:
    """Query sysDescr + sysName from a single host. Returns None on failure."""
    pdu = _build_get(community, [_OID_SYS_DESCR, _OID_SYS_NAME])
    resp = _udp_exchange(ip, port, pdu, timeout)
    if not resp:
        return None

    varbinds = _parse_varbinds(resp)
    sys_descr = ""
    sys_name  = ""

    for oid, val, tag in varbinds:
        if tag == 0x04:  # OCTET STRING
            text = val.decode("latin-1", errors="replace").strip()
            if _OID_SYS_DESCR.split(".")[:-1][-1] in oid.split(".")[-3:]:
                sys_descr = text
            elif _OID_SYS_NAME.split(".")[:-1][-1] in oid.split(".")[-3:]:
                sys_name = text

    # Fallback: first two long strings found
    strings = [(oid, val.decode("latin-1", errors="replace").strip(), tag)
               for oid, val, tag in varbinds if tag == 0x04]
    if not sys_descr and len(strings) >= 1:
        sys_descr = strings[0][1]
    if not sys_name and len(strings) >= 2:
        sys_name  = strings[1][1]

    if not sys_descr and not sys_name:
        # Got a response but couldn't parse strings — still mark host as up
        h = Host(ip=ip, status="up", source_files=["discovery:snmp"])
        h.services.append(Service(port=161, protocol="udp", state="open",
                                   service_name="snmp"))
        return h

    os_family = normalize_os_family(sys_descr)
    os_name, os_family, conf = infer_os(
        [],
        [],
        None,
        explicit_os_name=sys_descr[:200] if sys_descr else None,
        explicit_os_family=os_family if os_family != "Unknown" else None,
        explicit_confidence=CONF_EXPLICIT_HIGH if sys_descr else 0,
    )
    h = Host(
        ip=ip,
        os_name=os_name,
        os_family=os_family or "Unknown",
        os_confidence=conf,
        status="up",
        source_files=["discovery:snmp"],
    )
    if sys_name:
        h.hostnames = [sys_name]
    h.services.append(Service(port=161, protocol="udp", state="open",
                               service_name="snmp"))
    return h


def snmp_walk_arp_cache(
    ip: str,
    community: str = "public",
    port: int = 161,
    timeout: float = 2.0,
    max_entries: int = 1024,
) -> list[Host]:
    """Walk a device's ARP cache via SNMP.  Discovers hosts the device can reach.

    Queries ipNetToMediaNetAddress — the IP-address column of the ARP table.
    Returns a Host for each discovered entry (IP only; no services).
    """
    discovered: list[str] = []
    current_oid = _OID_ARP_IP
    req_id = 100

    for _ in range(max_entries):
        pdu = _build_getnext(community, current_oid, req_id)
        req_id += 1
        resp = _udp_exchange(ip, port, pdu, timeout)
        if not resp:
            break

        varbinds = _parse_varbinds(resp)
        if not varbinds:
            break

        oid, val, tag = varbinds[0]
        # Stop when we've walked past the ARP table
        if not oid.startswith(_OID_ARP_IP.rsplit(".", 1)[0]):
            break

        if tag == 0x40:  # IpAddress
            try:
                discovered.append(socket.inet_ntoa(val))
            except Exception:
                pass
        elif tag == 0x04 and len(val) == 4:  # OCTET STRING encoding of IP
            try:
                discovered.append(socket.inet_ntoa(val))
            except Exception:
                pass

        current_oid = oid

    return [
        Host(ip=discovered_ip, status="up", source_files=["discovery:snmp_arp"])
        for discovered_ip in discovered
        if _is_valid_unicast(discovered_ip)
    ]


def snmp_walk_cdp(
    ip: str,
    community: str = "public",
    port: int = 161,
    timeout: float = 2.0,
    max_entries: int = 256,
) -> list[Host]:
    """Walk Cisco CDP neighbor table.  Returns discovered neighbor hosts."""
    neighbors: dict[str, dict] = {}
    req_id = 200

    for oid_base, field in (
        (_OID_CDP_DEVICE_ID, "name"),
        (_OID_CDP_ADDRESS, "ip"),
        (_OID_CDP_PLATFORM, "platform"),
    ):
        current_oid = oid_base
        for _ in range(max_entries):
            pdu = _build_getnext(community, current_oid, req_id)
            req_id += 1
            resp = _udp_exchange(ip, port, pdu, timeout)
            if not resp:
                break
            varbinds = _parse_varbinds(resp)
            if not varbinds:
                break

            oid, val, tag = varbinds[0]
            if not oid.startswith(oid_base.rsplit(".", 2)[0]):
                break

            # Use the OID suffix as a neighbor key (local port + index)
            key = oid[len(oid_base):]
            if field == "ip" and len(val) >= 4:
                try:
                    # CDP address format: type (1 byte) + length (1 byte) + addr
                    offset = 0 if len(val) == 4 else 2
                    neighbors.setdefault(key, {})["ip"] = socket.inet_ntoa(
                        val[offset: offset + 4]
                    )
                except Exception:
                    pass
            elif tag == 0x04:
                neighbors.setdefault(key, {})[field] = val.decode(
                    "latin-1", errors="replace"
                ).strip()

            current_oid = oid

    hosts: list[Host] = []
    for info in neighbors.values():
        neighbor_ip = info.get("ip")
        if not neighbor_ip or not _is_valid_unicast(neighbor_ip):
            continue
        platform = info.get("platform", "")
        name     = info.get("name", "")
        os_name  = f"Cisco {platform}".strip() if platform else "Cisco IOS"
        h = Host(
            ip=neighbor_ip,
            os_name=os_name,
            os_family="Network",
            os_confidence=85,
            status="up",
            source_files=["discovery:cdp"],
            tags=["cdp-neighbor"],
        )
        if name:
            h.hostnames = [name]
        h.services.append(
            Service(port=161, protocol="udp", state="open", service_name="snmp")
        )
        hosts.append(h)

    return hosts


def snmp_walk_lldp(
    ip: str,
    community: str = "public",
    port: int = 161,
    timeout: float = 2.0,
    max_entries: int = 256,
) -> list[Host]:
    """Walk LLDP neighbor table (IEEE 802.1ab).  Returns discovered neighbors."""
    neighbors: dict[str, dict] = {}
    req_id = 300

    for oid_base, field in (
        (_OID_LLDP_CHASSIS, "chassis"),
        (_OID_LLDP_SYSNAME, "name"),
        (_OID_LLDP_SYSDESC, "desc"),
    ):
        current_oid = oid_base
        for _ in range(max_entries):
            pdu = _build_getnext(community, current_oid, req_id)
            req_id += 1
            resp = _udp_exchange(ip, port, pdu, timeout)
            if not resp:
                break
            varbinds = _parse_varbinds(resp)
            if not varbinds:
                break

            oid, val, tag = varbinds[0]
            if not oid.startswith(oid_base.rsplit(".", 2)[0]):
                break

            key = oid[len(oid_base):]
            if tag == 0x04:
                neighbors.setdefault(key, {})[field] = val.decode(
                    "latin-1", errors="replace"
                ).strip()
            current_oid = oid

    hosts: list[Host] = []
    for info in neighbors.values():
        desc  = info.get("desc", "")
        name  = info.get("name", "")
        chassis = info.get("chassis", "")

        # LLDP doesn't directly give us an IP; we use chassis ID when it's an IP
        ip_candidate = _extract_ip(chassis)
        if not ip_candidate:
            continue

        os_family = normalize_os_family(desc)
        h = Host(
            ip=ip_candidate,
            os_name=desc[:200] if desc else None,
            os_family=os_family,
            os_confidence=65,
            status="up",
            source_files=["discovery:lldp"],
            tags=["lldp-neighbor"],
        )
        if name:
            h.hostnames = [name]
        hosts.append(h)

    return hosts


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_valid_unicast(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (addr.is_multicast or addr.is_loopback
                    or addr.is_link_local or addr.is_unspecified)
    except ValueError:
        return False


def _extract_ip(text: str) -> str | None:
    """Try to parse *text* as an IPv4 address or extract one from it."""
    import re
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", text)
    if m:
        try:
            ipaddress.ip_address(m.group())
            return m.group()
        except ValueError:
            pass
    return None
