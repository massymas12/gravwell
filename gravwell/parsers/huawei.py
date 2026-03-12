"""Parser for Huawei VRP (Versatile Routing Platform) configuration files.

Supports:
  - ``display current-configuration`` output
  - Saved configuration files (same VRP text format)

Extracts one Host per routed interface (ip address configured, not shutdown).
All hosts from the same device share the device sysname and management
services deduced from the config (SSH / Telnet / SNMP / HTTP / NETCONF).

Key VRP format signals:
  - ``sysname <name>``                   — device hostname
  - ``Huawei`` / ``VRP`` in file header  — vendor header
  - ``interface GigabitEthernet0/0/0``   — Huawei interface naming
  - ``undo shutdown``                    — interface is up (Huawei negation)
"""
from __future__ import annotations
import re
import ipaddress
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, ParseResult
from gravwell.parsers.base import BaseParser

_RE_SYSNAME  = re.compile(r'^sysname\s+(\S+)', re.IGNORECASE | re.MULTILINE)
_RE_VERSION  = re.compile(r'VRP.*?V(\S+)', re.IGNORECASE)
_RE_IFACE    = re.compile(r'^interface\s+(\S+)', re.IGNORECASE)
_RE_IPADDR   = re.compile(
    r'^\s+ip address\s+([\d.]+)\s+([\d.]+)(\s+sub)?', re.IGNORECASE
)
_RE_DESC     = re.compile(r'^\s+description\s+(.+)$')
_RE_SHUTDOWN = re.compile(r'^\s+shutdown\s*$', re.IGNORECASE)

# Huawei interface prefixes (used in can_parse detection)
_HUAWEI_IFACES = re.compile(
    r'^interface\s+(?:GigabitEthernet|XGigabitEthernet|100GE|40GE|25GE|10GE'
    r'|Ethernet|FastEthernet|Vlanif|LoopBack|MEth|Tunnel'
    r'|Pos|Serial|Atm|Mp-group)',
    re.IGNORECASE | re.MULTILINE,
)


class HuaweiParser(BaseParser):
    name = "huawei"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath, 1024)
        # Strongest signal: Huawei/VRP vendor header
        if re.search(r'Huawei|Versatile Routing Platform', head, re.IGNORECASE):
            return True
        # sysname + a Huawei interface type
        if re.search(r'^sysname\s+', head, re.IGNORECASE | re.MULTILINE):
            if _HUAWEI_IFACES.search(head):
                return True
        # undo-based config lines (Huawei-exclusive negation syntax)
        if re.search(r'^undo\s+', head, re.IGNORECASE | re.MULTILINE):
            if _HUAWEI_IFACES.search(head):
                return True
        return False

    @classmethod
    def parse(cls, filepath: Path) -> ParseResult:
        result = ParseResult(source_file=str(filepath), parser_name=cls.name)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                text = fh.read()
        except OSError as e:
            result.errors.append(f"File read error: {e}")
            return result

        hosts = cls._parse_config(text, filepath.name)
        if not hosts:
            result.warnings.append(
                "No routed interfaces with IP addresses found in Huawei config"
            )
        result.hosts = hosts
        return result

    @classmethod
    def _parse_config(cls, text: str, source: str) -> list[Host]:
        # ── Global device info ─────────────────────────────────────────────
        hm = _RE_SYSNAME.search(text)
        device_name = hm.group(1) if hm else None

        vm = _RE_VERSION.search(text)
        version = vm.group(1) if vm else None
        os_name = f"Huawei VRP{' V' + version if version else ''}"

        # ── Management services ────────────────────────────────────────────
        svc_tpl: list[Service] = []
        # SSH: stelnet server enable / ssh server enable
        if re.search(r'stelnet server enable|ssh server enable',
                     text, re.IGNORECASE):
            svc_tpl.append(Service(
                port=22, protocol='tcp', state='open',
                service_name='ssh', product='Huawei SSH',
            ))
        # Telnet: user-interface vty with protocol inbound telnet
        if re.search(r'protocol inbound telnet', text, re.IGNORECASE):
            svc_tpl.append(Service(
                port=23, protocol='tcp', state='open',
                service_name='telnet', product='Huawei Telnet',
            ))
        # SNMP
        if re.search(r'^snmp-agent\b', text, re.IGNORECASE | re.MULTILINE):
            svc_tpl.append(Service(
                port=161, protocol='udp', state='open',
                service_name='snmp', product='Huawei SNMP',
            ))
        # HTTP management
        if re.search(r'^http server enable\b', text, re.IGNORECASE | re.MULTILINE):
            svc_tpl.append(Service(
                port=80, protocol='tcp', state='open',
                service_name='http', product='Huawei HTTP',
            ))
        # HTTPS management
        if re.search(r'^http secure-server enable\b',
                     text, re.IGNORECASE | re.MULTILINE):
            svc_tpl.append(Service(
                port=443, protocol='tcp', state='open',
                service_name='https', product='Huawei HTTPS',
            ))
        # NETCONF
        if re.search(r'^netconf\b', text, re.IGNORECASE | re.MULTILINE):
            svc_tpl.append(Service(
                port=830, protocol='tcp', state='open',
                service_name='netconf', product='Huawei NETCONF',
            ))

        # Default: SSH if nothing else detected
        if not svc_tpl:
            svc_tpl.append(Service(
                port=22, protocol='tcp', state='open',
                service_name='ssh', product='Huawei SSH',
            ))

        # ── Interface block parser ─────────────────────────────────────────
        interface_hosts: list[Host] = []
        seen: set[str] = set()

        in_iface    = False
        iface_name  = ''
        iface_ip: str | None   = None
        iface_mask: str | None = None
        iface_desc: str | None = None
        iface_down  = False
        secondary_ips: list[tuple[str, str]] = []

        def _flush() -> None:
            nonlocal iface_ip, iface_mask, iface_desc, iface_down, secondary_ips
            if iface_ip and not iface_down and iface_ip not in seen:
                seen.add(iface_ip)
                interface_hosts.append(_make_host(
                    ip=iface_ip, mask=iface_mask, iface_name=iface_name,
                    iface_desc=iface_desc, device_name=device_name,
                    os_name=os_name, services=list(svc_tpl), source=source,
                ))
                for sec_ip, sec_mask in secondary_ips:
                    if sec_ip not in seen:
                        seen.add(sec_ip)
                        interface_hosts.append(_make_host(
                            ip=sec_ip, mask=sec_mask, iface_name=iface_name,
                            iface_desc=iface_desc, device_name=device_name,
                            os_name=os_name, services=list(svc_tpl),
                            source=source,
                        ))
            iface_ip = iface_mask = iface_desc = None
            iface_down = False
            secondary_ips = []

        for line in text.splitlines():
            iface_m = _RE_IFACE.match(line)
            if iface_m:
                if in_iface:
                    _flush()
                in_iface   = True
                iface_name = iface_m.group(1)
                continue

            if in_iface and line.startswith(' '):
                ip_m = _RE_IPADDR.match(line)
                if ip_m:
                    if ip_m.group(3):           # secondary ("sub") address
                        secondary_ips.append((ip_m.group(1), ip_m.group(2)))
                    else:
                        iface_ip   = ip_m.group(1)
                        iface_mask = ip_m.group(2)
                elif _RE_DESC.match(line):
                    iface_desc = _RE_DESC.match(line).group(1).strip()
                elif _RE_SHUTDOWN.match(line):
                    iface_down = True
                # "undo shutdown" means up — no action needed (default is up)
            elif in_iface and (line.startswith('#') or not line.startswith(' ')):
                _flush()
                in_iface   = False
                iface_name = ''

        if in_iface:
            _flush()

        return interface_hosts


def _make_host(
    ip: str,
    mask: str | None,
    iface_name: str,
    iface_desc: str | None,
    device_name: str | None,
    os_name: str,
    services: list[Service],
    source: str,
) -> Host:
    tags = [f"huawei-interface:{iface_name}"]
    if device_name:
        tags.append(f"huawei-device:{device_name}")
    if iface_desc:
        tags.append(f"description:{iface_desc}")

    return Host(
        ip=ip,
        hostnames=[device_name] if device_name else [],
        os_name=os_name,
        os_family="Network",
        mac_vendor="Huawei",
        status="up",
        services=services,
        tags=tags,
        source_files=[source],
    )
