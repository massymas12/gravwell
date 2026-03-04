"""Parser for Cisco IOS / IOS-XE / NX-OS configuration files.

Supports:
  - show running-config output  (has 'Building configuration...' header)
  - Saved startup-config files  (same format, no header)

Extracts one Host per routed interface (ip address configured, not shutdown).
All hosts from the same device share the device hostname and management
services deduced from the config (SSH / Telnet / SNMP / HTTP).
"""
from __future__ import annotations
import re
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, ParseResult
from gravwell.parsers.base import BaseParser

_RE_HOSTNAME = re.compile(r'^hostname\s+(\S+)', re.IGNORECASE | re.MULTILINE)
_RE_VERSION  = re.compile(r'^version\s+([\d.()\w]+)', re.IGNORECASE | re.MULTILINE)
_RE_IFACE    = re.compile(r'^interface\s+(\S+)', re.IGNORECASE)
_RE_IPADDR   = re.compile(
    r'^\s+ip address\s+([\d.]+)\s+([\d.]+)(\s+secondary)?', re.IGNORECASE
)
_RE_DESC     = re.compile(r'^\s+description\s+(.+)$')
_RE_SHUTDOWN = re.compile(r'^\s+shutdown\s*$')
_RE_NO_IP    = re.compile(r'^\s+no ip address\s*$', re.IGNORECASE)


def _mask_to_prefix(mask: str) -> int:
    try:
        return sum(bin(int(o)).count('1') for o in mask.split('.'))
    except (ValueError, AttributeError):
        return 24


class CiscoParser(BaseParser):
    name = "cisco"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath, 512)
        # Strongest signal: Cisco show running-config output
        if "Building configuration" in head or "Current configuration" in head:
            return True
        # Saved config: hostname + a Cisco interface type present
        if "hostname " in head and re.search(
            r'^interface\s+(?:GigabitEthernet|FastEthernet|TenGigabit'
            r'|HundredGigE|Serial|Loopback|Vlan|Ethernet|Tunnel|Port-channel)',
            head, re.IGNORECASE | re.MULTILINE,
        ):
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
                "No routed interfaces with IP addresses found in config"
            )
        result.hosts = hosts
        return result

    @classmethod
    def _parse_config(cls, text: str, source: str) -> list[Host]:
        # ── Global device info ─────────────────────────────────────────────
        hm = _RE_HOSTNAME.search(text)
        device_name = hm.group(1) if hm else None

        vm = _RE_VERSION.search(text)
        ver = vm.group(1) if vm else None

        if re.search(r'NX-OS', text):
            os_name = f"Cisco NX-OS{' ' + ver if ver else ''}"
        elif re.search(r'IOS-XE', text, re.IGNORECASE):
            os_name = f"Cisco IOS-XE{' ' + ver if ver else ''}"
        else:
            os_name = f"Cisco IOS{' ' + ver if ver else ''}"

        # ── Management services ────────────────────────────────────────────
        svc_tpl: list[Service] = []
        if (re.search(r'^ip ssh version', text, re.IGNORECASE | re.MULTILINE)
                or re.search(r'transport input\s+(?:ssh|all)', text, re.IGNORECASE)):
            svc_tpl.append(Service(
                port=22, protocol='tcp', state='open',
                service_name='ssh', product='Cisco SSH',
            ))
        if re.search(r'transport input\s+(?:telnet|all)', text, re.IGNORECASE):
            svc_tpl.append(Service(
                port=23, protocol='tcp', state='open',
                service_name='telnet', product='Cisco Telnet',
            ))
        if re.search(r'^snmp-server', text, re.IGNORECASE | re.MULTILINE):
            svc_tpl.append(Service(
                port=161, protocol='udp', state='open',
                service_name='snmp', product='Cisco SNMP',
            ))
        if re.search(r'^ip http server\b', text, re.IGNORECASE | re.MULTILINE):
            svc_tpl.append(Service(
                port=80, protocol='tcp', state='open',
                service_name='http', product='Cisco HTTP',
            ))
        if re.search(r'^ip http secure-server\b', text, re.IGNORECASE | re.MULTILINE):
            svc_tpl.append(Service(
                port=443, protocol='tcp', state='open',
                service_name='https', product='Cisco HTTPS',
            ))

        # ── Interface block parser ─────────────────────────────────────────
        interface_hosts: list[Host] = []

        # mutable state for current interface block
        in_iface     = False
        iface_name   = ''
        iface_ip: str | None     = None
        iface_mask: str | None   = None
        iface_desc: str | None   = None
        iface_down   = False
        secondary_ips: list[tuple[str, str]] = []

        def _flush() -> None:
            nonlocal iface_ip, iface_mask, iface_desc, iface_down, secondary_ips
            if iface_ip and not iface_down:
                interface_hosts.append(_make_host(
                    ip=iface_ip, mask=iface_mask, iface_name=iface_name,
                    iface_desc=iface_desc, device_name=device_name,
                    os_name=os_name, services=list(svc_tpl), source=source,
                ))
                for sec_ip, sec_mask in secondary_ips:
                    interface_hosts.append(_make_host(
                        ip=sec_ip, mask=sec_mask, iface_name=iface_name,
                        iface_desc=iface_desc, device_name=device_name,
                        os_name=os_name, services=list(svc_tpl), source=source,
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
                    if ip_m.group(3):               # secondary address
                        secondary_ips.append((ip_m.group(1), ip_m.group(2)))
                    else:
                        iface_ip   = ip_m.group(1)
                        iface_mask = ip_m.group(2)
                elif _RE_NO_IP.match(line):
                    iface_ip = None
                elif _RE_DESC.match(line):
                    iface_desc = _RE_DESC.match(line).group(1).strip()
                elif _RE_SHUTDOWN.match(line):
                    iface_down = True
            elif in_iface:
                # Non-indented line (including '!') ends the block
                _flush()
                in_iface = False
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
    tags = [f"cisco-interface:{iface_name}"]
    if device_name:
        tags.append(f"cisco-device:{device_name}")
    if iface_desc:
        tags.append(f"description:{iface_desc}")

    return Host(
        ip=ip,
        hostnames=[device_name] if device_name else [],
        os_name=os_name,
        os_family="Network",
        mac_vendor="Cisco",
        status="up",
        services=services,
        tags=tags,
        source_files=[source],
    )
