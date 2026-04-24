"""Parser for Cisco IOS / IOS-XE / NX-OS configuration files.

Supports:
  - show running-config output  (has 'Building configuration...' header)
  - Saved startup-config files  (same format, no header)

Extracts one Host per routed interface (ip address configured, not shutdown).
All hosts from the same device share the device hostname and management
services deduced from the config (SSH / Telnet / SNMP / HTTP).

Also extracts VLAN membership:
  - VlanORM entries from the vlan name table (``vlan X / name Y`` blocks)
  - HostVlanORM SVI entries: each ``interface VlanX`` with an IP produces a
    direct host_ip → VLAN association (no MAC needed)
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

# VLAN name table (block style: "vlan 10\n name CORP")
_RE_VLAN_BLOCK = re.compile(r'^vlan\s+(\d+)\s*$', re.IGNORECASE)
_RE_VLAN_NAME  = re.compile(r'^\s+name\s+(.+)$', re.IGNORECASE)
# vlan database style: "vlan database\n vlan 10 name CORP"
_RE_VLAN_DB    = re.compile(r'^vlan\s+database\b', re.IGNORECASE)
_RE_VLAN_DB_LINE = re.compile(r'^\s+vlan\s+(\d+)\s+name\s+(.+)$', re.IGNORECASE)
# SVI interface name e.g. "Vlan10" → VLAN ID 10
_RE_CISCO_SVI  = re.compile(r'^[Vv]lan(\d+)$')


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
        if "Building configuration" in head or "Current configuration" in head:
            return True
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

        hosts, vlans, vlan_fdb = cls._parse_config(text, filepath.name)
        if not hosts:
            result.warnings.append(
                "No routed interfaces with IP addresses found in config"
            )
        result.hosts = hosts
        result.vlans = vlans
        result.vlan_fdb = vlan_fdb
        return result

    @classmethod
    def _parse_config(
        cls, text: str, source: str
    ) -> tuple[list[Host], list[dict], list[dict]]:
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

        # ── Line-by-line parser: interfaces + VLAN table ──────────────────
        interface_hosts: list[Host] = []
        vlan_names: dict[int, str] = {}   # vlan_id → name
        svi_map: dict[int, str] = {}      # vlan_id → SVI IP

        in_iface     = False
        in_vlan      = False
        in_vlan_db   = False
        iface_name   = ''
        iface_ip: str | None     = None
        iface_mask: str | None   = None
        iface_desc: str | None   = None
        iface_down   = False
        secondary_ips: list[tuple[str, str]] = []
        cur_vlan_id  = 0

        def _flush() -> None:
            nonlocal iface_ip, iface_mask, iface_desc, iface_down, secondary_ips
            if iface_ip and not iface_down:
                svi_m = _RE_CISCO_SVI.match(iface_name)
                if svi_m:
                    svi_map[int(svi_m.group(1))] = iface_ip
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
            stripped = line.strip()

            # Interface block detection takes priority
            iface_m = _RE_IFACE.match(line)
            if iface_m:
                if in_iface:
                    _flush()
                in_iface   = True
                in_vlan    = False
                in_vlan_db = False
                iface_name = iface_m.group(1)
                continue

            if in_iface:
                if line.startswith(' ') or line.startswith('\t'):
                    ip_m = _RE_IPADDR.match(line)
                    if ip_m:
                        if ip_m.group(3):
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
                else:
                    _flush()
                    in_iface = False
                    iface_name = ''
                continue

            # VLAN database section (legacy IOS)
            if _RE_VLAN_DB.match(line):
                in_vlan_db = True
                in_vlan    = False
                continue

            if in_vlan_db:
                if line.startswith(' ') or line.startswith('\t'):
                    db_m = _RE_VLAN_DB_LINE.match(line)
                    if db_m:
                        vlan_names[int(db_m.group(1))] = db_m.group(2).strip()
                else:
                    in_vlan_db = False
                continue

            # VLAN config block (IOS/NX-OS: "vlan 10 / name CORP")
            vlan_m = _RE_VLAN_BLOCK.match(line)
            if vlan_m:
                in_vlan    = True
                cur_vlan_id = int(vlan_m.group(1))
                continue

            if in_vlan:
                if line.startswith(' ') or line.startswith('\t'):
                    name_m = _RE_VLAN_NAME.match(line)
                    if name_m:
                        vlan_names[cur_vlan_id] = name_m.group(1).strip()
                else:
                    in_vlan = False

        if in_iface:
            _flush()

        # ── Build VLAN output ──────────────────────────────────────────────
        # switch_ip = VLAN-1 SVI (management), else lowest-ID SVI, else first host
        switch_ip: str | None = None
        if svi_map:
            switch_ip = svi_map.get(1) or svi_map[min(svi_map)]
        if not switch_ip and interface_hosts:
            switch_ip = interface_hosts[0].ip

        vlans: list[dict] = []
        vlan_fdb: list[dict] = []
        if switch_ip:
            seen_vids: set[int] = set()
            for vid, name in vlan_names.items():
                vlans.append({"switch_ip": switch_ip, "vlan_id": vid,
                              "vlan_name": name})
                seen_vids.add(vid)
            for vid, svi_ip in svi_map.items():
                if vid not in seen_vids:
                    vlans.append({"switch_ip": switch_ip, "vlan_id": vid,
                                  "vlan_name": f"VLAN {vid}"})
                vlan_fdb.append({"switch_ip": switch_ip, "vlan_id": vid,
                                 "host_ip": svi_ip})

        return interface_hosts, vlans, vlan_fdb


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
