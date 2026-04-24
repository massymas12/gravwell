"""Parser for Juniper JunOS configuration files.

Supports two common output formats:
  - Set-format  (``show configuration | display set``)
  - Curly-brace format  (``show configuration``, the native text format)

Extracts one Host per interface unit that has an inet address configured.

Also extracts VLAN membership:
  - VlanORM entries from ``set vlans NAME vlan-id X`` (set) or
    ``vlans { NAME { vlan-id X; } }`` (curly)
  - HostVlanORM SVI entries from IRB interfaces: ``irb unit X`` = VLAN X
    (IRB = Integrated Routing and Bridging — Juniper's equivalent of a Cisco SVI)
"""
from __future__ import annotations
import re
import ipaddress
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, ParseResult
from gravwell.parsers.base import BaseParser


# ── Set-format patterns ───────────────────────────────────────────────────────
_RE_SET_HOSTNAME = re.compile(
    r'^set\s+system\s+host-name\s+(\S+)',
    re.IGNORECASE | re.MULTILINE,
)
_RE_SET_VERSION = re.compile(
    r'^set\s+version\s+(\S+)',
    re.IGNORECASE | re.MULTILINE,
)
_RE_SET_IFACE_IP = re.compile(
    r'^set\s+interfaces\s+(\S+)\s+unit\s+(\S+)\s+'
    r'family\s+inet\s+address\s+([\d.]+/[\d]+)',
    re.IGNORECASE | re.MULTILINE,
)
_RE_SET_MGMT_IP = re.compile(
    r'^set\s+system\s+(?:management-)?ethernet\s+.*?inet\s+([\d.]+/[\d]+)',
    re.IGNORECASE | re.MULTILINE,
)
# VLAN name table: "set vlans CORP-LAN vlan-id 10"
_RE_SET_VLAN = re.compile(
    r'^set\s+vlans\s+(\S+)\s+vlan-id\s+(\d+)',
    re.IGNORECASE | re.MULTILINE,
)

# ── Curly-brace format patterns ───────────────────────────────────────────────
_RE_CB_HOSTNAME = re.compile(r'host-name\s+(\S+)\s*;', re.IGNORECASE)
_RE_CB_VERSION  = re.compile(r'^\s*version\s+(\S+)\s*;', re.IGNORECASE | re.MULTILINE)
_RE_CB_ADDRESS  = re.compile(r'address\s+([\d.]+/\d+)\s*;', re.IGNORECASE)
# VLAN block inside vlans { NAME { vlan-id X; } }
_RE_CB_VLAN_NAME_BLOCK = re.compile(
    r'vlans\s*\{(.*?)\n\}',
    re.DOTALL | re.IGNORECASE,
)
_RE_CB_VLAN_ENTRY = re.compile(
    r'^\s+(\S+)\s*\{[^}]*?vlan-id\s+(\d+)\s*;',
    re.MULTILINE | re.DOTALL,
)

# Management services from JunOS config (set-format)
_RE_SET_SERVICES = re.compile(r'^set\s+system\s+services\s+(\S+)', re.IGNORECASE | re.MULTILINE)
_RE_SET_SNMP     = re.compile(r'^set\s+snmp\s+', re.IGNORECASE | re.MULTILINE)


def _is_set_format(text: str) -> bool:
    first_lines = '\n'.join(text.splitlines()[:30])
    return bool(re.search(r'^set\s+', first_lines, re.IGNORECASE | re.MULTILINE))


class JuniperParser(BaseParser):
    name = "juniper"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath, 1024)
        if re.search(r'^set\s+system\s+', head, re.IGNORECASE | re.MULTILINE):
            return True
        if re.search(r'## Last commit:', head):
            return True
        if re.search(r'^version\s+\d+\.\d+', head, re.IGNORECASE | re.MULTILINE):
            if 'interfaces' in head and 'system' in head:
                return True
        if re.search(r'\bge-\d+/\d+/\d+\b|\bxe-\d+/\d+/\d+\b|\bae\d+\b', head):
            if 'family inet' in head or 'unit 0' in head:
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
            result.warnings.append("No interface IP addresses found in Juniper config")
        result.hosts = hosts
        result.vlans = vlans
        result.vlan_fdb = vlan_fdb
        return result

    @classmethod
    def _parse_config(
        cls, text: str, source: str
    ) -> tuple[list[Host], list[dict], list[dict]]:
        if _is_set_format(text):
            return cls._parse_set(text, source)
        return cls._parse_curly(text, source)

    # ── Set-format ────────────────────────────────────────────────────────────

    @classmethod
    def _parse_set(
        cls, text: str, source: str
    ) -> tuple[list[Host], list[dict], list[dict]]:
        m = _RE_SET_HOSTNAME.search(text)
        device_name = m.group(1) if m else None

        vm = _RE_SET_VERSION.search(text)
        version = vm.group(1) if vm else ''
        os_name = f"Juniper JunOS {version}".strip()

        svcs = _build_services(text)
        hosts: list[Host] = []
        seen: set[str] = set()
        # IRB unit → SVI IP (unit number = VLAN ID on Juniper EX/QFX)
        irb_map: dict[int, str] = {}

        for m in _RE_SET_IFACE_IP.finditer(text):
            iface = m.group(1)
            unit  = m.group(2)
            cidr  = m.group(3)
            try:
                net = ipaddress.ip_interface(cidr)
                ip = str(net.ip)
            except ValueError:
                continue
            if ip in seen:
                continue
            seen.add(ip)
            iface_label = f"{iface}.{unit}"
            hosts.append(_make_host(
                ip=ip, iface_name=iface_label,
                device_name=device_name, os_name=os_name,
                services=list(svcs), source=source,
            ))
            # IRB interfaces: unit number is the VLAN ID
            if iface.lower() == 'irb':
                try:
                    irb_map[int(unit)] = ip
                except ValueError:
                    pass

        mgmt_m = _RE_SET_MGMT_IP.search(text)
        if mgmt_m:
            try:
                net = ipaddress.ip_interface(mgmt_m.group(1))
                mgmt_ip = str(net.ip)
                if mgmt_ip not in seen:
                    hosts.append(_make_host(
                        ip=mgmt_ip, iface_name='management',
                        device_name=device_name, os_name=os_name,
                        services=list(svcs), source=source,
                    ))
            except ValueError:
                pass

        # VLAN name table from set vlans
        vlan_names: dict[int, str] = {}
        for vm2 in _RE_SET_VLAN.finditer(text):
            name = vm2.group(1)
            vid = int(vm2.group(2))
            vlan_names[vid] = name

        vlans, vlan_fdb = _build_vlan_output(hosts, vlan_names, irb_map)
        return hosts, vlans, vlan_fdb

    # ── Curly-brace format ────────────────────────────────────────────────────

    @classmethod
    def _parse_curly(
        cls, text: str, source: str
    ) -> tuple[list[Host], list[dict], list[dict]]:
        hm = _RE_CB_HOSTNAME.search(text)
        device_name = hm.group(1) if hm else None

        vm = _RE_CB_VERSION.search(text)
        version = vm.group(1) if vm else ''
        os_name = f"Juniper JunOS {version}".strip()

        svcs = _build_services(text)
        hosts: list[Host] = []
        seen: set[str] = set()
        irb_map: dict[int, str] = {}

        iface_block_m = re.search(
            r'^interfaces\s*\{(.*?)^\}',
            text, re.MULTILINE | re.DOTALL,
        )
        if iface_block_m:
            block = iface_block_m.group(1)
            current_iface = None
            current_unit: str | None = None
            for line in block.splitlines():
                iface_m = re.match(r'^\s{4}(\S+)\s*\{', line)
                if iface_m and not re.match(r'^\s{8}', line):
                    current_iface = iface_m.group(1)
                    current_unit = None
                    continue
                unit_m = re.match(r'^\s{8}unit\s+(\S+)\s*\{', line)
                if unit_m:
                    current_unit = unit_m.group(1)
                    continue
                addr_m = _RE_CB_ADDRESS.search(line)
                if addr_m and current_iface:
                    cidr = addr_m.group(1)
                    try:
                        net = ipaddress.ip_interface(cidr)
                        ip = str(net.ip)
                    except ValueError:
                        continue
                    if ip not in seen:
                        seen.add(ip)
                        iface_label = (f"{current_iface}.{current_unit}"
                                       if current_unit else current_iface)
                        hosts.append(_make_host(
                            ip=ip, iface_name=iface_label,
                            device_name=device_name, os_name=os_name,
                            services=list(svcs), source=source,
                        ))
                        if current_iface.lower() == 'irb' and current_unit:
                            try:
                                irb_map[int(current_unit)] = ip
                            except ValueError:
                                pass

        # VLAN name table from vlans { NAME { vlan-id X; } }
        vlan_names: dict[int, str] = {}
        vb_m = _RE_CB_VLAN_NAME_BLOCK.search(text)
        if vb_m:
            for entry_m in _RE_CB_VLAN_ENTRY.finditer(vb_m.group(1)):
                name = entry_m.group(1)
                vid = int(entry_m.group(2))
                vlan_names[vid] = name

        vlans, vlan_fdb = _build_vlan_output(hosts, vlan_names, irb_map)
        return hosts, vlans, vlan_fdb


def _build_vlan_output(
    hosts: list[Host],
    vlan_names: dict[int, str],
    irb_map: dict[int, str],
) -> tuple[list[dict], list[dict]]:
    """Produce vlans and vlan_fdb lists from parsed VLAN data."""
    if not vlan_names and not irb_map:
        return [], []
    # Use lowest-ID IRB IP as switch_ip, fallback to first host IP
    switch_ip: str | None = None
    if irb_map:
        switch_ip = irb_map[min(irb_map)]
    if not switch_ip and hosts:
        switch_ip = hosts[0].ip
    if not switch_ip:
        return [], []

    vlans: list[dict] = []
    vlan_fdb: list[dict] = []
    seen_vids: set[int] = set()
    for vid, name in vlan_names.items():
        vlans.append({"switch_ip": switch_ip, "vlan_id": vid, "vlan_name": name})
        seen_vids.add(vid)
    for vid, irb_ip in irb_map.items():
        if vid not in seen_vids:
            vlans.append({"switch_ip": switch_ip, "vlan_id": vid,
                          "vlan_name": f"VLAN {vid}"})
        vlan_fdb.append({"switch_ip": switch_ip, "vlan_id": vid, "host_ip": irb_ip})
    return vlans, vlan_fdb


def _build_services(text: str) -> list[Service]:
    svcs: list[Service] = []
    enabled = {m.group(1).lower() for m in _RE_SET_SERVICES.finditer(text)}
    if 'ssh' in enabled or re.search(r'ssh\s*\{', text, re.IGNORECASE):
        svcs.append(Service(port=22, protocol='tcp', state='open',
                            service_name='ssh', product='JunOS SSH'))
    if 'telnet' in enabled or re.search(r'telnet\s*\{', text, re.IGNORECASE):
        svcs.append(Service(port=23, protocol='tcp', state='open',
                            service_name='telnet', product='JunOS Telnet'))
    if 'web-management' in enabled or re.search(
            r'web-management\s*\{', text, re.IGNORECASE):
        svcs.append(Service(port=443, protocol='tcp', state='open',
                            service_name='https', product='J-Web HTTPS'))
        svcs.append(Service(port=80, protocol='tcp', state='open',
                            service_name='http', product='J-Web HTTP'))
    if _RE_SET_SNMP.search(text) or re.search(r'^snmp\s*\{', text,
                                               re.IGNORECASE | re.MULTILINE):
        svcs.append(Service(port=161, protocol='udp', state='open',
                            service_name='snmp', product='JunOS SNMP'))
    if 'netconf' in enabled or re.search(r'netconf\s*\{', text, re.IGNORECASE):
        svcs.append(Service(port=830, protocol='tcp', state='open',
                            service_name='netconf', product='JunOS NETCONF'))
    if not svcs:
        svcs.append(Service(port=22, protocol='tcp', state='open',
                            service_name='ssh', product='JunOS SSH'))
    return svcs


def _make_host(
    ip: str,
    iface_name: str,
    device_name: str | None,
    os_name: str,
    services: list[Service],
    source: str,
) -> Host:
    tags = [f"junos-interface:{iface_name}"]
    if device_name:
        tags.append(f"junos-device:{device_name}")
    return Host(
        ip=ip,
        hostnames=[device_name] if device_name else [],
        os_name=os_name,
        os_family="Network",
        mac_vendor="Juniper Networks",
        status="up",
        services=services,
        tags=tags,
        source_files=[source],
    )
