"""Parser for Fortinet FortiOS configuration files.

Supports the standard FortiOS text config format produced by:
  ``show full-configuration``  or  ``get system config``  or saved
  ``sys.conf`` backup files.

Extracts one Host per interface that has an IP address configured.

Also extracts VLAN membership:
  - Sub-interfaces with ``set vlanid X`` produce VlanORM entries (the alias
    or interface name is used as the VLAN name)
  - The sub-interface IP is recorded as a direct HostVlanORM entry (no MAC
    needed — the FortiGate is the L3 gateway for that VLAN)
"""
from __future__ import annotations
import re
import ipaddress
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, ParseResult
from gravwell.parsers.base import BaseParser


_RE_HOSTNAME = re.compile(
    r'^(?:\s*)set\s+hostname\s+"?([^"\n]+)"?',
    re.IGNORECASE | re.MULTILINE,
)
_RE_VERSION = re.compile(
    r'#(?:config-version|build).*?FGT.*?(?:v([\d.]+))?',
    re.IGNORECASE,
)

_RE_IFACE_EDIT   = re.compile(r'^\s*edit\s+"?([^"\n]+)"?', re.IGNORECASE)
_RE_IFACE_IP     = re.compile(r'^\s*set\s+ip\s+([\d.]+)\s+([\d.]+)', re.IGNORECASE)
_RE_ALLOWACCESS  = re.compile(r'^\s*set\s+allowaccess\s+(.+)$', re.IGNORECASE)
_RE_STATUS_DOWN  = re.compile(r'^\s*set\s+status\s+down\b', re.IGNORECASE)
_RE_VLANID       = re.compile(r'^\s*set\s+vlanid\s+(\d+)', re.IGNORECASE)
_RE_ALIAS        = re.compile(r'^\s*set\s+alias\s+"?([^"\n]+)"?', re.IGNORECASE)
_RE_MGMT_IP      = re.compile(r'^\s*set\s+ip\s+([\d.]+)(?:\s+([\d.]+))?', re.IGNORECASE)


class FortinetParser(BaseParser):
    name = "fortinet"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath, 1024)
        if re.search(r'config\s+system\s+global', head, re.IGNORECASE):
            return True
        if re.search(r'#config-version=FG|#build=|FGVM|FortiGate', head, re.IGNORECASE):
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
            result.warnings.append("No interface IP addresses found in FortiOS config")
        result.hosts = hosts
        result.vlans = vlans
        result.vlan_fdb = vlan_fdb
        return result

    @classmethod
    def _parse_config(
        cls, text: str, source: str
    ) -> tuple[list[Host], list[dict], list[dict]]:
        hm = _RE_HOSTNAME.search(text)
        device_name = hm.group(1).strip() if hm else None

        vm = re.search(r'#config-version=FG[^-]*-(\d+\.\d+)', text)
        if not vm:
            vm = re.search(r'version\s*=\s*(\d+\.\d+)', text)
        version = vm.group(1) if vm else ''
        os_name = f"Fortinet FortiOS {version}".strip()

        hosts: list[Host] = []
        # vlan_id → (vlan_name, svi_ip) from sub-interfaces
        vlan_svi: dict[int, tuple[str, str]] = {}

        in_interface_section = False
        depth = 0
        in_edit = False
        iface_name: str = ''
        iface_ip: str | None = None
        iface_mask: str | None = None
        allowaccess: list[str] = []
        iface_down = False
        iface_vlanid: int | None = None
        iface_alias: str = ''

        def _flush():
            nonlocal iface_ip, iface_mask, iface_name, allowaccess
            nonlocal iface_down, iface_vlanid, iface_alias
            if iface_ip and not iface_down:
                svcs = _allowaccess_to_services(allowaccess)
                hosts.append(_make_host(
                    ip=iface_ip, iface_name=iface_name,
                    device_name=device_name, os_name=os_name,
                    services=svcs, source=source,
                ))
                if iface_vlanid is not None:
                    vlan_name = iface_alias or iface_name
                    vlan_svi[iface_vlanid] = (vlan_name, iface_ip)
            iface_ip = iface_mask = None
            allowaccess = []
            iface_down = False
            iface_vlanid = None
            iface_alias = ''

        for line in text.splitlines():
            stripped = line.strip()

            if re.match(r'^config\s+system\s+interface\b', stripped, re.IGNORECASE):
                in_interface_section = True
                depth = 1
                continue

            if in_interface_section:
                if re.match(r'^config\b', stripped, re.IGNORECASE):
                    depth += 1
                elif stripped == 'end':
                    depth -= 1
                    if depth <= 0:
                        if in_edit:
                            _flush()
                        in_interface_section = False
                        in_edit = False
                        continue
                elif stripped == 'next' and depth == 1:
                    if in_edit:
                        _flush()
                    in_edit = False
                    continue

                if depth == 1:
                    m = _RE_IFACE_EDIT.match(line)
                    if m:
                        if in_edit:
                            _flush()
                        in_edit = True
                        iface_name = m.group(1).strip().strip('"')
                        continue

                if in_edit and depth == 1:
                    ip_m = _RE_IFACE_IP.match(line)
                    if ip_m:
                        iface_ip = ip_m.group(1)
                        iface_mask = ip_m.group(2)
                        continue
                    aa_m = _RE_ALLOWACCESS.match(line)
                    if aa_m:
                        allowaccess = aa_m.group(1).split()
                        continue
                    if _RE_STATUS_DOWN.match(line):
                        iface_down = True
                        continue
                    vid_m = _RE_VLANID.match(line)
                    if vid_m:
                        iface_vlanid = int(vid_m.group(1))
                        continue
                    alias_m = _RE_ALIAS.match(line)
                    if alias_m:
                        iface_alias = alias_m.group(1).strip().strip('"')

        # Management interface
        mgmt_block_m = re.search(
            r'^config\s+system\s+(?:management|admin)\b.*?^end',
            text, re.IGNORECASE | re.MULTILINE | re.DOTALL,
        )
        if mgmt_block_m:
            block = mgmt_block_m.group(0)
            ip_m = _RE_MGMT_IP.search(block)
            if ip_m:
                mgmt_ip = ip_m.group(1)
                if not any(h.ip == mgmt_ip for h in hosts):
                    svcs = [Service(port=443, protocol='tcp', state='open',
                                    service_name='https', product='FortiOS HTTPS'),
                            Service(port=22, protocol='tcp', state='open',
                                    service_name='ssh', product='FortiOS SSH')]
                    hosts.append(_make_host(
                        ip=mgmt_ip, iface_name='management',
                        device_name=device_name, os_name=os_name,
                        services=svcs, source=source,
                    ))

        # Build VLAN output
        switch_ip = hosts[0].ip if hosts else None
        vlans: list[dict] = []
        vlan_fdb: list[dict] = []
        if switch_ip and vlan_svi:
            for vid, (vlan_name, svi_ip) in vlan_svi.items():
                vlans.append({"switch_ip": switch_ip, "vlan_id": vid,
                              "vlan_name": vlan_name})
                vlan_fdb.append({"switch_ip": switch_ip, "vlan_id": vid,
                                 "host_ip": svi_ip})

        return hosts, vlans, vlan_fdb


def _allowaccess_to_services(allowaccess: list[str]) -> list[Service]:
    _MAP = {
        'ssh':    Service(port=22,  protocol='tcp', state='open',
                          service_name='ssh',   product='FortiOS SSH'),
        'telnet': Service(port=23,  protocol='tcp', state='open',
                          service_name='telnet', product='FortiOS Telnet'),
        'http':   Service(port=80,  protocol='tcp', state='open',
                          service_name='http',  product='FortiOS HTTP'),
        'https':  Service(port=443, protocol='tcp', state='open',
                          service_name='https', product='FortiOS HTTPS'),
        'snmp':   Service(port=161, protocol='udp', state='open',
                          service_name='snmp',  product='FortiOS SNMP'),
    }
    svcs = []
    for token in (t.lower() for t in allowaccess):
        svc = _MAP.get(token)
        if svc:
            svcs.append(svc)
    if not svcs:
        svcs.append(_MAP['https'])
    return svcs


def _make_host(
    ip: str,
    iface_name: str,
    device_name: str | None,
    os_name: str,
    services: list[Service],
    source: str,
) -> Host:
    tags = [f"fortios-interface:{iface_name}"]
    if device_name:
        tags.append(f"fortios-device:{device_name}")
    return Host(
        ip=ip,
        hostnames=[device_name] if device_name else [],
        os_name=os_name,
        os_family="Network",
        mac_vendor="Fortinet",
        status="up",
        services=services,
        tags=tags,
        source_files=[source],
    )
