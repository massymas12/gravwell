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

Also extracts VLAN membership:
  - VlanORM entries from ``vlan X / description Y`` blocks
  - HostVlanORM SVI entries from ``interface VlanifX`` interfaces (same concept
    as Cisco SVIs — the VLANIF IP is the L3 gateway for VLAN X)
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

# VLAN name table: "vlan 10\n description CORP-LAN"
_RE_VLAN_BLOCK = re.compile(r'^vlan\s+(\d+)\s*$', re.IGNORECASE)
_RE_VLAN_DESC  = re.compile(r'^\s+description\s+(.+)$', re.IGNORECASE)
# Huawei VLANIF interface: "interface Vlanif10"
_RE_HUAWEI_VLANIF = re.compile(r'^[Vv]lanif(\d+)$')

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
        if re.search(r'Huawei|Versatile Routing Platform', head, re.IGNORECASE):
            return True
        if re.search(r'^sysname\s+', head, re.IGNORECASE | re.MULTILINE):
            if _HUAWEI_IFACES.search(head):
                return True
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

        hosts, vlans, vlan_fdb = cls._parse_config(text, filepath.name)
        if not hosts:
            result.warnings.append(
                "No routed interfaces with IP addresses found in Huawei config"
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
        hm = _RE_SYSNAME.search(text)
        device_name = hm.group(1) if hm else None

        vm = _RE_VERSION.search(text)
        version = vm.group(1) if vm else None
        os_name = f"Huawei VRP{' V' + version if version else ''}"

        # ── Management services ────────────────────────────────────────────
        svc_tpl: list[Service] = []
        if re.search(r'stelnet server enable|ssh server enable', text, re.IGNORECASE):
            svc_tpl.append(Service(
                port=22, protocol='tcp', state='open',
                service_name='ssh', product='Huawei SSH',
            ))
        if re.search(r'protocol inbound telnet', text, re.IGNORECASE):
            svc_tpl.append(Service(
                port=23, protocol='tcp', state='open',
                service_name='telnet', product='Huawei Telnet',
            ))
        if re.search(r'^snmp-agent\b', text, re.IGNORECASE | re.MULTILINE):
            svc_tpl.append(Service(
                port=161, protocol='udp', state='open',
                service_name='snmp', product='Huawei SNMP',
            ))
        if re.search(r'^http server enable\b', text, re.IGNORECASE | re.MULTILINE):
            svc_tpl.append(Service(
                port=80, protocol='tcp', state='open',
                service_name='http', product='Huawei HTTP',
            ))
        if re.search(r'^http secure-server enable\b', text, re.IGNORECASE | re.MULTILINE):
            svc_tpl.append(Service(
                port=443, protocol='tcp', state='open',
                service_name='https', product='Huawei HTTPS',
            ))
        if re.search(r'^netconf\b', text, re.IGNORECASE | re.MULTILINE):
            svc_tpl.append(Service(
                port=830, protocol='tcp', state='open',
                service_name='netconf', product='Huawei NETCONF',
            ))
        if not svc_tpl:
            svc_tpl.append(Service(
                port=22, protocol='tcp', state='open',
                service_name='ssh', product='Huawei SSH',
            ))

        # ── Line-by-line parser: interfaces + VLAN table ──────────────────
        interface_hosts: list[Host] = []
        vlan_names: dict[int, str] = {}   # vlan_id → description
        svi_map: dict[int, str] = {}      # vlan_id → VLANIF IP
        seen: set[str] = set()

        in_iface    = False
        in_vlan     = False
        iface_name  = ''
        iface_ip: str | None   = None
        iface_mask: str | None = None
        iface_desc: str | None = None
        iface_down  = False
        secondary_ips: list[tuple[str, str]] = []
        cur_vlan_id = 0

        def _flush() -> None:
            nonlocal iface_ip, iface_mask, iface_desc, iface_down, secondary_ips
            if iface_ip and not iface_down and iface_ip not in seen:
                seen.add(iface_ip)
                vlanif_m = _RE_HUAWEI_VLANIF.match(iface_name)
                if vlanif_m:
                    svi_map[int(vlanif_m.group(1))] = iface_ip
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
            # Interface blocks
            iface_m = _RE_IFACE.match(line)
            if iface_m:
                if in_iface:
                    _flush()
                in_iface   = True
                in_vlan    = False
                iface_name = iface_m.group(1)
                continue

            if in_iface:
                if line.startswith(' '):
                    ip_m = _RE_IPADDR.match(line)
                    if ip_m:
                        if ip_m.group(3):
                            secondary_ips.append((ip_m.group(1), ip_m.group(2)))
                        else:
                            iface_ip   = ip_m.group(1)
                            iface_mask = ip_m.group(2)
                    elif _RE_DESC.match(line):
                        iface_desc = _RE_DESC.match(line).group(1).strip()
                    elif _RE_SHUTDOWN.match(line):
                        iface_down = True
                elif line.startswith('#') or not line.startswith(' '):
                    _flush()
                    in_iface   = False
                    iface_name = ''
                continue

            # VLAN config blocks ("vlan X / description Y")
            vlan_m = _RE_VLAN_BLOCK.match(line)
            if vlan_m:
                in_vlan    = True
                cur_vlan_id = int(vlan_m.group(1))
                continue

            if in_vlan:
                if line.startswith(' '):
                    desc_m = _RE_VLAN_DESC.match(line)
                    if desc_m:
                        vlan_names[cur_vlan_id] = desc_m.group(1).strip()
                else:
                    in_vlan = False

        if in_iface:
            _flush()

        # ── Build VLAN output ──────────────────────────────────────────────
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
