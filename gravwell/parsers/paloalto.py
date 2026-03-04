"""Parser for Palo Alto PAN-OS configuration files.

Supports:
  - Exported XML config  (``set cli config-output-format set``, then
    ``show config running`` saved to file, or ``export configuration`` XML dump)
  - Set-format CLI output  (``show config running | match set``)

Extracts one Host per routed interface IP.  All hosts share the device hostname
and management services inferred from the config.
"""
from __future__ import annotations
import re
import ipaddress
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, ParseResult
from gravwell.parsers.base import BaseParser

# --- XML helpers (optional — graceful fallback if lxml not installed)
try:
    from xml.etree import ElementTree as ET
    _HAS_ET = True
except ImportError:
    _HAS_ET = False


# ── Compiled patterns for set-format parser ───────────────────────────────────
_RE_SET_HOSTNAME = re.compile(
    r'^set\s+deviceconfig\s+system\s+hostname\s+(\S+)',
    re.IGNORECASE | re.MULTILINE,
)
_RE_SET_MGMT_IP = re.compile(
    r'^set\s+deviceconfig\s+system\s+ip-address\s+([\d.]+)',
    re.IGNORECASE | re.MULTILINE,
)
_RE_SET_IFACE_IP = re.compile(
    r'^set\s+network\s+interface\s+\S+\s+(\S+)\s+'
    r'(?:layer3\s+)?(?:units?\s+\S+\s+)?'
    r'(?:family\s+inet\s+)?(?:address\s+|ip\s+)'
    r'([\d.]+/[\d]+)',
    re.IGNORECASE | re.MULTILINE,
)
_RE_SET_MGMT_ALLOW = re.compile(
    r'^set\s+deviceconfig\s+system\s+service\s+(?:disable-)?(ssh|telnet|https?)',
    re.IGNORECASE | re.MULTILINE,
)


def _prefix_to_mask(prefix: int) -> str:
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return '.'.join(str((mask_int >> (8 * i)) & 0xFF) for i in reversed(range(4)))


class PaloAltoParser(BaseParser):
    name = "paloalto"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath, 1024)
        # XML export: starts with <config version= or contains <devices> + PAN tags
        if '<config version=' in head and '<devices>' in head:
            return True
        # Set-format
        if re.search(r'^set\s+deviceconfig\s+system\s+', head,
                     re.IGNORECASE | re.MULTILINE):
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
                "No interface IP addresses found in Palo Alto config"
            )
        result.hosts = hosts
        return result

    @classmethod
    def _parse_config(cls, text: str, source: str) -> list[Host]:
        text_stripped = text.strip()
        if text_stripped.startswith('<') and _HAS_ET:
            return cls._parse_xml(text, source)
        return cls._parse_set_format(text, source)

    # ── XML format ────────────────────────────────────────────────────────────

    @classmethod
    def _parse_xml(cls, text: str, source: str) -> list[Host]:
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []

        # hostname
        device_name = None
        for hn_el in root.iter('hostname'):
            device_name = (hn_el.text or '').strip() or None
            break

        # PAN-OS version
        version = root.get('version', '')
        os_name = f"Palo Alto PAN-OS {version}".strip()

        # Management services
        svcs: list[Service] = []
        mgmt_el = root.find('.//deviceconfig/system/service')
        if mgmt_el is not None:
            if mgmt_el.find('disable-ssh') is None:
                svcs.append(Service(port=22, protocol='tcp', state='open',
                                    service_name='ssh', product='PAN-OS SSH'))
            if mgmt_el.find('disable-telnet') is None:
                pass  # Telnet disabled by default on modern PAN-OS
            if mgmt_el.find('disable-https') is None:
                svcs.append(Service(port=443, protocol='tcp', state='open',
                                    service_name='https', product='PAN-OS HTTPS'))
            if mgmt_el.find('disable-http') is None:
                svcs.append(Service(port=80, protocol='tcp', state='open',
                                    service_name='http', product='PAN-OS HTTP'))
        else:
            # Default: SSH + HTTPS management
            svcs = [
                Service(port=22, protocol='tcp', state='open',
                        service_name='ssh', product='PAN-OS SSH'),
                Service(port=443, protocol='tcp', state='open',
                        service_name='https', product='PAN-OS HTTPS'),
            ]

        hosts: list[Host] = []

        # Ethernet / loopback / tunnel / vlan interfaces
        for iface_el in root.iter('entry'):
            parent_tag = iface_el.get('name', '')
            # Look for ip addresses under layer3
            for ip_el in iface_el.findall('.//ip/entry'):
                cidr = ip_el.get('name', '')
                if not cidr or '/' not in cidr:
                    continue
                try:
                    net = ipaddress.ip_interface(cidr)
                    ip = str(net.ip)
                except ValueError:
                    continue
                hosts.append(_make_host(
                    ip=ip, iface_name=parent_tag,
                    device_name=device_name, os_name=os_name,
                    services=list(svcs), source=source,
                ))

        # Management IP
        mgmt_ip_el = root.find('.//deviceconfig/system/ip-address')
        if mgmt_ip_el is not None and (mgmt_ip_el.text or '').strip():
            hosts.append(_make_host(
                ip=mgmt_ip_el.text.strip(), iface_name='management',
                device_name=device_name, os_name=os_name,
                services=list(svcs), source=source,
            ))

        return hosts

    # ── Set-format ────────────────────────────────────────────────────────────

    @classmethod
    def _parse_set_format(cls, text: str, source: str) -> list[Host]:
        m = _RE_SET_HOSTNAME.search(text)
        device_name = m.group(1) if m else None

        version_m = re.search(r'set\s+deviceconfig\s+system\s+sw-version\s+(\S+)',
                               text, re.IGNORECASE)
        version = version_m.group(1) if version_m else ''
        os_name = f"Palo Alto PAN-OS {version}".strip()

        svcs: list[Service] = [
            Service(port=22, protocol='tcp', state='open',
                    service_name='ssh', product='PAN-OS SSH'),
            Service(port=443, protocol='tcp', state='open',
                    service_name='https', product='PAN-OS HTTPS'),
        ]
        if re.search(r'^set\s+deviceconfig\s+system\s+service\s+disable-ssh',
                     text, re.IGNORECASE | re.MULTILINE):
            svcs = [s for s in svcs if s.port != 22]

        hosts: list[Host] = []

        for m in _RE_SET_IFACE_IP.finditer(text):
            iface_name = m.group(1)
            cidr = m.group(2)
            try:
                net = ipaddress.ip_interface(cidr)
                ip = str(net.ip)
            except ValueError:
                continue
            hosts.append(_make_host(
                ip=ip, iface_name=iface_name,
                device_name=device_name, os_name=os_name,
                services=list(svcs), source=source,
            ))

        # Management IP
        mgmt_m = _RE_SET_MGMT_IP.search(text)
        if mgmt_m:
            mgmt_ip = mgmt_m.group(1)
            if not any(h.ip == mgmt_ip for h in hosts):
                hosts.append(_make_host(
                    ip=mgmt_ip, iface_name='management',
                    device_name=device_name, os_name=os_name,
                    services=list(svcs), source=source,
                ))

        return hosts


def _make_host(
    ip: str,
    iface_name: str,
    device_name: str | None,
    os_name: str,
    services: list[Service],
    source: str,
) -> Host:
    tags = [f"panos-interface:{iface_name}"]
    if device_name:
        tags.append(f"panos-device:{device_name}")
    return Host(
        ip=ip,
        hostnames=[device_name] if device_name else [],
        os_name=os_name,
        os_family="Network",
        mac_vendor="Palo Alto Networks",
        status="up",
        services=services,
        tags=tags,
        source_files=[source],
    )
