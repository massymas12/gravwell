from __future__ import annotations
from pathlib import Path
from gravwell.models.dataclasses import ParseResult
from gravwell.parsers.base import BaseParser
from gravwell.parsers.nessus import NessusParser
from gravwell.parsers.openvas import OpenVASParser
from gravwell.parsers.nmap import NmapParser
from gravwell.parsers.masscan import MasscanParser
from gravwell.parsers.enum4linux import Enum4linuxParser
from gravwell.parsers.cisco import CiscoParser
from gravwell.parsers.nuclei import NucleiParser
from gravwell.parsers.paloalto import PaloAltoParser
from gravwell.parsers.fortinet import FortinetParser
from gravwell.parsers.juniper import JuniperParser
from gravwell.parsers.crowdstrike import CrowdStrikeParser

# Order matters: most specific signatures first
_PARSERS: list[type[BaseParser]] = [
    NessusParser,
    OpenVASParser,
    NmapParser,
    CrowdStrikeParser,  # before Nuclei/Enum4linux/Masscan — CS JSON arrays would
                        # otherwise be grabbed by Masscan's "starts with [" check
    NucleiParser,       # before Enum4linux/Masscan: keyed on "template-id"
    Enum4linuxParser,   # before Masscan: JSON starts with '{', not '['
    PaloAltoParser,     # XML config or set-format — before Cisco (both use set-format)
    FortinetParser,     # "config system global" block
    JuniperParser,      # "set system host-name" or curly-brace with "ge-0/0/0"
    CiscoParser,
    MasscanParser,
]

_FORMAT_MAP: dict[str, type[BaseParser]] = {
    "nessus": NessusParser,
    "openvas": OpenVASParser,
    "nmap": NmapParser,
    "nuclei": NucleiParser,
    "crowdstrike": CrowdStrikeParser,
    "enum4linux": Enum4linuxParser,
    "paloalto": PaloAltoParser,
    "fortinet": FortinetParser,
    "juniper": JuniperParser,
    "cisco": CiscoParser,
    "masscan": MasscanParser,
}


class ParserRegistry:
    @classmethod
    def parse(cls, filepath: Path, format: str | None = None) -> ParseResult:
        """
        Parse a file. If format is given, use that parser directly.
        Otherwise auto-detect by trying parsers in priority order.
        """
        if format:
            parser_cls = _FORMAT_MAP.get(format.lower())
            if not parser_cls:
                raise ValueError(
                    f"Unknown format '{format}'. "
                    f"Valid: {', '.join(_FORMAT_MAP)}"
                )
            return parser_cls.parse(filepath)

        for parser_cls in _PARSERS:
            if parser_cls.can_parse(filepath):
                return parser_cls.parse(filepath)

        raise ValueError(
            f"Could not detect format for '{filepath.name}'. "
            f"Use --format to specify one of: {', '.join(_FORMAT_MAP)}"
        )

    @classmethod
    def detect_format(cls, filepath: Path) -> str | None:
        for parser_cls in _PARSERS:
            if parser_cls.can_parse(filepath):
                return parser_cls.name
        return None
