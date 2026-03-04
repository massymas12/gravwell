from __future__ import annotations
import json
import re
from pathlib import Path
from gravwell.models.dataclasses import Host, Service, Vulnerability, ParseResult
from gravwell.parsers.base import BaseParser
from gravwell.models.os_inference import normalize_os_family, CONF_EXPLICIT_HIGH

# Default non-default share names to skip when raising share findings
_DEFAULT_SHARES = {"IPC$", "ADMIN$", "C$", "D$", "E$", "F$", "PRINT$"}

_SMB_SIGNING_VULN = Vulnerability(
    name="SMB Signing Disabled",
    severity="high",
    cvss_score=7.5,
    plugin_id="enum4linux-smb-signing-disabled",
    port=445,
    description=(
        "SMB signing is not required on this host. Attackers on the network "
        "can perform NTLM relay attacks (e.g. Responder + ntlmrelayx) to "
        "authenticate as any user whose challenge was captured, potentially "
        "leading to remote code execution or domain compromise."
    ),
    solution=(
        "Enable and require SMB signing via Group Policy: "
        "Computer Configuration > Windows Settings > Security Settings > "
        "Local Policies > Security Options > "
        "'Microsoft network server: Digitally sign communications (always)'."
    ),
)


def _users_vuln(users: list[str]) -> Vulnerability:
    sample = ", ".join(users[:50]) + ("..." if len(users) > 50 else "")
    return Vulnerability(
        name="SMB User Enumeration",
        severity="medium",
        cvss_score=5.3,
        plugin_id="enum4linux-users-enumerable",
        port=445,
        description=(
            f"{len(users)} account(s) enumerated via SMB null session or "
            f"authenticated RPC:\n{sample}"
        ),
        solution=(
            "Restrict anonymous enumeration: set RestrictAnonymous=2 and "
            "RestrictAnonymousSAM=1 in the registry, or via Group Policy."
        ),
    )


def _shares_vuln(shares: list[str]) -> Vulnerability:
    return Vulnerability(
        name="SMB Shares Enumerated",
        severity="low",
        cvss_score=3.1,
        plugin_id="enum4linux-shares",
        port=445,
        description=(
            f"Non-default SMB shares accessible on this host:\n"
            + ", ".join(shares)
        ),
        solution="Audit share permissions. Remove or restrict unnecessary shares.",
    )


def _os_family(os_string: str) -> str:
    return normalize_os_family(os_string)


class Enum4linuxParser(BaseParser):
    name = "enum4linux"

    @classmethod
    def can_parse(cls, filepath: Path) -> bool:
        head = cls._read_head(filepath, 512)
        # enum4linux-ng JSON: starts with '{' and has characteristic keys
        stripped = head.strip()
        if stripped.startswith("{") and '"target"' in head and (
            '"smb"' in head or '"users"' in head
        ):
            return True
        # Classic enum4linux text output
        lower = head.lower()
        return "enum4linux" in lower and "starting" in lower

    @classmethod
    def parse(cls, filepath: Path) -> ParseResult:
        result = ParseResult(source_file=str(filepath), parser_name=cls.name)
        head = cls._read_head(filepath, 16).strip()
        if head.startswith("{"):
            cls._parse_ng_json(filepath, result)
        else:
            cls._parse_classic(filepath, result)
        return result

    # ------------------------------------------------------------------
    # enum4linux-ng JSON
    # ------------------------------------------------------------------
    @classmethod
    def _parse_ng_json(cls, filepath: Path, result: ParseResult) -> None:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            result.errors.append(f"JSON parse error: {e}")
            return

        target = data.get("target", {})
        ip = target.get("host")
        if not ip:
            result.errors.append("No target host found in enum4linux-ng JSON")
            return

        host = Host(ip=ip, source_files=[filepath.name])

        smb = data.get("smb", {})
        ldap = data.get("ldap", {})

        # OS — SMB enumeration provides a reliable OS string
        if smb.get("os"):
            host.os_name = smb["os"]
            host.os_family = _os_family(smb["os"])
            host.os_confidence = CONF_EXPLICIT_HIGH

        # Domain tag
        domain = (
            ldap.get("domain")
            or smb.get("domain_name")
            or target.get("workgroup")
        )
        if domain:
            host.tags.append(f"domain:{domain}")

        # Hostname from LDAP DC field or NetBIOS
        for hn_source in (ldap.get("dc"), smb.get("server_name")):
            if hn_source and hn_source not in host.hostnames:
                host.hostnames.append(hn_source)

        # Always record the SMB service
        host.services.append(Service(
            port=445, protocol="tcp", state="open",
            service_name="microsoft-ds", product="SMB",
        ))

        # SMB signing check
        if smb.get("smb_signing") is False:
            import copy
            host.vulnerabilities.append(copy.copy(_SMB_SIGNING_VULN))

        # Users
        users_block = data.get("users", {})
        seen: set[str] = set()
        users: list[str] = []
        for key in ("via_rpc_querydispinfo", "via_rpc_enumdomusers",
                    "via_ldap", "via_samr"):
            for entry in users_block.get(key, []):
                uname = entry.get("username") or entry.get("name") or ""
                uname = uname.strip()
                if uname and uname not in seen:
                    seen.add(uname)
                    users.append(uname)
        if users:
            host.vulnerabilities.append(_users_vuln(users))

        # Shares
        shares_block = data.get("shares", {})
        seen_shares: set[str] = set()
        all_shares: list[str] = []
        for key in ("via_rpc_netshareenumall", "via_smbclient",
                    "via_net_share_enum"):
            for entry in shares_block.get(key, []):
                sname = (entry.get("name") or entry.get("share") or "").strip()
                if sname and sname not in seen_shares:
                    seen_shares.add(sname)
                    all_shares.append(sname)
        non_default = [s for s in all_shares if s.upper() not in _DEFAULT_SHARES]
        if non_default:
            host.vulnerabilities.append(_shares_vuln(non_default))

        result.hosts.append(host)

    # ------------------------------------------------------------------
    # Classic enum4linux plain-text
    # ------------------------------------------------------------------
    @classmethod
    def _parse_classic(cls, filepath: Path, result: ParseResult) -> None:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError as e:
            result.errors.append(f"File read error: {e}")
            return

        source = filepath.name

        # Target IP — "Target ........... x.x.x.x"
        ip: str | None = None
        m = re.search(r"Target\s*\.+\s*([\d.]+)", text)
        if m:
            ip = m.group(1)
        if not ip:
            # Fallback: section header "on x.x.x.x |" or "[on x.x.x.x]"
            m = re.search(r"\bon\s+((?:\d{1,3}\.){3}\d{1,3})\b", text)
            if m:
                ip = m.group(1)
        if not ip:
            result.errors.append(
                "Could not determine target IP from enum4linux output"
            )
            return

        host = Host(ip=ip, source_files=[source])

        # Domain / workgroup
        m = re.search(r"\[\+\] Got domain/workgroup name:\s*(\S+)", text)
        if m:
            host.tags.append(f"domain:{m.group(1)}")

        # OS info from "OS=[Windows Server 2019 Standard 17763]"
        m = re.search(r"OS=\[([^\]]+)\]", text)
        if m:
            host.os_name = m.group(1).strip()
            host.os_family = _os_family(host.os_name)
            host.os_confidence = CONF_EXPLICIT_HIGH

        # NetBIOS hostname: first <00> Workstation Service line
        m = re.search(
            r"^\s+(\S+)\s+<00>\s+-\s+\S+\s+<ACTIVE>\s+Workstation Service",
            text, re.MULTILINE,
        )
        if m:
            hn = m.group(1).strip()
            if hn and hn not in host.hostnames:
                host.hostnames.append(hn)

        # SMB service
        host.services.append(Service(
            port=445, protocol="tcp", state="open",
            service_name="microsoft-ds", product="SMB",
        ))

        # SMB signing (some enum4linux versions / with -A flag)
        if re.search(r"signing is (NOT required|[Dd]isabled|not required)", text):
            import copy
            host.vulnerabilities.append(copy.copy(_SMB_SIGNING_VULN))

        # Users — two formats emitted by different enum4linux versions:
        #   "user:[Administrator] rid:[0x1f4]"
        #   "Account: john.doe   Name: ..."
        seen: set[str] = set()
        users: list[str] = []
        for m in re.finditer(r"user:\[([^\]]+)\]", text):
            u = m.group(1).strip()
            if u and u not in seen:
                seen.add(u)
                users.append(u)
        if not users:
            for m in re.finditer(r"Account:\s+(\S+)\s+Name:", text):
                u = m.group(1).strip()
                if u and u not in seen:
                    seen.add(u)
                    users.append(u)
        if users:
            host.vulnerabilities.append(_users_vuln(users))

        # Shares — parse the table after "Sharename   Type   Comment" header
        shares: list[str] = []
        in_shares = False
        for line in text.splitlines():
            if re.search(r"Sharename\s+Type\s+Comment", line, re.IGNORECASE):
                in_shares = True
                continue
            if not in_shares:
                continue
            if re.match(r"\s*-{3,}", line):
                continue
            m = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)\b", line)
            if m:
                shares.append(m.group(1))
            elif line.strip() == "" or re.match(r"\s*\[", line):
                in_shares = False

        non_default = [s for s in shares if s.upper() not in _DEFAULT_SHARES]
        if non_default:
            host.vulnerabilities.append(_shares_vuln(non_default))

        result.hosts.append(host)
