"""Tests for all scan file parsers."""
import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


class TestNmapParser:
    def test_detects_nmap_file(self):
        from gravwell.parsers.nmap import NmapParser
        assert NmapParser.can_parse(FIXTURES / "sample_nmap.xml")

    def test_parses_hosts(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample_nmap.xml")
        assert result.parser_name == "nmap"
        assert len(result.hosts) == 3
        assert not result.errors

    def test_host_ips(self):
        from gravwell.parsers.nmap import NmapParser
        result = NmapParser.parse(FIXTURES / "sample_nmap.xml")
        ips = {h.ip for h in result.hosts}
        assert "192.168.1.1" in ips
        assert "192.168.1.10" in ips
        assert "10.0.0.50" in ips

    def test_services_parsed(self):
        from gravwell.parsers.nmap import NmapParser
        result = NmapParser.parse(FIXTURES / "sample_nmap.xml")
        gateway = next(h for h in result.hosts if h.ip == "192.168.1.1")
        ports = {s.port for s in gateway.services}
        assert 22 in ports
        assert 80 in ports
        assert 443 in ports

    def test_os_detection(self):
        from gravwell.parsers.nmap import NmapParser
        result = NmapParser.parse(FIXTURES / "sample_nmap.xml")
        win = next(h for h in result.hosts if h.ip == "192.168.1.10")
        assert win.os_family == "Windows"
        linux = next(h for h in result.hosts if h.ip == "192.168.1.1")
        assert linux.os_family == "Linux"

    def test_hostname(self):
        from gravwell.parsers.nmap import NmapParser
        result = NmapParser.parse(FIXTURES / "sample_nmap.xml")
        gw = next(h for h in result.hosts if h.ip == "192.168.1.1")
        assert "gateway.local" in gw.hostnames

    def test_banner_parsed(self):
        from gravwell.parsers.nmap import NmapParser
        result = NmapParser.parse(FIXTURES / "sample_nmap.xml")
        gw = next(h for h in result.hosts if h.ip == "192.168.1.1")
        http_svc = next(s for s in gw.services if s.port == 80)
        assert "nginx" in (http_svc.banner or "").lower()


class TestNessusParser:
    def test_detects_nessus_file(self):
        from gravwell.parsers.nessus import NessusParser
        assert NessusParser.can_parse(FIXTURES / "sample.nessus")

    def test_does_not_detect_nmap(self):
        from gravwell.parsers.nessus import NessusParser
        assert not NessusParser.can_parse(FIXTURES / "sample_nmap.xml")

    def test_parses_hosts(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample.nessus")
        assert result.parser_name == "nessus"
        assert len(result.hosts) == 2
        assert not result.errors

    def test_vulnerabilities_parsed(self):
        from gravwell.parsers.nessus import NessusParser
        result = NessusParser.parse(FIXTURES / "sample.nessus")
        win = next(h for h in result.hosts if h.ip == "192.168.1.10")
        assert len(win.vulnerabilities) >= 2
        names = {v.name for v in win.vulnerabilities}
        assert any("EternalBlue" in n or "MS17-010" in n for n in names)

    def test_cvss_score(self):
        from gravwell.parsers.nessus import NessusParser
        result = NessusParser.parse(FIXTURES / "sample.nessus")
        win = next(h for h in result.hosts if h.ip == "192.168.1.10")
        critical = [v for v in win.vulnerabilities if v.severity == "critical"]
        assert any(v.cvss_score >= 9.0 for v in critical)

    def test_cve_ids_parsed(self):
        from gravwell.parsers.nessus import NessusParser
        result = NessusParser.parse(FIXTURES / "sample.nessus")
        win = next(h for h in result.hosts if h.ip == "192.168.1.10")
        all_cves = [cve for v in win.vulnerabilities for cve in v.cve_ids]
        assert "CVE-2017-0143" in all_cves


class TestMasscanParser:
    def test_detects_masscan_json(self):
        from gravwell.parsers.masscan import MasscanParser
        assert MasscanParser.can_parse(FIXTURES / "sample_masscan.json")

    def test_parses_hosts(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample_masscan.json")
        assert result.parser_name == "masscan"
        assert len(result.hosts) == 2
        ips = {h.ip for h in result.hosts}
        assert "192.168.1.20" in ips

    def test_services_parsed(self):
        from gravwell.parsers.masscan import MasscanParser
        result = MasscanParser.parse(FIXTURES / "sample_masscan.json")
        h = next(h for h in result.hosts if h.ip == "192.168.1.20")
        ports = {s.port for s in h.services}
        assert 80 in ports
        assert 443 in ports
        assert 8080 in ports


class TestEnum4linuxParser:
    def test_detects_classic(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        assert Enum4linuxParser.can_parse(FIXTURES / "sample_enum4linux.txt")

    def test_detects_ng_json(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        assert Enum4linuxParser.can_parse(FIXTURES / "sample_enum4linux_ng.json")

    def test_does_not_detect_nmap(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        assert not Enum4linuxParser.can_parse(FIXTURES / "sample_nmap.xml")

    def test_classic_parses_ip(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        result = Enum4linuxParser.parse(FIXTURES / "sample_enum4linux.txt")
        assert not result.errors
        assert len(result.hosts) == 1
        assert result.hosts[0].ip == "192.168.1.50"

    def test_classic_parses_hostname(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        result = Enum4linuxParser.parse(FIXTURES / "sample_enum4linux.txt")
        assert "CORP-DC01" in result.hosts[0].hostnames

    def test_classic_parses_os(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        result = Enum4linuxParser.parse(FIXTURES / "sample_enum4linux.txt")
        h = result.hosts[0]
        assert "Windows Server 2019" in h.os_name
        assert h.os_family == "Windows"

    def test_classic_domain_tag(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        result = Enum4linuxParser.parse(FIXTURES / "sample_enum4linux.txt")
        assert "domain:CORP" in result.hosts[0].tags

    def test_classic_users_vulnerability(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        result = Enum4linuxParser.parse(FIXTURES / "sample_enum4linux.txt")
        vuln_names = {v.name for v in result.hosts[0].vulnerabilities}
        assert "SMB User Enumeration" in vuln_names
        users_vuln = next(v for v in result.hosts[0].vulnerabilities
                          if v.name == "SMB User Enumeration")
        assert "Administrator" in users_vuln.description
        assert "john.doe" in users_vuln.description

    def test_classic_share_vulnerability(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        result = Enum4linuxParser.parse(FIXTURES / "sample_enum4linux.txt")
        vuln_names = {v.name for v in result.hosts[0].vulnerabilities}
        assert "SMB Shares Enumerated" in vuln_names
        share_vuln = next(v for v in result.hosts[0].vulnerabilities
                          if v.name == "SMB Shares Enumerated")
        # Non-default share should appear; default shares should not
        assert "Backups" in share_vuln.description
        assert "ADMIN$" not in share_vuln.description

    def test_ng_json_parses_ip(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        result = Enum4linuxParser.parse(FIXTURES / "sample_enum4linux_ng.json")
        assert not result.errors
        assert result.hosts[0].ip == "10.0.0.10"

    def test_ng_json_smb_signing_vulnerability(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        result = Enum4linuxParser.parse(FIXTURES / "sample_enum4linux_ng.json")
        vuln_names = {v.name for v in result.hosts[0].vulnerabilities}
        assert "SMB Signing Disabled" in vuln_names
        signing_vuln = next(v for v in result.hosts[0].vulnerabilities
                            if v.name == "SMB Signing Disabled")
        assert signing_vuln.severity == "high"
        assert signing_vuln.cvss_score == 7.5

    def test_ng_json_ldap_hostname(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        result = Enum4linuxParser.parse(FIXTURES / "sample_enum4linux_ng.json")
        assert "dc01.contoso.local" in result.hosts[0].hostnames

    def test_ng_json_users_deduplicated(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        result = Enum4linuxParser.parse(FIXTURES / "sample_enum4linux_ng.json")
        users_vuln = next(v for v in result.hosts[0].vulnerabilities
                          if v.name == "SMB User Enumeration")
        # alice and bob.smith appear in both rpc lists — should not be doubled
        assert users_vuln.description.count("alice") == 1

    def test_ng_json_non_default_shares(self):
        from gravwell.parsers.enum4linux import Enum4linuxParser
        result = Enum4linuxParser.parse(FIXTURES / "sample_enum4linux_ng.json")
        share_vuln = next(v for v in result.hosts[0].vulnerabilities
                          if v.name == "SMB Shares Enumerated")
        assert "IT_Tools" in share_vuln.description
        assert "Finance" in share_vuln.description
        # SYSVOL is not in _DEFAULT_SHARES so it should appear
        assert "IPC$" not in share_vuln.description

    def test_auto_detect_classic(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample_enum4linux.txt")
        assert result.parser_name == "enum4linux"

    def test_auto_detect_ng_json(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample_enum4linux_ng.json")
        assert result.parser_name == "enum4linux"

    def test_force_format(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(
            FIXTURES / "sample_enum4linux.txt", format="enum4linux"
        )
        assert result.parser_name == "enum4linux"


class TestCiscoParser:
    def test_detects_cisco_file(self):
        from gravwell.parsers.cisco import CiscoParser
        assert CiscoParser.can_parse(FIXTURES / "sample_cisco.txt")

    def test_auto_detects_via_registry(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample_cisco.txt")
        assert result.parser_name == "cisco"

    def test_host_count(self):
        from gravwell.parsers.cisco import CiscoParser
        result = CiscoParser.parse(FIXTURES / "sample_cisco.txt")
        # GigEth0/0, GigEth0/1, GigEth0/2, Loopback0, Vlan10 = 5 routed interfaces
        # GigEth0/3 is shutdown → excluded
        assert len(result.hosts) == 5
        assert not result.errors

    def test_correct_ips(self):
        from gravwell.parsers.cisco import CiscoParser
        result = CiscoParser.parse(FIXTURES / "sample_cisco.txt")
        ips = {h.ip for h in result.hosts}
        assert "203.0.113.1" in ips
        assert "10.10.0.1" in ips
        assert "172.16.50.1" in ips
        assert "192.0.2.1" in ips
        assert "10.10.10.1" in ips

    def test_shutdown_interface_excluded(self):
        from gravwell.parsers.cisco import CiscoParser
        result = CiscoParser.parse(FIXTURES / "sample_cisco.txt")
        ips = {h.ip for h in result.hosts}
        # GigEth0/3 has no ip address + shutdown, should not appear
        assert len([h for h in result.hosts if h.ip.startswith("0.")]) == 0

    def test_os_family_and_vendor(self):
        from gravwell.parsers.cisco import CiscoParser
        result = CiscoParser.parse(FIXTURES / "sample_cisco.txt")
        for host in result.hosts:
            assert host.os_family == "Network"
            assert host.mac_vendor == "Cisco"


class TestNucleiParser:
    def test_detects_nuclei_file(self):
        from gravwell.parsers.nuclei import NucleiParser
        assert NucleiParser.can_parse(FIXTURES / "sample_nuclei.jsonl")

    def test_auto_detects_via_registry(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample_nuclei.jsonl")
        assert result.parser_name == "nuclei"
        assert not result.errors

    def test_host_count(self):
        from gravwell.parsers.nuclei import NucleiParser
        result = NucleiParser.parse(FIXTURES / "sample_nuclei.jsonl")
        # 3 distinct IPs: 192.168.1.10, 10.0.0.50, 192.168.1.1
        assert len(result.hosts) == 3

    def test_vulnerabilities_assigned(self):
        from gravwell.parsers.nuclei import NucleiParser
        result = NucleiParser.parse(FIXTURES / "sample_nuclei.jsonl")
        host = next(h for h in result.hosts if h.ip == "192.168.1.10")
        # Should have CVE-2021-44228 (critical) and CVE-2023-44487 (high)
        assert len(host.vulnerabilities) == 2
        names = {v.name for v in host.vulnerabilities}
        assert "Apache Log4j2 RCE" in names
        assert "HTTP/2 Rapid Reset Attack" in names

    def test_severity_mapping(self):
        from gravwell.parsers.nuclei import NucleiParser
        result = NucleiParser.parse(FIXTURES / "sample_nuclei.jsonl")
        host = next(h for h in result.hosts if h.ip == "192.168.1.10")
        log4j = next(v for v in host.vulnerabilities
                     if "Log4j" in v.name)
        assert log4j.severity == "critical"
        assert log4j.cvss_score == 10.0

    def test_cve_ids_extracted(self):
        from gravwell.parsers.nuclei import NucleiParser
        result = NucleiParser.parse(FIXTURES / "sample_nuclei.jsonl")
        host = next(h for h in result.hosts if h.ip == "192.168.1.10")
        log4j = next(v for v in host.vulnerabilities if "Log4j" in v.name)
        assert "CVE-2021-44228" in log4j.cve_ids

    def test_port_extracted_from_uri(self):
        from gravwell.parsers.nuclei import NucleiParser
        result = NucleiParser.parse(FIXTURES / "sample_nuclei.jsonl")
        host = next(h for h in result.hosts if h.ip == "192.168.1.10")
        ports = {s.port for s in host.services}
        assert 443 in ports

    def test_info_only_entry(self):
        from gravwell.parsers.nuclei import NucleiParser
        result = NucleiParser.parse(FIXTURES / "sample_nuclei.jsonl")
        ssh_host = next(h for h in result.hosts if h.ip == "192.168.1.1")
        ssh_vuln = next(v for v in ssh_host.vulnerabilities
                        if "OpenSSH" in v.name)
        assert ssh_vuln.severity == "info"
        assert ssh_vuln.cvss_score == 0.0
        assert 22 in {s.port for s in ssh_host.services}

    def test_tags_added_to_host(self):
        from gravwell.parsers.nuclei import NucleiParser
        result = NucleiParser.parse(FIXTURES / "sample_nuclei.jsonl")
        host = next(h for h in result.hosts if h.ip == "192.168.1.10")
        assert "rce" in host.tags or "cve2021" in host.tags

    def test_solution_field(self):
        from gravwell.parsers.nuclei import NucleiParser
        result = NucleiParser.parse(FIXTURES / "sample_nuclei.jsonl")
        host = next(h for h in result.hosts if h.ip == "192.168.1.10")
        log4j = next(v for v in host.vulnerabilities if "Log4j" in v.name)
        assert "2.17.0" in log4j.solution

    def test_force_format_via_registry(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(
            FIXTURES / "sample_nuclei.jsonl", format="nuclei"
        )
        assert result.parser_name == "nuclei"

    def test_hostname_tag(self):
        from gravwell.parsers.cisco import CiscoParser
        result = CiscoParser.parse(FIXTURES / "sample_cisco.txt")
        for host in result.hosts:
            assert any("cisco-device:core-sw-01" in t for t in host.tags)

    def test_services_ssh(self):
        from gravwell.parsers.cisco import CiscoParser
        result = CiscoParser.parse(FIXTURES / "sample_cisco.txt")
        host = result.hosts[0]
        ports = {s.port for s in host.services}
        assert 22 in ports   # ip ssh version 2 in config

    def test_services_http_https(self):
        from gravwell.parsers.cisco import CiscoParser
        result = CiscoParser.parse(FIXTURES / "sample_cisco.txt")
        host = result.hosts[0]
        ports = {s.port for s in host.services}
        assert 80 in ports   # ip http server
        assert 443 in ports  # ip http secure-server

    def test_services_snmp(self):
        from gravwell.parsers.cisco import CiscoParser
        result = CiscoParser.parse(FIXTURES / "sample_cisco.txt")
        host = result.hosts[0]
        ports = {s.port for s in host.services}
        assert 161 in ports  # snmp-server community

    def test_interface_tag(self):
        from gravwell.parsers.cisco import CiscoParser
        result = CiscoParser.parse(FIXTURES / "sample_cisco.txt")
        wan = next(h for h in result.hosts if h.ip == "203.0.113.1")
        assert any("cisco-interface:GigabitEthernet0/0" in t for t in wan.tags)

    def test_description_tag(self):
        from gravwell.parsers.cisco import CiscoParser
        result = CiscoParser.parse(FIXTURES / "sample_cisco.txt")
        wan = next(h for h in result.hosts if h.ip == "203.0.113.1")
        assert any("description:WAN Uplink" in t for t in wan.tags)

    def test_ios_os_name(self):
        from gravwell.parsers.cisco import CiscoParser
        result = CiscoParser.parse(FIXTURES / "sample_cisco.txt")
        for host in result.hosts:
            assert "Cisco IOS" in host.os_name
            assert "15.6" in host.os_name

    def test_force_format(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample_cisco.txt", format="cisco")
        assert result.parser_name == "cisco"


class TestParserRegistry:
    def test_auto_detect_nmap(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample_nmap.xml")
        assert result.parser_name == "nmap"

    def test_auto_detect_nessus(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample.nessus")
        assert result.parser_name == "nessus"

    def test_auto_detect_masscan(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample_masscan.json")
        assert result.parser_name == "masscan"

    def test_force_format(self):
        from gravwell.parsers.registry import ParserRegistry
        result = ParserRegistry.parse(FIXTURES / "sample_nmap.xml", format="nmap")
        assert result.parser_name == "nmap"

    def test_unknown_format_raises(self):
        from gravwell.parsers.registry import ParserRegistry
        with pytest.raises(ValueError, match="Unknown format"):
            ParserRegistry.parse(FIXTURES / "sample_nmap.xml", format="badformat")
