"""Tests for database ingestion and deduplication."""
import pytest
import tempfile
import os
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def tmp_db(tmp_path):
    db_path = str(tmp_path / "test.db")
    from gravwell.database import init_db
    init_db(db_path)
    return db_path


class TestIngestion:
    def test_ingest_nmap(self, tmp_db):
        from gravwell.parsers.registry import ParserRegistry
        from gravwell.models.ingestion import ingest_parse_result
        from gravwell.database import get_session
        from gravwell.models.orm import HostORM

        result = ParserRegistry.parse(FIXTURES / "sample_nmap.xml")
        with get_session(tmp_db) as session:
            h_count, _, __ = ingest_parse_result(session, result)
        assert h_count == 3

        with get_session(tmp_db) as session:
            hosts = session.query(HostORM).all()
            assert len(hosts) == 3

    def test_ingest_nessus(self, tmp_db):
        from gravwell.parsers.registry import ParserRegistry
        from gravwell.models.ingestion import ingest_parse_result
        from gravwell.database import get_session
        from gravwell.models.orm import VulnerabilityORM

        result = ParserRegistry.parse(FIXTURES / "sample.nessus")
        with get_session(tmp_db) as session:
            _, v_count, __ = ingest_parse_result(session, result)
        assert v_count > 0

        with get_session(tmp_db) as session:
            vulns = session.query(VulnerabilityORM).all()
            assert len(vulns) == v_count

    def test_host_deduplication(self, tmp_db):
        """Ingesting the same host from two sources should merge, not duplicate."""
        from gravwell.parsers.registry import ParserRegistry
        from gravwell.models.ingestion import ingest_parse_result
        from gravwell.database import get_session
        from gravwell.models.orm import HostORM

        result1 = ParserRegistry.parse(FIXTURES / "sample_nmap.xml")
        result2 = ParserRegistry.parse(FIXTURES / "sample.nessus")

        with get_session(tmp_db) as session:
            ingest_parse_result(session, result1)
        with get_session(tmp_db) as session:
            ingest_parse_result(session, result2)

        with get_session(tmp_db) as session:
            # 192.168.1.10 appears in both — should be one row
            hosts = session.query(HostORM).filter_by(ip="192.168.1.10").all()
            assert len(hosts) == 1

    def test_aggregates_updated(self, tmp_db):
        """After ingest, host aggregates (max_cvss, vuln_counts) should be set."""
        from gravwell.parsers.registry import ParserRegistry
        from gravwell.models.ingestion import ingest_parse_result
        from gravwell.database import get_session
        from gravwell.models.orm import HostORM

        result = ParserRegistry.parse(FIXTURES / "sample.nessus")
        with get_session(tmp_db) as session:
            ingest_parse_result(session, result)

        with get_session(tmp_db) as session:
            win = session.query(HostORM).filter_by(ip="192.168.1.10").first()
            assert win is not None
            assert win.max_cvss >= 9.0
            assert win.vuln_count_critical >= 1

    def test_merged_source_files(self, tmp_db):
        """Host ingested from two files should have both source files listed."""
        from gravwell.parsers.registry import ParserRegistry
        from gravwell.models.ingestion import ingest_parse_result
        from gravwell.database import get_session
        from gravwell.models.orm import HostORM

        r1 = ParserRegistry.parse(FIXTURES / "sample_nmap.xml")
        r2 = ParserRegistry.parse(FIXTURES / "sample.nessus")
        with get_session(tmp_db) as session:
            ingest_parse_result(session, r1)
        with get_session(tmp_db) as session:
            ingest_parse_result(session, r2)

        with get_session(tmp_db) as session:
            host = session.query(HostORM).filter_by(ip="192.168.1.10").first()
            assert len(host.source_files) >= 2

    def test_mac_based_host_merge(self, tmp_db):
        """Two hosts with the same MAC but different IPs should merge into one row."""
        from gravwell.models.ingestion import ingest_parse_result
        from gravwell.database import get_session
        from gravwell.models.orm import HostORM
        from gravwell.models.dataclasses import Host, ParseResult, Service

        def _pr(ip, mac, src):
            return ParseResult(
                hosts=[Host(
                    ip=ip, hostnames=[], os_name=None, os_family=None,
                    mac=mac, mac_vendor=None, status="up",
                    services=[], vulnerabilities=[], source_files=[src], tags=[],
                )],
                source_file=src,
                parser_name="test",
                warnings=[], errors=[],
            )

        r1 = _pr("192.168.1.1", "AA:BB:CC:DD:EE:FF", "scan1.xml")
        r2 = _pr("10.0.0.1",    "AA:BB:CC:DD:EE:FF", "scan2.xml")

        with get_session(tmp_db) as session:
            ingest_parse_result(session, r1)
        with get_session(tmp_db) as session:
            ingest_parse_result(session, r2)

        with get_session(tmp_db) as session:
            hosts = session.query(HostORM).all()
            assert len(hosts) == 1, "same MAC must produce exactly one host row"
            h = hosts[0]
            assert h.ip == "192.168.1.1"
            assert "10.0.0.1" in h.additional_ips
