"""Tests for graph building and attack path analysis."""
import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def populated_db(tmp_path):
    db_path = str(tmp_path / "test.db")
    from gravwell.database import init_db, get_session
    from gravwell.parsers.registry import ParserRegistry
    from gravwell.models.ingestion import ingest_parse_result

    init_db(db_path)
    for fixture in ["sample_nmap.xml", "sample.nessus", "sample_masscan.json"]:
        result = ParserRegistry.parse(FIXTURES / fixture)
        with get_session(db_path) as session:
            ingest_parse_result(session, result)
    return db_path


class TestGraphBuilder:
    def test_graph_has_nodes(self, populated_db):
        from gravwell.database import get_session
        from gravwell.graph.builder import build_graph
        with get_session(populated_db) as session:
            G = build_graph(session)
        assert G.number_of_nodes() > 0

    def test_graph_has_edges(self, populated_db):
        from gravwell.database import get_session
        from gravwell.graph.builder import build_graph
        with get_session(populated_db) as session:
            G = build_graph(session)
        # Hosts in 192.168.1.0/24 should be connected
        assert G.number_of_edges() > 0

    def test_cytoscape_elements(self, populated_db):
        from gravwell.database import get_session
        from gravwell.graph.builder import build_graph, get_cytoscape_elements
        with get_session(populated_db) as session:
            G = build_graph(session)
        elements = get_cytoscape_elements(G)
        all_nodes = [e for e in elements if "source" not in e["data"]]
        host_nodes = [e for e in all_nodes if e["data"].get("node_type") == "host"]
        subnet_nodes = [e for e in all_nodes if e["data"].get("node_type") == "subnet_group"]
        edges = [e for e in elements if "source" in e["data"]]
        # Every host in the graph should appear as a host node element
        assert len(host_nodes) == G.number_of_nodes()
        # There should be at least one subnet group
        assert len(subnet_nodes) >= 1
        # There should be some edges
        assert len(edges) > 0

    def test_node_attributes(self, populated_db):
        from gravwell.database import get_session
        from gravwell.graph.builder import build_graph
        with get_session(populated_db) as session:
            G = build_graph(session)
        win = G.nodes.get("192.168.1.10")
        assert win is not None
        assert win["os_family"] == "Windows"
        assert win["max_cvss"] >= 9.0


class TestAttackPaths:
    def test_find_path_between_subnets(self, populated_db):
        """Hosts in same subnet should have a path."""
        from gravwell.database import get_session
        from gravwell.graph.builder import build_graph
        from gravwell.graph.analysis import find_attack_paths
        with get_session(populated_db) as session:
            G = build_graph(session)
        paths = find_attack_paths(G, "192.168.1.1", "192.168.1.10")
        assert len(paths) >= 1

    def test_path_contains_both_endpoints(self, populated_db):
        from gravwell.database import get_session
        from gravwell.graph.builder import build_graph
        from gravwell.graph.analysis import find_attack_paths
        with get_session(populated_db) as session:
            G = build_graph(session)
        paths = find_attack_paths(G, "192.168.1.1", "192.168.1.10")
        if paths:
            first_path = paths[0]
            ips = [s.ip for s in first_path.steps]
            assert "192.168.1.1" in ips
            assert "192.168.1.10" in ips

    def test_no_path_returns_empty(self, populated_db):
        from gravwell.database import get_session
        from gravwell.graph.builder import build_graph
        from gravwell.graph.analysis import find_attack_paths
        with get_session(populated_db) as session:
            G = build_graph(session)
        paths = find_attack_paths(G, "1.2.3.4", "5.6.7.8")
        assert paths == []


class TestPivotAnalysis:
    def test_pivot_candidates(self, populated_db):
        from gravwell.database import get_session
        from gravwell.graph.builder import build_graph
        from gravwell.graph.analysis import find_pivot_candidates
        with get_session(populated_db) as session:
            G = build_graph(session)
        candidates = find_pivot_candidates(G)
        # Just checking it runs without error and returns a list
        assert isinstance(candidates, list)

    def test_critical_exposure(self, populated_db):
        from gravwell.database import get_session
        from gravwell.graph.builder import build_graph
        from gravwell.graph.analysis import get_critical_exposure
        with get_session(populated_db) as session:
            G = build_graph(session)
        exposed = get_critical_exposure(G, min_cvss=9.0)
        assert any(e.ip == "192.168.1.10" for e in exposed)

    def test_network_segments(self, populated_db):
        from gravwell.database import get_session
        from gravwell.graph.builder import build_graph
        from gravwell.graph.analysis import find_network_segments
        with get_session(populated_db) as session:
            G = build_graph(session)
        segments = find_network_segments(G)
        assert isinstance(segments, list)
        assert len(segments) >= 1
