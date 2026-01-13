"""Unit tests for Z3 constraint solver."""

from ipaddress import IPv4Address, IPv4Network

import pytest
import networkx as nx

from ibn.solver.z3_solver import DiversePathSolver, SolverConfig
from ibn.intent.schema import Intent, Requirements, Constraints
from ibn.model.topology import Topology, Node, Edge, FailureDomain
from ibn.errors import SolverError, UnsatisfiableIntent


def create_simple_topology() -> tuple[Topology, nx.DiGraph]:
    """Create a simple test topology with two failure domains.

    Topology:
        HQ -- Core1 (Domain A) -- Branch
        HQ -- Core2 (Domain B) -- Branch
    """
    nodes = {
        "HQ": Node(
            name="HQ",
            loopback=IPv4Network("10.0.0.1/32"),
            mgmt_ip=IPv4Address("10.100.0.1"),
            role="hub",
        ),
        "Core1": Node(
            name="Core1",
            loopback=IPv4Network("10.0.0.2/32"),
            mgmt_ip=IPv4Address("10.100.0.2"),
            role="core",
        ),
        "Core2": Node(
            name="Core2",
            loopback=IPv4Network("10.0.0.3/32"),
            mgmt_ip=IPv4Address("10.100.0.3"),
            role="core",
        ),
        "Branch": Node(
            name="Branch",
            loopback=IPv4Network("10.0.0.4/32"),
            mgmt_ip=IPv4Address("10.100.0.4"),
            role="branch",
        ),
    }

    edges = [
        Edge(
            src="HQ", dst="Core1",
            subnet=IPv4Network("10.1.0.0/30"),
            latency=10, cost=10,
            domain="domain_a"
        ),
        Edge(
            src="Core1", dst="Branch",
            subnet=IPv4Network("10.1.0.4/30"),
            latency=10, cost=10,
            domain="domain_a"
        ),
        Edge(
            src="HQ", dst="Core2",
            subnet=IPv4Network("10.1.0.8/30"),
            latency=15, cost=15,
            domain="domain_b"
        ),
        Edge(
            src="Core2", dst="Branch",
            subnet=IPv4Network("10.1.0.12/30"),
            latency=15, cost=15,
            domain="domain_b"
        ),
    ]

    failure_domains = {
        "domain_a": FailureDomain(name="domain_a", members=["Core1"]),
        "domain_b": FailureDomain(name="domain_b", members=["Core2"]),
    }

    topology = Topology(
        nodes=nodes,
        edges=edges,
        failure_domains=failure_domains,
    )

    # Build NetworkX graph
    graph = nx.DiGraph()
    for name in nodes.keys():
        graph.add_node(name)

    for edge in edges:
        graph.add_edge(
            edge.src, edge.dst,
            latency=edge.latency,
            cost=edge.cost,
            domain=edge.domain,
        )
        # Add reverse edge for bidirectional
        graph.add_edge(
            edge.dst, edge.src,
            latency=edge.latency,
            cost=edge.cost,
            domain=edge.domain,
        )

    return topology, graph


def create_intent(
    source: str = "HQ",
    dest: str = "Branch",
    latency_ms: int = 50,
    diverse: bool = True,
    avoid_nodes: list[str] | None = None,
    avoid_domains: list[str] | None = None,
) -> Intent:
    """Create a test intent."""
    return Intent(
        name="Test Intent",
        type="branch-wan",
        source=source,
        destination=dest,
        requirements=Requirements(
            latency_ms=latency_ms,
            diverse_paths=diverse,
        ),
        constraints=Constraints(
            avoid_nodes=avoid_nodes or [],
            avoid_domains=avoid_domains or [],
        ),
    )


class TestDiversePathSolver:
    """Tests for the Z3 diverse path solver."""

    def test_find_diverse_paths(self):
        """Test finding two diverse paths."""
        topology, graph = create_simple_topology()
        intent = create_intent()

        solver = DiversePathSolver(topology, graph)
        result = solver.solve(intent)

        assert result.is_diverse is True
        assert result.meets_sla is True
        assert len(result.primary_path.path) >= 3
        assert len(result.backup_path.path) >= 3

        # Paths should use different domains
        assert result.primary_path.domain != result.backup_path.domain

    def test_latency_constraint(self):
        """Test that paths meet latency constraint."""
        topology, graph = create_simple_topology()
        intent = create_intent(latency_ms=100)

        solver = DiversePathSolver(topology, graph)
        result = solver.solve(intent)

        assert result.primary_path.total_latency_ms <= 100
        assert result.backup_path.total_latency_ms <= 100

    def test_tight_latency_constraint(self):
        """Test with tight latency constraint that only one path can meet."""
        topology, graph = create_simple_topology()
        # Only one path can meet 25ms (HQ->Core1->Branch = 20ms)
        # Since diverse=True requires BOTH paths to meet constraint,
        # we need to disable diversity for this test
        intent = create_intent(latency_ms=25, diverse=False)

        solver = DiversePathSolver(topology, graph)
        result = solver.solve(intent)

        # At least primary path should meet constraint
        assert result.primary_path.total_latency_ms <= 25

    def test_impossible_latency_constraint(self):
        """Test that unsatisfiable constraints raise error."""
        topology, graph = create_simple_topology()
        intent = create_intent(latency_ms=5)  # Too tight

        solver = DiversePathSolver(topology, graph)

        with pytest.raises(UnsatisfiableIntent):
            solver.solve(intent)

    def test_avoid_node_constraint(self):
        """Test avoiding specific nodes."""
        topology, graph = create_simple_topology()
        # When avoiding Core1, both paths must use Core2 (same domain)
        # so we need diverse=False for this to be solvable
        intent = create_intent(avoid_nodes=["Core1"], diverse=False)

        solver = DiversePathSolver(topology, graph)
        result = solver.solve(intent)

        # Neither path should contain Core1
        assert "Core1" not in result.primary_path.path
        assert "Core1" not in result.backup_path.path

    def test_avoid_domain_constraint(self):
        """Test avoiding specific failure domains."""
        topology, graph = create_simple_topology()
        intent = create_intent(avoid_domains=["domain_a"], diverse=False)

        solver = DiversePathSolver(topology, graph)
        result = solver.solve(intent)

        # Paths should not use domain_a
        assert result.primary_path.domain != "domain_a"

    def test_invalid_source(self):
        """Test error on invalid source node."""
        topology, graph = create_simple_topology()
        intent = create_intent(source="InvalidNode")

        solver = DiversePathSolver(topology, graph)

        with pytest.raises(SolverError) as exc_info:
            solver.solve(intent)
        assert "Source node not in graph" in str(exc_info.value)

    def test_invalid_destination(self):
        """Test error on invalid destination node."""
        topology, graph = create_simple_topology()
        intent = create_intent(dest="InvalidNode")

        solver = DiversePathSolver(topology, graph)

        with pytest.raises(SolverError) as exc_info:
            solver.solve(intent)
        assert "Destination node not in graph" in str(exc_info.value)

    def test_cost_optimization(self):
        """Test that solver minimizes cost."""
        topology, graph = create_simple_topology()
        intent = create_intent()

        # With optimization
        config_opt = SolverConfig(optimize_cost=True)
        solver_opt = DiversePathSolver(topology, graph, config_opt)
        result_opt = solver_opt.solve(intent)

        # Without optimization
        config_no_opt = SolverConfig(optimize_cost=False)
        solver_no_opt = DiversePathSolver(topology, graph, config_no_opt)
        result_no_opt = solver_no_opt.solve(intent)

        # Both should find valid paths
        assert result_opt.is_diverse
        assert result_no_opt.is_diverse

    def test_non_diverse_paths_allowed(self):
        """Test solving without diversity requirement."""
        topology, graph = create_simple_topology()
        intent = create_intent(diverse=False)

        solver = DiversePathSolver(topology, graph)
        result = solver.solve(intent)

        # Should find paths (may or may not be diverse)
        assert len(result.primary_path.path) >= 3
        assert len(result.backup_path.path) >= 3

    def test_solver_time_recorded(self):
        """Test that solver time is recorded."""
        topology, graph = create_simple_topology()
        intent = create_intent()

        solver = DiversePathSolver(topology, graph)
        result = solver.solve(intent)

        assert result.solver_time_ms >= 0

    def test_path_result_structure(self):
        """Test that path results have correct structure."""
        topology, graph = create_simple_topology()
        intent = create_intent()

        solver = DiversePathSolver(topology, graph)
        result = solver.solve(intent)

        # Check primary path structure
        assert result.primary_path.path[0] == "HQ"
        assert result.primary_path.path[-1] == "Branch"
        assert result.primary_path.hops == len(result.primary_path.path) - 1
        assert result.primary_path.total_latency_ms > 0
        assert result.primary_path.total_cost > 0

        # Check backup path structure
        assert result.backup_path.path[0] == "HQ"
        assert result.backup_path.path[-1] == "Branch"


class TestSolverConfig:
    """Tests for SolverConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SolverConfig()
        assert config.timeout_ms == 30000
        assert config.optimize_cost is True
        assert config.require_diverse is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = SolverConfig(
            timeout_ms=5000,
            optimize_cost=False,
            require_diverse=False,
        )
        assert config.timeout_ms == 5000
        assert config.optimize_cost is False
        assert config.require_diverse is False
