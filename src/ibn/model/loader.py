"""Topology loader from YAML to NetworkX graph.

Loads topology definition from YAML, validates with Pydantic,
and builds a NetworkX DiGraph for path computation.
"""

from pathlib import Path
from typing import Any

import networkx as nx
import yaml
from pydantic import ValidationError

from ibn.errors import (
    EdgeNotFoundError,
    NodeNotFoundError,
    TopologyLoadError,
    TopologyValidationError,
)
from ibn.model.topology import Edge, FailureDomain, Node, Topology, TopologyFile


class TopologyLoader:
    """Loads and validates network topology from YAML files.

    Converts YAML topology definition into:
    1. Validated Pydantic Topology model
    2. NetworkX DiGraph for path computation

    Example:
        loader = TopologyLoader()
        topology, graph = loader.load("lab.yaml")
    """

    def load(self, path: Path | str) -> tuple[Topology, nx.DiGraph]:
        """Load topology from YAML file.

        Args:
            path: Path to topology YAML file

        Returns:
            Tuple of (Topology model, NetworkX graph)

        Raises:
            TopologyLoadError: If file cannot be read
            TopologyValidationError: If topology data is invalid
        """
        path = Path(path)
        raw_data = self._load_yaml(path)
        topology_file = self._validate_topology_file(raw_data)
        topology = self._build_topology(topology_file)
        graph = self._build_graph(topology)
        return topology, graph

    def _load_yaml(self, path: Path) -> dict[str, Any]:
        """Load raw YAML data from file."""
        if not path.exists():
            raise TopologyLoadError(
                f"Topology file not found: {path}",
                {"path": str(path)},
            )

        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise TopologyLoadError(
                f"Invalid YAML in topology file: {e}",
                {"path": str(path)},
            ) from e
        except OSError as e:
            raise TopologyLoadError(
                f"Cannot read topology file: {e}",
                {"path": str(path)},
            ) from e

        if not isinstance(data, dict):
            raise TopologyLoadError(
                "Topology file must contain a YAML mapping",
                {"path": str(path)},
            )

        return data

    def _validate_topology_file(self, data: dict[str, Any]) -> TopologyFile:
        """Validate raw data against TopologyFile schema."""
        try:
            return TopologyFile.model_validate(data)
        except ValidationError as e:
            raise TopologyValidationError(
                f"Topology validation failed: {e.error_count()} errors",
                {"errors": e.errors()},
            ) from e

    def _build_topology(self, topo_file: TopologyFile) -> Topology:
        """Build indexed Topology from validated file data."""
        # Index nodes by name
        nodes_by_name: dict[str, Node] = {}
        for node in topo_file.nodes:
            if node.name in nodes_by_name:
                raise TopologyValidationError(
                    f"Duplicate node name: {node.name}",
                    {"node": node.name},
                )
            nodes_by_name[node.name] = node

        # Validate edge references
        for edge in topo_file.edges:
            if edge.src not in nodes_by_name:
                raise NodeNotFoundError(edge.src)
            if edge.dst not in nodes_by_name:
                raise NodeNotFoundError(edge.dst)

        # Build failure domains
        failure_domains: dict[str, FailureDomain] = {}
        for domain_name, members in topo_file.failure_domains.items():
            failure_domains[domain_name] = FailureDomain(
                name=domain_name,
                members=members,
            )

        return Topology(
            nodes=nodes_by_name,
            edges=topo_file.edges,
            failure_domains=failure_domains,
        )

    def _build_graph(self, topology: Topology) -> nx.DiGraph:
        """Build NetworkX DiGraph from Topology.

        Creates a directed graph with:
        - Nodes with loopback/mgmt_ip attributes
        - Edges with latency/cost/domain attributes
        - Bidirectional edges (network links are typically bidirectional)
        """
        graph = nx.DiGraph()

        # Add nodes
        for name, node in topology.nodes.items():
            graph.add_node(
                name,
                loopback=str(node.loopback),
                mgmt_ip=str(node.mgmt_ip),
                role=node.role,
            )

        # Add edges (bidirectional)
        for edge in topology.edges:
            # Forward direction
            graph.add_edge(
                edge.src,
                edge.dst,
                subnet=str(edge.subnet),
                latency=edge.latency,
                cost=edge.cost,
                domain=edge.domain,
                bandwidth_mbps=edge.bandwidth_mbps,
            )
            # Reverse direction (same properties)
            graph.add_edge(
                edge.dst,
                edge.src,
                subnet=str(edge.subnet),
                latency=edge.latency,
                cost=edge.cost,
                domain=edge.domain,
                bandwidth_mbps=edge.bandwidth_mbps,
            )

        return graph

    def get_edge(self, graph: nx.DiGraph, src: str, dst: str) -> dict[str, Any]:
        """Get edge attributes from graph.

        Raises:
            EdgeNotFoundError: If edge doesn't exist
        """
        if not graph.has_edge(src, dst):
            raise EdgeNotFoundError(src, dst)
        return dict(graph.edges[src, dst])

    def get_failure_domain_edges(
        self,
        topology: Topology,
        graph: nx.DiGraph,
        domain_name: str,
    ) -> list[tuple[str, str]]:
        """Get all edges that belong to a failure domain."""
        if domain_name not in topology.failure_domains:
            return []

        domain = topology.failure_domains[domain_name]
        domain_edges = []

        for edge in topology.edges:
            # Edge is in domain if explicitly listed or if src/dst node is in domain
            edge_id = edge.edge_id
            if edge_id in domain.members or edge.domain == domain_name:
                domain_edges.append((edge.src, edge.dst))
                domain_edges.append((edge.dst, edge.src))  # Bidirectional
            elif edge.src in domain.members or edge.dst in domain.members:
                domain_edges.append((edge.src, edge.dst))
                domain_edges.append((edge.dst, edge.src))

        return domain_edges
