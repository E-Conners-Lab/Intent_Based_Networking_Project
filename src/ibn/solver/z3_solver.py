"""Z3 Constraint Solver for Diverse Path Selection.

This is the technical heart of the IBN platform. It uses Microsoft's
Z3 SMT solver to find optimal paths that:
1. Meet latency constraints
2. Don't share failure domains (true diversity)
3. Minimize total cost

The key insight: standard shortest-path algorithms (Dijkstra, etc.) can't
handle diversity constraints. Z3 can express "path1 and path2 must not
share ANY element from the same failure domain" as a logical constraint
and find provably optimal solutions.
"""

import time
from dataclasses import dataclass

import networkx as nx
from z3 import And, Bool, If, Implies, Not, Optimize, Or, Sum, sat

from ibn.errors import SolverError, SolverTimeout, UnsatisfiableIntent
from ibn.intent.schema import Intent, PathResult, SolverResult
from ibn.model.topology import Topology


@dataclass
class SolverConfig:
    """Configuration for the Z3 solver."""

    timeout_ms: int = 30000  # 30 seconds default
    optimize_cost: bool = True  # Whether to minimize cost
    require_diverse: bool = True  # Whether to require diverse paths


class DiversePathSolver:
    """Z3-based solver for finding diverse network paths.

    Given a network topology and an intent (source, destination, constraints),
    finds two paths that:
    - Are valid (connected from source to destination)
    - Meet the latency SLA
    - Don't share failure domains (if required)
    - Minimize total cost (if optimization enabled)

    Example:
        solver = DiversePathSolver(topology, graph)
        result = solver.solve(intent)
        print(f"Primary: {result.primary_path.path_string}")
        print(f"Backup: {result.backup_path.path_string}")
    """

    def __init__(
        self,
        topology: Topology,
        graph: nx.DiGraph,
        config: SolverConfig | None = None,
    ):
        self.topology = topology
        self.graph = graph
        self.config = config or SolverConfig()

        # Extract graph structure
        self.nodes = list(graph.nodes())
        self.edges = list(graph.edges())

        # Build failure domain membership for edges
        self._build_domain_map()

    def _build_domain_map(self) -> None:
        """Build mapping of edges to their failure domains."""
        self.edge_to_domain: dict[tuple[str, str], str | None] = {}

        for edge in self.edges:
            src, dst = edge
            # Get domain from edge attributes
            domain = self.graph.edges[src, dst].get("domain")
            self.edge_to_domain[edge] = domain

    def solve(self, intent: Intent) -> SolverResult:
        """Solve for diverse paths meeting the intent requirements.

        Args:
            intent: The network intent to satisfy

        Returns:
            SolverResult with primary and backup paths

        Raises:
            UnsatisfiableIntent: If no solution exists
            SolverTimeout: If solver exceeds time limit
            SolverError: For other solver errors
        """
        start_time = time.time()

        source = intent.source
        dest = intent.destination
        max_latency = intent.requirements.latency_ms
        require_diverse = intent.requirements.diverse_paths

        # Validate source and destination exist
        if source not in self.nodes:
            raise SolverError(f"Source node not in graph: {source}")
        if dest not in self.nodes:
            raise SolverError(f"Destination node not in graph: {dest}")

        # Create the optimizer
        optimizer = Optimize()
        optimizer.set("timeout", self.config.timeout_ms)

        # Create boolean variables for each edge in each path
        # path1[e] = True means edge e is in the primary path
        # path2[e] = True means edge e is in the backup path
        path1_vars = {e: Bool(f"p1_{e[0]}_{e[1]}") for e in self.edges}
        path2_vars = {e: Bool(f"p2_{e[0]}_{e[1]}") for e in self.edges}

        # === CONSTRAINT 1: Valid paths (flow conservation) ===
        self._add_flow_constraints(optimizer, path1_vars, source, dest)
        self._add_flow_constraints(optimizer, path2_vars, source, dest)

        # === CONSTRAINT 2: Latency constraints ===
        self._add_latency_constraints(optimizer, path1_vars, max_latency)
        self._add_latency_constraints(optimizer, path2_vars, max_latency)

        # === CONSTRAINT 3: Avoid nodes constraint ===
        for node in intent.constraints.avoid_nodes:
            self._add_avoid_node_constraint(optimizer, path1_vars, node)
            self._add_avoid_node_constraint(optimizer, path2_vars, node)

        # === CONSTRAINT 4: Diversity constraint (no shared failure domains) ===
        if require_diverse:
            self._add_diversity_constraints(optimizer, path1_vars, path2_vars)

        # === CONSTRAINT 5: Domain avoidance ===
        for domain in intent.constraints.avoid_domains:
            self._add_avoid_domain_constraint(optimizer, path1_vars, domain)
            self._add_avoid_domain_constraint(optimizer, path2_vars, domain)

        # === OBJECTIVE: Minimize total cost ===
        if self.config.optimize_cost:
            total_cost = Sum([
                If(path1_vars[e], self.graph.edges[e[0], e[1]].get("cost", 1), 0)
                for e in self.edges
            ]) + Sum([
                If(path2_vars[e], self.graph.edges[e[0], e[1]].get("cost", 1), 0)
                for e in self.edges
            ])
            optimizer.minimize(total_cost)

        # === SOLVE ===
        result = optimizer.check()
        solve_time_ms = int((time.time() - start_time) * 1000)

        if result == sat:
            model = optimizer.model()

            # Extract paths from the model
            primary_path = self._extract_path(model, path1_vars, source, dest)
            backup_path = self._extract_path(model, path2_vars, source, dest)

            # Build path results
            primary_result = self._build_path_result(primary_path)
            backup_result = self._build_path_result(backup_path)

            # Check if paths are actually diverse
            is_diverse = self._check_diversity(primary_path, backup_path)

            # Check if both paths meet SLA
            meets_sla = (
                primary_result.total_latency_ms <= max_latency and
                backup_result.total_latency_ms <= max_latency
            )

            notes = []
            if is_diverse:
                notes.append("Paths use different failure domains")
            if meets_sla:
                notes.append(f"Both paths meet {max_latency}ms latency SLA")

            return SolverResult(
                primary_path=primary_result,
                backup_path=backup_result,
                solver_time_ms=solve_time_ms,
                is_diverse=is_diverse,
                meets_sla=meets_sla,
                notes=notes,
            )
        else:
            # No solution found
            raise UnsatisfiableIntent(
                f"No paths found meeting constraints: "
                f"source={source}, dest={dest}, max_latency={max_latency}ms, "
                f"diverse={require_diverse}",
                {"source": source, "dest": dest, "max_latency": max_latency},
            )

    def _add_flow_constraints(
        self,
        optimizer: Optimize,
        path_vars: dict[tuple[str, str], Bool],
        source: str,
        dest: str,
    ) -> None:
        """Add flow conservation constraints for a valid path.

        For each node:
        - Source: outflow - inflow = 1 (one edge leaves)
        - Destination: inflow - outflow = 1 (one edge enters)
        - Transit: inflow = outflow (what goes in must come out)
        """
        for node in self.nodes:
            # Count incoming edges
            incoming = Sum([
                If(path_vars[e], 1, 0)
                for e in self.edges if e[1] == node
            ])

            # Count outgoing edges
            outgoing = Sum([
                If(path_vars[e], 1, 0)
                for e in self.edges if e[0] == node
            ])

            if node == source:
                # Source: must have exactly one more outgoing than incoming
                optimizer.add(outgoing - incoming == 1)
            elif node == dest:
                # Destination: must have exactly one more incoming than outgoing
                optimizer.add(incoming - outgoing == 1)
            else:
                # Transit: balanced flow
                optimizer.add(incoming == outgoing)

    def _add_latency_constraints(
        self,
        optimizer: Optimize,
        path_vars: dict[tuple[str, str], Bool],
        max_latency: int,
    ) -> None:
        """Add constraint that total path latency must be <= max_latency."""
        total_latency = Sum([
            If(path_vars[e], self.graph.edges[e[0], e[1]].get("latency", 0), 0)
            for e in self.edges
        ])
        optimizer.add(total_latency <= max_latency)

    def _add_avoid_node_constraint(
        self,
        optimizer: Optimize,
        path_vars: dict[tuple[str, str], Bool],
        node: str,
    ) -> None:
        """Add constraint to avoid a specific node."""
        if node not in self.nodes:
            return  # Node doesn't exist, nothing to avoid

        # No edges to/from this node should be in the path
        for e in self.edges:
            if e[0] == node or e[1] == node:
                optimizer.add(Not(path_vars[e]))

    def _add_avoid_domain_constraint(
        self,
        optimizer: Optimize,
        path_vars: dict[tuple[str, str], Bool],
        domain: str,
    ) -> None:
        """Add constraint to avoid all edges in a failure domain."""
        for e in self.edges:
            if self.edge_to_domain.get(e) == domain:
                optimizer.add(Not(path_vars[e]))

    def _add_diversity_constraints(
        self,
        optimizer: Optimize,
        path1_vars: dict[tuple[str, str], Bool],
        path2_vars: dict[tuple[str, str], Bool],
    ) -> None:
        """Add constraints ensuring paths don't share failure domains.

        For each failure domain, if path1 uses ANY edge in that domain,
        path2 must not use ANY edge in that domain.
        """
        # Group edges by failure domain
        domain_edges: dict[str, list[tuple[str, str]]] = {}
        for e, domain in self.edge_to_domain.items():
            if domain:  # Only consider edges with assigned domains
                if domain not in domain_edges:
                    domain_edges[domain] = []
                domain_edges[domain].append(e)

        # For each domain, add mutual exclusion constraint
        for domain, edges in domain_edges.items():
            if not edges:
                continue

            # path1 uses this domain if ANY edge in domain is in path1
            path1_uses_domain = Or([path1_vars[e] for e in edges])

            # path2 uses this domain if ANY edge in domain is in path2
            path2_uses_domain = Or([path2_vars[e] for e in edges])

            # They can't both use the same domain
            optimizer.add(Not(And(path1_uses_domain, path2_uses_domain)))

    def _extract_path(
        self,
        model,
        path_vars: dict[tuple[str, str], Bool],
        source: str,
        dest: str,
    ) -> list[str]:
        """Extract the ordered path from a Z3 model."""
        # Find edges that are part of the path
        active_edges = [
            e for e in self.edges
            if model.evaluate(path_vars[e], model_completion=True)
        ]

        # Build adjacency from active edges
        next_node: dict[str, str] = {}
        for src, dst in active_edges:
            next_node[src] = dst

        # Walk the path from source to destination
        path = [source]
        current = source
        visited = {source}

        while current != dest and current in next_node:
            next_n = next_node[current]
            if next_n in visited:
                # Cycle detected - shouldn't happen with proper constraints
                break
            path.append(next_n)
            visited.add(next_n)
            current = next_n

        return path

    def _build_path_result(self, path: list[str]) -> PathResult:
        """Build a PathResult from a node path."""
        total_latency = 0
        total_cost = 0
        domain = None

        # Calculate totals by walking edges
        for i in range(len(path) - 1):
            src, dst = path[i], path[i + 1]
            if self.graph.has_edge(src, dst):
                edge_data = self.graph.edges[src, dst]
                total_latency += edge_data.get("latency", 0)
                total_cost += edge_data.get("cost", 0)

                # Track domain (use first non-None domain encountered)
                edge_domain = edge_data.get("domain")
                if edge_domain and not domain:
                    domain = edge_domain

        return PathResult(
            path=path,
            total_latency_ms=total_latency,
            total_cost=total_cost,
            domain=domain,
            hops=len(path) - 1,
        )

    def _check_diversity(
        self,
        path1: list[str],
        path2: list[str],
    ) -> bool:
        """Check if two paths are truly diverse (no shared failure domains)."""
        domains1 = set()
        domains2 = set()

        # Collect domains used by path1
        for i in range(len(path1) - 1):
            edge = (path1[i], path1[i + 1])
            domain = self.edge_to_domain.get(edge)
            if domain:
                domains1.add(domain)

        # Collect domains used by path2
        for i in range(len(path2) - 1):
            edge = (path2[i], path2[i + 1])
            domain = self.edge_to_domain.get(edge)
            if domain:
                domains2.add(domain)

        # Paths are diverse if they share no domains
        return len(domains1 & domains2) == 0


def solve_diverse_paths(
    topology: Topology,
    graph: nx.DiGraph,
    intent: Intent,
    config: SolverConfig | None = None,
) -> SolverResult:
    """Convenience function to solve for diverse paths.

    Args:
        topology: Network topology
        graph: NetworkX graph representation
        intent: Intent to satisfy
        config: Optional solver configuration

    Returns:
        SolverResult with primary and backup paths
    """
    solver = DiversePathSolver(topology, graph, config)
    return solver.solve(intent)
