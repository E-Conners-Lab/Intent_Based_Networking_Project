"""Network topology data models.

Pydantic models for representing network topology elements:
- Nodes (routers/switches)
- Edges (links between nodes)
- Failure domains (groups of elements that can fail together)
"""

from ipaddress import IPv4Address, IPv4Network

from pydantic import BaseModel, Field, field_validator


class Node(BaseModel):
    """A network node (router or switch).

    Represents a device in the topology with its addressing
    and optional metadata.
    """

    name: str = Field(..., min_length=1, description="Unique node identifier")
    loopback: IPv4Network = Field(..., description="Loopback address with mask")
    mgmt_ip: IPv4Address = Field(..., description="Management IP address")
    role: str | None = Field(default=None, description="Node role (e.g., 'core', 'branch')")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        # Ensure name is valid for use in Z3 variables
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"Node name must be alphanumeric (with - or _): {v}")
        return v


class Edge(BaseModel):
    """A link between two nodes.

    Represents a network connection with its properties
    used for path computation and constraint solving.
    """

    src: str = Field(..., description="Source node name")
    dst: str = Field(..., description="Destination node name")
    subnet: IPv4Network = Field(..., description="Link subnet")
    latency: int = Field(..., ge=0, description="Link latency in milliseconds")
    cost: int = Field(..., ge=0, description="Link cost (arbitrary units)")
    domain: str | None = Field(default=None, description="Failure domain identifier")
    bandwidth_mbps: int = Field(default=1000, ge=1, description="Bandwidth in Mbps")

    # Interface names for config generation (C8000V uses GigabitEthernet1, etc.)
    src_interface: str | None = Field(
        default=None,
        description="Source interface (e.g., 'GigabitEthernet1')",
    )
    dst_interface: str | None = Field(
        default=None,
        description="Destination interface (e.g., 'GigabitEthernet1')",
    )

    @property
    def edge_id(self) -> str:
        """Unique identifier for this edge."""
        return f"{self.src}-{self.dst}"


class FailureDomain(BaseModel):
    """A set of elements that share a common failure mode.

    When one element in a domain fails, all elements in that
    domain are assumed to be affected. Used for diverse path computation.
    """

    name: str = Field(..., description="Domain identifier (e.g., 'A', 'B')")
    members: list[str] = Field(..., min_length=1, description="Node/edge names in this domain")


class TopologyFile(BaseModel):
    """Root model for topology YAML file.

    Validates the complete topology file structure.
    """

    nodes: list[Node] = Field(..., min_length=1, description="Network nodes")
    edges: list[Edge] = Field(..., min_length=1, description="Network links")
    failure_domains: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Failure domain definitions",
    )


class Topology(BaseModel):
    """Validated and indexed topology.

    Provides fast lookups and validation that all references
    are valid (edges reference existing nodes, etc.)
    """

    nodes: dict[str, Node] = Field(default_factory=dict, description="Nodes by name")
    edges: list[Edge] = Field(default_factory=list, description="All edges")
    failure_domains: dict[str, FailureDomain] = Field(
        default_factory=dict,
        description="Failure domains by name",
    )

    @property
    def node_count(self) -> int:
        """Number of nodes in topology."""
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        """Number of edges in topology."""
        return len(self.edges)

    @property
    def domain_count(self) -> int:
        """Number of failure domains."""
        return len(self.failure_domains)

    def get_node(self, name: str) -> Node | None:
        """Get node by name."""
        return self.nodes.get(name)

    def get_edges_from(self, node_name: str) -> list[Edge]:
        """Get all edges originating from a node."""
        return [e for e in self.edges if e.src == node_name]

    def get_edges_to(self, node_name: str) -> list[Edge]:
        """Get all edges terminating at a node."""
        return [e for e in self.edges if e.dst == node_name]

    def get_neighbors(self, node_name: str) -> list[str]:
        """Get names of all nodes directly connected to a node."""
        neighbors = set()
        for edge in self.edges:
            if edge.src == node_name:
                neighbors.add(edge.dst)
            elif edge.dst == node_name:
                neighbors.add(edge.src)
        return list(neighbors)
