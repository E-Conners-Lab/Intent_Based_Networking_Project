"""Configuration generator.

Generates device configurations from:
- Topology (physical network state)
- Intent (what connectivity is needed)
- Service Model (how to implement it)
- Solver Result (which paths to use)

Uses Jinja2 templates for the actual config syntax.
"""

from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ibn.intent.schema import Intent, PathResult
from ibn.model.addressing import get_dst_ip, get_loopback_ip, get_src_ip
from ibn.model.topology import Edge, Node, Topology
from ibn.services.schema import ServiceModel


@dataclass
class BGPNeighbor:
    """BGP neighbor configuration data."""

    ip: IPv4Address
    name: str
    remote_as: int
    route_map_in: str
    route_map_out: str | None
    is_primary: bool
    interface: str


@dataclass
class RouteMapConfig:
    """Route-map configuration data."""

    name: str
    local_preference: int
    community: str
    match_prefix_list: str | None = None


@dataclass
class InterfaceConfig:
    """Interface configuration data."""

    name: str
    ip_address: IPv4Address
    subnet_mask: str
    description: str
    bfd_enabled: bool
    bfd_interval: int
    bfd_min_rx: int
    bfd_multiplier: int


@dataclass
class NodeConfig:
    """Complete configuration for a single node."""

    hostname: str
    router_id: IPv4Address
    bgp_as: int
    neighbors: list[BGPNeighbor]
    route_maps: list[RouteMapConfig]
    interfaces: list[InterfaceConfig]
    advertise_networks: list[str]  # "network x.x.x.x mask y.y.y.y" statements


class ConfigGenerator:
    """Generates IOS-XE configurations from intent and topology.

    Example:
        generator = ConfigGenerator(topology, intent, service, solver_result)
        configs = generator.generate_all()
        for hostname, config in configs.items():
            print(f"--- {hostname} ---")
            print(config)
    """

    def __init__(
        self,
        topology: Topology,
        intent: Intent,
        service: ServiceModel,
        primary_path: PathResult,
        backup_path: PathResult | None = None,
        template_dir: Path | None = None,
    ):
        self.topology = topology
        self.intent = intent
        self.service = service
        self.primary_path = primary_path
        self.backup_path = backup_path

        # Setup Jinja2
        if template_dir is None:
            # Default to templates/ in project root
            template_dir = Path(__file__).parent.parent.parent.parent / "templates"

        self.jinja_env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate_all(self) -> dict[str, str]:
        """Generate configurations for all nodes in the paths.

        Returns:
            Dict mapping hostname to configuration string
        """
        configs = {}

        # Get all nodes involved in the paths
        nodes_in_paths = set(self.primary_path.path)
        if self.backup_path:
            nodes_in_paths.update(self.backup_path.path)

        for node_name in nodes_in_paths:
            node_config = self._build_node_config(node_name)
            config_text = self._render_config(node_config)
            configs[node_name] = config_text

        return configs

    def _build_node_config(self, node_name: str) -> NodeConfig:
        """Build configuration data for a single node."""
        node = self.topology.nodes[node_name]

        # Determine this node's role in the paths
        is_source = node_name == self.intent.source
        is_destination = node_name == self.intent.destination

        # Find BGP neighbors based on path
        neighbors = self._find_neighbors(node_name)

        # Build route-maps
        route_maps = self._build_route_maps()

        # Build interface configs
        interfaces = self._build_interfaces(node_name)

        # Networks to advertise
        advertise_networks = []
        if is_source or is_destination:
            # Advertise our loopback
            lo_ip = get_loopback_ip(node.loopback)
            advertise_networks.append(f"network {lo_ip} mask 255.255.255.255")

        return NodeConfig(
            hostname=node_name,
            router_id=get_loopback_ip(node.loopback),
            bgp_as=self.service.routing.bgp.as_number if self.service.routing.bgp else 65000,
            neighbors=neighbors,
            route_maps=route_maps,
            interfaces=interfaces,
            advertise_networks=advertise_networks,
        )

    def _find_neighbors(self, node_name: str) -> list[BGPNeighbor]:
        """Find BGP neighbors for a node based on paths."""
        neighbors = []
        bgp_config = self.service.routing.bgp

        # Check primary path
        primary_neighbors = self._get_path_neighbors(
            node_name,
            self.primary_path.path,
            is_primary=True,
        )
        neighbors.extend(primary_neighbors)

        # Check backup path
        if self.backup_path:
            backup_neighbors = self._get_path_neighbors(
                node_name,
                self.backup_path.path,
                is_primary=False,
            )
            # Don't add duplicates
            existing_ips = {n.ip for n in neighbors}
            for neighbor in backup_neighbors:
                if neighbor.ip not in existing_ips:
                    neighbors.append(neighbor)

        return neighbors

    def _get_path_neighbors(
        self,
        node_name: str,
        path: list[str],
        is_primary: bool,
    ) -> list[BGPNeighbor]:
        """Get neighbors for a node within a specific path."""
        neighbors = []
        bgp_config = self.service.routing.bgp

        if node_name not in path:
            return neighbors

        idx = path.index(node_name)

        # Check previous node in path
        if idx > 0:
            prev_node = path[idx - 1]
            neighbor = self._create_neighbor(
                node_name, prev_node, is_primary, direction="from"
            )
            if neighbor:
                neighbors.append(neighbor)

        # Check next node in path
        if idx < len(path) - 1:
            next_node = path[idx + 1]
            neighbor = self._create_neighbor(
                node_name, next_node, is_primary, direction="to"
            )
            if neighbor:
                neighbors.append(neighbor)

        return neighbors

    def _create_neighbor(
        self,
        local_node: str,
        remote_node: str,
        is_primary: bool,
        direction: str,
    ) -> BGPNeighbor | None:
        """Create a BGP neighbor entry."""
        bgp_config = self.service.routing.bgp

        # Find the edge between these nodes
        edge = self._find_edge(local_node, remote_node)
        if not edge:
            return None

        # Determine IPs
        if edge.src == local_node:
            # We are source, neighbor is at dst_ip
            neighbor_ip = get_dst_ip(edge.subnet)
            local_interface = edge.src_interface or "GigabitEthernet1"
        else:
            # We are destination, neighbor is at src_ip
            neighbor_ip = get_src_ip(edge.subnet)
            local_interface = edge.dst_interface or "GigabitEthernet1"

        # Route-map depends on primary/backup
        if is_primary:
            route_map = bgp_config.primary_path.route_map_name
        else:
            route_map = bgp_config.backup_path.route_map_name

        return BGPNeighbor(
            ip=neighbor_ip,
            name=remote_node,
            remote_as=bgp_config.as_number,
            route_map_in=route_map,
            route_map_out=None,
            is_primary=is_primary,
            interface=local_interface,
        )

    def _find_edge(self, node_a: str, node_b: str) -> Edge | None:
        """Find edge between two nodes (either direction)."""
        for edge in self.topology.edges:
            if (edge.src == node_a and edge.dst == node_b) or \
               (edge.src == node_b and edge.dst == node_a):
                return edge
        return None

    def _build_route_maps(self) -> list[RouteMapConfig]:
        """Build route-map configurations."""
        route_maps = []
        bgp_config = self.service.routing.bgp

        # Primary path route-map
        route_maps.append(RouteMapConfig(
            name=bgp_config.primary_path.route_map_name,
            local_preference=bgp_config.primary_path.local_preference,
            community=bgp_config.primary_path.community,
        ))

        # Backup path route-map (if different)
        if bgp_config.backup_path.route_map_name != bgp_config.primary_path.route_map_name:
            route_maps.append(RouteMapConfig(
                name=bgp_config.backup_path.route_map_name,
                local_preference=bgp_config.backup_path.local_preference,
                community=bgp_config.backup_path.community,
            ))

        return route_maps

    def _build_interfaces(self, node_name: str) -> list[InterfaceConfig]:
        """Build interface configurations for BGP-enabled interfaces."""
        interfaces = []
        bfd = self.service.bfd

        # Find all edges connected to this node
        for edge in self.topology.edges:
            if edge.src == node_name:
                interface_name = edge.src_interface or "GigabitEthernet1"
                ip = get_src_ip(edge.subnet)
                remote = edge.dst
            elif edge.dst == node_name:
                interface_name = edge.dst_interface or "GigabitEthernet1"
                ip = get_dst_ip(edge.subnet)
                remote = edge.src
            else:
                continue

            # Only include interfaces that are part of our paths
            in_primary = (node_name in self.primary_path.path and
                         remote in self.primary_path.path)
            in_backup = (self.backup_path and
                        node_name in self.backup_path.path and
                        remote in self.backup_path.path)

            if not (in_primary or in_backup):
                continue

            interfaces.append(InterfaceConfig(
                name=interface_name,
                ip_address=ip,
                subnet_mask=str(edge.subnet.netmask),
                description=f"To {remote}",
                bfd_enabled=bfd.enabled,
                bfd_interval=bfd.interval_ms,
                bfd_min_rx=bfd.min_rx_ms,
                bfd_multiplier=bfd.multiplier,
            ))

        return interfaces

    def _render_config(self, node_config: NodeConfig) -> str:
        """Render configuration using Jinja2 template."""
        try:
            template = self.jinja_env.get_template("ios-xe/bgp.j2")
            return template.render(
                config=node_config,
                intent=self.intent,
                service=self.service,
            )
        except Exception as e:
            # If template doesn't exist, return a simple text version
            return self._render_simple(node_config)

    def _render_simple(self, config: NodeConfig) -> str:
        """Simple text-based config rendering (fallback if no template)."""
        lines = [
            f"! Configuration for {config.hostname}",
            f"! Intent: {self.intent.name}",
            f"! Generated by IBN Platform",
            "!",
            f"hostname {config.hostname}",
            "!",
        ]

        # BGP configuration
        lines.extend([
            f"router bgp {config.bgp_as}",
            f" bgp router-id {config.router_id}",
            " bgp log-neighbor-changes",
            " !",
        ])

        # Neighbors
        for neighbor in config.neighbors:
            path_type = "PRIMARY" if neighbor.is_primary else "BACKUP"
            lines.extend([
                f" ! {path_type} path via {neighbor.name}",
                f" neighbor {neighbor.ip} remote-as {neighbor.remote_as}",
                f" neighbor {neighbor.ip} description {neighbor.name}",
                f" neighbor {neighbor.ip} fall-over bfd",
            ])

        lines.append(" !")
        lines.append(" address-family ipv4")

        for neighbor in config.neighbors:
            lines.extend([
                f"  neighbor {neighbor.ip} activate",
                f"  neighbor {neighbor.ip} route-map {neighbor.route_map_in} in",
            ])

        for network in config.advertise_networks:
            lines.append(f"  {network}")

        lines.extend([
            " exit-address-family",
            "!",
        ])

        # Route-maps
        for rm in config.route_maps:
            lines.extend([
                f"route-map {rm.name} permit 10",
                f" set local-preference {rm.local_preference}",
                f" set community {rm.community}",
                "!",
            ])

        # BFD on interfaces
        if self.service.bfd.enabled:
            for iface in config.interfaces:
                lines.extend([
                    f"interface {iface.name}",
                    f" description {iface.description}",
                    f" ip address {iface.ip_address} {iface.subnet_mask}",
                    f" bfd interval {iface.bfd_interval} min_rx {iface.bfd_min_rx} multiplier {iface.bfd_multiplier}",
                    " no shutdown",
                    "!",
                ])

        return "\n".join(lines)
