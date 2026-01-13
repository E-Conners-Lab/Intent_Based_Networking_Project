"""Network model components."""

from ibn.model.addressing import (
    get_dst_ip,
    get_interface_ips,
    get_loopback_ip,
    get_src_ip,
    ip_with_mask,
    loopback_with_mask,
)
from ibn.model.loader import TopologyLoader
from ibn.model.topology import Edge, FailureDomain, Node, Topology

__all__ = [
    "Edge",
    "FailureDomain",
    "Node",
    "Topology",
    "TopologyLoader",
    "get_dst_ip",
    "get_interface_ips",
    "get_loopback_ip",
    "get_src_ip",
    "ip_with_mask",
    "loopback_with_mask",
]
