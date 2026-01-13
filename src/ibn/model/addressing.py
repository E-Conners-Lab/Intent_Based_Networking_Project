"""IP addressing utilities.

Calculates interface IP addresses from subnet definitions.
Handles point-to-point link addressing conventions.
"""

from ipaddress import IPv4Address, IPv4Network


def get_interface_ips(subnet: IPv4Network) -> tuple[IPv4Address, IPv4Address]:
    """Get the two usable IPs from a point-to-point subnet.

    Convention for /30 subnets:
    - .1 = source device (lower numbered)
    - .2 = destination device (higher numbered)

    Args:
        subnet: IPv4Network (typically a /30 for P2P links)

    Returns:
        Tuple of (src_ip, dst_ip)

    Example:
        >>> get_interface_ips(IPv4Network("10.100.12.0/30"))
        (IPv4Address('10.100.12.1'), IPv4Address('10.100.12.2'))
    """
    hosts = list(subnet.hosts())

    if len(hosts) < 2:
        raise ValueError(f"Subnet {subnet} has fewer than 2 usable hosts")

    return hosts[0], hosts[1]


def get_src_ip(subnet: IPv4Network) -> IPv4Address:
    """Get the source device IP for a P2P link."""
    src_ip, _ = get_interface_ips(subnet)
    return src_ip


def get_dst_ip(subnet: IPv4Network) -> IPv4Address:
    """Get the destination device IP for a P2P link."""
    _, dst_ip = get_interface_ips(subnet)
    return dst_ip


def ip_with_mask(ip: IPv4Address, subnet: IPv4Network) -> str:
    """Format IP with subnet mask for IOS configuration.

    Args:
        ip: IPv4 address
        subnet: Network to get mask from

    Returns:
        String like "10.100.12.1 255.255.255.252"
    """
    return f"{ip} {subnet.netmask}"


def get_loopback_ip(loopback: IPv4Network) -> IPv4Address:
    """Extract the IP address from a loopback definition.

    Args:
        loopback: Loopback as IPv4Network (e.g., 10.100.0.1/32)

    Returns:
        The IP address portion
    """
    return loopback.network_address


def loopback_with_mask(loopback: IPv4Network) -> str:
    """Format loopback for IOS configuration.

    Args:
        loopback: Loopback network (e.g., 10.100.0.1/32)

    Returns:
        String like "10.100.0.1 255.255.255.255"
    """
    return f"{loopback.network_address} {loopback.netmask}"
