"""NETCONF and RESTCONF Connectors for IBN Platform.

Provides modern API-based device connectivity as an alternative to SSH/CLI.
- NETCONF: XML-based using ncclient (RFC 6241)
- RESTCONF: JSON-based using requests (RFC 8040)

Both use YANG models for Cisco IOS-XE devices.
"""

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any
from xml.etree import ElementTree as ET

import requests
from ncclient import manager

from ibn.deploy.connector import DeviceConnector, DeviceCredentials


class Protocol(Enum):
    """Connection protocol options."""

    SSH = "ssh"
    NETCONF = "netconf"
    RESTCONF = "restconf"


@dataclass
class ConnectionResult:
    """Result of a NETCONF/RESTCONF operation."""

    success: bool
    output: str
    protocol: Protocol
    error: str | None = None


class NetconfConnector:
    """NETCONF connector for IOS-XE devices.

    Uses ncclient to communicate via NETCONF (port 830).
    Leverages Cisco IOS-XE YANG models for configuration.

    Example:
        connector = NetconfConnector(credentials)
        result = connector.get_bgp_config("10.100.0.1", "IBN-HQ")
        if result.success:
            print(result.output)
    """

    # YANG namespace for IOS-XE native config
    NS_NATIVE = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
    NS_BGP = "http://cisco.com/ns/yang/Cisco-IOS-XE-bgp"
    NS_BGP_OPER = "http://cisco.com/ns/yang/Cisco-IOS-XE-bgp-oper"
    NS_BFD_OC = "http://openconfig.net/yang/bfd"  # OpenConfig BFD model

    def __init__(
        self,
        credentials: DeviceCredentials,
        port: int = 830,
        timeout: int = 30,
    ):
        self.credentials = credentials
        self.port = port
        self.timeout = timeout

    def _connect(self, host: str):
        """Create NETCONF connection context manager."""
        return manager.connect(
            host=host,
            port=self.port,
            username=self.credentials.username,
            password=self.credentials.password,
            hostkey_verify=False,
            device_params={"name": "iosxe"},
            timeout=self.timeout,
        )

    def get_running_config(self, host: str, hostname: str) -> ConnectionResult:
        """Get running configuration via NETCONF.

        Args:
            host: Device IP address
            hostname: Device hostname (for logging)

        Returns:
            ConnectionResult with config XML
        """
        try:
            with self._connect(host) as conn:
                config = conn.get_config(source="running")
                return ConnectionResult(
                    success=True,
                    output=config.data_xml,
                    protocol=Protocol.NETCONF,
                )
        except Exception as e:
            return ConnectionResult(
                success=False,
                output=f"NETCONF error on {hostname}: {str(e)}",
                protocol=Protocol.NETCONF,
                error=str(e),
            )

    def get_bgp_config(self, host: str, hostname: str) -> ConnectionResult:
        """Get BGP configuration via NETCONF.

        Args:
            host: Device IP address
            hostname: Device hostname (for logging)

        Returns:
            ConnectionResult with BGP config XML
        """
        # Filter for BGP config only - use subtree tuple format
        bgp_filter = f"""
            <native xmlns="{self.NS_NATIVE}">
                <router>
                    <bgp xmlns="{self.NS_BGP}"/>
                </router>
            </native>
        """
        try:
            with self._connect(host) as conn:
                config = conn.get_config(source="running", filter=("subtree", bgp_filter))
                return ConnectionResult(
                    success=True,
                    output=config.data_xml,
                    protocol=Protocol.NETCONF,
                )
        except Exception as e:
            return ConnectionResult(
                success=False,
                output=f"NETCONF error on {hostname}: {str(e)}",
                protocol=Protocol.NETCONF,
                error=str(e),
            )

    def push_config(self, host: str, hostname: str, config: str) -> ConnectionResult:
        """Push configuration via NETCONF.

        Args:
            host: Device IP address
            hostname: Device hostname (for logging)
            config: XML configuration to push

        Returns:
            ConnectionResult indicating success/failure
        """
        try:
            with self._connect(host) as conn:
                conn.edit_config(target="running", config=config)
                return ConnectionResult(
                    success=True,
                    output=f"Configuration applied to {hostname}",
                    protocol=Protocol.NETCONF,
                )
        except Exception as e:
            return ConnectionResult(
                success=False,
                output=f"NETCONF error on {hostname}: {str(e)}",
                protocol=Protocol.NETCONF,
                error=str(e),
            )

    def verify_bgp_neighbors(self, host: str, hostname: str) -> ConnectionResult:
        """Verify BGP neighbor status via NETCONF.

        Args:
            host: Device IP address
            hostname: Device hostname (for logging)

        Returns:
            ConnectionResult with BGP neighbor state
        """
        # Filter for BGP operational state - ncclient needs tuple format
        bgp_oper_filter = f"""
            <bgp-state-data xmlns="{self.NS_BGP_OPER}">
                <neighbors/>
            </bgp-state-data>
        """
        try:
            with self._connect(host) as conn:
                # Use subtree filter format for ncclient
                state = conn.get(filter=("subtree", bgp_oper_filter))
                output = self._format_bgp_state(state.data_xml)
                return ConnectionResult(
                    success=True,
                    output=output,
                    protocol=Protocol.NETCONF,
                )
        except Exception as e:
            return ConnectionResult(
                success=False,
                output=f"NETCONF error on {hostname}: {str(e)}",
                protocol=Protocol.NETCONF,
                error=str(e),
            )

    def verify_bfd_neighbors(self, host: str, hostname: str) -> ConnectionResult:
        """Verify BFD session status via NETCONF.

        Args:
            host: Device IP address
            hostname: Device hostname (for logging)

        Returns:
            ConnectionResult with BFD session state
        """
        # Use OpenConfig BFD model (widely supported on IOS-XE)
        bfd_oper_filter = f"""
            <bfd xmlns="{self.NS_BFD_OC}">
                <interfaces/>
            </bfd>
        """
        try:
            with self._connect(host) as conn:
                state = conn.get(filter=("subtree", bfd_oper_filter))
                output = self._format_bfd_state(state.data_xml)
                return ConnectionResult(
                    success=True,
                    output=output,
                    protocol=Protocol.NETCONF,
                )
        except Exception as e:
            return ConnectionResult(
                success=False,
                output=f"NETCONF error on {hostname}: {str(e)}",
                protocol=Protocol.NETCONF,
                error=str(e),
            )

    def _format_bgp_state(self, xml_data: str) -> str:
        """Format BGP state XML for display."""
        lines = ["BGP Neighbor Status (via NETCONF):", "=" * 50]
        try:
            # Parse XML and extract neighbor info
            root = ET.fromstring(xml_data)
            # Handle namespaces
            ns = {"bgp": self.NS_BGP_OPER}
            neighbors = root.findall(".//bgp:neighbor", ns)
            if not neighbors:
                # Try without namespace prefix
                neighbors = root.iter()
                for elem in root.iter():
                    if "neighbor" in elem.tag and "neighbor-id" not in elem.tag:
                        neighbor_id = elem.find(".//{*}neighbor-id")
                        state = elem.find(".//{*}session-state")
                        if neighbor_id is not None:
                            nid = neighbor_id.text or "unknown"
                            st = state.text if state is not None else "unknown"
                            lines.append(f"  {nid}: {st}")
            else:
                for neighbor in neighbors:
                    neighbor_id = neighbor.find("bgp:neighbor-id", ns)
                    state = neighbor.find("bgp:session-state", ns)
                    nid = neighbor_id.text if neighbor_id is not None else "unknown"
                    st = state.text if state is not None else "unknown"
                    lines.append(f"  {nid}: {st}")
        except ET.ParseError:
            lines.append("  Unable to parse XML response")
            lines.append(f"  Raw: {xml_data[:200]}...")
        return "\n".join(lines)

    def _format_bfd_state(self, xml_data: str) -> str:
        """Format BFD state XML for display (OpenConfig model)."""
        lines = ["BFD Session Status (via NETCONF):", "=" * 50]
        try:
            root = ET.fromstring(xml_data)
            # OpenConfig BFD uses <peer> elements with <state> children
            for elem in root.iter():
                if elem.tag.endswith("}peer") or elem.tag == "peer":
                    # Look for state/remote-address and state/session-state
                    remote = elem.find(".//{*}remote-address")
                    state = elem.find(".//{*}session-state")
                    if remote is not None:
                        r = remote.text or "unknown"
                        s = state.text if state is not None else "unknown"
                        lines.append(f"  {r}: {s}")
        except ET.ParseError:
            lines.append("  Unable to parse XML response")
        return "\n".join(lines)


class RestconfConnector:
    """RESTCONF connector for IOS-XE devices.

    Uses requests to communicate via RESTCONF (port 443).
    Returns JSON using Cisco IOS-XE YANG models.

    Example:
        connector = RestconfConnector(credentials)
        result = connector.get_bgp_config("10.100.0.1", "IBN-HQ")
        if result.success:
            print(result.output)
    """

    # RESTCONF paths for IOS-XE
    PATH_NATIVE = "/data/Cisco-IOS-XE-native:native"
    PATH_BGP = "/data/Cisco-IOS-XE-native:native/router/bgp"
    PATH_BGP_OPER = "/data/Cisco-IOS-XE-bgp-oper:bgp-state-data"
    PATH_BFD_OC = "/data/openconfig-bfd:bfd"  # OpenConfig BFD model

    def __init__(
        self,
        credentials: DeviceCredentials,
        port: int = 443,
        verify_ssl: bool = False,
        timeout: int = 30,
    ):
        self.credentials = credentials
        self.port = port
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        # Disable SSL warnings for self-signed certs
        if not verify_ssl:
            requests.packages.urllib3.disable_warnings()

    def _build_url(self, host: str, path: str) -> str:
        """Build RESTCONF URL."""
        return f"https://{host}:{self.port}/restconf{path}"

    def _get_headers(self) -> dict[str, str]:
        """Get standard RESTCONF headers."""
        return {
            "Accept": "application/yang-data+json",
            "Content-Type": "application/yang-data+json",
        }

    def _get_auth(self) -> tuple[str, str]:
        """Get authentication tuple."""
        return (self.credentials.username, self.credentials.password)

    def get_running_config(self, host: str, hostname: str) -> ConnectionResult:
        """Get running configuration via RESTCONF.

        Args:
            host: Device IP address
            hostname: Device hostname (for logging)

        Returns:
            ConnectionResult with config JSON
        """
        url = self._build_url(host, self.PATH_NATIVE)
        try:
            response = requests.get(
                url,
                headers=self._get_headers(),
                auth=self._get_auth(),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )

            if response.status_code == 200:
                return ConnectionResult(
                    success=True,
                    output=json.dumps(response.json(), indent=2),
                    protocol=Protocol.RESTCONF,
                )
            else:
                return ConnectionResult(
                    success=False,
                    output=f"HTTP {response.status_code}: {response.text}",
                    protocol=Protocol.RESTCONF,
                    error=f"HTTP {response.status_code}",
                )
        except Exception as e:
            return ConnectionResult(
                success=False,
                output=f"RESTCONF error on {hostname}: {str(e)}",
                protocol=Protocol.RESTCONF,
                error=str(e),
            )

    def get_bgp_config(self, host: str, hostname: str) -> ConnectionResult:
        """Get BGP configuration via RESTCONF.

        Args:
            host: Device IP address
            hostname: Device hostname (for logging)

        Returns:
            ConnectionResult with BGP config JSON
        """
        url = self._build_url(host, self.PATH_BGP)
        try:
            response = requests.get(
                url,
                headers=self._get_headers(),
                auth=self._get_auth(),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )

            if response.status_code == 200:
                return ConnectionResult(
                    success=True,
                    output=json.dumps(response.json(), indent=2),
                    protocol=Protocol.RESTCONF,
                )
            else:
                return ConnectionResult(
                    success=False,
                    output=f"HTTP {response.status_code}: {response.text}",
                    protocol=Protocol.RESTCONF,
                    error=f"HTTP {response.status_code}",
                )
        except Exception as e:
            return ConnectionResult(
                success=False,
                output=f"RESTCONF error on {hostname}: {str(e)}",
                protocol=Protocol.RESTCONF,
                error=str(e),
            )

    def push_config(
        self, host: str, hostname: str, config: dict[str, Any]
    ) -> ConnectionResult:
        """Push configuration via RESTCONF.

        Args:
            host: Device IP address
            hostname: Device hostname (for logging)
            config: Configuration dict to push

        Returns:
            ConnectionResult indicating success/failure
        """
        url = self._build_url(host, self.PATH_BGP)
        try:
            response = requests.patch(
                url,
                headers=self._get_headers(),
                auth=self._get_auth(),
                json=config,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )

            if response.status_code in (200, 201, 204):
                return ConnectionResult(
                    success=True,
                    output=f"Configuration applied to {hostname}",
                    protocol=Protocol.RESTCONF,
                )
            else:
                return ConnectionResult(
                    success=False,
                    output=f"HTTP {response.status_code}: {response.text}",
                    protocol=Protocol.RESTCONF,
                    error=f"HTTP {response.status_code}",
                )
        except Exception as e:
            return ConnectionResult(
                success=False,
                output=f"RESTCONF error on {hostname}: {str(e)}",
                protocol=Protocol.RESTCONF,
                error=str(e),
            )

    def verify_bgp_neighbors(self, host: str, hostname: str) -> ConnectionResult:
        """Verify BGP neighbor status via RESTCONF.

        Args:
            host: Device IP address
            hostname: Device hostname (for logging)

        Returns:
            ConnectionResult with BGP neighbor state
        """
        url = self._build_url(host, self.PATH_BGP_OPER)
        try:
            response = requests.get(
                url,
                headers=self._get_headers(),
                auth=self._get_auth(),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                # Format output for display
                output = self._format_bgp_neighbors(data)
                return ConnectionResult(
                    success=True,
                    output=output,
                    protocol=Protocol.RESTCONF,
                )
            else:
                return ConnectionResult(
                    success=False,
                    output=f"HTTP {response.status_code}: {response.text}",
                    protocol=Protocol.RESTCONF,
                    error=f"HTTP {response.status_code}",
                )
        except Exception as e:
            return ConnectionResult(
                success=False,
                output=f"RESTCONF error on {hostname}: {str(e)}",
                protocol=Protocol.RESTCONF,
                error=str(e),
            )

    def verify_bfd_neighbors(self, host: str, hostname: str) -> ConnectionResult:
        """Verify BFD session status via RESTCONF.

        Args:
            host: Device IP address
            hostname: Device hostname (for logging)

        Returns:
            ConnectionResult with BFD session state
        """
        url = self._build_url(host, self.PATH_BFD_OC)
        try:
            response = requests.get(
                url,
                headers=self._get_headers(),
                auth=self._get_auth(),
                verify=self.verify_ssl,
                timeout=self.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                output = self._format_bfd_sessions(data)
                return ConnectionResult(
                    success=True,
                    output=output,
                    protocol=Protocol.RESTCONF,
                )
            else:
                return ConnectionResult(
                    success=False,
                    output=f"HTTP {response.status_code}: {response.text}",
                    protocol=Protocol.RESTCONF,
                    error=f"HTTP {response.status_code}",
                )
        except Exception as e:
            return ConnectionResult(
                success=False,
                output=f"RESTCONF error on {hostname}: {str(e)}",
                protocol=Protocol.RESTCONF,
                error=str(e),
            )

    def _format_bgp_neighbors(self, data: dict) -> str:
        """Format BGP neighbor data for display."""
        lines = ["BGP Neighbor Status (via RESTCONF):", "=" * 50]

        try:
            neighbors = (
                data.get("Cisco-IOS-XE-bgp-oper:bgp-state-data", {})
                .get("neighbors", {})
                .get("neighbor", [])
            )
            for neighbor in neighbors:
                neighbor_id = neighbor.get("neighbor-id", "unknown")
                state = neighbor.get("session-state", "unknown")
                lines.append(f"  {neighbor_id}: {state}")
        except (KeyError, TypeError):
            lines.append("  Unable to parse neighbor data")

        return "\n".join(lines)

    def _format_bfd_sessions(self, data: dict) -> str:
        """Format BFD session data for display (OpenConfig model)."""
        lines = ["BFD Session Status (via RESTCONF):", "=" * 50]

        try:
            # OpenConfig BFD structure: bfd/interfaces/interface[]/peers/peer[]
            interfaces = (
                data.get("openconfig-bfd:bfd", {})
                .get("interfaces", {})
                .get("interface", [])
            )
            for interface in interfaces:
                peers = interface.get("peers", {}).get("peer", [])
                for peer in peers:
                    state_data = peer.get("state", {})
                    remote = state_data.get("remote-address", "unknown")
                    state = state_data.get("session-state", "unknown")
                    lines.append(f"  {remote}: {state}")
        except (KeyError, TypeError):
            lines.append("  Unable to parse session data")

        return "\n".join(lines)


def create_connector(
    credentials: DeviceCredentials,
    protocol: Protocol,
    port: int | None = None,
) -> DeviceConnector | NetconfConnector | RestconfConnector:
    """Factory function to create the appropriate connector.

    Args:
        credentials: Device credentials
        protocol: Protocol to use (SSH, NETCONF, RESTCONF)
        port: Optional custom port

    Returns:
        Connector instance for the specified protocol
    """
    if protocol == Protocol.SSH:
        return DeviceConnector(credentials)
    elif protocol == Protocol.NETCONF:
        return NetconfConnector(credentials, port=port or 830)
    elif protocol == Protocol.RESTCONF:
        return RestconfConnector(credentials, port=port or 443)
    else:
        raise ValueError(f"Unknown protocol: {protocol}")
