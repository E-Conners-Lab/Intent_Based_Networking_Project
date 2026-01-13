"""Device Connector for IBN Platform.

Handles SSH connections to network devices using Netmiko.
Supports configuration deployment and verification commands.
"""

from dataclasses import dataclass
from typing import Any

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from ibn.errors import IBNError


class DeviceConnectionError(IBNError):
    """Failed to connect to a device."""
    pass


class DeviceConfigError(IBNError):
    """Failed to apply configuration to a device."""
    pass


@dataclass
class DeviceCredentials:
    """Credentials for device access."""
    username: str
    password: str
    enable_secret: str | None = None


@dataclass
class ConnectionResult:
    """Result of a device connection attempt."""
    hostname: str
    success: bool
    message: str
    device_type: str = "cisco_xe"


@dataclass
class DeployResult:
    """Result of deploying config to a device."""
    hostname: str
    success: bool
    message: str
    output: str = ""
    config_lines: int = 0


@dataclass
class VerifyResult:
    """Result of verification command."""
    hostname: str
    command: str
    output: str
    success: bool


class DeviceConnector:
    """Manages connections to network devices.

    Example:
        connector = DeviceConnector(credentials)
        result = connector.deploy_config("10.255.255.101", config_text)
        verify = connector.verify(ip, "show ip bgp summary")
    """

    def __init__(
        self,
        credentials: DeviceCredentials,
        device_type: str = "cisco_xe",
        timeout: int = 30,
    ):
        self.credentials = credentials
        self.device_type = device_type
        self.timeout = timeout

    def _get_connection_params(self, host: str) -> dict[str, Any]:
        """Build Netmiko connection parameters."""
        params = {
            "device_type": self.device_type,
            "host": host,
            "username": self.credentials.username,
            "password": self.credentials.password,
            "timeout": self.timeout,
            "conn_timeout": self.timeout,
        }
        if self.credentials.enable_secret:
            params["secret"] = self.credentials.enable_secret
        return params

    def test_connection(self, host: str, hostname: str = "") -> ConnectionResult:
        """Test SSH connectivity to a device.

        Args:
            host: IP address or hostname
            hostname: Friendly name for logging

        Returns:
            ConnectionResult with success status
        """
        display_name = hostname or host
        try:
            with ConnectHandler(**self._get_connection_params(host)) as conn:
                # Quick command to verify connection
                output = conn.send_command("show version | include uptime")
                return ConnectionResult(
                    hostname=display_name,
                    success=True,
                    message=f"Connected: {output.strip()[:60]}...",
                    device_type=self.device_type,
                )
        except NetmikoAuthenticationException:
            return ConnectionResult(
                hostname=display_name,
                success=False,
                message="Authentication failed",
                device_type=self.device_type,
            )
        except NetmikoTimeoutException:
            return ConnectionResult(
                hostname=display_name,
                success=False,
                message="Connection timeout",
                device_type=self.device_type,
            )
        except Exception as e:
            return ConnectionResult(
                hostname=display_name,
                success=False,
                message=str(e),
                device_type=self.device_type,
            )

    def deploy_config(
        self,
        host: str,
        config: str,
        hostname: str = "",
        save_config: bool = True,
    ) -> DeployResult:
        """Deploy configuration to a device.

        Args:
            host: IP address
            config: Configuration text to apply
            hostname: Friendly name for logging
            save_config: Whether to save to startup-config

        Returns:
            DeployResult with success status and output
        """
        display_name = hostname or host

        # Parse config into lines, skip comments and empty lines
        config_lines = [
            line for line in config.splitlines()
            if line.strip() and not line.strip().startswith("!")
        ]

        try:
            with ConnectHandler(**self._get_connection_params(host)) as conn:
                # Send configuration
                output = conn.send_config_set(
                    config_lines,
                    exit_config_mode=True,
                    strip_prompt=True,
                    strip_command=True,
                )

                # Save configuration
                if save_config:
                    save_output = conn.save_config()
                    output += f"\n{save_output}"

                return DeployResult(
                    hostname=display_name,
                    success=True,
                    message="Configuration applied successfully",
                    output=output,
                    config_lines=len(config_lines),
                )

        except NetmikoAuthenticationException:
            return DeployResult(
                hostname=display_name,
                success=False,
                message="Authentication failed",
            )
        except NetmikoTimeoutException:
            return DeployResult(
                hostname=display_name,
                success=False,
                message="Connection timeout",
            )
        except Exception as e:
            return DeployResult(
                hostname=display_name,
                success=False,
                message=f"Error: {str(e)}",
            )

    def verify(
        self,
        host: str,
        command: str,
        hostname: str = "",
    ) -> VerifyResult:
        """Run a verification command on a device.

        Args:
            host: IP address
            command: Show command to run
            hostname: Friendly name for logging

        Returns:
            VerifyResult with command output
        """
        display_name = hostname or host

        try:
            with ConnectHandler(**self._get_connection_params(host)) as conn:
                output = conn.send_command(command)
                return VerifyResult(
                    hostname=display_name,
                    command=command,
                    output=output,
                    success=True,
                )
        except Exception as e:
            return VerifyResult(
                hostname=display_name,
                command=command,
                output=str(e),
                success=False,
            )

    def verify_bgp_neighbors(self, host: str, hostname: str = "") -> VerifyResult:
        """Verify BGP neighbor status."""
        return self.verify(host, "show ip bgp summary", hostname)

    def verify_bfd_neighbors(self, host: str, hostname: str = "") -> VerifyResult:
        """Verify BFD session status."""
        return self.verify(host, "show bfd neighbors", hostname)

    def verify_routes(self, host: str, hostname: str = "") -> VerifyResult:
        """Verify routing table."""
        return self.verify(host, "show ip route bgp", hostname)

    def get_running_config(
        self,
        host: str,
        section: str | None = None,
        hostname: str = "",
    ) -> VerifyResult:
        """Get running configuration from device.

        Args:
            host: IP address
            section: Optional section filter (e.g., "router bgp")
            hostname: Friendly name for logging

        Returns:
            VerifyResult with config output
        """
        if section:
            command = f"show running-config | section {section}"
        else:
            command = "show running-config"
        return self.verify(host, command, hostname)

    def get_bgp_config(self, host: str, hostname: str = "") -> VerifyResult:
        """Get BGP section of running config."""
        return self.get_running_config(host, "router bgp", hostname)
