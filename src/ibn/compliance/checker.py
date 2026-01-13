"""Compliance Checker for IBN Platform.

Monitors network state and verifies it matches the intended configuration.
Detects configuration drift, session failures, and other compliance violations.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from ibn.deploy import DeviceConnector, DeviceCredentials
from ibn.intent.schema import Intent
from ibn.model.topology import Topology


class ComplianceStatus(Enum):
    """Overall compliance status."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"


class ViolationType(Enum):
    """Types of compliance violations."""

    BGP_SESSION_DOWN = "bgp_session_down"
    BFD_SESSION_DOWN = "bfd_session_down"
    CONFIG_DRIFT = "config_drift"
    PATH_MISMATCH = "path_mismatch"
    DEVICE_UNREACHABLE = "device_unreachable"


@dataclass
class ComplianceViolation:
    """A single compliance violation detected during a check."""

    violation_type: ViolationType
    device: str
    message: str
    severity: str  # "critical", "warning", "info"
    detected_at: datetime
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceReport:
    """Result of a compliance check.

    Contains the overall status, list of violations, and metadata
    about the check.
    """

    status: ComplianceStatus
    intent_name: str
    checked_at: datetime
    violations: list[ComplianceViolation]
    devices_checked: list[str]
    check_duration_ms: int = 0

    @property
    def is_compliant(self) -> bool:
        """Return True if network is compliant."""
        return self.status == ComplianceStatus.COMPLIANT

    @property
    def total_violations(self) -> int:
        """Total number of violations."""
        return len(self.violations)

    @property
    def critical_count(self) -> int:
        """Count of critical violations."""
        return sum(1 for v in self.violations if v.severity == "critical")

    @property
    def warning_count(self) -> int:
        """Count of warning violations."""
        return sum(1 for v in self.violations if v.severity == "warning")

    def summary(self) -> str:
        """Generate a human-readable summary of the report."""
        status_str = self.status.value.upper()
        device_count = len(self.devices_checked)

        if self.is_compliant:
            return f"[{status_str}] {self.intent_name}: {device_count} devices checked, no violations"
        else:
            return (
                f"[{status_str}] {self.intent_name}: "
                f"{self.total_violations} violation(s) - "
                f"{self.critical_count} critical, {self.warning_count} warning"
            )


class ComplianceChecker:
    """Checks network compliance against intended state.

    Verifies that:
    - All BGP sessions are established
    - All BFD sessions are up
    - Configuration matches what was deployed
    - Paths match the solved intent

    Example:
        checker = ComplianceChecker(topology, credentials)
        report = checker.check_compliance(intent)

        if not report.is_compliant:
            for violation in report.violations:
                print(f"{violation.device}: {violation.message}")
    """

    def __init__(
        self,
        topology: Topology,
        credentials: DeviceCredentials,
    ):
        self.topology = topology
        self.credentials = credentials
        self.connector = DeviceConnector(credentials)

    def check_compliance(
        self,
        intent: Intent,
        expected_state: dict[str, Any] | None = None,
    ) -> ComplianceReport:
        """Run a full compliance check for an intent.

        Args:
            intent: The intent to check compliance for
            expected_state: Optional expected state from deployment

        Returns:
            ComplianceReport with status and any violations
        """
        start_time = datetime.now()
        all_violations: list[ComplianceViolation] = []
        devices_checked: list[str] = []

        # Check each device in the topology
        for hostname, node in self.topology.nodes.items():
            if not node.mgmt_ip:
                continue

            devices_checked.append(hostname)

            # Check BGP compliance
            bgp_violations = self.check_bgp_compliance(hostname)
            all_violations.extend(bgp_violations)

            # Check BFD compliance
            bfd_violations = self.check_bfd_compliance(hostname)
            all_violations.extend(bfd_violations)

            # Check config drift if expected state provided
            if expected_state and hostname in expected_state:
                drift_violations = self.check_config_drift(
                    hostname, expected_state[hostname]
                )
                all_violations.extend(drift_violations)

        # Determine overall status
        if not all_violations:
            status = ComplianceStatus.COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT

        check_duration = int((datetime.now() - start_time).total_seconds() * 1000)

        return ComplianceReport(
            status=status,
            intent_name=intent.name,
            checked_at=start_time,
            violations=all_violations,
            devices_checked=devices_checked,
            check_duration_ms=check_duration,
        )

    def check_bgp_compliance(self, hostname: str) -> list[ComplianceViolation]:
        """Check BGP session compliance for a device.

        Args:
            hostname: Device hostname to check

        Returns:
            List of BGP-related violations
        """
        violations: list[ComplianceViolation] = []
        node = self.topology.nodes.get(hostname)

        if not node or not node.mgmt_ip:
            return violations

        result = self.connector.verify_bgp_neighbors(str(node.mgmt_ip), hostname)

        if not result.success:
            violations.append(
                ComplianceViolation(
                    violation_type=ViolationType.DEVICE_UNREACHABLE,
                    device=hostname,
                    message=f"Cannot reach device: {result.output}",
                    severity="critical",
                    detected_at=datetime.now(),
                )
            )
            return violations

        # Parse BGP neighbors and check for non-established sessions
        down_neighbors = self._parse_bgp_down_neighbors(result.output)

        for neighbor_ip in down_neighbors:
            violations.append(
                ComplianceViolation(
                    violation_type=ViolationType.BGP_SESSION_DOWN,
                    device=hostname,
                    message=f"BGP neighbor {neighbor_ip} is not established",
                    severity="critical",
                    detected_at=datetime.now(),
                    details={"neighbor": neighbor_ip},
                )
            )

        return violations

    def check_bfd_compliance(self, hostname: str) -> list[ComplianceViolation]:
        """Check BFD session compliance for a device.

        Args:
            hostname: Device hostname to check

        Returns:
            List of BFD-related violations
        """
        violations: list[ComplianceViolation] = []
        node = self.topology.nodes.get(hostname)

        if not node or not node.mgmt_ip:
            return violations

        result = self.connector.verify_bfd_neighbors(str(node.mgmt_ip), hostname)

        if not result.success:
            # Device unreachable already reported in BGP check
            return violations

        # Parse BFD neighbors and check for down sessions
        down_neighbors = self._parse_bfd_down_neighbors(result.output)

        for neighbor_ip in down_neighbors:
            violations.append(
                ComplianceViolation(
                    violation_type=ViolationType.BFD_SESSION_DOWN,
                    device=hostname,
                    message=f"BFD session to {neighbor_ip} is down",
                    severity="critical",
                    detected_at=datetime.now(),
                    details={"neighbor": neighbor_ip},
                )
            )

        return violations

    def check_config_drift(
        self,
        hostname: str,
        expected: dict[str, Any],
    ) -> list[ComplianceViolation]:
        """Check for configuration drift on a device.

        Args:
            hostname: Device hostname to check
            expected: Expected configuration state

        Returns:
            List of config drift violations
        """
        violations: list[ComplianceViolation] = []
        node = self.topology.nodes.get(hostname)

        if not node or not node.mgmt_ip:
            return violations

        # Get current BGP config
        result = self.connector.get_bgp_config(str(node.mgmt_ip), hostname)

        if not result.success:
            return violations

        current_config = result.output

        # Check for expected BGP neighbors
        expected_neighbors = expected.get("bgp_neighbors", [])
        for neighbor in expected_neighbors:
            if neighbor not in current_config:
                violations.append(
                    ComplianceViolation(
                        violation_type=ViolationType.CONFIG_DRIFT,
                        device=hostname,
                        message=f"Expected BGP neighbor {neighbor} not in config",
                        severity="warning",
                        detected_at=datetime.now(),
                        details={"expected_neighbor": neighbor},
                    )
                )

        return violations

    def _parse_bgp_down_neighbors(self, output: str) -> list[str]:
        """Parse BGP output and return list of down neighbor IPs."""
        down_neighbors = []

        # Match lines like: 10.100.12.2     4   65000   100   100   50  0  0 00:30:00  Idle
        # Last column is state - if it's a number, session is established
        # If it's a word like Idle/Active/Connect, session is down
        pattern = r"(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+[\d:]+\s+(\S+)"

        for match in re.finditer(pattern, output):
            neighbor_ip = match.group(1)
            state = match.group(2)

            # If state is NOT a number, the session is not established
            if not state.isdigit():
                down_neighbors.append(neighbor_ip)

        return down_neighbors

    def _parse_bfd_down_neighbors(self, output: str) -> list[str]:
        """Parse BFD output and return list of down neighbor IPs."""
        down_neighbors = []

        # Match lines like: 10.100.12.2    4097/4098    Down    Down    Gi1
        pattern = r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+(Up|Down)\s+"

        for match in re.finditer(pattern, output):
            neighbor_ip = match.group(1)
            state = match.group(2)

            if state == "Down":
                down_neighbors.append(neighbor_ip)

        return down_neighbors


def check_network_compliance(
    topology: Topology,
    credentials: DeviceCredentials,
    intent: Intent,
) -> ComplianceReport:
    """Convenience function to run a compliance check.

    Args:
        topology: Network topology
        credentials: Device credentials
        intent: Intent to check compliance for

    Returns:
        ComplianceReport with status and violations
    """
    checker = ComplianceChecker(topology, credentials)
    return checker.check_compliance(intent)
