"""Unit tests for compliance monitoring module.

TDD: These tests define the expected behavior of the compliance checker
before implementation.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from ibn.compliance.checker import (
    ComplianceChecker,
    ComplianceReport,
    ComplianceStatus,
    ComplianceViolation,
    ViolationType,
)


class TestComplianceStatus:
    """Tests for ComplianceStatus enum."""

    def test_status_values(self):
        """Test that all expected status values exist."""
        assert ComplianceStatus.COMPLIANT.value == "compliant"
        assert ComplianceStatus.NON_COMPLIANT.value == "non_compliant"
        assert ComplianceStatus.UNKNOWN.value == "unknown"


class TestViolationType:
    """Tests for ViolationType enum."""

    def test_violation_types(self):
        """Test that all expected violation types exist."""
        assert ViolationType.BGP_SESSION_DOWN.value == "bgp_session_down"
        assert ViolationType.BFD_SESSION_DOWN.value == "bfd_session_down"
        assert ViolationType.CONFIG_DRIFT.value == "config_drift"
        assert ViolationType.PATH_MISMATCH.value == "path_mismatch"
        assert ViolationType.DEVICE_UNREACHABLE.value == "device_unreachable"


class TestComplianceViolation:
    """Tests for ComplianceViolation dataclass."""

    def test_create_violation(self):
        """Test creating a compliance violation."""
        violation = ComplianceViolation(
            violation_type=ViolationType.BGP_SESSION_DOWN,
            device="IBN-HQ",
            message="BGP neighbor 10.100.12.2 is down",
            severity="critical",
            detected_at=datetime.now(),
        )
        assert violation.violation_type == ViolationType.BGP_SESSION_DOWN
        assert violation.device == "IBN-HQ"
        assert "BGP neighbor" in violation.message
        assert violation.severity == "critical"

    def test_violation_with_details(self):
        """Test violation with additional details."""
        violation = ComplianceViolation(
            violation_type=ViolationType.CONFIG_DRIFT,
            device="IBN-Core1",
            message="Configuration changed outside of IBN",
            severity="warning",
            detected_at=datetime.now(),
            details={"expected": "local-pref 200", "actual": "local-pref 150"},
        )
        assert violation.details["expected"] == "local-pref 200"
        assert violation.details["actual"] == "local-pref 150"


class TestComplianceReport:
    """Tests for ComplianceReport dataclass."""

    def test_create_compliant_report(self):
        """Test creating a compliant report."""
        report = ComplianceReport(
            status=ComplianceStatus.COMPLIANT,
            intent_name="NYC Branch",
            checked_at=datetime.now(),
            violations=[],
            devices_checked=["IBN-HQ", "IBN-Core1", "IBN-Core2", "IBN-Branch"],
        )
        assert report.status == ComplianceStatus.COMPLIANT
        assert report.is_compliant is True
        assert len(report.violations) == 0
        assert len(report.devices_checked) == 4

    def test_create_non_compliant_report(self):
        """Test creating a non-compliant report."""
        violation = ComplianceViolation(
            violation_type=ViolationType.BGP_SESSION_DOWN,
            device="IBN-HQ",
            message="BGP session down",
            severity="critical",
            detected_at=datetime.now(),
        )
        report = ComplianceReport(
            status=ComplianceStatus.NON_COMPLIANT,
            intent_name="NYC Branch",
            checked_at=datetime.now(),
            violations=[violation],
            devices_checked=["IBN-HQ"],
        )
        assert report.status == ComplianceStatus.NON_COMPLIANT
        assert report.is_compliant is False
        assert len(report.violations) == 1

    def test_report_violation_counts(self):
        """Test violation count methods."""
        violations = [
            ComplianceViolation(
                violation_type=ViolationType.BGP_SESSION_DOWN,
                device="IBN-HQ",
                message="BGP down",
                severity="critical",
                detected_at=datetime.now(),
            ),
            ComplianceViolation(
                violation_type=ViolationType.BFD_SESSION_DOWN,
                device="IBN-HQ",
                message="BFD down",
                severity="critical",
                detected_at=datetime.now(),
            ),
            ComplianceViolation(
                violation_type=ViolationType.CONFIG_DRIFT,
                device="IBN-Core1",
                message="Config drift",
                severity="warning",
                detected_at=datetime.now(),
            ),
        ]
        report = ComplianceReport(
            status=ComplianceStatus.NON_COMPLIANT,
            intent_name="NYC Branch",
            checked_at=datetime.now(),
            violations=violations,
            devices_checked=["IBN-HQ", "IBN-Core1"],
        )
        assert report.critical_count == 2
        assert report.warning_count == 1
        assert report.total_violations == 3


class TestComplianceChecker:
    """Tests for ComplianceChecker class."""

    @pytest.fixture
    def mock_topology(self):
        """Create a mock topology."""
        topology = MagicMock()
        topology.nodes = {
            "IBN-HQ": MagicMock(mgmt_ip="10.100.0.1"),
            "IBN-Core1": MagicMock(mgmt_ip="10.100.0.2"),
            "IBN-Core2": MagicMock(mgmt_ip="10.100.0.3"),
            "IBN-Branch": MagicMock(mgmt_ip="10.100.0.4"),
        }
        return topology

    @pytest.fixture
    def mock_intent(self):
        """Create a mock intent."""
        intent = MagicMock()
        intent.name = "NYC Branch"
        intent.source = "IBN-HQ"
        intent.destination = "IBN-Branch"
        return intent

    @pytest.fixture
    def mock_credentials(self):
        """Create mock credentials."""
        return MagicMock(username="admin", password="password")

    def test_checker_initialization(self, mock_topology, mock_credentials):
        """Test checker initialization."""
        checker = ComplianceChecker(mock_topology, mock_credentials)
        assert checker.topology == mock_topology
        assert checker.credentials == mock_credentials

    def test_check_bgp_compliance_all_up(
        self, mock_topology, mock_intent, mock_credentials
    ):
        """Test BGP compliance check when all sessions are up."""
        checker = ComplianceChecker(mock_topology, mock_credentials)

        # Mock connector to return established BGP sessions
        with patch.object(checker, "connector") as mock_connector:
            mock_connector.verify_bgp_neighbors.return_value = MagicMock(
                success=True,
                output="10.100.12.2     4   65000   100   100   50  0  0 00:30:00  10",
            )

            violations = checker.check_bgp_compliance("IBN-HQ")
            assert len(violations) == 0

    def test_check_bgp_compliance_session_down(
        self, mock_topology, mock_intent, mock_credentials
    ):
        """Test BGP compliance check when a session is down."""
        checker = ComplianceChecker(mock_topology, mock_credentials)

        with patch.object(checker, "connector") as mock_connector:
            mock_connector.verify_bgp_neighbors.return_value = MagicMock(
                success=True,
                output="10.100.12.2     4   65000   100   100   50  0  0 00:30:00  Idle",
            )

            violations = checker.check_bgp_compliance("IBN-HQ")
            assert len(violations) >= 1
            assert violations[0].violation_type == ViolationType.BGP_SESSION_DOWN

    def test_check_bfd_compliance_all_up(
        self, mock_topology, mock_intent, mock_credentials
    ):
        """Test BFD compliance check when all sessions are up."""
        checker = ComplianceChecker(mock_topology, mock_credentials)

        with patch.object(checker, "connector") as mock_connector:
            mock_connector.verify_bfd_neighbors.return_value = MagicMock(
                success=True,
                output="10.100.12.2    4097/4098    Up    Up    Gi1",
            )

            violations = checker.check_bfd_compliance("IBN-HQ")
            assert len(violations) == 0

    def test_check_bfd_compliance_session_down(
        self, mock_topology, mock_intent, mock_credentials
    ):
        """Test BFD compliance check when a session is down."""
        checker = ComplianceChecker(mock_topology, mock_credentials)

        with patch.object(checker, "connector") as mock_connector:
            mock_connector.verify_bfd_neighbors.return_value = MagicMock(
                success=True,
                output="10.100.12.2    4097/4098    Down    Down    Gi1",
            )

            violations = checker.check_bfd_compliance("IBN-HQ")
            assert len(violations) >= 1
            assert violations[0].violation_type == ViolationType.BFD_SESSION_DOWN

    def test_check_device_unreachable(
        self, mock_topology, mock_intent, mock_credentials
    ):
        """Test compliance check when device is unreachable."""
        checker = ComplianceChecker(mock_topology, mock_credentials)

        with patch.object(checker, "connector") as mock_connector:
            mock_connector.verify_bgp_neighbors.return_value = MagicMock(
                success=False,
                output="Connection timed out",
            )

            violations = checker.check_bgp_compliance("IBN-HQ")
            assert len(violations) >= 1
            assert violations[0].violation_type == ViolationType.DEVICE_UNREACHABLE

    def test_run_full_compliance_check(
        self, mock_topology, mock_intent, mock_credentials
    ):
        """Test running a full compliance check."""
        checker = ComplianceChecker(mock_topology, mock_credentials)

        with patch.object(checker, "connector") as mock_connector:
            # All devices reachable and compliant
            mock_connector.verify_bgp_neighbors.return_value = MagicMock(
                success=True,
                output="10.100.12.2     4   65000   100   100   50  0  0 00:30:00  10",
            )
            mock_connector.verify_bfd_neighbors.return_value = MagicMock(
                success=True,
                output="10.100.12.2    4097/4098    Up    Up    Gi1",
            )

            report = checker.check_compliance(mock_intent)

            assert isinstance(report, ComplianceReport)
            assert report.intent_name == "NYC Branch"

    def test_compliance_check_with_expected_state(
        self, mock_topology, mock_intent, mock_credentials
    ):
        """Test compliance check against expected state from deployment."""
        checker = ComplianceChecker(mock_topology, mock_credentials)

        expected_state = {
            "IBN-HQ": {
                "bgp_neighbors": ["10.100.12.2", "10.100.13.2"],
                "bfd_neighbors": ["10.100.12.2", "10.100.13.2"],
            }
        }

        with patch.object(checker, "connector") as mock_connector:
            mock_connector.verify_bgp_neighbors.return_value = MagicMock(
                success=True,
                output="10.100.12.2     4   65000   100   100   50  0  0 00:30:00  10",
            )
            mock_connector.verify_bfd_neighbors.return_value = MagicMock(
                success=True,
                output="10.100.12.2    4097/4098    Up    Up    Gi1",
            )
            mock_connector.get_bgp_config.return_value = MagicMock(
                success=True,
                output="neighbor 10.100.12.2 remote-as 65000",
            )

            report = checker.check_compliance(mock_intent, expected_state=expected_state)
            assert isinstance(report, ComplianceReport)


class TestComplianceReportSummary:
    """Tests for compliance report summary generation."""

    def test_summary_compliant(self):
        """Test summary for compliant report."""
        report = ComplianceReport(
            status=ComplianceStatus.COMPLIANT,
            intent_name="NYC Branch",
            checked_at=datetime.now(),
            violations=[],
            devices_checked=["IBN-HQ", "IBN-Core1", "IBN-Core2", "IBN-Branch"],
        )
        summary = report.summary()
        assert "COMPLIANT" in summary
        assert "4 devices" in summary

    def test_summary_non_compliant(self):
        """Test summary for non-compliant report."""
        violations = [
            ComplianceViolation(
                violation_type=ViolationType.BGP_SESSION_DOWN,
                device="IBN-HQ",
                message="BGP down",
                severity="critical",
                detected_at=datetime.now(),
            ),
        ]
        report = ComplianceReport(
            status=ComplianceStatus.NON_COMPLIANT,
            intent_name="NYC Branch",
            checked_at=datetime.now(),
            violations=violations,
            devices_checked=["IBN-HQ"],
        )
        summary = report.summary()
        assert "NON-COMPLIANT" in summary or "NON_COMPLIANT" in summary
        assert "1" in summary  # violation count
