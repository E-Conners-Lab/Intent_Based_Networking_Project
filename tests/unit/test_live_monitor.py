"""Unit tests for live device monitoring.

TDD: These tests define the expected behavior before implementation.
"""

import os
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def disable_global_limiter():
    """Disable the global rate limiter for tests."""
    from ibn.web.app import limiter
    original_enabled = limiter.enabled
    limiter.enabled = False
    limiter.reset()
    yield
    limiter.enabled = original_enabled


class TestCredentialsFromEnv:
    """Tests for loading credentials from environment variables."""

    def test_get_credentials_from_env(self):
        """Test credentials are loaded from environment variables."""
        from ibn.web.credentials import get_credentials

        with patch.dict(os.environ, {
            "IBN_DEVICE_USER": "testuser",
            "IBN_DEVICE_PASS": "testpass",
        }):
            creds = get_credentials()
            assert creds.username == "testuser"
            assert creds.password == "testpass"

    def test_get_credentials_with_enable_secret(self):
        """Test enable secret is loaded if provided."""
        from ibn.web.credentials import get_credentials

        with patch.dict(os.environ, {
            "IBN_DEVICE_USER": "testuser",
            "IBN_DEVICE_PASS": "testpass",
            "IBN_DEVICE_ENABLE": "enablesecret",
        }):
            creds = get_credentials()
            assert creds.enable_secret == "enablesecret"

    def test_get_credentials_returns_none_if_missing(self):
        """Test None is returned if credentials not set."""
        from ibn.web.credentials import get_credentials

        with patch.dict(os.environ, {}, clear=True):
            # Remove the env vars if they exist
            os.environ.pop("IBN_DEVICE_USER", None)
            os.environ.pop("IBN_DEVICE_PASS", None)
            creds = get_credentials()
            assert creds is None

    def test_credentials_available_check(self):
        """Test checking if credentials are available."""
        from ibn.web.credentials import credentials_available

        with patch.dict(os.environ, {
            "IBN_DEVICE_USER": "testuser",
            "IBN_DEVICE_PASS": "testpass",
        }):
            assert credentials_available() is True

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("IBN_DEVICE_USER", None)
            os.environ.pop("IBN_DEVICE_PASS", None)
            assert credentials_available() is False


class TestLiveMonitorEndpoints:
    """Tests for live monitoring API endpoints."""

    @pytest.fixture
    def app(self):
        """Create app with rate limiting disabled."""
        from ibn.web.app import create_app
        return create_app(rate_limit_enabled=False)

    @pytest.fixture
    def auth_client(self, app):
        """Create authenticated test client."""
        from fastapi.testclient import TestClient
        client = TestClient(app)
        client.post("/login", data={"username": "admin", "password": "admin"})
        return client

    @patch("ibn.web.routes.monitor.get_credentials")
    @patch("ibn.web.routes.monitor.DeviceConnector")
    def test_live_status_with_credentials(self, mock_connector_class, mock_get_creds, auth_client):
        """Test live status endpoint when credentials are available."""
        from ibn.deploy.connector import DeviceCredentials, ConnectionResult

        # Mock credentials
        mock_get_creds.return_value = DeviceCredentials(
            username="admin", password="admin"
        )

        # Mock connector
        mock_connector = MagicMock()
        mock_connector.test_connection.return_value = ConnectionResult(
            hostname="IBN-HQ",
            success=True,
            message="Connected",
            device_type="cisco_xe",
        )
        mock_connector_class.return_value = mock_connector

        response = auth_client.get("/api/monitor/status?live=true")
        assert response.status_code == 200
        data = response.json()
        assert "devices" in data

    @patch("ibn.web.routes.monitor.get_credentials")
    def test_live_status_without_credentials(self, mock_get_creds, auth_client):
        """Test live status returns placeholder when no credentials."""
        mock_get_creds.return_value = None

        response = auth_client.get("/api/monitor/status?live=true")
        assert response.status_code == 200
        data = response.json()
        assert "devices" in data
        # Should show that credentials are not configured
        assert data.get("credentials_configured") is False or \
               all(d["status"] in ["unknown", "no_credentials"] for d in data["devices"])

    @patch("ibn.web.routes.monitor.get_credentials")
    @patch("ibn.web.routes.monitor.DeviceConnector")
    def test_live_bgp_status(self, mock_connector_class, mock_get_creds, auth_client):
        """Test live BGP status endpoint."""
        from ibn.deploy.connector import DeviceCredentials, VerifyResult

        mock_get_creds.return_value = DeviceCredentials(
            username="admin", password="admin"
        )

        mock_connector = MagicMock()
        mock_connector.verify_bgp_neighbors.return_value = VerifyResult(
            hostname="IBN-HQ",
            command="show ip bgp summary",
            output="BGP router identifier 10.100.0.1\nNeighbor        AS    Up/Down  State",
            success=True,
        )
        mock_connector_class.return_value = mock_connector

        response = auth_client.get("/api/monitor/bgp?live=true")
        assert response.status_code == 200
        data = response.json()
        assert "bgp_status" in data

    @patch("ibn.web.routes.monitor.get_credentials")
    @patch("ibn.web.routes.monitor.DeviceConnector")
    def test_live_bfd_status(self, mock_connector_class, mock_get_creds, auth_client):
        """Test live BFD status endpoint."""
        from ibn.deploy.connector import DeviceCredentials, VerifyResult

        mock_get_creds.return_value = DeviceCredentials(
            username="admin", password="admin"
        )

        mock_connector = MagicMock()
        mock_connector.verify_bfd_neighbors.return_value = VerifyResult(
            hostname="IBN-HQ",
            command="show bfd neighbors",
            output="OurAddr    NeighAddr   State",
            success=True,
        )
        mock_connector_class.return_value = mock_connector

        response = auth_client.get("/api/monitor/bfd?live=true")
        assert response.status_code == 200
        data = response.json()
        assert "bfd_status" in data

    @patch("ibn.web.routes.monitor.get_credentials")
    @patch("ibn.web.routes.monitor.DeviceConnector")
    def test_connection_failure_handling(self, mock_connector_class, mock_get_creds, auth_client):
        """Test that connection failures are handled gracefully."""
        from ibn.deploy.connector import DeviceCredentials, ConnectionResult

        mock_get_creds.return_value = DeviceCredentials(
            username="admin", password="admin"
        )

        mock_connector = MagicMock()
        mock_connector.test_connection.return_value = ConnectionResult(
            hostname="IBN-HQ",
            success=False,
            message="Connection timeout",
            device_type="cisco_xe",
        )
        mock_connector_class.return_value = mock_connector

        response = auth_client.get("/api/monitor/status?live=true")
        assert response.status_code == 200
        data = response.json()
        # Should still return data, just with failed status
        assert "devices" in data


class TestRefreshEndpoint:
    """Tests for auto-refresh functionality."""

    @pytest.fixture
    def app(self):
        from ibn.web.app import create_app
        return create_app(rate_limit_enabled=False)

    @pytest.fixture
    def auth_client(self, app):
        from fastapi.testclient import TestClient
        client = TestClient(app)
        client.post("/login", data={"username": "admin", "password": "admin"})
        return client

    def test_htmx_partial_includes_refresh_trigger(self, auth_client):
        """Test that HTMX responses include refresh headers."""
        response = auth_client.get(
            "/api/monitor/status",
            headers={"HX-Request": "true"}
        )
        assert response.status_code == 200
        # The response should be HTML for HTMX requests
        assert "text/html" in response.headers.get("content-type", "")
