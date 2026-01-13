"""Unit tests for NETCONF/RESTCONF connectors.

TDD: These tests define the expected behavior before implementation.
"""

from unittest.mock import MagicMock, patch
import pytest

from ibn.deploy.netconf import (
    NetconfConnector,
    RestconfConnector,
    ConnectionResult,
    Protocol,
)
from ibn.deploy import DeviceCredentials


class TestProtocolEnum:
    """Tests for Protocol enum."""

    def test_protocol_values(self):
        """Test that all expected protocol values exist."""
        assert Protocol.SSH.value == "ssh"
        assert Protocol.NETCONF.value == "netconf"
        assert Protocol.RESTCONF.value == "restconf"


class TestConnectionResult:
    """Tests for ConnectionResult dataclass."""

    def test_success_result(self):
        """Test creating a successful result."""
        result = ConnectionResult(
            success=True,
            output="Configuration applied",
            protocol=Protocol.NETCONF,
        )
        assert result.success is True
        assert result.protocol == Protocol.NETCONF

    def test_failure_result(self):
        """Test creating a failure result."""
        result = ConnectionResult(
            success=False,
            output="Connection refused",
            protocol=Protocol.RESTCONF,
            error="timeout",
        )
        assert result.success is False
        assert result.error == "timeout"


class TestNetconfConnector:
    """Tests for NETCONF connector."""

    @pytest.fixture
    def credentials(self):
        """Create test credentials."""
        return DeviceCredentials(username="admin", password="password")

    @pytest.fixture
    def connector(self, credentials):
        """Create a NETCONF connector."""
        return NetconfConnector(credentials)

    def test_connector_initialization(self, connector, credentials):
        """Test connector initialization."""
        assert connector.credentials == credentials
        assert connector.port == 830  # Default NETCONF port

    def test_connector_custom_port(self, credentials):
        """Test connector with custom port."""
        connector = NetconfConnector(credentials, port=8300)
        assert connector.port == 8300

    @patch("ibn.deploy.netconf.manager")
    def test_get_running_config(self, mock_manager, connector):
        """Test getting running config via NETCONF."""
        # Mock the NETCONF manager
        mock_conn = MagicMock()
        mock_manager.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_manager.connect.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.get_config.return_value.data_xml = "<config>router bgp 65000</config>"

        result = connector.get_running_config("10.100.0.1", "IBN-HQ")

        assert result.success is True
        assert result.protocol == Protocol.NETCONF
        assert "router bgp" in result.output or "config" in result.output

    @patch("ibn.deploy.netconf.manager")
    def test_get_bgp_config(self, mock_manager, connector):
        """Test getting BGP config via NETCONF."""
        mock_conn = MagicMock()
        mock_manager.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_manager.connect.return_value.__exit__ = MagicMock(return_value=False)

        bgp_xml = """
        <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
            <router>
                <bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-bgp">
                    <id>65000</id>
                </bgp>
            </router>
        </native>
        """
        mock_conn.get_config.return_value.data_xml = bgp_xml

        result = connector.get_bgp_config("10.100.0.1", "IBN-HQ")

        assert result.success is True
        assert result.protocol == Protocol.NETCONF

    @patch("ibn.deploy.netconf.manager")
    def test_push_config(self, mock_manager, connector):
        """Test pushing config via NETCONF."""
        mock_conn = MagicMock()
        mock_manager.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_manager.connect.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.edit_config.return_value = MagicMock()

        config = """
        <config>
            <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
                <router>
                    <bgp xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-bgp">
                        <id>65000</id>
                    </bgp>
                </router>
            </native>
        </config>
        """
        result = connector.push_config("10.100.0.1", "IBN-HQ", config)

        assert result.success is True
        assert result.protocol == Protocol.NETCONF
        mock_conn.edit_config.assert_called_once()

    @patch("ibn.deploy.netconf.manager")
    def test_verify_bgp_neighbors(self, mock_manager, connector):
        """Test verifying BGP neighbors via NETCONF."""
        mock_conn = MagicMock()
        mock_manager.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_manager.connect.return_value.__exit__ = MagicMock(return_value=False)

        # Mock BGP neighbor state
        neighbor_xml = """
        <bgp-state-data xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-bgp-oper">
            <neighbors>
                <neighbor>
                    <neighbor-id>10.100.12.2</neighbor-id>
                    <session-state>established</session-state>
                </neighbor>
            </neighbors>
        </bgp-state-data>
        """
        mock_conn.get.return_value.data_xml = neighbor_xml

        result = connector.verify_bgp_neighbors("10.100.0.1", "IBN-HQ")

        assert result.success is True

    @patch("ibn.deploy.netconf.manager")
    def test_filter_format_is_tuple(self, mock_manager, connector):
        """Test that NETCONF filters use correct tuple format for ncclient."""
        mock_conn = MagicMock()
        mock_manager.connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_manager.connect.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.get.return_value.data_xml = "<data></data>"

        connector.verify_bgp_neighbors("10.100.0.1", "IBN-HQ")

        # Verify filter is passed as tuple ("subtree", xml_content)
        call_args = mock_conn.get.call_args
        filter_arg = call_args.kwargs.get("filter") or call_args[1].get("filter")
        assert isinstance(filter_arg, tuple), "Filter should be a tuple"
        assert filter_arg[0] == "subtree", "Filter type should be 'subtree'"
        assert "bgp-state-data" in filter_arg[1], "Filter should contain BGP state element"
        assert "<filter>" not in filter_arg[1], "Filter should NOT contain outer <filter> tag"

    @patch("ibn.deploy.netconf.manager")
    def test_connection_failure(self, mock_manager, connector):
        """Test handling connection failure."""
        mock_manager.connect.side_effect = Exception("Connection refused")

        result = connector.get_running_config("10.100.0.1", "IBN-HQ")

        assert result.success is False
        assert "Connection" in result.output or "refused" in result.output.lower()


class TestRestconfConnector:
    """Tests for RESTCONF connector."""

    @pytest.fixture
    def credentials(self):
        """Create test credentials."""
        return DeviceCredentials(username="admin", password="password")

    @pytest.fixture
    def connector(self, credentials):
        """Create a RESTCONF connector."""
        return RestconfConnector(credentials)

    def test_connector_initialization(self, connector, credentials):
        """Test connector initialization."""
        assert connector.credentials == credentials
        assert connector.port == 443  # Default RESTCONF port

    def test_connector_custom_port(self, credentials):
        """Test connector with custom port."""
        connector = RestconfConnector(credentials, port=8443)
        assert connector.port == 8443

    def test_base_url_construction(self, connector):
        """Test that base URL is constructed correctly."""
        url = connector._build_url("10.100.0.1", "/data/native")
        assert "10.100.0.1" in url
        assert "/data/native" in url
        assert "restconf" in url

    @patch("ibn.deploy.netconf.requests")
    def test_get_running_config(self, mock_requests, connector):
        """Test getting running config via RESTCONF."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Cisco-IOS-XE-native:native": {
                "router": {"bgp": {"id": 65000}}
            }
        }
        mock_requests.get.return_value = mock_response

        result = connector.get_running_config("10.100.0.1", "IBN-HQ")

        assert result.success is True
        assert result.protocol == Protocol.RESTCONF

    @patch("ibn.deploy.netconf.requests")
    def test_get_bgp_config(self, mock_requests, connector):
        """Test getting BGP config via RESTCONF."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Cisco-IOS-XE-bgp:bgp": {
                "id": 65000,
                "neighbor": [
                    {"id": "10.100.12.2", "remote-as": 65000}
                ]
            }
        }
        mock_requests.get.return_value = mock_response

        result = connector.get_bgp_config("10.100.0.1", "IBN-HQ")

        assert result.success is True
        assert result.protocol == Protocol.RESTCONF

    @patch("ibn.deploy.netconf.requests")
    def test_push_config(self, mock_requests, connector):
        """Test pushing config via RESTCONF."""
        mock_response = MagicMock()
        mock_response.status_code = 204  # No Content = success
        mock_requests.patch.return_value = mock_response

        config = {
            "Cisco-IOS-XE-bgp:bgp": {
                "id": 65000,
                "neighbor": [
                    {"id": "10.100.12.2", "remote-as": 65000}
                ]
            }
        }
        result = connector.push_config("10.100.0.1", "IBN-HQ", config)

        assert result.success is True
        assert result.protocol == Protocol.RESTCONF

    @patch("ibn.deploy.netconf.requests")
    def test_verify_bgp_neighbors(self, mock_requests, connector):
        """Test verifying BGP neighbors via RESTCONF."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Cisco-IOS-XE-bgp-oper:bgp-state-data": {
                "neighbors": {
                    "neighbor": [
                        {
                            "neighbor-id": "10.100.12.2",
                            "session-state": "established"
                        }
                    ]
                }
            }
        }
        mock_requests.get.return_value = mock_response

        result = connector.verify_bgp_neighbors("10.100.0.1", "IBN-HQ")

        assert result.success is True

    @patch("ibn.deploy.netconf.requests")
    def test_verify_bfd_neighbors(self, mock_requests, connector):
        """Test verifying BFD neighbors via RESTCONF."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "Cisco-IOS-XE-bfd-oper:bfd-state": {
                "sessions": {
                    "session": [
                        {
                            "remote-addr": "10.100.12.2",
                            "local-state": "up"
                        }
                    ]
                }
            }
        }
        mock_requests.get.return_value = mock_response

        result = connector.verify_bfd_neighbors("10.100.0.1", "IBN-HQ")

        assert result.success is True

    @patch("ibn.deploy.netconf.requests")
    def test_connection_failure(self, mock_requests, connector):
        """Test handling connection failure."""
        mock_requests.get.side_effect = Exception("Connection refused")

        result = connector.get_running_config("10.100.0.1", "IBN-HQ")

        assert result.success is False

    @patch("ibn.deploy.netconf.requests")
    def test_http_error(self, mock_requests, connector):
        """Test handling HTTP error response."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_requests.get.return_value = mock_response

        result = connector.get_running_config("10.100.0.1", "IBN-HQ")

        assert result.success is False
        assert "401" in result.output or "Unauthorized" in result.output


class TestConnectorFactory:
    """Tests for connector factory function."""

    @pytest.fixture
    def credentials(self):
        """Create test credentials."""
        return DeviceCredentials(username="admin", password="password")

    def test_create_ssh_connector(self, credentials):
        """Test creating SSH connector."""
        from ibn.deploy.netconf import create_connector
        from ibn.deploy import DeviceConnector

        connector = create_connector(credentials, Protocol.SSH)
        assert isinstance(connector, DeviceConnector)

    def test_create_netconf_connector(self, credentials):
        """Test creating NETCONF connector."""
        from ibn.deploy.netconf import create_connector

        connector = create_connector(credentials, Protocol.NETCONF)
        assert isinstance(connector, NetconfConnector)

    def test_create_restconf_connector(self, credentials):
        """Test creating RESTCONF connector."""
        from ibn.deploy.netconf import create_connector

        connector = create_connector(credentials, Protocol.RESTCONF)
        assert isinstance(connector, RestconfConnector)
