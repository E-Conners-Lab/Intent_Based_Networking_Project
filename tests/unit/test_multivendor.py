"""Unit tests for multi-vendor template support.

TDD: These tests define the expected behavior before implementation.
"""

from ipaddress import IPv4Address, IPv4Network
from unittest.mock import MagicMock, patch

import pytest

from ibn.model.topology import Node, Topology, Edge


class TestVendorEnum:
    """Tests for Vendor enum."""

    def test_vendor_values(self):
        """Test that all expected vendor values exist."""
        from ibn.model.topology import Vendor

        assert Vendor.CISCO_IOS_XE.value == "cisco-ios-xe"
        assert Vendor.ARISTA_EOS.value == "arista-eos"
        assert Vendor.JUNIPER_JUNOS.value == "juniper-junos"

    def test_vendor_from_string(self):
        """Test creating vendor from string value."""
        from ibn.model.topology import Vendor

        assert Vendor("cisco-ios-xe") == Vendor.CISCO_IOS_XE
        assert Vendor("arista-eos") == Vendor.ARISTA_EOS
        assert Vendor("juniper-junos") == Vendor.JUNIPER_JUNOS


class TestNodeVendorField:
    """Tests for Node vendor field."""

    def test_node_default_vendor(self):
        """Test that nodes default to Cisco IOS-XE."""
        node = Node(
            name="R1",
            loopback=IPv4Network("10.0.0.1/32"),
            mgmt_ip=IPv4Address("192.168.1.1"),
        )
        from ibn.model.topology import Vendor

        assert node.vendor == Vendor.CISCO_IOS_XE

    def test_node_with_arista_vendor(self):
        """Test creating node with Arista vendor."""
        from ibn.model.topology import Vendor

        node = Node(
            name="R1",
            loopback=IPv4Network("10.0.0.1/32"),
            mgmt_ip=IPv4Address("192.168.1.1"),
            vendor=Vendor.ARISTA_EOS,
        )
        assert node.vendor == Vendor.ARISTA_EOS

    def test_node_with_juniper_vendor(self):
        """Test creating node with Juniper vendor."""
        from ibn.model.topology import Vendor

        node = Node(
            name="R1",
            loopback=IPv4Network("10.0.0.1/32"),
            mgmt_ip=IPv4Address("192.168.1.1"),
            vendor=Vendor.JUNIPER_JUNOS,
        )
        assert node.vendor == Vendor.JUNIPER_JUNOS

    def test_node_vendor_from_string(self):
        """Test creating node with vendor as string."""
        node = Node(
            name="R1",
            loopback=IPv4Network("10.0.0.1/32"),
            mgmt_ip=IPv4Address("192.168.1.1"),
            vendor="arista-eos",
        )
        from ibn.model.topology import Vendor

        assert node.vendor == Vendor.ARISTA_EOS


class TestTemplateSelection:
    """Tests for template selection based on vendor."""

    @pytest.fixture
    def cisco_node(self):
        """Create a Cisco node."""
        from ibn.model.topology import Vendor

        return Node(
            name="IBN-HQ",
            loopback=IPv4Network("10.100.0.1/32"),
            mgmt_ip=IPv4Address("10.255.255.101"),
            vendor=Vendor.CISCO_IOS_XE,
        )

    @pytest.fixture
    def arista_node(self):
        """Create an Arista node."""
        from ibn.model.topology import Vendor

        return Node(
            name="IBN-HQ",
            loopback=IPv4Network("10.100.0.1/32"),
            mgmt_ip=IPv4Address("10.255.255.101"),
            vendor=Vendor.ARISTA_EOS,
        )

    @pytest.fixture
    def juniper_node(self):
        """Create a Juniper node."""
        from ibn.model.topology import Vendor

        return Node(
            name="IBN-HQ",
            loopback=IPv4Network("10.100.0.1/32"),
            mgmt_ip=IPv4Address("10.255.255.101"),
            vendor=Vendor.JUNIPER_JUNOS,
        )

    def test_select_cisco_template(self, cisco_node):
        """Test that Cisco nodes use ios-xe template."""
        from ibn.deploy.generator import ConfigGenerator

        template_path = ConfigGenerator._get_template_path(cisco_node.vendor)
        assert template_path == "cisco-ios-xe/bgp.j2"

    def test_select_arista_template(self, arista_node):
        """Test that Arista nodes use eos template."""
        from ibn.deploy.generator import ConfigGenerator

        template_path = ConfigGenerator._get_template_path(arista_node.vendor)
        assert template_path == "arista-eos/bgp.j2"

    def test_select_juniper_template(self, juniper_node):
        """Test that Juniper nodes use junos template."""
        from ibn.deploy.generator import ConfigGenerator

        template_path = ConfigGenerator._get_template_path(juniper_node.vendor)
        assert template_path == "juniper-junos/bgp.j2"


class TestMultiVendorConfigGeneration:
    """Tests for generating configs for different vendors."""

    @pytest.fixture
    def mock_topology(self):
        """Create a mock topology with mixed vendors."""
        from ibn.model.topology import Vendor

        nodes = {
            "R1": Node(
                name="R1",
                loopback=IPv4Network("10.0.0.1/32"),
                mgmt_ip=IPv4Address("192.168.1.1"),
                vendor=Vendor.CISCO_IOS_XE,
            ),
            "R2": Node(
                name="R2",
                loopback=IPv4Network("10.0.0.2/32"),
                mgmt_ip=IPv4Address("192.168.1.2"),
                vendor=Vendor.ARISTA_EOS,
            ),
            "R3": Node(
                name="R3",
                loopback=IPv4Network("10.0.0.3/32"),
                mgmt_ip=IPv4Address("192.168.1.3"),
                vendor=Vendor.JUNIPER_JUNOS,
            ),
        }
        edges = [
            Edge(
                src="R1",
                dst="R2",
                subnet=IPv4Network("10.1.12.0/30"),
                latency=10,
                cost=10,
            ),
            Edge(
                src="R2",
                dst="R3",
                subnet=IPv4Network("10.1.23.0/30"),
                latency=10,
                cost=10,
            ),
        ]
        return Topology(nodes=nodes, edges=edges)

    def test_mixed_vendor_topology(self, mock_topology):
        """Test that topology can contain mixed vendors."""
        from ibn.model.topology import Vendor

        assert mock_topology.nodes["R1"].vendor == Vendor.CISCO_IOS_XE
        assert mock_topology.nodes["R2"].vendor == Vendor.ARISTA_EOS
        assert mock_topology.nodes["R3"].vendor == Vendor.JUNIPER_JUNOS


class TestDeviceConnectorVendor:
    """Tests for vendor-aware device connector."""

    def test_get_netmiko_device_type_cisco(self):
        """Test Netmiko device type for Cisco."""
        from ibn.model.topology import Vendor
        from ibn.deploy.connector import DeviceConnector

        device_type = DeviceConnector._get_netmiko_device_type(Vendor.CISCO_IOS_XE)
        assert device_type == "cisco_ios"  # cisco_ios works better for keyboard-interactive auth

    def test_get_netmiko_device_type_arista(self):
        """Test Netmiko device type for Arista."""
        from ibn.model.topology import Vendor
        from ibn.deploy.connector import DeviceConnector

        device_type = DeviceConnector._get_netmiko_device_type(Vendor.ARISTA_EOS)
        assert device_type == "arista_eos"

    def test_get_netmiko_device_type_juniper(self):
        """Test Netmiko device type for Juniper."""
        from ibn.model.topology import Vendor
        from ibn.deploy.connector import DeviceConnector

        device_type = DeviceConnector._get_netmiko_device_type(Vendor.JUNIPER_JUNOS)
        assert device_type == "juniper_junos"


class TestVendorSpecificCommands:
    """Tests for vendor-specific CLI commands."""

    def test_cisco_bgp_summary_command(self):
        """Test Cisco BGP summary command."""
        from ibn.model.topology import Vendor
        from ibn.deploy.connector import DeviceConnector

        cmd = DeviceConnector._get_bgp_summary_command(Vendor.CISCO_IOS_XE)
        assert cmd == "show ip bgp summary"

    def test_arista_bgp_summary_command(self):
        """Test Arista BGP summary command."""
        from ibn.model.topology import Vendor
        from ibn.deploy.connector import DeviceConnector

        cmd = DeviceConnector._get_bgp_summary_command(Vendor.ARISTA_EOS)
        assert cmd == "show ip bgp summary"

    def test_juniper_bgp_summary_command(self):
        """Test Juniper BGP summary command."""
        from ibn.model.topology import Vendor
        from ibn.deploy.connector import DeviceConnector

        cmd = DeviceConnector._get_bgp_summary_command(Vendor.JUNIPER_JUNOS)
        assert cmd == "show bgp summary"

    def test_cisco_bfd_command(self):
        """Test Cisco BFD command."""
        from ibn.model.topology import Vendor
        from ibn.deploy.connector import DeviceConnector

        cmd = DeviceConnector._get_bfd_neighbors_command(Vendor.CISCO_IOS_XE)
        assert cmd == "show bfd neighbors"

    def test_arista_bfd_command(self):
        """Test Arista BFD command."""
        from ibn.model.topology import Vendor
        from ibn.deploy.connector import DeviceConnector

        cmd = DeviceConnector._get_bfd_neighbors_command(Vendor.ARISTA_EOS)
        assert cmd == "show bfd peers"

    def test_juniper_bfd_command(self):
        """Test Juniper BFD command."""
        from ibn.model.topology import Vendor
        from ibn.deploy.connector import DeviceConnector

        cmd = DeviceConnector._get_bfd_neighbors_command(Vendor.JUNIPER_JUNOS)
        assert cmd == "show bfd session"
