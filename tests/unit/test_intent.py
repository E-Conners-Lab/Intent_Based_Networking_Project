"""Unit tests for intent parser and validation."""

import tempfile
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

import pytest
import yaml

from ibn.intent.parser import IntentParser, load_intent
from ibn.intent.schema import Intent, IntentStatus
from ibn.model.topology import Topology, Node, Edge, FailureDomain
from ibn.errors import IntentParseError, IntentValidationError


def create_test_topology() -> Topology:
    """Create a test topology."""
    nodes = {
        "HQ": Node(
            name="HQ",
            loopback=IPv4Network("10.0.0.1/32"),
            mgmt_ip=IPv4Address("10.100.0.1"),
            role="hub",
        ),
        "Core1": Node(
            name="Core1",
            loopback=IPv4Network("10.0.0.2/32"),
            mgmt_ip=IPv4Address("10.100.0.2"),
            role="core",
        ),
        "Core2": Node(
            name="Core2",
            loopback=IPv4Network("10.0.0.3/32"),
            mgmt_ip=IPv4Address("10.100.0.3"),
            role="core",
        ),
        "Branch": Node(
            name="Branch",
            loopback=IPv4Network("10.0.0.4/32"),
            mgmt_ip=IPv4Address("10.100.0.4"),
            role="branch",
        ),
    }

    edges = [
        Edge(src="HQ", dst="Core1", subnet=IPv4Network("10.1.0.0/30"), latency=10, cost=10, domain="domain_a"),
        Edge(src="Core1", dst="Branch", subnet=IPv4Network("10.1.0.4/30"), latency=10, cost=10, domain="domain_a"),
        Edge(src="HQ", dst="Core2", subnet=IPv4Network("10.1.0.8/30"), latency=15, cost=15, domain="domain_b"),
        Edge(src="Core2", dst="Branch", subnet=IPv4Network("10.1.0.12/30"), latency=15, cost=15, domain="domain_b"),
    ]

    return Topology(
        nodes=nodes,
        edges=edges,
        failure_domains={
            "domain_a": FailureDomain(name="domain_a", members=["Core1"]),
            "domain_b": FailureDomain(name="domain_b", members=["Core2"]),
        },
    )


class TestIntentParser:
    """Tests for IntentParser class."""

    @pytest.fixture
    def valid_intent_yaml(self):
        """Create a valid intent YAML string."""
        return """
name: NYC Branch Connectivity
type: branch-wan
source: HQ
destination: Branch
requirements:
  latency_ms: 50
  diverse_paths: true
constraints:
  avoid_nodes: []
  avoid_domains: []
"""

    @pytest.fixture
    def temp_intent_file(self, valid_intent_yaml):
        """Create a temporary intent file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(valid_intent_yaml)
            f.flush()
            yield Path(f.name)
        Path(f.name).unlink()

    def test_parse_valid_intent(self, temp_intent_file):
        """Test parsing a valid intent file."""
        parser = IntentParser()
        intent = parser.parse(temp_intent_file)

        assert intent.name == "NYC Branch Connectivity"
        assert intent.type == "branch-wan"
        assert intent.source == "HQ"
        assert intent.destination == "Branch"
        assert intent.requirements.latency_ms == 50
        assert intent.requirements.diverse_paths is True

    def test_parse_wrapped_format(self):
        """Test parsing intent in wrapped format (intent: {...})."""
        wrapped_yaml = """
intent:
  name: Test Intent
  type: branch-wan
  source: HQ
  destination: Branch
  requirements:
    latency_ms: 50
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(wrapped_yaml)
            f.flush()
            path = Path(f.name)

        try:
            parser = IntentParser()
            intent = parser.parse(path)
            assert intent.name == "Test Intent"
        finally:
            path.unlink()

    def test_parse_nonexistent_file(self):
        """Test error on nonexistent file."""
        parser = IntentParser()

        with pytest.raises(IntentParseError) as exc_info:
            parser.parse(Path("/nonexistent/file.yaml"))
        assert "not found" in str(exc_info.value)

    def test_parse_invalid_yaml(self):
        """Test error on invalid YAML."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("invalid: yaml: content: [")
            f.flush()
            path = Path(f.name)

        try:
            parser = IntentParser()
            with pytest.raises(IntentParseError) as exc_info:
                parser.parse(path)
            assert "Invalid YAML" in str(exc_info.value)
        finally:
            path.unlink()

    def test_parse_missing_required_fields(self):
        """Test error on missing required fields."""
        incomplete_yaml = """
name: Test Intent
type: branch-wan
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(incomplete_yaml)
            f.flush()
            path = Path(f.name)

        try:
            parser = IntentParser()
            with pytest.raises(IntentValidationError):
                parser.parse(path)
        finally:
            path.unlink()

    def test_parse_and_validate(self, temp_intent_file):
        """Test parsing and validating against topology."""
        topology = create_test_topology()
        parser = IntentParser()

        intent = parser.parse_and_validate(temp_intent_file, topology)

        assert intent.status == IntentStatus.VALIDATED
        assert intent.source == "HQ"
        assert intent.destination == "Branch"

    def test_validate_invalid_source(self):
        """Test validation fails for invalid source node."""
        intent_yaml = """
name: Test Intent
type: branch-wan
source: InvalidNode
destination: Branch
requirements:
  latency_ms: 50
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(intent_yaml)
            f.flush()
            path = Path(f.name)

        try:
            topology = create_test_topology()
            parser = IntentParser()

            with pytest.raises(IntentValidationError) as exc_info:
                parser.parse_and_validate(path, topology)
            assert "Source node not found" in str(exc_info.value.details)
        finally:
            path.unlink()

    def test_validate_invalid_destination(self):
        """Test validation fails for invalid destination node."""
        intent_yaml = """
name: Test Intent
type: branch-wan
source: HQ
destination: InvalidNode
requirements:
  latency_ms: 50
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(intent_yaml)
            f.flush()
            path = Path(f.name)

        try:
            topology = create_test_topology()
            parser = IntentParser()

            with pytest.raises(IntentValidationError) as exc_info:
                parser.parse_and_validate(path, topology)
            assert "Destination node not found" in str(exc_info.value.details)
        finally:
            path.unlink()

    def test_validate_against_topology_returns_issues(self):
        """Test validate_against_topology returns list of issues."""
        topology = create_test_topology()
        parser = IntentParser()

        # Create intent with invalid avoided node
        intent = Intent(
            name="Test",
            type="branch-wan",
            source="HQ",
            destination="Branch",
            requirements={"latency_ms": 50},
            constraints={"avoid_nodes": ["NonexistentNode"]},
        )

        issues = parser.validate_against_topology(intent, topology)
        assert len(issues) > 0
        assert any("NonexistentNode" in issue for issue in issues)


class TestLoadIntent:
    """Tests for load_intent convenience function."""

    def test_load_intent(self):
        """Test the load_intent convenience function."""
        intent_yaml = """
name: Quick Test
type: branch-wan
source: HQ
destination: Branch
requirements:
  latency_ms: 100
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(intent_yaml)
            f.flush()
            path = Path(f.name)

        try:
            intent = load_intent(path)
            assert intent.name == "Quick Test"
            assert intent.requirements.latency_ms == 100
        finally:
            path.unlink()


class TestIntentDefaults:
    """Tests for intent default values."""

    def test_default_requirements(self):
        """Test default requirement values."""
        intent_yaml = """
name: Minimal Intent
type: branch-wan
source: HQ
destination: Branch
requirements:
  latency_ms: 50
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(intent_yaml)
            f.flush()
            path = Path(f.name)

        try:
            intent = load_intent(path)
            # diverse_paths defaults to True per schema
            assert intent.requirements.diverse_paths is True
        finally:
            path.unlink()

    def test_default_constraints(self):
        """Test default constraint values."""
        intent_yaml = """
name: Minimal Intent
type: branch-wan
source: HQ
destination: Branch
requirements:
  latency_ms: 50
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(intent_yaml)
            f.flush()
            path = Path(f.name)

        try:
            intent = load_intent(path)
            # Constraints should default to empty lists
            assert intent.constraints.avoid_nodes == []
            assert intent.constraints.avoid_domains == []
        finally:
            path.unlink()
