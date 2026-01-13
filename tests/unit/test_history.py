"""Unit tests for deployment history module."""

import json
import tempfile
from pathlib import Path

import pytest

from ibn.state.history import DeploymentHistory, DeploymentRecord, DeviceSnapshot


class TestDeviceSnapshot:
    """Tests for DeviceSnapshot dataclass."""

    def test_create_snapshot(self):
        """Test creating a device snapshot."""
        snapshot = DeviceSnapshot(
            hostname="IBN-HQ",
            mgmt_ip="10.100.0.1",
            config="router bgp 65000\n neighbor 10.100.12.2",
            timestamp="2024-01-15T10:30:00",
        )
        assert snapshot.hostname == "IBN-HQ"
        assert snapshot.mgmt_ip == "10.100.0.1"
        assert "router bgp" in snapshot.config
        assert snapshot.timestamp == "2024-01-15T10:30:00"


class TestDeploymentRecord:
    """Tests for DeploymentRecord dataclass."""

    def test_create_record(self):
        """Test creating a deployment record."""
        record = DeploymentRecord(
            id="20240115_103000",
            timestamp="2024-01-15T10:30:00",
            intent_name="NYC Branch",
            intent_file="nyc-branch.yaml",
        )
        assert record.id == "20240115_103000"
        assert record.intent_name == "NYC Branch"
        assert record.devices == []
        assert record.success is True

    def test_record_with_devices(self):
        """Test deployment record with device snapshots."""
        snapshot = DeviceSnapshot(
            hostname="IBN-HQ",
            mgmt_ip="10.100.0.1",
            config="router bgp 65000",
            timestamp="2024-01-15T10:30:00",
        )
        record = DeploymentRecord(
            id="20240115_103000",
            timestamp="2024-01-15T10:30:00",
            intent_name="NYC Branch",
            intent_file="nyc-branch.yaml",
            devices=[snapshot],
            primary_path="HQ → Core1 → Branch",
            backup_path="HQ → Core2 → Branch",
        )
        assert len(record.devices) == 1
        assert record.devices[0].hostname == "IBN-HQ"
        assert "Core1" in record.primary_path

    def test_to_dict(self):
        """Test converting record to dictionary."""
        record = DeploymentRecord(
            id="20240115_103000",
            timestamp="2024-01-15T10:30:00",
            intent_name="NYC Branch",
            intent_file="nyc-branch.yaml",
        )
        data = record.to_dict()
        assert data["id"] == "20240115_103000"
        assert data["intent_name"] == "NYC Branch"
        assert isinstance(data["devices"], list)

    def test_from_dict(self):
        """Test creating record from dictionary."""
        data = {
            "id": "20240115_103000",
            "timestamp": "2024-01-15T10:30:00",
            "intent_name": "NYC Branch",
            "intent_file": "nyc-branch.yaml",
            "devices": [
                {
                    "hostname": "IBN-HQ",
                    "mgmt_ip": "10.100.0.1",
                    "config": "router bgp 65000",
                    "timestamp": "2024-01-15T10:30:00",
                }
            ],
            "primary_path": "HQ → Core1 → Branch",
            "backup_path": "HQ → Core2 → Branch",
            "success": True,
            "notes": "",
        }
        record = DeploymentRecord.from_dict(data)
        assert record.id == "20240115_103000"
        assert len(record.devices) == 1
        assert record.devices[0].hostname == "IBN-HQ"


class TestDeploymentHistory:
    """Tests for DeploymentHistory class."""

    @pytest.fixture
    def temp_history_path(self):
        """Create a temporary path for history file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir) / "history.json"

    def test_create_history(self, temp_history_path):
        """Test creating a new history instance."""
        history = DeploymentHistory(path=temp_history_path)
        assert history.path == temp_history_path
        assert history._records == []

    def test_create_record(self, temp_history_path):
        """Test creating a new deployment record."""
        history = DeploymentHistory(path=temp_history_path)
        record = history.create_record("NYC Branch", "nyc-branch.yaml")

        assert record.intent_name == "NYC Branch"
        assert record.intent_file == "nyc-branch.yaml"
        assert record.id  # Should have generated ID
        assert record.timestamp  # Should have timestamp

    def test_save_and_load_record(self, temp_history_path):
        """Test saving and loading records."""
        history = DeploymentHistory(path=temp_history_path)
        record = history.create_record("NYC Branch", "nyc-branch.yaml")
        record.primary_path = "HQ → Core1 → Branch"
        history.save_record(record)

        # Create new instance to load from disk
        history2 = DeploymentHistory(path=temp_history_path)
        assert len(history2._records) == 1
        loaded = history2._records[0]
        assert loaded.intent_name == "NYC Branch"
        assert loaded.primary_path == "HQ → Core1 → Branch"

    def test_get_last_deployment(self, temp_history_path):
        """Test getting the last deployment."""
        history = DeploymentHistory(path=temp_history_path)

        # No deployments yet
        assert history.get_last_deployment() is None

        # Add a deployment
        record1 = history.create_record("Intent 1", "intent1.yaml")
        history.save_record(record1)

        record2 = history.create_record("Intent 2", "intent2.yaml")
        history.save_record(record2)

        last = history.get_last_deployment()
        assert last.intent_name == "Intent 2"

    def test_get_deployment_by_id(self, temp_history_path):
        """Test getting a deployment by ID."""
        history = DeploymentHistory(path=temp_history_path)
        record = history.create_record("NYC Branch", "nyc-branch.yaml")
        record_id = record.id
        history.save_record(record)

        found = history.get_deployment(record_id)
        assert found is not None
        assert found.intent_name == "NYC Branch"

        # Non-existent ID
        assert history.get_deployment("nonexistent") is None

    def test_list_deployments(self, temp_history_path):
        """Test listing deployments."""
        history = DeploymentHistory(path=temp_history_path)

        for i in range(5):
            record = history.create_record(f"Intent {i}", f"intent{i}.yaml")
            history.save_record(record)

        # List all
        deployments = history.list_deployments(limit=10)
        assert len(deployments) == 5
        # Should be newest first
        assert deployments[0].intent_name == "Intent 4"

        # Limit results
        deployments = history.list_deployments(limit=3)
        assert len(deployments) == 3

    def test_history_limit(self, temp_history_path):
        """Test that history is limited to 20 records."""
        history = DeploymentHistory(path=temp_history_path)

        # Add 25 records
        for i in range(25):
            record = history.create_record(f"Intent {i}", f"intent{i}.yaml")
            history.save_record(record)

        # Should only keep last 20
        assert len(history._records) == 20
        # First record should be Intent 5 (0-4 were dropped)
        assert history._records[0].intent_name == "Intent 5"

    def test_clear_history(self, temp_history_path):
        """Test clearing history."""
        history = DeploymentHistory(path=temp_history_path)
        record = history.create_record("NYC Branch", "nyc-branch.yaml")
        history.save_record(record)

        assert len(history._records) == 1
        history.clear()
        assert len(history._records) == 0

        # Verify persistence
        history2 = DeploymentHistory(path=temp_history_path)
        assert len(history2._records) == 0

    def test_corrupted_history_file(self, temp_history_path):
        """Test handling of corrupted history file."""
        # Write invalid JSON
        temp_history_path.parent.mkdir(parents=True, exist_ok=True)
        with open(temp_history_path, "w") as f:
            f.write("not valid json")

        # Should not raise, just initialize empty
        history = DeploymentHistory(path=temp_history_path)
        assert history._records == []
