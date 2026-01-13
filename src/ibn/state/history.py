"""Deployment History for IBN Platform.

Tracks deployment history and enables rollback to previous configurations.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class DeviceSnapshot:
    """Snapshot of a device's configuration at a point in time."""
    hostname: str
    mgmt_ip: str
    config: str  # The BGP/relevant config section
    timestamp: str


@dataclass
class DeploymentRecord:
    """Record of a single deployment operation."""
    id: str
    timestamp: str
    intent_name: str
    intent_file: str
    devices: list[DeviceSnapshot] = field(default_factory=list)
    primary_path: str = ""
    backup_path: str = ""
    success: bool = True
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeploymentRecord":
        """Create from dictionary."""
        devices = [DeviceSnapshot(**d) for d in data.pop("devices", [])]
        return cls(devices=devices, **data)


class DeploymentHistory:
    """Manages deployment history and rollback state.

    Stores deployment records in a JSON file for persistence.

    Example:
        history = DeploymentHistory()

        # Before deploying, save current state
        record = history.create_record("NYC Branch", "nyc-branch.yaml")
        record.devices.append(DeviceSnapshot(...))
        history.save_record(record)

        # Later, rollback
        last = history.get_last_deployment()
        for device in last.devices:
            # Restore device.config
    """

    DEFAULT_PATH = Path.home() / ".ibn" / "history.json"

    def __init__(self, path: Path | None = None):
        self.path = path or self.DEFAULT_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: list[DeploymentRecord] = []
        self._load()

    def _load(self) -> None:
        """Load history from disk."""
        if self.path.exists():
            try:
                with open(self.path) as f:
                    data = json.load(f)
                    self._records = [
                        DeploymentRecord.from_dict(r) for r in data.get("records", [])
                    ]
            except (json.JSONDecodeError, KeyError):
                self._records = []

    def _save(self) -> None:
        """Save history to disk."""
        data = {"records": [r.to_dict() for r in self._records]}
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)

    def create_record(self, intent_name: str, intent_file: str) -> DeploymentRecord:
        """Create a new deployment record.

        Args:
            intent_name: Name of the intent being deployed
            intent_file: Path to the intent file

        Returns:
            New DeploymentRecord (not yet saved)
        """
        now = datetime.now()
        record_id = now.strftime("%Y%m%d_%H%M%S")

        return DeploymentRecord(
            id=record_id,
            timestamp=now.isoformat(),
            intent_name=intent_name,
            intent_file=str(intent_file),
        )

    def save_record(self, record: DeploymentRecord) -> None:
        """Save a deployment record to history.

        Args:
            record: The deployment record to save
        """
        self._records.append(record)
        # Keep last 20 deployments
        if len(self._records) > 20:
            self._records = self._records[-20:]
        self._save()

    def get_last_deployment(self) -> DeploymentRecord | None:
        """Get the most recent deployment record.

        Returns:
            Last DeploymentRecord or None if no history
        """
        return self._records[-1] if self._records else None

    def get_deployment(self, record_id: str) -> DeploymentRecord | None:
        """Get a specific deployment by ID.

        Args:
            record_id: The deployment ID

        Returns:
            DeploymentRecord or None if not found
        """
        for record in self._records:
            if record.id == record_id:
                return record
        return None

    def list_deployments(self, limit: int = 10) -> list[DeploymentRecord]:
        """List recent deployments.

        Args:
            limit: Maximum number to return

        Returns:
            List of DeploymentRecords (newest first)
        """
        return list(reversed(self._records[-limit:]))

    def clear(self) -> None:
        """Clear all deployment history."""
        self._records = []
        self._save()
