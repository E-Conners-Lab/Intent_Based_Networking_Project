"""Intent parser and validator.

Loads intent YAML files, validates against schema, and checks
that referenced nodes exist in the topology.
"""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from ibn.errors import (
    IntentParseError,
    IntentValidationError,
    NodeNotFoundError,
)
from ibn.intent.schema import Intent, IntentFile, IntentStatus
from ibn.model.topology import Topology


class IntentParser:
    """Parses and validates network intents.

    Validates both the intent schema and cross-references against
    the network topology (source/destination must exist, avoided
    nodes must exist, etc.)
    """

    def parse(self, path: Path | str) -> Intent:
        """Parse intent from YAML file.

        Args:
            path: Path to intent YAML file

        Returns:
            Validated Intent object

        Raises:
            IntentParseError: If YAML is invalid
            IntentValidationError: If intent data fails validation
        """
        path = Path(path)
        raw_data = self._load_yaml(path)
        intent = self._validate_schema(raw_data)
        return intent

    def parse_and_validate(
        self,
        path: Path | str,
        topology: Topology,
    ) -> Intent:
        """Parse intent and validate against topology.

        Args:
            path: Path to intent YAML file
            topology: Network topology to validate against

        Returns:
            Validated Intent with status set to VALIDATED

        Raises:
            IntentParseError: If YAML is invalid
            IntentValidationError: If intent or topology validation fails
        """
        intent = self.parse(path)
        self._validate_against_topology(intent, topology)
        intent.status = IntentStatus.VALIDATED
        return intent

    def validate_against_topology(
        self,
        intent: Intent,
        topology: Topology,
    ) -> list[str]:
        """Validate intent against topology, returning any issues.

        Returns:
            List of validation issues (empty if valid)
        """
        issues = []

        # Check source exists
        if intent.source not in topology.nodes:
            issues.append(f"Source node not found in topology: {intent.source}")

        # Check destination exists
        if intent.destination not in topology.nodes:
            issues.append(f"Destination node not found in topology: {intent.destination}")

        # Check avoided nodes exist (warning, not error)
        for node in intent.constraints.avoid_nodes:
            if node not in topology.nodes:
                issues.append(f"Avoided node not found in topology: {node}")

        # Check avoided domains exist
        for domain in intent.constraints.avoid_domains:
            if domain not in topology.failure_domains:
                issues.append(f"Avoided domain not found in topology: {domain}")

        # Check preferred domains exist
        for domain in intent.constraints.prefer_domains:
            if domain not in topology.failure_domains:
                issues.append(f"Preferred domain not found in topology: {domain}")

        # Check that source and destination are connected
        # (This is a basic check - full path validation happens in solver)
        if not issues:  # Only check if nodes exist
            source_neighbors = topology.get_neighbors(intent.source)
            dest_neighbors = topology.get_neighbors(intent.destination)

            if not source_neighbors:
                issues.append(f"Source node {intent.source} has no connections")
            if not dest_neighbors:
                issues.append(f"Destination node {intent.destination} has no connections")

        return issues

    def _validate_against_topology(
        self,
        intent: Intent,
        topology: Topology,
    ) -> None:
        """Validate intent against topology, raising on error."""
        issues = self.validate_against_topology(intent, topology)

        if issues:
            raise IntentValidationError(
                f"Intent validation failed: {len(issues)} issue(s)",
                {"issues": issues},
            )

    def _load_yaml(self, path: Path) -> dict[str, Any]:
        """Load raw YAML data from file."""
        if not path.exists():
            raise IntentParseError(
                f"Intent file not found: {path}",
                {"path": str(path)},
            )

        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise IntentParseError(
                f"Invalid YAML in intent file: {e}",
                {"path": str(path)},
            ) from e
        except OSError as e:
            raise IntentParseError(
                f"Cannot read intent file: {e}",
                {"path": str(path)},
            ) from e

        if not isinstance(data, dict):
            raise IntentParseError(
                "Intent file must contain a YAML mapping",
                {"path": str(path)},
            )

        return data

    def _validate_schema(self, data: dict[str, Any]) -> Intent:
        """Validate raw data against Intent schema."""
        try:
            # Support both wrapped (intent: {...}) and unwrapped formats
            if "intent" in data:
                intent_file = IntentFile.model_validate(data)
                return intent_file.intent
            else:
                return Intent.model_validate(data)
        except ValidationError as e:
            raise IntentValidationError(
                f"Intent schema validation failed: {e.error_count()} error(s)",
                {"errors": e.errors()},
            ) from e


def load_intent(path: Path | str) -> Intent:
    """Convenience function to load an intent from file.

    Args:
        path: Path to intent YAML file

    Returns:
        Parsed Intent object
    """
    parser = IntentParser()
    return parser.parse(path)


def load_and_validate_intent(path: Path | str, topology: Topology) -> Intent:
    """Convenience function to load and validate an intent.

    Args:
        path: Path to intent YAML file
        topology: Topology to validate against

    Returns:
        Validated Intent object
    """
    parser = IntentParser()
    return parser.parse_and_validate(path, topology)
