"""Exception hierarchy for IBN Platform.

All exceptions inherit from IBNError for consistent handling.
Specific exceptions provide context for different failure modes.
"""

from typing import Any


class IBNError(Exception):
    """Base exception for all IBN platform errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


# Topology Errors
class TopologyError(IBNError):
    """Base exception for topology-related errors."""


class TopologyLoadError(TopologyError):
    """Failed to load topology from file."""


class TopologyValidationError(TopologyError):
    """Topology data failed validation."""


class NodeNotFoundError(TopologyError):
    """Referenced node does not exist in topology."""

    def __init__(self, node_name: str) -> None:
        super().__init__(f"Node not found: {node_name}", {"node": node_name})
        self.node_name = node_name


class EdgeNotFoundError(TopologyError):
    """Referenced edge does not exist in topology."""

    def __init__(self, src: str, dst: str) -> None:
        super().__init__(f"Edge not found: {src} -> {dst}", {"src": src, "dst": dst})
        self.src = src
        self.dst = dst


# Intent Errors
class IntentError(IBNError):
    """Base exception for intent-related errors."""


class IntentParseError(IntentError):
    """Failed to parse intent YAML."""


class IntentValidationError(IntentError):
    """Intent data failed validation."""


class UnsatisfiableIntent(IntentError):
    """No solution exists that satisfies all intent constraints."""


# Solver Errors
class SolverError(IBNError):
    """Base exception for constraint solver errors."""


class SolverTimeout(SolverError):
    """Solver exceeded time limit."""


# Configuration Errors
class ConfigError(IBNError):
    """Base exception for configuration errors."""


class ConfigLoadError(ConfigError):
    """Failed to load configuration."""


class ConfigValidationError(ConfigError):
    """Configuration failed validation."""
