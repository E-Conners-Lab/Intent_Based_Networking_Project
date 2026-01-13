"""Service models for intent types."""

from ibn.services.schema import (
    BFDConfig,
    BGPConfig,
    PathPreference,
    RoutingConfig,
    ServiceModel,
)
from ibn.services.registry import ServiceRegistry, get_service

__all__ = [
    "BFDConfig",
    "BGPConfig",
    "PathPreference",
    "RoutingConfig",
    "ServiceModel",
    "ServiceRegistry",
    "get_service",
]
