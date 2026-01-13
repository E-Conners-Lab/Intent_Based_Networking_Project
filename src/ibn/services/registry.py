"""Service model registry.

Pre-defined service models for each intent type.
"""

from ibn.services.schema import (
    BFDConfig,
    BGPConfig,
    PathPreference,
    RoutingConfig,
    RoutingProtocol,
    ServiceModel,
)


# =============================================================================
# BRANCH-WAN SERVICE MODEL
# =============================================================================
# This defines what a "branch-wan" intent means in terms of configuration.
# - Uses iBGP with AS 65000
# - Primary path gets local-preference 200 (higher = preferred)
# - Backup path gets local-preference 100
# - BFD enabled for fast failover (~450ms detection)
# =============================================================================

BRANCH_WAN_SERVICE = ServiceModel(
    name="Branch WAN Connectivity",
    intent_type="branch-wan",
    description=(
        "Dual-homed branch connectivity with diverse paths. "
        "Uses iBGP with local-preference for path selection and "
        "BFD for sub-second failover."
    ),
    routing=RoutingConfig(
        protocol=RoutingProtocol.BGP,
        bgp=BGPConfig(
            as_number=65000,
            use_ibgp=True,
            log_neighbor_changes=True,
            primary_path=PathPreference(
                local_preference=200,  # Higher = preferred
                metric=100,
                community="65000:100",
                route_map_name="PRIMARY-PATH",
            ),
            backup_path=PathPreference(
                local_preference=100,  # Lower = less preferred
                metric=200,
                community="65000:200",
                route_map_name="BACKUP-PATH",
            ),
        ),
    ),
    bfd=BFDConfig(
        enabled=True,
        interval_ms=150,
        min_rx_ms=150,
        multiplier=3,  # Failover in ~450ms
    ),
    advertise_loopbacks=True,
    advertise_connected=False,
)


# =============================================================================
# SITE-TO-SITE SERVICE MODEL
# =============================================================================
# Simple site-to-site connectivity without path diversity requirements.
# =============================================================================

SITE_TO_SITE_SERVICE = ServiceModel(
    name="Site-to-Site Connectivity",
    intent_type="site-to-site",
    description=(
        "Simple site-to-site connectivity using single best path. "
        "Uses iBGP with BFD for fast failover."
    ),
    routing=RoutingConfig(
        protocol=RoutingProtocol.BGP,
        bgp=BGPConfig(
            as_number=65000,
            use_ibgp=True,
            log_neighbor_changes=True,
            primary_path=PathPreference(
                local_preference=100,
                metric=100,
                community="65000:100",
                route_map_name="SITE-TO-SITE",
            ),
            backup_path=PathPreference(
                local_preference=100,  # Same preference - let BGP decide
                metric=100,
                community="65000:100",
                route_map_name="SITE-TO-SITE",
            ),
        ),
    ),
    bfd=BFDConfig(
        enabled=True,
        interval_ms=300,
        min_rx_ms=300,
        multiplier=3,
    ),
    advertise_loopbacks=True,
    advertise_connected=False,
)


class ServiceRegistry:
    """Registry of available service models."""

    _services: dict[str, ServiceModel] = {
        "branch-wan": BRANCH_WAN_SERVICE,
        "site-to-site": SITE_TO_SITE_SERVICE,
    }

    @classmethod
    def get(cls, intent_type: str) -> ServiceModel | None:
        """Get service model for an intent type."""
        return cls._services.get(intent_type)

    @classmethod
    def list_types(cls) -> list[str]:
        """List available intent types."""
        return list(cls._services.keys())

    @classmethod
    def register(cls, service: ServiceModel) -> None:
        """Register a new service model."""
        cls._services[service.intent_type] = service


def get_service(intent_type: str) -> ServiceModel:
    """Get service model for an intent type.

    Raises:
        ValueError: If no service model exists for the intent type.
    """
    service = ServiceRegistry.get(intent_type)
    if service is None:
        available = ", ".join(ServiceRegistry.list_types())
        raise ValueError(
            f"No service model for intent type '{intent_type}'. "
            f"Available types: {available}"
        )
    return service
