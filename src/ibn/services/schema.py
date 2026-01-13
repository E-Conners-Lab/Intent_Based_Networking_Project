"""Service model schema.

Defines the structure of service models that map intent types
to concrete network configurations.

A service model answers: "What does a 'branch-wan' intent actually
mean in terms of protocols, settings, and configurations?"
"""

from enum import Enum

from pydantic import BaseModel, Field


class RoutingProtocol(str, Enum):
    """Supported routing protocols."""
    BGP = "bgp"
    OSPF = "ospf"
    STATIC = "static"


class PathPreference(BaseModel):
    """Configuration for path preference (primary vs backup)."""

    local_preference: int = Field(
        ...,
        ge=0,
        le=4294967295,
        description="BGP local preference (higher = preferred)",
    )
    metric: int = Field(
        ...,
        ge=0,
        description="Metric/cost for this path",
    )
    community: str = Field(
        ...,
        description="BGP community string (e.g., '65000:100')",
    )
    route_map_name: str = Field(
        ...,
        description="Name of the route-map to apply",
    )


class BFDConfig(BaseModel):
    """Bidirectional Forwarding Detection configuration."""

    enabled: bool = Field(default=True)
    interval_ms: int = Field(
        default=150,
        ge=50,
        le=10000,
        description="BFD interval in milliseconds",
    )
    min_rx_ms: int = Field(
        default=150,
        ge=50,
        le=10000,
        description="Minimum receive interval in milliseconds",
    )
    multiplier: int = Field(
        default=3,
        ge=2,
        le=50,
        description="Detection multiplier",
    )


class BGPConfig(BaseModel):
    """BGP-specific configuration."""

    as_number: int = Field(
        ...,
        ge=1,
        le=4294967295,
        description="BGP AS number",
    )
    use_ibgp: bool = Field(
        default=True,
        description="Use iBGP (same AS) vs eBGP",
    )
    log_neighbor_changes: bool = Field(default=True)

    # Path preference settings
    primary_path: PathPreference = Field(
        ...,
        description="Settings for primary path",
    )
    backup_path: PathPreference = Field(
        ...,
        description="Settings for backup path",
    )


class RoutingConfig(BaseModel):
    """Routing configuration for a service."""

    protocol: RoutingProtocol = Field(
        default=RoutingProtocol.BGP,
        description="Routing protocol to use",
    )
    bgp: BGPConfig | None = Field(
        default=None,
        description="BGP configuration (if protocol is BGP)",
    )


class ServiceModel(BaseModel):
    """Complete service model definition.

    Maps an intent type to concrete configuration requirements.
    """

    name: str = Field(..., description="Service model name")
    intent_type: str = Field(
        ...,
        description="Intent type this model applies to (e.g., 'branch-wan')",
    )
    description: str = Field(default="", description="Human-readable description")

    # Routing configuration
    routing: RoutingConfig = Field(
        ...,
        description="How routing is configured for this service",
    )

    # Fast failover
    bfd: BFDConfig = Field(
        default_factory=BFDConfig,
        description="BFD configuration for fast failover",
    )

    # What prefixes to advertise
    advertise_loopbacks: bool = Field(
        default=True,
        description="Advertise source/destination loopbacks",
    )
    advertise_connected: bool = Field(
        default=False,
        description="Advertise connected subnets",
    )
