"""Intent schema models.

Pydantic models for defining network intents - what operators want
rather than how to configure it.

Example intent:
    intent:
      name: "NYC Branch Connectivity"
      type: branch-wan
      source: IBN-HQ
      destination: IBN-Branch
      requirements:
        latency_ms: 50
        availability: 99.9
        bandwidth_mbps: 100
      constraints:
        avoid_nodes: [legacy-router]
        prefer_domains: [A]
"""

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field, field_validator, model_validator


class IntentType(str, Enum):
    """Supported intent types."""

    BRANCH_WAN = "branch-wan"
    SITE_TO_SITE = "site-to-site"
    DATACENTER = "datacenter"


class IntentStatus(str, Enum):
    """Intent lifecycle status."""

    PENDING = "pending"
    VALIDATED = "validated"
    SOLVING = "solving"
    SOLVED = "solved"
    DEPLOYING = "deploying"
    ACTIVE = "active"
    FAILED = "failed"


class Requirements(BaseModel):
    """SLA requirements for the intent.

    These are the "what" - the business requirements that must be met.
    """

    latency_ms: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Maximum acceptable latency in milliseconds",
    )

    availability: float = Field(
        default=99.9,
        ge=90.0,
        le=100.0,
        description="Required availability percentage (e.g., 99.9)",
    )

    bandwidth_mbps: int = Field(
        default=100,
        ge=1,
        description="Minimum bandwidth in Mbps",
    )

    diverse_paths: bool = Field(
        default=True,
        description="Require paths through different failure domains",
    )

    encrypted: bool = Field(
        default=False,
        description="Require encryption on the path",
    )


class Constraints(BaseModel):
    """Path constraints for the solver.

    These guide the solver but don't define hard requirements.
    """

    avoid_nodes: list[str] = Field(
        default_factory=list,
        description="Nodes to avoid (e.g., EOL hardware)",
    )

    avoid_domains: list[str] = Field(
        default_factory=list,
        description="Failure domains to avoid entirely",
    )

    prefer_domains: list[str] = Field(
        default_factory=list,
        description="Failure domains to prefer for primary path",
    )

    prefer_lowest_cost: bool = Field(
        default=True,
        description="Optimize for lowest cost when SLA is met",
    )

    max_hops: int | None = Field(
        default=None,
        ge=1,
        le=20,
        description="Maximum number of hops allowed",
    )


class PathResult(BaseModel):
    """Result of path computation for an intent."""

    path: list[str] = Field(..., description="Ordered list of node names")
    total_latency_ms: int = Field(..., ge=0)
    total_cost: int = Field(..., ge=0)
    domain: str | None = Field(default=None, description="Primary failure domain used")
    hops: int = Field(..., ge=0)

    @property
    def path_string(self) -> str:
        """Human-readable path representation."""
        return " → ".join(self.path)


class SolverResult(BaseModel):
    """Complete result from the constraint solver."""

    primary_path: PathResult
    backup_path: PathResult | None = None
    solver_time_ms: int = Field(..., ge=0)
    is_diverse: bool = Field(default=False)
    meets_sla: bool = Field(default=False)
    notes: list[str] = Field(default_factory=list)


class Intent(BaseModel):
    """A network intent - declarative specification of desired connectivity.

    This is the core abstraction of IBN. Operators define what they want,
    and the platform figures out how to achieve it.
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Human-readable intent name",
    )

    type: IntentType = Field(
        default=IntentType.BRANCH_WAN,
        description="Intent type determines validation rules",
    )

    source: str = Field(
        ...,
        min_length=1,
        description="Source node name",
    )

    destination: str = Field(
        ...,
        min_length=1,
        description="Destination node name",
    )

    requirements: Requirements = Field(
        default_factory=Requirements,
        description="SLA requirements",
    )

    constraints: Constraints = Field(
        default_factory=Constraints,
        description="Path constraints for solver",
    )

    status: IntentStatus = Field(
        default=IntentStatus.PENDING,
        description="Current lifecycle status",
    )

    solver_result: SolverResult | None = Field(
        default=None,
        description="Result from constraint solver (populated after solving)",
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Ensure name is suitable for use as identifier."""
        # Allow spaces and common punctuation in display name
        return v.strip()

    @model_validator(mode="after")
    def validate_source_destination(self) -> "Intent":
        """Ensure source and destination are different."""
        if self.source == self.destination:
            raise ValueError("Source and destination must be different")
        return self

    @property
    def intent_id(self) -> str:
        """Generate a unique identifier for this intent."""
        # Slugify the name for use as ID
        slug = self.name.lower().replace(" ", "-")
        return f"{self.type.value}/{slug}"

    def meets_requirements(self, path_result: PathResult) -> tuple[bool, list[str]]:
        """Check if a path result meets this intent's requirements.

        Returns:
            Tuple of (meets_requirements, list of issues)
        """
        issues = []

        if path_result.total_latency_ms > self.requirements.latency_ms:
            issues.append(
                f"Latency {path_result.total_latency_ms}ms exceeds "
                f"requirement {self.requirements.latency_ms}ms"
            )

        if self.constraints.max_hops and path_result.hops > self.constraints.max_hops:
            issues.append(
                f"Hops {path_result.hops} exceeds maximum {self.constraints.max_hops}"
            )

        # Check avoided nodes
        for node in self.constraints.avoid_nodes:
            if node in path_result.path:
                issues.append(f"Path includes avoided node: {node}")

        return len(issues) == 0, issues


class IntentFile(BaseModel):
    """Root model for intent YAML file."""

    intent: Intent
