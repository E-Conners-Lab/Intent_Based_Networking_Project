"""Pydantic configuration models for IBN Platform.

Uses pydantic-settings for environment variable loading
with validation and type coercion.
"""

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class IBNSettings(BaseSettings):
    """Main application settings.

    Settings can be provided via:
    - Environment variables (prefixed with IBN_)
    - .env file in project root
    - Direct instantiation
    """

    model_config = SettingsConfigDict(
        env_prefix="IBN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Topology settings
    topology_file: Path = Field(
        default=Path("examples/lab.yaml"),
        description="Path to topology YAML file",
    )

    # Solver settings
    solver_timeout_ms: int = Field(
        default=30000,
        ge=1000,
        le=300000,
        description="Z3 solver timeout in milliseconds",
    )

    # Default constraints
    default_max_latency_ms: int = Field(
        default=50,
        ge=1,
        description="Default maximum latency constraint in ms",
    )

    # Logging
    log_level: str = Field(
        default="INFO",
        description="Logging level",
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return upper

    @field_validator("topology_file")
    @classmethod
    def validate_topology_path(cls, v: Path) -> Path:
        # Don't validate existence here - let the loader handle that
        # This allows for relative paths that make sense at runtime
        return v


def get_settings() -> IBNSettings:
    """Get application settings singleton."""
    return IBNSettings()
