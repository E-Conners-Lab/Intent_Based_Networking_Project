"""Credentials management for web dashboard.

Loads device credentials from environment variables for secure access.

Environment variables:
    IBN_DEVICE_USER: SSH username for network devices
    IBN_DEVICE_PASS: SSH password for network devices
    IBN_DEVICE_ENABLE: Enable secret (optional, for Cisco devices)

Example:
    export IBN_DEVICE_USER="admin"
    export IBN_DEVICE_PASS="your_password"
    export IBN_DEVICE_ENABLE="enable_secret"  # optional
"""

import os

from ibn.deploy.connector import DeviceCredentials


def get_credentials() -> DeviceCredentials | None:
    """Get device credentials from environment variables.

    Returns:
        DeviceCredentials if both username and password are set, None otherwise.
    """
    username = os.environ.get("IBN_DEVICE_USER")
    password = os.environ.get("IBN_DEVICE_PASS")

    if not username or not password:
        return None

    enable_secret = os.environ.get("IBN_DEVICE_ENABLE")

    return DeviceCredentials(
        username=username,
        password=password,
        enable_secret=enable_secret,
    )


def credentials_available() -> bool:
    """Check if device credentials are configured.

    Returns:
        True if both IBN_DEVICE_USER and IBN_DEVICE_PASS are set.
    """
    return bool(
        os.environ.get("IBN_DEVICE_USER") and
        os.environ.get("IBN_DEVICE_PASS")
    )
