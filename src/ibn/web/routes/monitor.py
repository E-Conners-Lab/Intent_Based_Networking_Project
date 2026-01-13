"""Real-time monitoring routes with live device support."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse

from ibn.deploy.connector import DeviceConnector
from ibn.model.loader import TopologyLoader
from ibn.web.credentials import credentials_available, get_credentials
from ibn.web.deps import get_current_user

router = APIRouter()

# Default topology
DEFAULT_TOPOLOGY = Path(__file__).parent.parent.parent.parent.parent / "examples" / "lab.yaml"

# Thread pool for blocking SSH operations
executor = ThreadPoolExecutor(max_workers=10)


def _check_device_status(connector: DeviceConnector, ip: str, name: str, vendor) -> dict:
    """Check device status (runs in thread pool)."""
    result = connector.test_connection(ip, name)
    return {
        "name": name,
        "mgmt_ip": ip,
        "vendor": vendor.value,
        "status": "up" if result.success else "down",
        "message": result.message,
    }


def _get_bgp_status(connector: DeviceConnector, ip: str, name: str, vendor) -> dict:
    """Get BGP status for a device (runs in thread pool)."""
    # Use vendor-specific command
    command = DeviceConnector._get_bgp_summary_command(vendor)
    result = connector.verify(ip, command, name)
    return {
        "device": name,
        "mgmt_ip": ip,
        "output": result.output if result.success else result.output,
        "status": "ok" if result.success else "error",
        "success": result.success,
    }


def _get_bfd_status(connector: DeviceConnector, ip: str, name: str, vendor) -> dict:
    """Get BFD status for a device (runs in thread pool)."""
    # Use vendor-specific command
    command = DeviceConnector._get_bfd_neighbors_command(vendor)
    result = connector.verify(ip, command, name)
    return {
        "device": name,
        "mgmt_ip": ip,
        "output": result.output if result.success else result.output,
        "status": "ok" if result.success else "error",
        "success": result.success,
    }


@router.get("/monitor", response_class=HTMLResponse)
async def monitor_page(request: Request, user: str = Depends(get_current_user)):
    """Render monitoring page."""
    templates = request.app.state.templates
    is_htmx = request.headers.get("HX-Request") == "true"

    if is_htmx:
        return templates.TemplateResponse(
            "partials/monitor.html",
            {"request": request, "user": user},
        )

    return templates.TemplateResponse(
        "monitor.html",
        {"request": request, "user": user, "credentials_configured": credentials_available()},
    )


@router.get("/api/monitor/status")
async def get_status(
    request: Request,
    user: str = Depends(get_current_user),
    live: bool = Query(default=False, description="Fetch live status from devices"),
):
    """Get device status overview.

    Args:
        live: If True, actually connect to devices to check status.
              Requires IBN_DEVICE_USER and IBN_DEVICE_PASS env vars.
    """
    is_htmx = request.headers.get("HX-Request") == "true"

    try:
        loader = TopologyLoader()
        topology, _ = loader.load(DEFAULT_TOPOLOGY)

        devices = []
        creds_configured = credentials_available()

        if live and creds_configured:
            # Get credentials and create connector
            creds = get_credentials()

            # Check each device in parallel using thread pool
            loop = asyncio.get_event_loop()
            tasks = []

            for name, node in topology.nodes.items():
                # Create connector with correct device type for each vendor
                device_type = DeviceConnector._get_netmiko_device_type(node.vendor)
                connector = DeviceConnector(creds, device_type=device_type)

                task = loop.run_in_executor(
                    executor,
                    _check_device_status,
                    connector,
                    str(node.mgmt_ip),
                    name,
                    node.vendor,
                )
                tasks.append(task)

            # Wait for all checks to complete
            devices = await asyncio.gather(*tasks)
        else:
            # Return placeholder data
            for name, node in topology.nodes.items():
                status = "no_credentials" if live and not creds_configured else "unknown"
                devices.append({
                    "name": name,
                    "mgmt_ip": str(node.mgmt_ip),
                    "vendor": node.vendor.value,
                    "status": status,
                    "message": "Credentials not configured" if status == "no_credentials" else "Not checked",
                })

        if is_htmx:
            templates = request.app.state.templates
            return templates.TemplateResponse(
                "partials/status_table.html",
                {"request": request, "devices": devices, "live": live},
            )

        return {
            "devices": devices,
            "credentials_configured": creds_configured,
            "live": live,
        }

    except FileNotFoundError:
        return {"devices": [], "credentials_configured": False, "live": False}


@router.get("/api/monitor/bgp")
async def get_bgp_status(
    request: Request,
    user: str = Depends(get_current_user),
    live: bool = Query(default=False, description="Fetch live BGP status"),
):
    """Get BGP neighbor status for all devices."""
    is_htmx = request.headers.get("HX-Request") == "true"

    try:
        loader = TopologyLoader()
        topology, _ = loader.load(DEFAULT_TOPOLOGY)

        bgp_status: list[dict[str, Any]] = []
        creds_configured = credentials_available()

        if live and creds_configured:
            creds = get_credentials()
            loop = asyncio.get_event_loop()
            tasks = []

            for name, node in topology.nodes.items():
                device_type = DeviceConnector._get_netmiko_device_type(node.vendor)
                connector = DeviceConnector(creds, device_type=device_type)

                task = loop.run_in_executor(
                    executor,
                    _get_bgp_status,
                    connector,
                    str(node.mgmt_ip),
                    name,
                    node.vendor,
                )
                tasks.append(task)

            bgp_status = await asyncio.gather(*tasks)
        else:
            for name, node in topology.nodes.items():
                bgp_status.append({
                    "device": name,
                    "mgmt_ip": str(node.mgmt_ip),
                    "output": "",
                    "status": "not_checked",
                    "success": False,
                })

        if is_htmx:
            templates = request.app.state.templates
            return templates.TemplateResponse(
                "partials/bgp_status.html",
                {"request": request, "bgp_status": bgp_status, "live": live},
            )

        return {"bgp_status": bgp_status, "credentials_configured": creds_configured}

    except FileNotFoundError:
        return {"bgp_status": [], "credentials_configured": False}


@router.get("/api/monitor/bfd")
async def get_bfd_status(
    request: Request,
    user: str = Depends(get_current_user),
    live: bool = Query(default=False, description="Fetch live BFD status"),
):
    """Get BFD session status for all devices."""
    is_htmx = request.headers.get("HX-Request") == "true"

    try:
        loader = TopologyLoader()
        topology, _ = loader.load(DEFAULT_TOPOLOGY)

        bfd_status: list[dict[str, Any]] = []
        creds_configured = credentials_available()

        if live and creds_configured:
            creds = get_credentials()
            loop = asyncio.get_event_loop()
            tasks = []

            for name, node in topology.nodes.items():
                device_type = DeviceConnector._get_netmiko_device_type(node.vendor)
                connector = DeviceConnector(creds, device_type=device_type)

                task = loop.run_in_executor(
                    executor,
                    _get_bfd_status,
                    connector,
                    str(node.mgmt_ip),
                    name,
                    node.vendor,
                )
                tasks.append(task)

            bfd_status = await asyncio.gather(*tasks)
        else:
            for name, node in topology.nodes.items():
                bfd_status.append({
                    "device": name,
                    "mgmt_ip": str(node.mgmt_ip),
                    "output": "",
                    "status": "not_checked",
                    "success": False,
                })

        if is_htmx:
            templates = request.app.state.templates
            return templates.TemplateResponse(
                "partials/bfd_status.html",
                {"request": request, "bfd_status": bfd_status, "live": live},
            )

        return {"bfd_status": bfd_status, "credentials_configured": creds_configured}

    except FileNotFoundError:
        return {"bfd_status": [], "credentials_configured": False}


@router.get("/api/monitor/refresh")
async def get_refresh_status(user: str = Depends(get_current_user)):
    """Get credentials status for refresh configuration."""
    return {
        "credentials_configured": credentials_available(),
        "refresh_interval_seconds": 30,
    }
