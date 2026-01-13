"""Real-time monitoring routes."""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from ibn.model.loader import TopologyLoader
from ibn.web.deps import get_current_user

router = APIRouter()

# Default topology
DEFAULT_TOPOLOGY = Path(__file__).parent.parent.parent.parent.parent / "examples" / "lab.yaml"


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
        {"request": request, "user": user},
    )


@router.get("/api/monitor/status")
async def get_status(request: Request, user: str = Depends(get_current_user)):
    """Get device status overview.

    Returns status without actually connecting to devices (for demo).
    In production, this would use DeviceConnector.
    """
    is_htmx = request.headers.get("HX-Request") == "true"

    try:
        loader = TopologyLoader()
        topology, _ = loader.load(DEFAULT_TOPOLOGY)

        devices = []
        for name, node in topology.nodes.items():
            devices.append({
                "name": name,
                "mgmt_ip": str(node.mgmt_ip),
                "vendor": node.vendor.value,
                "status": "unknown",  # Would be checked via connector
                "bgp_status": "unknown",
                "bfd_status": "unknown",
            })

        if is_htmx:
            templates = request.app.state.templates
            return templates.TemplateResponse(
                "partials/status_table.html",
                {"request": request, "devices": devices},
            )

        return {"devices": devices}

    except FileNotFoundError:
        return {"devices": []}


@router.get("/api/monitor/bgp")
async def get_bgp_status(
    request: Request,
    user: str = Depends(get_current_user),
):
    """Get BGP neighbor status for all devices.

    In production, this would use DeviceConnector to query devices.
    """
    try:
        loader = TopologyLoader()
        topology, _ = loader.load(DEFAULT_TOPOLOGY)

        bgp_status: list[dict[str, Any]] = []
        for name, node in topology.nodes.items():
            bgp_status.append({
                "device": name,
                "mgmt_ip": str(node.mgmt_ip),
                "neighbors": [],  # Would be populated by DeviceConnector
                "status": "not_checked",
            })

        return {"bgp_status": bgp_status}

    except FileNotFoundError:
        return {"bgp_status": []}


@router.get("/api/monitor/bfd")
async def get_bfd_status(
    request: Request,
    user: str = Depends(get_current_user),
):
    """Get BFD session status for all devices."""
    try:
        loader = TopologyLoader()
        topology, _ = loader.load(DEFAULT_TOPOLOGY)

        bfd_status: list[dict[str, Any]] = []
        for name, node in topology.nodes.items():
            bfd_status.append({
                "device": name,
                "mgmt_ip": str(node.mgmt_ip),
                "sessions": [],  # Would be populated by DeviceConnector
                "status": "not_checked",
            })

        return {"bfd_status": bfd_status}

    except FileNotFoundError:
        return {"bfd_status": []}
