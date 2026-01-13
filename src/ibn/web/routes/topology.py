"""Topology visualization routes."""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from ibn.model.loader import TopologyLoader
from ibn.web.deps import get_current_user

router = APIRouter()

# Default topology file
DEFAULT_TOPOLOGY = Path(__file__).parent.parent.parent.parent.parent / "examples" / "lab.yaml"


@router.get("/topology", response_class=HTMLResponse)
async def topology_page(request: Request, user: str = Depends(get_current_user)):
    """Render topology visualization page."""
    templates = request.app.state.templates
    is_htmx = request.headers.get("HX-Request") == "true"

    if is_htmx:
        return templates.TemplateResponse(
            "partials/topology.html",
            {"request": request, "user": user},
        )

    return templates.TemplateResponse(
        "topology.html",
        {"request": request, "user": user},
    )


@router.get("/api/topology")
async def get_topology(request: Request, user: str = Depends(get_current_user)):
    """Get topology data for visualization.

    Returns nodes and edges in a format suitable for D3.js or similar.
    """
    try:
        loader = TopologyLoader()
        topology, _ = loader.load(DEFAULT_TOPOLOGY)

        nodes = []
        for name, node in topology.nodes.items():
            nodes.append({
                "id": name,
                "label": name,
                "loopback": str(node.loopback),
                "mgmt_ip": str(node.mgmt_ip),
                "role": node.role,
                "vendor": node.vendor.value,
            })

        edges = []
        for edge in topology.edges:
            edges.append({
                "source": edge.src,
                "target": edge.dst,
                "subnet": str(edge.subnet),
                "latency": edge.latency,
                "cost": edge.cost,
                "domain": edge.domain,
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "domains": list(topology.failure_domains.keys()),
        }

    except FileNotFoundError:
        return {"nodes": [], "edges": [], "domains": []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
