"""Intent management routes."""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ibn.intent.schema import Intent
from ibn.model.loader import TopologyLoader
from ibn.solver.z3_solver import DiversePathSolver
from ibn.web.deps import get_current_user

router = APIRouter()

# In-memory intent storage (use database in production)
INTENTS: list[dict[str, Any]] = []

# Default topology
DEFAULT_TOPOLOGY = Path(__file__).parent.parent.parent.parent.parent / "examples" / "lab.yaml"


class IntentCreate(BaseModel):
    """Intent creation request."""

    name: str
    type: str
    source: str
    destination: str
    requirements: dict[str, Any] = {}


class IntentSolve(BaseModel):
    """Intent solve request."""

    name: str
    type: str
    source: str
    destination: str
    requirements: dict[str, Any] = {}


@router.get("/intents", response_class=HTMLResponse)
async def intents_page(request: Request, user: str = Depends(get_current_user)):
    """Render intents management page."""
    templates = request.app.state.templates
    is_htmx = request.headers.get("HX-Request") == "true"

    if is_htmx:
        return templates.TemplateResponse(
            "partials/intents.html",
            {"request": request, "user": user, "intents": INTENTS},
        )

    return templates.TemplateResponse(
        "intents.html",
        {"request": request, "user": user, "intents": INTENTS},
    )


@router.get("/api/intents")
async def list_intents(user: str = Depends(get_current_user)):
    """List all intents."""
    return INTENTS


@router.post("/api/intents", status_code=201)
async def create_intent(intent: IntentCreate, user: str = Depends(get_current_user)):
    """Create a new intent."""
    intent_dict = {
        "id": len(INTENTS) + 1,
        "name": intent.name,
        "type": intent.type,
        "source": intent.source,
        "destination": intent.destination,
        "requirements": intent.requirements,
        "status": "created",
        "created_by": user,
    }
    INTENTS.append(intent_dict)
    return intent_dict


@router.post("/api/intents/solve")
async def solve_intent(intent_data: IntentSolve, user: str = Depends(get_current_user)):
    """Solve an intent and return paths."""
    try:
        # Load topology and graph
        loader = TopologyLoader()
        topology, graph = loader.load(DEFAULT_TOPOLOGY)

        # Create intent object
        intent = Intent(
            name=intent_data.name,
            type=intent_data.type,
            source=intent_data.source,
            destination=intent_data.destination,
            requirements=intent_data.requirements,
        )

        # Solve using Z3
        solver = DiversePathSolver(topology, graph)
        result = solver.solve(intent)

        return {
            "success": True,
            "primary_path": {
                "path": result.primary_path.path,
                "latency_ms": result.primary_path.total_latency_ms,
                "cost": result.primary_path.total_cost,
                "domain": result.primary_path.domain,
            },
            "backup_path": {
                "path": result.backup_path.path,
                "latency_ms": result.backup_path.total_latency_ms,
                "cost": result.backup_path.total_cost,
                "domain": result.backup_path.domain,
            } if result.backup_path else None,
            "solver_time_ms": result.solver_time_ms,
            "is_diverse": result.is_diverse,
            "meets_sla": result.meets_sla,
        }

    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Topology file not found")
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/api/intents/{intent_id}")
async def get_intent(intent_id: int, user: str = Depends(get_current_user)):
    """Get a specific intent."""
    for intent in INTENTS:
        if intent["id"] == intent_id:
            return intent
    raise HTTPException(status_code=404, detail="Intent not found")


@router.delete("/api/intents/{intent_id}")
async def delete_intent(intent_id: int, user: str = Depends(get_current_user)):
    """Delete an intent."""
    for i, intent in enumerate(INTENTS):
        if intent["id"] == intent_id:
            INTENTS.pop(i)
            return {"message": "Intent deleted"}
    raise HTTPException(status_code=404, detail="Intent not found")
