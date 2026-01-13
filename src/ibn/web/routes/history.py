"""Deployment history routes."""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from ibn.state.history import DeploymentHistory
from ibn.web.deps import get_current_user

router = APIRouter()

# Deployment history instance
history = DeploymentHistory()


@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request, user: str = Depends(get_current_user)):
    """Render deployment history page."""
    templates = request.app.state.templates
    is_htmx = request.headers.get("HX-Request") == "true"

    deployments = history.list_deployments()

    if is_htmx:
        return templates.TemplateResponse(
            "partials/history.html",
            {"request": request, "user": user, "deployments": deployments},
        )

    return templates.TemplateResponse(
        "history.html",
        {"request": request, "user": user, "deployments": deployments},
    )


@router.get("/api/history")
async def list_history(user: str = Depends(get_current_user)):
    """List all deployments."""
    deployments = history.list_deployments()
    return [
        {
            "id": d.id,
            "intent_name": d.intent_name,
            "timestamp": d.timestamp,
            "status": "success" if d.success else "failed",
            "device_count": len(d.devices),
        }
        for d in deployments
    ]


@router.get("/api/history/{deployment_id}")
async def get_deployment(deployment_id: str, user: str = Depends(get_current_user)):
    """Get details of a specific deployment."""
    deployment = history.get_deployment(deployment_id)
    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")

    return {
        "id": deployment.id,
        "intent_name": deployment.intent_name,
        "timestamp": deployment.timestamp,
        "status": "success" if deployment.success else "failed",
        "devices": [
            {"hostname": d.hostname, "mgmt_ip": d.mgmt_ip, "config": d.config}
            for d in deployment.devices
        ],
        "primary_path": deployment.primary_path,
        "backup_path": deployment.backup_path,
        "notes": deployment.notes,
    }


@router.post("/api/history/{deployment_id}/rollback")
async def rollback_deployment(deployment_id: str, user: str = Depends(get_current_user)):
    """Rollback to a specific deployment.

    Note: Actual rollback requires device credentials,
    which would be provided in a production system.
    """
    deployment = history.get_deployment(deployment_id)
    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")

    return {
        "message": f"Rollback to deployment {deployment_id} would be executed",
        "deployment": deployment.intent_name,
        "note": "Requires device credentials to execute",
    }
