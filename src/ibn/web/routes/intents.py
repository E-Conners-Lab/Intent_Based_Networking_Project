"""Intent management routes with persistence and deploy workflow."""

import asyncio
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ibn.deploy.connector import DeviceConnector
from ibn.deploy.generator import ConfigGenerator
from ibn.intent.schema import Intent, Requirements
from ibn.model.loader import TopologyLoader
from ibn.solver.z3_solver import DiversePathSolver
from ibn.web.credentials import get_credentials
from ibn.web.deps import get_current_user
from ibn.web.lifecycle import IntentLifecycle, InvalidTransitionError
from ibn.web.persistence import IntentRepository

router = APIRouter()

# Default topology path
DEFAULT_TOPOLOGY = Path(__file__).parent.parent.parent.parent.parent / "examples" / "lab.yaml"

# Lifecycle manager
lifecycle = IntentLifecycle()


def get_repository(request: Request) -> IntentRepository:
    """Get the intent repository from app state."""
    return request.app.state.intent_repository


def load_topology():
    """Load the default topology."""
    loader = TopologyLoader()
    return loader.load(DEFAULT_TOPOLOGY)


class IntentCreate(BaseModel):
    """Intent creation request."""

    name: str
    type: str
    source: str
    destination: str
    protocol: str = "bgp"  # bgp, ospf, sr-mpls
    requirements: dict[str, Any] = {}
    constraints: dict[str, Any] = {}


# =============================================================================
# HTML Routes
# =============================================================================


@router.get("/intents", response_class=HTMLResponse)
async def intents_page(request: Request, user: str = Depends(get_current_user)):
    """Render intents management page."""
    templates = request.app.state.templates
    repo = get_repository(request)
    is_htmx = request.headers.get("HX-Request") == "true"

    intents = repo.list_all()

    if is_htmx:
        return templates.TemplateResponse(
            "partials/intents.html",
            {"request": request, "user": user, "intents": intents},
        )

    return templates.TemplateResponse(
        "intents.html",
        {"request": request, "user": user, "intents": intents},
    )


# =============================================================================
# Intent CRUD API
# =============================================================================


@router.get("/api/intents")
async def list_intents(
    request: Request,
    status: str | None = None,
    user: str = Depends(get_current_user),
):
    """List all intents, optionally filtered by status."""
    repo = get_repository(request)

    if status:
        return repo.list_by_status(status)
    return repo.list_all()


@router.post("/api/intents", status_code=201)
async def create_intent(
    request: Request,
    intent: IntentCreate,
    user: str = Depends(get_current_user),
):
    """Create a new intent."""
    repo = get_repository(request)

    intent_data = {
        "name": intent.name,
        "type": intent.type,
        "source": intent.source,
        "destination": intent.destination,
        "protocol": intent.protocol,
        "requirements": intent.requirements,
        "constraints": intent.constraints,
    }

    created = repo.create(intent_data)
    return created


@router.get("/api/intents/{intent_id}")
async def get_intent(
    request: Request,
    intent_id: str,
    user: str = Depends(get_current_user),
):
    """Get a specific intent by ID."""
    repo = get_repository(request)
    intent = repo.get(intent_id)

    if not intent:
        raise HTTPException(status_code=404, detail="Intent not found")

    return intent


@router.delete("/api/intents/{intent_id}")
async def delete_intent(
    request: Request,
    intent_id: str,
    user: str = Depends(get_current_user),
):
    """Delete an intent."""
    repo = get_repository(request)

    if not repo.delete(intent_id):
        raise HTTPException(status_code=404, detail="Intent not found")

    return {"message": "Intent deleted"}


# =============================================================================
# Solve Workflow
# =============================================================================


@router.post("/api/intents/{intent_id}/solve")
async def solve_intent(
    request: Request,
    intent_id: str,
    user: str = Depends(get_current_user),
):
    """Solve an intent using Z3 constraint solver."""
    repo = get_repository(request)
    intent_data = repo.get(intent_id)

    if not intent_data:
        raise HTTPException(status_code=404, detail="Intent not found")

    # Validate status transition
    current_status = intent_data["status"]
    if current_status not in ("pending", "failed"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot solve intent in '{current_status}' status. Must be 'pending' or 'failed'.",
        )

    # Update status to solving
    repo.update_status(intent_id, "solving")

    try:
        # Load topology
        topology, graph = load_topology()

        # Build requirements
        reqs = intent_data.get("requirements", {})

        # Create intent object
        intent = Intent(
            name=intent_data["name"],
            type=intent_data["type"],
            source=intent_data["source"],
            destination=intent_data["destination"],
            requirements=reqs,
        )

        # Solve using Z3
        solver = DiversePathSolver(topology, graph)
        result = solver.solve(intent)

        # Build solution data
        solution = {
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

        # Update with solution (sets status to solved)
        repo.update_solution(intent_id, solution)

        return {
            "success": True,
            **solution,
        }

    except Exception as e:
        # Mark as failed
        repo.update_status(intent_id, "failed")
        return {"success": False, "error": str(e)}


# Legacy endpoint for solving without persisted intent
@router.post("/api/intents/solve")
async def solve_intent_inline(
    request: Request,
    intent_data: IntentCreate,
    user: str = Depends(get_current_user),
):
    """Solve an intent inline (without persistence)."""
    try:
        topology, graph = load_topology()

        intent = Intent(
            name=intent_data.name,
            type=intent_data.type,
            source=intent_data.source,
            destination=intent_data.destination,
            requirements=intent_data.requirements,
        )

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


# =============================================================================
# Config Generation
# =============================================================================


@router.get("/api/intents/{intent_id}/configs")
async def get_configs(
    request: Request,
    intent_id: str,
    user: str = Depends(get_current_user),
):
    """Get generated configs for a solved intent."""
    repo = get_repository(request)
    intent_data = repo.get(intent_id)

    if not intent_data:
        raise HTTPException(status_code=404, detail="Intent not found")

    # Check if already has configs
    if intent_data.get("configs"):
        return {
            "configs": intent_data["configs"],
            "cached": True,
        }

    # Must be solved to generate configs
    if intent_data["status"] not in ("solved", "deploying", "deployed", "active"):
        raise HTTPException(
            status_code=400,
            detail="Intent must be solved before configs can be generated",
        )

    try:
        # Load topology for config generation
        topology, graph = load_topology()

        # Get solution
        solution = intent_data.get("solution")
        if not solution:
            raise HTTPException(status_code=400, detail="No solution found for intent")

        # Generate configs using ConfigGenerator
        # Note: This requires the generator to be properly configured
        # For now, return placeholder configs based on solution
        configs = _generate_realistic_configs(intent_data, solution, topology)

        # Store configs
        repo.update_configs(intent_id, configs)

        return {
            "configs": configs,
            "cached": False,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _get_link_ips(edge, device_name: str) -> tuple[str, str, str]:
    """Get local IP, remote IP, and interface for a device on an edge.

    Returns (local_ip, remote_ip, local_interface).
    Convention: .1 for src side, .2 for dst side of /30 subnet.
    """
    subnet_base = str(edge.subnet.network_address)
    base_parts = subnet_base.rsplit(".", 1)
    base = base_parts[0]

    if device_name == edge.src:
        local_ip = f"{base}.1"
        remote_ip = f"{base}.2"
        interface = edge.src_interface or "GigabitEthernet1"
    else:
        local_ip = f"{base}.2"
        remote_ip = f"{base}.1"
        interface = edge.dst_interface or "GigabitEthernet1"

    return local_ip, remote_ip, interface


def _find_edge_between(topology, node_a: str, node_b: str):
    """Find the edge connecting two nodes."""
    for edge in topology.edges:
        if (edge.src == node_a and edge.dst == node_b) or \
           (edge.src == node_b and edge.dst == node_a):
            return edge
    return None


def _generate_device_config(
    device_name: str,
    device,
    topology,
    primary_path: list[str],
    backup_path: list[str],
    intent_name: str,
) -> str:
    """Generate realistic Cisco IOS-XE config for a device."""
    lines = [
        f"! =====================================================",
        f"! Configuration for {device_name}",
        f"! Intent: {intent_name}",
        f"! Role: {device.role or 'unknown'}",
        f"! =====================================================",
        f"!",
    ]

    # Get router ID from loopback
    router_id = str(device.loopback.network_address)

    # Collect neighbors for this device
    neighbors = []  # [(remote_ip, remote_name, is_primary, local_interface, subnet)]

    # Check primary path neighbors
    if device_name in primary_path:
        idx = primary_path.index(device_name)
        if idx > 0:
            neighbor_name = primary_path[idx - 1]
            edge = _find_edge_between(topology, device_name, neighbor_name)
            if edge:
                local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                neighbors.append((remote_ip, neighbor_name, True, interface, edge.subnet))
        if idx < len(primary_path) - 1:
            neighbor_name = primary_path[idx + 1]
            edge = _find_edge_between(topology, device_name, neighbor_name)
            if edge:
                local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                neighbors.append((remote_ip, neighbor_name, True, interface, edge.subnet))

    # Check backup path neighbors (avoid duplicates)
    if device_name in backup_path:
        idx = backup_path.index(device_name)
        existing_neighbors = {n[1] for n in neighbors}
        if idx > 0:
            neighbor_name = backup_path[idx - 1]
            if neighbor_name not in existing_neighbors:
                edge = _find_edge_between(topology, device_name, neighbor_name)
                if edge:
                    local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                    neighbors.append((remote_ip, neighbor_name, False, interface, edge.subnet))
        if idx < len(backup_path) - 1:
            neighbor_name = backup_path[idx + 1]
            if neighbor_name not in existing_neighbors:
                edge = _find_edge_between(topology, device_name, neighbor_name)
                if edge:
                    local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                    neighbors.append((remote_ip, neighbor_name, False, interface, edge.subnet))

    # Generate interface configs
    configured_interfaces = set()
    for remote_ip, neighbor_name, is_primary, interface, subnet in neighbors:
        if interface in configured_interfaces:
            continue
        configured_interfaces.add(interface)

        local_ip, _, _ = _get_link_ips(
            _find_edge_between(topology, device_name, neighbor_name),
            device_name
        )
        mask = str(subnet.netmask)
        path_type = "PRIMARY" if is_primary else "BACKUP"

        lines.extend([
            f"interface {interface}",
            f" description Link to {neighbor_name} [{path_type}]",
            f" ip address {local_ip} {mask}",
            f" no shutdown",
            f"!",
        ])

    # Loopback interface
    lines.extend([
        f"interface Loopback0",
        f" description Router ID",
        f" ip address {router_id} 255.255.255.255",
        f"!",
    ])

    # BGP configuration
    lines.extend([
        f"router bgp 65000",
        f" bgp router-id {router_id}",
        f" bgp log-neighbor-changes",
        f" no bgp default ipv4-unicast",
        f" !",
    ])

    # BGP neighbors
    for remote_ip, neighbor_name, is_primary, interface, subnet in neighbors:
        neighbor_device = topology.nodes.get(neighbor_name)
        remote_router_id = str(neighbor_device.loopback.network_address) if neighbor_device else remote_ip
        path_type = "PRIMARY" if is_primary else "BACKUP"

        lines.extend([
            f" ! Neighbor: {neighbor_name} [{path_type}]",
            f" neighbor {remote_ip} remote-as 65000",
            f" neighbor {remote_ip} description {neighbor_name}",
            f" neighbor {remote_ip} update-source {interface}",
            f" neighbor {remote_ip} fall-over bfd",
            f" !",
        ])

    # Address family
    lines.extend([
        f" address-family ipv4",
        f"  network {router_id} mask 255.255.255.255",
    ])

    for remote_ip, neighbor_name, is_primary, interface, subnet in neighbors:
        lines.append(f"  neighbor {remote_ip} activate")

    lines.extend([
        f" exit-address-family",
        f"!",
    ])

    # BFD for fast failover
    lines.extend([
        f"bfd-template single-hop IBN-BFD",
        f" interval min-tx 100 min-rx 100 multiplier 3",
        f"!",
    ])

    return "\n".join(lines)


def _generate_ospf_config(
    device_name: str,
    device,
    topology,
    primary_path: list[str],
    backup_path: list[str],
    intent_name: str,
) -> str:
    """Generate OSPF config for a device."""
    lines = [
        f"! =====================================================",
        f"! Configuration for {device_name}",
        f"! Intent: {intent_name}",
        f"! Protocol: OSPF",
        f"! Role: {device.role or 'unknown'}",
        f"! =====================================================",
        f"!",
    ]

    router_id = str(device.loopback.network_address)

    # Collect neighbors and interfaces
    neighbors = []
    if device_name in primary_path:
        idx = primary_path.index(device_name)
        if idx > 0:
            neighbor_name = primary_path[idx - 1]
            edge = _find_edge_between(topology, device_name, neighbor_name)
            if edge:
                local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                neighbors.append((remote_ip, neighbor_name, True, interface, edge.subnet, edge.cost))
        if idx < len(primary_path) - 1:
            neighbor_name = primary_path[idx + 1]
            edge = _find_edge_between(topology, device_name, neighbor_name)
            if edge:
                local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                neighbors.append((remote_ip, neighbor_name, True, interface, edge.subnet, edge.cost))

    if device_name in backup_path:
        idx = backup_path.index(device_name)
        existing = {n[1] for n in neighbors}
        if idx > 0:
            neighbor_name = backup_path[idx - 1]
            if neighbor_name not in existing:
                edge = _find_edge_between(topology, device_name, neighbor_name)
                if edge:
                    local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                    neighbors.append((remote_ip, neighbor_name, False, interface, edge.subnet, edge.cost))
        if idx < len(backup_path) - 1:
            neighbor_name = backup_path[idx + 1]
            if neighbor_name not in existing:
                edge = _find_edge_between(topology, device_name, neighbor_name)
                if edge:
                    local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                    neighbors.append((remote_ip, neighbor_name, False, interface, edge.subnet, edge.cost))

    # Interface configs
    configured_interfaces = set()
    for remote_ip, neighbor_name, is_primary, interface, subnet, cost in neighbors:
        if interface in configured_interfaces:
            continue
        configured_interfaces.add(interface)

        local_ip, _, _ = _get_link_ips(
            _find_edge_between(topology, device_name, neighbor_name),
            device_name
        )
        mask = str(subnet.netmask)
        path_type = "PRIMARY" if is_primary else "BACKUP"

        lines.extend([
            f"interface {interface}",
            f" description Link to {neighbor_name} [{path_type}]",
            f" ip address {local_ip} {mask}",
            f" ip ospf 1 area 0",
            f" ip ospf cost {cost}",
            f" ip ospf bfd",
            f" no shutdown",
            f"!",
        ])

    # Loopback
    lines.extend([
        f"interface Loopback0",
        f" description Router ID",
        f" ip address {router_id} 255.255.255.255",
        f" ip ospf 1 area 0",
        f"!",
    ])

    # OSPF process
    lines.extend([
        f"router ospf 1",
        f" router-id {router_id}",
        f" log-adjacency-changes",
        f" passive-interface default",
    ])

    for _, neighbor_name, _, interface, _, _ in neighbors:
        lines.append(f" no passive-interface {interface}")

    lines.extend([
        f" bfd all-interfaces",
        f"!",
    ])

    # BFD
    lines.extend([
        f"bfd-template single-hop IBN-BFD",
        f" interval min-tx 100 min-rx 100 multiplier 3",
        f"!",
    ])

    return "\n".join(lines)


def _generate_sr_mpls_config(
    device_name: str,
    device,
    topology,
    primary_path: list[str],
    backup_path: list[str],
    intent_name: str,
) -> str:
    """Generate Segment Routing MPLS config for a device."""
    lines = [
        f"! =====================================================",
        f"! Configuration for {device_name}",
        f"! Intent: {intent_name}",
        f"! Protocol: SR-MPLS (Segment Routing with MPLS)",
        f"! Role: {device.role or 'unknown'}",
        f"! =====================================================",
        f"!",
    ]

    router_id = str(device.loopback.network_address)
    # Generate node SID from last octet of loopback (e.g., 10.100.0.1 -> SID 1)
    node_sid = int(router_id.split(".")[-1])

    # Collect neighbors
    neighbors = []
    if device_name in primary_path:
        idx = primary_path.index(device_name)
        if idx > 0:
            neighbor_name = primary_path[idx - 1]
            edge = _find_edge_between(topology, device_name, neighbor_name)
            if edge:
                local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                neighbors.append((remote_ip, neighbor_name, True, interface, edge.subnet, edge.cost))
        if idx < len(primary_path) - 1:
            neighbor_name = primary_path[idx + 1]
            edge = _find_edge_between(topology, device_name, neighbor_name)
            if edge:
                local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                neighbors.append((remote_ip, neighbor_name, True, interface, edge.subnet, edge.cost))

    if device_name in backup_path:
        idx = backup_path.index(device_name)
        existing = {n[1] for n in neighbors}
        if idx > 0:
            neighbor_name = backup_path[idx - 1]
            if neighbor_name not in existing:
                edge = _find_edge_between(topology, device_name, neighbor_name)
                if edge:
                    local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                    neighbors.append((remote_ip, neighbor_name, False, interface, edge.subnet, edge.cost))
        if idx < len(backup_path) - 1:
            neighbor_name = backup_path[idx + 1]
            if neighbor_name not in existing:
                edge = _find_edge_between(topology, device_name, neighbor_name)
                if edge:
                    local_ip, remote_ip, interface = _get_link_ips(edge, device_name)
                    neighbors.append((remote_ip, neighbor_name, False, interface, edge.subnet, edge.cost))

    # Interface configs
    configured_interfaces = set()
    for remote_ip, neighbor_name, is_primary, interface, subnet, cost in neighbors:
        if interface in configured_interfaces:
            continue
        configured_interfaces.add(interface)

        local_ip, _, _ = _get_link_ips(
            _find_edge_between(topology, device_name, neighbor_name),
            device_name
        )
        mask = str(subnet.netmask)
        path_type = "PRIMARY" if is_primary else "BACKUP"

        lines.extend([
            f"interface {interface}",
            f" description Link to {neighbor_name} [{path_type}]",
            f" ip address {local_ip} {mask}",
            f" ip ospf 1 area 0",
            f" ip ospf cost {cost}",
            f" mpls ip",
            f" no shutdown",
            f"!",
        ])

    # Loopback with prefix-SID
    lines.extend([
        f"interface Loopback0",
        f" description Router ID / Node SID {node_sid}",
        f" ip address {router_id} 255.255.255.255",
        f" ip ospf 1 area 0",
        f"!",
    ])

    # Segment Routing global block
    lines.extend([
        f"segment-routing mpls",
        f" global-block 16000 23999",
        f" !",
        f" connected-prefix-sid-map",
        f"  address-family ipv4",
        f"   {router_id}/32 index {node_sid} range 1",
        f"  exit-address-family",
        f"!",
    ])

    # OSPF with SR extensions
    lines.extend([
        f"router ospf 1",
        f" router-id {router_id}",
        f" log-adjacency-changes",
        f" passive-interface default",
    ])

    for _, neighbor_name, _, interface, _, _ in neighbors:
        lines.append(f" no passive-interface {interface}")

    lines.extend([
        f" segment-routing mpls",
        f" segment-routing prefix-sid-map advertise-local",
        f"!",
    ])

    # TI-LFA for fast reroute
    lines.extend([
        f"! TI-LFA (Topology-Independent Loop-Free Alternate)",
        f"router ospf 1",
        f" fast-reroute per-prefix enable area 0 prefix-priority high",
        f" fast-reroute per-prefix ti-lfa enable area 0",
        f"!",
    ])

    return "\n".join(lines)


def _generate_realistic_configs(
    intent_data: dict,
    solution: dict,
    topology,
) -> dict[str, str]:
    """Generate realistic Cisco IOS-XE configs based on solution paths."""
    configs = {}
    protocol = intent_data.get("protocol", "bgp")

    primary_path = solution.get("primary_path", {}).get("path", [])
    backup_path = solution.get("backup_path", {}).get("path", []) if solution.get("backup_path") else []

    all_devices = set(primary_path + backup_path)

    # Select generator based on protocol
    if protocol == "ospf":
        generator = _generate_ospf_config
    elif protocol == "sr-mpls":
        generator = _generate_sr_mpls_config
    else:  # default to bgp
        generator = _generate_device_config

    for device_name in all_devices:
        device = topology.nodes.get(device_name)
        if not device:
            continue

        configs[device_name] = generator(
            device_name=device_name,
            device=device,
            topology=topology,
            primary_path=primary_path,
            backup_path=backup_path,
            intent_name=intent_data["name"],
        )

    return configs


# =============================================================================
# Deploy Workflow
# =============================================================================


@router.post("/api/intents/{intent_id}/deploy")
async def deploy_intent(
    request: Request,
    intent_id: str,
    user: str = Depends(get_current_user),
):
    """Deploy an intent's configurations to devices."""
    repo = get_repository(request)
    intent_data = repo.get(intent_id)

    if not intent_data:
        raise HTTPException(status_code=404, detail="Intent not found")

    # Check status - allow retry from failed or solved
    if intent_data["status"] not in ("solved", "failed"):
        raise HTTPException(
            status_code=400,
            detail=f"Intent must be solved before deployment. Current status: {intent_data['status']}",
        )

    # If retrying from failed, check we have a solution
    if intent_data["status"] == "failed" and not intent_data.get("solution"):
        raise HTTPException(
            status_code=400,
            detail="Intent has no solution. Please solve first.",
        )

    # Check credentials
    creds = get_credentials()
    if not creds:
        raise HTTPException(
            status_code=400,
            detail="Device credentials not configured. Set IBN_DEVICE_USER and IBN_DEVICE_PASS.",
        )

    # Get or generate configs
    configs = intent_data.get("configs")
    if not configs:
        # Generate configs first
        config_response = await get_configs(request, intent_id, user)
        configs = config_response.get("configs", {})

    # Update status to deploying
    repo.update_status(intent_id, "deploying")

    try:
        # Load topology for device info
        topology, _ = load_topology()

        results = {}
        all_success = True

        for device_name, config in configs.items():
            device = topology.nodes.get(device_name)
            if not device:
                results[device_name] = {"success": False, "message": "Device not found in topology"}
                all_success = False
                continue

            try:
                connector = DeviceConnector(
                    credentials=creds,
                    device_type=DeviceConnector._get_netmiko_device_type(device.vendor),
                )

                # Run in thread pool to avoid async/sync conflicts with Netmiko
                result = await asyncio.to_thread(
                    connector.deploy_config,
                    host=str(device.mgmt_ip),
                    config=config,
                    hostname=device_name,
                )
                results[device_name] = {
                    "success": result.success,
                    "message": result.message,
                    "config_lines": result.config_lines,
                }

                if not result.success:
                    all_success = False

            except Exception as e:
                results[device_name] = {"success": False, "message": str(e)}
                all_success = False

        # Record deployment
        repo.record_deployment(intent_id, all_success, results)

        if all_success:
            repo.update_status(intent_id, "deployed")
        else:
            repo.update_status(intent_id, "failed")

        return {
            "success": all_success,
            "results": results,
        }

    except Exception as e:
        repo.update_status(intent_id, "failed")
        repo.record_deployment(intent_id, False, {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Verify Workflow
# =============================================================================


@router.post("/api/intents/{intent_id}/verify")
async def verify_intent(
    request: Request,
    intent_id: str,
    user: str = Depends(get_current_user),
):
    """Verify deployment by checking BGP/BFD sessions."""
    repo = get_repository(request)
    intent_data = repo.get(intent_id)

    if not intent_data:
        raise HTTPException(status_code=404, detail="Intent not found")

    # Check status
    if intent_data["status"] not in ("deployed",):
        raise HTTPException(
            status_code=400,
            detail=f"Intent must be deployed before verification. Current status: {intent_data['status']}",
        )

    # Check credentials
    creds = get_credentials()
    if not creds:
        raise HTTPException(
            status_code=400,
            detail="Device credentials not configured.",
        )

    # Update status to verifying
    repo.update_status(intent_id, "verifying")

    try:
        topology, _ = load_topology()
        solution = intent_data.get("solution", {})

        primary_path = solution.get("primary_path", {}).get("path", [])
        backup_path = solution.get("backup_path", {}).get("path", []) if solution.get("backup_path") else []
        all_devices = set(primary_path + backup_path)

        results = {}
        all_verified = True

        for device_name in all_devices:
            device = topology.nodes.get(device_name)
            if not device:
                continue

            try:
                connector = DeviceConnector(
                    credentials=creds,
                    device_type=DeviceConnector._get_netmiko_device_type(device.vendor),
                )

                # Verify BGP/OSPF neighbors based on protocol
                # Run in thread pool to avoid async/sync conflicts with Netmiko
                protocol = intent_data.get("protocol", "bgp")
                if protocol == "bgp":
                    verify_result = await asyncio.to_thread(
                        connector.verify_bgp_neighbors,
                        host=str(device.mgmt_ip),
                        hostname=device_name,
                    )
                else:
                    # OSPF/SR-MPLS use OSPF neighbors
                    verify_result = await asyncio.to_thread(
                        connector.verify,
                        host=str(device.mgmt_ip),
                        command="show ip ospf neighbor",
                        hostname=device_name,
                    )

                results[device_name] = {
                    "routing": {
                        "success": verify_result.success,
                        "output": verify_result.output[:500] if verify_result.output else None,
                    },
                }

                if not verify_result.success:
                    all_verified = False

            except Exception as e:
                results[device_name] = {"error": str(e)}
                all_verified = False

        if all_verified:
            repo.update_status(intent_id, "active")
        else:
            repo.update_status(intent_id, "failed")

        return {
            "verified": all_verified,
            "results": results,
        }

    except Exception as e:
        repo.update_status(intent_id, "failed")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Re-check (verify without status change)
# =============================================================================


@router.post("/api/intents/{intent_id}/recheck")
async def recheck_intent(
    request: Request,
    intent_id: str,
    user: str = Depends(get_current_user),
):
    """Re-check routing status without changing intent state."""
    repo = get_repository(request)
    intent_data = repo.get(intent_id)

    if not intent_data:
        raise HTTPException(status_code=404, detail="Intent not found")

    # Check credentials
    creds = get_credentials()
    if not creds:
        raise HTTPException(
            status_code=400,
            detail="Device credentials not configured.",
        )

    try:
        topology, _ = load_topology()
        solution = intent_data.get("solution", {})

        primary_path = solution.get("primary_path", {}).get("path", [])
        backup_path = solution.get("backup_path", {}).get("path", []) if solution.get("backup_path") else []
        all_devices = set(primary_path + backup_path)

        results = {}

        for device_name in all_devices:
            device = topology.nodes.get(device_name)
            if not device:
                continue

            try:
                connector = DeviceConnector(
                    credentials=creds,
                    device_type=DeviceConnector._get_netmiko_device_type(device.vendor),
                )

                # Check BGP/OSPF neighbors based on protocol
                # Run in thread pool to avoid async/sync conflicts with Netmiko
                protocol = intent_data.get("protocol", "bgp")
                if protocol == "bgp":
                    verify_result = await asyncio.to_thread(
                        connector.verify_bgp_neighbors,
                        host=str(device.mgmt_ip),
                        hostname=device_name,
                    )
                else:
                    # OSPF/SR-MPLS use OSPF neighbors
                    verify_result = await asyncio.to_thread(
                        connector.verify,
                        host=str(device.mgmt_ip),
                        command="show ip ospf neighbor",
                        hostname=device_name,
                    )

                results[device_name] = {
                    "routing": {
                        "success": verify_result.success,
                        "output": verify_result.output if verify_result.output else None,
                    },
                }

            except Exception as e:
                results[device_name] = {"error": str(e)}

        return {"results": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Deployment History
# =============================================================================


@router.get("/api/intents/{intent_id}/deployments")
async def get_deployment_history(
    request: Request,
    intent_id: str,
    user: str = Depends(get_current_user),
):
    """Get deployment history for an intent."""
    repo = get_repository(request)

    if not repo.get(intent_id):
        raise HTTPException(status_code=404, detail="Intent not found")

    history = repo.get_deployment_history(intent_id)
    return {"deployments": history}
