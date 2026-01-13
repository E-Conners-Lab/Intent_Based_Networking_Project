"""IBN Platform CLI.

Command-line interface for the Intent-Based Networking platform.
Uses Click for command parsing and Rich for output formatting.
"""

import os
from pathlib import Path

import click
from dotenv import load_dotenv

# Load .env file if present
load_dotenv()
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ibn.errors import IBNError, SolverError, SolverTimeout, UnsatisfiableIntent
from ibn.intent import IntentParser
from ibn.model.loader import TopologyLoader
from ibn.solver import DiversePathSolver, SolverConfig
from ibn.viz import TopologyDiagram

console = Console()

# Default topology file for commands that need it
DEFAULT_TOPOLOGY = Path("examples/lab.yaml")


@click.group()
@click.version_option(package_name="ibn-platform")
def main() -> None:
    """Intent-Based Networking Platform.

    Automate network configuration through declarative intents
    with constraint-based path optimization.
    """


@main.command("load-topology")
@click.argument("topology_file", type=click.Path(exists=True, path_type=Path))
def load_topology(topology_file: Path) -> None:
    """Load and validate a topology file.

    Parses the YAML topology definition, validates all nodes and edges,
    and reports topology statistics.

    TOPOLOGY_FILE: Path to the topology YAML file
    """
    try:
        loader = TopologyLoader()
        topology, graph = loader.load(topology_file)

        # Build summary table
        table = Table(title="Topology Summary", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="dim")
        table.add_column("Value", justify="right")

        table.add_row("Nodes", str(topology.node_count))
        table.add_row("Edges", str(topology.edge_count))
        table.add_row("Failure Domains", str(topology.domain_count))
        table.add_row("Graph Edges (bidirectional)", str(graph.number_of_edges()))

        console.print(table)
        console.print()

        # Node details
        node_table = Table(title="Nodes", show_header=True, header_style="bold green")
        node_table.add_column("Name")
        node_table.add_column("Loopback")
        node_table.add_column("Management IP")
        node_table.add_column("Role")

        for name, node in topology.nodes.items():
            node_table.add_row(
                name,
                str(node.loopback),
                str(node.mgmt_ip),
                node.role or "-",
            )

        console.print(node_table)
        console.print()

        # Edge details
        edge_table = Table(title="Edges", show_header=True, header_style="bold yellow")
        edge_table.add_column("Source")
        edge_table.add_column("Destination")
        edge_table.add_column("Subnet")
        edge_table.add_column("Latency (ms)", justify="right")
        edge_table.add_column("Cost", justify="right")
        edge_table.add_column("Domain")

        for edge in topology.edges:
            edge_table.add_row(
                edge.src,
                edge.dst,
                str(edge.subnet),
                str(edge.latency),
                str(edge.cost),
                edge.domain or "-",
            )

        console.print(edge_table)
        console.print()

        # Failure domains
        if topology.failure_domains:
            domain_table = Table(
                title="Failure Domains", show_header=True, header_style="bold magenta"
            )
            domain_table.add_column("Domain")
            domain_table.add_column("Members")

            for name, domain in topology.failure_domains.items():
                domain_table.add_row(name, ", ".join(domain.members))

            console.print(domain_table)
            console.print()

        # Success message
        console.print(
            Panel(
                f"[bold green]Graph: {topology.node_count} nodes, "
                f"{topology.edge_count} edges, "
                f"{topology.domain_count} failure domains[/bold green]",
                title="Topology Loaded",
                border_style="green",
            )
        )

    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        if e.details:
            console.print(f"[dim]Details: {e.details}[/dim]")
        raise SystemExit(1)


@main.command("info")
def info() -> None:
    """Show platform information."""
    from ibn import __version__

    console.print(
        Panel(
            f"[bold]IBN Platform[/bold] v{__version__}\n\n"
            "Intent-Based Networking with Z3 constraint solving\n"
            "for diverse path selection and SLA optimization.",
            title="About",
            border_style="blue",
        )
    )


@main.command("show-topology")
@click.option(
    "--topology",
    "-t",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_TOPOLOGY,
    help="Topology file",
    show_default=True,
)
def show_topology(topology: Path) -> None:
    """Display the network topology diagram.

    Shows an ASCII visualization of the network with nodes,
    links, and failure domains.
    """
    try:
        loader = TopologyLoader()
        topo, _ = loader.load(topology)

        diagram = TopologyDiagram(topo)
        diagram.show()

    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        raise SystemExit(1)


@main.command("validate-intent")
@click.argument("intent_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--topology",
    "-t",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Topology file to validate against (optional)",
)
def validate_intent(intent_file: Path, topology: Path | None) -> None:
    """Validate an intent file.

    Parses the intent YAML and validates the schema. If a topology
    file is provided, also validates that referenced nodes exist.

    INTENT_FILE: Path to the intent YAML file
    """
    try:
        parser = IntentParser()

        if topology:
            # Load topology first
            loader = TopologyLoader()
            topo, _ = loader.load(topology)

            # Parse and validate against topology
            intent = parser.parse_and_validate(intent_file, topo)
            validated_against_topology = True
        else:
            # Just validate schema
            intent = parser.parse(intent_file)
            validated_against_topology = False

        # Display intent details
        console.print()
        console.print(
            Panel(
                f"[bold]{intent.name}[/bold]\n"
                f"Type: {intent.type.value}\n"
                f"Status: {intent.status.value}",
                title="Intent",
                border_style="cyan",
            )
        )

        # Endpoints table
        endpoint_table = Table(title="Endpoints", show_header=True, header_style="bold green")
        endpoint_table.add_column("Role")
        endpoint_table.add_column("Node")

        endpoint_table.add_row("Source", intent.source)
        endpoint_table.add_row("Destination", intent.destination)

        console.print(endpoint_table)
        console.print()

        # Requirements table
        req_table = Table(title="Requirements", show_header=True, header_style="bold yellow")
        req_table.add_column("Requirement")
        req_table.add_column("Value", justify="right")

        req_table.add_row("Max Latency", f"{intent.requirements.latency_ms} ms")
        req_table.add_row("Availability", f"{intent.requirements.availability}%")
        req_table.add_row("Bandwidth", f"{intent.requirements.bandwidth_mbps} Mbps")
        req_table.add_row("Diverse Paths", "Yes" if intent.requirements.diverse_paths else "No")
        req_table.add_row("Encrypted", "Yes" if intent.requirements.encrypted else "No")

        console.print(req_table)
        console.print()

        # Constraints table
        const_table = Table(title="Constraints", show_header=True, header_style="bold magenta")
        const_table.add_column("Constraint")
        const_table.add_column("Value")

        const_table.add_row(
            "Avoid Nodes",
            ", ".join(intent.constraints.avoid_nodes) or "-",
        )
        const_table.add_row(
            "Avoid Domains",
            ", ".join(intent.constraints.avoid_domains) or "-",
        )
        const_table.add_row(
            "Prefer Domains",
            ", ".join(intent.constraints.prefer_domains) or "-",
        )
        const_table.add_row(
            "Prefer Lowest Cost",
            "Yes" if intent.constraints.prefer_lowest_cost else "No",
        )
        const_table.add_row(
            "Max Hops",
            str(intent.constraints.max_hops) if intent.constraints.max_hops else "-",
        )

        console.print(const_table)
        console.print()

        # Success message
        if validated_against_topology:
            console.print(
                Panel(
                    f"[bold green]Intent validated against topology[/bold green]\n"
                    f"Source '{intent.source}' and destination '{intent.destination}' exist\n"
                    f"Ready for solver",
                    title="Validation Complete",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    "[bold yellow]Schema validated[/bold yellow]\n"
                    "Use --topology to validate against network topology",
                    title="Validation Complete",
                    border_style="yellow",
                )
            )

    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        if e.details:
            if "issues" in e.details:
                console.print("[bold red]Issues:[/bold red]")
                for issue in e.details["issues"]:
                    console.print(f"  • {issue}")
            elif "errors" in e.details:
                console.print("[bold red]Validation errors:[/bold red]")
                for error in e.details["errors"]:
                    loc = " → ".join(str(x) for x in error.get("loc", []))
                    msg = error.get("msg", "Unknown error")
                    console.print(f"  • {loc}: {msg}")
            else:
                console.print(f"[dim]Details: {e.details}[/dim]")
        raise SystemExit(1)


@main.command("solve")
@click.argument("intent_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--topology",
    "-t",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_TOPOLOGY,
    help="Topology file",
    show_default=True,
)
@click.option(
    "--timeout",
    type=int,
    default=30000,
    help="Solver timeout in milliseconds",
    show_default=True,
)
def solve(intent_file: Path, topology: Path, timeout: int) -> None:
    """Solve for optimal diverse paths.

    Uses the Z3 constraint solver to find primary and backup paths
    that meet the intent requirements (latency, diversity, cost).

    INTENT_FILE: Path to the intent YAML file
    """
    try:
        # Load topology
        console.print(f"[dim]Loading topology from {topology}...[/dim]")
        loader = TopologyLoader()
        topo, graph = loader.load(topology)
        console.print(f"[green]✓[/green] Topology: {topo.node_count} nodes, {topo.edge_count} edges")

        # Parse intent
        console.print(f"[dim]Parsing intent from {intent_file}...[/dim]")
        parser = IntentParser()
        intent = parser.parse_and_validate(intent_file, topo)
        console.print(f"[green]✓[/green] Intent: {intent.name}")

        # Configure and run solver
        config = SolverConfig(timeout_ms=timeout)
        solver = DiversePathSolver(topo, graph, config)

        console.print()
        console.print(f"[bold]Solving:[/bold] {intent.source} → {intent.destination}")
        console.print(f"[dim]  Max latency: {intent.requirements.latency_ms}ms[/dim]")
        console.print(f"[dim]  Diverse paths: {intent.requirements.diverse_paths}[/dim]")
        console.print()

        result = solver.solve(intent)

        # Display results
        console.print(
            Panel(
                f"[bold green]Solution Found![/bold green]\n"
                f"Solver time: {result.solver_time_ms}ms",
                title="Z3 Solver Result",
                border_style="green",
            )
        )

        # Path details table
        path_table = Table(title="Computed Paths", show_header=True, header_style="bold cyan")
        path_table.add_column("Path")
        path_table.add_column("Route")
        path_table.add_column("Latency", justify="right")
        path_table.add_column("Cost", justify="right")
        path_table.add_column("Hops", justify="right")
        path_table.add_column("Domain")

        path_table.add_row(
            "[green]Primary[/green]",
            result.primary_path.path_string,
            f"{result.primary_path.total_latency_ms}ms",
            str(result.primary_path.total_cost),
            str(result.primary_path.hops),
            result.primary_path.domain or "-",
        )
        path_table.add_row(
            "[yellow]Backup[/yellow]",
            result.backup_path.path_string,
            f"{result.backup_path.total_latency_ms}ms",
            str(result.backup_path.total_cost),
            str(result.backup_path.hops),
            result.backup_path.domain or "-",
        )

        console.print(path_table)
        console.print()

        # Status summary
        status_items = []
        if result.is_diverse:
            status_items.append("[green]✓[/green] Paths are diverse (no shared failure domains)")
        else:
            status_items.append("[yellow]![/yellow] Paths share failure domains")

        if result.meets_sla:
            status_items.append(f"[green]✓[/green] Both paths meet {intent.requirements.latency_ms}ms SLA")
        else:
            status_items.append("[red]✗[/red] SLA not met")

        for item in status_items:
            console.print(item)

        # Show topology diagram with paths
        console.print()
        diagram = TopologyDiagram(topo)
        diagram.show_paths(result)

        if result.notes:
            console.print()
            console.print("[dim]Notes:[/dim]")
            for note in result.notes:
                console.print(f"[dim]  • {note}[/dim]")

    except UnsatisfiableIntent as e:
        console.print(
            Panel(
                f"[bold red]No Solution Found[/bold red]\n\n"
                f"{e.message}\n\n"
                "Try relaxing constraints:\n"
                "  • Increase max latency\n"
                "  • Disable diverse path requirement\n"
                "  • Remove node/domain restrictions",
                title="Unsatisfiable",
                border_style="red",
            )
        )
        raise SystemExit(1)

    except SolverTimeout as e:
        console.print(f"[bold red]Solver timeout:[/bold red] {e.message}")
        console.print("Try increasing --timeout or simplifying the topology")
        raise SystemExit(1)

    except SolverError as e:
        console.print(f"[bold red]Solver error:[/bold red] {e.message}")
        raise SystemExit(1)

    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        raise SystemExit(1)


@main.command("generate-bootstrap")
@click.option(
    "--device",
    "-d",
    type=str,
    default=None,
    help="Generate for specific device (default: all)",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(path_type=Path),
    default=Path("bootstrap-configs"),
    help="Output directory for configs",
)
def generate_bootstrap(device: str | None, output_dir: Path) -> None:
    """Generate bootstrap configurations for lab devices.

    Creates the base configurations needed before IBN Platform
    can manage the devices.
    """
    from jinja2 import Environment, FileSystemLoader
    import yaml

    template_dir = Path(__file__).parent.parent.parent / "templates"
    devices_file = template_dir / "bootstrap" / "lab-devices.yaml"

    if not devices_file.exists():
        console.print(f"[red]Error:[/red] Devices file not found: {devices_file}")
        raise SystemExit(1)

    with open(devices_file) as f:
        data = yaml.safe_load(f)

    devices_data = data.get("devices", {})

    if device:
        if device not in devices_data:
            console.print(f"[red]Error:[/red] Device '{device}' not found")
            console.print(f"Available: {', '.join(devices_data.keys())}")
            raise SystemExit(1)
        devices_data = {device: devices_data[device]}

    # Setup Jinja2
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("bootstrap/c8000v-base.j2")

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold]Generating bootstrap configurations...[/bold]\n")

    for dev_name, dev_data in devices_data.items():
        config = template.render(**dev_data)
        output_file = output_dir / f"{dev_name}-bootstrap.txt"

        with open(output_file, "w") as f:
            f.write(config)

        console.print(f"[green]✓[/green] {dev_name} → {output_file}")

    console.print(
        Panel(
            f"[bold green]Generated {len(devices_data)} bootstrap config(s)[/bold green]\n\n"
            "Apply these configs via console before using IBN Platform.\n"
            "After applying:\n"
            "  1. Verify SSH: ssh admin@<mgmt_ip>\n"
            "  2. Verify NETCONF: ssh -p 830 admin@<mgmt_ip> -s netconf",
            title="Bootstrap Configs Ready",
            border_style="green",
        )
    )


@main.command("generate-config")
@click.argument("intent_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--topology",
    "-t",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_TOPOLOGY,
    help="Topology file",
    show_default=True,
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output directory (default: print to stdout)",
)
def generate_config(intent_file: Path, topology: Path, output_dir: Path | None) -> None:
    """Generate device configurations from an intent.

    Uses mock paths (until Z3 solver is implemented) to demonstrate
    configuration generation.

    INTENT_FILE: Path to the intent YAML file
    """
    from ibn.deploy.generator import ConfigGenerator
    from ibn.services import get_service

    try:
        # Load topology
        loader = TopologyLoader()
        topo, graph = loader.load(topology)
        console.print(f"[green]✓[/green] Topology loaded")

        # Parse intent
        parser = IntentParser()
        intent = parser.parse_and_validate(intent_file, topo)
        console.print(f"[green]✓[/green] Intent validated: {intent.name}")

        # Get service model
        service = get_service(intent.type.value)
        console.print(f"[green]✓[/green] Service model: {service.name}")

        # Run Z3 solver for optimal paths
        console.print(f"[dim]Running Z3 solver...[/dim]")
        solver = DiversePathSolver(topo, graph)
        result = solver.solve(intent)
        console.print(f"[green]✓[/green] Solution found in {result.solver_time_ms}ms")

        primary_path = result.primary_path
        backup_path = result.backup_path

        console.print(f"\n[bold]Computed Paths:[/bold]")
        console.print(f"  Primary: {primary_path.path_string} ({primary_path.total_latency_ms}ms, Domain {primary_path.domain})")
        console.print(f"  Backup:  {backup_path.path_string} ({backup_path.total_latency_ms}ms, Domain {backup_path.domain})")

        # Generate configs
        generator = ConfigGenerator(
            topology=topo,
            intent=intent,
            service=service,
            primary_path=primary_path,
            backup_path=backup_path,
        )

        configs = generator.generate_all()

        console.print(f"\n[bold]Generated Configurations:[/bold]\n")

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            for hostname, config in configs.items():
                output_file = output_dir / f"{hostname}-config.txt"
                with open(output_file, "w") as f:
                    f.write(config)
                console.print(f"[green]✓[/green] {hostname} → {output_file}")
        else:
            for hostname, config in configs.items():
                console.print(Panel(
                    config,
                    title=f"[bold]{hostname}[/bold]",
                    border_style="cyan",
                ))

    except UnsatisfiableIntent as e:
        console.print(
            Panel(
                f"[bold red]No Solution Found[/bold red]\n\n"
                f"{e.message}",
                title="Unsatisfiable",
                border_style="red",
            )
        )
        raise SystemExit(1)

    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        raise SystemExit(1)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise SystemExit(1)


@main.command("apply")
@click.argument("intent_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--topology",
    "-t",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_TOPOLOGY,
    help="Topology file",
    show_default=True,
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Validate only, don't solve or deploy",
)
def apply_intent(intent_file: Path, topology: Path, dry_run: bool) -> None:
    """Apply an intent to the network.

    Validates the intent, runs the constraint solver to find optimal
    paths, and (eventually) deploys configuration to devices.

    INTENT_FILE: Path to the intent YAML file
    """
    try:
        # Load topology
        console.print(f"[dim]Loading topology from {topology}...[/dim]")
        loader = TopologyLoader()
        topo, graph = loader.load(topology)
        console.print(f"[green]✓[/green] Topology loaded: {topo.node_count} nodes, {topo.edge_count} edges")

        # Parse and validate intent
        console.print(f"[dim]Parsing intent from {intent_file}...[/dim]")
        parser = IntentParser()
        intent = parser.parse_and_validate(intent_file, topo)
        console.print(f"[green]✓[/green] Intent validated: {intent.name}")

        # Display what we're trying to achieve
        console.print()
        console.print(
            Panel(
                f"[bold]Intent:[/bold] {intent.name}\n"
                f"[bold]Route:[/bold] {intent.source} → {intent.destination}\n"
                f"[bold]Max Latency:[/bold] {intent.requirements.latency_ms}ms\n"
                f"[bold]Diverse Paths:[/bold] {'Required' if intent.requirements.diverse_paths else 'Not required'}",
                title="Applying Intent",
                border_style="cyan",
            )
        )

        if dry_run:
            console.print()
            console.print("[yellow]Dry run mode - stopping before solver[/yellow]")
            console.print(
                Panel(
                    "[bold yellow]Ready for solver[/bold yellow]\n"
                    "Intent is validated and ready for path computation.\n"
                    "Remove --dry-run to run the constraint solver.",
                    title="Dry Run Complete",
                    border_style="yellow",
                )
            )
            return

        # Run Z3 solver
        console.print()
        console.print("[dim]Running Z3 constraint solver...[/dim]")

        try:
            solver = DiversePathSolver(topo, graph)
            result = solver.solve(intent)

            console.print(f"[green]✓[/green] Solution found in {result.solver_time_ms}ms")
            console.print()

            # Path details table
            path_table = Table(title="Computed Paths", show_header=True, header_style="bold cyan")
            path_table.add_column("Path")
            path_table.add_column("Route")
            path_table.add_column("Latency", justify="right")
            path_table.add_column("Cost", justify="right")
            path_table.add_column("Domain")

            path_table.add_row(
                "[green]Primary[/green]",
                result.primary_path.path_string,
                f"{result.primary_path.total_latency_ms}ms",
                str(result.primary_path.total_cost),
                result.primary_path.domain or "-",
            )
            path_table.add_row(
                "[yellow]Backup[/yellow]",
                result.backup_path.path_string,
                f"{result.backup_path.total_latency_ms}ms",
                str(result.backup_path.total_cost),
                result.backup_path.domain or "-",
            )

            console.print(path_table)
            console.print()

            # Status
            if result.is_diverse:
                console.print("[green]✓[/green] Paths are diverse (no shared failure domains)")
            if result.meets_sla:
                console.print(f"[green]✓[/green] Both paths meet {intent.requirements.latency_ms}ms SLA")

            console.print()
            console.print(
                Panel(
                    "[bold]Next Steps:[/bold]\n"
                    "1. Run `ibn generate-config` to create device configs\n"
                    "2. Week 5: Add failure simulation\n"
                    "3. Week 6: Deploy configs to devices",
                    title="Intent Solved",
                    border_style="green",
                )
            )

        except UnsatisfiableIntent as e:
            console.print(
                Panel(
                    f"[bold red]No Solution Found[/bold red]\n\n"
                    f"{e.message}\n\n"
                    "Try relaxing constraints:\n"
                    "  • Increase max latency\n"
                    "  • Disable diverse path requirement\n"
                    "  • Remove node/domain restrictions",
                    title="Unsatisfiable",
                    border_style="red",
                )
            )
            raise SystemExit(1)

        except SolverError as e:
            console.print(f"[bold red]Solver error:[/bold red] {e.message}")
            raise SystemExit(1)

    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        if e.details:
            if "issues" in e.details:
                console.print("[bold red]Issues:[/bold red]")
                for issue in e.details["issues"]:
                    console.print(f"  • {issue}")
            else:
                console.print(f"[dim]Details: {e.details}[/dim]")
        raise SystemExit(1)


@main.command("test-connections")
@click.option(
    "--topology",
    "-t",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_TOPOLOGY,
    help="Topology file",
    show_default=True,
)
@click.option("--username", "-u", default=lambda: os.environ.get("IBN_USERNAME"), prompt=True, help="SSH username (or set IBN_USERNAME)")
@click.option("--password", "-p", default=lambda: os.environ.get("IBN_PASSWORD"), prompt=True, hide_input=True, help="SSH password (or set IBN_PASSWORD)")
def test_connections(topology: Path, username: str, password: str) -> None:
    """Test SSH connectivity to all devices in topology.

    Verifies that all devices are reachable before deployment.
    """
    from ibn.deploy import DeviceConnector, DeviceCredentials

    try:
        loader = TopologyLoader()
        topo, _ = loader.load(topology)

        credentials = DeviceCredentials(username=username, password=password)
        connector = DeviceConnector(credentials)

        console.print(f"\n[bold]Testing connections to {topo.node_count} devices...[/bold]\n")

        results_table = Table(show_header=True, header_style="bold cyan")
        results_table.add_column("Device")
        results_table.add_column("IP Address")
        results_table.add_column("Status")
        results_table.add_column("Details")

        all_success = True
        for name, node in topo.nodes.items():
            if not node.mgmt_ip:
                results_table.add_row(name, "-", "[yellow]SKIP[/yellow]", "No management IP")
                continue

            result = connector.test_connection(str(node.mgmt_ip), name)

            if result.success:
                results_table.add_row(
                    name,
                    str(node.mgmt_ip),
                    "[green]OK[/green]",
                    result.message[:50],
                )
            else:
                all_success = False
                results_table.add_row(
                    name,
                    str(node.mgmt_ip),
                    "[red]FAIL[/red]",
                    result.message,
                )

        console.print(results_table)
        console.print()

        if all_success:
            console.print("[green]✓ All devices reachable[/green]")
        else:
            console.print("[red]✗ Some devices unreachable[/red]")
            raise SystemExit(1)

    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        raise SystemExit(1)


@main.command("deploy")
@click.argument("intent_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--topology",
    "-t",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_TOPOLOGY,
    help="Topology file",
    show_default=True,
)
@click.option("--username", "-u", default=lambda: os.environ.get("IBN_USERNAME"), prompt=True, help="SSH username (or set IBN_USERNAME)")
@click.option("--password", "-p", default=lambda: os.environ.get("IBN_PASSWORD"), prompt=True, hide_input=True, help="SSH password (or set IBN_PASSWORD)")
@click.option("--dry-run", is_flag=True, help="Show what would be deployed without deploying")
@click.option("--diff", "show_diff", is_flag=True, help="Show config diff before deploying")
@click.option("--no-verify", is_flag=True, help="Skip verification after deployment")
def deploy(
    intent_file: Path,
    topology: Path,
    username: str,
    password: str,
    dry_run: bool,
    show_diff: bool,
    no_verify: bool,
) -> None:
    """Deploy an intent to network devices.

    Solves for optimal paths, generates configurations, and pushes
    them to devices via SSH.

    INTENT_FILE: Path to the intent YAML file
    """
    from ibn.deploy import ConfigGenerator, DeviceConnector, DeviceCredentials
    from ibn.services import get_service

    try:
        # Load topology
        console.print(f"[dim]Loading topology...[/dim]")
        loader = TopologyLoader()
        topo, graph = loader.load(topology)
        console.print(f"[green]✓[/green] Topology: {topo.node_count} nodes")

        # Parse intent
        console.print(f"[dim]Parsing intent...[/dim]")
        parser = IntentParser()
        intent = parser.parse_and_validate(intent_file, topo)
        console.print(f"[green]✓[/green] Intent: {intent.name}")

        # Run solver
        console.print(f"[dim]Running Z3 solver...[/dim]")
        solver = DiversePathSolver(topo, graph)
        result = solver.solve(intent)
        console.print(f"[green]✓[/green] Solution found in {result.solver_time_ms}ms")

        # Display paths
        console.print()
        console.print(f"[bold]Primary:[/bold] {result.primary_path.path_string}")
        console.print(f"[bold]Backup:[/bold]  {result.backup_path.path_string}")
        console.print()

        # Get service and generate configs
        service = get_service(intent.type.value)
        generator = ConfigGenerator(
            topology=topo,
            intent=intent,
            service=service,
            primary_path=result.primary_path,
            backup_path=result.backup_path,
        )
        configs = generator.generate_all()

        if dry_run:
            console.print("[yellow]DRY RUN - showing configs without deploying[/yellow]\n")
            for hostname, config in configs.items():
                console.print(Panel(
                    config,
                    title=f"[bold]{hostname}[/bold]",
                    border_style="cyan",
                ))
            return

        # Deploy to devices
        credentials = DeviceCredentials(username=username, password=password)
        connector = DeviceConnector(credentials)

        # Show diff if requested
        if show_diff:
            from ibn.deploy import generate_diff, display_diff, display_diff_summary

            console.print("[bold]Fetching current configs and generating diff...[/bold]\n")

            diffs = []
            for hostname, proposed_config in configs.items():
                node = topo.nodes.get(hostname)
                if not node or not node.mgmt_ip:
                    continue

                # Get current BGP config
                current_result = connector.get_bgp_config(str(node.mgmt_ip), hostname)
                current_config = current_result.output if current_result.success else ""

                # Generate diff
                diff = generate_diff(hostname, current_config, proposed_config)
                diffs.append(diff)

            # Show summary
            display_diff_summary(diffs, console)
            console.print()

            # Show detailed diffs
            for diff in diffs:
                if diff.has_changes:
                    display_diff(diff, console)

            # Ask for confirmation
            if not click.confirm("\nProceed with deployment?"):
                console.print("[yellow]Deployment cancelled[/yellow]")
                return

            console.print()

        # Save pre-deployment state for rollback
        from ibn.state import DeploymentHistory, DeploymentRecord
        from ibn.state.history import DeviceSnapshot

        console.print("[dim]Saving pre-deployment state...[/dim]")
        history = DeploymentHistory()
        record = history.create_record(intent.name, str(intent_file))
        record.primary_path = result.primary_path.path_string
        record.backup_path = result.backup_path.path_string

        for hostname in configs.keys():
            node = topo.nodes.get(hostname)
            if not node or not node.mgmt_ip:
                continue

            # Get current BGP config before overwriting
            current = connector.get_bgp_config(str(node.mgmt_ip), hostname)
            if current.success:
                snapshot = DeviceSnapshot(
                    hostname=hostname,
                    mgmt_ip=str(node.mgmt_ip),
                    config=current.output,
                    timestamp=record.timestamp,
                )
                record.devices.append(snapshot)

        console.print(f"[green]✓[/green] Saved state for {len(record.devices)} devices")
        console.print()

        console.print("[bold]Deploying configurations...[/bold]\n")

        deploy_table = Table(show_header=True, header_style="bold cyan")
        deploy_table.add_column("Device")
        deploy_table.add_column("Status")
        deploy_table.add_column("Lines")
        deploy_table.add_column("Details")

        all_success = True
        for hostname, config in configs.items():
            node = topo.nodes.get(hostname)
            if not node or not node.mgmt_ip:
                deploy_table.add_row(
                    hostname, "[yellow]SKIP[/yellow]", "-", "No management IP"
                )
                continue

            deploy_result = connector.deploy_config(
                str(node.mgmt_ip),
                config,
                hostname,
            )

            if deploy_result.success:
                deploy_table.add_row(
                    hostname,
                    "[green]OK[/green]",
                    str(deploy_result.config_lines),
                    deploy_result.message,
                )
            else:
                all_success = False
                deploy_table.add_row(
                    hostname,
                    "[red]FAIL[/red]",
                    "-",
                    deploy_result.message,
                )

        console.print(deploy_table)
        console.print()

        if not all_success:
            console.print("[red]✗ Deployment had failures[/red]")
            record.success = False
            record.notes = "Deployment had failures"
            history.save_record(record)
            raise SystemExit(1)

        console.print("[green]✓ Configuration deployed to all devices[/green]")

        # Save successful deployment record
        record.success = True
        history.save_record(record)
        console.print(f"[dim]Deployment saved (ID: {record.id}) - use 'ibn rollback' to undo[/dim]")

        # Verification
        if not no_verify:
            console.print("\n[bold]Verifying BGP neighbors...[/bold]\n")

            for hostname in configs.keys():
                node = topo.nodes.get(hostname)
                if not node or not node.mgmt_ip:
                    continue

                verify_result = connector.verify_bgp_neighbors(
                    str(node.mgmt_ip), hostname
                )

                console.print(f"[bold]{hostname}[/bold]")
                if verify_result.success:
                    console.print(verify_result.output)
                else:
                    console.print(f"[red]Verification failed: {verify_result.output}[/red]")
                console.print()

        console.print(
            Panel(
                f"[bold green]Intent Deployed Successfully[/bold green]\n\n"
                f"Intent: {intent.name}\n"
                f"Devices configured: {len(configs)}\n"
                f"Primary path: {result.primary_path.path_string}\n"
                f"Backup path: {result.backup_path.path_string}",
                title="Deployment Complete",
                border_style="green",
            )
        )

    except UnsatisfiableIntent as e:
        console.print(f"[bold red]No solution:[/bold red] {e.message}")
        raise SystemExit(1)
    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        raise SystemExit(1)


@main.command("what-if")
@click.argument("intent_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--topology",
    "-t",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_TOPOLOGY,
    help="Topology file",
    show_default=True,
)
@click.option(
    "--fail-node",
    multiple=True,
    help="Simulate node failure (can be used multiple times)",
)
@click.option(
    "--fail-domain",
    multiple=True,
    help="Simulate domain failure (can be used multiple times)",
)
def what_if(
    intent_file: Path,
    topology: Path,
    fail_node: tuple[str, ...],
    fail_domain: tuple[str, ...],
) -> None:
    """Simulate failures and show solver response.

    Test how the network would respond to node or domain failures.
    Great for validating that your topology has sufficient redundancy.

    Examples:
        ibn what-if intent.yaml --fail-node IBN-Core1
        ibn what-if intent.yaml --fail-domain A
    """
    try:
        # Load topology
        loader = TopologyLoader()
        topo, graph = loader.load(topology)

        # Parse intent
        parser = IntentParser()
        intent = parser.parse_and_validate(intent_file, topo)

        console.print()
        console.print(
            Panel(
                f"[bold]Intent:[/bold] {intent.name}\n"
                f"[bold]Route:[/bold] {intent.source} → {intent.destination}\n"
                f"[bold]Simulated Failures:[/bold]\n"
                f"  Nodes: {', '.join(fail_node) if fail_node else 'None'}\n"
                f"  Domains: {', '.join(fail_domain) if fail_domain else 'None'}",
                title="What-If Analysis",
                border_style="cyan",
            )
        )

        # First, show the baseline (no failures)
        console.print("\n[bold]BASELINE (no failures):[/bold]")
        solver = DiversePathSolver(topo, graph)

        try:
            baseline = solver.solve(intent)
            console.print(f"  Primary: {baseline.primary_path.path_string} ({baseline.primary_path.total_latency_ms}ms)")
            console.print(f"  Backup:  {baseline.backup_path.path_string} ({baseline.backup_path.total_latency_ms}ms)")
            console.print(f"  [green]✓ Diverse paths available[/green]" if baseline.is_diverse else "  [yellow]! Paths share domains[/yellow]")
        except UnsatisfiableIntent:
            console.print("  [red]✗ No solution even without failures![/red]")
            raise SystemExit(1)

        # Now simulate each failure scenario
        if fail_node or fail_domain:
            # Modify the intent to avoid the failed elements
            from copy import deepcopy
            failed_intent = deepcopy(intent)

            for node in fail_node:
                if node not in failed_intent.constraints.avoid_nodes:
                    failed_intent.constraints.avoid_nodes.append(node)

            for domain in fail_domain:
                if domain not in failed_intent.constraints.avoid_domains:
                    failed_intent.constraints.avoid_domains.append(domain)

            console.print(f"\n[bold]WITH FAILURES:[/bold]")

            if fail_node:
                console.print(f"  [red]✗ Node(s) down: {', '.join(fail_node)}[/red]")
            if fail_domain:
                console.print(f"  [red]✗ Domain(s) down: {', '.join(fail_domain)}[/red]")

            console.print()

            try:
                failed_result = solver.solve(failed_intent)
                console.print(f"  [green]✓ SOLUTION FOUND[/green]")
                console.print(f"  Primary: {failed_result.primary_path.path_string} ({failed_result.primary_path.total_latency_ms}ms)")
                console.print(f"  Backup:  {failed_result.backup_path.path_string} ({failed_result.backup_path.total_latency_ms}ms)")

                # Check if paths changed
                if baseline.primary_path.path != failed_result.primary_path.path:
                    console.print(f"  [yellow]! Primary path rerouted[/yellow]")
                if baseline.backup_path.path != failed_result.backup_path.path:
                    console.print(f"  [yellow]! Backup path rerouted[/yellow]")

                console.print()
                console.print(
                    Panel(
                        "[bold green]Network is resilient![/bold green]\n\n"
                        "The solver found alternative paths that still meet\n"
                        "the intent requirements despite the failures.",
                        title="Resilience Verified",
                        border_style="green",
                    )
                )

            except UnsatisfiableIntent:
                console.print(f"  [red]✗ NO SOLUTION AVAILABLE[/red]")
                console.print()
                console.print(
                    Panel(
                        "[bold red]Network would be DOWN![/bold red]\n\n"
                        "With this failure scenario, there's no way to meet\n"
                        "the intent requirements. Consider:\n"
                        "  • Adding redundant paths\n"
                        "  • Relaxing latency requirements\n"
                        "  • Disabling diversity requirement",
                        title="Single Point of Failure Detected",
                        border_style="red",
                    )
                )
                raise SystemExit(1)

    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        raise SystemExit(1)


@main.command("verify")
@click.option(
    "--topology",
    "-t",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_TOPOLOGY,
    help="Topology file",
    show_default=True,
)
@click.option("--username", "-u", default=lambda: os.environ.get("IBN_USERNAME"), prompt=True, help="SSH username (or set IBN_USERNAME)")
@click.option("--password", "-p", default=lambda: os.environ.get("IBN_PASSWORD"), prompt=True, hide_input=True, help="SSH password (or set IBN_PASSWORD)")
@click.option("--bgp", is_flag=True, help="Show BGP neighbor status")
@click.option("--bfd", is_flag=True, help="Show BFD session status")
@click.option("--routes", is_flag=True, help="Show BGP routes")
@click.option("--all", "show_all", is_flag=True, help="Show all verifications")
def verify(
    topology: Path,
    username: str,
    password: str,
    bgp: bool,
    bfd: bool,
    routes: bool,
    show_all: bool,
) -> None:
    """Verify network state after deployment.

    Connects to devices and shows BGP/BFD status to confirm
    the intent was applied correctly.
    """
    from ibn.deploy import DeviceConnector, DeviceCredentials

    # Default to BGP if nothing specified
    if not any([bgp, bfd, routes, show_all]):
        bgp = True

    if show_all:
        bgp = bfd = routes = True

    try:
        loader = TopologyLoader()
        topo, _ = loader.load(topology)

        credentials = DeviceCredentials(username=username, password=password)
        connector = DeviceConnector(credentials)

        console.print(f"\n[bold]Verifying {topo.node_count} devices...[/bold]\n")

        for name, node in topo.nodes.items():
            if not node.mgmt_ip:
                continue

            console.print(f"[bold cyan]{'='*60}[/bold cyan]")
            console.print(f"[bold cyan]{name}[/bold cyan] ({node.mgmt_ip})")
            console.print(f"[bold cyan]{'='*60}[/bold cyan]")

            if bgp:
                result = connector.verify_bgp_neighbors(str(node.mgmt_ip), name)
                console.print("\n[bold]BGP Neighbors:[/bold]")
                console.print(result.output if result.success else f"[red]{result.output}[/red]")

            if bfd:
                result = connector.verify_bfd_neighbors(str(node.mgmt_ip), name)
                console.print("\n[bold]BFD Sessions:[/bold]")
                console.print(result.output if result.success else f"[red]{result.output}[/red]")

            if routes:
                result = connector.verify_routes(str(node.mgmt_ip), name)
                console.print("\n[bold]BGP Routes:[/bold]")
                console.print(result.output if result.success else f"[red]{result.output}[/red]")

            console.print()

    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        raise SystemExit(1)


@main.command("watch")
@click.option(
    "--topology",
    "-t",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_TOPOLOGY,
    help="Topology file",
    show_default=True,
)
@click.option("--username", "-u", default=lambda: os.environ.get("IBN_USERNAME"), prompt=True, help="SSH username (or set IBN_USERNAME)")
@click.option("--password", "-p", default=lambda: os.environ.get("IBN_PASSWORD"), prompt=True, hide_input=True, help="SSH password (or set IBN_PASSWORD)")
@click.option("--interval", "-i", type=int, default=5, help="Polling interval in seconds", show_default=True)
def watch(topology: Path, username: str, password: str, interval: int) -> None:
    """Watch network status in real-time.

    Continuously monitors BGP and BFD session status across all devices.
    Displays live updates and alerts on state changes.

    Press Ctrl+C to stop watching.
    """
    from ibn.deploy import DeviceCredentials
    from ibn.monitor import NetworkWatcher

    try:
        loader = TopologyLoader()
        topo, _ = loader.load(topology)

        credentials = DeviceCredentials(username=username, password=password)
        watcher = NetworkWatcher(topo, credentials)

        # Start watching
        watcher.watch(interval=interval)

    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        raise SystemExit(1)


@main.command("compliance")
@click.argument("intent_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--topology",
    "-t",
    type=click.Path(exists=True, path_type=Path),
    default=DEFAULT_TOPOLOGY,
    help="Topology file",
    show_default=True,
)
@click.option("--username", "-u", default=lambda: os.environ.get("IBN_USERNAME"), prompt=True, help="SSH username (or set IBN_USERNAME)")
@click.option("--password", "-p", default=lambda: os.environ.get("IBN_PASSWORD"), prompt=True, hide_input=True, help="SSH password (or set IBN_PASSWORD)")
@click.option("--continuous", "-c", is_flag=True, help="Run continuous compliance monitoring")
@click.option("--interval", "-i", type=int, default=30, help="Check interval in seconds (for continuous mode)", show_default=True)
def compliance(
    intent_file: Path,
    topology: Path,
    username: str,
    password: str,
    continuous: bool,
    interval: int,
) -> None:
    """Check network compliance against an intent.

    Verifies that the network state matches the intended configuration.
    Reports any violations including BGP/BFD session failures and config drift.

    Use --continuous for ongoing compliance monitoring.

    INTENT_FILE: Path to the intent YAML file
    """
    import time

    from ibn.compliance import ComplianceChecker, ComplianceStatus
    from ibn.deploy import DeviceCredentials

    try:
        loader = TopologyLoader()
        topo, _ = loader.load(topology)

        parser = IntentParser()
        intent = parser.parse(intent_file)

        credentials = DeviceCredentials(username=username, password=password)
        checker = ComplianceChecker(topo, credentials)

        def run_check() -> bool:
            """Run a single compliance check and display results."""
            console.print(f"\n[bold]Checking compliance for: {intent.name}[/bold]")
            console.print(f"[dim]Checking {topo.node_count} devices...[/dim]\n")

            report = checker.check_compliance(intent)

            # Display status
            if report.is_compliant:
                console.print(
                    Panel(
                        f"[bold green]COMPLIANT[/bold green]\n\n"
                        f"All {len(report.devices_checked)} devices are operating as intended.\n"
                        f"Check duration: {report.check_duration_ms}ms",
                        title="Compliance Status",
                        border_style="green",
                    )
                )
            else:
                # Build violations table
                table = Table(title="Compliance Violations", show_header=True, header_style="bold red")
                table.add_column("Device")
                table.add_column("Type")
                table.add_column("Severity")
                table.add_column("Message")

                for violation in report.violations:
                    severity_style = "red" if violation.severity == "critical" else "yellow"
                    table.add_row(
                        violation.device,
                        violation.violation_type.value,
                        f"[{severity_style}]{violation.severity}[/{severity_style}]",
                        violation.message[:50],
                    )

                console.print(
                    Panel(
                        f"[bold red]NON-COMPLIANT[/bold red]\n\n"
                        f"Found {report.total_violations} violation(s):\n"
                        f"  - Critical: {report.critical_count}\n"
                        f"  - Warning: {report.warning_count}\n\n"
                        f"Check duration: {report.check_duration_ms}ms",
                        title="Compliance Status",
                        border_style="red",
                    )
                )
                console.print()
                console.print(table)

            return report.is_compliant

        if continuous:
            console.print(f"[bold]Starting continuous compliance monitoring (every {interval}s)[/bold]")
            console.print("[dim]Press Ctrl+C to stop[/dim]")

            try:
                while True:
                    run_check()
                    console.print(f"\n[dim]Next check in {interval} seconds...[/dim]")
                    time.sleep(interval)
            except KeyboardInterrupt:
                console.print("\n[yellow]Compliance monitoring stopped[/yellow]")
        else:
            is_compliant = run_check()
            if not is_compliant:
                raise SystemExit(1)

    except IBNError as e:
        console.print(f"[bold red]Error:[/bold red] {e.message}")
        raise SystemExit(1)


@main.command("history")
@click.option("--limit", "-n", type=int, default=10, help="Number of deployments to show")
def history(limit: int) -> None:
    """Show deployment history.

    Lists recent deployments with their IDs for use with rollback.
    """
    from ibn.state import DeploymentHistory

    hist = DeploymentHistory()
    records = hist.list_deployments(limit)

    if not records:
        console.print("[dim]No deployment history found[/dim]")
        return

    table = Table(title="Deployment History", show_header=True, header_style="bold cyan")
    table.add_column("ID")
    table.add_column("Timestamp")
    table.add_column("Intent")
    table.add_column("Paths")
    table.add_column("Devices")
    table.add_column("Status")

    for record in records:
        timestamp = record.timestamp[:19].replace("T", " ")
        paths = f"{record.primary_path}"
        status = "[green]OK[/green]" if record.success else "[red]FAILED[/red]"

        table.add_row(
            record.id,
            timestamp,
            record.intent_name[:25],
            paths[:30],
            str(len(record.devices)),
            status,
        )

    console.print(table)
    console.print()
    console.print("[dim]Use 'ibn rollback' to restore previous configuration[/dim]")


@main.command("rollback")
@click.option(
    "--deployment-id",
    "-d",
    type=str,
    default=None,
    help="Specific deployment ID to rollback to (default: last deployment)",
)
@click.option("--username", "-u", default=lambda: os.environ.get("IBN_USERNAME"), prompt=True, help="SSH username (or set IBN_USERNAME)")
@click.option("--password", "-p", default=lambda: os.environ.get("IBN_PASSWORD"), prompt=True, hide_input=True, help="SSH password (or set IBN_PASSWORD)")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def rollback(deployment_id: str | None, username: str, password: str, yes: bool) -> None:
    """Rollback to a previous configuration.

    Restores the BGP configuration that was saved before the last deployment.
    Use --deployment-id to rollback to a specific deployment.
    """
    from ibn.deploy import DeviceConnector, DeviceCredentials
    from ibn.state import DeploymentHistory

    hist = DeploymentHistory()

    # Get the deployment to rollback
    if deployment_id:
        record = hist.get_deployment(deployment_id)
        if not record:
            console.print(f"[red]Deployment '{deployment_id}' not found[/red]")
            console.print("Use 'ibn history' to see available deployments")
            raise SystemExit(1)
    else:
        record = hist.get_last_deployment()
        if not record:
            console.print("[red]No deployment history found[/red]")
            console.print("Nothing to rollback to")
            raise SystemExit(1)

    # Show what will be rolled back
    console.print()
    console.print(
        Panel(
            f"[bold]Deployment ID:[/bold] {record.id}\n"
            f"[bold]Timestamp:[/bold] {record.timestamp[:19].replace('T', ' ')}\n"
            f"[bold]Intent:[/bold] {record.intent_name}\n"
            f"[bold]Devices:[/bold] {len(record.devices)}",
            title="Rollback Target",
            border_style="yellow",
        )
    )

    if not record.devices:
        console.print("[red]No device configurations saved in this deployment[/red]")
        raise SystemExit(1)

    # Show devices to be restored
    console.print("\n[bold]Configurations to restore:[/bold]")
    for device in record.devices:
        config_preview = device.config[:100].replace("\n", " ")
        console.print(f"  • {device.hostname} ({device.mgmt_ip})")

    console.print()

    # Confirm
    if not yes:
        if not click.confirm("Proceed with rollback?"):
            console.print("[yellow]Rollback cancelled[/yellow]")
            return

    # Perform rollback
    credentials = DeviceCredentials(username=username, password=password)
    connector = DeviceConnector(credentials)

    console.print("\n[bold]Rolling back configurations...[/bold]\n")

    rollback_table = Table(show_header=True, header_style="bold cyan")
    rollback_table.add_column("Device")
    rollback_table.add_column("Status")
    rollback_table.add_column("Details")

    all_success = True
    for device in record.devices:
        # The saved config is the output of "show run | section router bgp"
        # We need to apply it as configuration
        # For a proper rollback, we'd need to:
        # 1. Remove current BGP config
        # 2. Apply the saved config

        # Build rollback commands
        rollback_config = device.config

        result = connector.deploy_config(
            device.mgmt_ip,
            rollback_config,
            device.hostname,
            save_config=True,
        )

        if result.success:
            rollback_table.add_row(
                device.hostname,
                "[green]OK[/green]",
                "Configuration restored",
            )
        else:
            all_success = False
            rollback_table.add_row(
                device.hostname,
                "[red]FAIL[/red]",
                result.message,
            )

    console.print(rollback_table)
    console.print()

    if all_success:
        console.print(
            Panel(
                "[bold green]Rollback Complete[/bold green]\n\n"
                f"Restored configuration from deployment {record.id}",
                title="Success",
                border_style="green",
            )
        )
    else:
        console.print("[red]Rollback had failures - check device status[/red]")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
