"""Topology Visualization for IBN Platform.

Generates ASCII diagrams of network topology with path highlighting.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ibn.intent.schema import PathResult, SolverResult
from ibn.model.topology import Topology


class TopologyDiagram:
    """Generates visual representations of network topology.

    Example:
        diagram = TopologyDiagram(topology)
        diagram.show()  # Basic topology
        diagram.show_paths(solver_result)  # With path highlighting
    """

    def __init__(self, topology: Topology):
        self.topology = topology
        self.console = Console()

    def _get_lab_diagram(
        self,
        primary_path: list[str] | None = None,
        backup_path: list[str] | None = None,
    ) -> str:
        """Generate ASCII diagram for the 4-node lab topology."""

        # Determine which links are primary/backup
        primary_edges = set()
        backup_edges = set()

        if primary_path:
            for i in range(len(primary_path) - 1):
                primary_edges.add((primary_path[i], primary_path[i + 1]))
                primary_edges.add((primary_path[i + 1], primary_path[i]))

        if backup_path:
            for i in range(len(backup_path) - 1):
                backup_edges.add((backup_path[i], backup_path[i + 1]))
                backup_edges.add((backup_path[i + 1], backup_path[i]))

        # Link styling
        def link_style(node1: str, node2: str) -> tuple[str, str]:
            """Return (line_char, color) for a link."""
            if (node1, node2) in primary_edges:
                return ("━", "green")
            elif (node1, node2) in backup_edges:
                return ("─", "yellow")
            else:
                return ("─", "dim")

        # Get link characters
        hq_core1 = link_style("IBN-HQ", "IBN-Core1")
        hq_core2 = link_style("IBN-HQ", "IBN-Core2")
        core1_branch = link_style("IBN-Core1", "IBN-Branch")
        core2_branch = link_style("IBN-Core2", "IBN-Branch")

        # Build the diagram
        diagram = f"""
                         ┌─────────────┐
                         │   IBN-HQ    │
                         │  10.100.0.1 │
                         └──────┬──────┘
                                │
               ┌────────────────┴────────────────┐
               │                                 │
               │ [{hq_core1[1]}]G1                            G2[{hq_core2[1]}] │
               │                                 │
        ┌──────┴──────┐                   ┌──────┴──────┐
        │  IBN-Core1  │                   │  IBN-Core2  │
        │  Domain A   │                   │  Domain B   │
        │ 10.100.0.2  │                   │ 10.100.0.3  │
        └──────┬──────┘                   └──────┬──────┘
               │                                 │
               │ [{core1_branch[1]}]G2                            G2[{core2_branch[1]}] │
               │                                 │
               └────────────────┬────────────────┘
                                │
                         ┌──────┴──────┐
                         │ IBN-Branch  │
                         │ 10.100.0.4  │
                         └─────────────┘
"""
        return diagram

    def _get_simple_diagram(
        self,
        primary_path: list[str] | None = None,
        backup_path: list[str] | None = None,
    ) -> Text:
        """Generate a Rich Text diagram with colors."""

        text = Text()

        # Header
        text.append("\n")
        text.append("                         ┌─────────────┐\n")
        text.append("                         │   ")
        text.append("IBN-HQ", style="bold cyan")
        text.append("    │\n")
        text.append("                         │  10.100.0.1 │\n")
        text.append("                         └──────┬──────┘\n")
        text.append("                                │\n")

        # Determine link colors
        def get_link_style(path: list[str] | None, node1: str, node2: str) -> str:
            if path:
                for i in range(len(path) - 1):
                    if (path[i] == node1 and path[i+1] == node2) or \
                       (path[i] == node2 and path[i+1] == node1):
                        return "bold"
            return "dim"

        p_hq_c1 = "bold green" if primary_path and "IBN-Core1" in primary_path else \
                  "bold yellow" if backup_path and "IBN-Core1" in backup_path else "dim"
        p_hq_c2 = "bold green" if primary_path and "IBN-Core2" in primary_path and "IBN-Core1" not in (primary_path or []) else \
                  "bold yellow" if backup_path and "IBN-Core2" in backup_path else "dim"

        # Check actual path connections
        primary_uses_core1 = primary_path and "IBN-HQ" in primary_path and "IBN-Core1" in primary_path
        primary_uses_core2 = primary_path and "IBN-HQ" in primary_path and "IBN-Core2" in primary_path
        backup_uses_core1 = backup_path and "IBN-HQ" in backup_path and "IBN-Core1" in backup_path
        backup_uses_core2 = backup_path and "IBN-HQ" in backup_path and "IBN-Core2" in backup_path

        # Left side (to Core1)
        left_top = "bold green" if primary_uses_core1 else "bold yellow" if backup_uses_core1 else "dim"
        # Right side (to Core2)
        right_top = "bold green" if primary_uses_core2 else "bold yellow" if backup_uses_core2 else "dim"

        # Bottom connections
        left_bottom = "bold green" if primary_uses_core1 else "bold yellow" if backup_uses_core1 else "dim"
        right_bottom = "bold green" if primary_uses_core2 else "bold yellow" if backup_uses_core2 else "dim"

        text.append("               ┌────────────────┴────────────────┐\n")
        text.append("               ")
        text.append("│", style=left_top)
        text.append("                                 ")
        text.append("│", style=right_top)
        text.append("\n")

        # Core routers
        text.append("        ┌──────┴──────┐                   ┌──────┴──────┐\n")
        text.append("        │  ")
        text.append("IBN-Core1", style="bold cyan" if primary_uses_core1 or backup_uses_core1 else "cyan")
        text.append("  │                   │  ")
        text.append("IBN-Core2", style="bold cyan" if primary_uses_core2 or backup_uses_core2 else "cyan")
        text.append("  │\n")
        text.append("        │  ")
        text.append("Domain A", style="green")
        text.append("   │                   │  ")
        text.append("Domain B", style="yellow")
        text.append("   │\n")
        text.append("        │ 10.100.0.2  │                   │ 10.100.0.3  │\n")
        text.append("        └──────┬──────┘                   └──────┬──────┘\n")

        text.append("               ")
        text.append("│", style=left_bottom)
        text.append("                                 ")
        text.append("│", style=right_bottom)
        text.append("\n")

        text.append("               └────────────────┬────────────────┘\n")
        text.append("                                │\n")
        text.append("                         ┌──────┴──────┐\n")
        text.append("                         │ ")
        text.append("IBN-Branch", style="bold cyan")
        text.append("  │\n")
        text.append("                         │ 10.100.0.4  │\n")
        text.append("                         └─────────────┘\n")

        return text

    def show(self) -> None:
        """Display the basic topology diagram."""
        diagram = self._get_simple_diagram()
        self.console.print(Panel(
            diagram,
            title="[bold]Network Topology[/bold]",
            border_style="blue",
        ))

        # Legend
        legend = Table(show_header=False, box=None, padding=(0, 2))
        legend.add_column()
        legend.add_column()
        legend.add_row("[green]Domain A[/green]", "Failure Domain A (Core1 path)")
        legend.add_row("[yellow]Domain B[/yellow]", "Failure Domain B (Core2 path)")
        self.console.print(legend)

    def show_paths(self, result: SolverResult) -> None:
        """Display topology with computed paths highlighted."""
        diagram = self._get_simple_diagram(
            primary_path=result.primary_path.path,
            backup_path=result.backup_path.path,
        )

        self.console.print(Panel(
            diagram,
            title="[bold]Computed Paths[/bold]",
            border_style="cyan",
        ))

        # Path legend
        legend = Table(show_header=False, box=None, padding=(0, 2))
        legend.add_column()
        legend.add_column()
        legend.add_row(
            "[bold green]━━━[/bold green]",
            f"Primary: {result.primary_path.path_string} ({result.primary_path.total_latency_ms}ms)"
        )
        legend.add_row(
            "[bold yellow]───[/bold yellow]",
            f"Backup: {result.backup_path.path_string} ({result.backup_path.total_latency_ms}ms)"
        )
        legend.add_row(
            "[dim]───[/dim]",
            "Unused links"
        )
        self.console.print(legend)

    def show_failure(
        self,
        result: SolverResult,
        failed_nodes: list[str] | None = None,
        failed_domains: list[str] | None = None,
    ) -> None:
        """Display topology with failures marked."""
        diagram = self._get_simple_diagram(
            primary_path=result.primary_path.path,
            backup_path=result.backup_path.path,
        )

        title = "[bold red]Failure Scenario[/bold red]"
        if failed_nodes:
            title += f" - Node(s): {', '.join(failed_nodes)}"
        if failed_domains:
            title += f" - Domain(s): {', '.join(failed_domains)}"

        self.console.print(Panel(
            diagram,
            title=title,
            border_style="red",
        ))
