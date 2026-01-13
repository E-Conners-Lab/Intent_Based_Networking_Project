"""Configuration Diff for IBN Platform.

Compares current device configuration with proposed changes.
"""

import difflib
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text


@dataclass
class ConfigDiff:
    """Result of comparing current and proposed configs."""
    hostname: str
    has_changes: bool
    additions: int
    deletions: int
    diff_lines: list[str]
    current_config: str
    proposed_config: str


def generate_diff(
    hostname: str,
    current_config: str,
    proposed_config: str,
) -> ConfigDiff:
    """Generate a diff between current and proposed configuration.

    Args:
        hostname: Device hostname
        current_config: Current running config (or empty if new)
        proposed_config: Proposed configuration to apply

    Returns:
        ConfigDiff with diff details
    """
    current_lines = current_config.splitlines(keepends=True)
    proposed_lines = proposed_config.splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        current_lines,
        proposed_lines,
        fromfile=f"{hostname} (current)",
        tofile=f"{hostname} (proposed)",
        lineterm="",
    ))

    additions = sum(1 for line in diff if line.startswith("+") and not line.startswith("+++"))
    deletions = sum(1 for line in diff if line.startswith("-") and not line.startswith("---"))

    return ConfigDiff(
        hostname=hostname,
        has_changes=len(diff) > 0,
        additions=additions,
        deletions=deletions,
        diff_lines=diff,
        current_config=current_config,
        proposed_config=proposed_config,
    )


def display_diff(diff: ConfigDiff, console: Console | None = None) -> None:
    """Display a configuration diff with Rich formatting.

    Args:
        diff: ConfigDiff to display
        console: Rich console (creates one if not provided)
    """
    if console is None:
        console = Console()

    if not diff.has_changes:
        console.print(f"[dim]{diff.hostname}: No changes[/dim]")
        return

    # Build colored diff output
    diff_text = Text()

    for line in diff.diff_lines:
        if line.startswith("+++") or line.startswith("---"):
            diff_text.append(line + "\n", style="bold")
        elif line.startswith("@@"):
            diff_text.append(line + "\n", style="cyan")
        elif line.startswith("+"):
            diff_text.append(line + "\n", style="green")
        elif line.startswith("-"):
            diff_text.append(line + "\n", style="red")
        else:
            diff_text.append(line + "\n", style="dim")

    # Summary
    summary = f"[green]+{diff.additions}[/green] additions, [red]-{diff.deletions}[/red] deletions"

    console.print(Panel(
        diff_text,
        title=f"[bold]{diff.hostname}[/bold] - {summary}",
        border_style="yellow",
    ))


def display_diff_summary(diffs: list[ConfigDiff], console: Console | None = None) -> None:
    """Display a summary table of all diffs.

    Args:
        diffs: List of ConfigDiff objects
        console: Rich console
    """
    if console is None:
        console = Console()

    from rich.table import Table

    table = Table(title="Configuration Changes", show_header=True, header_style="bold cyan")
    table.add_column("Device")
    table.add_column("Status")
    table.add_column("Additions", justify="right")
    table.add_column("Deletions", justify="right")

    total_additions = 0
    total_deletions = 0

    for diff in diffs:
        if diff.has_changes:
            status = "[yellow]MODIFIED[/yellow]"
            total_additions += diff.additions
            total_deletions += diff.deletions
        else:
            status = "[dim]No changes[/dim]"

        table.add_row(
            diff.hostname,
            status,
            f"[green]+{diff.additions}[/green]" if diff.additions else "-",
            f"[red]-{diff.deletions}[/red]" if diff.deletions else "-",
        )

    # Total row
    table.add_row(
        "[bold]Total[/bold]",
        "",
        f"[bold green]+{total_additions}[/bold green]",
        f"[bold red]-{total_deletions}[/bold red]",
        style="bold",
    )

    console.print(table)
