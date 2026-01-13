"""Network Watcher for IBN Platform.

Monitors network state and detects changes in BGP/BFD status.
"""

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ibn.deploy import DeviceConnector, DeviceCredentials
from ibn.model.topology import Topology


class EventType(Enum):
    """Types of network events."""
    BGP_UP = "bgp_up"
    BGP_DOWN = "bgp_down"
    BFD_UP = "bfd_up"
    BFD_DOWN = "bfd_down"
    DEVICE_UNREACHABLE = "device_unreachable"
    DEVICE_RECOVERED = "device_recovered"


@dataclass
class WatchEvent:
    """A network state change event."""
    timestamp: datetime
    event_type: EventType
    device: str
    neighbor: str | None = None
    details: str = ""


@dataclass
class DeviceState:
    """Current state of a device."""
    hostname: str
    reachable: bool = True
    bgp_neighbors: dict[str, str] = field(default_factory=dict)  # neighbor -> state
    bfd_neighbors: dict[str, str] = field(default_factory=dict)  # neighbor -> state
    last_check: datetime | None = None


class NetworkWatcher:
    """Monitors network devices for state changes.

    Example:
        watcher = NetworkWatcher(topology, credentials)
        watcher.watch(interval=5)  # Poll every 5 seconds
    """

    def __init__(
        self,
        topology: Topology,
        credentials: DeviceCredentials,
    ):
        self.topology = topology
        self.connector = DeviceConnector(credentials)
        self.console = Console()
        self.states: dict[str, DeviceState] = {}
        self.events: list[WatchEvent] = []
        self.callbacks: list[Callable[[WatchEvent], None]] = []

        # Initialize state for each device
        for hostname in topology.nodes:
            self.states[hostname] = DeviceState(hostname=hostname)

    def on_event(self, callback: Callable[[WatchEvent], None]) -> None:
        """Register a callback for network events."""
        self.callbacks.append(callback)

    def _emit_event(self, event: WatchEvent) -> None:
        """Emit an event to all callbacks."""
        self.events.append(event)
        for callback in self.callbacks:
            callback(event)

    def _parse_bgp_neighbors(self, output: str) -> dict[str, str]:
        """Parse BGP neighbor states from show output."""
        neighbors = {}
        # Match lines like: 10.100.12.2     4        65000       2       2        1    0    0 00:00:40        0
        # The last column is State/PfxRcd - if it's a number, session is established
        pattern = r"(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+[\d:]+\s+(\S+)"
        for match in re.finditer(pattern, output):
            neighbor_ip = match.group(1)
            state = match.group(2)
            # If state is a number (prefix count), session is established
            if state.isdigit():
                neighbors[neighbor_ip] = "Established"
            else:
                neighbors[neighbor_ip] = state
        return neighbors

    def _parse_bfd_neighbors(self, output: str) -> dict[str, str]:
        """Parse BFD neighbor states from show output."""
        neighbors = {}
        # Match lines like: 10.100.12.2    4097/4098    Up    Up    Gi1
        pattern = r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+(Up|Down)\s+"
        for match in re.finditer(pattern, output):
            neighbor_ip = match.group(1)
            state = match.group(2)
            neighbors[neighbor_ip] = state
        return neighbors

    def check_device(self, hostname: str) -> list[WatchEvent]:
        """Check a single device and return any events."""
        events = []
        node = self.topology.nodes.get(hostname)
        if not node or not node.mgmt_ip:
            return events

        state = self.states[hostname]
        now = datetime.now()

        # Check BGP
        bgp_result = self.connector.verify_bgp_neighbors(str(node.mgmt_ip), hostname)

        if not bgp_result.success:
            if state.reachable:
                events.append(WatchEvent(
                    timestamp=now,
                    event_type=EventType.DEVICE_UNREACHABLE,
                    device=hostname,
                    details=bgp_result.output,
                ))
                state.reachable = False
        else:
            if not state.reachable:
                events.append(WatchEvent(
                    timestamp=now,
                    event_type=EventType.DEVICE_RECOVERED,
                    device=hostname,
                ))
                state.reachable = True

            # Parse BGP neighbors
            new_bgp = self._parse_bgp_neighbors(bgp_result.output)

            # Check for state changes
            for neighbor, new_state in new_bgp.items():
                old_state = state.bgp_neighbors.get(neighbor)
                if old_state != new_state:
                    if new_state == "Established":
                        events.append(WatchEvent(
                            timestamp=now,
                            event_type=EventType.BGP_UP,
                            device=hostname,
                            neighbor=neighbor,
                            details=f"State: {old_state} → {new_state}",
                        ))
                    elif old_state == "Established":
                        events.append(WatchEvent(
                            timestamp=now,
                            event_type=EventType.BGP_DOWN,
                            device=hostname,
                            neighbor=neighbor,
                            details=f"State: {old_state} → {new_state}",
                        ))

            state.bgp_neighbors = new_bgp

        # Check BFD
        bfd_result = self.connector.verify_bfd_neighbors(str(node.mgmt_ip), hostname)

        if bfd_result.success:
            new_bfd = self._parse_bfd_neighbors(bfd_result.output)

            for neighbor, new_state in new_bfd.items():
                old_state = state.bfd_neighbors.get(neighbor)
                if old_state != new_state:
                    if new_state == "Up":
                        events.append(WatchEvent(
                            timestamp=now,
                            event_type=EventType.BFD_UP,
                            device=hostname,
                            neighbor=neighbor,
                        ))
                    elif old_state == "Up":
                        events.append(WatchEvent(
                            timestamp=now,
                            event_type=EventType.BFD_DOWN,
                            device=hostname,
                            neighbor=neighbor,
                        ))

            state.bfd_neighbors = new_bfd

        state.last_check = now
        return events

    def check_all(self) -> list[WatchEvent]:
        """Check all devices and return events."""
        all_events = []
        for hostname in self.topology.nodes:
            events = self.check_device(hostname)
            for event in events:
                self._emit_event(event)
            all_events.extend(events)
        return all_events

    def _build_status_table(self) -> Table:
        """Build a status table for display."""
        table = Table(title="Network Status", show_header=True, header_style="bold cyan")
        table.add_column("Device")
        table.add_column("Status")
        table.add_column("BGP Neighbors")
        table.add_column("BFD Sessions")
        table.add_column("Last Check")

        for hostname, state in self.states.items():
            if not state.reachable:
                status = "[red]UNREACHABLE[/red]"
            else:
                status = "[green]OK[/green]"

            bgp_up = sum(1 for s in state.bgp_neighbors.values() if s == "Established")
            bgp_total = len(state.bgp_neighbors)
            bgp_str = f"[green]{bgp_up}[/green]/{bgp_total}" if bgp_up == bgp_total else f"[yellow]{bgp_up}[/yellow]/{bgp_total}"

            bfd_up = sum(1 for s in state.bfd_neighbors.values() if s == "Up")
            bfd_total = len(state.bfd_neighbors)
            bfd_str = f"[green]{bfd_up}[/green]/{bfd_total}" if bfd_up == bfd_total else f"[yellow]{bfd_up}[/yellow]/{bfd_total}"

            last_check = state.last_check.strftime("%H:%M:%S") if state.last_check else "-"

            table.add_row(hostname, status, bgp_str, bfd_str, last_check)

        return table

    def _build_events_panel(self, max_events: int = 10) -> Panel:
        """Build a panel showing recent events."""
        if not self.events:
            content = "[dim]No events yet[/dim]"
        else:
            lines = []
            for event in self.events[-max_events:]:
                time_str = event.timestamp.strftime("%H:%M:%S")

                if event.event_type == EventType.BGP_DOWN:
                    icon = "[red]▼[/red]"
                    msg = f"BGP DOWN: {event.device} → {event.neighbor}"
                elif event.event_type == EventType.BGP_UP:
                    icon = "[green]▲[/green]"
                    msg = f"BGP UP: {event.device} → {event.neighbor}"
                elif event.event_type == EventType.BFD_DOWN:
                    icon = "[red]▼[/red]"
                    msg = f"BFD DOWN: {event.device} → {event.neighbor}"
                elif event.event_type == EventType.BFD_UP:
                    icon = "[green]▲[/green]"
                    msg = f"BFD UP: {event.device} → {event.neighbor}"
                elif event.event_type == EventType.DEVICE_UNREACHABLE:
                    icon = "[red]✗[/red]"
                    msg = f"UNREACHABLE: {event.device}"
                elif event.event_type == EventType.DEVICE_RECOVERED:
                    icon = "[green]✓[/green]"
                    msg = f"RECOVERED: {event.device}"
                else:
                    icon = "[dim]•[/dim]"
                    msg = str(event)

                lines.append(f"[dim]{time_str}[/dim] {icon} {msg}")

            content = "\n".join(reversed(lines))

        return Panel(content, title="Recent Events", border_style="yellow")

    def watch(self, interval: int = 5, max_iterations: int | None = None) -> None:
        """Start watching the network with live updates.

        Args:
            interval: Seconds between checks
            max_iterations: Maximum number of check cycles (None = infinite)
        """
        self.console.print(f"\n[bold]Starting network watch (polling every {interval}s)...[/bold]")
        self.console.print("[dim]Press Ctrl+C to stop[/dim]\n")

        # Initial check
        self.check_all()

        iteration = 0
        try:
            with Live(console=self.console, refresh_per_second=1) as live:
                while max_iterations is None or iteration < max_iterations:
                    # Build display
                    status_table = self._build_status_table()
                    events_panel = self._build_events_panel()

                    # Combine into layout
                    display = Table.grid()
                    display.add_row(status_table)
                    display.add_row(events_panel)

                    live.update(display)

                    # Wait and check again
                    time.sleep(interval)
                    self.check_all()
                    iteration += 1

        except KeyboardInterrupt:
            self.console.print("\n[yellow]Watch stopped[/yellow]")
