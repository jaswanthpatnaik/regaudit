"""RegAudit Live Terminal Dashboard.

Renders an SSH-safe, Azure-safe full-screen terminal monitoring dashboard using
the Rich library (rich.live.Live, rich.layout.Layout, rich.table.Table, rich.panel.Panel).
Features real-time change streaming, dynamic threat-level badges, keygroup distribution,
and non-blocking keyboard controls.
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from rich import box
from rich.console import Console, RenderableType
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config.registry_keys import ALL_MONITORED_KEYS, get_key_category

if TYPE_CHECKING:
    from baseline.snapshot import BaselineManager
    from database.db_manager import DatabaseManager
    from engine.alert_engine import AlertEngine
    from monitor.poller import RegistryPoller


# Non-blocking keyboard input helper for Windows and POSIX
try:
    import msvcrt

    def check_keypress() -> Optional[str]:
        """Check for single keystroke without blocking on Windows."""
        try:
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                if ch in (b"\x00", b"\xe0"):
                    if msvcrt.kbhit():
                        msvcrt.getch()
                    return None
                return ch.decode("utf-8", errors="ignore").lower()
        except Exception:
            return None
        return None

except ImportError:
    import select

    def check_keypress() -> Optional[str]:
        """Check for single keystroke without blocking on POSIX."""
        if sys.stdin.isatty():
            r, _, _ = select.select([sys.stdin], [], [], 0)
            if r:
                return sys.stdin.read(1).lower()
        return None


class TerminalDashboard:
    """Manages the full-screen terminal dashboard interface."""

    def __init__(
        self,
        poller: RegistryPoller,
        alert_engine: AlertEngine,
        baseline_manager: BaselineManager,
        db_manager: DatabaseManager,
        export_callback: Optional[Callable[[], str]] = None,
    ) -> None:
        """Initialize TerminalDashboard with engine dependencies.

        Args:
            poller: Active RegistryPoller instance.
            alert_engine: AlertEngine with in-memory alert history.
            baseline_manager: BaselineManager for snapshot info and rebuilds.
            db_manager: DatabaseManager for change records.
            export_callback: Optional function invoked when 'E' key is pressed to generate HTML report.
        """
        self.poller = poller
        self.alert_engine = alert_engine
        self.baseline_manager = baseline_manager
        self.db_manager = db_manager
        self.export_callback = export_callback

        self.console = Console(force_terminal=True, highlight=False)
        self.start_time = time.time()
        self.status_message = "Monitoring active..."
        self.status_timer = 0.0
        self.show_help = False

    def get_uptime_str(self) -> str:
        """Format elapsed monitoring time as HH:MM:SS."""
        elapsed = int(time.time() - self.start_time)
        hours, rem = divmod(elapsed, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def build_header(self) -> Panel:
        """Render the double-edged top header panel."""
        hostname = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "Windows-Host"
        platform_str = "Windows (winreg)" if sys.platform == "win32" else f"POSIX ({sys.platform})"
        baseline_status = "LOADED" if self.baseline_manager.exists() else "NO BASELINE"
        cycle_num = self.poller.poll_cycles
        uptime = self.get_uptime_str()

        stats = self.alert_engine.get_stats()
        monitored_count = len(ALL_MONITORED_KEYS)

        header_text = Text()
        header_text.append("RegAudit v1.0 — Windows Registry Change Monitoring System\n", style="bold white on dark_blue")
        header_text.append(f"Platform: {platform_str}  |  Host: {hostname}  |  Baseline: {baseline_status}  |  Uptime: {uptime}  |  Poll #{cycle_num}\n", style="cyan")
        header_text.append(f"Keys Monitored: {monitored_count}  |  ", style="bright_white")
        header_text.append(f"CRITICAL: {stats['critical']}  ", style="bold red")
        header_text.append(f"HIGH: {stats['high']}  ", style="bold dark_orange")
        header_text.append(f"MEDIUM: {stats['medium']}  ", style="yellow")
        header_text.append(f"LOW: {stats['low']} today", style="green")

        return Panel(
            header_text,
            box=box.DOUBLE_EDGE,
            style="bold white on dark_blue",
            padding=(0, 1),
        )

    def build_change_table(self) -> Table:
        """Render the live change feed table (last 30 changes, newest first)."""
        table = Table(
            box=box.SIMPLE_HEAVY,
            expand=True,
            show_header=True,
            header_style="bold cyan",
            row_styles=["", "dim"],
        )
        table.add_column("Time", width=8, no_wrap=True)
        table.add_column("SEV", width=8, justify="center")
        table.add_column("Type", width=8, justify="center")
        table.add_column("Hive", width=5)
        table.add_column("Key Path", ratio=2, overflow="ellipsis")
        table.add_column("Value", ratio=1, overflow="ellipsis")
        table.add_column("Change / Data", ratio=2, overflow="ellipsis")

        recent = self.alert_engine.get_recent_changes(limit=30)
        if not recent:
            table.add_row(
                datetime.now(timezone.utc).strftime("%H:%M:%S"),
                Text("INFO", style="bold green"),
                "-",
                "-",
                "Baseline verified — No changes detected",
                "-",
                "System state intact",
            )
            return table

        for item in recent:
            t_str = str(item.get("timestamp", ""))[11:19] or "--:--:--"
            sev = str(item.get("severity", "LOW")).upper()

            # Severity Styling
            if sev == "CRITICAL":
                sev_styled = Text(sev, style="bold white on red")
            elif sev == "HIGH":
                sev_styled = Text(sev, style="bold red")
            elif sev == "MEDIUM":
                sev_styled = Text(sev, style="bold yellow")
            else:
                sev_styled = Text(sev, style="dim cyan")

            # Change Type Styling
            ctype = str(item.get("change_type", "MODIFIED")).upper()
            if ctype == "ADDED":
                type_styled = Text(ctype, style="bold green")
            elif ctype == "DELETED":
                type_styled = Text(ctype, style="bold red")
            else:
                type_styled = Text(ctype, style="bold yellow")

            hive = str(item.get("hive", ""))
            key_path = str(item.get("key_path", ""))
            val_name = str(item.get("value_name", ""))
            old_d = str(item.get("old_data", "") or "")
            new_d = str(item.get("new_data", "") or "")

            if ctype == "MODIFIED":
                change_desc = Text()
                change_desc.append(old_d[:18] + "..." if len(old_d) > 18 else old_d, style="yellow dim")
                change_desc.append(" -> ", style="bold white")
                change_desc.append(new_d[:18] + "..." if len(new_d) > 18 else new_d, style="bold yellow")
            elif ctype == "ADDED":
                change_desc = Text(new_d[:35], style="green")
            else:  # DELETED
                change_desc = Text(old_d[:35], style="strike red")

            table.add_row(
                t_str,
                sev_styled,
                type_styled,
                hive,
                key_path,
                val_name,
                change_desc,
            )

        return table

    def build_sidebar(self) -> Layout:
        """Construct the four-panel right sidebar."""
        side = Layout()
        side.split_column(
            Layout(name="stats", ratio=2),
            Layout(name="threat", ratio=1),
            Layout(name="patterns", ratio=3),
            Layout(name="groups", ratio=2),
        )

        stats = self.alert_engine.get_stats()

        # Panel 1: Stats
        stats_table = Table.grid(expand=True, padding=(0, 1))
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Count", justify="right", style="bold white")
        stats_table.add_row("Total Changes:", str(stats["total"]))
        stats_table.add_row("Critical Alerts:", f"[bold red]{stats['critical']}[/bold red]")
        stats_table.add_row("High Severity:", f"[bold dark_orange]{stats['high']}[/bold dark_orange]")
        stats_table.add_row("Medium Severity:", f"[yellow]{stats['medium']}[/yellow]")
        stats_table.add_row("Low / Informational:", f"[green]{stats['low']}[/green]")
        side["stats"].update(Panel(stats_table, title="[bold cyan]Session Stats[/bold cyan]", box=box.ROUNDED))

        # Panel 2: Threat Level
        if stats["critical"] > 0:
            threat_badge = Panel(
                "\n[bold white on red]  CRITICAL THREAT  [/bold white on red]\nActive malware signature detected!",
                title="[bold red]Threat Level[/bold red]",
                box=box.ROUNDED,
                style="red",
            )
        elif stats["high"] > 0:
            threat_badge = Panel(
                "\n[bold black on yellow]     ELEVATED ALERT     [/bold black on yellow]\nSecurity policy tampering detected.",
                title="[bold yellow]Threat Level[/bold yellow]",
                box=box.ROUNDED,
                style="yellow",
            )
        else:
            threat_badge = Panel(
                "\n[bold white on dark_green]       SYSTEM CLEAN       [/bold white on dark_green]\nNo hostile modifications observed.",
                title="[bold green]Threat Level[/bold green]",
                box=box.ROUNDED,
                style="green",
            )
        side["threat"].update(threat_badge)

        # Panel 3: Pattern Matches
        pat_table = Table.grid(expand=True, padding=(0, 0))
        pat_table.add_column("Time", width=7, style="dim")
        pat_table.add_column("Rule", style="bold red", overflow="ellipsis")

        if not self.alert_engine.recent_patterns:
            pat_table.add_row("", "[dim]No malicious signatures matched[/dim]")
        else:
            for p in list(self.alert_engine.recent_patterns)[:5]:
                pat_table.add_row(f"{p['time']} ", f"{p['pattern'][:26]}")

        side["patterns"].update(
            Panel(pat_table, title="[bold red]Pattern Matches[/bold red]", box=box.ROUNDED)
        )

        # Panel 4: Key Groups
        autorun_count = sum(1 for _, k in ALL_MONITORED_KEYS if get_key_category(k) == "AUTORUN")
        sec_count = sum(1 for _, k in ALL_MONITORED_KEYS if get_key_category(k) == "SECURITY")
        pers_count = sum(1 for _, k in ALL_MONITORED_KEYS if get_key_category(k) == "PERSISTENCE")

        group_table = Table.grid(expand=True, padding=(0, 1))
        group_table.add_column("Group", style="bold blue")
        group_table.add_column("Keys", justify="right", style="white")
        group_table.add_row("Autorun / Startup:", f"{autorun_count} keys")
        group_table.add_row("Security Policies:", f"{sec_count} keys")
        group_table.add_row("Persistence / IFEO:", f"{pers_count} keys")
        side["groups"].update(Panel(group_table, title="[bold blue]Key Groups[/bold blue]", box=box.ROUNDED))

        return side

    def build_footer(self) -> Panel:
        """Render interactive command footer panel."""
        msg = ""
        if time.time() < self.status_timer:
            msg = f"  |  [bold yellow]{self.status_message}[/bold yellow]"

        footer_text = (
            "[bold white][ Q ][/bold white] Quit    "
            "[bold white][ B ][/bold white] Rebuild Baseline    "
            "[bold white][ E ][/bold white] Export HTML    "
            "[bold white][ H ][/bold white] Toggle Help"
            f"{msg}"
        )
        return Panel(footer_text, box=box.ROUNDED, style="dim white on black", padding=(0, 1))

    def build_layout(self) -> Layout:
        """Compose the full responsive layout hierarchy."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3),
        )

        layout["header"].update(self.build_header())
        layout["footer"].update(self.build_footer())

        layout["body"].split_row(
            Layout(name="left", ratio=62),
            Layout(name="right", ratio=38),
        )

        if self.show_help:
            help_content = (
                "[bold cyan]RegAudit Live Keyboard Navigation[/bold cyan]\n\n"
                "  • [bold white]Q[/bold white] : Terminate monitoring session cleanly and persist session stats.\n"
                "  • [bold white]B[/bold white] : Rebuild the cryptographic baseline snapshot from the current live registry.\n"
                "  • [bold white]E[/bold white] : Export a comprehensive self-contained HTML audit report to disk.\n"
                "  • [bold white]H[/bold white] : Dismiss this help overlay and return to the change feed.\n\n"
                "[dim]Logs are continuously saved to logs/regaudit.log (10MB x 3). Changes stored in SQLite WAL.[/dim]"
            )
            layout["left"].update(Panel(help_content, title="[bold yellow]Help & Controls[/bold yellow]", box=box.ROUNDED))
        else:
            layout["left"].update(
                Panel(
                    self.build_change_table(),
                    title="[bold cyan]Live Registry Change Feed (Last 30 Events)[/bold cyan]",
                    box=box.ROUNDED,
                )
            )

        layout["right"].update(self.build_sidebar())
        return layout

    def render_loop(self, max_duration: Optional[float] = None) -> None:
        """Start the interactive full-screen Live dashboard rendering loop."""
        end_time = (time.time() + max_duration) if max_duration else None
        use_screen = self.console.is_terminal
        with Live(
            self.build_layout(),
            console=self.console,
            screen=use_screen,
            refresh_per_second=2.0,
            auto_refresh=True,
        ) as live:
            while not self.poller.is_stopped():
                if end_time and time.time() >= end_time:
                    self.poller.stop()
                    break

                # Check for keyboard commands
                key = check_keypress()
                if key == "q":
                    self.poller.stop()
                    break
                elif key == "b":
                    self.status_message = "Recapturing cryptographic baseline..."
                    self.status_timer = time.time() + 4.0
                    try:
                        self.baseline_manager.create("Manual baseline rebuild from dashboard")
                        self.poller.rebuild_baseline_in_memory()
                        self.status_message = "Baseline successfully rebuilt!"
                    except Exception as exc:
                        self.status_message = f"Baseline error: {exc}"
                elif key == "e":
                    self.status_message = "Exporting HTML report..."
                    self.status_timer = time.time() + 4.0
                    if self.export_callback:
                        try:
                            outfile = self.export_callback()
                            self.status_message = f"Exported: {outfile}"
                        except Exception as exc:
                            self.status_message = f"Export error: {exc}"
                    else:
                        self.status_message = "Export handler not configured."
                elif key == "h":
                    self.show_help = not self.show_help

                live.update(self.build_layout())
                time.sleep(0.4)
