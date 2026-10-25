"""RegAudit — Windows Registry Change Monitoring System.

Main application entry point. Coordinates baseline capture, diff analysis,
continuous monitoring poller, rich live terminal UI, and HTML report exporting.
"""

from __future__ import annotations

import colorama

colorama.init(autoreset=True)

import argparse
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is available on sys.path for direct python main.py invocation
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from baseline.snapshot import BaselineManager
from config.loader import RegAuditConfig, load_config
from config.registry_keys import ALL_MONITORED_KEYS
from dashboard.ui import TerminalDashboard
from database.db_manager import DatabaseManager
from engine.alert_engine import AlertEngine
from engine.change_analyzer import ChangeAnalyzer
from monitor.poller import RegistryPoller, detect_differences
from reporter.html_exporter import HtmlExporter
from utils.logger import setup_logging
from utils.platform_check import assert_windows_supported, get_platform_status
from utils.registry_helpers import WINREG_AVAILABLE

console = Console(force_terminal=True, highlight=False)


def handle_baseline_capture(
    baseline_mgr: BaselineManager, db_mgr: DatabaseManager, notes: str = "CLI baseline capture"
) -> int:
    """Capture initial cryptographic baseline and persist to JSON and SQLite.

    Returns:
        Exit code (0 on success, 1 on failure).
    """
    if not assert_windows_supported(allow_export_only=False):
        return 1

    console.print(
        Panel(
            "[bold cyan]RegAudit &mdash; Cryptographic Baseline Capture[/bold cyan]\n"
            f"Scanning {len(ALL_MONITORED_KEYS)} root sensitive registry paths...",
            box=box.ROUNDED,
            style="cyan",
        )
    )

    try:
        data = baseline_mgr.create(notes=notes)
        entries = data.get("entries", {})
        total_keys = len(ALL_MONITORED_KEYS)
        total_vals = len(entries)

        # Record to SQLite
        db_mgr.record_baseline_snapshot(
            total_keys=total_keys,
            total_values=total_vals,
            notes=notes,
            captured_at=data.get("metadata", {}).get("captured_at"),
        )

        table = Table(box=box.ROUNDED, title="Baseline Capture Summary", style="green")
        table.add_column("Property", style="bold white")
        table.add_column("Value", style="cyan")
        table.add_row("Snapshot Path", str(baseline_mgr.baseline_path))
        table.add_row("Root Keys Monitored", str(total_keys))
        table.add_row("Registry Values Indexed & Hashed", str(total_vals))
        table.add_row("Timestamp (UTC)", str(data.get("metadata", {}).get("captured_at", "")))
        console.print(table)

        console.print(
            "[bold green]SUCCESS:[/bold green] Baseline successfully initialized. "
            "You can now launch live monitoring with [yellow]python main.py[/yellow].\n"
        )
        return 0

    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] Failed to capture baseline snapshot: {exc}")
        logging.getLogger("RegAudit").error("Baseline capture failed: %s", exc, exc_info=True)
        return 1


def handle_diff_audit(
    baseline_mgr: BaselineManager,
    analyzer: ChangeAnalyzer,
    db_mgr: DatabaseManager,
) -> int:
    """Compare current live registry state against saved baseline and print summary table.

    Returns:
        Exit code (0 on success, 1 on failure).
    """
    if not assert_windows_supported(allow_export_only=False):
        return 1

    if not baseline_mgr.exists():
        console.print(
            Panel(
                "[bold red]Baseline Not Found![/bold red]\n"
                "No baseline snapshot exists yet. Run:\n"
                "  [bold yellow]python main.py --baseline[/bold yellow]\n"
                "to capture the initial reference state.",
                box=box.ROUNDED,
                style="red",
            )
        )
        return 1

    try:
        baseline_data = baseline_mgr.load()
        baseline_entries = baseline_data.get("entries", {})
        console.print(
            f"[bold cyan]Comparing live registry against baseline ({len(baseline_entries)} reference values)...[/bold cyan]"
        )

        live_entries = baseline_mgr.capture_current_state(ALL_MONITORED_KEYS)
        changes = detect_differences(baseline_entries, live_entries)

        if not changes:
            console.print(
                Panel(
                    "[bold green]INTEGRITY VERIFIED: ZERO DEVIATIONS[/bold green]\n\n"
                    f"All {len(live_entries)} registry values match stored baseline hashes exactly.\n"
                    "No unauthorized additions, modifications, or deletions detected.",
                    title="[bold green]RegAudit Diff Results[/bold green]",
                    box=box.ROUNDED,
                )
            )
            return 0

        # Render Table of Changes
        table = Table(
            title=f"RegAudit Integrity Audit &mdash; {len(changes)} Baseline Deviation(s) Detected",
            box=box.DOUBLE_EDGE,
            header_style="bold cyan",
        )
        table.add_column("SEV", width=10, justify="center")
        table.add_column("Type", width=10, justify="center")
        table.add_column("Target Path & Value", ratio=3)
        table.add_column("Delta (Old -> New)", ratio=3)
        table.add_column("Matched Rule", ratio=2)

        for c in changes:
            sev, pattern, detail = analyzer.analyze(c)
            # Persist to database
            c_record = {
                "timestamp": c.get("timestamp"),
                "hive": c.get("hive"),
                "key_path": c.get("key_path"),
                "value_name": c.get("value_name"),
                "change_type": c.get("change_type"),
                "old_data": c.get("old_data"),
                "new_data": c.get("new_data"),
                "old_type": c.get("old_type"),
                "new_type": c.get("new_type"),
                "severity": sev,
                "pattern_matched": pattern,
                "detail": detail,
                "session_id": "diff_audit",
            }
            db_mgr.insert_change(c_record)

            sev_style = "bold white on red" if sev == "CRITICAL" else ("bold red" if sev == "HIGH" else "yellow")
            type_style = "green" if c["change_type"] == "ADDED" else ("red" if c["change_type"] == "DELETED" else "yellow")

            target = f"{c['hive']}\\{c['key_path']}\\{c['value_name']}"
            delta = f"{str(c['old_data'])[:25]} -> {str(c['new_data'])[:25]}"

            table.add_row(
                Text(sev, style=sev_style),
                Text(c["change_type"], style=type_style),
                target,
                delta,
                pattern or detail[:30],
            )

        console.print(table)
        return 0

    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] Diff audit failed: {exc}")
        return 1


def handle_export_report(
    db_mgr: DatabaseManager,
    baseline_mgr: BaselineManager,
    output_path: Path,
    last_n: Optional[int] = None,
) -> int:
    """Generate self-contained HTML audit report.

    Works on Windows and Kali Linux (secondary target).

    Returns:
        Exit code (0 on success, 1 on failure).
    """
    assert_windows_supported(allow_export_only=True)

    console.print(f"[bold cyan]Compiling RegAudit HTML report to {output_path}...[/bold cyan]")

    baseline_data: Dict[str, Any] = {}
    if baseline_mgr.exists():
        try:
            baseline_data = baseline_mgr.load()
        except Exception:
            baseline_data = {}

    try:
        exporter = HtmlExporter(db_manager=db_mgr, baseline_data=baseline_data)
        final_file = exporter.generate_html(output_path, last_n_changes=last_n)

        console.print(
            Panel(
                f"[bold green]Report Generated Successfully![/bold green]\n\n"
                f"File: [bold white]{final_file}[/bold white]\n"
                f"File Size: {final_file.stat().st_size:,} bytes\n"
                "Self-contained dark-theme HTML report with zero external dependencies.",
                title="[bold green]RegAudit &bull; Export Completed[/bold green]",
                box=box.ROUNDED,
            )
        )
        return 0
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] Failed to export HTML report: {exc}")
        return 1


def run_live_monitoring(
    config: RegAuditConfig,
    baseline_mgr: BaselineManager,
    db_mgr: DatabaseManager,
    max_duration: Optional[float] = None,
) -> int:
    """Start continuous live monitoring daemon and terminal UI."""
    if not assert_windows_supported(allow_export_only=False):
        return 1

    session_id = datetime.now(timezone.utc).strftime("session_%Y%m%d_%H%M%S")
    db_mgr.start_session(session_id=session_id, baseline_used=str(baseline_mgr.baseline_path))

    # Check baseline existence, auto-capture if missing
    if not baseline_mgr.exists():
        console.print(
            "[bold yellow]No prior baseline detected. Automatically capturing reference snapshot...[/bold yellow]"
        )
        baseline_mgr.create("Auto-captured at session startup")

    analyzer = ChangeAnalyzer(config=config)
    alert_engine = AlertEngine(
        db_manager=db_mgr,
        session_id=session_id,
        console=console,
    )

    poller = RegistryPoller(
        baseline_manager=baseline_mgr,
        analyzer=analyzer,
        alert_engine=alert_engine,
        poll_interval_seconds=config.poll_interval_seconds,
        monitored_keys=ALL_MONITORED_KEYS,
    )

    def on_export_requested() -> str:
        rep_file = PROJECT_ROOT / f"report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
        exporter = HtmlExporter(db_manager=db_mgr, baseline_data=baseline_mgr.load() if baseline_mgr.exists() else {})
        exporter.generate_html(rep_file)
        return rep_file.name

    dashboard = TerminalDashboard(
        poller=poller,
        alert_engine=alert_engine,
        baseline_manager=baseline_mgr,
        db_manager=db_mgr,
        export_callback=on_export_requested,
    )

    # Clean signal handling
    def sig_handler(sig: int, frame: Any) -> None:
        poller.stop()

    try:
        signal.signal(signal.SIGINT, sig_handler)
    except Exception:
        pass

    # Start poller daemon thread
    poller.start()

    try:
        # Launch terminal UI loop
        dashboard.render_loop(max_duration=max_duration)
    except KeyboardInterrupt:
        poller.stop()
    finally:
        poller.stop()
        stats = alert_engine.get_stats()
        db_mgr.close_session(session_id=session_id, stats=stats)
        console.print("\n[bold cyan]Monitoring session finalized. Audit logs persisted to SQLite and disk.[/bold cyan]")

    return 0


def main() -> None:
    """Parse CLI arguments and dispatch execution."""
    parser = argparse.ArgumentParser(
        prog="RegAudit",
        description="RegAudit — Windows Registry Change Monitoring System (Cybersecurity Intern Deliverable)",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Capture an initial cryptographic baseline snapshot of all monitored keys.",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Perform a one-time integrity check comparing current registry state against baseline.",
    )
    parser.add_argument(
        "--export",
        nargs="?",
        const="report.html",
        default=None,
        metavar="FILE",
        help="Export persistent audit history to a self-contained HTML report (default: report.html).",
    )
    parser.add_argument(
        "--last",
        type=int,
        default=None,
        metavar="N",
        help="Limit number of changes exported in HTML report (e.g. --last 200).",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        metavar="SEC",
        help="Run live monitoring for specified seconds and then exit cleanly (useful for automated testing/triage).",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        metavar="FILE",
        help="Path to custom config.yaml file.",
    )

    args = parser.parse_args()

    # Load configuration
    cfg_path = Path(args.config) if args.config else None
    config = load_config(cfg_path)

    # Setup rotating file logger
    setup_logging(
        log_file=config.log_path,
        max_bytes=config.log_max_bytes,
        backup_count=config.log_backup_count,
    )

    # Initialize Core Managers
    db_mgr = DatabaseManager(db_path=config.db_path)
    baseline_mgr = BaselineManager(baseline_path=config.baseline_path)
    analyzer = ChangeAnalyzer(config=config)

    # Dispatch Modes
    if args.baseline:
        sys.exit(handle_baseline_capture(baseline_mgr, db_mgr))
    elif args.diff:
        sys.exit(handle_diff_audit(baseline_mgr, analyzer, db_mgr))
    elif args.export is not None:
        target_html = Path(args.export)
        sys.exit(handle_export_report(db_mgr, baseline_mgr, target_html, last_n=args.last))
    else:
        sys.exit(run_live_monitoring(config, baseline_mgr, db_mgr, max_duration=args.duration))


if __name__ == "__main__":
    main()
