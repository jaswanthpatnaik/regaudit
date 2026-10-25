"""RegAudit Platform Verification and Privilege Detection.

Verifies OS runtime environment (Windows vs. POSIX/Kali Linux), validates administrative
elevation for sensitive HKLM registry access, and renders helpful diagnostic panels.
"""

from __future__ import annotations

import os
import platform
import sys
from typing import NamedTuple

from rich.console import Console
from rich.panel import Panel

console = Console()


class PlatformStatus(NamedTuple):
    """Encapsulates system platform attributes and privilege levels."""

    is_windows: bool
    is_linux: bool
    is_admin: bool
    os_name: str
    os_version: str
    hostname: str


def get_platform_status() -> PlatformStatus:
    """Detect current operating system and privilege elevation status.

    Returns:
        PlatformStatus named tuple with system details.
    """
    is_win = sys.platform == "win32"
    is_lin = sys.platform.startswith("linux")
    is_admin = False

    if is_win:
        try:
            import ctypes

            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        except Exception:
            is_admin = False
    elif is_lin:
        try:
            is_admin = os.geteuid() == 0
        except (AttributeError, OSError):
            is_admin = False

    return PlatformStatus(
        is_windows=is_win,
        is_linux=is_lin,
        is_admin=is_admin,
        os_name=platform.system(),
        os_version=platform.release(),
        hostname=platform.node(),
    )


def assert_windows_supported(allow_export_only: bool = False) -> bool:
    """Validate that the current environment supports Windows registry operations.

    Args:
        allow_export_only: If True, allows running on non-Windows for offline export.

    Returns:
        True if running on Windows, or False if in export-only mode on POSIX.
    """
    status = get_platform_status()

    if status.is_windows:
        if not status.is_admin:
            console.print(
                Panel(
                    "[bold yellow]WARNING: Running without Administrator Privileges![/bold yellow]\n\n"
                    "RegAudit is reading user-level keys (HKCU) and standard machine keys (HKLM),\n"
                    "but certain sensitive security keys (e.g. Defender, SAM, SafeBoot policies)\n"
                    "require Administrator elevation for complete visibility.\n"
                    "[dim]Recommended: Restart terminal with 'Run as Administrator'.[/dim]",
                    title="[bold yellow]Privilege Notice[/bold yellow]",
                    border_style="yellow",
                )
            )
        return True

    # Non-Windows environment (e.g. Kali Linux)
    if allow_export_only:
        console.print(
            Panel(
                f"[bold cyan]Kali Linux / POSIX Environment Detected ({status.hostname})[/bold cyan]\n\n"
                "Registry live monitoring: [bold red]Windows Only[/bold red] (winreg unavailable on Linux).\n"
                "Running in [bold green]Offline Analysis & Report Export Mode[/bold green].\n"
                "Reading stored SQLite change records to generate audit artifacts.",
                title="[bold cyan]RegAudit — Platform Compatibility Notice[/bold cyan]",
                border_style="cyan",
            )
        )
        return False

    console.print(
        Panel(
            f"[bold red]Incompatible Platform: {status.os_name} ({sys.platform})[/bold red]\n\n"
            "Live Windows Registry monitoring requires a Windows 10, Windows 11, or Windows Server host.\n\n"
            "[bold white]Available on Kali Linux:[/bold white]\n"
            "  • Offline HTML Report Export: [yellow]python main.py --export report.html[/yellow]\n"
            "  • Database inspection of transferred 'regaudit.db' files\n\n"
            "Please run live monitoring from a Windows environment.",
            title="[bold red]RegAudit — Platform Error[/bold red]",
            border_style="red",
        )
    )
    return False
