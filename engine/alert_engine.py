"""RegAudit Alert Engine.

Dispatches registry change events to SQLite persistence, rotating audit logs, and
real-time terminal alerts. Renders high-visibility Rich panels and emits audible bell
notifications for CRITICAL and HIGH severity malware indicators.
"""

from __future__ import annotations

import collections
import logging
import sys
import threading
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Deque, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel

if TYPE_CHECKING:
    from database.db_manager import DatabaseManager

LOGGER = logging.getLogger("RegAudit.AlertEngine")


class AlertEngine:
    """Coordinates alerting, persistent logging, and statistics for detected registry events."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        session_id: Optional[str] = None,
        console: Optional[Console] = None,
        max_recent_feed: int = 100,
    ) -> None:
        """Initialize the AlertEngine.

        Args:
            db_manager: Optional DatabaseManager instance for SQLite storage.
            session_id: Current monitoring session identifier.
            console: Rich console instance for terminal rendering.
            max_recent_feed: Size of in-memory feed ring-buffer.
        """
        self.db_manager = db_manager
        self.session_id = session_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.console = console or Console(force_terminal=True, highlight=False)
        self._lock = threading.Lock()

        # In-memory buffer for real-time terminal UI feed
        self.recent_changes: Deque[Dict[str, Any]] = collections.deque(maxlen=max_recent_feed)

        # Statistics
        self.total_changes = 0
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0

        # Recent pattern matches for dashboard sidebar
        self.recent_patterns: Deque[Dict[str, str]] = collections.deque(maxlen=10)

        # Optional UI callback to signal arrival of new alerts
        self.on_alert_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def register_callback(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback for alert notifications."""
        self.on_alert_callbacks.append(cb)

    def on_change(
        self,
        change: Dict[str, Any],
        severity: str,
        pattern: str,
        detail: str,
    ) -> None:
        """Process a detected change event across storage, log files, and interactive displays.

        Args:
            change: Event data containing hive, key_path, value_name, change_type, etc.
            severity: Classified severity ("CRITICAL", "HIGH", "MEDIUM", "LOW").
            pattern: Matched malware rule or description.
            detail: Contextual explanation of the change.
        """
        sev = severity.upper()
        now_iso = change.get("timestamp") or datetime.now(timezone.utc).isoformat()
        hive = change.get("hive", "")
        key_path = change.get("key_path", "")
        value_name = change.get("value_name", "")
        change_type = change.get("change_type", "MODIFIED")
        old_data = change.get("old_data")
        new_data = change.get("new_data")
        old_type = change.get("old_type")
        new_type = change.get("new_type")

        event_record = {
            "timestamp": now_iso,
            "hive": hive,
            "key_path": key_path,
            "value_name": value_name,
            "change_type": change_type,
            "old_data": old_data,
            "new_data": new_data,
            "old_type": old_type,
            "new_type": new_type,
            "severity": sev,
            "pattern_matched": pattern,
            "detail": detail,
            "session_id": self.session_id,
        }

        with self._lock:
            self.total_changes += 1
            if sev == "CRITICAL":
                self.critical_count += 1
            elif sev == "HIGH":
                self.high_count += 1
            elif sev == "MEDIUM":
                self.medium_count += 1
            else:
                self.low_count += 1

            self.recent_changes.appendleft(event_record)

            if pattern and not pattern.startswith("General") and not pattern.startswith("Registry Entry Removed"):
                self.recent_patterns.appendleft(
                    {
                        "pattern": pattern,
                        "severity": sev,
                        "time": now_iso[11:19] if len(now_iso) >= 19 else now_iso,
                    }
                )

        # 1. Insert into SQLite Database
        if self.db_manager:
            try:
                self.db_manager.insert_change(event_record)
            except Exception as exc:
                LOGGER.error("Failed to persist change to SQLite: %s", exc)

        # 2. Write to Rotating File Log
        log_msg = (
            f"[{sev}] {change_type} {hive}\\{key_path}\\{value_name} | "
            f"Old: '{old_data}' | New: '{new_data}' | Pattern: {pattern} | {detail}"
        )
        if sev == "CRITICAL":
            LOGGER.critical(log_msg)
        elif sev == "HIGH":
            LOGGER.error(log_msg)
        elif sev == "MEDIUM":
            LOGGER.warning(log_msg)
        else:
            LOGGER.info(log_msg)

        # 3. Direct Terminal Alerts (outside full-screen dashboard or during CLI diff)
        # Note: If live dashboard is handling UI, it renders these from the recent_changes queue.
        # However, if standalone or printing directly:
        # Emit terminal bell for CRITICAL
        if sev == "CRITICAL":
            try:
                sys.stdout.write("\a")
                sys.stdout.flush()
            except Exception:
                pass

        # Trigger registered callbacks
        for cb in self.on_alert_callbacks:
            try:
                cb(event_record)
            except Exception as cb_exc:
                LOGGER.debug("Error in alert callback: %s", cb_exc)

    def get_recent_changes(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Retrieve a copy of the most recent change records."""
        with self._lock:
            return list(self.recent_changes)[:limit]

    def get_stats(self) -> Dict[str, int]:
        """Obtain snapshot of current session metrics."""
        with self._lock:
            return {
                "total": self.total_changes,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            }
