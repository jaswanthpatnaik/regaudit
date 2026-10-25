"""RegAudit Continuous Registry Poller.

Executes continuous background monitoring of sensitive Windows Registry keys
in a dedicated daemon thread. Detects additions, modifications, and deletions
against cryptographic baselines and forwards detected events to the ChangeAnalyzer
and AlertEngine.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from baseline.snapshot import BaselineManager, build_entry_key
from config.registry_keys import ALL_MONITORED_KEYS
from utils.registry_helpers import WINREG_AVAILABLE

if TYPE_CHECKING:
    from engine.alert_engine import AlertEngine
    from engine.change_analyzer import ChangeAnalyzer

LOGGER = logging.getLogger("RegAudit.Poller")


def detect_differences(
    baseline_entries: Dict[str, Dict[str, Any]],
    current_entries: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Compare baseline snapshot entries against current live entries.

    Args:
        baseline_entries: Mapping of entry_id to baseline dictionary.
        current_entries: Mapping of entry_id to live captured dictionary.

    Returns:
        List of change event dictionaries with change_type ADDED, MODIFIED, or DELETED.
    """
    changes: List[Dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Check for ADDED and MODIFIED values
    for entry_id, live_val in current_entries.items():
        if entry_id not in baseline_entries:
            changes.append(
                {
                    "timestamp": now_iso,
                    "hive": live_val["hive"],
                    "key_path": live_val["key"],
                    "value_name": live_val["value_name"],
                    "change_type": "ADDED",
                    "old_data": None,
                    "new_data": live_val["data"],
                    "old_type": None,
                    "new_type": live_val["data_type"],
                    "sha256_old": None,
                    "sha256_new": live_val["sha256"],
                }
            )
        else:
            base_val = baseline_entries[entry_id]
            # Compare both SHA-256 and literal string data
            if (live_val["sha256"] != base_val["sha256"]) or (live_val["data"] != base_val["data"]):
                changes.append(
                    {
                        "timestamp": now_iso,
                        "hive": live_val["hive"],
                        "key_path": live_val["key"],
                        "value_name": live_val["value_name"],
                        "change_type": "MODIFIED",
                        "old_data": base_val["data"],
                        "new_data": live_val["data"],
                        "old_type": base_val["data_type"],
                        "new_type": live_val["data_type"],
                        "sha256_old": base_val["sha256"],
                        "sha256_new": live_val["sha256"],
                    }
                )

    # 2. Check for DELETED values
    for entry_id, base_val in baseline_entries.items():
        if entry_id not in current_entries:
            changes.append(
                {
                    "timestamp": now_iso,
                    "hive": base_val["hive"],
                    "key_path": base_val["key"],
                    "value_name": base_val["value_name"],
                    "change_type": "DELETED",
                    "old_data": base_val["data"],
                    "new_data": None,
                    "old_type": base_val["data_type"],
                    "new_type": None,
                    "sha256_old": base_val["sha256"],
                    "sha256_new": None,
                }
            )

    return changes


class RegistryPoller(threading.Thread):
    """Background daemon thread that continuously audits registry keys against baseline."""

    def __init__(
        self,
        baseline_manager: BaselineManager,
        analyzer: ChangeAnalyzer,
        alert_engine: AlertEngine,
        poll_interval_seconds: int = 10,
        monitored_keys: Optional[List[Tuple[int, str]]] = None,
        on_cycle_complete: Optional[Callable[[int], None]] = None,
    ) -> None:
        """Initialize the background polling thread.

        Args:
            baseline_manager: Manager providing baseline data and capture logic.
            analyzer: ChangeAnalyzer instance for malware signature matching.
            alert_engine: AlertEngine instance for dispatching alerts & logs.
            poll_interval_seconds: Delay in seconds between polling cycles.
            monitored_keys: Monitored keys list. Defaults to ALL_MONITORED_KEYS.
            on_cycle_complete: Optional callback invoked when a poll cycle finishes.
        """
        super().__init__(daemon=True, name="RegAudit-PollerThread")
        self.baseline_manager = baseline_manager
        self.analyzer = analyzer
        self.alert_engine = alert_engine
        self.poll_interval = max(1, poll_interval_seconds)
        self.monitored_keys = monitored_keys or ALL_MONITORED_KEYS
        self.on_cycle_complete = on_cycle_complete

        self._stop_event = threading.Event()
        self.poll_cycles = 0
        self.last_poll_time: Optional[datetime] = None
        self.active_state: Dict[str, Dict[str, Any]] = {}

        # Initialize active reference state from baseline
        if self.baseline_manager.exists():
            try:
                base_data = self.baseline_manager.load()
                self.active_state = dict(base_data.get("entries", {}))
            except Exception as exc:
                LOGGER.error("Failed to load initial baseline in poller: %s", exc)
                self.active_state = {}

    def stop(self) -> None:
        """Signal the polling thread to terminate."""
        self._stop_event.set()

    def is_stopped(self) -> bool:
        """Return True if termination was requested."""
        return self._stop_event.is_set()

    def rebuild_baseline_in_memory(self) -> None:
        """Reload or update the active reference state after a baseline re-capture."""
        if self.baseline_manager.exists():
            try:
                base_data = self.baseline_manager.load()
                self.active_state = dict(base_data.get("entries", {}))
                LOGGER.info("Poller reloaded baseline: %d entries loaded.", len(self.active_state))
            except Exception as exc:
                LOGGER.error("Error reloading baseline in poller: %s", exc)

    def run_single_poll(self) -> List[Dict[str, Any]]:
        """Perform a single synchronous comparison against active state.

        Returns:
            List of detected change dictionaries.
        """
        if not WINREG_AVAILABLE:
            LOGGER.debug("Poller skipped: winreg unavailable on this platform.")
            return []

        try:
            current_state = self.baseline_manager.capture_current_state(self.monitored_keys)
        except Exception as exc:
            LOGGER.error("Unexpected error capturing registry state: %s", exc)
            return []

        # If we had no prior active state, initialize it now
        if not self.active_state:
            self.active_state = current_state
            return []

        changes = detect_differences(self.active_state, current_state)

        for change in changes:
            try:
                severity, pattern, detail = self.analyzer.analyze(change)
                self.alert_engine.on_change(change, severity, pattern, detail)
            except Exception as exc:
                LOGGER.error("Error processing change alert: %s", exc)

        # Update active state to match current live snapshot so changes are only alerted once
        self.active_state = current_state
        self.poll_cycles += 1
        self.last_poll_time = datetime.now(timezone.utc)

        if self.on_cycle_complete:
            try:
                self.on_cycle_complete(self.poll_cycles)
            except Exception:
                pass

        return changes

    def run(self) -> None:
        """Main polling thread loop."""
        LOGGER.info("RegistryPoller started. Polling every %d seconds.", self.poll_interval)
        while not self._stop_event.is_set():
            try:
                self.run_single_poll()
            except Exception as exc:
                LOGGER.error("Unhandled exception in RegistryPoller loop: %s", exc)

            # Sleep in small increments for responsive termination
            for _ in range(self.poll_interval * 2):
                if self._stop_event.is_set():
                    break
                time.sleep(0.5)

        LOGGER.info("RegistryPoller thread terminated cleanly.")
