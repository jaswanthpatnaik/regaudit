"""RegAudit Baseline Snapshot Manager.

Captures, persists, and loads comprehensive cryptographic snapshots of all monitored
Windows Registry keys. Stores per-value SHA-256 digests and metadata to verify registry
integrity and establish an immutable baseline for change detection.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config.registry_keys import ALL_MONITORED_KEYS
from utils.platform_check import get_platform_status
from utils.registry_helpers import (
    get_hive_from_name,
    get_hive_name,
    list_subkeys,
    read_key_values,
)

LOGGER = logging.getLogger("RegAudit.Baseline")


def build_entry_key(hive_name: str, key_path: str, value_name: str) -> str:
    """Build standardized unique lookup key for a registry value entry."""
    return f"{hive_name}\\{key_path}\\{value_name}".lower()


class BaselineManager:
    """Manages creation, loading, integrity verification, and updating of the registry baseline."""

    def __init__(self, baseline_path: Path) -> None:
        """Initialize BaselineManager with path to baseline JSON file.

        Args:
            baseline_path: File path where baseline JSON snapshot is saved/loaded.
        """
        self.baseline_path = Path(baseline_path)

    def exists(self) -> bool:
        """Check if a valid baseline file already exists on disk."""
        return self.baseline_path.is_file() and self.baseline_path.stat().st_size > 0

    def capture_current_state(
        self, keys_to_monitor: Optional[List[Tuple[int, str]]] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Read all monitored keys from live registry and assemble structured entries.

        If a key is inaccessible, logs a WARNING and skips without crashing.

        Args:
            keys_to_monitor: List of (hive_handle, subkey_str) pairs to scan. Defaults to ALL_MONITORED_KEYS.

        Returns:
            Dictionary mapping standardized entry keys to value metadata dicts.
        """
        targets = keys_to_monitor or ALL_MONITORED_KEYS
        entries: Dict[str, Dict[str, Any]] = {}
        now_iso = datetime.now(timezone.utc).isoformat()

        for hive, subkey in targets:
            hive_str = get_hive_name(hive, short=True)
            try:
                # 1. Read direct values on the target key
                direct_vals = read_key_values(hive, subkey)
                for val_name, val_info in direct_vals.items():
                    entry_id = build_entry_key(hive_str, subkey, val_name)
                    entries[entry_id] = {
                        "hive": hive_str,
                        "key": subkey,
                        "value_name": val_name,
                        "data": val_info["data"],
                        "data_type": val_info["type"],
                        "sha256": val_info["sha256"],
                        "captured_at": now_iso,
                    }

                # 2. Inspect key child subtrees for specific sensitive persistence/policy containers
                # e.g., Windows Defender policies, Firewall profiles, IFEO debugger entries
                subkey_lower = subkey.lower()
                should_scan_children = any(
                    sig in subkey_lower
                    for sig in [
                        "windows defender",
                        "firewallpolicy",
                        "image file execution options",
                    ]
                )

                if should_scan_children:
                    children = list_subkeys(hive, subkey)
                    for child in children:
                        child_subkey = f"{subkey}\\{child}"
                        child_vals = read_key_values(hive, child_subkey)
                        for val_name, val_info in child_vals.items():
                            entry_id = build_entry_key(hive_str, child_subkey, val_name)
                            entries[entry_id] = {
                                "hive": hive_str,
                                "key": child_subkey,
                                "value_name": val_name,
                                "data": val_info["data"],
                                "data_type": val_info["type"],
                                "sha256": val_info["sha256"],
                                "captured_at": now_iso,
                            }
            except Exception as exc:
                LOGGER.warning("Error scanning key %s\\%s during baseline capture: %s", hive_str, subkey, exc)
                continue

        return entries

    def create(self, notes: str = "Initial baseline capture") -> Dict[str, Any]:
        """Capture live registry state and save complete JSON baseline snapshot to disk.

        Args:
            notes: Optional human-readable notes for this snapshot.

        Returns:
            The complete baseline snapshot dictionary.
        """
        platform_info = get_platform_status()
        LOGGER.info("Starting baseline capture across %d monitored root keys...", len(ALL_MONITORED_KEYS))

        entries = self.capture_current_state()
        now_iso = datetime.now(timezone.utc).isoformat()

        snapshot_data: Dict[str, Any] = {
            "metadata": {
                "captured_at": now_iso,
                "hostname": platform_info.hostname,
                "os_name": platform_info.os_name,
                "os_version": platform_info.os_version,
                "is_admin": platform_info.is_admin,
                "total_keys_monitored": len(ALL_MONITORED_KEYS),
                "total_values_captured": len(entries),
                "notes": notes,
            },
            "entries": entries,
        }

        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(snapshot_data, f, indent=2, sort_keys=True)

        LOGGER.info(
            "Baseline snapshot successfully saved to %s (%d values captured).",
            self.baseline_path,
            len(entries),
        )
        return snapshot_data

    def load(self) -> Dict[str, Any]:
        """Load stored baseline snapshot from disk.

        Returns:
            Parsed snapshot dictionary.

        Raises:
            FileNotFoundError: If baseline file does not exist.
            json.JSONDecodeError: If baseline file is corrupted.
        """
        if not self.exists():
            raise FileNotFoundError(f"Baseline file does not exist at {self.baseline_path}")

        with open(self.baseline_path, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)

        return data

    def update(
        self,
        hive_str: str,
        key_path: str,
        value_name: str,
        entry_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update or remove a single entry in the baseline file.

        Args:
            hive_str: Hive identifier (e.g. HKLM).
            key_path: Path to registry key.
            value_name: Name of the value.
            entry_data: New value metadata dict, or None if deleted.
        """
        if not self.exists():
            LOGGER.warning("Cannot update baseline: file %s does not exist.", self.baseline_path)
            return

        baseline = self.load()
        entries: Dict[str, Any] = baseline.get("entries", {})
        entry_id = build_entry_key(hive_str, key_path, value_name)

        if entry_data is None:
            entries.pop(entry_id, None)
        else:
            entries[entry_id] = entry_data

        baseline["metadata"]["total_values_captured"] = len(entries)
        baseline["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()

        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2, sort_keys=True)

        LOGGER.debug("Updated baseline entry for %s", entry_id)
