"""RegAudit Configuration Loader.

Loads, validates, and provides structured access to RegAudit runtime configuration
from config.yaml with secure fallbacks, path normalization, and type safety.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

LOGGER = logging.getLogger("RegAudit.Config")

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent


@dataclass
class MalwarePattern:
    """Structure representing a malicious registry value pattern rule."""

    name: str
    match: Optional[str] = None
    key_contains: Optional[str] = None
    severity: str = "HIGH"


@dataclass
class RegAuditConfig:
    """Strongly typed representation of RegAudit configuration settings."""

    poll_interval_seconds: int = 10
    db_path: Path = field(default_factory=lambda: PROJECT_ROOT / "data" / "regaudit.db")
    baseline_path: Path = field(default_factory=lambda: PROJECT_ROOT / "baseline" / "registry_baseline.json")
    log_path: Path = field(default_factory=lambda: PROJECT_ROOT / "logs" / "regaudit.log")
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 3
    alert_on_severity: List[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    suspicious_paths: List[str] = field(
        default_factory=lambda: [
            "\\Temp\\",
            "\\AppData\\Roaming\\",
            "\\AppData\\Local\\Temp\\",
            "\\Downloads\\",
            "\\Public\\",
            "\\ProgramData\\",
        ]
    )
    malware_value_patterns: List[MalwarePattern] = field(
        default_factory=lambda: [
            MalwarePattern(name="DisableAntiSpyware", match="1", severity="HIGH"),
            MalwarePattern(name="DisableRealtimeMonitoring", match="1", severity="HIGH"),
            MalwarePattern(name="EnableLUA", match="0", severity="HIGH"),
            MalwarePattern(name="ConsentPromptBehaviorAdmin", match="0", severity="HIGH"),
            MalwarePattern(name="DisableCMD", match="1", severity="CRITICAL"),
            MalwarePattern(name="DisableRegistryTools", match="1", severity="CRITICAL"),
            MalwarePattern(name="Shell", key_contains="Winlogon", severity="CRITICAL"),
            MalwarePattern(name="Userinit", key_contains="Winlogon", severity="CRITICAL"),
        ]
    )

    def ensure_directories(self) -> None:
        """Ensure all required runtime directories exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)


def load_config(config_file: Optional[Path] = None) -> RegAuditConfig:
    """Load configuration from YAML file or return robust defaults.

    Args:
        config_file: Optional path to YAML configuration. Defaults to config.yaml in project root.

    Returns:
        RegAuditConfig instance initialized with parsed settings.
    """
    target_path = config_file or (PROJECT_ROOT / "config.yaml")
    cfg = RegAuditConfig()

    if not target_path.exists():
        LOGGER.warning("Configuration file not found at %s. Using default settings.", target_path)
        cfg.ensure_directories()
        return cfg

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            raw_data: Dict[str, Any] = yaml.safe_load(f) or {}

        if "poll_interval_seconds" in raw_data:
            cfg.poll_interval_seconds = int(raw_data["poll_interval_seconds"])

        if "db_path" in raw_data:
            cfg.db_path = (PROJECT_ROOT / raw_data["db_path"]).resolve()

        if "baseline_path" in raw_data:
            cfg.baseline_path = (PROJECT_ROOT / raw_data["baseline_path"]).resolve()

        if "log_path" in raw_data:
            cfg.log_path = (PROJECT_ROOT / raw_data["log_path"]).resolve()

        if "log_max_bytes" in raw_data:
            cfg.log_max_bytes = int(raw_data["log_max_bytes"])

        if "log_backup_count" in raw_data:
            cfg.log_backup_count = int(raw_data["log_backup_count"])

        if "alert_on_severity" in raw_data and isinstance(raw_data["alert_on_severity"], list):
            cfg.alert_on_severity = [str(s).upper() for s in raw_data["alert_on_severity"]]

        if "suspicious_paths" in raw_data and isinstance(raw_data["suspicious_paths"], list):
            cfg.suspicious_paths = [str(p) for p in raw_data["suspicious_paths"]]

        if "malware_value_patterns" in raw_data and isinstance(raw_data["malware_value_patterns"], list):
            patterns: List[MalwarePattern] = []
            for item in raw_data["malware_value_patterns"]:
                if isinstance(item, dict) and "name" in item:
                    patterns.append(
                        MalwarePattern(
                            name=str(item["name"]),
                            match=str(item["match"]) if "match" in item else None,
                            key_contains=str(item["key_contains"]) if "key_contains" in item else None,
                            severity=str(item.get("severity", "HIGH")).upper(),
                        )
                    )
            if patterns:
                cfg.malware_value_patterns = patterns

    except Exception as exc:
        LOGGER.error("Failed to parse config file %s: %s. Reverting to safe defaults.", target_path, exc)

    cfg.ensure_directories()
    return cfg
