"""RegAudit Change Analyzer Engine.

Performs heuristic evaluation and signature-based malware detection on registry
changes (Module 2). Classifies events into CRITICAL, HIGH, MEDIUM, and LOW severity
levels by inspecting security policy tampering, startup persistence, UAC bypasses,
and suspicious execution paths.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from config.loader import MalwarePattern, RegAuditConfig

LOGGER = logging.getLogger("RegAudit.Analyzer")


class ChangeAnalyzer:
    """Evaluates registry changes for suspicious patterns, defense impairment, and malware indicators."""

    def __init__(self, config: Optional[RegAuditConfig] = None) -> None:
        """Initialize the change analyzer with detection rules.

        Args:
            config: Optional RegAuditConfig instance. If omitted, uses default rules.
        """
        self.config = config or RegAuditConfig()
        self.suspicious_paths: List[str] = [p.lower() for p in self.config.suspicious_paths]
        self.patterns: List[MalwarePattern] = self.config.malware_value_patterns

    def is_suspicious_path(self, target_str: str) -> Optional[str]:
        """Check if an executable or path points to an untrusted/volatile directory.

        Malware frequently executes droppers or persistent binaries from Temp, AppData,
        Downloads, or Public directories to avoid requiring administrative file writes.

        Args:
            target_str: The path or command-line string to inspect.

        Returns:
            The matched suspicious path fragment, or None.
        """
        norm_val = target_str.replace("/", "\\").lower()
        for susp in self.suspicious_paths:
            clean_susp = susp.replace("/", "\\").strip("\\").lower()
            if not clean_susp:
                continue
            if (
                f"\\{clean_susp}\\" in norm_val
                or f"\\{clean_susp}" in norm_val
                or norm_val.startswith(clean_susp)
            ):
                return susp
        return None

    def analyze(self, change: Dict[str, Any]) -> Tuple[str, str, str]:
        """Analyze a registry change event and determine its threat severity.

        Args:
            change: Change dictionary containing hive, key_path, value_name,
                    change_type, old_data, new_data, etc.

        Returns:
            Tuple of (severity, pattern_matched, detail)
            Severity is one of: CRITICAL, HIGH, MEDIUM, LOW.
        """
        key_path = str(change.get("key_path", "")).strip()
        value_name = str(change.get("value_name", "")).strip()
        change_type = str(change.get("change_type", "")).upper()
        new_data = str(change.get("new_data", "")).strip() if change.get("new_data") is not None else ""
        old_data = str(change.get("old_data", "")).strip() if change.get("old_data") is not None else ""

        key_lower = key_path.lower()
        val_lower = value_name.lower()
        data_to_check = new_data if change_type != "DELETED" else old_data

        # =========================================================================
        # CRITICAL CHECKS
        # =========================================================================

        # 1. Winlogon Shell or Userinit Replacement (MITRE T1547.004)
        if "winlogon" in key_lower:
            if val_lower == "shell":
                clean_target = data_to_check.lower().replace('"', "").strip()
                if clean_target != "explorer.exe":
                    return (
                        "CRITICAL",
                        "Winlogon Shell Hijack (T1547.004)",
                        f"Logon Shell replaced from '{old_data}' to '{new_data}'. Expected 'explorer.exe'.",
                    )
            elif val_lower == "userinit":
                clean_target = data_to_check.lower().replace('"', "").strip()
                if "userinit.exe" not in clean_target:
                    return (
                        "CRITICAL",
                        "Winlogon Userinit Hijack (T1547.004)",
                        f"Userinit startup handler replaced with untrusted binary: '{new_data}'.",
                    )

        # 2. System Tool Disabling (Anti-Forensics: T1562.001)
        if val_lower == "disablecmd" and data_to_check == "1":
            return (
                "CRITICAL",
                "DisableCMD Tampering (T1562.001)",
                "Command Prompt execution disabled via registry policy (DisableCMD=1).",
            )
        if val_lower == "disableregistrytools" and data_to_check == "1":
            return (
                "CRITICAL",
                "DisableRegistryTools Tampering (T1562.001)",
                "Registry Editor (regedit) disabled via registry policy (DisableRegistryTools=1).",
            )

        # 3. Suspicious Executable Paths in Autoruns (MITRE T1547.001)
        is_autorun = any(k in key_lower for k in ["run", "runonce", "runservices"])
        if is_autorun and change_type in ("ADDED", "MODIFIED"):
            suspicious_match = self.is_suspicious_path(new_data)
            if suspicious_match:
                return (
                    "CRITICAL",
                    "Suspicious Autorun Path (T1547.001)",
                    f"Startup entry '{value_name}' points to volatile location '{suspicious_match}': {new_data}",
                )

        # =========================================================================
        # HIGH CHECKS
        # =========================================================================

        # 4. Windows Defender Tampering (MITRE T1562.001)
        if val_lower == "disableantispyware" and data_to_check == "1":
            return (
                "HIGH",
                "Defender Tampering: DisableAntiSpyware (T1562.001)",
                "Windows Defender anti-spyware protection disabled (DisableAntiSpyware=1).",
            )
        if val_lower == "disablerealtimemonitoring" and data_to_check == "1":
            return (
                "HIGH",
                "Defender Tampering: DisableRealtimeMonitoring (T1562.001)",
                "Windows Defender real-time antivirus engine disabled (DisableRealtimeMonitoring=1).",
            )

        # 5. UAC Tampering & Elevation Bypass (MITRE T1548.002)
        if val_lower == "enablelua" and data_to_check == "0":
            return (
                "HIGH",
                "UAC Disabled: EnableLUA (T1548.002)",
                "User Account Control (UAC) turned off globally (EnableLUA=0).",
            )
        if val_lower == "consentpromptbehavioradmin" and data_to_check == "0":
            return (
                "HIGH",
                "Silent Admin Elevation (T1548.002)",
                "ConsentPromptBehaviorAdmin set to 0 (elevates without prompting administrator).",
            )

        # 6. Windows Firewall Tampering (MITRE T1562.004)
        if "firewallpolicy" in key_lower and val_lower == "enablefirewall" and data_to_check == "0":
            return (
                "HIGH",
                "Firewall Disabled: EnableFirewall (T1562.004)",
                "Windows Defender Firewall profile turned off (EnableFirewall=0).",
            )

        # 7. Persistence via Windows Services (MITRE T1543.003)
        if r"services" in key_lower and change_type == "ADDED":
            return (
                "HIGH",
                "New Windows Service Created (T1543.003)",
                f"New service entry or parameter added under {key_path}: {value_name}={new_data}",
            )

        # 8. Configurable malware pattern rules from config.yaml
        for pat in self.patterns:
            if pat.name.lower() == val_lower:
                if pat.key_contains and pat.key_contains.lower() not in key_lower:
                    continue
                if pat.match is None or pat.match == data_to_check:
                    return (
                        pat.severity,
                        f"Configured Rule: {pat.name}",
                        f"Pattern matched for {value_name} in {key_path} (Value: {data_to_check})",
                    )

        # =========================================================================
        # MEDIUM CHECKS
        # =========================================================================

        # 9. Image File Execution Options (IFEO) Debugger Hijack (MITRE T1546.012)
        if "image file execution options" in key_lower:
            return (
                "MEDIUM",
                "IFEO Execution Modification (T1546.012)",
                f"Image File Execution Option adjusted for {key_path}: {value_name}={new_data}",
            )

        # 10. RunOnce Added or Modified (Dropper Persistence)
        if "runonce" in key_lower and change_type in ("ADDED", "MODIFIED"):
            return (
                "MEDIUM",
                "RunOnce Startup Entry Added (T1547.001)",
                f"One-time autorun entry '{value_name}' added: {new_data}",
            )

        # 11. New Autorun Entry (Run Key)
        if is_autorun and change_type == "ADDED":
            return (
                "MEDIUM",
                "New Autorun Entry Added (T1547.001)",
                f"New autorun item '{value_name}' registered in {key_path}: {new_data}",
            )

        # 12. SafeBoot Drivers / Services altered
        if "safeboot" in key_lower and change_type in ("ADDED", "MODIFIED"):
            return (
                "MEDIUM",
                "SafeBoot Configuration Altered (T1562.009)",
                f"SafeBoot whitelist key modified: {key_path}\\{value_name}",
            )

        # =========================================================================
        # LOW CHECKS
        # =========================================================================
        if change_type == "DELETED":
            return (
                "LOW",
                "Registry Entry Removed",
                f"Value '{value_name}' was removed from {key_path} (Prior value: {old_data})",
            )

        if is_autorun and change_type == "MODIFIED":
            return (
                "LOW",
                "Autorun Entry Modified",
                f"Value '{value_name}' in {key_path} modified: '{old_data}' -> '{new_data}'",
            )

        return (
            "LOW",
            "General Configuration Change",
            f"{change_type} value '{value_name}' in {key_path}: {new_data or old_data}",
        )
