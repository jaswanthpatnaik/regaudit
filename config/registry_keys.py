"""RegAudit Monitored Sensitive Registry Keys.

Defines all registry hives and subkeys monitored for unauthorized autorun persistence,
security policy tampering, and malware execution techniques. Fully guarded against
ImportError on non-Windows platforms (e.g. Kali Linux fallback mode).
"""

from __future__ import annotations

from typing import Dict, List, Tuple

# Safe winreg import with POSIX fallbacks
try:
    import winreg

    HKEY_CURRENT_USER: int = winreg.HKEY_CURRENT_USER
    HKEY_LOCAL_MACHINE: int = winreg.HKEY_LOCAL_MACHINE
except ImportError:
    winreg = None  # type: ignore
    HKEY_CURRENT_USER = 0x80000001
    HKEY_LOCAL_MACHINE = 0x80000002

# MODULE 1: Autorun and Startup Keys
# Security Relevance: Primary location for user-level and machine-level persistence.
# Malware Technique: MITRE ATT&CK T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)
AUTORUN_KEYS: List[Tuple[int, str]] = [
    (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

# MODULE 2: Security Policy and Tampering Keys
# Security Relevance: Modifying these keys disables Windows Defender, Windows Firewall, or UAC safeguards.
# Malware Technique: MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) & T1548.002 (Bypass UAC)
SECURITY_KEYS: List[Tuple[int, str]] = [
    (HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender"),
    (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
    (HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"),
    (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    (HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SafeBoot"),
]

# MODULE 3: Persistence and Execution Hijack Keys
# Security Relevance: Image File Execution Options (IFEO) debugger hijacks, shell folders, and Windows service entries.
# Malware Technique: MITRE ATT&CK T1546.012 (Image File Execution Options Injection) & T1543.003 (Windows Service)
PERSISTENCE_KEYS: List[Tuple[int, str]] = [
    (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
    (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"),
    (HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
    (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
]

ALL_MONITORED_KEYS: List[Tuple[int, str]] = AUTORUN_KEYS + SECURITY_KEYS + PERSISTENCE_KEYS

KEY_METADATA: Dict[str, Dict[str, str]] = {
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run": {
        "category": "AUTORUN",
        "description": "Standard user and machine startup execution list",
        "mitre_technique": "T1547.001",
    },
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce": {
        "category": "AUTORUN",
        "description": "One-time execution at next logon, frequently abused by droppers",
        "mitre_technique": "T1547.001",
    },
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run": {
        "category": "AUTORUN",
        "description": "32-bit compatibility startup execution list on 64-bit systems",
        "mitre_technique": "T1547.001",
    },
    r"SOFTWARE\Policies\Microsoft\Windows Defender": {
        "category": "SECURITY",
        "description": "Windows Defender Group Policy configurations (DisableAntiSpyware, Realtime)",
        "mitre_technique": "T1562.001",
    },
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System": {
        "category": "SECURITY",
        "description": "System security policies, UAC configurations (EnableLUA, ConsentPrompt)",
        "mitre_technique": "T1548.002",
    },
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy": {
        "category": "SECURITY",
        "description": "Windows Defender Firewall domain and standard profile configurations",
        "mitre_technique": "T1562.004",
    },
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon": {
        "category": "SECURITY",
        "description": "Windows logon handling (Shell, Userinit replacements for logon persistence)",
        "mitre_technique": "T1547.004",
    },
    r"SYSTEM\CurrentControlSet\Control\SafeBoot": {
        "category": "SECURITY",
        "description": "SafeBoot drivers and services configuration (used in ransomware/AV-stripping)",
        "mitre_technique": "T1562.009",
    },
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options": {
        "category": "PERSISTENCE",
        "description": "IFEO debugger hijacking to intercept application launches (e.g. sethc.exe)",
        "mitre_technique": "T1546.012",
    },
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders": {
        "category": "PERSISTENCE",
        "description": "Explorer special folders redirection including Startup path",
        "mitre_technique": "T1547.009",
    },
    r"SYSTEM\CurrentControlSet\Services": {
        "category": "PERSISTENCE",
        "description": "Windows Service control registry entries used for persistent daemons",
        "mitre_technique": "T1543.003",
    },
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices": {
        "category": "PERSISTENCE",
        "description": "Legacy RunServices entry executed before user login",
        "mitre_technique": "T1547.001",
    },
}


def get_key_category(key_path: str) -> str:
    """Determine the monitoring category for a given key path."""
    for known_key, meta in KEY_METADATA.items():
        if known_key.lower() in key_path.lower():
            return meta["category"]
    return "GENERAL"
