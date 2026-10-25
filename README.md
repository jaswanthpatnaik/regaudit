# RegAudit — Windows Registry Change Monitoring System

<div align="center">

![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6?logo=windows&logoColor=white)
![Fallback](https://img.shields.io/badge/Secondary-Kali%20Linux%20(Export--Only)-557C94?logo=kalilinux&logoColor=white)
![Security Posture](https://img.shields.io/badge/Posture-Strictly%20Defensive%20(Read--Only)-success?logo=shield&logoColor=white)
![UI](https://img.shields.io/badge/Interface-Rich%20Live%20Terminal%20(SSH--Safe)-blueviolet)
![Storage](https://img.shields.io/badge/Database-SQLite%20(WAL%20Mode)-003B57?logo=sqlite&logoColor=white)
![Network](https://img.shields.io/badge/Network-100%25%20Local%20%7C%20Zero%20APIs-brightgreen)
![Internship](https://img.shields.io/badge/Unified%20Mentor-Cybersecurity%20Internship-orange)

**An agentless, strictly defensive host-based intrusion detection and registry integrity monitoring toolkit designed for blue-team cybersecurity operations and digital forensics.**

[Features](#-key-features) •
[Architecture](#-system-architecture) •
[Installation](#-installation--setup) •
[Quick Start](#-quick-start-guide) •
[CLI Reference](#-command-line-reference) •
[MITRE ATT&CK Matrix](#-malware-detection-matrix--mitre-attck) •
[Testing](#-testing--verification)

</div>

---

## 📌 Executive Summary

**RegAudit** is a real-time host-based intrusion detection toolkit that continuously audits sensitive Windows Registry hives (`HKEY_LOCAL_MACHINE` and `HKEY_CURRENT_USER`). It detects unauthorized autorun persistence, defense impairment (disabling Windows Defender, Windows Firewall, or UAC), anti-forensics policies, and execution hooks launched from volatile/untrusted directories.

Developed as a cybersecurity project deliverable for **Unified Mentor** (*Domain: Cybersecurity Intern, Sub-domain: Cybersecurity Security*), RegAudit implements all four official modules required for comprehensive endpoint monitoring.

### 🛡️ Defensive Engineering Constraints
* **Strictly Read-Only:** RegAudit only inspects registry keys using standard library `winreg` with defensive exception handling. It **never writes, alters, or deletes** any registry keys.
* **100% Local & Offline:** Zero external API keys, zero cloud dependencies, zero paid services. Operates seamlessly in air-gapped environments.
* **SSH & Azure Safe:** Pure terminal UI powered by `rich` with no desktop GUI, no browser dashboard, and no notification popups.
* **Dual-Target Support:** Primary target is Windows 10/11/Server. A graceful fallback mode is provided for Kali Linux analysts to inspect SQLite databases and generate HTML reports offline.

---

## ⚡ Key Features

* **Real-Time Autorun Auditing:** Detects newly registered startup hooks across `Run`, `RunOnce`, and 32-bit `WOW6432Node` keys.
* **Malware Signature & Heuristic Engine:** Flags Defender disabling, firewall tampering, UAC bypasses (`EnableLUA=0`, `ConsentPromptBehaviorAdmin=0`), and Winlogon shell replacements.
* **Volatile Path Detection:** Identifies autoruns executing out of untrusted directories (`\Temp\`, `\AppData\Roaming\`, `\Downloads\`, `\Public\`, `\ProgramData\`).
* **Cryptographic Baselines:** Serializes monitored keys into JSON baselines (`baseline/registry_baseline.json`) with deterministic per-value SHA-256 integrity digests.
* **Interactive Terminal Dashboard:** Full-screen Rich TUI with live event streaming, dynamic threat-level badges, metrics breakdown, and hotkeys (`[Q]`, `[B]`, `[E]`, `[H]`).
* **Enterprise Persistence:** Concurrent SQLite logging in Write-Ahead Logging (`WAL`) mode alongside 10MB x 3 rotating disk logs.
* **Offline Forensic HTML Reporting:** Exports a self-contained, dark-themed HTML audit report (`report.html`) with zero CDN, zero external fonts, and zero JavaScript.

---

## 🧩 The Four Core Modules

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                                    RegAudit                                       │
│                 Windows Registry Change Monitoring Architecture                   │
└───────────────────────────────────────────────────────────────────────────────────┘
                                          │
        ┌─────────────────────────────────┴─────────────────────────────────┐
        ▼                                                                   ▼
┌──────────────────────────────┐                         ┌──────────────────────────────────┐
│ MODULE 1: Autorun Monitoring │                         │ MODULE 2: Malware Detection      │
│ • HKCU/HKLM Run & RunOnce    │                         │ • Defender & Firewall Tampering  │
│ • WOW6432Node Compatibility  │                         │ • UAC Bypass / Elevation Hooks   │
│ • Startup Folder Redirects   │                         │ • Winlogon Shell/Userinit Hijack │
│ • Untrusted Binary Locations │                         │ • Anti-Forensics (DisableCMD)    │
└──────────────┬───────────────┘                         └──────────────────┬───────────────┘
               │                                                            │
               └──────────────────────────────────┬─────────────────────────┘
                                                  ▼
                               ┌─────────────────────────────────────┐
                               │ MODULE 3: Registry Integrity Engine │
                               │ • Cryptographic JSON Baseline       │
                               │ • SHA-256 Deterministic Hashing     │
                               │ • Deep State Diff: ADD/MOD/DEL      │
                               └──────────────────┬──────────────────┘
                                                  ▼
                               ┌─────────────────────────────────────┐
                               │ MODULE 4: Alerting & Reporting      │
                               │ • Rich Live Terminal Dashboard      │
                               │ • SQLite Persistence (WAL Mode)     │
                               │ • Rotating File Logs (10MB x 3)     │
                               │ • Standalone Dark-Theme HTML Export │
                               └─────────────────────────────────────┘
```

### Module 1 — Autorun Key Monitoring
Audits high-priority registry autorun points exploited by droppers and persistent malware:
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`

### Module 2 — Malware-Like Change Detection
Heuristically evaluates each detected change against a rule taxonomy:
- **CRITICAL:** Winlogon `Shell` / `Userinit` hijacking, `DisableCMD=1`, `DisableRegistryTools=1`, startup items pointing to volatile user paths (`\Temp\`, `\AppData\`).
- **HIGH:** `DisableAntiSpyware=1`, `DisableRealtimeMonitoring=1`, `EnableLUA=0`, `ConsentPromptBehaviorAdmin=0`, `EnableFirewall=0`, new unauthorized Windows Services.
- **MEDIUM:** New standard autorun entry added, `RunOnce` key modified, `Image File Execution Options` (IFEO) debugger modified.
- **LOW:** Standard value updates, non-critical value deletions, benign configuration changes.

### Module 3 — Registry Integrity Checker
Captures a structured snapshot of all monitored keys. Each entry records the hive, subkey, value name, data type, human-readable data, and a SHA-256 hash. The one-shot diff command (`--diff`) compares the live registry against the baseline and prints a color-coded delta summary.

### Module 4 — Alerting & Reporting Module
- **Terminal UI:** Live event stream using `rich.live.Live` with instant threat-level calculation (`SYSTEM CLEAN`, `ELEVATED ALERT`, `CRITICAL THREAT`) and audible terminal bell (`\a`) on critical alerts.
- **Database Storage:** ACID transactions recorded to `data/regaudit.db` with query indexes on timestamps, severities, and session IDs.
- **Log Archiving:** Managed via `logging.handlers.RotatingFileHandler` writing up to 30MB of historical logs to `logs/regaudit.log`.
- **Forensic Report:** Emits an inline-CSS HTML report containing executive KPI summary cards, autorun inventory, change logs, and auto-generated blue-team remediation actions.

---

## 🎯 Malware Detection Matrix & MITRE ATT&CK

| Target Key / Value | Severity | MITRE ATT&CK ID | Technique Name | Threat Mechanism & Impact |
| :--- | :---: | :---: | :--- | :--- |
| `HKLM\...\Winlogon` (`Shell`) | **CRITICAL** | **T1547.004** | Winlogon Helper | Replaces `explorer.exe` with attacker binary during user logon. |
| `HKLM\...\Winlogon` (`Userinit`) | **CRITICAL** | **T1547.004** | Winlogon Helper | Hooks logon initialization to execute persistence before user shell. |
| `HKLM\...\Policies\System` (`DisableCMD`) | **CRITICAL** | **T1562.001** | Impair Defenses: Disable Tools | Blocks analyst and incident responder access to Command Prompt. |
| `HKLM\...\Policies\System` (`DisableRegistryTools`) | **CRITICAL** | **T1562.001** | Impair Defenses: Disable Tools | Prevents launching `regedit.exe` to inspect malicious registry entries. |
| `HKCU\...\Run` (`\Temp\`, `\AppData\`) | **CRITICAL** | **T1547.001** | Registry Run Keys / Startup Folder | Executes binaries dropped in unprivileged, volatile user folders. |
| `HKLM\...\Windows Defender` (`DisableAntiSpyware`) | **HIGH** | **T1562.001** | Impair Defenses: Disable Tools | Disables Microsoft Defender Antivirus engine entirely. |
| `HKLM\...\Windows Defender` (`DisableRealtimeMonitoring`) | **HIGH** | **T1562.001** | Impair Defenses: Disable Tools | Suspends on-access scanning, allowing unhindered malware execution. |
| `HKLM\...\Policies\System` (`EnableLUA`) | **HIGH** | **T1548.002** | Abuse Elevation Control: Bypass UAC | Disables User Account Control (UAC) globally (`0` = disabled). |
| `HKLM\...\Policies\System` (`ConsentPromptBehaviorAdmin`) | **HIGH** | **T1548.002** | Abuse Elevation Control: Bypass UAC | Silently elevates administrator tasks without displaying UAC prompt (`0`). |
| `HKLM\...\FirewallPolicy` (`EnableFirewall`) | **HIGH** | **T1562.004** | Impair Defenses: Disable Firewall | Disables firewall profiles, permitting unauthorized network traversal. |
| `HKLM\...\Services` (`ImagePath`, `Start`) | **HIGH** | **T1543.003** | Create or Modify System Process: Service | Registers or alters Windows Services for SYSTEM-level persistence. |
| `HKLM\...\Image File Execution Options` (`Debugger`) | **MEDIUM** | **T1546.012** | Event Triggered Execution: IFEO Injection | Intercepts accessibility tools (e.g., `sethc.exe`) to spawn backdoor. |

---

## 💻 Installation & Setup

### Requirements
- **Windows:** Windows 10, Windows 11, or Windows Server (Python 3.10+ recommended)
- **Linux (Analysis & Export mode):** Kali Linux, Ubuntu, Debian (Python 3.10+)

### Setup on Windows (PowerShell as Administrator)
```powershell
# 1. Clone repository
git clone https://github.com/jaswanthpatnaik/regaudit.git
cd regaudit

# 2. Create and activate virtual environment
python -m venv venv
venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
```

### Setup on Kali Linux (Offline Forensics Mode)
```bash
# 1. Clone or copy regaudit directory
cd regaudit

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Quick Start Guide

### Step 1: Capture Cryptographic Reference Baseline
Before launching continuous monitoring, take an initial snapshot of all 14 root sensitive keys:
```powershell
python main.py --baseline
```

### Step 2: Start Continuous Live Monitoring Dashboard
Launch the interactive terminal dashboard:
```powershell
python main.py
```

### Step 3: Verify Integrity with One-Shot Diff Audit
Compare current live registry state against the baseline reference without launching the full dashboard:
```powershell
python main.py --diff
```

### Step 4: Export Forensic HTML Report
Generate an offline, dark-themed HTML report:
```powershell
python main.py --export report.html
```

---

## ⌨️ Dashboard Interactive Controls

When running `python main.py`, the following interactive hotkeys are active:

| Key | Action | Description |
| :---: | :--- | :--- |
| **`Q`** | **Quit** | Shuts down background polling daemon cleanly and commits session summary to SQLite. |
| **`B`** | **Rebuild Baseline** | Recaptures cryptographic SHA-256 baseline from live registry state without restarting. |
| **`E`** | **Export Report** | Instantly generates a timestamped HTML forensic report to disk. |
| **`H`** | **Toggle Help** | Shows/hides the in-terminal command and controls overlay panel. |

---

## 📖 Command Line Reference

```text
usage: RegAudit [-h] [--baseline] [--diff] [--export [FILE]] [--last N] [--duration SEC] [--config FILE]

RegAudit — Windows Registry Change Monitoring System (Cybersecurity Intern Deliverable)

options:
  -h, --help       show this help message and exit
  --baseline       Capture an initial cryptographic baseline snapshot of all monitored keys.
  --diff           Perform a one-time integrity check comparing current registry state against baseline.
  --export [FILE]  Export persistent audit history to a self-contained HTML report (default: report.html).
  --last N         Limit number of changes exported in HTML report (e.g. --last 200).
  --duration SEC   Run live monitoring for specified seconds and then exit cleanly (useful for automated triage).
  --config FILE    Path to custom config.yaml file.
```

---

## 🧪 Verification & Lab Testing

RegAudit provides built-in integrity verification commands and lab testing procedures:

### Built-in Verification Workflow:
1. **Initial Baseline Capture:**
   ```powershell
   python main.py --baseline
   ```
   Scans all 14 sensitive root registry keys, hashes all discovered values with SHA-256, and stores the reference state in `baseline/registry_baseline.json`.

2. **One-Shot Integrity Diff:**
   ```powershell
   python main.py --diff
   ```
   Audits live values against baseline hashes and prints a color-coded delta table (`ADDED`, `MODIFIED`, `DELETED`).

3. **Offline Forensic Export:**
   ```powershell
   python main.py --export report.html
   ```
   Generates a standalone, dark-themed HTML report for forensics archiving and internship submission.

### Safe Lab Simulation Test (VMware / Sandbox)
To verify live detection in a test lab:
1. Start RegAudit: `python main.py`
2. In a separate elevated PowerShell window, simulate an autorun key addition:
   ```powershell
   reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TestUpdater" /t REG_SZ /d "C:\Program Files\VendorApp\update.exe" /f
   ```
3. Observe the live feed alert: **SEV:** `MEDIUM` | **Rule:** `New Autorun Entry Added (T1547.001)`
4. Clean up the test key:
   ```powershell
   reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TestUpdater" /f
   ```

---

## 📂 Project Structure

```
regaudit/
├── main.py                     # CLI entry point, signal handling & mode coordinator
├── config.yaml                 # Polling intervals, paths, and malware pattern signatures
├── requirements.txt            # Minimal runtime dependencies (rich, pyyaml, colorama)
├── DOCUMENTATION.md            # Detailed internship deliverable document & lab guide
├── README.md                   # Comprehensive GitHub repository documentation
├── LICENSE                     # MIT Open-Source License
├── .gitignore                  # Git ignore rules for bytecode, virtualenv & databases
├── baseline/
│   ├── __init__.py
│   ├── snapshot.py             # BaselineManager: SHA-256 snapshot capture & persistence
│   └── .gitkeep                # Baseline reference directory
├── config/
│   ├── __init__.py
│   ├── loader.py               # Strong-typed YAML configuration loader with defaults
│   └── registry_keys.py        # Monitored registry keys & MITRE ATT&CK annotations
├── dashboard/
│   ├── __init__.py
│   └── ui.py                   # TerminalDashboard: Rich live layout & non-blocking hotkeys
├── data/
│   └── .gitkeep                # SQLite storage directory (data/regaudit.db)
├── database/
│   ├── __init__.py
│   └── db_manager.py           # DatabaseManager: Thread-safe SQLite persistence in WAL mode
├── engine/
│   ├── __init__.py
│   ├── alert_engine.py         # AlertEngine: SQLite inserts, rotating logs, terminal alerts
│   └── change_analyzer.py      # ChangeAnalyzer: Heuristic engine & malware rule classifier
├── logs/
│   └── .gitkeep                # Application logs directory (logs/regaudit.log)
├── monitor/
│   ├── __init__.py
│   └── poller.py               # RegistryPoller: Daemon thread & differential comparison
├── reporter/
│   ├── __init__.py
│   └── html_exporter.py        # HtmlExporter: Self-contained, dark-theme HTML report generator
└── utils/
    ├── __init__.py
    ├── logger.py               # RotatingFileHandler configuration (10MB x 3)
    ├── platform_check.py       # OS detector and Administrator privilege validator
    └── registry_helpers.py     # Strictly read-only winreg helpers & SHA-256 hasher
```

---

## 🔒 Defensive Security Posture & Limitations

1. **Strictly Defensive:** The codebase does not write, modify, or delete registry keys under any circumstances.
2. **Polling Frequency vs. Overhead:** Defaults to 10-second polling intervals (`poll_interval_seconds: 10` in `config.yaml`). Ephemeral changes created and deleted within that window will not trigger alerts.
3. **Privilege Requirements:** Standard user permissions allow querying `HKCU` keys. Comprehensive inspection of security policies in `HKLM` requires launching PowerShell with **Run as Administrator**.
4. **POSIX Limitations:** Live registry monitoring requires Windows APIs (`winreg`). On Kali Linux, RegAudit operates in **Offline Forensics Mode**, allowing analysts to inspect transferred SQLite databases and compile forensic reports.

---

## 📜 License & Attribution

This project was built for the **Unified Mentor Cybersecurity Internship** (*Domain: Cybersecurity Intern, Sub-domain: Cybersecurity Security*).

Distributed under the **MIT License**. See `LICENSE` for more information.
