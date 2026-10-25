# RegAudit — Windows Registry Change Monitoring System
**Unified Mentor Cybersecurity Internship Project Deliverable**  
*Domain: Cybersecurity Intern | Sub-domain: Cybersecurity Security*

---

## Executive Overview
**RegAudit** is a strictly defensive, agentless host-based intrusion detection and registry integrity verification toolkit built for Windows 10, Windows 11, and Windows Server systems. It continuously audits mission-critical registry hives (`HKEY_LOCAL_MACHINE` and `HKEY_CURRENT_USER`) to detect persistence mechanisms, evasion tactics, and security tampering in real time.

RegAudit strictly operates in a **read-only defensive posture**: it never writes, alters, or deletes registry entries. All operations are 100% local, requiring zero internet connectivity, zero API keys, and zero paid third-party components.

---

## 1. System Architecture Diagram

```
+-----------------------------------------------------------------------------+
|                                  RegAudit                                    |
|             Windows Registry Change Monitoring System Architecture           |
+-----------------------------------------------------------------------------+
                                       |
    +----------------------------------+----------------------------------+
    |                                                                     |
    v                                                                     v
[ MODULE 1: Autorun Monitoring ]                         [ MODULE 2: Threat Detection ]
- HKCU & HKLM Run / RunOnce                              - Heuristic Rule Engine
- WOW6432Node Run Entries                                - Suspicious Execution Paths
- Startup Folder redirections                            - Defender / Firewall Tampering
- Shell / Userinit Winlogon                              - UAC Bypasses & Anti-Forensics
    |                                                                     |
    +----------------------------------+----------------------------------+
                                       |
                                       v
                     [ MODULE 3: Registry Integrity Checker ]
                     - Cryptographic Baselines (baseline/registry_baseline.json)
                     - Deterministic SHA-256 Per-Value Digest Calculation
                     - Deep State Diff Engine: ADDED | MODIFIED | DELETED
                                       |
                                       v
                       [ MODULE 4: Alerting & Reporting ]
        +------------------------------+------------------------------+
        |                              |                              |
        v                              v                              v
[ Live Rich UI ]              [ SQLite Persistence ]         [ Report Exporter ]
- Full-screen dashboard       - data/regaudit.db (WAL)       - Inline-CSS HTML
- Dynamic Threat Level        - Audit log ring buffer        - Zero CDN / Self-contained
- Real-time event stream      - logs/regaudit.log (10MB x 3) - Forensics Ready
```

---

## 2. Deep Dive: The Four Core Modules

### Module 1: Autorun Key Monitoring
* **Objective:** Detect unauthorized persistence hooks configured to launch binaries automatically during operating system startup or user logon.
* **Mechanism:** RegAudit inspects both standard and 32-bit subsystem registry hives:
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`
* **Defensive Value:** Prevents stealthy threat actors from surviving reboots by inserting startup execution entries. Flagged paths immediately alert security analysts to untrusted or newly dropped payloads.

### Module 2: Malware-Like Change Detection
* **Objective:** Heuristically identify modifications that align with known attacker tradecraft, Defense Evasion, and Privilege Escalation.
* **Mechanism:** The `ChangeAnalyzer` inspects every incoming modification against a rule matrix:
  - **Defender Tampering:** Disabling anti-spyware (`DisableAntiSpyware=1`) or real-time protection (`DisableRealtimeMonitoring=1`).
  - **UAC Bypass:** Disabling User Account Control (`EnableLUA=0`) or configuring silent administrator elevation (`ConsentPromptBehaviorAdmin=0`).
  - **Host Isolation & Anti-Forensics:** Disabling Registry Editor (`DisableRegistryTools=1`) or Command Prompt (`DisableCMD=1`).
  - **Volatile Execution Paths:** Any autorun binary located within `\Temp\`, `\AppData\Roaming\`, `\Downloads\`, `\Public\`, or `\ProgramData\`.
* **Defensive Value:** Maps low-level registry mutations directly to threat severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and emits immediate audio-visual alerts.

### Module 3: Registry Integrity Checker
* **Objective:** Mathematically prove whether monitored registry keys remain identical to a known-trusted reference state.
* **Mechanism:** The `BaselineManager` serializes all monitored keys into a cryptographic baseline snapshot (`baseline/registry_baseline.json`). Each registry value is converted into deterministic byte buffers and hashed via SHA-256.
* **Defensive Value:** Allows instant verification (`python main.py --diff`) to detect unauthorized modifications that may have slipped through during maintenance windows or system drift.

### Module 4: Alerting & Reporting Module
* **Objective:** Deliver multi-channel visibility, long-term forensic persistence, and audit deliverables.
* **Mechanism:**
  - **Terminal Console:** Interactive, SSH-compatible Rich dashboard updating dynamically with zero screen flicker. Emits terminal bells (`\a`) and red alert panels on critical security breaches.
  - **Persistent Logging:** Rotates audit logs across three 10MB archives (`logs/regaudit.log`) using Python's `RotatingFileHandler`.
  - **Database:** Stores all change records, timestamps, old/new data, and session statistics in SQLite (`data/regaudit.db`) using Write-Ahead Logging (`PRAGMA journal_mode=WAL;`).
  - **HTML Reporter:** Exports a dark-themed, self-contained HTML audit report (`report.html`) formatted with executive KPI cards, change tables, and actionable blue-team recommendations.

---

## 3. Malware Technique Reference Table

| Registry Key / Value Target | MITRE ATT&CK ID | Technique Name | Attacker Rationale / Impact |
| :--- | :--- | :--- | :--- |
| `HKLM\...\Winlogon` (`Shell` / `Userinit`) | **T1547.004** | Boot/Logon: Winlogon Helper | Replaces `explorer.exe` or hooks `userinit.exe` to execute malware whenever any user logs onto Windows. |
| `HKLM\...\Windows Defender` (`DisableAntiSpyware`) | **T1562.001** | Impair Defenses: Disable Tools | Completely disables Microsoft Defender Antivirus engine, blinding host defenses. |
| `HKLM\...\Windows Defender` (`DisableRealtimeMonitoring`) | **T1562.001** | Impair Defenses: Disable Tools | Shuts down real-time on-access file scanning, allowing unhindered payload dropping. |
| `HKLM\...\Policies\System` (`EnableLUA=0`) | **T1548.002** | Abuse Elevation Control: Bypass UAC | Completely strips User Account Control tokens; applications execute with elevated admin permissions without prompting. |
| `HKLM\...\Policies\System` (`ConsentPromptBehaviorAdmin=0`)| **T1548.002** | Abuse Elevation Control: Bypass UAC | Automatically elevates administrative privilege requests silently without showing the UAC prompt dialog. |
| `HKLM\...\Policies\System` (`DisableCMD=1`) | **T1562.001** | Impair Defenses: Anti-Forensics | Prevents incident responders and system administrators from launching Command Prompt (`cmd.exe`). |
| `HKLM\...\Policies\System` (`DisableRegistryTools=1`) | **T1562.001** | Impair Defenses: Anti-Forensics | Prevents users or analysts from opening `regedit.exe` to inspect or clean malicious registry modifications. |
| `HKLM\...\FirewallPolicy` (`EnableFirewall=0`) | **T1562.004** | Impair Defenses: Disable Firewall | Shuts down Windows Defender Firewall profiles, opening host ports to lateral movement and command-and-control. |
| `HKCU\...\Run` (`C:\Users\...\AppData\...`) | **T1547.001** | Registry Run Keys / Startup Folder | Establishes persistent execution pointing to volatile user-writable folders that do not require administrative privileges. |
| `HKLM\...\Image File Execution Options` (`Debugger`) | **T1546.012** | IFEO Injection | Intercepts legitimate binaries (e.g. Accessibility tools like `sethc.exe` or `Utilman.exe`) and launches malware instead. |

---

## 4. VMware / Lab Test Guide

Use this step-by-step guide in a Windows 10/11 virtual machine or test environment to safely verify detection capabilities.

### Prerequisites
Launch an elevated PowerShell prompt (**Run as Administrator**):
```powershell
python main.py --baseline
python main.py
```
Leave the RegAudit live dashboard running in your terminal.

---

### Test Case 1: Triggering a MEDIUM Alert (Unauthorized Autorun Key)
In this test, we simulate an unknown software installation or user-level persistence mechanism by creating a new `Run` key entry.

1. Open a second PowerShell window (or `regedit`).
2. Run the following command:
   ```powershell
   reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TestUpdater" /t REG_SZ /d "C:\Program Files\VendorApp\update.exe" /f
   ```
3. **Observed RegAudit Behavior:**
   - Within 10 seconds (the default polling interval), the left feed flashes:
     - **SEV:** `MEDIUM`
     - **Type:** `ADDED`
     - **Key:** `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\TestUpdater`
     - **Matched Rule:** `New Autorun Entry Added (T1547.001)`
   - The "Session Stats" panel increments `Total Changes` and `Medium Severity`.
4. **Cleanup:**
   ```powershell
   reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TestUpdater" /f
   ```

---

### Test Case 2: Triggering a HIGH Alert (Defender Policy Tampering)
In this test, we simulate an adversary disabling Windows Defender's real-time monitoring engine.

1. Execute the following command in an administrative PowerShell terminal:
   ```powershell
   reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f
   ```
2. **Observed RegAudit Behavior:**
   - **SEV:** `HIGH`
   - **Type:** `ADDED` (or `MODIFIED`)
   - **Matched Rule:** `Defender Tampering: DisableRealtimeMonitoring (T1562.001)`
   - The **Threat Level** badge turns from `SYSTEM CLEAN` to `ELEVATED ALERT` (yellow).
3. **Cleanup:**
   ```powershell
   reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /f
   ```

---

### Test Case 3: Triggering a CRITICAL Alert (Suspicious Dropper in Temp)
In this test, we simulate malware registering an autorun item pointing directly to a user's `\Temp\` directory.

1. Execute:
   ```powershell
   reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "DiscordVoiceFix" /t REG_SZ /d "C:\Users\Public\Temp\updater.exe" /f
   ```
2. **Observed RegAudit Behavior:**
   - RegAudit emits an audible terminal bell (`\a`).
   - The live feed registers a bold red alert:
     - **SEV:** `CRITICAL`
     - **Matched Rule:** `Suspicious Autorun Path (T1547.001)`
     - **Detail:** Startup entry points to volatile directory `\temp\`.
   - The **Threat Level** badge switches to `CRITICAL THREAT` (bold white on red).
3. **Cleanup:**
   ```powershell
   reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "DiscordVoiceFix" /f
   ```

---

## 5. Known Limitations & Engineering Trade-offs

1. **Polling Delay vs. CPU Overhead:**
   - RegAudit polls monitored hives on a configurable interval (default: 10 seconds). Changes executed and reverted *within* that 10-second window will not be detected. Polling intervals can be tuned down to 2–5 seconds in `config.yaml`, but balance must be maintained against CPU consumption.
2. **Administrator Privilege Requirement:**
   - Reading `HKCU` (current user) requires only standard user rights. However, reading secured `HKLM` policies (such as Defender or System policies) requires Administrative elevation. If launched without elevation, RegAudit displays a privilege warning banner and skips restricted keys.
3. **Cross-Platform / Kali Linux Operating Mode:**
   - The Windows Registry is exclusive to Microsoft Windows. Under Kali Linux or standard Linux distributions, live monitoring is unavailable. However, RegAudit provides full **offline forensics support** on Linux: analysts can transfer `regaudit.db` from a compromised Windows machine to Kali Linux and execute `python3 main.py --export report.html` to generate audit reports.

---

## 6. Installation & Execution Guide

### Primary Target: Windows 10 / 11 / Server (PowerShell as Administrator)
```powershell
# 1. Create and activate virtual environment
python -m venv venv
venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Capture cryptographic baseline reference
python main.py --baseline

# 4. Launch live terminal monitoring dashboard
python main.py

# 5. One-time integrity diff verification
python main.py --diff

# 6. Generate standalone HTML audit report
python main.py --export report.html
```

### Secondary Target: Kali Linux (Offline Forensics & Report Export)
```bash
# 1. Create and activate virtual environment
python3 -m venv venv && source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Export HTML report from transferred database
python main.py --export report.html --last 200
```
