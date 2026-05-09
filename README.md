# 🔬 DFIR-Auto — Automated Forensic Triage

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![DFIR](https://img.shields.io/badge/DFIR-Triage-8B0000?style=for-the-badge)
![Windows](https://img.shields.io/badge/Windows-✓-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-✓-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Gemini](https://img.shields.io/badge/Gemini_AI-Free_Tier-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Portfolio](https://img.shields.io/badge/Portfolio-F--01_Forensics-8B0000?style=for-the-badge)

**Live system forensic triage — processes, network, filesystem, persistence, EVTX — with AI incident reconstruction**

*F-01 of 9 · Cybersecurity Portfolio by [@jmsDev](https://www.linkedin.com/in/jmsilva83)*

</div>

---

## What it does

DFIR-Auto runs a **concurrent forensic sweep** of a live system: suspicious processes, active network connections, filesystem anomalies in temp directories, persistence mechanisms (registry/cron/launchd), and Windows Event Log analysis. All findings are timestamped into a **forensic timeline** and fed to **Google Gemini** for incident narrative reconstruction.

```bash
dfirauto triage
dfirauto demo --no-ai
dfirauto collect process
dfirauto report triage.json --output report.html
```

---

## Features

- **5 concurrent collectors** — all run in parallel via `asyncio.gather`
- **Cross-platform** — Windows (primary), Linux, macOS — each collector self-checks platform support
- **Forensic timeline** — all artifacts sorted chronologically into a unified timeline
- **MITRE ATT&CK mapping** — every artifact tagged with relevant technique IDs
- **AI incident narrative** — Gemini reconstructs what happened, THREAT_ASSESSMENT, IOC summary, recommendations
- **HTML report** — dark-theme professional report with artifact table, timeline, AI narrative panel
- **JSON export** — machine-readable output for chain-of-custody documentation

---

## Collectors

### Process Collector (`psutil`)
Enumerates all running processes and flags:

| Detection | Severity | MITRE |
|---|---|---|
| Process masquerading (svchost.exe at wrong path) | CRITICAL | T1036.005 |
| No executable on disk (process hollowing indicator) | HIGH | T1055.012 |
| Running from temp/AppData/Public paths | HIGH | T1059, T1204.002 |
| Known network tools (nc, socat, nmap) | HIGH | T1049, T1571 |
| External connections on non-standard ports | MEDIUM | T1071 |

### Network Collector (`psutil`)
Analyzes active network connections:

| Detection | Severity | MITRE |
|---|---|---|
| Suspicious listening ports (4444, 31337, 6666...) | HIGH | T1571 |
| Suspicious outbound ports (4444, 1337...) | HIGH | T1095 |
| Connection bursts (> 50 simultaneous) | MEDIUM | T1046 |

### Filesystem Collector
Scans temp directories for suspicious files:

| Detection | Severity | MITRE |
|---|---|---|
| Double extensions (invoice.pdf.exe) | HIGH | T1036.007 |
| Hidden executables (.hidden.sh, prefixed dot) | MEDIUM | T1564.001 |
| PE/ELF magic byte mismatch with extension | HIGH | T1027 |
| Webshell signatures (eval+exec+system combos) | CRITICAL | T1505.003 |
| SUID/SGID binaries in temp (Linux) | HIGH | T1548.001 |

### Persistence Collector
Platform-specific persistence enumeration:

| Platform | Checked Locations |
|---|---|
| **Windows** | `HKLM\SOFTWARE\...\Run`, `HKCU\SOFTWARE\...\Run`, `HKLM\...\RunOnce` |
| **Linux** | `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/rc.local`, `~/.bashrc`, `~/.profile`, `authorized_keys` |
| **macOS** | `/Library/LaunchDaemons/`, `/Library/LaunchAgents/`, `~/Library/LaunchAgents/` |

### EVTX Collector (Windows Event Log)
Parses `.evtx` files for critical Event IDs:

| Event ID | Meaning | Severity |
|---|---|---|
| 4625 | Failed logon | MEDIUM |
| 4648 | Explicit credentials logon | HIGH |
| 4672 | Special privilege logon | HIGH |
| 4688 | Process creation (cmdline logging) | contextual |
| 4698 | Scheduled task created | HIGH |
| 4720/4726 | User created/deleted | HIGH |
| 4732 | User added to privileged group | HIGH |
| 7045 | New service installed | HIGH |
| 1102/104 | Security log cleared | CRITICAL |

---

## Installation

```bash
git clone https://github.com/jmsdev83/dfirauto
cd dfirauto
pip install -e .

cp .env.example .env
# Add GEMINI_API_KEY for AI narrative (optional)
```

---

## Usage

```bash
# Full triage of current system
dfirauto triage

# Triage without AI (faster, no API key needed)
dfirauto triage --no-ai

# Triage + save JSON report
dfirauto triage --no-ai --output triage.json

# Triage with EVTX analysis
dfirauto triage --evtx C:\Windows\System32\winevt\Logs\Security.evtx

# Run a single collector
dfirauto collect process
dfirauto collect network
dfirauto collect filesystem
dfirauto collect persistence
dfirauto collect evtx --evtx Security.evtx

# Generate HTML report from saved JSON
dfirauto report triage.json --output report.html

# Demo (full triage, no EVTX)
dfirauto demo --no-ai
```

---

## Architecture

```
dfirauto triage
       │
       ▼
  asyncio.gather(collectors)   ← all run in parallel
  ┌────┴──────────────────────────────────────────────┐
  │  ProcessCollector    NetworkCollector              │
  │  FilesystemCollector PersistenceCollector          │
  │  EvtxCollector (if --evtx)                         │
  └────┬──────────────────────────────────────────────┘
       │
       ▼
  TimelineBuilder       ← sort all artifacts by timestamp → unified timeline
       │
       ▼
  GeminiAnalyzer        ← INCIDENT_NARRATIVE + THREAT_ASSESSMENT + IOC_SUMMARY + RECOMMENDATIONS
       │
       ▼
  Rich terminal table / HTML report / JSON export
```

---

## Severity Classification

| Level | Meaning | Example |
|---|---|---|
| 🔴 **CRITICAL** | Active compromise indicator | Process masquerade, log cleared, webshell |
| 🟠 **HIGH** | Strong malicious signal | Hollowed process, suspicious persistence, LSASS |
| 🟡 **MEDIUM** | Suspicious indicator | Temp directory binary, after-hours connection |
| 🔵 **LOW** | Attacker-useful observation | Service running from unusual path |
| ⚪ **INFO** | Baseline observation | Standard registry run key |

---

## Project Structure

```
dfirauto/
├── dfirauto/
│   ├── collectors/
│   │   ├── base.py                  # BaseCollector ABC + platform check
│   │   ├── process_collector.py     # psutil process enumeration
│   │   ├── network_collector.py     # psutil net connections
│   │   ├── filesystem_collector.py  # Temp dir analysis
│   │   ├── persistence_collector.py # Registry/cron/launchd
│   │   └── evtx_collector.py        # Windows Event Log (python-evtx)
│   ├── core/
│   │   └── triage.py               # Orchestrator + timeline builder
│   ├── analyzers/
│   │   └── ai_analyzer.py          # Gemini incident narrative
│   ├── types/
│   │   └── artifacts.py            # ForensicArtifact, TriageReport, TimelineEvent
│   ├── report/
│   │   ├── generator.py
│   │   └── template.html
│   └── cli/
│       └── main.py
└── pyproject.toml
```

---

## Environment Variables

```env
GEMINI_API_KEY=             # AI incident reconstruction (optional)
```

---

## Portfolio

| # | Category | Project | Status |
|---|---|---|---|
| P-01 | Offensive | ReconAI — Recon Orchestrator | ✅ |
| P-02 | Offensive | WebHunter — OWASP Top 10 Scanner | ✅ |
| P-03 | Offensive | PhishSim — Red Team Phishing | ✅ |
| D-01 | Defensive | SOC-Lite — AI SIEM | ✅ |
| D-02 | Defensive | ThreatFeed — CTI Aggregator | ✅ |
| D-03 | Defensive | HoneyGrid — SSH/HTTP Honeypot | ✅ |
| F-01 | Forensics | **DFIR-Auto** ← you are here | ✅ |
| F-02 | Forensics | MalwareScope — Malware Analyzer | ✅ |
| F-03 | Forensics | PCAPForge — Network Forensics | ✅ |

---

<div align="center">

Copyright © 2025 Desarrollado desde Las Breñas con 💜 por [@jmsDev](https://www.linkedin.com/in/jmsilva83) · All rights reserved

</div>
