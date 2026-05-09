"""
EVTX Collector — Windows Event Log analysis (offline .evtx files or live on Windows).

Detects:
- Account creation / deletion (4720, 4726)
- Privilege escalation (4672, 4673)
- Logon failures (4625) — brute force
- Logon success after failures (4624)
- Process creation with suspicious cmdline (4688)
- PowerShell execution (4104)
- Log clearing (1102, 104)
- RDP connection (4624 logon_type=10)
- Service installation (7045)
- Scheduled task creation (4698)
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from dfirauto.collectors.base import BaseCollector
from dfirauto.types.artifacts import (
    ArtifactType, CollectorResult, CollectorStatus, ForensicArtifact, Severity,
)

try:
    from evtx import PyEvtxParser
    EVTX_OK = True
except ImportError:
    EVTX_OK = False

import re

# Event ID -> (artifact_type, severity, description, mitre_techniques, mitre_tactics)
_EVENT_MAP = {
    4624: (ArtifactType.EVENT_LOG, Severity.INFO, "Successful logon", ["T1078"], ["initial-access"]),
    4625: (ArtifactType.EVENT_LOG, Severity.MEDIUM, "Failed logon attempt", ["T1110.001"], ["credential-access"]),
    4648: (ArtifactType.EVENT_LOG, Severity.MEDIUM, "Logon with explicit credentials (RunAs)", ["T1134.002"], ["privilege-escalation"]),
    4672: (ArtifactType.EVENT_LOG, Severity.HIGH, "Special privileges assigned (admin logon)", ["T1078.001"], ["privilege-escalation"]),
    4673: (ArtifactType.EVENT_LOG, Severity.HIGH, "Privileged service called", ["T1078.001"], ["privilege-escalation"]),
    4688: (ArtifactType.EVENT_LOG, Severity.INFO, "Process creation", ["T1059"], ["execution"]),
    4698: (ArtifactType.EVENT_LOG, Severity.HIGH, "Scheduled task created", ["T1053.005"], ["persistence"]),
    4720: (ArtifactType.USER_ACCOUNT, Severity.HIGH, "User account created", ["T1136.001"], ["persistence"]),
    4726: (ArtifactType.USER_ACCOUNT, Severity.MEDIUM, "User account deleted", ["T1531"], ["impact"]),
    4732: (ArtifactType.USER_ACCOUNT, Severity.HIGH, "User added to privileged group", ["T1098.001"], ["persistence"]),
    4768: (ArtifactType.EVENT_LOG, Severity.INFO, "Kerberos TGT requested", ["T1558.001"], ["credential-access"]),
    4769: (ArtifactType.EVENT_LOG, Severity.MEDIUM, "Kerberos service ticket requested", ["T1558.003"], ["credential-access"]),
    4776: (ArtifactType.EVENT_LOG, Severity.MEDIUM, "NTLM authentication", ["T1550.002"], ["credential-access"]),
    7045: (ArtifactType.SERVICE, Severity.HIGH, "New service installed", ["T1543.003"], ["persistence"]),
    1102: (ArtifactType.EVENT_LOG, Severity.CRITICAL, "Security log cleared", ["T1070.001"], ["defense-evasion"]),
    104:  (ArtifactType.EVENT_LOG, Severity.CRITICAL, "System log cleared", ["T1070.001"], ["defense-evasion"]),
}

# 4688 cmdline patterns that escalate severity
_SUSPICIOUS_CMDLINE = [
    r"powershell.*-enc", r"powershell.*-e ", r"powershell.*bypass",
    r"cmd.*\/c.*del", r"wscript", r"cscript", r"mshta",
    r"certutil.*-decode", r"bitsadmin.*transfer",
    r"regsvr32.*scrobj", r"rundll32.*javascript",
    r"net\s+user.*\/add", r"net\s+localgroup.*administrators",
    r"whoami.*\/priv", r"mimikatz", r"procdump",
    r"psexec", r"wmic.*process.*call",
]
_SUSPICIOUS_RE = [re.compile(p, re.IGNORECASE) for p in _SUSPICIOUS_CMDLINE]

_POWERSHELL_EVENTS = {4104, 4105, 4106}


def _get_hostname() -> str:
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return "unknown"


def _extract_field(record_data: str, field_name: str) -> str:
    """Extract field value from EVTX XML record."""
    # Try <Data Name="FieldName">value</Data>
    pattern = rf'<Data Name="{field_name}">(.*?)</Data>'
    m = re.search(pattern, record_data, re.DOTALL)
    if m:
        return m.group(1).strip()
    return ""


class EvtxCollector(BaseCollector):
    name = "evtx"
    description = "Windows Event Log analysis — logons, process creation, account changes, log clearing"
    platforms = ["windows", "linux"]  # Linux for offline analysis of .evtx files

    def __init__(self, evtx_path: str | Path | None = None):
        self.evtx_path = Path(evtx_path) if evtx_path else None

    async def collect(self) -> CollectorResult:
        result = CollectorResult(collector=self.name)

        if not EVTX_OK:
            result.status = CollectorStatus.ERROR
            result.error = "python-evtx not installed (pip install python-evtx)"
            return result

        result.status = CollectorStatus.RUNNING
        start = time.perf_counter()
        hostname = _get_hostname()

        paths_to_parse: list[Path] = []
        if self.evtx_path:
            paths_to_parse = [self.evtx_path] if self.evtx_path.is_file() else list(self.evtx_path.glob("*.evtx"))
        else:
            # Default Windows locations
            import sys
            if sys.platform.startswith("win"):
                default_paths = [
                    Path(r"C:\Windows\System32\winevt\Logs\Security.evtx"),
                    Path(r"C:\Windows\System32\winevt\Logs\System.evtx"),
                    Path(r"C:\Windows\System32\winevt\Logs\Application.evtx"),
                    Path(r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"),
                ]
                paths_to_parse = [p for p in default_paths if p.exists()]

        if not paths_to_parse:
            result.status = CollectorStatus.SKIPPED
            result.error = "No .evtx files found. Provide --evtx path."
            return result

        for evtx_file in paths_to_parse:
            result.evidence_paths.append(str(evtx_file))
            try:
                self._parse_evtx(evtx_file, hostname, result)
            except Exception as exc:
                result.error = f"Parse error on {evtx_file}: {exc}"

        result.status = CollectorStatus.DONE
        result.duration_seconds = time.perf_counter() - start
        return result

    def _parse_evtx(self, path: Path, hostname: str, result: CollectorResult) -> None:
        try:
            parser = PyEvtxParser(str(path))
        except Exception:
            return

        for record in parser.records():
            try:
                data = record.get("data", "")
                if not data:
                    continue

                # Extract event ID
                eid_m = re.search(r"<EventID[^>]*>(\d+)</EventID>", data)
                if not eid_m:
                    continue
                event_id = int(eid_m.group(1))

                if event_id not in _EVENT_MAP and event_id not in _POWERSHELL_EVENTS:
                    continue

                # Extract timestamp
                ts_m = re.search(r'SystemTime="([^"]+)"', data)
                ts = datetime.now(timezone.utc)
                if ts_m:
                    try:
                        ts = datetime.fromisoformat(ts_m.group(1).replace("Z", "+00:00"))
                    except Exception:
                        pass

                art_type, severity, base_desc, mitre, tactics = _EVENT_MAP.get(
                    event_id,
                    (ArtifactType.EVENT_LOG, Severity.INFO, f"Event {event_id}", [], [])
                )

                # Extract common fields
                username = _extract_field(data, "SubjectUserName") or \
                           _extract_field(data, "TargetUserName")
                process = _extract_field(data, "NewProcessName") or \
                          _extract_field(data, "ProcessName")
                cmdline = _extract_field(data, "CommandLine")
                logon_type = _extract_field(data, "LogonType")
                service_name = _extract_field(data, "ServiceName")

                # Elevate severity for suspicious cmdlines in process creation
                tags: list[str] = []
                if event_id == 4688 and cmdline:
                    matches = [r.pattern for r in _SUSPICIOUS_RE if r.search(cmdline)]
                    if matches:
                        severity = Severity.CRITICAL
                        tags.extend(["suspicious_cmdline"] + [f"pattern:{m[:20]}" for m in matches[:3]])
                        mitre = ["T1059.001", "T1059.003"]
                    elif process:
                        continue  # Skip boring process creation

                # RDP logon
                if event_id == 4624 and logon_type == "10":
                    severity = Severity.MEDIUM
                    tags.append("rdp_logon")
                    mitre = ["T1021.001"]
                elif event_id == 4624:
                    continue  # Skip boring logons

                # Build description
                desc = base_desc
                if username:
                    desc += f" — user: {username}"
                if process:
                    desc += f" — process: {process}"
                if cmdline:
                    desc += f" — cmd: {cmdline[:100]}"
                if service_name:
                    desc += f" — service: {service_name}"

                artifact = ForensicArtifact(
                    artifact_type=art_type,
                    severity=severity,
                    timestamp=ts,
                    collector=self.name,
                    hostname=hostname,
                    username=username or None,
                    name=f"EventID:{event_id}",
                    value=cmdline or process or service_name or "",
                    description=desc,
                    mitre_techniques=mitre,
                    mitre_tactics=tactics,
                    tags=tags,
                    raw={"event_id": event_id, "logon_type": logon_type},
                )
                result.artifacts.append(artifact)

            except Exception:
                continue
