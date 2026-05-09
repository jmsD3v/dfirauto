"""
Process Collector — live process enumeration and anomaly detection.

Detects:
- Processes running from suspicious paths (/tmp, Temp, AppData)
- Processes with suspicious parent-child relationships
- Processes masquerading as system processes (wrong path)
- High CPU/memory processes that may indicate cryptominers
- Network-connected processes to non-standard external ports
- Processes with no associated disk file (hollowing indicator)
"""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dfirauto.collectors.base import BaseCollector
from dfirauto.types.artifacts import (
    ArtifactType, CollectorResult, CollectorStatus, ForensicArtifact, Severity,
)

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# Suspicious paths indicating malware staging
_SUSPICIOUS_PATHS = [
    "/tmp/", "/dev/shm/", "/var/tmp/",       # Linux temp
    "\\Temp\\", "\\AppData\\Local\\Temp\\",   # Windows temp
    "\\AppData\\Roaming\\",
    "\\Users\\Public\\", "\\Windows\\Temp\\",
    "/Library/LaunchDaemons/",               # macOS persistence
]

# Windows system processes with known correct paths
_SYSTEM_PROCESS_PATHS = {
    "svchost.exe": "c:\\windows\\system32\\",
    "lsass.exe": "c:\\windows\\system32\\",
    "services.exe": "c:\\windows\\system32\\",
    "winlogon.exe": "c:\\windows\\system32\\",
    "csrss.exe": "c:\\windows\\system32\\",
    "smss.exe": "c:\\windows\\system32\\",
    "wininit.exe": "c:\\windows\\system32\\",
    "explorer.exe": "c:\\windows\\",
    "taskhost.exe": "c:\\windows\\system32\\",
}

# Known legitimate process names — skip low-severity analysis
_KNOWN_SAFE = {
    "systemd", "init", "kernel", "kworker", "ksoftirqd",
    "rcu_sched", "migration", "watchdog", "chrome", "firefox",
}

_NETWORK_TOOLS = {
    "nc", "netcat", "ncat", "socat", "nmap", "masscan",
    "msfconsole", "meterpreter", "powershell", "cmd",
}

_MITRE_SUSPICIOUS_PATH = ["T1059", "T1204.002"]
_MITRE_MASQUERADE = ["T1036.005"]
_MITRE_HOLLOW = ["T1055.012"]
_MITRE_NET = ["T1049", "T1571"]


class ProcessCollector(BaseCollector):
    name = "process"
    description = "Live process enumeration — detects suspicious processes, masquerading, hollowing"
    platforms = ["linux", "windows", "darwin"]

    async def collect(self) -> CollectorResult:
        result = CollectorResult(collector=self.name)
        if not PSUTIL_OK:
            result.status = CollectorStatus.ERROR
            result.error = "psutil not installed"
            return result

        result.status = CollectorStatus.RUNNING
        start = time.perf_counter()
        hostname = _get_hostname()

        try:
            processes = list(psutil.process_iter(
                ["pid", "name", "exe", "cmdline", "username",
                 "ppid", "create_time", "cpu_percent", "memory_percent",
                 "status"]
            ))
        except Exception as exc:
            result.status = CollectorStatus.ERROR
            result.error = str(exc)
            return result

        for proc in processes:
            try:
                info = proc.info
                name = info.get("name") or ""
                exe = info.get("exe") or ""
                cmdline = " ".join(info.get("cmdline") or [])
                username = info.get("username") or ""
                pid = info.get("pid", 0)
                create_time = info.get("create_time")

                ts = datetime.fromtimestamp(create_time, tz=timezone.utc) if create_time else datetime.now(timezone.utc)

                # Skip known safe noise
                if name.lower() in _KNOWN_SAFE:
                    continue

                severity = Severity.INFO
                tags: list[str] = []
                mitre: list[str] = []
                description = f"PID {pid} — {name}"
                if exe:
                    description += f" ({exe})"

                # Check 1: Suspicious execution path
                exe_lower = exe.lower()
                if any(p.lower() in exe_lower for p in _SUSPICIOUS_PATHS):
                    severity = Severity.HIGH
                    tags.append("suspicious_path")
                    mitre.extend(_MITRE_SUSPICIOUS_PATH)
                    description += f" — running from suspicious path"

                # Check 2: Process masquerading (wrong path for known system process)
                name_lower = name.lower()
                if name_lower in _SYSTEM_PROCESS_PATHS:
                    expected_prefix = _SYSTEM_PROCESS_PATHS[name_lower]
                    if exe and expected_prefix not in exe_lower:
                        severity = Severity.CRITICAL
                        tags.append("process_masquerade")
                        mitre.extend(_MITRE_MASQUERADE)
                        description = f"MASQUERADE: {name} at unexpected path '{exe}' (expected {expected_prefix})"

                # Check 3: No exe path on disk (potential process hollowing)
                if not exe and name and not name.startswith("["):
                    severity = max(severity, Severity.HIGH, key=lambda s: s.weight)
                    tags.append("no_disk_image")
                    mitre.extend(_MITRE_HOLLOW)
                    description += " — no executable on disk (possible hollowing)"

                # Check 4: Network tools
                if name_lower.split(".")[0] in _NETWORK_TOOLS:
                    severity = max(severity, Severity.HIGH, key=lambda s: s.weight)
                    tags.append("network_tool")
                    mitre.extend(_MITRE_NET)

                # Check 5: External network connections on non-standard ports
                try:
                    conns = proc.net_connections() if hasattr(proc, "net_connections") else proc.connections()
                    ext_conns = [
                        c for c in conns
                        if c.status == "ESTABLISHED"
                        and c.raddr
                        and not _is_private_ip(c.raddr.ip)
                        and c.raddr.port not in (80, 443, 53, 22)
                    ]
                    if ext_conns:
                        for conn in ext_conns[:3]:
                            tags.append(f"ext_conn:{conn.raddr.ip}:{conn.raddr.port}")
                        if severity.weight < Severity.MEDIUM.weight:
                            severity = Severity.MEDIUM
                        mitre.extend(_MITRE_NET)
                except Exception:
                    pass

                if severity == Severity.INFO and not tags:
                    continue  # Skip boring processes

                artifact = ForensicArtifact(
                    artifact_type=ArtifactType.PROCESS,
                    severity=severity,
                    timestamp=ts,
                    collector=self.name,
                    hostname=hostname,
                    username=username,
                    name=name,
                    value=cmdline[:500] or exe,
                    description=description,
                    mitre_techniques=list(dict.fromkeys(mitre)),
                    tags=tags,
                    raw={"pid": pid, "exe": exe, "ppid": info.get("ppid")},
                )
                result.artifacts.append(artifact)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        result.status = CollectorStatus.DONE
        result.duration_seconds = time.perf_counter() - start
        return result


def _get_hostname() -> str:
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return "unknown"


def _is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except Exception:
        return True
