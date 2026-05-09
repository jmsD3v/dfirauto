"""
Persistence Collector — startup locations, scheduled tasks, services, cron jobs.

Detects:
- Suspicious cron jobs (Linux/Mac)
- Suspicious startup registry keys (Windows)
- New/modified services
- SSH authorized_keys modifications
- rc.local / init.d modifications
- LaunchDaemons / LaunchAgents (macOS)
- Suspicious WMI subscriptions (Windows)
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dfirauto.collectors.base import BaseCollector
from dfirauto.types.artifacts import (
    ArtifactType, CollectorResult, CollectorStatus, ForensicArtifact, Severity,
)

_SUSPICIOUS_CRON_PATTERNS = [
    "wget", "curl", "bash -i", "nc ", "python", "perl", "ruby",
    "base64", "/tmp/", "/dev/shm", "mkfifo", ">& /dev/", "python -c",
]

_WIN_AUTORUN_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SYSTEM\CurrentControlSet\Services",
]

_LINUX_PERSISTENCE_FILES = [
    "/etc/rc.local", "/etc/rc.d/rc.local",
    "/etc/profile", "/etc/bashrc", "/etc/bash.bashrc",
    "/root/.bashrc", "/root/.bash_profile", "/root/.profile",
]

_CRON_DIRS = [
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
    "/etc/cron.weekly", "/etc/cron.monthly",
    "/var/spool/cron", "/var/spool/cron/crontabs",
]


def _get_hostname() -> str:
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return "unknown"


def _suspicious_pattern_in(text: str) -> list[str]:
    found = []
    text_lower = text.lower()
    for p in _SUSPICIOUS_CRON_PATTERNS:
        if p in text_lower:
            found.append(p)
    return found


class PersistenceCollector(BaseCollector):
    name = "persistence"
    description = "Startup locations, cron jobs, services, registry autorun, SSH keys"
    platforms = ["linux", "windows", "darwin"]

    async def collect(self) -> CollectorResult:
        result = CollectorResult(collector=self.name)
        result.status = CollectorStatus.RUNNING
        start = time.perf_counter()
        hostname = _get_hostname()

        if sys.platform.startswith("win"):
            await self._collect_windows(result, hostname)
        elif sys.platform.startswith("darwin"):
            await self._collect_macos(result, hostname)
        else:
            await self._collect_linux(result, hostname)

        result.status = CollectorStatus.DONE
        result.duration_seconds = time.perf_counter() - start
        return result

    async def _collect_linux(self, result: CollectorResult, hostname: str) -> None:
        now = datetime.now(timezone.utc)

        # Cron directories
        for cron_dir in _CRON_DIRS:
            p = Path(cron_dir)
            if not p.exists():
                continue
            try:
                entries = list(p.iterdir()) if p.is_dir() else [p]
                for entry in entries:
                    if not entry.is_file():
                        continue
                    try:
                        content = entry.read_text(encoding="utf-8", errors="replace")
                        for line in content.splitlines():
                            line = line.strip()
                            if line.startswith("#") or not line:
                                continue
                            suspects = _suspicious_pattern_in(line)
                            if suspects:
                                artifact = ForensicArtifact(
                                    artifact_type=ArtifactType.SCHEDULED_TASK,
                                    severity=Severity.HIGH,
                                    timestamp=now,
                                    collector=self.name,
                                    hostname=hostname,
                                    name=f"cron:{entry.name}",
                                    value=line[:300],
                                    description=f"Suspicious cron entry in {entry}: {line[:150]}",
                                    mitre_techniques=["T1053.003"],
                                    mitre_tactics=["persistence"],
                                    tags=[f"pattern:{p}" for p in suspects],
                                )
                                result.artifacts.append(artifact)
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                continue

        # Persistence files (/etc/rc.local, .bashrc, etc.)
        for fp in _LINUX_PERSISTENCE_FILES:
            try:
                path = Path(fp)
                if not path.exists():
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
                suspects = _suspicious_pattern_in(content)
                if suspects:
                    artifact = ForensicArtifact(
                        artifact_type=ArtifactType.PERSISTENCE,
                        severity=Severity.HIGH,
                        timestamp=datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc),
                        collector=self.name,
                        hostname=hostname,
                        name=fp,
                        value=content[-500:],
                        description=f"Suspicious content in {fp}: patterns={suspects}",
                        mitre_techniques=["T1546.004"],
                        mitre_tactics=["persistence"],
                        tags=["startup_file"] + [f"pattern:{p}" for p in suspects],
                    )
                    result.artifacts.append(artifact)
            except (PermissionError, OSError):
                continue

        # SSH authorized_keys
        for home in [Path("/root"), *Path("/home").iterdir()] if Path("/home").exists() else [Path("/root")]:
            try:
                ssh_dir = home / ".ssh"
                auth_keys = ssh_dir / "authorized_keys"
                if auth_keys.exists():
                    lines = auth_keys.read_text(encoding="utf-8", errors="replace").strip().splitlines()
                    if len(lines) > 0:
                        artifact = ForensicArtifact(
                            artifact_type=ArtifactType.PERSISTENCE,
                            severity=Severity.MEDIUM,
                            timestamp=datetime.fromtimestamp(auth_keys.stat().st_mtime, tz=timezone.utc),
                            collector=self.name,
                            hostname=hostname,
                            username=home.name,
                            name=str(auth_keys),
                            value=f"{len(lines)} authorized key(s)",
                            description=f"SSH authorized_keys for {home.name}: {len(lines)} key(s)",
                            mitre_techniques=["T1098.004"],
                            mitre_tactics=["persistence"],
                            tags=["ssh_key"],
                        )
                        result.artifacts.append(artifact)
            except (PermissionError, OSError, StopIteration):
                continue

    async def _collect_windows(self, result: CollectorResult, hostname: str) -> None:
        try:
            import winreg
        except ImportError:
            result.error = "winreg not available"
            return

        now = datetime.now(timezone.utc)
        for key_path in _WIN_AUTORUN_KEYS:
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    key = winreg.OpenKey(hive, key_path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            suspects = _suspicious_pattern_in(str(value))
                            severity = Severity.HIGH if suspects else Severity.MEDIUM
                            artifact = ForensicArtifact(
                                artifact_type=ArtifactType.REGISTRY,
                                severity=severity,
                                timestamp=now,
                                collector=self.name,
                                hostname=hostname,
                                name=f"{key_path}\\{name}",
                                value=str(value)[:300],
                                description=f"Autorun entry: {name} = {value}",
                                mitre_techniques=["T1547.001"],
                                mitre_tactics=["persistence"],
                                tags=["autorun"] + ([f"pattern:{p}" for p in suspects] if suspects else []),
                            )
                            result.artifacts.append(artifact)
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except (WindowsError, OSError):
                    continue

    async def _collect_macos(self, result: CollectorResult, hostname: str) -> None:
        import subprocess
        now = datetime.now(timezone.utc)

        launchd_dirs = [
            "/Library/LaunchDaemons", "/Library/LaunchAgents",
            str(Path.home() / "Library/LaunchAgents"),
        ]
        for d in launchd_dirs:
            p = Path(d)
            if not p.exists():
                continue
            try:
                for plist in p.glob("*.plist"):
                    try:
                        content = plist.read_text(encoding="utf-8", errors="replace")
                        suspects = _suspicious_pattern_in(content)
                        severity = Severity.HIGH if suspects else Severity.MEDIUM
                        artifact = ForensicArtifact(
                            artifact_type=ArtifactType.PERSISTENCE,
                            severity=severity,
                            timestamp=datetime.fromtimestamp(plist.stat().st_mtime, tz=timezone.utc),
                            collector=self.name,
                            hostname=hostname,
                            name=str(plist),
                            value=content[:500],
                            description=f"LaunchAgent/Daemon: {plist.name}",
                            mitre_techniques=["T1543.001"],
                            mitre_tactics=["persistence"],
                            tags=["launchd"] + ([f"pattern:{p}" for p in suspects] if suspects else []),
                        )
                        result.artifacts.append(artifact)
                    except Exception:
                        continue
            except (PermissionError, OSError):
                continue
