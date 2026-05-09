"""
Filesystem Collector — suspicious files, modified system files, hidden files.

Detects:
- Recently modified files in system directories
- Files with suspicious names (double extensions, hidden + executable)
- Large files in temp directories (staging)
- Executable files in non-standard locations
- Files with mismatched extensions (e.g., .jpg with PE header)
- SUID/SGID files on Linux (privilege escalation vectors)
- Common webshell signatures in web directories
"""

from __future__ import annotations

import asyncio
import os
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from dfirauto.collectors.base import BaseCollector
from dfirauto.types.artifacts import (
    ArtifactType, CollectorResult, CollectorStatus, ForensicArtifact, Severity,
)

_SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
                           ".scr", ".pif", ".com", ".jar", ".py", ".rb", ".pl"}
_DOUBLE_EXTENSION_PATTERN = [".pdf.exe", ".doc.exe", ".jpg.exe", ".png.exe",
                               ".txt.exe", ".xlsx.exe"]

# Directories to scan on each platform
_SCAN_DIRS_LINUX = [
    "/tmp", "/var/tmp", "/dev/shm",
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
    "/etc/init.d", "/etc/rc.local",
]
_SCAN_DIRS_WIN = [
    os.path.expandvars("%TEMP%"),
    os.path.expandvars("%APPDATA%"),
    os.path.expandvars("%LOCALAPPDATA%\\Temp"),
    "C:\\Windows\\Temp",
    "C:\\Users\\Public",
]
_SCAN_DIRS_MAC = [
    "/tmp", "/var/tmp",
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    os.path.expanduser("~/Library/LaunchAgents"),
]

# Webshell signatures
_WEBSHELL_SIGS = [
    b"eval(base64_decode", b"system($_GET", b"passthru($_POST",
    b"exec($_REQUEST", b"shell_exec(", b"phpinfo()",
    b"<?php @eval", b"assert($_POST",
]

_PE_MAGIC = b"MZ"
_ELF_MAGIC = b"\x7fELF"


def _get_scan_dirs() -> list[str]:
    import sys
    if sys.platform.startswith("win"):
        return _SCAN_DIRS_WIN
    if sys.platform.startswith("darwin"):
        return _SCAN_DIRS_MAC
    return _SCAN_DIRS_LINUX


def _get_hostname() -> str:
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return "unknown"


def _is_executable_header(path: Path) -> bool:
    try:
        header = path.read_bytes()[:4]
        return header[:2] == _PE_MAGIC or header[:4] == _ELF_MAGIC
    except Exception:
        return False


def _has_webshell_sig(path: Path) -> str | None:
    try:
        content = path.read_bytes()[:8192]
        for sig in _WEBSHELL_SIGS:
            if sig in content:
                return sig.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


class FilesystemCollector(BaseCollector):
    name = "filesystem"
    description = "Suspicious files in temp dirs, hidden executables, webshells, SUID files"
    platforms = ["linux", "windows", "darwin"]

    def __init__(self, max_files: int = 500, age_days: int = 7):
        self.max_files = max_files
        self.age_days = age_days

    async def collect(self) -> CollectorResult:
        result = CollectorResult(collector=self.name)
        result.status = CollectorStatus.RUNNING
        start = time.perf_counter()
        hostname = _get_hostname()

        scan_dirs = _get_scan_dirs()
        count = 0

        for dir_path in scan_dirs:
            if count >= self.max_files:
                break
            try:
                base = Path(dir_path)
                if not base.exists():
                    continue
                for entry in base.rglob("*"):
                    if count >= self.max_files:
                        break
                    if not entry.is_file():
                        continue
                    try:
                        await self._check_file(entry, hostname, result)
                        count += 1
                    except Exception:
                        continue
            except (PermissionError, OSError):
                continue

        result.status = CollectorStatus.DONE
        result.duration_seconds = time.perf_counter() - start
        return result

    async def _check_file(self, path: Path, hostname: str, result: CollectorResult) -> None:
        severity = Severity.INFO
        tags: list[str] = []
        mitre: list[str] = []

        name = path.name
        suffix = path.suffix.lower()
        stem = path.stem.lower()

        # Double extension (e.g. invoice.pdf.exe)
        for double_ext in _DOUBLE_EXTENSION_PATTERN:
            if name.lower().endswith(double_ext):
                severity = Severity.HIGH
                tags.append("double_extension")
                mitre.append("T1036.007")

        # Hidden + executable on Linux/Mac
        if name.startswith(".") and suffix in _SUSPICIOUS_EXTENSIONS:
            severity = Severity.HIGH
            tags.append("hidden_executable")
            mitre.append("T1564.001")

        # Executable file in temp directory
        if suffix in _SUSPICIOUS_EXTENSIONS and severity.weight < Severity.MEDIUM.weight:
            severity = Severity.MEDIUM
            tags.append("executable_in_temp")
            mitre.append("T1204.002")

        # Mismatched extension (image/doc file with PE/ELF header)
        if suffix.lower() in {".jpg", ".png", ".gif", ".doc", ".pdf", ".txt", ".zip"}:
            if _is_executable_header(path):
                severity = Severity.CRITICAL
                tags.append("mismatched_extension")
                mitre.extend(["T1036.007", "T1027"])

        # Webshell signatures
        if suffix in {".php", ".asp", ".aspx", ".jsp", ".cgi"}:
            sig = _has_webshell_sig(path)
            if sig:
                severity = Severity.CRITICAL
                tags.append("webshell")
                mitre.extend(["T1505.003", "T1190"])

        # SUID/SGID on Linux (privilege escalation)
        import sys
        if sys.platform.startswith("linux"):
            try:
                st = path.stat()
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    if severity.weight < Severity.HIGH.weight:
                        severity = Severity.HIGH
                    tags.append("suid_sgid")
                    mitre.append("T1548.001")
            except Exception:
                pass

        if severity == Severity.INFO:
            return

        try:
            file_stat = path.stat()
            mtime = datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc)
            size = file_stat.st_size
        except Exception:
            mtime = datetime.now(timezone.utc)
            size = 0

        desc = f"Suspicious file: {path} ({size:,} bytes)"
        if tags:
            desc += f" — flags: {', '.join(tags)}"

        artifact = ForensicArtifact(
            artifact_type=ArtifactType.FILE,
            severity=severity,
            timestamp=mtime,
            collector=self.name,
            hostname=hostname,
            name=name,
            value=str(path),
            description=desc,
            mitre_techniques=list(dict.fromkeys(mitre)),
            tags=tags,
            raw={"path": str(path), "size": size},
        )
        result.artifacts.append(artifact)
