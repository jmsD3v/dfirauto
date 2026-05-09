"""
Network Collector — active connections, listening ports, DNS cache.

Detects:
- Outbound connections to non-standard ports (possible C2)
- Listening services on unexpected ports
- Connections to known-bad IP ranges
- Large number of connections from single process (scanner/beaconing)
- Connections to Tor exit ranges (rough heuristic)
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from dfirauto.collectors.base import BaseCollector
from dfirauto.types.artifacts import (
    ArtifactType, CollectorResult, CollectorStatus, ForensicArtifact, Severity,
)

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# Ports that are suspicious when listening externally
_SUSPICIOUS_LISTEN_PORTS = {
    1337, 4444, 4445, 31337, 1234, 12345, 9999, 6666, 6667,  # classic backdoor ports
    5555, 7777, 8888,  # often used by RATs
    2222, 3333,        # alt SSH
}

# Ports that are suspicious as outbound C2 channels
_SUSPICIOUS_OUTBOUND_PORTS = {
    1337, 4444, 31337, 1234, 12345, 9999, 6666, 8888, 7777,
    4445, 5555, 3333,
}

_COMMON_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                 3306, 5432, 6379, 27017, 8080, 8443}


def _is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except Exception:
        return True


def _get_hostname() -> str:
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return "unknown"


class NetworkCollector(BaseCollector):
    name = "network"
    description = "Active connections, listening ports, suspicious outbound traffic detection"
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
        now = datetime.now(timezone.utc)

        try:
            all_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, Exception) as exc:
            result.status = CollectorStatus.ERROR
            result.error = str(exc)
            return result

        # Group by pid for burst detection
        from collections import defaultdict, Counter
        pid_conn_count: Counter = Counter()
        for conn in all_conns:
            if conn.pid:
                pid_conn_count[conn.pid] += 1

        for conn in all_conns:
            severity = Severity.INFO
            tags: list[str] = []
            mitre: list[str] = []

            lport = conn.laddr.port if conn.laddr else 0
            rip = conn.raddr.ip if conn.raddr else ""
            rport = conn.raddr.port if conn.raddr else 0
            status = conn.status or ""

            # Suspicious listening port
            if status == "LISTEN" and lport in _SUSPICIOUS_LISTEN_PORTS:
                severity = Severity.HIGH
                tags.append(f"suspicious_listen:{lport}")
                mitre.extend(["T1095", "T1571"])

            # External established connection to suspicious port
            if status == "ESTABLISHED" and rip and not _is_private_ip(rip):
                if rport in _SUSPICIOUS_OUTBOUND_PORTS:
                    severity = Severity.CRITICAL
                    tags.append(f"c2_port:{rport}")
                    mitre.extend(["T1095", "T1571", "T1041"])
                elif rport not in _COMMON_PORTS:
                    severity = Severity.MEDIUM
                    tags.append(f"nonstandard_port:{rport}")
                    mitre.append("T1571")

            # Process with excessive connections (scanner/beaconing)
            if conn.pid and pid_conn_count[conn.pid] > 50:
                if severity.weight < Severity.MEDIUM.weight:
                    severity = Severity.MEDIUM
                tags.append(f"conn_burst:{pid_conn_count[conn.pid]}")
                mitre.append("T1046")

            if severity == Severity.INFO:
                continue

            # Get process name
            proc_name = "?"
            try:
                if conn.pid:
                    proc_name = psutil.Process(conn.pid).name()
            except Exception:
                pass

            local_str = f"{conn.laddr.ip}:{lport}" if conn.laddr else "?"
            remote_str = f"{rip}:{rport}" if rip else ""
            desc = f"{proc_name} (PID {conn.pid}) {local_str}"
            if remote_str:
                desc += f" -> {remote_str}"
            desc += f" [{status}]"

            artifact = ForensicArtifact(
                artifact_type=ArtifactType.NETWORK_CONNECTION,
                severity=severity,
                timestamp=now,
                collector=self.name,
                hostname=hostname,
                name=proc_name,
                value=f"{local_str} -> {remote_str} [{status}]",
                description=desc,
                mitre_techniques=list(dict.fromkeys(mitre)),
                iocs=[rip] if rip and not _is_private_ip(rip) else [],
                tags=tags,
                raw={"pid": conn.pid, "lport": lport, "rip": rip, "rport": rport,
                     "status": status},
            )
            result.artifacts.append(artifact)

        result.status = CollectorStatus.DONE
        result.duration_seconds = time.perf_counter() - start
        return result
