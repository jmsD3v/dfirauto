"""DFIR-Auto triage orchestrator — runs all collectors in parallel."""

from __future__ import annotations

import asyncio
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from dfirauto.collectors.base import BaseCollector
from dfirauto.collectors.evtx_collector import EvtxCollector
from dfirauto.collectors.filesystem_collector import FilesystemCollector
from dfirauto.collectors.network_collector import NetworkCollector
from dfirauto.collectors.persistence_collector import PersistenceCollector
from dfirauto.collectors.process_collector import ProcessCollector
from dfirauto.types.artifacts import (
    CollectorStatus, ForensicArtifact, TimelineEvent, TriageReport,
)


async def run_triage(
    evtx_path: str | Path | None = None,
    use_ai: bool = True,
    max_files: int = 300,
) -> TriageReport:
    """Run full triage: all collectors in parallel, then build timeline + AI analysis."""
    report = TriageReport(hostname=_get_hostname())
    start = time.perf_counter()

    # Build collector list
    collectors: list[BaseCollector] = [
        ProcessCollector(),
        NetworkCollector(),
        FilesystemCollector(max_files=max_files),
        PersistenceCollector(),
    ]
    if evtx_path:
        collectors.append(EvtxCollector(evtx_path=evtx_path))

    # Filter to supported platforms
    collectors = [c for c in collectors if c.is_supported()]

    # Run all collectors concurrently
    tasks = [c.collect() for c in collectors]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            from dfirauto.types.artifacts import CollectorResult
            err_result = CollectorResult(collector="unknown", status=CollectorStatus.ERROR,
                                         error=str(result))
            report.collector_results.append(err_result)
        else:
            report.collector_results.append(result)

    # Build timeline from all artifacts
    all_artifacts = report.all_artifacts
    timeline_events = []
    for artifact in sorted(all_artifacts, key=lambda a: a.timestamp):
        timeline_events.append(TimelineEvent(
            timestamp=artifact.timestamp,
            event_type=artifact.artifact_type.value,
            description=artifact.description,
            artifact=artifact,
            severity=artifact.severity,
            source=artifact.collector,
        ))
    report.timeline = timeline_events

    # AI narrative
    if use_ai and all_artifacts:
        from dfirauto.analyzers.ai_analyzer import analyze_triage
        await analyze_triage(report)

    report.finished_at = datetime.now(timezone.utc)
    report.collector_results  # trigger property

    return report


def _get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"
