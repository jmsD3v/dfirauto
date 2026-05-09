"""DFIR-Auto core data models — forensic artifacts, timeline, incident."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ArtifactType(str, Enum):
    PROCESS = "process"
    NETWORK_CONNECTION = "network_connection"
    FILE = "file"
    REGISTRY = "registry"
    EVENT_LOG = "event_log"
    PREFETCH = "prefetch"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    USER_ACCOUNT = "user_account"
    MEMORY_STRING = "memory_string"
    BROWSER_HISTORY = "browser_history"
    DNS = "dns"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]

    @property
    def color(self) -> str:
        return {
            "critical": "red", "high": "dark_orange",
            "medium": "yellow", "low": "cyan", "info": "bright_black"
        }[self.value]


class CollectorStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class ForensicArtifact:
    """A single forensic artifact found during triage."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    artifact_type: ArtifactType = ArtifactType.FILE
    severity: Severity = Severity.INFO
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    collector: str = ""             # which collector found it
    hostname: str = ""
    username: str | None = None
    # Core finding data
    name: str = ""                  # process name, file path, registry key, etc.
    value: str = ""                 # command line, file hash, reg value, etc.
    description: str = ""          # human-readable finding
    # Enrichment
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.artifact_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "collector": self.collector,
            "hostname": self.hostname,
            "username": self.username,
            "name": self.name,
            "value": self.value,
            "description": self.description,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "iocs": self.iocs,
            "tags": self.tags,
        }


@dataclass
class TimelineEvent:
    """A single event in the forensic timeline."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str = ""
    description: str = ""
    artifact: ForensicArtifact | None = None
    severity: Severity = Severity.INFO
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity.value,
            "source": self.source,
            "artifact_id": self.artifact.id if self.artifact else None,
        }


@dataclass
class CollectorResult:
    """Result from a single forensic collector."""
    collector: str = ""
    status: CollectorStatus = CollectorStatus.PENDING
    artifacts: list[ForensicArtifact] = field(default_factory=list)
    error: str | None = None
    duration_seconds: float = 0.0
    evidence_paths: list[str] = field(default_factory=list)


@dataclass
class TriageReport:
    """Full DFIR triage result."""
    case_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    hostname: str = ""
    investigator: str = "DFIR-Auto"
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    collector_results: list[CollectorResult] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    ai_narrative: str = ""
    ai_ioc_summary: str = ""
    recommendations: list[str] = field(default_factory=list)

    @property
    def all_artifacts(self) -> list[ForensicArtifact]:
        artifacts = []
        for cr in self.collector_results:
            artifacts.extend(cr.artifacts)
        return artifacts

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or datetime.now(timezone.utc)
        return (end - self.started_at).total_seconds()

    @property
    def summary(self) -> dict[str, Any]:
        arts = self.all_artifacts
        return {
            "total_artifacts": len(arts),
            "critical": sum(1 for a in arts if a.severity == Severity.CRITICAL),
            "high": sum(1 for a in arts if a.severity == Severity.HIGH),
            "medium": sum(1 for a in arts if a.severity == Severity.MEDIUM),
            "timeline_events": len(self.timeline),
            "collectors_run": len(self.collector_results),
            "collectors_done": sum(1 for r in self.collector_results if r.status == CollectorStatus.DONE),
        }

    def sorted_artifacts(self) -> list[ForensicArtifact]:
        return sorted(self.all_artifacts, key=lambda a: a.severity.weight, reverse=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "hostname": self.hostname,
            "investigator": self.investigator,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "summary": self.summary,
            "ai_narrative": self.ai_narrative,
            "ai_ioc_summary": self.ai_ioc_summary,
            "recommendations": self.recommendations,
            "artifacts": [a.to_dict() for a in self.sorted_artifacts()],
            "timeline": [e.to_dict() for e in self.timeline],
        }
