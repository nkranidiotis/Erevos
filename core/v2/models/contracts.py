from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass(slots=True)
class Evidence:
    """Atomic evidence item for explainable detections."""

    source: str
    field: str
    value: str
    offset: Optional[int] = None
    rva: Optional[int] = None
    va: Optional[int] = None


@dataclass(slots=True)
class Finding:
    """Single explainable finding emitted by analyzers/heuristics."""

    key: str
    title: str
    severity: str
    confidence: str
    summary: str
    evidence: List[Evidence] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisContext:
    file_path: str
    file_bytes: bytes
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    facts: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    log: List[Dict[str, Any]] = field(default_factory=list)

    def add_log(self, action: str, details: Dict[str, Any] | None = None) -> None:
        self.log.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "details": details or {},
            }
        )

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
