"""Findings: the normalized unit of result Mercury produces.

Recon output, scanner hits, and artifact-analysis results all land here so the
report layer has one shape to render.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Finding(BaseModel):
    title: str
    severity: Severity = Severity.INFO
    target: str = ""
    source: str = Field(default="", description="Tool or analyzer that produced this")
    description: str = ""
    evidence: str = ""
    # MITRE ATT&CK technique IDs, e.g. ["T1204.002"]
    attack: list[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FindingStore:
    """A simple append + persist collection of findings."""

    def __init__(self) -> None:
        self._items: list[Finding] = []

    def add(self, finding: Finding) -> Finding:
        self._items.append(finding)
        return finding

    def extend(self, findings: list[Finding]) -> None:
        self._items.extend(findings)

    def all(self) -> list[Finding]:
        return sorted(self._items, key=lambda f: f.severity.rank, reverse=True)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps([f.model_dump(mode="json") for f in self._items], indent=2),
            encoding="utf-8",
        )
