"""Defensive artifact analysis.

Everything in this package is static: Mercury inspects suspicious artifacts
(ClickFix lures, scripts, agent skills, suspected RAT samples) by reading and
pattern-matching them. It never executes, detonates, or "runs to see what it
does." Samples are hashed and quarantined on intake.
"""

from .analyzer import analyze_content, analyze_file
from .intake import Artifact, ingest
from .skills import audit_skill

__all__ = ["Artifact", "analyze_content", "analyze_file", "audit_skill", "ingest"]
