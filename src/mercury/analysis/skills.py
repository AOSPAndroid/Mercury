"""Audit an agent "skill" package for poisoning / malicious-skill indicators.

Motivated by the Hermes abuse campaign, where the agent's skills system was
loaded with custom offensive skills. A skill is typically a directory with a
manifest (SKILL.md / skill.md / *.yaml) plus helper scripts. This auditor reads
those files statically and reports injection, exfiltration, and
unattended-execution indicators. It never runs the skill.
"""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from .signatures import SIGNATURES, SKILL_SIGNATURES, Signature, scan

_MANIFEST_NAMES = {"skill.md", "skill.yaml", "skill.yml", "manifest.yaml", "manifest.yml"}
_TEXT_SUFFIXES = {".md", ".py", ".sh", ".js", ".ts", ".yaml", ".yml", ".json", ".txt", ".ps1"}
_MAX_BYTES = 2 * 1024 * 1024


def _hits_to_findings(
    target: str, source: str, hits: list[tuple[Signature, str]]
) -> list[Finding]:
    return [
        Finding(
            title=sig.name,
            severity=sig.severity,
            target=target,
            source=source,
            description=sig.description,
            evidence=snippet,
            attack=list(sig.attack),
        )
        for sig, snippet in hits
    ]


def audit_skill(path: str | Path) -> list[Finding]:
    """Statically audit a skill file or directory. Returns findings."""
    root = Path(path)
    files: list[Path]
    if root.is_dir():
        files = [p for p in root.rglob("*") if p.is_file()]
        skill_name = root.name
    else:
        files = [root]
        skill_name = root.name

    rules = SKILL_SIGNATURES + SIGNATURES
    findings: list[Finding] = []
    saw_manifest = False

    for f in files:
        if f.suffix.lower() not in _TEXT_SUFFIXES and f.name.lower() not in _MANIFEST_NAMES:
            continue
        if f.name.lower() in _MANIFEST_NAMES:
            saw_manifest = True
        try:
            text = f.read_bytes()[:_MAX_BYTES].decode("utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(
            _hits_to_findings(
                target=f"{skill_name}:{f.name}",
                source="skill-audit",
                hits=scan(text, rules),
            )
        )

    if root.is_dir() and not saw_manifest:
        findings.append(
            Finding(
                title="Skill has no recognizable manifest",
                severity="low",  # type: ignore[arg-type]
                target=skill_name,
                source="skill-audit",
                description="No SKILL.md / manifest found; an unstructured skill "
                "package is harder to review and may hide behavior in scripts.",
            )
        )
    return findings
