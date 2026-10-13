"""Static analyzer that turns signature hits into findings."""

from __future__ import annotations

from pathlib import Path

from ..findings import Finding
from .signatures import SIGNATURES, Signature, scan

# Cap how much of a file we read into memory for pattern matching.
_MAX_BYTES = 5 * 1024 * 1024


def _to_findings(target: str, source: str, hits: list[tuple[Signature, str]]) -> list[Finding]:
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


def analyze_content(
    text: str, *, target: str = "", source: str = "analyzer"
) -> list[Finding]:
    """Scan an in-memory string against the generic signature set."""
    return _to_findings(target, source, scan(text, SIGNATURES))


def analyze_file(path: str | Path, *, target: str = "") -> list[Finding]:
    """Read a (quarantined) file as text and scan it. Never executes it."""
    p = Path(path)
    data = p.read_bytes()[:_MAX_BYTES]
    text = data.decode("utf-8", errors="replace")
    return analyze_content(text, target=target or p.name, source=f"file:{p.name}")
