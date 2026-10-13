"""Render findings into a client-ready Markdown report."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from .engagement import Engagement
from .findings import Finding, Severity

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def render_markdown(engagement: Engagement, findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append(f"# Mercury Engagement Report — {engagement.name}")
    lines.append("")
    lines.append(f"- **Client:** {engagement.authorization.client}")
    lines.append(f"- **Operator:** {engagement.operator}")
    lines.append(f"- **Authorized by:** {engagement.authorization.authorizing_party}")
    lines.append(f"- **Authorization ref:** {engagement.authorization.sow_reference}")
    lines.append(f"- **Generated:** {now}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in _ORDER:
        lines.append(f"| {sev.value.title()} | {counts.get(sev, 0)} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    ordered = sorted(findings, key=lambda f: f.severity.rank, reverse=True)
    if not ordered:
        lines.append("_No findings recorded._")
    for i, f in enumerate(ordered, 1):
        lines.append(f"### {i}. [{f.severity.value.upper()}] {f.title}")
        lines.append("")
        if f.target:
            lines.append(f"- **Target:** `{f.target}`")
        if f.source:
            lines.append(f"- **Source:** {f.source}")
        if f.attack:
            lines.append(f"- **ATT&CK:** {', '.join(f.attack)}")
        lines.append("")
        if f.description:
            lines.append(f.description)
            lines.append("")
        if f.evidence:
            lines.append("```")
            lines.append(f.evidence)
            lines.append("```")
            lines.append("")
    return "\n".join(lines)
