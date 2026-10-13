"""Allowlisted tool specifications.

Mercury does not run arbitrary shell commands. It runs a curated set of
read-oriented reconnaissance and enumeration tools, each described by a
``ToolSpec`` that builds an explicit argument vector. This is the deliberate
opposite of a "run anything" agent: adding a capability means adding a spec and
a parser, which is reviewable.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..findings import Finding, Severity


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    # Build argv (excluding the binary) from a target and caller options.
    build_args: Callable[[str, dict], list[str]]
    # Parse stdout into findings.
    parse: Callable[[str, str], list[Finding]]
    description: str = ""
    # Default seconds before the subprocess is killed.
    timeout: int = 300
    tags: tuple[str, ...] = field(default_factory=tuple)


# --- parsers ------------------------------------------------------------------


def _parse_nmap(target: str, out: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        # e.g. "22/tcp open ssh OpenSSH 8.9p1"
        if "/tcp" in line and " open " in line:
            parts = line.split()
            port_proto = parts[0]
            service = parts[2] if len(parts) > 2 else "unknown"
            banner = " ".join(parts[3:]) if len(parts) > 3 else ""
            desc = f"Service {service} reachable on {target}."
            if banner:
                desc += f" Banner: {banner}"
            findings.append(
                Finding(
                    title=f"Open port {port_proto} ({service})",
                    severity=Severity.INFO,
                    target=target,
                    source="nmap",
                    description=desc,
                    evidence=line,
                )
            )
    return findings


def _parse_httpx(target: str, out: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if line:
            findings.append(
                Finding(
                    title="HTTP service responded",
                    severity=Severity.INFO,
                    target=target,
                    source="httpx",
                    description="HTTP probe returned a response.",
                    evidence=line,
                )
            )
    return findings


# --- specs --------------------------------------------------------------------

TOOLS: dict[str, ToolSpec] = {
    "nmap": ToolSpec(
        name="nmap",
        binary="nmap",
        # -Pn no ping, -sV version detect; ports constrained by caller if given.
        build_args=lambda target, opts: (
            ["-Pn", "-sV"]
            + (["-p", opts["ports"]] if opts.get("ports") else [])
            + [target]
        ),
        parse=_parse_nmap,
        description="Service/version enumeration of in-scope hosts.",
        tags=("recon", "enumeration"),
    ),
    "httpx": ToolSpec(
        name="httpx",
        binary="httpx",
        build_args=lambda target, opts: ["-silent", "-status-code", "-title", "-u", target],
        parse=_parse_httpx,
        description="HTTP probing of in-scope web endpoints.",
        tags=("recon", "web"),
    ),
}
