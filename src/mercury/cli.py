"""Mercury command-line interface.

Commands:
  mercury scope-check   Test whether targets are in scope (no network action).
  mercury recon         Run an allowlisted recon tool against an in-scope target.
  mercury analyze       Statically analyze a suspicious file (ClickFix lure, script, sample).
  mercury audit-skill   Statically audit an agent skill package for poisoning.
  mercury verify-audit  Verify the audit-log hash chain.
  mercury report        Render a Markdown report from a findings JSON file.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .analysis import analyze_file, audit_skill, ingest
from .audit import AuditLog
from .authorization import Guard, ScopeViolation
from .engagement import Engagement
from .findings import Finding, FindingStore
from .orchestrator import ToolRunner
from .report import render_markdown

app = typer.Typer(help="Mercury: authorization-first red-team and analysis agent.", add_completion=False)
console = Console()

DEFAULT_AUDIT = "engagements/audit.log.jsonl"
DEFAULT_QUARANTINE = "engagements/quarantine"


def _load(engagement_path: str, audit_path: str) -> tuple[Engagement, Guard]:
    eng = Engagement.load(engagement_path)
    guard = Guard(eng, AuditLog(audit_path))
    return eng, guard


@app.command()
def version() -> None:
    """Print the Mercury version."""
    console.print(f"Mercury {__version__}")


@app.command("scope-check")
def scope_check(
    targets: list[str] = typer.Argument(..., help="Hosts/URLs to test"),
    engagement: str = typer.Option(..., "--engagement", "-e", help="Engagement YAML"),
) -> None:
    """Report whether each target is in scope. Performs no network action."""
    eng = Engagement.load(engagement)
    table = Table("Target", "Decision", "Reason")
    for t in targets:
        d = eng.scope.check(t)
        table.add_row(t, "[green]ALLOW[/]" if d else "[red]DENY[/]", d.reason)
    console.print(table)


@app.command()
def recon(
    tool: str = typer.Argument(..., help="Allowlisted tool (nmap, httpx)"),
    target: str = typer.Argument(..., help="In-scope host or URL"),
    engagement: str = typer.Option(..., "--engagement", "-e"),
    audit: str = typer.Option(DEFAULT_AUDIT, "--audit"),
    ports: str = typer.Option("", "--ports", help="Port spec passed to the tool"),
    out: str = typer.Option("", "--out", help="Write findings JSON here"),
) -> None:
    """Run an allowlisted recon tool against an in-scope target."""
    _, guard = _load(engagement, audit)
    runner = ToolRunner(guard)
    try:
        result = runner.run(tool, target, options={"ports": ports} if ports else {})
    except ScopeViolation as exc:
        console.print(f"[red]DENIED:[/] {exc}")
        raise typer.Exit(code=2) from exc
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[yellow]{exc}[/]")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]{tool}[/] rc={result.returncode}, {len(result.findings)} finding(s)")
    for f in result.findings:
        console.print(f"  - [{f.severity.value}] {f.title}")
    if out:
        store = FindingStore()
        store.extend(result.findings)
        store.save(out)
        console.print(f"findings written to {out}")


@app.command()
def analyze(
    path: str = typer.Argument(..., help="Suspicious file to analyze statically"),
    quarantine: str = typer.Option(DEFAULT_QUARANTINE, "--quarantine"),
    out: str = typer.Option("", "--out", help="Write findings JSON here"),
) -> None:
    """Quarantine and statically analyze a suspicious artifact (never executed)."""
    art = ingest(path, quarantine)
    console.print(f"ingested [cyan]{art.name}[/] sha256={art.sha256[:16]}… -> {art.quarantine_path}")
    findings = analyze_file(art.quarantine_path, target=art.name)
    _print_findings(findings)
    if out:
        store = FindingStore()
        store.extend(findings)
        store.save(out)
        console.print(f"findings written to {out}")


@app.command("audit-skill")
def audit_skill_cmd(
    path: str = typer.Argument(..., help="Skill file or directory to audit"),
    out: str = typer.Option("", "--out"),
) -> None:
    """Statically audit an agent skill package for poisoning indicators."""
    findings = audit_skill(path)
    _print_findings(findings)
    if out:
        store = FindingStore()
        store.extend(findings)
        store.save(out)
        console.print(f"findings written to {out}")


@app.command("verify-audit")
def verify_audit(audit: str = typer.Option(DEFAULT_AUDIT, "--audit")) -> None:
    """Verify the audit-log hash chain is intact."""
    ok, msg = AuditLog(audit).verify()
    console.print(("[green]OK:[/] " if ok else "[red]FAIL:[/] ") + msg)
    raise typer.Exit(code=0 if ok else 3)


@app.command()
def report(
    engagement: str = typer.Option(..., "--engagement", "-e"),
    findings: str = typer.Option(..., "--findings", "-f", help="Findings JSON file"),
    out: str = typer.Option("report.md", "--out", "-o"),
) -> None:
    """Render a Markdown report from a findings JSON file."""
    eng = Engagement.load(engagement)
    items = [Finding.model_validate(x) for x in json.loads(Path(findings).read_text())]
    Path(out).write_text(render_markdown(eng, items), encoding="utf-8")
    console.print(f"report written to [green]{out}[/] ({len(items)} findings)")


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        console.print("[green]no indicators matched[/]")
        return
    table = Table("Severity", "Finding", "ATT&CK", "Evidence")
    for f in sorted(findings, key=lambda x: x.severity.rank, reverse=True):
        table.add_row(f.severity.value, f.title, ", ".join(f.attack), f.evidence[:60])
    console.print(table)


if __name__ == "__main__":
    app()
