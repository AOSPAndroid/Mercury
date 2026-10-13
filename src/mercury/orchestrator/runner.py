"""Run allowlisted tools under the authorization guard.

Flow for every run:
  1. Resolve the tool from the allowlist (unknown tool -> error).
  2. Ask the Guard to authorize the action against the target (scope + audit).
  3. Execute the tool as an explicit argv (never ``shell=True``) with a timeout.
  4. Record completion in the audit log and parse output into findings.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from ..authorization import Guard
from ..findings import Finding
from .tools import TOOLS, ToolSpec


@dataclass
class ToolResult:
    tool: str
    target: str
    returncode: int
    stdout: str
    stderr: str
    findings: list[Finding]


class ToolRunner:
    def __init__(self, guard: Guard) -> None:
        self.guard = guard

    def available(self, tool: str) -> bool:
        spec = TOOLS.get(tool)
        return bool(spec and shutil.which(spec.binary))

    def run(
        self,
        tool: str,
        target: str,
        *,
        port: int | None = None,
        options: dict | None = None,
    ) -> ToolResult:
        spec: ToolSpec | None = TOOLS.get(tool)
        if spec is None:
            raise ValueError(f"unknown tool {tool!r}; allowlisted tools: {sorted(TOOLS)}")

        # Scope check + audit happen here. Raises ScopeViolation if denied.
        self.guard.authorize(action=f"tool:{tool}", target=target, port=port)

        if not shutil.which(spec.binary):
            raise FileNotFoundError(
                f"{spec.binary!r} is not installed or not on PATH"
            )

        argv = [spec.binary, *spec.build_args(target, options or {})]
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=spec.timeout,
                shell=False,
                check=False,
            )
            stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, rc = (exc.stdout or ""), f"timeout after {spec.timeout}s", 124

        self.guard.audit.record(
            "tool_run",
            actor=self.guard.engagement.operator,
            tool=tool,
            target=target,
            argv=argv,
            returncode=rc,
        )

        findings = spec.parse(target, stdout) if rc == 0 else []
        return ToolResult(tool, target, rc, stdout, stderr, findings)
