# Mercury — contributor & agent guide

Mercury is an authorization-first red-team + analysis agent. Read this before
changing anything; some rules here are load-bearing, not style.

## Non-negotiable design rules

These exist because Mercury's whole point is to be the *governable* opposite of
an auto-exploiting agent. Do not weaken them:

1. **No bypass of the Guard.** Every action that touches a target goes through
   `authorization.Guard.authorize(...)`, which checks scope and writes to the
   audit log. Never add a "skip scope", "force", or "YOLO" flag.
2. **No arbitrary command execution.** Tools are added only as reviewable
   `ToolSpec` entries in `orchestrator/tools.py` with explicit argv. Never
   introduce `shell=True` or pass user strings to a shell.
3. **Analysis is static.** The `analysis/` package reads and pattern-matches
   artifacts. It must never execute, import, or "detonate" a sample. Intake
   quarantines samples read-only (`0o400`).
4. **No offensive payload generation.** Mercury does not build malware, RATs,
   ClickFix delivery chains, exploit implants, or poisoned skills. The malicious
   TTPs it knows about live in `signatures.py` as *detection* rules only.
5. **The audit log is append-only and verifiable.** Don't add deletion/rewrite
   paths. `AuditLog.verify()` must stay able to detect tampering.

## Layout

- `scope.py` — scope model + in-scope matching (CIDR/domain/port/time).
- `audit.py` — hash-chained append-only audit log.
- `engagement.py` — engagement YAML model + readiness checks.
- `authorization.py` — the Guard (scope check + audit, raises `ScopeViolation`).
- `orchestrator/` — allowlisted tool specs and the subprocess runner.
- `analysis/` — intake, signatures, static analyzer, skill auditor.
- `findings.py` / `report.py` — normalized findings and Markdown reporting.
- `cli.py` — the `mercury` CLI.

## Adding a recon tool

Add a `ToolSpec` to `TOOLS` in `orchestrator/tools.py`: a `build_args` that
returns an explicit argument list, and a `parse` that turns stdout into
`Finding`s. Keep tools read/enumeration-oriented.

## Adding a detection signature

Append a `Signature` to `SIGNATURES` (generic) or `SKILL_SIGNATURES` (skill
audit) in `analysis/signatures.py`. Give it a MITRE ATT&CK mapping where one
applies, and add a test with a **defanged** fixture (keywords only, no working
payload) in `tests/test_analysis.py`.

## Checks before pushing

```bash
. .venv/bin/activate
ruff check src tests
pytest -q
```

## Attribution / secrets

Never commit live engagement data: `.gitignore` already excludes real
`*.engagement.yaml`, the audit log, the quarantine dir, findings JSON, and
reports. Keep only `example.engagement.yaml`.
