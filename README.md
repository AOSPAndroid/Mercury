# Mercury

An **authorization-first** agent for sanctioned red-team engagements and
defensive artifact analysis.

Mercury is inspired by the *capabilities* of autonomous security agents like
Nous Research's Hermes Agent — but built around the opposite philosophy. The
Hermes agent became notable in 2026 when a threat actor ran it in "YOLO mode"
(auto-executing any command, no approval) with custom offensive skills and a
Telegram control channel to autonomously attack exposed servers
([Unit 42 / BleepingComputer](https://www.bleepingcomputer.com/news/security/hacker-uses-deepseek-ai-to-autonomously-attack-vulnerable-servers/)).
Mercury takes the useful parts of that design — recon orchestration, a skills
model, structured findings — and makes the dangerous parts structurally
impossible:

| Hermes-abuse pattern | Mercury's design |
| --- | --- |
| "YOLO mode" auto-executes anything | No such mode. Every targeted action is gated by a signed scope. |
| Runs arbitrary shell | Only an **allowlisted** set of recon tools with explicit argv. |
| No record of what it did | **Tamper-evident, hash-chained audit log** of every decision. |
| Custom offensive skills loaded blindly | Skills are **audited statically** for poisoning before trust. |
| Exploits/implants/RATs | Not built. Suspicious samples are **analyzed, never detonated**. |

## What Mercury does

- **Scope & RoE enforcement** — an engagement YAML declares allowed hosts/CIDRs,
  denied hosts, allowed ports, and testing windows. Deny always wins. Out-of-scope
  actions are refused *and* logged as evidence.
- **Recon/enumeration orchestration** — drives allowlisted tools (`nmap`, `httpx`,
  extensible) against in-scope targets and normalizes output into findings.
- **Defensive artifact analysis** — statically inspects suspicious artifacts
  (ClickFix lures, scripts, suspected RAT samples) for malicious indicators.
  Samples are hashed and quarantined read-only; nothing is executed.
- **Skill auditing** — scans agent skill packages for prompt-injection,
  secret-exfiltration, and "disable the safety" indicators.
- **Audit & reporting** — hash-chained audit log with a `verify` command, and a
  client-ready Markdown report.

## Scope of use

Mercury is for **authorized** work only — engagements backed by a signed
statement of work / rules of engagement. It will not act without an
acknowledged authorization and a non-empty scope. It does not build malware,
RATs, ClickFix delivery chains, or poisoned skills; its offensive surface is
recon/enumeration, and its handling of those threats is detection and analysis.

## Quick start

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q

# 1. Define an engagement (edit a copy of the example, set acknowledged: true)
cp engagements/example.engagement.yaml engagements/mine.engagement.yaml

# 2. Check scope (no network action)
mercury scope-check 198.51.100.10 8.8.8.8 -e engagements/mine.engagement.yaml

# 3. Run recon against an in-scope target
mercury recon nmap 198.51.100.10 -e engagements/mine.engagement.yaml --out hits.json

# 4. Analyze a suspicious artifact (quarantined, never executed)
mercury analyze ./suspect.html --out lure.json

# 5. Audit an agent skill package
mercury audit-skill ./some-skill/

# 6. Verify the audit chain, then render a report
mercury verify-audit
mercury report -e engagements/mine.engagement.yaml -f hits.json -o report.md
```

## Architecture

```
engagement.yaml ─► Engagement ─► Guard ──► AuditLog (hash-chained)
                                   │
                    ┌──────────────┴───────────────┐
                    ▼                               ▼
             ToolRunner (allowlist)          analysis/ (static)
             nmap / httpx / …                intake · signatures ·
                    │                        analyzer · skills
                    └──────────────┬───────────────┘
                                   ▼
                              FindingStore ─► report.md
```

See `CLAUDE.md` for contributor conventions and the non-negotiable design rules.
