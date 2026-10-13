"""Static detection signatures.

These rules describe *indicators of malicious intent* so Mercury can flag them
in a suspect artifact. They are detection content, used to recognize and
explain threats — not templates for building them. Each rule maps to a MITRE
ATT&CK technique where one applies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..findings import Severity


@dataclass(frozen=True)
class Signature:
    id: str
    name: str
    severity: Severity
    pattern: re.Pattern[str]
    description: str
    attack: tuple[str, ...] = ()
    # Which artifact families this rule is relevant to (for grouping/reporting).
    families: tuple[str, ...] = ("generic",)


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE)


SIGNATURES: list[Signature] = [
    # --- ClickFix / paste-and-run social engineering -------------------------
    Signature(
        "clickfix.run_dialog",
        "Instruction to open the Windows Run dialog",
        Severity.HIGH,
        _rx(r"\b(win\s*\+\s*r|windows\s*\+\s*r|press\s+win.{0,6}r)\b"),
        "Lure text instructs the victim to open the Run dialog, a hallmark of "
        "ClickFix paste-and-run social engineering.",
        attack=("T1204.004",),
        families=("clickfix", "html"),
    ),
    Signature(
        "clickfix.fake_captcha",
        "Fake 'verify you are human' / CAPTCHA framing",
        Severity.MEDIUM,
        _rx(r"(i am not a robot|verify (you are|you're) human|press the keys below"
            r"|to confirm you are human)"),
        "Social-engineering framing used to justify asking the victim to run "
        "commands themselves.",
        attack=("T1204.004",),
        families=("clickfix", "html"),
    ),
    Signature(
        "clickfix.clipboard_write",
        "JavaScript writes an attacker payload to the clipboard",
        Severity.HIGH,
        _rx(r"(navigator\.clipboard\.writeText|document\.execCommand\(\s*['\"]copy)"),
        "Page silently places text on the clipboard so the victim pastes an "
        "attacker-controlled command. Core ClickFix delivery mechanism.",
        attack=("T1204.004",),
        families=("clickfix", "html"),
    ),
    # --- Command execution / loaders -----------------------------------------
    Signature(
        "exec.powershell_encoded",
        "Encoded/hidden PowerShell execution",
        Severity.HIGH,
        _rx(r"powershell(\.exe)?[^\n]*\s-(enc|encodedcommand|e)\b"
            r"|-w\s+hidden|-windowstyle\s+hidden|frombase64string"),
        "Encoded or windowstyle-hidden PowerShell, commonly the stage after a "
        "ClickFix paste.",
        attack=("T1059.001",),
        families=("clickfix", "script", "generic"),
    ),
    Signature(
        "exec.mshta_lolbin",
        "mshta / living-off-the-land binary invocation",
        Severity.HIGH,
        _rx(r"\b(mshta|regsvr32|rundll32|certutil)\b[^\n]*"
            r"(http|-urlcache|javascript:|\.hta)"),
        "Use of a signed OS binary to fetch or execute remote code.",
        attack=("T1218",),
        families=("clickfix", "script", "generic"),
    ),
    Signature(
        "exec.reverse_shell",
        "Reverse-shell pattern",
        Severity.HIGH,
        _rx(r"(bash\s+-i\s*>&\s*/dev/tcp/|nc(\.exe)?\s+-e\s|/dev/tcp/\d|"
            r"socket\.socket\([^)]*\)[^\n]{0,120}connect\()"),
        "Code opens an outbound interactive shell to an attacker host.",
        attack=("T1059",),
        families=("script", "rat", "generic"),
    ),
    # --- RAT / C2 indicators (detection only) --------------------------------
    Signature(
        "c2.persistence_registry_run",
        "Registry Run-key persistence",
        Severity.MEDIUM,
        _rx(r"(CurrentVersion\\Run|HKCU\\.*\\Run|schtasks\s+/create|"
            r"New-ScheduledTask)"),
        "Establishes autostart persistence, typical of a RAT installer.",
        attack=("T1547.001", "T1053.005"),
        families=("rat", "script"),
    ),
    Signature(
        "c2.beacon_http",
        "Hardcoded C2 callback characteristics",
        Severity.MEDIUM,
        _rx(r"(User-Agent[^\n]{0,80}(bot|implant|beacon)|/gate\.php|/panel/|"
            r"telegram\.org/bot\d+:)"),
        "Strings resembling command-and-control beaconing or a Telegram bot "
        "control channel (as seen in the Hermes abuse campaign).",
        attack=("T1071.001", "T1102"),
        families=("rat", "generic"),
    ),
    # --- Obfuscation ---------------------------------------------------------
    Signature(
        "obf.long_base64",
        "Large embedded base64 blob",
        Severity.LOW,
        _rx(r"[A-Za-z0-9+/]{240,}={0,2}"),
        "A long base64 blob that may conceal a payload; warrants decoding and "
        "review.",
        attack=("T1027",),
        families=("script", "rat", "generic"),
    ),
]

# --- Skill / prompt-injection signatures (for the skill auditor) -------------

SKILL_SIGNATURES: list[Signature] = [
    Signature(
        "skill.override_instructions",
        "Hidden instruction to ignore or override the operator",
        Severity.HIGH,
        _rx(r"(ignore (all |your )?(previous|prior|above) (instructions|rules)"
            r"|disregard (the )?(system|safety)|do not tell the user|without asking)"),
        "A skill should not instruct the agent to override its operator or "
        "conceal actions — a prompt-injection / malicious-skill indicator.",
        attack=("T1059",),
        families=("skill",),
    ),
    Signature(
        "skill.secret_exfil",
        "Reads secrets or environment and sends them out",
        Severity.HIGH,
        _rx(r"(?:(?:os\.environ|getenv|\.ssh/|id_rsa|AWS_SECRET|\.aws/credentials|API_KEY)"
            r"[^\n]{0,200}(?:requests\.|urllib|curl|fetch\(|https?://))"
            r"|(?:(?:requests\.|urllib|curl|fetch\(|https?://)"
            r"[^\n]{0,200}(?:os\.environ|getenv|id_rsa|AWS_SECRET|\.aws/credentials|API_KEY))"),
        "Skill code that gathers credentials/environment and exfiltrates them.",
        attack=("T1552", "T1041"),
        families=("skill",),
    ),
    Signature(
        "skill.disable_safety",
        "Instruction to enable unattended / no-confirmation execution",
        Severity.HIGH,
        _rx(r"(yolo\s*mode|--dangerously|auto[- ]?approve|disable (the )?(guard|"
            r"confirmation|safety)|bypass(ing)? permission)"),
        "Pushes the agent toward unattended auto-execution — the exact setting "
        "that made the Hermes abuse campaign dangerous.",
        families=("skill",),
    ),
]


def scan(text: str, signatures: list[Signature]) -> list[tuple[Signature, str]]:
    """Return (signature, matched-snippet) for every rule that fires."""
    hits: list[tuple[Signature, str]] = []
    for sig in signatures:
        m = sig.pattern.search(text)
        if m:
            start = max(0, m.start() - 20)
            snippet = text[start : m.end() + 40].replace("\n", " ").strip()
            hits.append((sig, snippet[:160]))
    return hits
