"""Safe intake of suspicious artifacts.

Intake copies a sample into a quarantine directory, strips its execute bits,
computes a SHA-256, and records basic metadata. It deliberately does not open
the file in any interpreter or run it.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Artifact:
    original_path: str
    quarantine_path: str
    sha256: str
    size: int
    ingested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def name(self) -> str:
        return Path(self.original_path).name


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def ingest(path: str | os.PathLike[str], quarantine_dir: str | os.PathLike[str]) -> Artifact:
    src = Path(path)
    if not src.is_file():
        raise FileNotFoundError(f"not a file: {src}")

    qdir = Path(quarantine_dir)
    qdir.mkdir(parents=True, exist_ok=True)

    digest = _sha256(src)
    # Name the quarantined copy by hash so duplicates collapse and the original
    # name (which may itself be a lure, e.g. "invoice.pdf.exe") cannot mislead.
    dest = qdir / f"{digest}{src.suffix}"
    if not dest.exists():
        shutil.copy2(src, dest)
        # read-only, no execute, for owner only
        dest.chmod(0o400)

    return Artifact(
        original_path=str(src),
        quarantine_path=str(dest),
        sha256=digest,
        size=src.stat().st_size,
    )
