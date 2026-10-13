"""Tamper-evident, append-only audit log.

Every scope decision and every tool invocation is written here as a JSON line.
Each record carries the SHA-256 of the previous record, forming a hash chain:
altering or deleting any past entry breaks verification of every later entry.
This is what makes an engagement defensible after the fact.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


def _hash(prev_hash: str, record: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode())
    h.update(_canonical(record))
    return h.hexdigest()


class AuditLog:
    """Append-only hash-chained log backed by a JSONL file."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def _last_hash(self) -> str:
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)["hash"]
        return last

    def record(self, event: str, actor: str, **fields: Any) -> dict[str, Any]:
        """Append an event. Returns the written record (including its hash)."""
        body = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "actor": actor,
            "data": fields,
        }
        prev = self._last_hash()
        record = {"prev": prev, **body}
        record["hash"] = _hash(prev, body)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def entries(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def verify(self) -> tuple[bool, str]:
        """Re-walk the chain. Returns (ok, message)."""
        prev = GENESIS
        for i, rec in enumerate(self.entries()):
            if rec.get("prev") != prev:
                return False, f"entry {i}: broken prev-link"
            body = {k: rec[k] for k in ("ts", "event", "actor", "data")}
            if _hash(prev, body) != rec.get("hash"):
                return False, f"entry {i}: hash mismatch (record was altered)"
            prev = rec["hash"]
        return True, "audit chain intact"
