"""Engagement definition: who authorized what, against which assets, when.

An engagement is loaded from a YAML file that a human fills in before any
testing begins. Mercury refuses to act without one. The ``authorization`` block
is intended to capture the real-world paper trail (client, authorizing party,
reference to the signed statement of work / rules of engagement).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .scope import Scope


class Authorization(BaseModel):
    """The human paper trail behind an engagement.

    These fields do not grant authority by themselves; they record it so the
    audit log and report can show who approved the work. ``acknowledged`` must
    be explicitly set to ``true`` by the operator, confirming they hold the
    signed authorization referenced here.
    """

    client: str
    authorizing_party: str
    contact_email: str
    sow_reference: str = Field(description="Statement of work / RoE document reference")
    acknowledged: bool = False


class Engagement(BaseModel):
    name: str
    operator: str
    authorization: Authorization
    scope: Scope

    @classmethod
    def load(cls, path: str | Path) -> Engagement:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)

    def assert_ready(self) -> None:
        """Raise if the engagement is not safe to act on."""
        if not self.authorization.acknowledged:
            raise PermissionError(
                "engagement authorization is not acknowledged; set "
                "authorization.acknowledged: true only if you hold the signed "
                f"authorization referenced by {self.authorization.sow_reference!r}"
            )
        if not self.scope.allow_hosts:
            raise PermissionError("engagement scope has no allow_hosts; nothing is in scope")
