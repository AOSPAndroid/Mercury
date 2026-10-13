"""The authorization guard every targeted action passes through.

Nothing in Mercury touches a target directly. Instead, a component asks the
Guard to authorize an action against a target. The Guard checks the engagement
scope, records the decision in the audit log, and either returns or raises
``ScopeViolation``. There is no bypass flag.
"""

from __future__ import annotations

from .audit import AuditLog
from .engagement import Engagement
from .scope import ScopeDecision


class ScopeViolation(PermissionError):
    """Raised when an action is attempted against an out-of-scope target."""


class Guard:
    def __init__(self, engagement: Engagement, audit: AuditLog) -> None:
        engagement.assert_ready()
        self.engagement = engagement
        self.audit = audit

    def authorize(self, action: str, target: str, port: int | None = None) -> ScopeDecision:
        """Authorize ``action`` against ``target``. Raises on denial.

        The decision is always recorded in the audit log first — including
        denials — so attempts outside scope are themselves evidence.
        """
        decision = self.engagement.scope.check(target, port=port)
        self.audit.record(
            "scope_decision",
            actor=self.engagement.operator,
            action=action,
            target=target,
            port=port,
            allowed=decision.allowed,
            reason=decision.reason,
        )
        if not decision:
            raise ScopeViolation(
                f"refusing {action!r} against {target!r}: {decision.reason}"
            )
        return decision
