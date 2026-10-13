"""Engagement scope model and in-scope matching.

The scope is the heart of Mercury's authorization model. A target (host, IP, or
URL) is actionable only if it matches an allow rule AND matches no deny rule AND
the current time falls inside an authorized window. Deny always wins.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class TimeWindow(BaseModel):
    """An authorized testing window, inclusive of start, exclusive of end."""

    start: datetime
    end: datetime

    def contains(self, moment: datetime) -> bool:
        m = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
        return self.start <= m < self.end


class Scope(BaseModel):
    """The set of assets, ports, and time windows an engagement authorizes.

    Matching rules:
      * ``allow_hosts`` / ``deny_hosts`` accept IPs, CIDR ranges, or domains
        (a domain rule matches the domain and its subdomains).
      * ``deny`` entries always override ``allow`` entries.
      * If ``windows`` is empty, no time restriction is applied; otherwise the
        action must fall inside at least one window.
    """

    allow_hosts: list[str] = Field(default_factory=list)
    deny_hosts: list[str] = Field(default_factory=list)
    allow_ports: list[int] = Field(default_factory=list)
    windows: list[TimeWindow] = Field(default_factory=list)

    # ---- target normalization -------------------------------------------------

    @staticmethod
    def _host_of(target: str) -> str:
        """Extract the host component from a bare host or a URL."""
        if "://" in target:
            return (urlparse(target).hostname or "").lower()
        # strip any :port suffix on a bare host (but not on IPv6 literals)
        if target.count(":") == 1:
            target = target.split(":", 1)[0]
        return target.strip().lower()

    @staticmethod
    def _as_ip(host: str) -> ipaddress._BaseAddress | None:
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None

    @classmethod
    def _matches_rule(cls, host: str, rule: str) -> bool:
        rule = rule.strip().lower()
        ip = cls._as_ip(host)
        # CIDR / IP rule
        if "/" in rule or cls._as_ip(rule) is not None:
            try:
                net = ipaddress.ip_network(rule, strict=False)
            except ValueError:
                return False
            return ip is not None and ip in net
        # domain rule: exact or subdomain match (only meaningful for hostnames)
        if ip is not None:
            return False
        return host == rule or host.endswith("." + rule)

    # ---- public API -----------------------------------------------------------

    def host_allowed(self, target: str) -> bool:
        host = self._host_of(target)
        if not host:
            return False
        if any(self._matches_rule(host, r) for r in self.deny_hosts):
            return False
        return any(self._matches_rule(host, r) for r in self.allow_hosts)

    def port_allowed(self, port: int | None) -> bool:
        if port is None or not self.allow_ports:
            return True
        return port in self.allow_ports

    def window_open(self, moment: datetime | None = None) -> bool:
        if not self.windows:
            return True
        moment = moment or datetime.now(timezone.utc)
        return any(w.contains(moment) for w in self.windows)

    def check(
        self, target: str, port: int | None = None, moment: datetime | None = None
    ) -> ScopeDecision:
        """Return a structured allow/deny decision with a human-readable reason."""
        if not self.host_allowed(target):
            host = self._host_of(target)
            if any(self._matches_rule(host, r) for r in self.deny_hosts):
                return ScopeDecision(False, f"{host!r} matches a deny rule")
            return ScopeDecision(False, f"{host!r} is not in any allow rule")
        if not self.port_allowed(port):
            return ScopeDecision(False, f"port {port} is not in allow_ports")
        if not self.window_open(moment):
            return ScopeDecision(False, "outside the authorized testing window")
        return ScopeDecision(True, "in scope")


class ScopeDecision:
    """Result of a scope check. Truthy when allowed."""

    __slots__ = ("allowed", "reason")

    def __init__(self, allowed: bool, reason: str) -> None:
        self.allowed = allowed
        self.reason = reason

    def __bool__(self) -> bool:
        return self.allowed

    def __repr__(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY"
        return f"<ScopeDecision {verdict}: {self.reason}>"
