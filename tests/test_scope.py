from datetime import datetime, timedelta, timezone

from mercury.scope import Scope, TimeWindow


def test_cidr_allow_and_deny():
    s = Scope(allow_hosts=["10.0.0.0/24"], deny_hosts=["10.0.0.5"])
    assert s.check("10.0.0.9")
    assert not s.check("10.0.0.5")  # deny wins
    assert not s.check("10.0.1.9")  # outside range


def test_domain_subdomain_matching():
    s = Scope(allow_hosts=["example.com"], deny_hosts=["secret.example.com"])
    assert s.check("https://app.example.com/login")
    assert s.check("example.com")
    assert not s.check("secret.example.com")
    assert not s.check("notexample.com")


def test_deny_overrides_allow_for_same_host():
    s = Scope(allow_hosts=["example.com"], deny_hosts=["example.com"])
    assert not s.check("example.com")


def test_port_restriction():
    s = Scope(allow_hosts=["10.0.0.1"], allow_ports=[80, 443])
    assert s.check("10.0.0.1", port=443)
    assert not s.check("10.0.0.1", port=22)


def test_time_window():
    now = datetime.now(timezone.utc)
    past = TimeWindow(start=now - timedelta(days=2), end=now - timedelta(days=1))
    s = Scope(allow_hosts=["10.0.0.1"], windows=[past])
    assert not s.check("10.0.0.1")  # window closed
    open_now = TimeWindow(start=now - timedelta(hours=1), end=now + timedelta(hours=1))
    s2 = Scope(allow_hosts=["10.0.0.1"], windows=[open_now])
    assert s2.check("10.0.0.1")


def test_empty_scope_denies_everything():
    assert not Scope().check("example.com")
