import json

from mercury.audit import AuditLog
from mercury.authorization import Guard, ScopeViolation
from mercury.engagement import Authorization, Engagement
from mercury.scope import Scope


def _engagement():
    return Engagement(
        name="test",
        operator="tester",
        authorization=Authorization(
            client="ACME",
            authorizing_party="CISO",
            contact_email="ciso@acme.example",
            sow_reference="SOW-1",
            acknowledged=True,
        ),
        scope=Scope(allow_hosts=["10.0.0.0/24"]),
    )


def test_chain_intact(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.record("x", "tester", a=1)
    log.record("y", "tester", b=2)
    ok, msg = log.verify()
    assert ok, msg


def test_tamper_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.record("x", "tester", a=1)
    log.record("y", "tester", b=2)

    lines = p.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["data"]["a"] = 999  # tamper with a past entry
    lines[0] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")

    ok, _ = AuditLog(p).verify()
    assert not ok


def test_guard_logs_and_blocks_out_of_scope(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    guard = Guard(_engagement(), log)

    guard.authorize("tool:nmap", "10.0.0.5")  # in scope, ok

    try:
        guard.authorize("tool:nmap", "8.8.8.8")  # out of scope
        raise AssertionError("expected ScopeViolation")
    except ScopeViolation:
        pass

    events = [e["event"] for e in log.entries()]
    # both the allow and the deny were recorded
    assert events.count("scope_decision") == 2
    denials = [e for e in log.entries() if e["data"].get("allowed") is False]
    assert denials and denials[0]["data"]["target"] == "8.8.8.8"


def test_unacknowledged_engagement_refused(tmp_path):
    eng = _engagement()
    eng.authorization.acknowledged = False
    try:
        Guard(eng, AuditLog(tmp_path / "a.jsonl"))
        raise AssertionError("expected PermissionError")
    except PermissionError:
        pass
