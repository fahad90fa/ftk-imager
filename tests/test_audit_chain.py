from pathlib import Path

from forensic_imager.audit import verify_audit_chain, write_audit_event


def test_audit_chain_valid_and_tamper_detected(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    write_audit_event(log, "start", source="/dev/sdb")
    write_audit_event(log, "stop", bytes=123)

    out = verify_audit_chain(log)
    assert out["valid"] is True
    assert out["chained_events"] == 2

    lines = log.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("123", "999")
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    try:
        verify_audit_chain(log)
    except RuntimeError:
        pass
    else:
        raise AssertionError("tampering was not detected")


def test_audit_chain_rejects_unsigned_by_default(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text('{"event":"legacy","ts":"2026-01-01T00:00:00Z"}\n', encoding="utf-8")

    try:
        verify_audit_chain(log)
    except RuntimeError:
        pass
    else:
        raise AssertionError("unsigned event was not rejected")

    out = verify_audit_chain(log, require_all_signed=False)
    assert out["unsigned_events"] == 1
