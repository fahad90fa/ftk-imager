import json
from pathlib import Path

from forensic_imager.audit import write_audit_event
from forensic_imager.case_mgmt import init_case_workspace
from forensic_imager.seal import create_case_seal, verify_case_seal


def test_case_seal_detects_tamper(tmp_path: Path) -> None:
    case_dir = tmp_path / "CASE"
    init_case_workspace(case_dir, "CASE", "ex", "d", "n")

    # Minimal artifacts
    (case_dir / "acquisition_report.txt").write_text("report\n", encoding="utf-8")
    (case_dir / "image.hashes").write_text("md5=aaa\nsha1=bbb\nsha256=ccc\n", encoding="utf-8")
    (case_dir / "core_audit.jsonl").write_text("{}\n", encoding="utf-8")
    (case_dir / "case.json").write_text(json.dumps({"image_path": ""}), encoding="utf-8")

    audit = case_dir / "audit.jsonl"
    write_audit_event(audit, "x")
    write_audit_event(audit, "y")

    seal = create_case_seal(case_dir)
    out = verify_case_seal(case_dir, seal)
    assert out["valid"] is True

    # Tamper with report.
    (case_dir / "acquisition_report.txt").write_text("changed\n", encoding="utf-8")
    try:
        verify_case_seal(case_dir, seal)
    except RuntimeError:
        pass
    else:
        raise AssertionError("tampering not detected")
